package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyDouble;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyShort;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;
import network.crypta.io.comm.AsyncMessageCallback;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.Message;
import network.crypta.keys.Key;
import network.crypta.keys.NodeCHK;
import network.crypta.support.io.NativeThread;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class RequestHandlerTest {

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private PeerNode source;
  @Mock private PeerTransport transport;
  @Mock private RequestTag tag;
  @Mock private NodeStats nodeStats;
  @Mock private FailureTable failureTable;

  private static final long UID = 42L;
  private static final short HTL_ZERO = 0;
  private static final short HTL = 5;
  private static final boolean REAL_TIME = false;
  private static final boolean NEEDS_PUBKEY = false;

  private NodeCHK anyChkKey() {
    byte[] rk = new byte[NodeCHK.KEY_LENGTH];
    for (int i = 0; i < rk.length; i++) rk[i] = (byte) (i + 1);
    return new NodeCHK(rk, (byte) 1);
  }

  @BeforeEach
  void setupNodeDefaults() {
    when(node.network().stats()).thenReturn(nodeStats);
    when(node.routing().failureTable()).thenReturn(failureTable);
    when(source.transport()).thenReturn(transport);
  }

  @Test
  void run_whenHtlZero_sendsAcceptedThenDataNotFound_andUnlocks() throws Exception {
    // Arrange
    Key key = anyChkKey();
    List<Message> sent = new ArrayList<>();
    // Capture outbound messages and immediately complete callbacks when present
    doAnswer(
            inv -> {
              Message m = inv.getArgument(0);
              AsyncMessageCallback cb = inv.getArgument(1);
              sent.add(m);
              if (cb != null) cb.sent();
              return null;
            })
        .when(transport)
        .sendAsync(any(Message.class), any(), any());

    RequestHandler rh =
        new RequestHandler(
            RequestHandlerContext.of(node, source, UID, HTL_ZERO, key, tag, REAL_TIME),
            null,
            NEEDS_PUBKEY);

    // By default, the mocked node will return null from makeRequestSender(..) which is what we need

    // Act
    rh.run();

    // Assert: first FNPAccepted, then FNPDataNotFound
    assertTrue(sent.size() >= 2, "Expected at least Accepted and DataNotFound messages");
    assertEquals("FNPAccepted", sent.get(0).getSpec().getName());
    assertEquals("FNPDataNotFound", sent.get(1).getSpec().getName());

    // Unlock must be called once a terminal is enqueued
    verify(tag, atLeastOnce()).unlockHandler();

    // Failure table informed of final failure
    verify(failureTable, times(1))
        .onFinalFailure(
            eq(key), isNull(), eq(HTL_ZERO), eq(HTL_ZERO), anyLong(), anyLong(), eq(source));

    // Basic recording of remote request (we don't assert the numerics here)
    verify(nodeStats, times(1))
        .remoteRequest(
            eq(false), eq(false), eq(false), anyShort(), anyDouble(), eq(REAL_TIME), eq(false));
  }

  @Test
  void onReceivedRejectOverload_sendsOnlyOnce_andIsLocalFalse() throws Exception {
    // Arrange
    Key key = anyChkKey();
    List<Message> sent = new ArrayList<>();
    doAnswer(
            inv -> {
              Message m = inv.getArgument(0);
              sent.add(m);
              return null;
            })
        .when(transport)
        .sendAsync(any(Message.class), any(), any());

    RequestHandler rh =
        new RequestHandler(
            RequestHandlerContext.of(node, source, UID, HTL, key, tag, REAL_TIME),
            null,
            NEEDS_PUBKEY);

    // Act
    rh.onReceivedRejectOverload();
    rh.onReceivedRejectOverload(); // the second call must be ignored

    // Assert
    assertEquals(1, sent.size(), "Only one RejectedOverload should be forwarded");
    Message msg = sent.getFirst();
    assertEquals("FNPRejectOverload", msg.getSpec().getName());
    assertFalse(msg.getBoolean(DMT.IS_LOCAL), "Forwarded overload must have isLocal=false");
  }

  @Test
  void onRequestSenderFinished_successCHK_withoutTransfer_sendsLocalRejectedOverload_andUnlocks()
      throws Exception {
    // Arrange
    Key key = anyChkKey();
    List<Message> sent = new ArrayList<>();
    doAnswer(
            inv -> {
              Message m = inv.getArgument(0);
              AsyncMessageCallback cb = inv.getArgument(1);
              sent.add(m);
              if (cb != null) cb.sent();
              return null;
            })
        .when(transport)
        .sendAsync(any(Message.class), any(), any());
    when(tag.hasSourceReallyRestarted()).thenReturn(false);

    RequestHandler rh =
        new RequestHandler(
            RequestHandlerContext.of(node, source, UID, HTL, key, tag, REAL_TIME),
            null,
            NEEDS_PUBKEY);

    // Act: SUCCESS for CHK with no transfer started → maybeCompleteTransfer() sends local reject
    rh.onRequestSenderFinished(RequestSender.SUCCESS, /*fromOfferedKey*/ false, /*rs*/ null);

    // Assert
    // The terminal message must be a local (isLocal=true) RejectedOverload due to missing transfer
    Message terminal = sent.getLast();
    assertEquals("FNPRejectOverload", terminal.getSpec().getName());
    assertTrue(terminal.getBoolean(DMT.IS_LOCAL), "Terminal reject must have isLocal=true");
    verify(tag, atLeastOnce()).unlockHandler();

    // Also records success in remoteRequest accounting (not from an offered key)
    verify(nodeStats, times(1))
        .remoteRequest(
            eq(false), eq(true), eq(false), anyShort(), anyDouble(), eq(REAL_TIME), eq(false));
  }

  @Test
  void isHighHtl_dependsOnNodeMax() {
    when(node.maxHTL()).thenReturn((short) 10);
    Key key = anyChkKey();

    RequestHandler high =
        new RequestHandler(
            RequestHandlerContext.of(node, source, UID, (short) 9, key, tag, REAL_TIME),
            null,
            NEEDS_PUBKEY);
    RequestHandler low =
        new RequestHandler(
            RequestHandlerContext.of(node, source, UID, (short) 8, key, tag, REAL_TIME),
            null,
            NEEDS_PUBKEY);

    assertTrue(high.isHighHtl());
    assertFalse(low.isHighHtl());
  }

  @Test
  void byteCounters_updateNodeStats_andSentPayloadAdjustsSign() {
    Key key = anyChkKey();
    RequestHandler rh =
        new RequestHandler(
            RequestHandlerContext.of(node, source, UID, HTL, key, tag, REAL_TIME),
            null,
            NEEDS_PUBKEY);

    rh.sentBytes(100);
    rh.receivedBytes(50);
    rh.sentPayload(20);

    // requestSentBytes called with +100 then -20, and received with +50
    verify(nodeStats, times(1)).requestSentBytes(false, 100);
    verify(nodeStats, times(1)).requestReceivedBytes(false, 50);
    verify(node, times(1)).sentPayload(20);
    verify(nodeStats, times(1)).requestSentBytes(false, -20);
  }

  @Test
  void getPriority_returnsHighPriority() {
    Key key = anyChkKey();
    RequestHandler rh =
        new RequestHandler(
            RequestHandlerContext.of(node, source, UID, HTL, key, tag, REAL_TIME),
            null,
            NEEDS_PUBKEY);
    assertEquals(NativeThread.PriorityLevel.HIGH_PRIORITY.value, rh.getPriority());
  }
}

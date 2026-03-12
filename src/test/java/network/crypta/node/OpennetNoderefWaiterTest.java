package network.crypta.node;

import java.util.stream.Stream;
import network.crypta.io.comm.AsyncMessageFilterCallback;
import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.DisconnectedException;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.MessageCore;
import network.crypta.io.xfer.BulkReceiver;
import network.crypta.node.OpennetNoderefWaiter.NoderefCallback;
import network.crypta.node.OpennetNoderefWaiter.NoderefTransferCtx;
import network.crypta.node.OpennetNoderefWaiter.WaitedTooLongForOpennetNoderefException;
import network.crypta.node.subsystem.NodeNetworkSubsystem;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class OpennetNoderefWaiterTest {
  private static final long UID = 100L;
  private static final long XFER_UID = 200L;
  private static final int PADDED_LEN = 8;
  private static final int REAL_LEN = 5;

  private Node node;
  private MessageCore usm;
  private PeerNode source;
  private ByteCounter ctr;

  @BeforeEach
  void setUp() {
    node = mock(Node.class);
    NodeNetworkSubsystem network = mock(NodeNetworkSubsystem.class);
    usm = mock(MessageCore.class);
    source = mock(PeerNode.class);
    ctr = mock(ByteCounter.class);

    when(node.network()).thenReturn(network);
    when(network.usm()).thenReturn(usm);
  }

  @Test
  void waitForOpennetNoderef_whenMatchedMessage_returnsNoderef()
      throws DisconnectedException, WaitedTooLongForOpennetNoderefException {
    Message msg = DMT.createFNPOpennetConnectReplyNew(UID, XFER_UID, REAL_LEN, PADDED_LEN);
    byte[] expected = new byte[] {1, 2, 3, 4, 5};

    doAnswer(
            invocation -> {
              AsyncMessageFilterCallback callback = invocation.getArgument(1);
              callback.onMatched(msg);
              return null;
            })
        .when(usm)
        .addAsyncFilter(any(), any(), any());

    NoderefTransferCtx expectedCtx = new NoderefTransferCtx(source, true, UID, false, ctr, node);

    try (MockedStatic<OpennetNoderefWaiter> mocked =
        mockStatic(OpennetNoderefWaiter.class, org.mockito.Mockito.CALLS_REAL_METHODS)) {
      mocked
          .when(
              () ->
                  OpennetNoderefWaiter.innerWaitForOpennetNoderef(
                      eq(XFER_UID), eq(PADDED_LEN), eq(REAL_LEN), eq(expectedCtx)))
          .thenReturn(expected);

      byte[] result = OpennetNoderefWaiter.waitForOpennetNoderef(true, source, UID, ctr, node);

      assertArrayEquals(expected, result);
      mocked.verify(
          () ->
              OpennetNoderefWaiter.innerWaitForOpennetNoderef(
                  XFER_UID, PADDED_LEN, REAL_LEN, expectedCtx));
    }
  }

  @Test
  void waitForOpennetNoderef_whenTimeout_throwsWaitedTooLong() throws DisconnectedException {
    doAnswer(
            invocation -> {
              AsyncMessageFilterCallback callback = invocation.getArgument(1);
              callback.onTimeout();
              return null;
            })
        .when(usm)
        .addAsyncFilter(any(), any(), any());

    assertThrows(
        WaitedTooLongForOpennetNoderefException.class,
        () -> OpennetNoderefWaiter.waitForOpennetNoderef(false, source, UID, ctr, node));
  }

  @ParameterizedTest
  @MethodSource("ackMessages")
  void waitForOpennetNoderef_whenAckMessage_callsAcked(Message ackMessage, boolean timedOutFlag)
      throws DisconnectedException {
    NoderefCallback callback = mock(NoderefCallback.class);

    doAnswer(
            invocation -> {
              AsyncMessageFilterCallback filterCallback = invocation.getArgument(1);
              filterCallback.onMatched(ackMessage);
              return null;
            })
        .when(usm)
        .addAsyncFilter(any(), any(), any());

    OpennetNoderefWaiter.waitForOpennetNoderef(false, source, UID, ctr, callback, node);

    verify(callback).acked(timedOutFlag);
    verify(callback, never()).gotNoderef(any());
    verify(callback, never()).timedOut();
  }

  @Test
  void waitForOpennetNoderef_whenFilterTimeout_callsTimedOut() throws DisconnectedException {
    NoderefCallback callback = mock(NoderefCallback.class);

    doAnswer(
            invocation -> {
              AsyncMessageFilterCallback filterCallback = invocation.getArgument(1);
              filterCallback.onTimeout();
              return null;
            })
        .when(usm)
        .addAsyncFilter(any(), any(), any());

    OpennetNoderefWaiter.waitForOpennetNoderef(true, source, UID, ctr, callback, node);

    verify(callback).timedOut();
    verify(callback, never()).acked(anyBoolean());
    verify(callback, never()).gotNoderef(any());
  }

  @Test
  void waitForOpennetNoderef_whenDisconnectedException_callsGotNoderefNull()
      throws DisconnectedException {
    NoderefCallback callback = mock(NoderefCallback.class);

    doAnswer(
            _ -> {
              throw new DisconnectedException();
            })
        .when(usm)
        .addAsyncFilter(any(), any(), any());

    OpennetNoderefWaiter.waitForOpennetNoderef(true, source, UID, ctr, callback, node);

    verify(callback).gotNoderef(null);
    verify(callback, never()).acked(anyBoolean());
    verify(callback, never()).timedOut();
  }

  @Test
  void innerWaitForOpennetNoderef_whenReceiveSucceeds_returnsTrimmedBuffer() {
    NoderefTransferCtx ctx = new NoderefTransferCtx(source, false, UID, false, ctr, node);

    try (MockedConstruction<BulkReceiver> bulkReceiver =
        org.mockito.Mockito.mockConstruction(
            BulkReceiver.class, (mock, _) -> when(mock.receive()).thenReturn(true))) {
      byte[] result =
          OpennetNoderefWaiter.innerWaitForOpennetNoderef(XFER_UID, PADDED_LEN, REAL_LEN, ctx);

      assertNotNull(result);
      assertArrayEquals(new byte[REAL_LEN], result);
      assertEquals(1, bulkReceiver.constructed().size());
    }
  }

  @Test
  void innerWaitForOpennetNoderef_whenReceiveFailsAndSendReject_callsRejectRef() {
    when(source.isConnected()).thenReturn(true);
    NoderefTransferCtx ctx = new NoderefTransferCtx(source, false, UID, true, ctr, node);

    try (MockedConstruction<BulkReceiver> bulkReceiver =
            org.mockito.Mockito.mockConstruction(
                BulkReceiver.class, (mock, _) -> when(mock.receive()).thenReturn(false));
        MockedStatic<OpennetManager> opennetManager = mockStatic(OpennetManager.class)) {
      byte[] result =
          OpennetNoderefWaiter.innerWaitForOpennetNoderef(XFER_UID, PADDED_LEN, REAL_LEN, ctx);

      assertNull(result);
      assertEquals(1, bulkReceiver.constructed().size());
      opennetManager.verify(
          () -> OpennetManager.rejectRef(UID, source, DMT.NODEREF_REJECTED_TRANSFER_FAILED, ctr));
    }
  }

  private static Stream<Arguments> ackMessages() {
    return Stream.of(
        Arguments.of(DMT.createFNPOpennetCompletedAck(UID), false),
        Arguments.of(DMT.createFNPOpennetCompletedTimeout(UID), true));
  }
}

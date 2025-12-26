package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyDouble;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anySet;
import static org.mockito.ArgumentMatchers.anyShort;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import network.crypta.crypt.RandomSource;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.MessageCore;
import network.crypta.io.comm.MessageFilter;
import network.crypta.io.comm.NotConnectedException;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.io.NativeThread;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@SuppressWarnings("java:S100")
class AnnounceSenderTest {

  @Mock private Node node;
  @Mock private OpennetManager om;
  @Mock private PeerNode onlyNode;
  @Mock private AnnouncementCallback cb;
  @Mock private RequestTracker tracker;
  @Mock private MessageCore usm;
  @Mock private NodeStats stats;
  @Mock private NodeCrypto crypto;
  @Mock private PriorityAwareExecutor executor;
  @Mock private PeerManager peers;
  @Mock private PeerRoutingSelector routingSelector;

  private static final long FIXED_UID = 777L;

  @BeforeEach
  void setUpCommon() {
    when(node.getTracker()).thenReturn(tracker);
    when(node.getUSM()).thenReturn(usm);
    when(node.getNodeStats()).thenReturn(stats);
    when(node.getExecutor()).thenReturn(executor);
    // Run runnables inline for determinism when used.
    Mockito.doAnswer(
            inv -> {
              Runnable r = inv.getArgument(0);
              r.run();
              return null;
            })
        .when(executor)
        .execute(any(Runnable.class));

    when(om.getCrypto()).thenReturn(crypto);
    when(crypto.myCompressedFullRef()).thenReturn(new byte[] {1, 2, 3});

    // Local-origin announce defaults
    when(node.maxHTL()).thenReturn((short) 3);
    when(node.isOpennetEnabled()).thenReturn(true);
    when(node.isAdvancedModeEnabled()).thenReturn(false);

    // Deterministic UID
    RandomSource rnd = Mockito.mock(RandomSource.class);
    when(rnd.nextLong()).thenReturn(FIXED_UID);
    when(node.getRandom()).thenReturn(rnd);
  }

  @Test
  void run_whenAcceptedThenTimeout_expectNodeFailedTimedOut() throws Exception {
    // Arrange
    AnnounceSender sender = new AnnounceSender(0.5, om, node, cb, onlyNode);

    // start -> returns transfer uid; finish -> no-op
    when(om.startSendAnnouncementRequest(
            anyLong(), any(PeerNode.class), any(), any(), anyDouble(), anyShort()))
        .thenReturn(123L);
    Mockito.doNothing()
        .when(om)
        .finishSentAnnouncementRequest(any(PeerNode.class), any(), any(), anyLong());

    // First waitFor: Accepted; Second waitFor: timeout (null)
    Message accepted = DMT.createFNPAccepted(FIXED_UID);
    when(usm.waitFor(any(MessageFilter.class), any())).thenReturn(accepted).thenReturn(null);

    // Act
    sender.run();

    // Assert
    verify(cb, times(1)).acceptedSomewhere();
    verify(cb, times(1)).nodeFailed(onlyNode, "timed out");
    verify(cb, times(1)).completed();
    verify(stats, atLeastOnce()).endAnnouncement(FIXED_UID);
    // Originated locally: no source path or peer selection
    verify(node, never()).getPeers();
  }

  @Test
  void run_whenAcceptedThenRejectedOverload_expectRnfAndNodeFailedRouteNotFound() throws Exception {
    // Arrange
    AnnounceSender sender = new AnnounceSender(0.5, om, node, cb, onlyNode);

    when(om.startSendAnnouncementRequest(
            anyLong(), any(PeerNode.class), any(), any(), anyDouble(), anyShort()))
        .thenReturn(9876L);
    Mockito.doNothing()
        .when(om)
        .finishSentAnnouncementRequest(any(PeerNode.class), any(), any(), anyLong());

    Message accepted = DMT.createFNPAccepted(FIXED_UID);
    Message rejected = DMT.createFNPRejectedOverload(FIXED_UID, true);
    when(usm.waitFor(any(MessageFilter.class), any())).thenReturn(accepted).thenReturn(rejected);

    // Act
    sender.run();

    // Assert
    verify(cb, times(1)).acceptedSomewhere();
    verify(cb, times(1)).nodeFailed(onlyNode, "route not found");
    verify(cb, times(1)).completed();
    verify(stats, atLeastOnce()).endAnnouncement(FIXED_UID);
  }

  @Test
  void run_whenNodeNotWantedThenCompleted_expectCompletedAndNoHang() throws Exception {
    // Arrange
    AnnounceSender sender = new AnnounceSender(0.5, om, node, cb, onlyNode);

    when(om.startSendAnnouncementRequest(
            anyLong(), any(PeerNode.class), any(), any(), anyDouble(), anyShort()))
        .thenReturn(4242L);
    Mockito.doNothing()
        .when(om)
        .finishSentAnnouncementRequest(any(PeerNode.class), any(), any(), anyLong());

    Message accepted = DMT.createFNPAccepted(FIXED_UID);
    Message notWanted = DMT.createFNPOpennetAnnounceNodeNotWanted(FIXED_UID);
    Message completed = DMT.createFNPOpennetAnnounceCompleted(FIXED_UID);

    when(usm.waitFor(any(MessageFilter.class), any()))
        .thenReturn(accepted)
        .thenReturn(notWanted)
        .thenReturn(completed)
        .thenReturn(null); // completion follow-up ends

    // Act
    sender.run();

    // Assert
    verify(cb, times(1)).acceptedSomewhere();
    verify(cb, times(1)).nodeNotWanted();
    verify(cb, times(1)).completed();
    verify(stats, atLeastOnce()).endAnnouncement(FIXED_UID);
  }

  @Test
  void run_whenNoOnlyNodeAndNoPeerChosen_expectNoMoreNodes() {
    // Arrange: onlyNode == null, routingSelector.closerPeer() returns null so we RNF with next ==
    // null
    when(node.getPeers()).thenReturn(peers);
    when(peers.routingSelector()).thenReturn(routingSelector);
    when(node.decrementHTL(isNull(), anyShort())).thenReturn((short) 1);
    when(routingSelector.closerPeer(
            isNull(),
            anySet(),
            anyDouble(),
            anyBoolean(),
            anyBoolean(),
            anyInt(),
            isNull(),
            isNull(),
            anyShort(),
            anyLong(),
            anyBoolean(),
            anyBoolean(),
            anyBoolean()))
        .thenReturn(null);

    AnnounceSender sender = new AnnounceSender(0.25, om, node, cb, null);

    // Act
    sender.run();

    // Assert
    verify(cb, times(1)).noMoreNodes();
    verify(cb, times(1)).completed();
    Mockito.verifyNoInteractions(usm);
    verify(stats, atLeastOnce()).endAnnouncement(FIXED_UID);
  }

  @Test
  void getPriority_returnsHighPriorityValue() {
    // Arrange
    AnnounceSender sender = new AnnounceSender(0.1, om, node, cb, null);

    // Act / Assert
    assertEquals(NativeThread.PriorityLevel.HIGH_PRIORITY.value, sender.getPriority());
  }

  @Test
  void updateHtl_usesLastPeerAfterSendFailure() throws Exception {
    // Arrange: multi-peer routing (onlyNode == null)
    when(node.getPeers()).thenReturn(peers);
    when(peers.routingSelector()).thenReturn(routingSelector);

    PeerNode p1 = Mockito.mock(PeerNode.class);
    PeerNode p2 = Mockito.mock(PeerNode.class);
    when(routingSelector.closerPeer(
            isNull(),
            anySet(),
            anyDouble(),
            anyBoolean(),
            anyBoolean(),
            anyInt(),
            isNull(),
            isNull(),
            anyShort(),
            anyLong(),
            anyBoolean(),
            anyBoolean(),
            anyBoolean()))
        .thenReturn(p1, p2, null);

    // Decrement HTL returns a sequence to keep iterations going
    when(node.decrementHTL(any(), anyShort())).thenReturn((short) 2, (short) 1, (short) 1);

    // First peer p1: start OK, then we don't get Accepted (timeout), so routeOnce ->
    // CONTINUE_FORWARDED
    when(om.startSendAnnouncementRequest(
            anyLong(), any(PeerNode.class), any(), any(), anyDouble(), anyShort()))
        .thenReturn(111L)
        // Second attempt on p2: fail to start transfer
        .thenThrow(new NotConnectedException("send fail"));

    // Accepted wait: first call returns null (timeout/try another), no further waits because p2
    // send fails
    when(usm.waitFor(any(MessageFilter.class), any())).thenReturn(null);

    AnnounceSender sender = new AnnounceSender(0.2, om, node, cb, null);

    // Act
    sender.run();

    // Assert: verify decrementHTL was called with p2 as the 'from' on the iteration after send
    // failure
    ArgumentCaptor<PeerNode> fromCaptor = ArgumentCaptor.forClass(PeerNode.class);
    verify(node, atLeast(3)).decrementHTL(fromCaptor.capture(), anyShort());
    // Calls expected: [null (initial), p1 (after first forward), p2 (after send failure)]
    java.util.List<PeerNode> calls = fromCaptor.getAllValues();
    // Ensure we have at least 3 calls and the third is p2
    assertEquals(p2, calls.get(2));
  }
}

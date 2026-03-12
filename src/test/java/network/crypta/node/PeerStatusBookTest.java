package network.crypta.node;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class PeerStatusBookTest {
  private static final long NOW = 10_000L;

  private final Object lock = new Object();

  @Mock private PeerRoster roster;
  @Mock private PeerNode peer;

  private PeerStatusBook book;

  @BeforeEach
  void setUp() {
    book = new PeerStatusBook(roster, lock);
  }

  @Test
  void onPeerAdded_whenRecordStatusTrue_tracksAllAndDarknetStatuses() {
    when(peer.recordStatus()).thenReturn(true);
    when(peer.getPeerNodeStatus()).thenReturn(PeerManager.PEER_NODE_STATUS_CONNECTED);
    when(peer.isOpennet()).thenReturn(false);

    book.onPeerAdded(peer);

    assertEquals(1, book.getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_CONNECTED, false));
    assertEquals(1, book.getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_CONNECTED, true));
  }

  @Test
  void onPeerAdded_whenRecordStatusFalse_doesNotTrackStatuses() {
    when(peer.recordStatus()).thenReturn(false);

    book.onPeerAdded(peer);

    assertEquals(0, book.getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_CONNECTED, false));
    assertEquals(0, book.getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_CONNECTED, true));
  }

  @Test
  void onPeerRemoved_whenStatusAndReasonsPresent_clearsAllTracking() {
    when(peer.recordStatus()).thenReturn(true);
    when(peer.getPeerNodeStatus()).thenReturn(PeerManager.PEER_NODE_STATUS_TOO_NEW);
    when(peer.isOpennet()).thenReturn(false);
    when(peer.getPreviousBackoffReason(true)).thenReturn("rt");
    when(peer.getPreviousBackoffReason(false)).thenReturn("bulk");

    book.onPeerAdded(peer);
    book.addPeerNodeRoutingBackoffReason("rt", peer, true);
    book.addPeerNodeRoutingBackoffReason("bulk", peer, false);

    book.onPeerRemoved(peer);

    assertEquals(0, book.getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_TOO_NEW, false));
    assertEquals(0, book.getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_TOO_NEW, true));
    assertEquals(0, book.getPeerNodeRoutingBackoffReasonSize("rt", true));
    assertEquals(0, book.getPeerNodeRoutingBackoffReasonSize("bulk", false));
  }

  @Test
  void changePeerNodeStatus_whenDarknet_movesCountsBetweenStatuses() {
    when(peer.recordStatus()).thenReturn(true);
    when(peer.getPeerNodeStatus()).thenReturn(PeerManager.PEER_NODE_STATUS_DISCONNECTED);
    when(peer.isOpennet()).thenReturn(false);

    book.onPeerAdded(peer);
    book.changePeerNodeStatus(
        peer,
        PeerManager.PEER_NODE_STATUS_DISCONNECTED,
        PeerManager.PEER_NODE_STATUS_CONNECTED,
        false);

    assertEquals(0, book.getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_DISCONNECTED, false));
    assertEquals(1, book.getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_CONNECTED, false));
    assertEquals(0, book.getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_DISCONNECTED, true));
    assertEquals(1, book.getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_CONNECTED, true));
  }

  @Test
  void getPeerNodeRoutingBackoffReasons_whenTracked_returnsDistinctReasonsPerStream() {
    book.addPeerNodeRoutingBackoffReason("reason-a", peer, true);
    book.addPeerNodeRoutingBackoffReason("reason-b", peer, true);
    book.addPeerNodeRoutingBackoffReason("bulk-only", peer, false);

    Set<String> realtimeReasons =
        new HashSet<>(Arrays.asList(book.getPeerNodeRoutingBackoffReasons(true)));
    Set<String> bulkReasons =
        new HashSet<>(Arrays.asList(book.getPeerNodeRoutingBackoffReasons(false)));

    assertEquals(Set.of("reason-a", "reason-b"), realtimeReasons);
    assertEquals(Set.of("bulk-only"), bulkReasons);
  }

  @Test
  void getPeerNodeStatuses_whenRequested_returnsSnapshotInRosterOrder() {
    PeerNode first = peer;
    PeerNode second = org.mockito.Mockito.mock(PeerNode.class);
    PeerNodeStatus firstStatus = org.mockito.Mockito.mock(PeerNodeStatus.class);
    PeerNodeStatus secondStatus = org.mockito.Mockito.mock(PeerNodeStatus.class);
    when(roster.myPeers()).thenReturn(new PeerNode[] {first, second});
    when(first.getStatus(true)).thenReturn(firstStatus);
    when(second.getStatus(true)).thenReturn(secondStatus);

    PeerNodeStatus[] statuses = book.getPeerNodeStatuses(true);

    assertEquals(2, statuses.length);
    assertSame(firstStatus, statuses[0]);
    assertSame(secondStatus, statuses[1]);
    verify(first).getStatus(true);
    verify(second).getStatus(true);
  }

  @Test
  void getDarknetPeerNodeStatuses_whenRequested_returnsDarknetSnapshots() {
    DarknetPeerNode darknetPeer = org.mockito.Mockito.mock(DarknetPeerNode.class);
    DarknetPeerNodeStatus status = org.mockito.Mockito.mock(DarknetPeerNodeStatus.class);
    when(roster.getDarknetPeers()).thenReturn(new DarknetPeerNode[] {darknetPeer});
    when(darknetPeer.getStatus(false)).thenReturn(status);

    DarknetPeerNodeStatus[] statuses = book.getDarknetPeerNodeStatuses(false);

    assertEquals(1, statuses.length);
    assertSame(status, statuses[0]);
    verify(darknetPeer).getStatus(false);
  }

  @Test
  void getOpennetPeerNodeStatuses_whenRequested_returnsOpennetSnapshots() {
    OpennetPeerNode opennetPeer = org.mockito.Mockito.mock(OpennetPeerNode.class);
    OpennetPeerNodeStatus status = org.mockito.Mockito.mock(OpennetPeerNodeStatus.class);
    when(roster.getOpennetPeers()).thenReturn(new OpennetPeerNode[] {opennetPeer});
    when(opennetPeer.getStatus(false)).thenReturn(status);

    OpennetPeerNodeStatus[] statuses = book.getOpennetPeerNodeStatuses(false);

    assertEquals(1, statuses.length);
    assertSame(status, statuses[0]);
    verify(opennetPeer).getStatus(false);
  }

  @Test
  void maybeUpdateOldestNeverConnectedDarknetPeerAge_whenIntervalElapsed_updatesMaxAge() {
    PeerNode first = org.mockito.Mockito.mock(PeerNode.class);
    PeerNode second = org.mockito.Mockito.mock(PeerNode.class);
    PeerNode third = org.mockito.Mockito.mock(PeerNode.class);

    when(first.isDarknet()).thenReturn(true);
    when(first.getPeerNodeStatus()).thenReturn(PeerManager.PEER_NODE_STATUS_NEVER_CONNECTED);
    when(first.getPeerAddedTime()).thenReturn(NOW - 1_000L);

    when(second.isDarknet()).thenReturn(true);
    when(second.getPeerNodeStatus()).thenReturn(PeerManager.PEER_NODE_STATUS_NEVER_CONNECTED);
    when(second.getPeerAddedTime()).thenReturn(NOW - 2_000L);

    when(third.isDarknet()).thenReturn(false);

    PeerNode[] initialPeers = new PeerNode[] {first, second, third};
    PeerNode[] updatedPeers = new PeerNode[] {second, third};

    when(roster.myPeers()).thenReturn(initialPeers, updatedPeers);

    book.maybeUpdateOldestNeverConnectedDarknetPeerAge(NOW);

    assertEquals(2_000L, book.getOldestNeverConnectedDarknetPeerAge());

    book.maybeUpdateOldestNeverConnectedDarknetPeerAge(NOW + 4_999L);

    assertEquals(2_000L, book.getOldestNeverConnectedDarknetPeerAge());

    book.maybeUpdateOldestNeverConnectedDarknetPeerAge(NOW + 5_001L);

    assertEquals(7_001L, book.getOldestNeverConnectedDarknetPeerAge());
    verify(roster, times(2)).myPeers();
  }

  @Test
  void maybeUpdateOldestNeverConnectedDarknetPeerAge_whenNoMatchingPeers_returnsZero() {
    PeerNode nonDarknet = org.mockito.Mockito.mock(PeerNode.class);
    when(nonDarknet.isDarknet()).thenReturn(false);
    when(roster.myPeers()).thenReturn(new PeerNode[] {nonDarknet});

    book.maybeUpdateOldestNeverConnectedDarknetPeerAge(NOW);

    assertEquals(0L, book.getOldestNeverConnectedDarknetPeerAge());
  }

  @Test
  void maybeLogPeerNodeStatusSummary_whenCalledTwiceWithinInterval_logsOnce() {
    when(roster.myPeers()).thenReturn(new PeerNode[] {peer});
    when(peer.getPeerNodeStatus()).thenReturn(PeerManager.PEER_NODE_STATUS_CONNECTED);

    book.maybeLogPeerNodeStatusSummary(NOW);
    book.maybeLogPeerNodeStatusSummary(NOW);

    verify(roster, times(1)).myPeers();
    verify(peer, times(1)).getPeerNodeStatus();
  }

  @Test
  void maybeUpdatePeerNodeRoutableConnectionStats_whenIntervalElapsed_updatesPeers() {
    PeerNode first = peer;
    PeerNode second = org.mockito.Mockito.mock(PeerNode.class);
    when(roster.myPeers()).thenReturn(new PeerNode[] {first, second});

    book.maybeUpdatePeerNodeRoutableConnectionStats(NOW);
    book.maybeUpdatePeerNodeRoutableConnectionStats(NOW + 6_999L);

    verify(first, times(1)).checkRoutableConnectionStatus();
    verify(second, times(1)).checkRoutableConnectionStatus();
  }

  @Test
  void maybeUpdatePeerNodeRoutableConnectionStats_whenIntervalNotElapsed_skipsPeers() {
    when(roster.myPeers()).thenReturn(new PeerNode[] {peer});

    book.maybeUpdatePeerNodeRoutableConnectionStats(NOW);
    book.maybeUpdatePeerNodeRoutableConnectionStats(NOW + 1_000L);

    verify(peer, times(1)).checkRoutableConnectionStatus();
    verify(roster, times(1)).myPeers();
  }
}

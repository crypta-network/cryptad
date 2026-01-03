package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Set;
import network.crypta.keys.Key;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class PeerRoutingSelectorTest {

  private static final long NOW = 1_000_000L;
  private static final short OUTGOING_HTL = 5;
  private static final double TARGET = 0.25;

  @Mock private Node node;
  @Mock private PeerRoster roster;
  @Mock private PeerStatusBook statusBook;

  private PeerRoutingSelector selector;

  @BeforeEach
  void setUp() {
    selector = new PeerRoutingSelector(node, roster, statusBook);
    when(node.getLocation()).thenReturn(0.0);
    when(node.isEnablePerNodeFailureTables()).thenReturn(false);
  }

  @Test
  void closerPeer_whenNoConnectedPeers_expectNull() {
    // Arrange
    when(roster.connectedPeers()).thenReturn(new PeerNode[0]);

    // Act
    PeerNode selected =
        selector.closerPeer(
            null,
            identityPeerSet(),
            TARGET,
            true,
            false,
            -1,
            null,
            2.0,
            null,
            OUTGOING_HTL,
            0L,
            true,
            false,
            null,
            false,
            NOW,
            false);

    // Assert
    assertNull(selected);
  }

  @Test
  void closerPeer_whenSingleEligiblePeer_expectNull() {
    // Arrange
    PeerNode onlyPeer = routablePeerAt(0.80);
    when(roster.connectedPeers()).thenReturn(new PeerNode[] {onlyPeer});

    // Act
    PeerNode selected =
        selector.closerPeer(
            null,
            identityPeerSet(),
            TARGET,
            true,
            false,
            -1,
            null,
            2.0,
            null,
            OUTGOING_HTL,
            0L,
            true,
            false,
            null,
            false,
            NOW,
            false);

    // Assert
    assertNull(selected);
  }

  @Test
  void closerPeer_whenTwoEligiblePeers_expectSecondClosestSelected() {
    // Arrange
    PeerNode closest = routablePeerAt(0.24);
    PeerNode secondClosest = routablePeerAt(0.30);
    when(roster.connectedPeers()).thenReturn(new PeerNode[] {closest, secondClosest});

    // Act
    PeerNode selected =
        selector.closerPeer(
            null,
            identityPeerSet(),
            TARGET,
            true,
            false,
            -1,
            null,
            2.0,
            null,
            OUTGOING_HTL,
            0L,
            true,
            false,
            null,
            false,
            NOW,
            false);

    // Assert
    assertEquals(secondClosest, selected);
  }

  @Test
  void closerPeer_whenIgnoreSelfFalseAndOnlyPeersBeyondSelf_expectNull() {
    // Arrange
    when(node.getLocation()).thenReturn(0.0); // self distance to target=0.25 is 0.25

    PeerNode closerBeyondSelf = routablePeerAt(0.60); // diff=0.35 (> 0.25)
    PeerNode fartherBeyondSelf = routablePeerAt(0.80); // diff=0.45 (> 0.25)

    when(roster.connectedPeers()).thenReturn(new PeerNode[] {closerBeyondSelf, fartherBeyondSelf});

    // Act
    PeerNode selected =
        selector.closerPeer(
            null,
            identityPeerSet(),
            TARGET,
            false,
            false,
            -1,
            null,
            2.0,
            null,
            OUTGOING_HTL,
            0L,
            true,
            false,
            null,
            false,
            NOW,
            false);

    // Assert
    assertNull(selected);
  }

  @Test
  void closerPeer_whenIgnoreSelfTrueAndOnlyPeersBeyondSelf_expectSelectsSecond() {
    // Arrange
    when(node.getLocation()).thenReturn(0.0); // self distance to target=0.25 is 0.25

    PeerNode closerBeyondSelf = routablePeerAt(0.60); // diff=0.35
    PeerNode fartherBeyondSelf = routablePeerAt(0.80); // diff=0.45

    when(roster.connectedPeers()).thenReturn(new PeerNode[] {closerBeyondSelf, fartherBeyondSelf});

    // Act
    PeerNode selected =
        selector.closerPeer(
            null,
            identityPeerSet(),
            TARGET,
            true,
            false,
            -1,
            null,
            2.0,
            null,
            OUTGOING_HTL,
            0L,
            true,
            false,
            null,
            false,
            NOW,
            false);

    // Assert
    assertEquals(fartherBeyondSelf, selected);
  }

  @Test
  void closerPeer_whenNewLoadManagementAndMissingLoadStats_expectSkipsPeer() {
    // Arrange
    PeerNode missingStats = routablePeerAt(0.24);
    stubLoadStats(missingStats, null);

    PeerNode ignored = routablePeerAt(0.27);
    stubLoadStats(ignored, mock(PeerLoadStats.class));

    PeerNode selectedExpected = routablePeerAt(0.30);
    stubLoadStats(selectedExpected, mock(PeerLoadStats.class));

    when(roster.connectedPeers())
        .thenReturn(new PeerNode[] {missingStats, ignored, selectedExpected});

    // Act
    PeerNode selected =
        selector.closerPeer(
            null,
            identityPeerSet(),
            TARGET,
            true,
            false,
            -1,
            null,
            2.0,
            null,
            OUTGOING_HTL,
            0L,
            true,
            true,
            null,
            false,
            NOW,
            true);

    // Assert
    assertEquals(selectedExpected, selected);
  }

  @Test
  void closerPeer_whenMandatoryBackoff_expectSkipsPeer() {
    // Arrange
    PeerNode inMandatoryBackoff = routablePeerAt(0.24);
    stubLoadStats(inMandatoryBackoff, mock(PeerLoadStats.class));
    when(inMandatoryBackoff.isInMandatoryBackoff(NOW, true)).thenReturn(true);

    PeerNode ignored = routablePeerAt(0.27);
    stubLoadStats(ignored, mock(PeerLoadStats.class));

    PeerNode selectedExpected = routablePeerAt(0.30);
    stubLoadStats(selectedExpected, mock(PeerLoadStats.class));

    when(roster.connectedPeers())
        .thenReturn(new PeerNode[] {inMandatoryBackoff, ignored, selectedExpected});

    // Act
    PeerNode selected =
        selector.closerPeer(
            null,
            identityPeerSet(),
            TARGET,
            true,
            false,
            -1,
            null,
            2.0,
            null,
            OUTGOING_HTL,
            0L,
            true,
            true,
            null,
            false,
            NOW,
            true);

    // Assert
    assertEquals(selectedExpected, selected);
  }

  @Test
  void closerPeer_whenPeerIsOverSelected_expectSkipped() {
    // Arrange
    PeerNode overSelected = routablePeerAt(0.24);
    when(overSelected.selectionRate()).thenReturn(100.0);

    PeerNode ignored = routablePeerAt(0.27);
    when(ignored.selectionRate()).thenReturn(1.0);

    PeerNode selectedExpected = routablePeerAt(0.30);
    when(selectedExpected.selectionRate()).thenReturn(1.0);

    PeerNode other1 = routablePeerAt(0.35);
    PeerNode other2 = routablePeerAt(0.40);
    when(other1.selectionRate()).thenReturn(1.0);
    when(other2.selectionRate()).thenReturn(1.0);

    when(roster.connectedPeers())
        .thenReturn(new PeerNode[] {overSelected, ignored, selectedExpected, other1, other2});

    // Act
    PeerNode selected =
        selector.closerPeer(
            null,
            identityPeerSet(),
            TARGET,
            true,
            false,
            -1,
            null,
            2.0,
            null,
            OUTGOING_HTL,
            0L,
            true,
            false,
            null,
            false,
            NOW,
            false);

    // Assert
    assertEquals(selectedExpected, selected);
  }

  @Test
  void closerPeer_whenMinVersionRejectsOldFred_expectSkipsPeer() {
    // Arrange
    int minVersion = 1_000;

    PeerNode oldFred = routablePeerAt(0.24);
    when(oldFred.getNodeName()).thenReturn("Fred");
    when(oldFred.getVersion()).thenReturn("Fred,0.7,1.0,999");

    PeerNode ignored = routablePeerAt(0.27);
    when(ignored.getNodeName()).thenReturn("Fred");
    when(ignored.getVersion()).thenReturn("Fred,0.7,1.0,1000");

    PeerNode selectedExpected = routablePeerAt(0.30);
    when(selectedExpected.getNodeName()).thenReturn("Fred");
    when(selectedExpected.getVersion()).thenReturn("Fred,0.7,1.0,1001");

    when(roster.connectedPeers()).thenReturn(new PeerNode[] {oldFred, ignored, selectedExpected});

    // Act
    PeerNode selected =
        selector.closerPeer(
            null,
            identityPeerSet(),
            TARGET,
            true,
            false,
            minVersion,
            null,
            2.0,
            null,
            OUTGOING_HTL,
            0L,
            true,
            false,
            null,
            false,
            NOW,
            false);

    // Assert
    assertEquals(selectedExpected, selected);
  }

  @Test
  void closerPeer_whenPeerPublishesCloserPeerLocation_expectInfluencesMaxDistance() {
    // Arrange
    when(node.getLocation()).thenReturn(0.0);
    PeerNode origin = mock(PeerNode.class);
    when(origin.getLocation()).thenReturn(0.10);

    PeerNode indirect = routablePeerAt(0.90);
    when(indirect.shallWeRouteAccordingToOurPeersLocation(OUTGOING_HTL)).thenReturn(true);
    when(indirect.getClosestPeerLocation(eq(TARGET), any())).thenReturn(0.21); // diff=0.04

    PeerNode direct = routablePeerAt(0.20); // diff=0.05

    double maxDistance = 0.06;
    when(roster.connectedPeers()).thenReturn(new PeerNode[] {indirect, direct});

    // Act
    PeerNode selected =
        selector.closerPeer(
            origin,
            identityPeerSet(),
            TARGET,
            true,
            false,
            -1,
            null,
            maxDistance,
            null,
            OUTGOING_HTL,
            0L,
            true,
            false,
            null,
            false,
            NOW,
            false);

    // Assert
    assertEquals(direct, selected);
    verify(indirect)
        .getClosestPeerLocation(
            eq(TARGET),
            argThat(
                (Set<Double> exclude) ->
                    exclude != null
                        && exclude.contains(0.0)
                        && exclude.contains(0.10)
                        && exclude.size() == 2));
  }

  @Test
  void closerPeer_whenAllCandidatesBackedOff_expectReturnsSecondClosestBackedOff() {
    // Arrange
    PeerNode closestBackedOff = routablePeerAt(0.24);
    when(closestBackedOff.isRoutingBackedOff(anyLong(), anyBoolean())).thenReturn(true);

    PeerNode secondBackedOff = routablePeerAt(0.30);
    when(secondBackedOff.isRoutingBackedOff(anyLong(), anyBoolean())).thenReturn(true);

    when(roster.connectedPeers()).thenReturn(new PeerNode[] {closestBackedOff, secondBackedOff});

    // Act
    PeerNode selected =
        selector.closerPeer(
            null,
            identityPeerSet(),
            TARGET,
            true,
            false,
            -1,
            null,
            2.0,
            null,
            OUTGOING_HTL,
            0L,
            true,
            false,
            null,
            false,
            NOW,
            false);

    // Assert
    assertEquals(secondBackedOff, selected);
  }

  @Test
  void closerPeer_whenAddUnpickedLocsToProvided_expectCollectsUnpickedAndBackedOff() {
    // Arrange
    PeerNode closest = routablePeerAt(0.22); // diff=0.03 (ignored)
    PeerNode selectedExpected = routablePeerAt(0.20); // diff=0.05

    PeerNode backedOff = routablePeerAt(0.19); // diff=0.06
    when(backedOff.isRoutingBackedOff(anyLong(), anyBoolean())).thenReturn(true);

    PeerNode unpicked = routablePeerAt(0.10); // diff=0.15

    when(roster.connectedPeers())
        .thenReturn(new PeerNode[] {closest, selectedExpected, backedOff, unpicked});

    List<Double> addUnpickedLocsTo = new ArrayList<>();

    // Act
    PeerNode selected =
        selector.closerPeer(
            null,
            identityPeerSet(),
            TARGET,
            true,
            false,
            -1,
            addUnpickedLocsTo,
            2.0,
            null,
            OUTGOING_HTL,
            0L,
            true,
            false,
            null,
            false,
            NOW,
            false);

    // Assert
    assertEquals(selectedExpected, selected);
    assertEquals(Set.of(0.10, 0.19), Set.copyOf(addUnpickedLocsTo));
  }

  @Test
  void closerPeer_whenRecentlyFailedAndUnderWaitingThreshold_expectDoesNotFail() {
    // Arrange
    when(node.isEnablePerNodeFailureTables()).thenReturn(true);

    FailureTable failureTable = mock(FailureTable.class);
    when(node.getFailureTable()).thenReturn(failureTable);

    Key key = mock(Key.class);
    TimedOutNodesList entry = mock(TimedOutNodesList.class);
    when(failureTable.getTimedOutNodesList(key)).thenReturn(entry);

    PeerNode closest = routablePeerAt(0.24);
    PeerNode selectedExpected = routablePeerAt(0.27);
    when(roster.connectedPeers()).thenReturn(new PeerNode[] {closest, selectedExpected});

    when(entry.getTimeoutTime(closest, OUTGOING_HTL, NOW, true)).thenReturn(NOW - 1);
    when(entry.getTimeoutTime(selectedExpected, OUTGOING_HTL, NOW, true)).thenReturn(NOW - 1);

    when(entry.getTimeoutTime(closest, OUTGOING_HTL, NOW, false)).thenReturn(NOW + 10_000);
    when(entry.getTimeoutTime(selectedExpected, OUTGOING_HTL, NOW, false)).thenReturn(NOW - 1);

    RecentlyFailedReturn recentlyFailed = new RecentlyFailedReturn();

    // Act
    PeerNode selected =
        selector.closerPeer(
            null,
            identityPeerSet(),
            TARGET,
            true,
            false,
            -1,
            null,
            2.0,
            key,
            OUTGOING_HTL,
            0L,
            true,
            false,
            recentlyFailed,
            false,
            NOW,
            false);

    // Assert
    assertEquals(selectedExpected, selected);
    assertEquals(-1L, recentlyFailed.recentlyFailed());
  }

  @Test
  void closerPeer_whenRecentlyFailedAndWaitingThresholdReached_expectFailsAndReturnsNull() {
    // Arrange
    when(node.isEnablePerNodeFailureTables()).thenReturn(true);
    when(node.isEnableULPRDataPropagation()).thenReturn(true);

    FailureTable failureTable = mock(FailureTable.class);
    when(node.getFailureTable()).thenReturn(failureTable);

    Key key = mock(Key.class);
    TimedOutNodesList entry = mock(TimedOutNodesList.class);
    when(failureTable.getTimedOutNodesList(key)).thenReturn(entry);
    when(failureTable.hadAnyOffers(key)).thenReturn(false);

    PeerNode closest = routablePeerAt(0.24);
    PeerNode middle = routablePeerAt(0.27);
    PeerNode farthest = routablePeerAt(0.30);
    when(roster.connectedPeers()).thenReturn(new PeerNode[] {closest, middle, farthest});

    for (PeerNode peer : List.of(closest, middle, farthest)) {
      when(entry.getTimeoutTime(peer, OUTGOING_HTL, NOW, true)).thenReturn(NOW - 1);
      when(entry.getTimeoutTime(peer, OUTGOING_HTL, NOW, false)).thenReturn(NOW + 10_000);
    }

    RecentlyFailedReturn recentlyFailed = new RecentlyFailedReturn();

    // Act
    PeerNode selected =
        selector.closerPeer(
            null,
            identityPeerSet(),
            TARGET,
            true,
            false,
            -1,
            null,
            2.0,
            key,
            OUTGOING_HTL,
            0L,
            true,
            false,
            recentlyFailed,
            false,
            NOW,
            false);

    // Assert
    assertNull(selected);
    assertEquals(NOW + 10_000, recentlyFailed.recentlyFailed());
  }

  @Test
  void closerPeer_whenCalculateMisroutingAndNoPeersCounted_expectNoNodeStatsReport() {
    // Arrange
    when(statusBook.getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_CONNECTED, false))
        .thenReturn(0);
    when(statusBook.getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_ROUTING_BACKED_OFF, false))
        .thenReturn(0);

    PeerNode closest = routablePeerAt(0.24);
    PeerNode selectedExpected = routablePeerAt(0.27);
    when(roster.connectedPeers()).thenReturn(new PeerNode[] {closest, selectedExpected});

    // Act
    PeerNode selected =
        selector.closerPeer(
            null,
            identityPeerSet(),
            TARGET,
            true,
            true,
            -1,
            null,
            2.0,
            null,
            OUTGOING_HTL,
            0L,
            true,
            false,
            null,
            false,
            NOW,
            false);

    // Assert
    assertEquals(selectedExpected, selected);
    verify(statusBook, atLeastOnce())
        .getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_CONNECTED, false);
    verify(statusBook, atLeastOnce())
        .getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_ROUTING_BACKED_OFF, false);
    verify(node, never()).getNodeStats();
  }

  @Test
  void closerPeer_whenRoutedToIsNull_expectNullPointerException() {
    // Arrange
    when(roster.connectedPeers()).thenReturn(new PeerNode[0]);

    // Act + Assert
    assertThrows(
        NullPointerException.class,
        () ->
            selector.closerPeer(
                null,
                null,
                TARGET,
                true,
                false,
                -1,
                null,
                2.0,
                null,
                OUTGOING_HTL,
                0L,
                true,
                false,
                null,
                false,
                NOW,
                false));
  }

  @Test
  void closerPeer_whenUsingConvenienceOverload_expectSameSelectionRulesApply() {
    // Arrange
    PeerNode closest = routablePeerAt(0.24);
    PeerNode selectedExpected = routablePeerAt(0.30);
    when(roster.connectedPeers()).thenReturn(new PeerNode[] {closest, selectedExpected});

    // Act
    PeerNode selected =
        selector.closerPeer(
            null,
            identityPeerSet(),
            TARGET,
            true,
            false,
            -1,
            null,
            null,
            OUTGOING_HTL,
            0L,
            true,
            false,
            false);

    // Assert
    assertEquals(selectedExpected, selected);
  }

  private static Set<PeerNode> identityPeerSet() {
    return Collections.newSetFromMap(new IdentityHashMap<>());
  }

  private PeerNode routablePeerAt(double location) {
    PeerNode peer = mock(PeerNode.class);
    lenient().when(peer.getLocation()).thenReturn(location);
    when(peer.selectionRate()).thenReturn(1.0);
    when(peer.isRoutable()).thenReturn(true);
    when(peer.isDisconnecting()).thenReturn(false);
    lenient().when(peer.isRoutingBackedOff(anyLong(), anyBoolean())).thenReturn(false);
    lenient().when(peer.shallWeRouteAccordingToOurPeersLocation(anyInt())).thenReturn(false);
    return peer;
  }

  private void stubLoadStats(PeerNode peer, PeerLoadStats statsOrNull) {
    PeerNodeLoadTracker.OutputLoadTracker tracker =
        mock(PeerNodeLoadTracker.OutputLoadTracker.class);
    when(tracker.getLastIncomingLoadStats()).thenReturn(statsOrNull);
    when(peer.outputLoadTracker(true)).thenReturn(tracker);
  }
}

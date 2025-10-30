package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100") // test method naming convention per project rules
class NodePingerTest {

  @Mock private Node node;
  @Mock private PeerManager peerManager;
  @Mock private network.crypta.support.Ticker ticker;

  private static PeerNode mockPeerWithPing(double pingMs) {
    PeerNode peer = Mockito.mock(PeerNode.class, Answers.RETURNS_DEEP_STUBS);
    when(peer.averagePingTime()).thenReturn(pingMs);
    // For capacity calculations we return trackers whose last stats are null unless overridden
    PeerNode.OutputLoadTracker rt =
        Mockito.mock(
            PeerNode.OutputLoadTracker.class,
            Mockito.withSettings()
                .useConstructor(true)
                .outerInstance(peer)
                .defaultAnswer(Answers.CALLS_REAL_METHODS));
    PeerNode.OutputLoadTracker bulk =
        Mockito.mock(
            PeerNode.OutputLoadTracker.class,
            Mockito.withSettings()
                .useConstructor(false)
                .outerInstance(peer)
                .defaultAnswer(Answers.CALLS_REAL_METHODS));
    Mockito.lenient().doReturn(null).when(rt).getLastIncomingLoadStats();
    Mockito.lenient().doReturn(null).when(bulk).getLastIncomingLoadStats();
    when(peer.outputLoadTracker(true)).thenReturn(rt);
    when(peer.outputLoadTracker(false)).thenReturn(bulk);
    return peer;
  }

  @Test
  void run_whenNoPeers_schedulesNextRunAndLeavesMeanPingUnchanged() {
    when(node.getPeers()).thenReturn(peerManager);
    when(node.getTicker()).thenReturn(ticker);
    when(peerManager.connectedPeers()).thenReturn(new PeerNode[0]);

    NodePinger pinger = new NodePinger(node);

    // Before run, average ping defaults to 0
    assertEquals(0.0, pinger.averagePingTime(), 0.000001);

    pinger.run();

    // Mean ping remains unchanged and job is re-queued
    assertEquals(0.0, pinger.averagePingTime(), 0.000001);
    verify(ticker, times(1)).queueTimedJob(pinger, 200L);
    verifyNoMoreInteractions(ticker);
  }

  @Test
  void run_withOddPeers_calculatesMedianPing() {
    when(node.getPeers()).thenReturn(peerManager);
    when(node.getTicker()).thenReturn(ticker);

    PeerNode p1 = mockPeerWithPing(100);
    PeerNode p2 = mockPeerWithPing(300);
    PeerNode p3 = mockPeerWithPing(50);
    PeerNode p4 = mockPeerWithPing(1000);
    PeerNode p5 = mockPeerWithPing(400);
    when(peerManager.connectedPeers()).thenReturn(new PeerNode[] {p1, p2, p3, p4, p5});

    NodePinger pinger = new NodePinger(node);
    pinger.run();

    // Sorted pings: [50, 100, 300, 400, 1000] -> median index 2 => 300
    assertEquals(300.0, pinger.averagePingTime(), 0.000001);
    verify(ticker).queueTimedJob(pinger, 200L);
  }

  @Test
  void run_withEvenPeers_usesUpperMedianIndex() {
    when(node.getPeers()).thenReturn(peerManager);
    when(node.getTicker()).thenReturn(ticker);

    PeerNode p1 = mockPeerWithPing(10);
    PeerNode p2 = mockPeerWithPing(40);
    PeerNode p3 = mockPeerWithPing(20);
    PeerNode p4 = mockPeerWithPing(30);
    when(peerManager.connectedPeers()).thenReturn(new PeerNode[] {p1, p2, p3, p4});

    NodePinger pinger = new NodePinger(node);
    pinger.run();

    // Sorted pings: [10, 20, 30, 40]; length/2 = 2 -> element at index 2 is 30
    assertEquals(30.0, pinger.averagePingTime(), 0.000001);
    verify(ticker).queueTimedJob(pinger, 200L);
  }

  @Test
  void capacityThreshold_whenStatsAvailable_computesThresholdsForAllCombinations() {
    when(node.getPeers()).thenReturn(peerManager);
    when(node.getTicker()).thenReturn(ticker);

    // Prepare four peers with explicit per-tracker stats.
    PeerNode[] peers = new PeerNode[4];
    for (int i = 0; i < peers.length; i++) {
      peers[i] = mockPeerWithPing(100 + i); // ping values irrelevant for this test
    }
    when(peerManager.connectedPeers()).thenReturn(peers);

    // Values per combination (already chosen to make math easy):
    double[] rtInput = {10, 20, 30, 40}; // threshold min(30/2, 20) = 15
    double[] rtOutput = {15, 25, 35, 100}; // threshold min(35/2, 25) = 17.5
    double[] bulkInput = {50, 5, 70, 60}; // sorted [5,50,60,70] -> min(60/2, 50) = 30
    double[] bulkOutput = {2, 4, 6, 8}; // min(6/2, 4) = 3

    for (int i = 0; i < peers.length; i++) {
      PeerNode peer = peers[i];

      PeerNode.OutputLoadTracker rt = peer.outputLoadTracker(true);
      PeerNode.OutputLoadTracker bulk = peer.outputLoadTracker(false);

      NodeStats.PeerLoadStats statsRt =
          Mockito.mock(NodeStats.PeerLoadStats.class, Answers.RETURNS_DEFAULTS);
      NodeStats.PeerLoadStats statsBulk =
          Mockito.mock(NodeStats.PeerLoadStats.class, Answers.RETURNS_DEFAULTS);

      // Stub the method used by NodePinger
      when(statsRt.peerLimit(true)).thenReturn(rtInput[i]);
      when(statsRt.peerLimit(false)).thenReturn(rtOutput[i]);
      when(statsBulk.peerLimit(true)).thenReturn(bulkInput[i]);
      when(statsBulk.peerLimit(false)).thenReturn(bulkOutput[i]);

      Mockito.doReturn(statsRt).when(rt).getLastIncomingLoadStats();
      Mockito.doReturn(statsBulk).when(bulk).getLastIncomingLoadStats();
    }

    NodePinger pinger = new NodePinger(node);
    pinger.run();

    assertEquals(15.0, pinger.capacityThreshold(true, true), 0.000001); // realtime input
    assertEquals(17.5, pinger.capacityThreshold(true, false), 0.000001); // realtime output
    assertEquals(30.0, pinger.capacityThreshold(false, true), 0.000001); // bulk input
    assertEquals(3.0, pinger.capacityThreshold(false, false), 0.000001); // bulk output

    verify(ticker).queueTimedJob(pinger, 200L);
  }

  @Test
  void capacityThreshold_whenSomeStatsAreNull_ignoresThem() {
    when(node.getPeers()).thenReturn(peerManager);
    when(node.getTicker()).thenReturn(ticker);

    PeerNode p1 = mockPeerWithPing(1);
    PeerNode p2 = mockPeerWithPing(2);
    PeerNode p3 = mockPeerWithPing(3);
    PeerNode p4 = mockPeerWithPing(4);
    when(peerManager.connectedPeers()).thenReturn(new PeerNode[] {p1, p2, p3, p4});

    // Prepare stats only for three peers on realtime tracker; the fourth returns null
    NodeStats.PeerLoadStats s1 =
        Mockito.mock(NodeStats.PeerLoadStats.class, Answers.RETURNS_DEFAULTS);
    NodeStats.PeerLoadStats s2 =
        Mockito.mock(NodeStats.PeerLoadStats.class, Answers.RETURNS_DEFAULTS);
    NodeStats.PeerLoadStats s3 =
        Mockito.mock(NodeStats.PeerLoadStats.class, Answers.RETURNS_DEFAULTS);

    when(s1.peerLimit(true)).thenReturn(5.0);
    when(s2.peerLimit(true)).thenReturn(10.0);
    when(s3.peerLimit(true)).thenReturn(15.0);

    PeerNode.OutputLoadTracker t1 = p1.outputLoadTracker(true);
    PeerNode.OutputLoadTracker t2 = p2.outputLoadTracker(true);
    PeerNode.OutputLoadTracker t3 = p3.outputLoadTracker(true);
    PeerNode.OutputLoadTracker t4 = p4.outputLoadTracker(true);
    Mockito.doReturn(s1).when(t1).getLastIncomingLoadStats();
    Mockito.doReturn(s2).when(t2).getLastIncomingLoadStats();
    Mockito.doReturn(s3).when(t3).getLastIncomingLoadStats();
    Mockito.doReturn(null).when(t4).getLastIncomingLoadStats();

    NodePinger pinger = new NodePinger(node);
    pinger.run();

    // Values considered: [5,10,15] -> median (index 1) = 10, Q1 (index 0) = 5
    assertEquals(5.0, pinger.capacityThreshold(true, true), 0.000001);
    verify(ticker).queueTimedJob(pinger, 200L);
  }

  @Test
  void capacityThreshold_whenNoStats_returnsZero() {
    when(node.getPeers()).thenReturn(peerManager);
    when(node.getTicker()).thenReturn(ticker);

    PeerNode p1 = mockPeerWithPing(42);
    PeerNode p2 = mockPeerWithPing(43);
    when(peerManager.connectedPeers()).thenReturn(new PeerNode[] {p1, p2});

    // Ensure trackers have no stats
    PeerNode.OutputLoadTracker p1rt = p1.outputLoadTracker(true);
    PeerNode.OutputLoadTracker p1bulk = p1.outputLoadTracker(false);
    PeerNode.OutputLoadTracker p2rt = p2.outputLoadTracker(true);
    PeerNode.OutputLoadTracker p2bulk = p2.outputLoadTracker(false);
    Mockito.doReturn(null).when(p1rt).getLastIncomingLoadStats();
    Mockito.doReturn(null).when(p1bulk).getLastIncomingLoadStats();
    Mockito.doReturn(null).when(p2rt).getLastIncomingLoadStats();
    Mockito.doReturn(null).when(p2bulk).getLastIncomingLoadStats();

    NodePinger pinger = new NodePinger(node);
    pinger.run();

    assertEquals(0.0, pinger.capacityThreshold(true, true), 0.000001);
    assertEquals(0.0, pinger.capacityThreshold(true, false), 0.000001);
    assertEquals(0.0, pinger.capacityThreshold(false, true), 0.000001);
    assertEquals(0.0, pinger.capacityThreshold(false, false), 0.000001);
    verify(ticker).queueTimedJob(pinger, 200L);
  }

  @Test
  void constant_crazyMaxPingTime_isOneYearInMillis() {
    // 365.25 days * DAY millis, ensure constant is wired as expected
    assertEquals(NodePinger.CRAZY_MAX_PING_TIME, 365.25 * 24 * 60 * 60 * 1000.0, 0.000001);
  }
}

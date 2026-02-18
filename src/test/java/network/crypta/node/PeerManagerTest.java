package network.crypta.node;

import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import network.crypta.crypt.RandomSource;
import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.FreenetInetAddress;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.NotConnectedException;
import network.crypta.io.comm.Peer;
import network.crypta.node.PeerManager.PeerStatusChangeListener;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class PeerManagerTest {

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private PriorityAwareExecutor executor;
  @Mock private LocationManager locationManager;
  @Mock private RandomSource randomSource;

  private PeerManager pm;

  @BeforeEach
  void setUp() {
    // Default executor runs tasks inline; addPeer() uses execute(Runnable)
    doAnswer(
            inv -> {
              Runnable r = inv.getArgument(0);
              r.run();
              return null;
            })
        .when(executor)
        .execute(any(Runnable.class));

    when(node.getExecutor()).thenReturn(executor);
    // These may be needed by some tests; keep lenient to avoid unnecessary stubbing failures.
    org.mockito.Mockito.lenient()
        .when(node.network().locationManager())
        .thenReturn(locationManager);
    org.mockito.Mockito.lenient().when(node.getRandom()).thenReturn(randomSource);

    pm = new PeerManager(node, SemiOrderedShutdownHook.get());
  }

  private PeerNode peer(
      boolean connected,
      boolean realConnection,
      boolean routable,
      boolean darknet,
      double location) {
    PeerNode pn = mock(PeerNode.class);
    PeerTransport transport = mock(PeerTransport.class);
    when(pn.transport()).thenReturn(transport);
    when(pn.isConnected()).thenReturn(connected);
    when(pn.isRealConnection()).thenReturn(realConnection);
    when(pn.isRoutable()).thenReturn(routable);
    when(pn.isSeed()).thenReturn(false);
    when(pn.isDarknet()).thenReturn(darknet);
    when(pn.getLocation()).thenReturn(location);
    when(pn.recordStatus()).thenReturn(true);
    when(pn.getPeerNodeStatus()).thenReturn(PeerManager.PEER_NODE_STATUS_CONNECTED);
    return pn;
  }

  @Test
  @DisplayName("addPeer_whenNewPeer_expectAddedAndListenerNotified")
  void addPeer_whenNewPeer_expectAddedAndListenerNotified() {
    PeerNode p1 = peer(true, true, true, true, 0.5);
    AtomicBoolean notified = new AtomicBoolean(false);
    PeerStatusChangeListener listener = () -> notified.set(true);
    pm.addPeerStatusChangeListener(listener);

    boolean added = pm.addPeer(p1);

    assertTrue(added, "Peer should be added");
    assertTrue(pm.countByStatus(PeerManager.PEER_NODE_STATUS_CONNECTED) >= 1);
    assertTrue(notified.get(), "Listener should be notified");
  }

  @Test
  @DisplayName("addPeer_whenDuplicate_expectFalse")
  void addPeer_whenDuplicate_expectFalse() {
    PeerNode p1 = peer(true, true, true, true, 0.1);
    assertTrue(pm.addPeer(p1));
    assertFalse(pm.addPeer(p1));
  }

  @Test
  @DisplayName("havePeer_whenAdded_expectTrue")
  void havePeer_whenAdded_expectTrue() {
    PeerNode p1 = peer(true, true, true, true, 0.1);
    pm.addPeer(p1);
    assertTrue(pm.havePeer(p1));
  }

  @Test
  @DisplayName("addConnectedPeer_whenNotRealOrNotConnected_expectIgnored")
  void addConnectedPeer_whenNotRealOrNotConnected_expectIgnored() {
    PeerNode notReal = peer(true, false, true, true, 0.2);
    pm.addPeer(notReal);
    pm.addConnectedPeer(notReal);
    assertFalse(pm.anyConnectedPeers());

    PeerNode notConnected = peer(false, true, true, true, 0.3);
    pm.addPeer(notConnected);
    pm.addConnectedPeer(notConnected);
    assertFalse(pm.anyConnectedPeers());
  }

  @Test
  @DisplayName("addConnectedPeer_whenFirst_expectTimeFirstAnyConnectionsSet")
  void addConnectedPeer_whenFirst_expectTimeFirstAnyConnectionsSet() {
    PeerNode p1 = peer(true, true, true, true, 0.4);
    pm.addPeer(p1);
    assertEquals(0L, pm.getTimeFirstAnyConnections());

    pm.addConnectedPeer(p1);

    assertTrue(pm.getTimeFirstAnyConnections() > 0L);
    assertTrue(pm.anyConnectedPeers());
    verify(locationManager, times(1)).announceLocChange();
  }

  @Test
  @DisplayName("getPeerLocationDoubles_whenPruneAndSort")
  void getPeerLocationDoubles_whenPruneAndSort() {
    when(node.shallWePublishOurPeersLocation()).thenReturn(true);
    PeerNode p1 = peer(true, true, true, true, 0.9);
    when(p1.shouldBeExcludedFromPeerList()).thenReturn(false);
    PeerNode p2 = peer(true, true, true, false, 0.2);
    when(p2.shouldBeExcludedFromPeerList()).thenReturn(true);
    PeerNode p3 = peer(true, true, false, true, 0.4);

    pm.addPeer(p1);
    pm.addPeer(p2);
    pm.addPeer(p3);
    pm.addConnectedPeer(p1);
    pm.addConnectedPeer(p2);
    pm.addConnectedPeer(p3);

    double[] pruned = pm.getPeerLocationDoubles(true);
    assertArrayEquals(new double[] {0.9}, pruned, 1e-12);

    double[] unprunedSorted = pm.getPeerLocationDoubles(false);
    assertArrayEquals(new double[] {0.2, 0.9}, unprunedSorted, 1e-12);
  }

  @Test
  @DisplayName("localBroadcast_flagsAndVersionFilters")
  void localBroadcast_flagsAndVersionFilters() throws Exception {
    Message msg = mock(Message.class);
    ByteCounter ctr = mock(ByteCounter.class);

    PeerNode p1 = peer(true, true, true, true, 0.1);
    when(p1.getBuildNumber()).thenReturn(100);
    PeerTransport p1Transport = p1.transport();
    PeerNode p2 = peer(true, true, false, true, 0.2);
    when(p2.getBuildNumber()).thenReturn(100);
    PeerNode p3 = peer(true, false, true, false, 0.3);
    when(p3.getBuildNumber()).thenReturn(100);
    PeerNode p4 = peer(false, true, true, true, 0.4);
    when(p4.getBuildNumber()).thenReturn(120);

    pm.addPeer(p1);
    pm.addPeer(p2);
    pm.addPeer(p3);
    pm.addPeer(p4);

    // only p1 qualifies
    pm.messenger().localBroadcast(msg, false, true, ctr, Integer.MIN_VALUE, Integer.MAX_VALUE);
    verify(p1Transport, times(1)).sendAsync(msg, null, ctr);

    // minVersion excludes all (since min=101 and p1..p3 have 100; p4 not connected)
    pm.messenger().localBroadcast(msg, true, false, ctr, 101, Integer.MAX_VALUE);
    verify(p1Transport, times(1)).sendAsync(msg, null, ctr); // unchanged

    // throwing NotConnectedException is ignored
    doThrow(new NotConnectedException()).when(p1Transport).sendAsync(msg, null, ctr);
    pm.messenger().localBroadcast(msg, false, true, ctr, Integer.MIN_VALUE, Integer.MAX_VALUE);
    // no exception thrown
  }

  @Test
  @DisplayName("locallyBroadcastDiffNodeRef_respectsFilters")
  void locallyBroadcastDiffNodeRef_respectsFilters() {
    SimpleFieldSet fs = new SimpleFieldSet(true);

    PeerNode dark = peer(true, true, true, true, 0.1);
    when(dark.isDarknet()).thenReturn(true);
    PeerNode open = peer(true, true, true, false, 0.2);
    when(open.isOpennet()).thenReturn(true);
    PeerNode disconnected = peer(false, true, true, true, 0.3);

    pm.addPeer(dark);
    pm.addPeer(open);
    pm.addPeer(disconnected);

    pm.messenger().locallyBroadcastDiffNodeRef(fs, true, false); // toDarknetOnly
    verify(dark, times(1))
        .sendNodeToNodeMessage(fs, Node.N2N_MESSAGE_TYPE_DIFFNODEREF, false, 0L, false);
    verify(open, times(0))
        .sendNodeToNodeMessage(any(), anyInt(), anyBoolean(), anyLong(), anyBoolean());

    pm.messenger().locallyBroadcastDiffNodeRef(fs, false, true); // toOpennetOnly
    verify(open, times(1))
        .sendNodeToNodeMessage(fs, Node.N2N_MESSAGE_TYPE_DIFFNODEREF, false, 0L, false);
  }

  @Test
  @DisplayName("getByPeer_exactAndByIpFallback")
  void getByPeer_exactAndByIpFallback() {
    PeerNode pn = peer(true, true, true, true, 0.1);
    when(pn.isDisabled()).thenReturn(false);
    Peer peer = mock(Peer.class);
    FreenetInetAddress addr = mock(FreenetInetAddress.class);
    when(peer.getFreenetAddress()).thenReturn(addr);

    pm.addPeer(pn);

    when(pn.matchesPeerAndPort(peer)).thenReturn(true);
    assertEquals(pn, pm.roster().getByPeer(peer));

    when(pn.matchesPeerAndPort(peer)).thenReturn(false);
    try (org.mockito.MockedStatic<PeerNodeAddressManager> addressMock =
        org.mockito.Mockito.mockStatic(PeerNodeAddressManager.class)) {
      addressMock.when(() -> PeerNodeAddressManager.matchesIP(pn, addr, false)).thenReturn(true);
      assertEquals(pn, pm.roster().getByPeer(peer));
    }
  }

  @Test
  @DisplayName("getByPeer_withMangler")
  void getByPeer_withMangler() {
    PeerNode pn1 = peer(true, true, true, true, 0.1);
    PeerNode pn2 = peer(true, true, true, true, 0.2);
    FNPPacketMangler mangler = mock(FNPPacketMangler.class);
    Peer peer = mock(Peer.class);
    FreenetInetAddress addr = mock(FreenetInetAddress.class);
    when(peer.getFreenetAddress()).thenReturn(addr);

    when(pn1.isDisabled()).thenReturn(false);
    when(pn2.isDisabled()).thenReturn(false);
    when(pn1.matchesPeerAndPort(peer)).thenReturn(true);
    when(pn2.matchesPeerAndPort(peer)).thenReturn(true);
    when(pn1.getOutgoingMangler()).thenReturn(mangler);
    when(pn2.getOutgoingMangler()).thenReturn(null);

    pm.addPeer(pn1);
    pm.addPeer(pn2);

    assertEquals(pn1, pm.roster().getByPeer(peer, mangler));

    // Fallback by IP + matching mangler
    when(pn1.matchesPeerAndPort(peer)).thenReturn(false);
    when(pn2.matchesPeerAndPort(peer)).thenReturn(false);
    try (org.mockito.MockedStatic<PeerNodeAddressManager> addressMock =
        org.mockito.Mockito.mockStatic(PeerNodeAddressManager.class)) {
      addressMock.when(() -> PeerNodeAddressManager.matchesIP(pn1, addr, false)).thenReturn(true);
      assertEquals(pn1, pm.roster().getByPeer(peer, mangler));
    }
  }

  @Test
  @DisplayName("getAllConnectedByAddress_filters")
  void getAllConnectedByAddress_filters() {
    FreenetInetAddress addr = mock(FreenetInetAddress.class);
    PeerNode p1 = peer(true, true, true, true, 0.1);
    PeerNode p2 = peer(false, true, true, true, 0.2);
    PeerNode p3 = peer(true, true, false, true, 0.3);
    PeerNode p4 = peer(true, true, true, true, 0.4);

    pm.addPeer(p1);
    pm.addPeer(p2);
    pm.addPeer(p3);
    pm.addPeer(p4);

    List<PeerNode> found;
    try (org.mockito.MockedStatic<PeerNodeAddressManager> addressMock =
        org.mockito.Mockito.mockStatic(PeerNodeAddressManager.class)) {
      addressMock.when(() -> PeerNodeAddressManager.matchesIP(p1, addr, true)).thenReturn(true);
      addressMock.when(() -> PeerNodeAddressManager.matchesIP(p4, addr, true)).thenReturn(false);
      found = pm.roster().getAllConnectedByAddress(addr, true);
    }
    assertNotNull(found);
    assertEquals(1, found.size());
    assertEquals(p1, found.getFirst());
  }

  @Test
  @DisplayName("getRandomPeer_basicBehavior")
  void getRandomPeer_basicBehavior() {
    // Case 1: One connected routable peer -> selected
    PeerNode p1 = peer(true, true, true, true, 0.1);
    pm.addPeer(p1);
    pm.addConnectedPeer(p1);
    when(randomSource.nextInt(anyInt())).thenReturn(0);
    PeerNode got = pm.getRandomPeer(null);
    assertEquals(p1, got);

    // Case 2: With two peers connected, excluding p2 should still return p1
    PeerNode p2 = peer(true, true, true, true, 0.9);
    pm.addPeer(p2);
    pm.addConnectedPeer(p2);
    PeerNode chosen = pm.getRandomPeer(p2);
    assertEquals(p1, chosen);

    // Case 3: Only connected peer is the excluded one -> null
    PeerManager pm2 = new PeerManager(node, SemiOrderedShutdownHook.get());
    PeerNode only = peer(true, true, true, true, 0.7);
    pm2.addPeer(only);
    pm2.addConnectedPeer(only);
    when(randomSource.nextInt(anyInt())).thenReturn(0);
    PeerNode none = pm2.getRandomPeer(only);
    assertNull(none);
  }

  @Test
  @DisplayName("anyConnectedPeers_and_anyDarknetPeers")
  void anyConnectedPeers_and_anyDarknetPeers() {
    PeerNode dark = peer(true, true, true, true, 0.1);
    PeerNode unroutable = peer(true, true, false, false, 0.2);
    pm.addPeer(dark);
    pm.addPeer(unroutable);
    pm.addConnectedPeer(dark);
    pm.addConnectedPeer(unroutable);
    assertTrue(pm.anyConnectedPeers());
    assertTrue(pm.anyDarknetPeers());
  }

  @Test
  @DisplayName("removeAllPeers_clearsState_and_callsOnRemove")
  void removeAllPeers_clearsState_and_callsOnRemove() {
    PeerNode p1 = peer(true, true, true, true, 0.2);
    PeerNode p2 = peer(true, true, true, false, 0.3);
    pm.addPeer(p1);
    pm.addPeer(p2);
    pm.addConnectedPeer(p1);
    pm.addConnectedPeer(p2);

    assertTrue(pm.anyConnectedPeers());

    pm.removeAllPeers();

    assertFalse(pm.anyConnectedPeers());
    // myPeers() is package-private; validate via API behavior: havePeer should be false and
    // onRemove must be called once per peer.
    assertFalse(pm.havePeer(p1));
    assertFalse(pm.havePeer(p2));
    verify(p1, times(1)).onRemove();
    verify(p2, times(1)).onRemove();
  }

  @Test
  @DisplayName("countNonBackedOffPeers_onlyCountsRoutableConnected")
  void countNonBackedOffPeers_onlyCountsRoutableConnected() {
    PeerNode p1 = peer(true, true, true, true, 0.1);
    when(p1.isRoutingBackedOff(false)).thenReturn(false);
    PeerNode p2 = peer(true, true, true, true, 0.2);
    when(p2.isRoutingBackedOff(false)).thenReturn(true);

    pm.addPeer(p1);
    pm.addPeer(p2);
    pm.addConnectedPeer(p1);
    pm.addConnectedPeer(p2);

    assertEquals(1, pm.countNonBackedOffPeers(false));
  }
}

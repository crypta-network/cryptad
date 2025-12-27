package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.anyInt;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.net.InetAddress;
import java.util.List;
import network.crypta.crypt.RandomSource;
import network.crypta.io.comm.FreenetInetAddress;
import network.crypta.io.comm.Peer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class PeerRosterTest {

  @Test
  void myPeers_whenEmpty_expectEmptyArray() {
    // Arrange
    PeerRoster roster = newRoster(mock(RandomSource.class), true);

    // Act
    PeerNode[] peers = roster.myPeers();

    // Assert
    assertEquals(0, peers.length);
  }

  @Test
  void addPeer_whenReactivateTrue_expectAddedAndForceCancelCalled() {
    // Arrange
    PeerRoster roster = newRoster(mock(RandomSource.class), true);
    PeerNode peer = mock(PeerNode.class);

    // Act
    boolean added = roster.addPeer(peer, true);

    // Assert
    assertTrue(added);
    assertSame(peer, roster.myPeers()[0]);
    verify(peer).forceCancelDisconnecting();
  }

  @Test
  void addPeer_whenAlreadyPresent_expectFalseAndNoDuplicate() {
    // Arrange
    PeerRoster roster = newRoster(mock(RandomSource.class), true);
    PeerNode peer = mock(PeerNode.class);
    roster.addPeer(peer, false);

    // Act
    boolean added = roster.addPeer(peer, false);

    // Assert
    assertFalse(added);
    assertEquals(1, roster.myPeers().length);
  }

  @Test
  void removePeer_whenPresent_expectRemovedAndConnectedRebuilt() {
    // Arrange
    PeerRoster roster = newRoster(mock(RandomSource.class), true);
    PeerNode remove = mock(PeerNode.class);
    PeerNode connected = mock(PeerNode.class);
    when(connected.isConnected()).thenReturn(true);
    when(connected.isRealConnection()).thenReturn(true);
    addPeers(roster, remove, connected);
    addConnectedPeers(roster, remove, connected);

    // Act
    boolean removed = roster.removePeer(remove);

    // Assert
    assertTrue(removed);
    assertArrayEquals(new PeerNode[] {connected}, roster.myPeers());
    assertArrayEquals(new PeerNode[] {connected}, roster.connectedPeers());
  }

  @Test
  void removePeer_whenDarknetNotPresent_expectFalseButExtraDataRemoved() {
    // Arrange
    PeerRoster roster = newRoster(mock(RandomSource.class), true);
    DarknetPeerNode darknet = mock(DarknetPeerNode.class);

    // Act
    boolean removed = roster.removePeer(darknet);

    // Assert
    assertFalse(removed);
    verify(darknet).removeExtraPeerDataDir();
  }

  @Test
  void removeAllPeers_whenCalled_expectClearsAndReturnsOld() {
    // Arrange
    PeerRoster roster = newRoster(mock(RandomSource.class), true);
    PeerNode peer = mock(PeerNode.class);
    addPeers(roster, peer);
    addConnectedPeers(roster, peer);

    // Act
    PeerNode[] oldPeers = roster.removeAllPeers();

    // Assert
    assertArrayEquals(new PeerNode[] {peer}, oldPeers);
    assertEquals(0, roster.myPeers().length);
    assertEquals(0, roster.connectedPeers().length);
  }

  @Test
  void disconnected_whenPeerPresent_expectConnectedPeersRebuilt() {
    // Arrange
    PeerRoster roster = newRoster(mock(RandomSource.class), true);
    PeerNode disconnecting = mock(PeerNode.class);
    PeerNode routable = mock(PeerNode.class);
    PeerNode notRoutable = mock(PeerNode.class);
    when(routable.isRoutable()).thenReturn(true);
    when(notRoutable.isRoutable()).thenReturn(false);
    addPeers(roster, disconnecting, routable, notRoutable);
    addConnectedPeers(roster, disconnecting, routable);

    // Act
    boolean updated = roster.disconnected(disconnecting);

    // Assert
    assertTrue(updated);
    assertArrayEquals(new PeerNode[] {routable}, roster.connectedPeers());
  }

  @Test
  void disconnected_whenPeerAbsent_expectFalse() {
    // Arrange
    PeerRoster roster = newRoster(mock(RandomSource.class), true);
    PeerNode peer = mock(PeerNode.class);
    addConnectedPeers(roster, mock(PeerNode.class));

    // Act
    boolean updated = roster.disconnected(peer);

    // Assert
    assertFalse(updated);
  }

  @Test
  void addConnectedPeer_whenNotRealConnection_expectFalse() {
    // Arrange
    PeerRoster roster = newRoster(mock(RandomSource.class), true);
    PeerNode peer = mock(PeerNode.class);
    when(peer.isRealConnection()).thenReturn(false);
    PeerRoster.PeerAdder peerAdder = mock(PeerRoster.PeerAdder.class);

    // Act
    boolean added = roster.addConnectedPeer(peer, peerAdder);

    // Assert
    assertFalse(added);
    verify(peerAdder, never()).add(peer);
  }

  @Test
  void addConnectedPeer_whenNotConnected_expectFalse() {
    // Arrange
    PeerRoster roster = newRoster(mock(RandomSource.class), true);
    PeerNode peer = mock(PeerNode.class);
    when(peer.isRealConnection()).thenReturn(true);
    when(peer.isConnected()).thenReturn(false);
    PeerRoster.PeerAdder peerAdder = mock(PeerRoster.PeerAdder.class);

    // Act
    boolean added = roster.addConnectedPeer(peer, peerAdder);

    // Assert
    assertFalse(added);
    verify(peerAdder, never()).add(peer);
  }

  @Test
  void addConnectedPeer_whenNotInRoster_expectPeerAdderCalledAndAdded() {
    // Arrange
    PeerRoster roster = newRoster(mock(RandomSource.class), true);
    PeerNode peer = mock(PeerNode.class);
    when(peer.isRealConnection()).thenReturn(true);
    when(peer.isConnected()).thenReturn(true);
    PeerRoster.PeerAdder peerAdder = mock(PeerRoster.PeerAdder.class);

    // Act
    boolean added = roster.addConnectedPeer(peer, peerAdder);

    // Assert
    assertTrue(added);
    assertArrayEquals(new PeerNode[] {peer}, roster.connectedPeers());
    verify(peerAdder).add(peer);
  }

  @Test
  void addConnectedPeer_whenAlreadyConnected_expectFalse() {
    // Arrange
    PeerRoster roster = newRoster(mock(RandomSource.class), true);
    PeerNode peer = mock(PeerNode.class);
    when(peer.isRealConnection()).thenReturn(true);
    when(peer.isConnected()).thenReturn(true);
    addConnectedPeers(roster, peer);
    PeerRoster.PeerAdder peerAdder = mock(PeerRoster.PeerAdder.class);

    // Act
    boolean added = roster.addConnectedPeer(peer, peerAdder);

    // Assert
    assertFalse(added);
  }

  @Test
  void getByPeer_whenMatchesPeerAndPort_expectMatchReturned() {
    // Arrange
    PeerRoster roster = newRoster(mock(RandomSource.class), true);
    Peer peer = mock(Peer.class);
    PeerNode disabled = mock(PeerNode.class);
    PeerNode match = mock(PeerNode.class);
    when(disabled.isDisabled()).thenReturn(true);
    when(match.isDisabled()).thenReturn(false);
    when(match.matchesPeerAndPort(peer)).thenReturn(true);
    addPeers(roster, disabled, match);

    // Act
    PeerNode found = roster.getByPeer(peer);

    // Assert
    assertSame(match, found);
  }

  @Test
  void getByPeer_whenMatchesIpOnly_expectFallbackMatch() throws Exception {
    // Arrange
    PeerRoster roster = newRoster(mock(RandomSource.class), true);
    FreenetInetAddress address = new FreenetInetAddress(InetAddress.getByName("127.0.0.1"));
    Peer peer = mock(Peer.class);
    when(peer.getFreenetAddress()).thenReturn(address);
    PeerNode peerNode = mock(PeerNode.class);
    when(peerNode.isDisabled()).thenReturn(false);
    when(peerNode.matchesPeerAndPort(peer)).thenReturn(false);
    when(peerNode.matchesIP(address, false)).thenReturn(true);
    addPeers(roster, peerNode);

    // Act
    PeerNode found = roster.getByPeer(peer);

    // Assert
    assertSame(peerNode, found);
  }

  @Test
  void getByPeer_withMangler_expectMatchReturned() {
    // Arrange
    PeerRoster roster = newRoster(mock(RandomSource.class), true);
    Peer peer = mock(Peer.class);
    FNPPacketMangler mangler = mock(FNPPacketMangler.class);
    PeerNode peerNode = mock(PeerNode.class);
    when(peerNode.isDisabled()).thenReturn(false);
    when(peerNode.matchesPeerAndPort(peer)).thenReturn(true);
    when(peerNode.getOutgoingMangler()).thenReturn(mangler);
    addPeers(roster, peerNode);

    // Act
    PeerNode found = roster.getByPeer(peer, mangler);

    // Assert
    assertSame(peerNode, found);
  }

  @Test
  void getAllConnectedByAddress_whenMatches_expectListReturned() throws Exception {
    // Arrange
    PeerRoster roster = newRoster(mock(RandomSource.class), true);
    FreenetInetAddress address = new FreenetInetAddress(InetAddress.getByName("127.0.0.3"));
    PeerNode match = mock(PeerNode.class);
    PeerNode noMatch = mock(PeerNode.class);
    when(match.isConnected()).thenReturn(true);
    when(match.isRoutable()).thenReturn(true);
    when(match.matchesIP(address, true)).thenReturn(true);
    when(noMatch.isConnected()).thenReturn(true);
    when(noMatch.isRoutable()).thenReturn(true);
    when(noMatch.matchesIP(address, true)).thenReturn(false);
    addPeers(roster, match, noMatch);

    // Act
    List<PeerNode> found = roster.getAllConnectedByAddress(address, true);

    // Assert
    assertEquals(1, found.size());
    assertSame(match, found.getFirst());
  }

  @Test
  void getAllConnectedByAddress_whenNone_expectNull() throws Exception {
    // Arrange
    PeerRoster roster = newRoster(mock(RandomSource.class), true);
    FreenetInetAddress address = new FreenetInetAddress(InetAddress.getByName("127.0.0.4"));
    PeerNode peer = mock(PeerNode.class);
    when(peer.isConnected()).thenReturn(false);
    addPeers(roster, peer);

    // Act
    List<PeerNode> found = roster.getAllConnectedByAddress(address, false);

    // Assert
    assertNull(found);
  }

  @Test
  void getByPubKeyHash_whenMatch_expectPeer() {
    // Arrange
    PeerRoster roster = newRoster(mock(RandomSource.class), true);
    PeerNode peer = mock(PeerNode.class);
    byte[] hash = new byte[] {1, 2, 3};
    setPeerKeyHash(peer, hash);
    addPeers(roster, peer);

    // Act
    PeerNode found = roster.getByPubKeyHash(hash);

    // Assert
    assertSame(peer, found);
  }

  @Test
  void getByPubKeyHash_whenNoMatch_expectNull() {
    // Arrange
    PeerRoster roster = newRoster(mock(RandomSource.class), true);
    PeerNode peer = mock(PeerNode.class);
    setPeerKeyHash(peer, new byte[] {9, 9, 9});
    addPeers(roster, peer);

    // Act
    PeerNode found = roster.getByPubKeyHash(new byte[] {1, 2, 3});

    // Assert
    assertNull(found);
  }

  @Test
  void getRandomPeer_whenNoConnectedPeers_expectNull() {
    // Arrange
    PeerRoster roster = newRoster(mock(RandomSource.class), true);

    // Act
    PeerNode found = roster.getRandomPeer();

    // Assert
    assertNull(found);
  }

  @Test
  void getRandomPeer_whenRoutableAvailable_expectSelected() {
    // Arrange
    RandomSource random = mock(RandomSource.class);
    when(random.nextInt(anyInt())).thenReturn(0);
    PeerRoster roster = newRoster(random, true);
    PeerNode peer = mock(PeerNode.class);
    when(peer.isRoutable()).thenReturn(true);
    addConnectedPeers(roster, peer);

    // Act
    PeerNode found = roster.getRandomPeer();

    // Assert
    assertSame(peer, found);
  }

  @Test
  void getRandomPeer_whenExcludeOnlyRoutable_expectNull() {
    // Arrange
    RandomSource random = mock(RandomSource.class);
    when(random.nextInt(anyInt())).thenReturn(0);
    PeerRoster roster = newRoster(random, true);
    PeerNode peer = mock(PeerNode.class);
    when(peer.isRoutable()).thenReturn(true);
    addPeers(roster, peer);
    addConnectedPeers(roster, peer);

    // Act
    PeerNode found = roster.getRandomPeer(peer);

    // Assert
    assertNull(found);
  }

  @Test
  void getRandomPeer_whenConnectedNotRoutable_expectRebuildAndSelect() {
    // Arrange
    RandomSource random = mock(RandomSource.class);
    when(random.nextInt(anyInt())).thenReturn(0);
    PeerRoster roster = newRoster(random, true);
    PeerNode notRoutable = mock(PeerNode.class);
    PeerNode routable = mock(PeerNode.class);
    when(notRoutable.isRoutable()).thenReturn(false);
    when(routable.isRoutable()).thenReturn(true);
    addConnectedPeers(roster, notRoutable);
    addPeers(roster, notRoutable, routable);

    // Act
    PeerNode found = roster.getRandomPeer();

    // Assert
    assertSame(routable, found);
  }

  @Test
  void getPeerLocationDoubles_whenPublishingDisabled_expectEmpty() {
    // Arrange
    PeerRoster roster = newRoster(mock(RandomSource.class), false);

    // Act
    double[] locations = roster.getPeerLocationDoubles(false);

    // Assert
    assertEquals(0, locations.length);
  }

  @Test
  void getPeerLocationDoubles_whenPruneFalse_expectSortedAll() {
    // Arrange
    PeerRoster roster = newRoster(mock(RandomSource.class), true);
    PeerNode first = mock(PeerNode.class);
    PeerNode second = mock(PeerNode.class);
    when(first.isRoutable()).thenReturn(true);
    when(second.isRoutable()).thenReturn(true);
    when(first.getLocation()).thenReturn(0.8);
    when(second.getLocation()).thenReturn(0.2);
    addConnectedPeers(roster, first, second);

    // Act
    double[] locations = roster.getPeerLocationDoubles(false);

    // Assert
    assertArrayEquals(new double[] {0.2, 0.8}, locations, 0.0);
  }

  @Test
  void getPeerLocationDoubles_whenPruneTrue_expectFiltered() {
    // Arrange
    PeerRoster roster = newRoster(mock(RandomSource.class), true);
    PeerNode included = mock(PeerNode.class);
    PeerNode excluded = mock(PeerNode.class);
    when(included.isRoutable()).thenReturn(true);
    when(excluded.isRoutable()).thenReturn(true);
    when(included.shouldBeExcludedFromPeerList()).thenReturn(false);
    when(excluded.shouldBeExcludedFromPeerList()).thenReturn(true);
    when(included.getLocation()).thenReturn(0.4);
    addConnectedPeers(roster, included, excluded);

    // Act
    double[] locations = roster.getPeerLocationDoubles(true);

    // Assert
    assertArrayEquals(new double[] {0.4}, locations, 0.0);
  }

  @Test
  void anyConnectedPeers_whenRoutablePresent_expectTrue() {
    // Arrange
    PeerRoster roster = newRoster(mock(RandomSource.class), true);
    PeerNode peer = mock(PeerNode.class);
    when(peer.isRoutable()).thenReturn(true);
    addConnectedPeers(roster, peer);

    // Act
    boolean any = roster.anyConnectedPeers();

    // Assert
    assertTrue(any);
  }

  @Test
  void anyDarknetPeers_whenDarknetConnected_expectTrue() {
    // Arrange
    PeerRoster roster = newRoster(mock(RandomSource.class), true);
    PeerNode peer = mock(PeerNode.class);
    when(peer.isDarknet()).thenReturn(true);
    addConnectedPeers(roster, peer);

    // Act
    boolean any = roster.anyDarknetPeers();

    // Assert
    assertTrue(any);
  }

  @Test
  void getDarknetPeers_whenMixed_expectOnlyDarknet() {
    // Arrange
    PeerRoster roster = newRoster(mock(RandomSource.class), true);
    DarknetPeerNode darknet = mock(DarknetPeerNode.class);
    OpennetPeerNode opennet = mock(OpennetPeerNode.class);
    addPeers(roster, darknet, opennet);

    // Act
    DarknetPeerNode[] peers = roster.getDarknetPeers();

    // Assert
    assertArrayEquals(new DarknetPeerNode[] {darknet}, peers);
  }

  @Test
  void getOpennetPeers_whenMixed_expectOnlyOpennet() {
    // Arrange
    PeerRoster roster = newRoster(mock(RandomSource.class), true);
    DarknetPeerNode darknet = mock(DarknetPeerNode.class);
    OpennetPeerNode opennet = mock(OpennetPeerNode.class);
    addPeers(roster, darknet, opennet);

    // Act
    OpennetPeerNode[] peers = roster.getOpennetPeers();

    // Assert
    assertArrayEquals(new OpennetPeerNode[] {opennet}, peers);
  }

  @Test
  void getOpennetAndSeedServerPeers_whenMixed_expectFiltered() {
    // Arrange
    PeerRoster roster = newRoster(mock(RandomSource.class), true);
    OpennetPeerNode opennet = mock(OpennetPeerNode.class);
    SeedServerPeerNode seedServer = mock(SeedServerPeerNode.class);
    DarknetPeerNode darknet = mock(DarknetPeerNode.class);
    addPeers(roster, opennet, seedServer, darknet);

    // Act
    PeerNode[] peers = roster.getOpennetAndSeedServerPeers();

    // Assert
    assertArrayEquals(new PeerNode[] {opennet, seedServer}, peers);
  }

  @Test
  void removeOpennetPeers_whenCalled_expectOpennetRemoved() {
    // Arrange
    PeerRoster roster = newRoster(mock(RandomSource.class), true);
    DarknetPeerNode darknet = mock(DarknetPeerNode.class);
    SeedServerPeerNode seedServer = mock(SeedServerPeerNode.class);
    OpennetPeerNode opennet = mock(OpennetPeerNode.class);
    when(darknet.isConnected()).thenReturn(true);
    when(seedServer.isConnected()).thenReturn(true);
    addPeers(roster, darknet, opennet, seedServer);
    addConnectedPeers(roster, darknet, opennet, seedServer);

    // Act
    roster.removeOpennetPeers();

    // Assert
    assertArrayEquals(new PeerNode[] {darknet, seedServer}, roster.myPeers());
    assertArrayEquals(new PeerNode[] {darknet, seedServer}, roster.connectedPeers());
  }

  @Test
  void containsPeer_whenOpennetMatchOnHash_expectPeer() {
    // Arrange
    PeerRoster roster = newRoster(mock(RandomSource.class), true);
    OpennetPeerNode existing = mock(OpennetPeerNode.class);
    setPeerKeyHash(existing, new byte[] {7, 7, 7});
    addPeers(roster, existing);
    PeerNode probe = mock(PeerNode.class);
    when(probe.isOpennet()).thenReturn(true);
    setPeerKeyHash(probe, new byte[] {7, 7, 7});

    // Act
    PeerNode found = roster.containsPeer(probe);

    // Assert
    assertSame(existing, found);
  }

  @Test
  void containsPeer_whenDarknetNoMatch_expectNull() {
    // Arrange
    PeerRoster roster = newRoster(mock(RandomSource.class), true);
    DarknetPeerNode existing = mock(DarknetPeerNode.class);
    setPeerKeyHash(existing, new byte[] {1, 1, 1});
    addPeers(roster, existing);
    PeerNode probe = mock(PeerNode.class);
    when(probe.isOpennet()).thenReturn(false);
    setPeerKeyHash(probe, new byte[] {2, 2, 2});

    // Act
    PeerNode found = roster.containsPeer(probe);

    // Assert
    assertNull(found);
  }

  @Test
  void anyConnectedPeerHasAddress_whenMatchAndEligible_expectTrue() throws Exception {
    // Arrange
    PeerRoster roster = newRoster(mock(RandomSource.class), true);
    FreenetInetAddress address = new FreenetInetAddress(InetAddress.getByName("127.0.0.5"));
    PeerNode peer = mock(PeerNode.class);
    PeerNode other = mock(PeerNode.class);
    Peer otherPeer = mock(Peer.class);
    when(peer.isDarknet()).thenReturn(true);
    when(other.isDarknet()).thenReturn(true);
    when(other.isConnected()).thenReturn(true);
    when(other.isRealConnection()).thenReturn(true);
    when(otherPeer.getFreenetAddress()).thenReturn(address);
    when(other.getPeer()).thenReturn(otherPeer);
    addPeers(roster, peer, other);

    // Act
    boolean found = roster.anyConnectedPeerHasAddress(address, peer);

    // Assert
    assertTrue(found);
  }

  @Test
  void anyConnectedPeerHasAddress_whenDarknetMismatch_expectFalse() throws Exception {
    // Arrange
    PeerRoster roster = newRoster(mock(RandomSource.class), true);
    FreenetInetAddress address = new FreenetInetAddress(InetAddress.getByName("127.0.0.6"));
    PeerNode peer = mock(PeerNode.class);
    PeerNode other = mock(PeerNode.class);
    when(peer.isDarknet()).thenReturn(false);
    when(other.isDarknet()).thenReturn(true);
    when(other.isConnected()).thenReturn(true);
    when(other.isRealConnection()).thenReturn(true);
    addPeers(roster, peer, other);

    // Act
    boolean found = roster.anyConnectedPeerHasAddress(address, peer);

    // Assert
    assertFalse(found);
  }

  @Test
  void countNonBackedOffPeers_whenMixed_expectCount() {
    // Arrange
    PeerRoster roster = newRoster(mock(RandomSource.class), true);
    PeerNode included = mock(PeerNode.class);
    PeerNode excluded = mock(PeerNode.class);
    when(included.isRoutable()).thenReturn(true);
    when(included.isRoutingBackedOff(true)).thenReturn(false);
    when(excluded.isRoutable()).thenReturn(true);
    when(excluded.isRoutingBackedOff(true)).thenReturn(true);
    addConnectedPeers(roster, included, excluded);

    // Act
    int count = roster.countNonBackedOffPeers(true);

    // Assert
    assertEquals(1, count);
  }

  @Test
  void countConnectedDarknetPeers_whenMixed_expectCount() {
    // Arrange
    PeerRoster roster = newRoster(mock(RandomSource.class), true);
    DarknetPeerNode included = mock(DarknetPeerNode.class);
    DarknetPeerNode excluded = mock(DarknetPeerNode.class);
    when(included.isOpennet()).thenReturn(false);
    when(included.isRoutable()).thenReturn(true);
    when(excluded.isOpennet()).thenReturn(true);
    addPeers(roster, included, excluded);

    // Act
    int count = roster.countConnectedDarknetPeers();

    // Assert
    assertEquals(1, count);
  }

  @Test
  void countConnectedPeers_whenMixed_expectCount() {
    // Arrange
    PeerRoster roster = newRoster(mock(RandomSource.class), true);
    PeerNode routable = mock(PeerNode.class);
    PeerNode notRoutable = mock(PeerNode.class);
    when(routable.isRoutable()).thenReturn(true);
    when(notRoutable.isRoutable()).thenReturn(false);
    addPeers(roster, routable, notRoutable);

    // Act
    int count = roster.countConnectedPeers();

    // Assert
    assertEquals(1, count);
  }

  @Test
  void countAlmostConnectedDarknetPeers_whenMixed_expectCount() {
    // Arrange
    PeerRoster roster = newRoster(mock(RandomSource.class), true);
    DarknetPeerNode included = mock(DarknetPeerNode.class);
    DarknetPeerNode excluded = mock(DarknetPeerNode.class);
    when(included.isOpennet()).thenReturn(false);
    when(included.isConnected()).thenReturn(true);
    when(excluded.isOpennet()).thenReturn(false);
    when(excluded.isConnected()).thenReturn(false);
    addPeers(roster, included, excluded);

    // Act
    int count = roster.countAlmostConnectedDarknetPeers();

    // Assert
    assertEquals(1, count);
  }

  @Test
  void countCompatibleDarknetPeers_whenMixed_expectCount() {
    // Arrange
    PeerRoster roster = newRoster(mock(RandomSource.class), true);
    DarknetPeerNode included = mock(DarknetPeerNode.class);
    DarknetPeerNode excluded = mock(DarknetPeerNode.class);
    when(included.isOpennet()).thenReturn(false);
    when(included.isConnected()).thenReturn(true);
    when(included.isRoutingCompatible()).thenReturn(true);
    when(excluded.isOpennet()).thenReturn(false);
    when(excluded.isConnected()).thenReturn(true);
    when(excluded.isRoutingCompatible()).thenReturn(false);
    addPeers(roster, included, excluded);

    // Act
    int count = roster.countCompatibleDarknetPeers();

    // Assert
    assertEquals(1, count);
  }

  @Test
  void countCompatibleRealPeers_whenMixed_expectCount() {
    // Arrange
    PeerRoster roster = newRoster(mock(RandomSource.class), true);
    PeerNode included = mock(PeerNode.class);
    PeerNode excluded = mock(PeerNode.class);
    when(included.isRealConnection()).thenReturn(true);
    when(included.isConnected()).thenReturn(true);
    when(included.isRoutingCompatible()).thenReturn(true);
    when(excluded.isRealConnection()).thenReturn(false);
    addPeers(roster, included, excluded);

    // Act
    int count = roster.countCompatibleRealPeers();

    // Assert
    assertEquals(1, count);
  }

  @Test
  void countConnectedOpennetPeers_whenMixed_expectCount() {
    // Arrange
    PeerRoster roster = newRoster(mock(RandomSource.class), true);
    OpennetPeerNode included = mock(OpennetPeerNode.class);
    OpennetPeerNode excluded = mock(OpennetPeerNode.class);
    when(included.isRoutable()).thenReturn(true);
    when(excluded.isRoutable()).thenReturn(false);
    addConnectedPeers(roster, included, excluded);

    // Act
    int count = roster.countConnectedOpennetPeers();

    // Assert
    assertEquals(1, count);
  }

  @Test
  void countValidPeers_whenMixed_expectCount() {
    // Arrange
    PeerRoster roster = newRoster(mock(RandomSource.class), true);
    PeerNode included = mock(PeerNode.class);
    PeerNode excluded = mock(PeerNode.class);
    when(included.isRealConnection()).thenReturn(true);
    when(included.isDisabled()).thenReturn(false);
    when(excluded.isRealConnection()).thenReturn(true);
    when(excluded.isDisabled()).thenReturn(true);
    addPeers(roster, included, excluded);

    // Act
    int count = roster.countValidPeers();

    // Assert
    assertEquals(1, count);
  }

  @Test
  void countConnectiblePeers_whenListenOnlyDarknet_expectExcluded() {
    // Arrange
    PeerRoster roster = newRoster(mock(RandomSource.class), true);
    DarknetPeerNode listenOnly = mock(DarknetPeerNode.class);
    PeerNode included = mock(PeerNode.class);
    when(listenOnly.isDisabled()).thenReturn(false);
    when(listenOnly.isListenOnly()).thenReturn(true);
    when(included.isDisabled()).thenReturn(false);
    addPeers(roster, listenOnly, included);

    // Act
    int count = roster.countConnectiblePeers();

    // Assert
    assertEquals(1, count);
  }

  @Test
  void countSeednodes_whenMixed_expectCount() {
    // Arrange
    PeerRoster roster = newRoster(mock(RandomSource.class), true);
    SeedServerPeerNode server = mock(SeedServerPeerNode.class);
    SeedClientPeerNode client = mock(SeedClientPeerNode.class);
    PeerNode other = mock(PeerNode.class);
    addPeers(roster, server, client, other);

    // Act
    int count = roster.countSeednodes();

    // Assert
    assertEquals(2, count);
  }

  @Test
  void countBackedOffPeers_whenMixed_expectCount() {
    // Arrange
    PeerRoster roster = newRoster(mock(RandomSource.class), true);
    PeerNode included = mock(PeerNode.class);
    PeerNode excluded = mock(PeerNode.class);
    when(included.isRealConnection()).thenReturn(true);
    when(included.isDisabled()).thenReturn(false);
    when(included.isRoutingBackedOff(false)).thenReturn(true);
    when(excluded.isRealConnection()).thenReturn(true);
    when(excluded.isDisabled()).thenReturn(false);
    when(excluded.isRoutingBackedOff(false)).thenReturn(false);
    addPeers(roster, included, excluded);

    // Act
    int count = roster.countBackedOffPeers(false);

    // Assert
    assertEquals(1, count);
  }

  @Test
  void countByStatus_whenMixed_expectCount() {
    // Arrange
    PeerRoster roster = newRoster(mock(RandomSource.class), true);
    PeerNode included = mock(PeerNode.class);
    PeerNode excluded = mock(PeerNode.class);
    when(included.getPeerNodeStatus()).thenReturn(3);
    when(excluded.getPeerNodeStatus()).thenReturn(4);
    addPeers(roster, included, excluded);

    // Act
    int count = roster.countByStatus(3);

    // Assert
    assertEquals(1, count);
  }

  @Test
  void getStatus_whenUnsorted_expectSortedLines() {
    // Arrange
    PeerRoster roster = newRoster(mock(RandomSource.class), true);
    PeerNode first = mock(PeerNode.class);
    PeerNode second = mock(PeerNode.class);
    PeerNodeStatus statusA = mock(PeerNodeStatus.class);
    PeerNodeStatus statusB = mock(PeerNodeStatus.class);
    when(statusA.toString()).thenReturn("B-status");
    when(statusB.toString()).thenReturn("A-status");
    when(first.getStatus(true)).thenReturn(statusA);
    when(second.getStatus(true)).thenReturn(statusB);
    addPeers(roster, first, second);

    // Act
    String status = roster.getStatus();

    // Assert
    assertEquals("A-status\nB-status\n", status);
  }

  @Test
  void getTMCIPeerList_whenUnsorted_expectSortedLines() {
    // Arrange
    PeerRoster roster = newRoster(mock(RandomSource.class), true);
    PeerNode first = mock(PeerNode.class);
    PeerNode second = mock(PeerNode.class);
    when(first.getTMCIPeerInfo()).thenReturn("peer-b");
    when(second.getTMCIPeerInfo()).thenReturn("peer-a");
    addPeers(roster, first, second);

    // Act
    String list = roster.getTMCIPeerList();

    // Assert
    assertEquals("peer-a\npeer-b\n", list);
  }

  @Test
  void readExtraPeerData_whenOneThrows_expectContinues() {
    // Arrange
    PeerRoster roster = newRoster(mock(RandomSource.class), true);
    DarknetPeerNode first = mock(DarknetPeerNode.class);
    DarknetPeerNode second = mock(DarknetPeerNode.class);
    doThrow(new IllegalStateException("boom")).when(first).readExtraPeerData();
    addPeers(roster, first, second);

    // Act
    roster.readExtraPeerData();

    // Assert
    verify(first).readExtraPeerData();
    verify(second).readExtraPeerData();
  }

  @Test
  void incrementSelectionSamples_whenCalled_expectDelegates() {
    // Arrange
    PeerRoster roster = newRoster(mock(RandomSource.class), true);
    PeerNode peer = mock(PeerNode.class);

    // Act
    roster.incrementSelectionSamples(peer);

    // Assert
    verify(peer).incrementNumberOfSelections();
  }

  private static PeerRoster newRoster(RandomSource random, boolean publish) {
    Node node = mock(Node.class);
    lenient().when(node.getRandom()).thenReturn(random);
    lenient().when(node.shallWePublishOurPeersLocation()).thenReturn(publish);
    return new PeerRoster(node, new Object());
  }

  private static void addPeers(PeerRoster roster, PeerNode... peers) {
    for (PeerNode peer : peers) {
      roster.addPeer(peer, false);
    }
  }

  private static void addConnectedPeers(PeerRoster roster, PeerNode... peers) {
    PeerRoster.PeerAdder noOp = _ -> {};
    for (PeerNode peer : peers) {
      when(peer.isRealConnection()).thenReturn(true);
      when(peer.isConnected()).thenReturn(true);
      roster.addPeer(peer, false);
      roster.addConnectedPeer(peer, noOp);
    }
  }

  @SuppressWarnings("java:S3011")
  private static void setPeerKeyHash(PeerNode peer, byte[] hash) {
    try {
      Field field = PeerNode.class.getDeclaredField("peerECDSAPubKeyHash");
      field.setAccessible(true);
      field.set(peer, hash);
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException("Failed to set peer key hash", e);
    }
  }
}

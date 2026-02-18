package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import network.crypta.io.comm.FreenetInetAddress;
import network.crypta.io.comm.Peer;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class PeerNodeAddressManagerTest {

  @Mock private PeerNode peer;

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private OutgoingPacketMangler outgoingMangler;

  @Test
  void markHandshakeIpUpdateAttempted_whenCalled_expectTimestampStored()
      throws ReflectiveOperationException {
    // Arrange
    PeerNodeAddressManager manager = new PeerNodeAddressManager(peer);

    // Act
    manager.markHandshakeIpUpdateAttempted(1234L);

    // Assert
    assertEquals(1234L, getLastAttemptedHandshakeIpUpdateTime(manager));
  }

  @Test
  void resetHandshakeIpUpdateTimer_whenMarked_expectClearedToZero()
      throws ReflectiveOperationException {
    // Arrange
    PeerNodeAddressManager manager = new PeerNodeAddressManager(peer);
    manager.markHandshakeIpUpdateAttempted(42L);

    // Act
    manager.resetHandshakeIpUpdateTimer();

    // Assert
    assertEquals(0L, getLastAttemptedHandshakeIpUpdateTime(manager));
  }

  @Test
  void maybeUpdateHandshakeIPs_whenRecentAttempt_expectNoApply()
      throws ReflectiveOperationException {
    // Arrange
    PeerNodeAddressManager manager = new PeerNodeAddressManager(peer);
    peer.nominalPeer = new CopyOnWriteArrayList<>();
    setLastAttemptedHandshakeIpUpdateTime(
        manager, System.currentTimeMillis() - TimeUnit.MINUTES.toMillis(1));

    // Act
    manager.maybeUpdateHandshakeIPs(false);

    // Assert
    verify(peer, never()).applyHandshakeIPs(any(Peer[].class), any(Peer.class), any(Peer.class));
  }

  @Test
  void maybeUpdateHandshakeIPs_whenNoNominalPeersAndNoDetectedPeer_expectApplyNulls()
      throws ReflectiveOperationException {
    // Arrange
    PeerNodeAddressManager manager = new PeerNodeAddressManager(peer);
    peer.nominalPeer = new CopyOnWriteArrayList<>();

    // Act
    manager.maybeUpdateHandshakeIPs(true);

    // Assert
    verify(peer).applyHandshakeIPs(isNull(), isNull(), isNull());
    assertEquals(0L, getLastAttemptedHandshakeIpUpdateTime(manager));
  }

  @Test
  void maybeUpdateHandshakeIPs_whenNoNominalPeersButDetectedPeer_expectApplyDetectedPeer()
      throws UnknownHostException {
    // Arrange
    PeerNodeAddressManager manager = new PeerNodeAddressManager(peer);
    peer.nominalPeer = new CopyOnWriteArrayList<>();
    Peer detectedPeer = new Peer(inetAddress(203, 0, 113, 10), 1234);
    when(peer.getPeer()).thenReturn(detectedPeer);

    // Act
    manager.maybeUpdateHandshakeIPs(true);

    // Assert
    ArgumentCaptor<Peer[]> handshakeCaptor = ArgumentCaptor.forClass(Peer[].class);
    ArgumentCaptor<Peer> detectedCaptor = ArgumentCaptor.forClass(Peer.class);
    verify(peer).applyHandshakeIPs(handshakeCaptor.capture(), detectedCaptor.capture(), isNull());

    Peer[] applied = handshakeCaptor.getValue();
    assertNotNull(applied);
    assertEquals(1, applied.length);
    assertSame(detectedPeer, applied[0]);
    assertSame(detectedPeer, detectedCaptor.getValue());
  }

  @Test
  void maybeUpdateHandshakeIPs_whenNominalPeersPresent_expectDedupeAndDetectedDuplicate()
      throws ReflectiveOperationException, UnknownHostException {
    // Arrange
    PeerNodeAddressManager manager = new PeerNodeAddressManager(peer);
    setPeerNodeNodeField(peer, node);
    when(peer.getOutgoingMangler()).thenReturn(outgoingMangler);

    InetAddress detectedAddress = inetAddress(203, 0, 113, 10);
    Peer detectedDuplicate = new Peer(detectedAddress, 1111);
    Peer localDetectedPeer = new Peer(detectedAddress, 1111);

    InetAddress matchingAddress = inetAddress(198, 51, 100, 7);
    Peer peerMatchingNode = new Peer(matchingAddress, 2222);
    Peer duplicatePeer = new Peer(matchingAddress, 2222);

    peer.nominalPeer =
        new CopyOnWriteArrayList<>(List.of(detectedDuplicate, peerMatchingNode, duplicatePeer));

    FreenetInetAddress localhost = new FreenetInetAddress(inetAddress(127, 0, 0, 1));
    when(node.network().freenetLocalhostAddress()).thenReturn(localhost);

    Peer[] nodePeers = new Peer[] {new Peer(matchingAddress, 9999)};
    when(outgoingMangler.getPrimaryIPAddress()).thenReturn(nodePeers);
    when(peer.getPeer()).thenReturn(localDetectedPeer);

    // Act
    manager.maybeUpdateHandshakeIPs(true);

    // Assert
    ArgumentCaptor<Peer[]> handshakeCaptor = ArgumentCaptor.forClass(Peer[].class);
    ArgumentCaptor<Peer> detectedCaptor = ArgumentCaptor.forClass(Peer.class);
    ArgumentCaptor<Peer> duplicateCaptor = ArgumentCaptor.forClass(Peer.class);
    verify(peer)
        .applyHandshakeIPs(
            handshakeCaptor.capture(), detectedCaptor.capture(), duplicateCaptor.capture());

    Peer[] applied = handshakeCaptor.getValue();
    assertNotNull(applied);
    assertEquals(3, applied.length);
    assertSame(detectedDuplicate, applied[0]);
    assertSame(peerMatchingNode, applied[1]);
    assertEquals(new Peer(localhost, 2222), applied[2]);

    assertSame(localDetectedPeer, detectedCaptor.getValue());
    assertSame(detectedDuplicate, duplicateCaptor.getValue());
  }

  @Test
  void maybeUpdateHandshakeIPs_whenIgnoreHostnamesFalse_expectTimerUpdated()
      throws ReflectiveOperationException {
    // Arrange
    PeerNodeAddressManager manager = new PeerNodeAddressManager(peer);
    peer.nominalPeer = new CopyOnWriteArrayList<>();
    long before = System.currentTimeMillis();

    // Act
    manager.maybeUpdateHandshakeIPs(false);

    // Assert
    long stored = getLastAttemptedHandshakeIpUpdateTime(manager);
    long after = System.currentTimeMillis();
    assertTrue(stored >= before && stored <= after);
  }

  @Test
  void getHandshakeIP_whenShouldSendHandshakeFalse_expectNull() {
    // Arrange
    when(peer.shouldSendHandshake()).thenReturn(false);
    PeerNodeAddressManager manager = new PeerNodeAddressManager(peer);

    // Act
    Peer result = manager.getHandshakeIP();

    // Assert
    assertNull(result);
  }

  @Test
  void getHandshakeIP_whenHandshakeIpsNull_expectNull() {
    // Arrange
    when(peer.shouldSendHandshake()).thenReturn(true);
    when(peer.getHandshakeIPs()).thenReturn(null);
    PeerNodeAddressManager manager = new PeerNodeAddressManager(peer);

    // Act
    Peer result = manager.getHandshakeIP();

    // Assert
    assertNull(result);
  }

  @Test
  void getHandshakeIP_whenCandidateMissingAddress_expectNull() {
    // Arrange
    Peer candidate = Mockito.mock(Peer.class);
    when(candidate.getAddress(false)).thenReturn(null);
    when(peer.shouldSendHandshake()).thenReturn(true);
    when(peer.getHandshakeIPs()).thenReturn(new Peer[] {candidate});
    when(peer.allowLocalAddresses()).thenReturn(true);
    PeerNodeAddressManager manager = new PeerNodeAddressManager(peer);

    // Act
    Peer result = manager.getHandshakeIP();

    // Assert
    assertNull(result);
  }

  @Test
  void getHandshakeIP_whenCandidateBlockedByPolicy_expectNull() throws UnknownHostException {
    // Arrange
    InetAddress address = inetAddress(203, 0, 113, 11);
    Peer candidate = createValidCandidate(address, true);
    FreenetInetAddress freenetAddress = candidate.getFreenetAddress();

    when(peer.shouldSendHandshake()).thenReturn(true);
    when(peer.getHandshakeIPs()).thenReturn(new Peer[] {candidate});
    when(peer.allowLocalAddresses()).thenReturn(true);
    when(peer.isConnected()).thenReturn(false);
    when(peer.getOutgoingMangler()).thenReturn(outgoingMangler);
    when(peer.selfPeerNode()).thenReturn(peer);
    when(outgoingMangler.allowConnection(peer, freenetAddress)).thenReturn(false);
    PeerNodeAddressManager manager = new PeerNodeAddressManager(peer);

    // Act
    Peer result = manager.getHandshakeIP();

    // Assert
    assertNull(result);
    verify(outgoingMangler).allowConnection(peer, freenetAddress);
  }

  @Test
  void getHandshakeIP_whenConnected_expectCandidate() throws UnknownHostException {
    // Arrange
    InetAddress address = inetAddress(203, 0, 113, 12);
    Peer candidate = createValidCandidate(address, false);

    when(peer.shouldSendHandshake()).thenReturn(true);
    when(peer.getHandshakeIPs()).thenReturn(new Peer[] {candidate});
    when(peer.allowLocalAddresses()).thenReturn(false);
    when(peer.isConnected()).thenReturn(true);
    PeerNodeAddressManager manager = new PeerNodeAddressManager(peer);

    // Act
    Peer result = manager.getHandshakeIP();

    // Assert
    assertSame(candidate, result);
  }

  @Test
  void getHandshakeIP_whenMultipleValidCandidates_expectAlternating() throws UnknownHostException {
    // Arrange
    Peer first = createValidCandidate(inetAddress(203, 0, 113, 13), false);
    Peer second = createValidCandidate(inetAddress(203, 0, 113, 14), false);

    when(peer.shouldSendHandshake()).thenReturn(true);
    when(peer.getHandshakeIPs()).thenReturn(new Peer[] {first, second});
    when(peer.allowLocalAddresses()).thenReturn(false);
    when(peer.isConnected()).thenReturn(true);
    PeerNodeAddressManager manager = new PeerNodeAddressManager(peer);

    // Act
    Peer firstResult = manager.getHandshakeIP();
    Peer secondResult = manager.getHandshakeIP();
    Peer thirdResult = manager.getHandshakeIP();

    // Assert
    assertSame(first, firstResult);
    assertSame(second, secondResult);
    assertSame(first, thirdResult);
  }

  @Test
  void matchesIP_whenStrictAndHostnameOnly_expectFalse()
      throws ReflectiveOperationException, UnknownHostException {
    // Arrange
    InetAddress resolved = inetAddress(192, 0, 2, 44);
    FreenetInetAddress hostnameAddress = new FreenetInetAddress("example.invalid", true);
    setFreenetInetAddressResolved(hostnameAddress, resolved);

    Peer hostPeer = new Peer(hostnameAddress, 1234);
    PeerNode peerNode = Mockito.mock(PeerNode.class, Mockito.CALLS_REAL_METHODS);
    Mockito.doReturn(hostPeer).when(peerNode).getPeer();

    FreenetInetAddress ipAddress = new FreenetInetAddress(resolved);

    // Act
    boolean result = PeerNodeAddressManager.matchesIP(peerNode, ipAddress, true);

    // Assert
    assertFalse(result);
  }

  @Test
  void matchesIP_whenNonStrictAndHostnameMatchesResolvedIp_expectTrue()
      throws ReflectiveOperationException, UnknownHostException {
    // Arrange
    InetAddress resolved = inetAddress(192, 0, 2, 45);
    FreenetInetAddress hostnameAddress = new FreenetInetAddress("example.invalid", true);
    setFreenetInetAddressResolved(hostnameAddress, resolved);

    Peer hostPeer = new Peer(hostnameAddress, 1234);
    PeerNode peerNode = Mockito.mock(PeerNode.class, Mockito.CALLS_REAL_METHODS);
    Mockito.doReturn(hostPeer).when(peerNode).getPeer();

    FreenetInetAddress ipAddress = new FreenetInetAddress(resolved);

    // Act
    boolean result = PeerNodeAddressManager.matchesIP(peerNode, ipAddress, false);

    // Assert
    assertTrue(result);
  }

  @Test
  void matchesIP_whenNominalPeerMatches_expectTrue() throws UnknownHostException {
    // Arrange
    InetAddress address = inetAddress(198, 51, 100, 9);
    Peer nominal = new Peer(address, 2468);
    PeerNode peerNode = Mockito.mock(PeerNode.class, Mockito.CALLS_REAL_METHODS);
    peerNode.nominalPeer = new CopyOnWriteArrayList<>(List.of(nominal));
    Mockito.doReturn(null).when(peerNode).getPeer();

    FreenetInetAddress matchAddress = new FreenetInetAddress(address);

    // Act
    boolean result = PeerNodeAddressManager.matchesIP(peerNode, matchAddress, true);

    // Assert
    assertTrue(result);
  }

  @Test
  void matchesIP_whenNoMatch_expectFalse() throws UnknownHostException {
    // Arrange
    InetAddress address = inetAddress(198, 51, 100, 10);
    Peer nominal = new Peer(address, 2468);
    PeerNode peerNode = Mockito.mock(PeerNode.class, Mockito.CALLS_REAL_METHODS);
    peerNode.nominalPeer = new CopyOnWriteArrayList<>(List.of(nominal));
    Mockito.doReturn(null).when(peerNode).getPeer();

    FreenetInetAddress otherAddress = new FreenetInetAddress(inetAddress(203, 0, 113, 99));

    // Act
    boolean result = PeerNodeAddressManager.matchesIP(peerNode, otherAddress, true);

    // Assert
    assertFalse(result);
  }

  @Test
  void shouldThrottle_whenNodeThrottlesLocalData_expectTrue() {
    // Arrange
    when(node.network().isThrottleLocalData()).thenReturn(true);

    // Act
    boolean result = PeerNodeAddressManager.shouldThrottle(null, node);

    // Assert
    assertTrue(result);
  }

  @Test
  void shouldThrottle_whenPeerNull_expectTrue() {
    // Arrange
    when(node.network().isThrottleLocalData()).thenReturn(false);

    // Act
    boolean result = PeerNodeAddressManager.shouldThrottle(null, node);

    // Assert
    assertTrue(result);
  }

  @Test
  void shouldThrottle_whenPeerAddressNull_expectTrue() {
    // Arrange
    Peer throttledPeer = Mockito.mock(Peer.class);
    when(node.network().isThrottleLocalData()).thenReturn(false);
    when(throttledPeer.getAddress(false)).thenReturn(null);

    // Act
    boolean result = PeerNodeAddressManager.shouldThrottle(throttledPeer, node);

    // Assert
    assertTrue(result);
  }

  @Test
  void shouldThrottle_whenPeerAddressIsLocal_expectFalse() throws UnknownHostException {
    // Arrange
    Peer throttledPeer = new Peer(inetAddress(127, 0, 0, 1), 1111);
    when(node.network().isThrottleLocalData()).thenReturn(false);

    // Act
    boolean result = PeerNodeAddressManager.shouldThrottle(throttledPeer, node);

    // Assert
    assertFalse(result);
  }

  @Test
  void shouldThrottle_whenPeerAddressIsPublic_expectTrue() throws UnknownHostException {
    // Arrange
    Peer throttledPeer = new Peer(inetAddress(8, 8, 8, 8), 1111);
    when(node.network().isThrottleLocalData()).thenReturn(false);

    // Act
    boolean result = PeerNodeAddressManager.shouldThrottle(throttledPeer, node);

    // Assert
    assertTrue(result);
  }

  @Test
  void parseDetectedPeer_whenMetadataMissing_expectNull() {
    // Arrange
    PeerNodeAddressManager manager = new PeerNodeAddressManager(peer);
    SimpleFieldSet metadata = new SimpleFieldSet(true);

    // Act
    Peer result = manager.parseDetectedPeer(metadata);

    // Assert
    assertNull(result);
  }

  @Test
  void parseDetectedPeer_whenValidDetectedUdp_expectPeerParsed() throws UnknownHostException {
    // Arrange
    PeerNodeAddressManager manager = new PeerNodeAddressManager(peer);
    SimpleFieldSet metadata = new SimpleFieldSet(true);
    metadata.putSingle("detected.udp", "203.0.113.7:1234");

    // Act
    Peer result = manager.parseDetectedPeer(metadata);

    // Assert
    assertNotNull(result);
    assertEquals(1234, result.getPort());
    assertEquals(inetAddress(203, 0, 113, 7), result.getAddress(false));
  }

  @Test
  void parseDetectedPeer_whenInvalidDetectedUdp_expectNull() {
    // Arrange
    PeerNodeAddressManager manager = new PeerNodeAddressManager(peer);
    SimpleFieldSet metadata = new SimpleFieldSet(true);
    metadata.putSingle("detected.udp", "invalid");

    // Act
    Peer result = manager.parseDetectedPeer(metadata);

    // Assert
    assertNull(result);
  }

  private static Peer createValidCandidate(InetAddress address, boolean allowLocalAddresses) {
    Peer candidate = Mockito.mock(Peer.class);
    FreenetInetAddress freenetAddress = new FreenetInetAddress(address);
    when(candidate.getAddress(false)).thenReturn(address);
    when(candidate.getFreenetAddress()).thenReturn(freenetAddress);
    when(candidate.isRealInternetAddress(false, false, allowLocalAddresses)).thenReturn(true);
    return candidate;
  }

  private static InetAddress inetAddress(int... octets) throws UnknownHostException {
    byte[] bytes = new byte[octets.length];
    for (int i = 0; i < octets.length; i++) {
      bytes[i] = (byte) octets[i];
    }
    return InetAddress.getByAddress(bytes);
  }

  @SuppressWarnings("java:S3011")
  private static void setPeerNodeNodeField(PeerNode target, Node value)
      throws ReflectiveOperationException {
    Field field = PeerNode.class.getDeclaredField("node");
    field.setAccessible(true);
    field.set(target, value);
  }

  @SuppressWarnings("java:S3011")
  private static void setFreenetInetAddressResolved(FreenetInetAddress address, InetAddress value)
      throws ReflectiveOperationException {
    Field field = FreenetInetAddress.class.getDeclaredField("address");
    field.setAccessible(true);
    field.set(address, value);
  }

  @SuppressWarnings("java:S3011")
  private static long getLastAttemptedHandshakeIpUpdateTime(PeerNodeAddressManager manager)
      throws ReflectiveOperationException {
    Field field =
        PeerNodeAddressManager.class.getDeclaredField("lastAttemptedHandshakeIPUpdateTime");
    field.setAccessible(true);
    return field.getLong(manager);
  }

  @SuppressWarnings("java:S3011")
  private static void setLastAttemptedHandshakeIpUpdateTime(
      PeerNodeAddressManager manager, long value) throws ReflectiveOperationException {
    Field field =
        PeerNodeAddressManager.class.getDeclaredField("lastAttemptedHandshakeIPUpdateTime");
    field.setAccessible(true);
    field.setLong(manager, value);
  }
}

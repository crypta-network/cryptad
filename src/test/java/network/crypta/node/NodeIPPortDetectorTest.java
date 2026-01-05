package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.InetAddress;
import java.net.UnknownHostException;
import network.crypta.io.comm.FreenetInetAddress;
import network.crypta.io.comm.Peer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class NodeIPPortDetectorTest {

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private NodeIPDetector ipDetector;
  @Mock private NodeCrypto crypto;
  @Mock private NodeCryptoConfig cryptoConfig;

  private NodeIPPortDetector detector;

  @BeforeEach
  void setUp() {
    // Common, safe default wiring
    lenient().when(crypto.getConfig()).thenReturn(cryptoConfig);
    detector = new NodeIPPortDetector(node, ipDetector, crypto, /* enableARKs= */ false);
  }

  @Test
  @DisplayName("constructor_whenCreated_registersWithIpDetector")
  void constructor_whenCreated_registersWithIpDetector() {
    verify(ipDetector, times(1)).addPortDetector(detector);
  }

  @Test
  @DisplayName("detectPrimaryIPAddress_whenBindToIsPublic_returnsOnlyBindTo")
  void detectPrimaryIPAddress_whenBindToIsPublic_returnsOnlyBindTo() throws Exception {
    FreenetInetAddress bindTo = ip("198.51.100.1");
    when(crypto.getBindTo()).thenReturn(bindTo);

    FreenetInetAddress[] out = detector.detectPrimaryIPAddress();

    assertArrayEquals(new FreenetInetAddress[] {bindTo}, out);
  }

  @Test
  @DisplayName("detectPrimaryIPAddress_whenBindToIsWildcard_delegatesToIpDetector_invertsFlagTrue")
  void detectPrimaryIPAddress_whenBindToIsWildcard_delegatesToIpDetector_invertsFlagTrue()
      throws Exception {
    // Arrange: bind to wildcard so primary path delegates to ipDetector
    when(crypto.getBindTo()).thenReturn(ip("0.0.0.0"));
    // includeLocalAddressesInNoderefs() = true ⇒ detector should pass false
    when(cryptoConfig.includeLocalAddressesInNoderefs()).thenReturn(true);
    FreenetInetAddress[] expected = new FreenetInetAddress[] {ip("203.0.113.10")};
    when(ipDetector.detectPrimaryIPAddress(false)).thenReturn(expected);

    // Act
    FreenetInetAddress[] out = detector.detectPrimaryIPAddress();

    // Assert
    assertArrayEquals(expected, out);
    verify(ipDetector, times(1)).detectPrimaryIPAddress(false);
  }

  @Test
  @DisplayName("detectPrimaryIPAddress_whenBindToIsWildcard_delegatesToIpDetector_invertsFlagFalse")
  void detectPrimaryIPAddress_whenBindToIsWildcard_delegatesToIpDetector_invertsFlagFalse()
      throws Exception {
    when(crypto.getBindTo()).thenReturn(ip("0.0.0.0"));
    // includeLocalAddressesInNoderefs() = false ⇒ detector should pass true
    when(cryptoConfig.includeLocalAddressesInNoderefs()).thenReturn(false);
    FreenetInetAddress[] expected = new FreenetInetAddress[] {ip("198.51.100.55")};
    when(ipDetector.detectPrimaryIPAddress(true)).thenReturn(expected);

    FreenetInetAddress[] out = detector.detectPrimaryIPAddress();

    assertArrayEquals(expected, out);
    verify(ipDetector, times(1)).detectPrimaryIPAddress(true);
  }

  @Test
  @DisplayName("detectPrimaryPeers_whenNoPeerNodes_returnsPrimaryWithOurPort")
  void detectPrimaryPeers_whenNoPeerNodes_returnsPrimaryWithOurPort() throws Exception {
    when(crypto.getBindTo()).thenReturn(ip("198.51.100.20"));
    when(crypto.getPortNumber()).thenReturn(12345);
    when(crypto.getPeerNodes()).thenReturn(null);

    Peer[] peers = detector.detectPrimaryPeers();

    assertEquals(1, peers.length);
    assertEquals(new Peer(ip("198.51.100.20"), 12345), peers[0]);
  }

  @Test
  @DisplayName("detectPrimaryPeers_whenPeersAgree_addsDetectedPeerOnce")
  void detectPrimaryPeers_whenPeersAgree_addsDetectedPeerOnce() throws Exception {
    // Primary address contributes one peer at our listen port
    when(crypto.getBindTo()).thenReturn(ip("198.51.100.30"));
    when(crypto.getPortNumber()).thenReturn(11111);

    // Two peer nodes both reporting the same external Peer for us
    Peer reported = new Peer(ip("203.0.113.5"), 54321);
    PeerNode pn1 = mock(PeerNode.class);
    when(pn1.getRemoteDetectedPeer()).thenReturn(reported);
    PeerNode pn2 = mock(PeerNode.class);
    when(pn2.getRemoteDetectedPeer()).thenReturn(reported);
    when(crypto.getPeerNodes()).thenReturn(new PeerNode[] {pn1, pn2});

    Peer[] peers = detector.detectPrimaryPeers();

    assertEquals(2, peers.length);
    assertEquals(new Peer(ip("198.51.100.30"), 11111), peers[0]);
    assertEquals(reported, peers[1]);
  }

  @Test
  @DisplayName("detectPrimaryPeers_whenMultipleVotes_addsBestOnlyWhenSecondNotPopular")
  void detectPrimaryPeers_whenMultipleVotes_addsBestOnlyWhenSecondNotPopular() throws Exception {
    when(crypto.getBindTo()).thenReturn(ip("198.51.100.40"));
    when(crypto.getPortNumber()).thenReturn(15000);

    Peer best = new Peer(ip("203.0.113.10"), 60000);
    Peer second = new Peer(ip("203.0.113.20"), 60001);
    // Popularity: best=3, second=1
    PeerNode p1 = pnWithDetected(best);
    PeerNode p2 = pnWithDetected(best);
    PeerNode p3 = pnWithDetected(best);
    PeerNode p4 = pnWithDetected(second);
    when(crypto.getPeerNodes()).thenReturn(new PeerNode[] {p1, p2, p3, p4});

    Peer[] peers = detector.detectPrimaryPeers();

    assertEquals(2, peers.length);
    assertEquals(new Peer(ip("198.51.100.40"), 15000), peers[0]);
    assertEquals(best, peers[1]);
  }

  @Test
  @DisplayName("detectPrimaryPeers_whenTwoPopular_alwaysIncludesBest_mayIncludeSecond")
  void detectPrimaryPeers_whenTwoPopular_alwaysIncludesBest_mayIncludeSecond() throws Exception {
    when(crypto.getBindTo()).thenReturn(ip("198.51.100.60"));
    when(crypto.getPortNumber()).thenReturn(44444);

    Peer best = new Peer(ip("203.0.113.100"), 50000);
    Peer second = new Peer(ip("203.0.113.101"), 50001);
    // Popularity: best=4, second=2 (>1). Iteration order of HashMap is unspecified, so assert
    // invariants: primary first, best present, optional second present.
    PeerNode[] nodes =
        new PeerNode[] {
          pnWithDetected(best),
          pnWithDetected(best),
          pnWithDetected(best),
          pnWithDetected(best),
          pnWithDetected(second),
          pnWithDetected(second)
        };
    when(crypto.getPeerNodes()).thenReturn(nodes);

    Peer[] peers = detector.detectPrimaryPeers();

    assertTrue(peers.length == 2 || peers.length == 3);
    assertEquals(new Peer(ip("198.51.100.60"), 44444), peers[0]);
    assertTrue(containsPeer(peers, best));
  }

  @Test
  @DisplayName("detectPrimaryPeers_whenDetectedEqualsPrimary_doesNotDuplicate")
  void detectPrimaryPeers_whenDetectedEqualsPrimary_doesNotDuplicate() throws Exception {
    when(crypto.getBindTo()).thenReturn(ip("198.51.100.200"));
    when(crypto.getPortNumber()).thenReturn(60000);

    Peer same = new Peer(ip("198.51.100.200"), 60000);
    PeerNode only = pnWithDetected(same);
    when(crypto.getPeerNodes()).thenReturn(new PeerNode[] {only});

    Peer[] peers = detector.detectPrimaryPeers();

    assertEquals(1, peers.length);
    assertEquals(same, peers[0]);
  }

  @Test
  @DisplayName("getPrimaryPeers_whenCached_returnsSameArrayInstance")
  void getPrimaryPeers_whenCached_returnsSameArrayInstance() throws Exception {
    when(crypto.getBindTo()).thenReturn(ip("198.51.100.70"));
    when(crypto.getPortNumber()).thenReturn(55555);
    when(crypto.getPeerNodes()).thenReturn(null);

    // First call populates lastPeers
    Peer[] first = detector.detectPrimaryPeers();
    // getPrimaryPeers should return the exact same array instance
    Peer[] second = detector.getPrimaryPeers();

    assertSame(first, second);
  }

  @Test
  @DisplayName("includes_whenAddressInPrimaryIPs_returnsTrue; otherwiseFalse")
  void includes_whenAddressInPrimaryIPs_returnsTrueOtherwiseFalse() throws Exception {
    // Force delegation to ipDetector by using wildcard bindTo
    when(crypto.getBindTo()).thenReturn(ip("0.0.0.0"));
    when(crypto.getConfig()).thenReturn(cryptoConfig);
    when(cryptoConfig.includeLocalAddressesInNoderefs()).thenReturn(false);

    FreenetInetAddress a = ip("198.51.100.80");
    FreenetInetAddress b = ip("198.51.100.81");
    when(ipDetector.detectPrimaryIPAddress(true)).thenReturn(new FreenetInetAddress[] {a});

    assertTrue(detector.includes(a));
    assertFalse(detector.includes(b));
  }

  private static FreenetInetAddress ip(String addr) throws UnknownHostException {
    return new FreenetInetAddress(InetAddress.getByName(addr));
  }

  private static PeerNode pnWithDetected(Peer p) {
    PeerNode pn = mock(PeerNode.class);
    when(pn.getRemoteDetectedPeer()).thenReturn(p);
    return pn;
  }

  private static boolean containsPeer(Peer[] arr, Peer p) {
    for (Peer it : arr) {
      if (p.equals(it)) return true;
    }
    return false;
  }
}

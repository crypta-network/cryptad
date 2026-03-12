package network.crypta.node;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.Peer;
import network.crypta.node.DarknetPeerNode.FRIEND_TRUST;
import network.crypta.node.DarknetPeerNode.FRIEND_VISIBILITY;
import network.crypta.node.subsystem.NodeBootstrap;
import network.crypta.node.subsystem.NodeNetworkSubsystem;
import network.crypta.support.Base64;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.math.MersenneTwister;
import org.junit.jupiter.api.BeforeEach;
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
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class DarknetPeerNodeTest {

  @Mock private Node mockNode;
  @Mock private NodeBootstrap bootstrap;
  @Mock private NodeNetworkSubsystem network;
  @Mock private NodeCrypto mockCrypto;
  @Mock private FNPPacketMangler mockMangler;
  @Mock private PeerManager mockPeers;

  @BeforeEach
  void setupCommonStubs() {
    // Deterministic PRNG used by PeerNode
    when(mockNode.bootstrap()).thenReturn(bootstrap);
    when(bootstrap.createRandom()).thenReturn(new MersenneTwister(123456789L));
    when(mockNode.getBootId()).thenReturn(1L);
    when(mockNode.network()).thenReturn(network);
    when(network.peers()).thenReturn(mockPeers);
    // Avoid ARK side effects in setters (setListenOnly/disablePeer)
    when(mockNode.isEnableARKs()).thenReturn(false);

    when(mockCrypto.isOpennet()).thenReturn(false);
    when(mockCrypto.getPacketMangler()).thenReturn(mockMangler);
    // Default: super.allowLocalAddresses() returns false unless we override
    when(mockMangler.alwaysAllowLocalAddresses()).thenReturn(false);

    // Minimal identity hash material used to derive setup keys in PeerNode
    byte[] ih = new byte[32];
    byte[] ihh = new byte[32];
    for (int i = 0; i < ih.length; i++) {
      ih[i] = (byte) i;
      ihh[i] = (byte) (i ^ 0xA5);
    }
    when(mockCrypto.getIdentityHash()).thenReturn(ih);
    when(mockCrypto.getIdentityHashHash()).thenReturn(ihh);
  }

  // --- Enum behavior ---

  @Test
  void friendTrust_valuesBackwards_returnsReversedCopy() {
    FRIEND_TRUST[] expected = FRIEND_TRUST.values();
    FRIEND_TRUST[] reversed = FRIEND_TRUST.valuesBackwards();

    FRIEND_TRUST[] calc = expected.clone();
    for (int i = 0, j = calc.length - 1; i < j; i++, j--) {
      FRIEND_TRUST tmp = calc[i];
      calc[i] = calc[j];
      calc[j] = tmp;
    }

    assertArrayEquals(calc, reversed, "valuesBackwards must be reverse order");
    assertNotSame(reversed, expected, "must return a defensive copy, not the original array");
  }

  @Test
  void friendTrust_isDefaultValue_trueOnlyForNormal() {
    assertFalse(FRIEND_TRUST.LOW.isDefaultValue());
    assertTrue(FRIEND_TRUST.NORMAL.isDefaultValue());
    assertFalse(FRIEND_TRUST.HIGH.isDefaultValue());
  }

  @Test
  void friendVisibility_getByCode_and_defaults_and_strictness() {
    assertEquals(FRIEND_VISIBILITY.YES, FRIEND_VISIBILITY.getByCode((short) 0));
    assertEquals(FRIEND_VISIBILITY.NAME_ONLY, FRIEND_VISIBILITY.getByCode((short) 1));
    assertEquals(FRIEND_VISIBILITY.NO, FRIEND_VISIBILITY.getByCode((short) 2));
    assertNull(FRIEND_VISIBILITY.getByCode((short) 42));

    // Defaults
    assertTrue(FRIEND_VISIBILITY.YES.isDefaultValue());
    assertFalse(FRIEND_VISIBILITY.NAME_ONLY.isDefaultValue());
    assertFalse(FRIEND_VISIBILITY.NO.isDefaultValue());

    // Strictness ordering: higher code => stricter
    assertTrue(FRIEND_VISIBILITY.NAME_ONLY.isStricterThan(FRIEND_VISIBILITY.YES));
    assertTrue(FRIEND_VISIBILITY.NO.isStricterThan(FRIEND_VISIBILITY.NAME_ONLY));
    assertTrue(FRIEND_VISIBILITY.NO.isStricterThan(FRIEND_VISIBILITY.YES));
  }

  // --- Node behavior ---

  @Test
  void getPeer_whenIgnoreSourcePort_returnsPeerWithSameIPDifferentPort() throws Exception {
    DarknetPeerNode node = newPeer("Alice", new String[] {"192.0.2.1:1000", "192.0.2.1:2000"});

    node.setIgnoreSourcePort(true);

    Peer p = node.getPeer();
    assertNotNull(p);
    assertEquals(2000, p.getPort(), "should switch to same IP but different port");
  }

  @Test
  void allowLocalAddresses_whenOverridden_returnsTrueAndPersists() throws Exception {
    DarknetPeerNode node = newPeer("Bob", new String[] {"192.0.2.2:3456"});

    // Baseline inherits from outgoing mangler (stubbed false)
    assertFalse(node.allowLocalAddresses());

    node.setAllowLocalAddresses(true);

    assertTrue(node.allowLocalAddresses());
    verify(mockPeers, atLeastOnce()).writePeersDarknetUrgent();
  }

  @Test
  void setListenOnly_whenBurstOnlyAlready_true_clearsBurstOnly() throws Exception {
    DarknetPeerNode node = newPeer("Carol", new String[] {"192.0.2.3:4444"});

    node.setBurstOnly(true);
    assertTrue(node.isBurstOnly());

    node.setListenOnly(true);

    assertTrue(node.isListenOnly());
    assertFalse(node.isBurstOnly());
    verify(mockPeers, atLeastOnce()).writePeersDarknetUrgent();
  }

  @Test
  void visibility_whenTheirIsStricter_returnsTheirVisibility() throws Exception {
    DarknetPeerNode node = newPeer("Dave", new String[] {"192.0.2.4:5555"});

    // Baseline from constructor metadata
    assertEquals(FRIEND_VISIBILITY.YES, node.getOurVisibility());

    // Simulate peer saying NO (stricter)
    Message m = mock(Message.class);
    when(m.getShort(org.mockito.ArgumentMatchers.anyString()))
        .thenReturn(FRIEND_VISIBILITY.NO.code);
    node.handleVisibility(m);

    assertEquals(FRIEND_VISIBILITY.NO, node.getTheirVisibility());
    assertEquals(FRIEND_VISIBILITY.NO, node.getVisibility());
    verify(mockPeers, times(1)).writePeersDarknet();
  }

  @Test
  void exportFieldSet_includesMyName() throws Exception {
    DarknetPeerNode node = newPeer("Erin", new String[] {"192.0.2.10:6000"});

    SimpleFieldSet fs = node.exportFieldSet();
    assertEquals("Erin", fs.get("myName"));
  }

  @Test
  void shouldSendHandshake_whenDisabledOrListenOnly_returnsFalse() throws Exception {
    DarknetPeerNode node = newPeer("Frank", new String[] {"192.0.2.11:7000"});

    node.disablePeer();
    assertTrue(node.isDisabled());
    assertFalse(node.shouldSendHandshake());

    node.enablePeer();
    assertFalse(node.isDisabled());

    node.setListenOnly(true);
    assertTrue(node.isListenOnly());
    assertFalse(node.shouldSendHandshake());
  }

  @Test
  void parse_physicalUdp_comma_hosts_with_shared_port() throws Exception {
    SimpleFieldSet sfs =
        minimalDarknetNoderef("CompatA", new String[] {"198.51.100.10,2001:db8::1:4711"});
    DarknetPeerNode pn =
        new DarknetPeerNode(
            sfs, mockNode, mockCrypto, true, FRIEND_TRUST.NORMAL, FRIEND_VISIBILITY.YES, mockPeers);

    SimpleFieldSet out = pn.exportFieldSet();
    java.util.Set<String> all =
        new java.util.HashSet<>(java.util.Arrays.asList(out.getAll("physical.udp")));
    assertTrue(all.contains("198.51.100.10:4711"), "actual=" + all);
    assertTrue(all.contains("2001:db8:0:0:0:0:0:1:4711"), "actual=" + all);
  }

  @Test
  void parse_physicalUdp_comma_separated_full_entries() throws Exception {
    SimpleFieldSet sfs =
        minimalDarknetNoderef("CompatB", new String[] {"198.51.100.11:14444,2001:db8::2:14444"});
    DarknetPeerNode pn =
        new DarknetPeerNode(
            sfs, mockNode, mockCrypto, true, FRIEND_TRUST.NORMAL, FRIEND_VISIBILITY.YES, mockPeers);

    SimpleFieldSet out = pn.exportFieldSet();
    java.util.Set<String> all =
        new java.util.HashSet<>(java.util.Arrays.asList(out.getAll("physical.udp")));
    assertTrue(all.contains("198.51.100.11:14444"), "actual=" + all);
    assertTrue(all.contains("2001:db8:0:0:0:0:0:2:14444"), "actual=" + all);
  }

  // --- Helpers ---

  private DarknetPeerNode newPeer(String name, String[] addresses) throws Exception {
    SimpleFieldSet fs = minimalDarknetNoderef(name, addresses);
    // fromLocal = true so unsigned and with local metadata; trust/visibility parameters are ignored
    return new DarknetPeerNode(
        fs, mockNode, mockCrypto, true, FRIEND_TRUST.NORMAL, FRIEND_VISIBILITY.YES, mockPeers);
  }

  private static SimpleFieldSet minimalDarknetNoderef(String myName, String[] addresses)
      throws Exception {
    SimpleFieldSet fs = new SimpleFieldSet(true);

    // Required top-level noderef fields
    fs.putSingle("version", "Cryptad,1,1.0");
    fs.putSingle("location", "0.50");
    fs.put("opennet", false);

    // Negotiation types present to avoid constructor fallback
    // Represent multivalued ints as separate appended values
    fs.putAppend("auth.negTypes", "1");
    fs.putAppend("auth.negTypes", "2");

    // Identity: 32 bytes -> Base64
    byte[] identity = new byte[32];
    for (int i = 0; i < identity.length; i++) identity[i] = (byte) (0x80 + i);
    fs.putSingle("identity", Base64.encode(identity));

    // At least one physical.udp address
    Arrays.stream(addresses).forEach(addr -> fs.putAppend("physical.udp", addr));

    // ECDSA P-256 public key in X.509 SubjectPublicKeyInfo encoding
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
    kpg.initialize(new ECGenParameterSpec("secp256r1"));
    KeyPair kp = kpg.generateKeyPair();
    String pubB64 = Base64.encode(kp.getPublic().getEncoded());
    fs.putSingle("ecdsa.P256.pub", pubB64);

    // Darknet-specific extras
    fs.putSingle("myName", myName);

    // Local metadata (constructor reads these when fromLocal=true)
    fs.putSingle("metadata.trustLevel", FRIEND_TRUST.NORMAL.name());
    fs.putSingle("metadata.ourVisibility", FRIEND_VISIBILITY.YES.name());
    fs.putSingle("metadata.theirVisibility", FRIEND_VISIBILITY.YES.name());

    return fs;
  }
}

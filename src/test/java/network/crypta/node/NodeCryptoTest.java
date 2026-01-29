package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.anyBoolean;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.reflect.Field;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.List;
import network.crypta.crypt.EntropySource;
import network.crypta.crypt.RandomSource;
import network.crypta.crypt.SHA256;
import network.crypta.crypt.UnsupportedCipherException;
import network.crypta.crypt.ciphers.Rijndael;
import network.crypta.io.AddressTracker.Status;
import network.crypta.io.comm.FreenetInetAddress;
import network.crypta.io.comm.Peer;
import network.crypta.io.comm.UdpSocketHandler;
import network.crypta.support.Base64;
import network.crypta.support.SimpleFieldSet;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.objenesis.ObjenesisStd;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@SuppressWarnings("java:S100")
class NodeCryptoTest {

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @BeforeEach
  void setup() {
    DeterministicRandom detRand = new DeterministicRandom(0x1234ABCDL);
    when(node.getRandom()).thenReturn(detRand);
  }

  // ---------- helpers ----------
  private static NodeCrypto bare(Node node, boolean opennet) {
    NodeCrypto nc = new ObjenesisStd().newInstance(NodeCrypto.class);
    setField(nc, "node", node);
    setField(nc, "isOpennet", opennet);
    setField(nc, "random", new DeterministicRandom(0xCAFEFEEDL));
    setField(nc, "config", mock(NodeCryptoConfig.class));
    setField(nc, "socket", mock(UdpSocketHandler.class));
    setField(nc, "packetMangler", mock(FNPPacketMangler.class));
    setField(nc, "detector", mock(NodeIPPortDetector.class));
    try {
      setField(nc, "anonSetupCipher", new Rijndael(256, 256));
    } catch (UnsupportedCipherException e) {
      throw new RuntimeException(e);
    }
    // Needed for synchronized section inside exportPublicFieldSet
    setField(nc, "referenceSync", new Object());
    return nc;
  }

  private static void setField(Object target, String name, Object value) {
    try {
      Field f = target.getClass().getDeclaredField(name);
      f.setAccessible(true);
      f.set(target, value);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  static class DeterministicRandom extends RandomSource {
    private final java.util.Random inner;

    DeterministicRandom(long seed) {
      this.inner = new java.util.Random(seed);
    }

    @Override
    public int acceptEntropy(EntropySource source, long data, int entropyGuess) {
      return 0;
    }

    @Override
    public int acceptTimerEntropy(EntropySource timer) {
      return 0;
    }

    @Override
    public int acceptTimerEntropy(EntropySource fnpTimingSource, double bias) {
      return 0;
    }

    @Override
    public int acceptEntropyBytes(
        EntropySource myPacketDataSource, byte[] buf, int offset, int length, double bias) {
      return 0;
    }

    @Override
    public void close() {
      // Intentionally empty: this deterministic test RNG holds no external
      // resources and requires no shutdown. Added to satisfy empty-method lint.
    }

    @Override
    protected synchronized int next(int bits) {
      // Delegate to a local deterministic PRNG
      return inner.nextInt() >>> (32 - bits);
    }
  }

  // ---------- tests ----------

  @Test
  void initCrypto_generatesExpectedFields() {
    NodeCrypto nc = bare(node, true);

    nc.initCrypto();

    // ECDSA keys exist and hash matches the public key bytes
    ECPublicKey pub = nc.getECDSAP256Pubkey();
    assertNotNull(pub, "ECDSA public key must be initialized");
    assertArrayEquals(SHA256.digest(pub.getEncoded()), nc.getEcdsaPubKeyHash());

    // ARK and nonce/identity derived
    assertNotNull(nc.getMyARK(), "ARK must be initialized");
    assertEquals(0L, nc.getMyARKNumber(), "ARK sequence should start at 0");
    assertNotNull(nc.getAnonSetupCipher(), "Anon setup cipher must be initialized");

    assertNotNull(nc.getMyIdentity());
    assertEquals(NodeCrypto.IDENTITY_LENGTH, nc.getMyIdentity().length);
    assertArrayEquals(SHA256.digest(nc.getMyIdentity()), nc.getIdentityHash());
    assertArrayEquals(SHA256.digest(nc.getIdentityHash()), nc.getIdentityHashHash());
  }

  @Test
  void readCrypto_whenMissingIdentity_throwsIOException() {
    NodeCrypto nc = bare(node, false);
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    assertThrows(java.io.IOException.class, () -> nc.readCrypto(sfs));
  }

  @Test
  void readCrypto_whenInvalidIdentityBase64_throwsIOException() {
    NodeCrypto nc = bare(node, false);
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    sfs.putSingle("identity", "%not-base64%");
    assertThrows(java.io.IOException.class, () -> nc.readCrypto(sfs));
  }

  @Test
  void readCrypto_validWithoutEcdsa_generatesKeyAndSetsHashesAndNonce() throws Exception {
    NodeCrypto nc = bare(node, true);

    byte[] identity = new byte[NodeCrypto.IDENTITY_LENGTH];
    for (int i = 0; i < identity.length; i++) identity[i] = (byte) i;
    String identityB64 = Base64.encode(identity);

    SimpleFieldSet sfs = new SimpleFieldSet(true);
    sfs.putSingle("identity", identityB64);
    // No ecdsa subset, no ARK fields, and no clientNonce => exercise generation paths

    nc.readCrypto(sfs);

    assertArrayEquals(identity, nc.getMyIdentity());
    assertArrayEquals(SHA256.digest(identity), nc.getIdentityHash());
    assertArrayEquals(SHA256.digest(nc.getIdentityHash()), nc.getIdentityHashHash());

    // ECDSA generated and hash is consistent
    ECPublicKey pub = nc.getECDSAP256Pubkey();
    assertNotNull(pub);
    assertArrayEquals(SHA256.digest(pub.getEncoded()), nc.getEcdsaPubKeyHash());

    assertNotNull(nc.getMyARK());
    assertEquals(0L, nc.getMyARKNumber());
  }

  @Test
  void exportPublicCryptoFieldSet_includesExpectedFields() {
    NodeCrypto nc = bare(node, true);
    nc.initCrypto();

    FNPPacketMangler mangler = (FNPPacketMangler) getField(nc, "packetMangler");
    when(mangler.supportedNegTypes(true)).thenReturn(new int[] {1, 2});

    SimpleFieldSet fs = nc.exportPublicCryptoFieldSet(false, false);

    // identity present and matches
    assertEquals(Base64.encode(nc.getMyIdentity()), fs.get("identity"));
    // auth.negTypes present and contains the negotiated values
    assertArrayEquals(new String[] {"1", "2"}, fs.getAll("auth.negTypes"));
    // ark fields present when not forSetup and not for anon initiator
    assertEquals(Long.toString(nc.getMyARKNumber()), fs.get("ark.number"));
    assertNotNull(fs.get("ark.pubURI"));

    // When forSetup=true, identity/ecdsa/ark fields are omitted but auth.negTypes retained
    SimpleFieldSet fsSetup = nc.exportPublicCryptoFieldSet(true, false);
    assertNull(fsSetup.get("identity"));
    assertNull(fsSetup.subset("ecdsa"));
    assertNull(fsSetup.get("ark.number"));
    assertNotNull(fsSetup.get("auth.negTypes"));
  }

  @Test
  void exportPublicFieldSet_addsIPsLocationAndSignature() throws Exception {
    NodeCrypto nc = bare(node, true);
    nc.initCrypto();

    // detector returns one address
    NodeIPPortDetector detector = (NodeIPPortDetector) getField(nc, "detector");
    Peer[] peers =
        new Peer[] {new Peer(new FreenetInetAddress(InetAddress.getLoopbackAddress()), 54321)};
    when(detector.detectPrimaryPeers()).thenReturn(peers);
    FNPPacketMangler mangler = (FNPPacketMangler) getField(nc, "packetMangler");
    when(mangler.supportedNegTypes(true)).thenReturn(new int[] {1});

    // location manager
    LocationManager lm = mock(LocationManager.class);
    when(lm.getLocation()).thenReturn(0.5);
    when(node.network().locationManager()).thenReturn(lm);

    SimpleFieldSet fs = nc.exportPublicFieldSet(true, false, false); // forSetup=true to avoid IPs

    // forSetup=true excludes location; version keys remain
    assertNull(fs.get("location"));
    assertNotNull(fs.get("version"));
    assertNotNull(fs.get("lastGoodVersion"));
    // opennet flag present (true)
    assertEquals("true", fs.get("opennet"));
    // not adding myName for opennet
    assertNull(fs.get("myName"));
    // signature field added
    assertNotNull(fs.get("sigP256"));
  }

  @Test
  void start_callsSocketAndManglerInOrder() {
    NodeCrypto nc = bare(node, true);

    UdpSocketHandler sock = (UdpSocketHandler) getField(nc, "socket");
    FNPPacketMangler mangler = (FNPPacketMangler) getField(nc, "packetMangler");

    nc.start();

    InOrder inOrder = Mockito.inOrder(sock, mangler);
    inOrder.verify(sock).calculateMaxPacketSize();
    inOrder.verify(sock).setLowLevelFilter(any());
    inOrder.verify(mangler).start();
    inOrder.verify(sock).start();
  }

  @Test
  void stop_closesSocket() {
    NodeCrypto nc = bare(node, true);
    NodeCryptoConfig cfg = (NodeCryptoConfig) getField(nc, "config");
    UdpSocketHandler sock = (UdpSocketHandler) getField(nc, "socket");

    nc.stop();

    verify(cfg).stopping();
    verify(sock).close();
  }

  @Test
  void onSetDropProbability_propagatesToSocket() {
    NodeCrypto nc = bare(node, true);
    UdpSocketHandler sock = (UdpSocketHandler) getField(nc, "socket");
    nc.onSetDropProbability(7);
    verify(sock).setDropProbability(7);
  }

  @Test
  void getAnonSetupPeerNodes_filtersByUnknownInitiatorAndMangler() {
    NodeCrypto nc = bare(node, true);
    FNPPacketMangler mangler = (FNPPacketMangler) getField(nc, "packetMangler");

    PeerManager pm = mock(PeerManager.class);
    PeerRoster roster = mock(PeerRoster.class);
    when(node.network().peers()).thenReturn(pm);
    when(pm.roster()).thenReturn(roster);

    PeerNode a = mock(PeerNode.class);
    when(a.handshakeUnknownInitiator()).thenReturn(true);
    when(a.getOutgoingMangler()).thenReturn(mangler);

    PeerNode b = mock(PeerNode.class);
    when(b.handshakeUnknownInitiator()).thenReturn(false);
    when(b.getOutgoingMangler()).thenReturn(mangler);

    PeerNode c = mock(PeerNode.class);
    when(c.handshakeUnknownInitiator()).thenReturn(true);
    when(c.getOutgoingMangler()).thenReturn(mock(OutgoingPacketMangler.class));

    when(pm.myPeers()).thenReturn(new PeerNode[] {a, b, c});

    PeerNode[] res = nc.getAnonSetupPeerNodes();
    assertEquals(1, res.length);
    assertSame(a, res[0]);
  }

  @Test
  void definitelyPortForwarded_delegatesToSocket() {
    NodeCrypto nc = bare(node, true);
    UdpSocketHandler sock = (UdpSocketHandler) getField(nc, "socket");
    when(sock.getDetectedConnectivityStatus()).thenReturn(Status.DEFINITELY_PORT_FORWARDED);
    assertTrue(nc.definitelyPortForwarded());
  }

  @Test
  void getIdentity_returnsECDSAPubKeyHash() {
    NodeCrypto nc = bare(node, true);
    nc.initCrypto();
    assertArrayEquals(nc.getEcdsaPubKeyHash(), nc.getIdentity(0));
  }

  @Test
  void allowConnection_honorsOneConnectionPerAddressPolicy() throws Exception {
    NodeCrypto nc = bare(node, true);

    NodeCryptoConfig cfg = (NodeCryptoConfig) getField(nc, "config");
    when(cfg.oneConnectionPerAddress()).thenReturn(true);

    PeerManager pm = mock(PeerManager.class);
    PeerRoster roster = mock(PeerRoster.class);
    when(node.network().peers()).thenReturn(pm);
    when(pm.roster()).thenReturn(roster);

    FreenetInetAddress addr = new FreenetInetAddress(InetAddress.getByName("203.0.113.5"));
    PeerNode peer = mock(PeerNode.class);

    NodeIPPortDetector detector = (NodeIPPortDetector) getField(nc, "detector");
    when(detector.includes(addr)).thenReturn(false);
    // Real internet address
    assertTrue(addr.isRealInternetAddress(false, false, false));

    when(roster.anyConnectedPeerHasAddress(addr, peer)).thenReturn(true);

    boolean res = nc.allowConnection(peer, addr);
    assertFalse(res);
  }

  @Test
  void maybeBootConnection_dropsDarknetPeerWhenConflicting() throws Exception {
    NodeCrypto nc = bare(node, false); // darknet instance

    NodeIPPortDetector detector = (NodeIPPortDetector) getField(nc, "detector");
    FreenetInetAddress address = new FreenetInetAddress(InetAddress.getByName("198.51.100.7"));
    when(detector.includes(address)).thenReturn(false);

    // Prepare PeerManager with a conflicting Darknet peer
    PeerManager pm = mock(PeerManager.class);
    PeerMessenger messenger = mock(PeerMessenger.class);
    PeerRoster roster = mock(PeerRoster.class);
    when(node.network().peers()).thenReturn(pm);
    when(pm.messenger()).thenReturn(messenger);
    when(pm.roster()).thenReturn(roster);

    DarknetPeerNode conflicting = mock(DarknetPeerNode.class);
    // Make the inner crypto's config return oneConnectionPerAddress=true
    NodeCrypto otherCrypto = bare(node, false);
    NodeCryptoConfig otherCfg = (NodeCryptoConfig) getField(otherCrypto, "config");
    when(otherCfg.oneConnectionPerAddress()).thenReturn(true);
    // Inject into the mocked peer via reflection (field is final in PeerNode)
    setPeerNodeCrypto(conflicting, otherCrypto);

    when(conflicting.isOpennet()).thenReturn(false);
    when(roster.getAllConnectedByAddress(address, true))
        .thenReturn(new ArrayList<>(List.of(conflicting)));

    // Caller peer is also darknet, so the conflict applies
    DarknetPeerNode caller = mock(DarknetPeerNode.class);

    nc.maybeBootConnection(caller, address);

    verify(messenger).disconnectAndRemove(eq(conflicting), eq(true), eq(true), anyBoolean());
  }

  @Test
  void myCompressedFullRef_hasPrefixAndIsInflatable() throws Exception {
    NodeCrypto nc = bare(node, true);
    nc.initCrypto();

    // Provide minimal detector/location so export succeeds
    NodeIPPortDetector detector = (NodeIPPortDetector) getField(nc, "detector");
    when(detector.detectPrimaryPeers()).thenReturn(new Peer[0]);
    FNPPacketMangler mangler = (FNPPacketMangler) getField(nc, "packetMangler");
    when(mangler.supportedNegTypes(true)).thenReturn(new int[] {1});
    LocationManager lm = mock(LocationManager.class);
    when(lm.getLocation()).thenReturn(0.25);
    when(node.network().locationManager()).thenReturn(lm);

    byte[] compressed = nc.myCompressedSetupRef();
    assertTrue(compressed.length > 1);
    assertEquals(0x01, compressed[0] & 0xFF); // compressed noderef marker

    // Inflate and sanity-parse the SFS
    SimpleFieldSet parsed = getParsed(compressed);
    assertNotNull(parsed.get("version"));
  }

  private static @NotNull SimpleFieldSet getParsed(byte[] compressed) throws IOException {
    String s;
    try (java.util.zip.InflaterInputStream iis =
        new java.util.zip.InflaterInputStream(
            new ByteArrayInputStream(compressed, 1, compressed.length - 1))) {
      byte[] buf = iis.readAllBytes();
      s = new String(buf, StandardCharsets.UTF_8);
    }

    // Ensure it's an SFS by parsing a few lines through SimpleFieldSet
    return new SimpleFieldSet(
        new BufferedReader(
            new InputStreamReader(
                new ByteArrayInputStream(s.getBytes(StandardCharsets.UTF_8)),
                StandardCharsets.UTF_8)),
        true,
        true);
  }

  // ---------- low-level reflect helpers ----------
  private static Object getField(Object target, String name) {
    try {
      Field f = target.getClass().getDeclaredField(name);
      f.setAccessible(true);
      return f.get(target);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private static void setPeerNodeCrypto(PeerNode target, NodeCrypto value) {
    try {
      Field f = PeerNode.class.getDeclaredField("crypto");
      f.setAccessible(true);
      f.set(target, value);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}

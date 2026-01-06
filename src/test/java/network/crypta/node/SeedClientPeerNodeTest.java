package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.security.interfaces.ECPublicKey;
import network.crypta.crypt.ECDSA;
import network.crypta.crypt.ECDSA.Curves;
import network.crypta.io.comm.MessageCore;
import network.crypta.io.comm.Peer;
import network.crypta.node.updater.NodeUpdateManager;
import network.crypta.support.Base64;
import network.crypta.support.BooleanLastTrueTracker;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.math.MersenneTwister;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SeedClientPeerNodeTest {

  @Mock private PeerManager peerManager;
  @Mock private PeerMessenger peerMessenger;

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private NodeCrypto crypto;

  private static final String VERSION_OK = "Cryptad,1,1.0,1";

  private ECPublicKey pubKey;

  @BeforeEach
  void setup() {
    // Deterministic EC key pair for peer noderef
    ECDSA ecdsa = new ECDSA(Curves.P256);
    pubKey = ecdsa.getPublicKey();

    // Node: provide the minimal collaborators touched by PeerNode logic
    when(node.bootstrap().createRandom()).thenReturn(new MersenneTwister(123456789L));
    when(node.getBootId()).thenReturn(42L);

    // USM, tracker, failure table, updater, and location manager are referenced on disconnect
    MessageCore usm = mock(MessageCore.class);
    doNothing().when(usm).onDisconnect(any());
    when(node.network().usm()).thenReturn(usm);

    when(peerManager.messenger()).thenReturn(peerMessenger);

    RequestTracker tracker = mock(RequestTracker.class);
    doNothing().when(tracker).onRestartOrDisconnect(any());
    when(node.routing().tracker()).thenReturn(tracker);

    FailureTable ft = mock(FailureTable.class);
    doNothing().when(ft).onDisconnect(any());
    when(node.routing().failureTable()).thenReturn(ft);

    NodeUpdateManager updater = mock(NodeUpdateManager.class);
    doNothing().when(updater).disconnected(any());
    when(node.services().nodeUpdater()).thenReturn(updater);

    LocationManager lm = mock(LocationManager.class);
    doNothing().when(lm).lostOrRestartedNode(any());
    when(node.network().locationManager()).thenReturn(lm);

    when(node.network().peers()).thenReturn(peerManager);
    when(peerManager.disconnected(any())).thenReturn(true);
    when(peerManager.havePeer(any())).thenReturn(false);

    // Crypto: opennet matching SeedClientPeerNode.isOpennetForNoderef()==true
    when(crypto.isOpennet()).thenReturn(true);
    // Identity hash lengths must match SHA-256 digest length used by PeerNode
    when(crypto.getIdentityHash()).thenReturn(new byte[32]);
    when(crypto.getIdentityHashHash()).thenReturn(new byte[32]);
    // OutgoingPacketMangler: provide a FNPPacketMangler mock with basic stubs
    FNPPacketMangler mangler = mock(FNPPacketMangler.class);
    when(mangler.supportedNegTypes(false)).thenReturn(new int[] {1, 2});
    when(mangler.getPrimaryIPAddress()).thenReturn(new Peer[0]);
    when(crypto.getPacketMangler()).thenReturn(mangler);
  }

  private static SimpleFieldSet baseSeedClientSFS(ECPublicKey pubKey, byte[] identity) {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("version", VERSION_OK);
    fs.putSingle("opennet", "true");
    fs.putSingle("location", "0.123");
    fs.putSingle("identity", Base64.encode(identity));
    fs.putSingle("ecdsa.P256.pub", Base64.encode(pubKey.getEncoded()));
    // No negTypes on purpose: Seed clients accept anonymous initiator and fill defaults
    return fs;
  }

  private static byte[] fixedIdentity(int seed) {
    byte[] id = new byte[32];
    for (int i = 0; i < id.length; i++) id[i] = (byte) (i ^ seed);
    return id;
  }

  private SeedClientPeerNode newClient(byte[] identity) throws Exception {
    SimpleFieldSet fs = baseSeedClientSFS(pubKey, identity);
    return new SeedClientPeerNode(fs, node, crypto, peerManager);
  }

  private OpennetPeerNode newOpennet(byte[] identity, OpennetManager opennet) throws Exception {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("version", VERSION_OK);
    fs.putSingle("opennet", "true");
    fs.putSingle("location", "0.123");
    fs.putSingle("identity", Base64.encode(identity));
    fs.putSingle("ecdsa.P256.pub", Base64.encode(pubKey.getEncoded()));
    // For Opennet peers, negotiation types must be explicitly present in the noderef
    fs.put("auth.negTypes", new int[] {1, 2});
    // Provide a non-empty metadata subset when fromLocal=true to satisfy constructor reads
    SimpleFieldSet meta = new SimpleFieldSet(true);
    meta.put("timeLastSuccess", 0);
    fs.put("metadata", meta);
    return new OpennetPeerNode(fs, node, crypto, opennet, /* fromLocal= */ true, peerManager);
  }

  @Test
  void flags_basicBooleans_matchContract() throws Exception {
    SeedClientPeerNode c = newClient(fixedIdentity(7));

    assertFalse(c.isDarknet());
    assertFalse(c.isOpennet()); // not a regular opennet peer
    assertTrue(c.isSeed());
    assertFalse(c.isRealConnection());
    assertFalse(c.isRoutingCompatible());
    assertTrue(c.canAcceptAnnouncements());
    assertFalse(c.recordStatus());
    assertTrue(c.handshakeUnknownInitiator());
    assertEquals(FNPPacketMangler.SETUP_OPENNET_SEEDNODE, c.handshakeSetupType());
    assertFalse(c.shouldSendHandshake());
    assertTrue(c.isOpennetForNoderef()); // noderef parsing expects opennet=true
    assertTrue(c.fromAnonymousInitiator());
  }

  @Test
  void getStatus_whenBuilt_marksSeedClient_andNotSearchable() throws Exception {
    SeedClientPeerNode c = newClient(fixedIdentity(1));

    PeerNodeStatus sLight = c.getStatus(true);
    assertTrue(sLight.isSeedClient());
    assertFalse(sLight.isSeedServer());
    assertFalse(sLight.isSearchable()); // not a real connection
    assertFalse(sLight.recordStatus()); // delegated from SeedClientPeerNode.recordStatus()

    PeerNodeStatus sHeavy = c.getStatus(false);
    assertTrue(sHeavy.isSeedClient());
    assertFalse(sHeavy.isSeedServer());
  }

  @Test
  void equals_whenSameTypeAndSameKey_true() throws Exception {
    byte[] id = fixedIdentity(3);
    SeedClientPeerNode a = newClient(id);
    // Rebuild second instance using the same ECDSA key and identity → equal
    SeedClientPeerNode b =
        new SeedClientPeerNode(baseSeedClientSFS(pubKey, id), node, crypto, peerManager);

    assertEquals(a, b);
    assertEquals(a.hashCode(), b.hashCode());
  }

  @SuppressWarnings("AssertBetweenInconvertibleTypes")
  @Test
  void equals_whenDifferentType_false_andSymmetric() throws Exception {
    SeedClientPeerNode a = newClient(fixedIdentity(9));
    // Different concrete type should never be equal in either direction
    OpennetManager opennet = mock(OpennetManager.class);
    OpennetPeerNode b = newOpennet(fixedIdentity(9), opennet);
    // Cast to Object to avoid IDE warning about comparing incompatible compile-time types
    // and to explicitly exercise cross-type equality semantics.
    assertNotEquals(a, b);
    assertNotEquals(b, a);
  }

  @Test
  void equals_whenSameTypeDifferentKey_false() throws Exception {
    SeedClientPeerNode a = newClient(fixedIdentity(1));
    // New EC key → different public key hash
    ECDSA otherEcdsa = new ECDSA(Curves.P256);
    ECPublicKey otherPub = otherEcdsa.getPublicKey();
    SeedClientPeerNode b =
        new SeedClientPeerNode(
            baseSeedClientSFS(otherPub, fixedIdentity(1)), node, crypto, peerManager);

    assertNotEquals(a, b);
  }

  @Test
  void disconnected_alwaysDelegatesToPeerManager_disconnectAndRemove_called() throws Exception {
    SeedClientPeerNode c = newClient(fixedIdentity(2));

    boolean ret = c.disconnected(false, false);
    // In override: super.disconnected(true,true) returns prior connected state. New peers start
    // disconnected, so false is expected.
    assertFalse(ret);
    verify(peerMessenger, times(1)).disconnectAndRemove(c, false, false, false);
  }

  @Test
  @DisplayName("fatalTimeout() forces immediate disconnect")
  void fatalTimeout_whenCalled_invokesForceDisconnect() throws Exception {
    SeedClientPeerNode c = spy(newClient(fixedIdentity(5)));
    doNothing().when(c).forceDisconnect();
    c.fatalTimeout();
    verify(c, times(1)).forceDisconnect();
  }

  @Test
  void shouldDisconnectAndRemoveNow_whenNeverConnected_returnsFalse() throws Exception {
    SeedClientPeerNode c = newClient(fixedIdentity(11));
    // Fresh instance: never connected, lastReceivedPacketTime == -1
    assertFalse(c.shouldDisconnectAndRemoveNow());
  }

  @Test
  void shouldDisconnectAndRemoveNow_whenNotConnectedAndStaleFor60s_returnsTrue() throws Exception {
    SeedClientPeerNode c = newClient(fixedIdentity(12));
    long now = System.currentTimeMillis();
    // Simulate: we once completed a connection (timestamp > 0) but are currently disconnected and
    // haven't received a packet for >60s.
    setPrivateLong(c, "connectedTime", now - 70_000L);
    setPrivateLong(c, "timeLastReceivedPacket", now - 70_000L);
    assertTrue(c.shouldDisconnectAndRemoveNow());
  }

  @Test
  void shouldDisconnectAndRemoveNow_whenConnectedUnderAnHour_returnsFalse() throws Exception {
    SeedClientPeerNode c = newClient(fixedIdentity(13));
    long now = System.currentTimeMillis();
    setConnected(c, now);
    setPrivateLong(c, "connectedTime", now - 30 * 60_000L); // 30 minutes ago
    assertFalse(c.shouldDisconnectAndRemoveNow());
  }

  @Test
  void shouldDisconnectAndRemoveNow_whenConnectedOverAnHour_returnsTrue() throws Exception {
    SeedClientPeerNode c = newClient(fixedIdentity(14));
    long now = System.currentTimeMillis();
    setConnected(c, now);
    setPrivateLong(c, "connectedTime", now - 2 * 60 * 60_000L); // 2 hours ago
    assertTrue(c.shouldDisconnectAndRemoveNow());
  }

  @Test
  void constructor_whenOpennetFlagMismatch_throws() {
    // opennet=false conflicts with SeedClientPeerNode.isOpennetForNoderef()==true
    SimpleFieldSet fs = baseSeedClientSFS(pubKey, fixedIdentity(77));
    fs.putOverwrite("opennet", "false");
    assertThrows(
        FSParseException.class, () -> new SeedClientPeerNode(fs, node, crypto, peerManager));
  }

  // ---------- Helpers ----------

  private static void setConnected(SeedClientPeerNode c, long now) throws Exception {
    Field internalsField = PeerNode.class.getDeclaredField("internals");
    internalsField.setAccessible(true);
    Object internals = internalsField.get(c);

    Field connectionStateField = internals.getClass().getDeclaredField("connectionState");
    connectionStateField.setAccessible(true);
    Object connectionState = connectionStateField.get(internals);

    Field trackerField = connectionState.getClass().getDeclaredField("connectedTracker");
    trackerField.setAccessible(true);
    BooleanLastTrueTracker tracker = (BooleanLastTrueTracker) trackerField.get(connectionState);
    tracker.set(true, now);
  }

  private static void setPrivateLong(Object target, String field, long value) throws Exception {
    Field f = PeerNode.class.getDeclaredField(field);
    f.setAccessible(true);
    f.setLong(target, value);
  }

  // No extra minimal mangler needed; FNPPacketMangler is mocked in setup().
}

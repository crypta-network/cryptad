package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.security.interfaces.ECPublicKey;
import java.util.concurrent.TimeUnit;
import network.crypta.crypt.ECDSA;
import network.crypta.crypt.ECDSA.Curves;
import network.crypta.io.AddressTracker;
import network.crypta.io.comm.MessageCore;
import network.crypta.io.comm.UdpSocketHandler;
import network.crypta.node.OpennetManager.ConnectionType;
import network.crypta.node.OpennetManager.LinkLengthClass;
import network.crypta.node.updater.NodeUpdateManager;
import network.crypta.node.updater.UpdateOverMandatoryManager;
import network.crypta.support.BooleanLastTrueTracker;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class OpennetPeerNodeTest {

  // SonarLint-friendly string constants to avoid S1192
  private static final String SFS_KEY_OPENNET = "opennet";
  private static final String SFS_KEY_ECDSA = "ecdsa";
  private static final String SFS_KEY_ECDSA_P256 = "P256";
  private static final String SFS_KEY_PUB = "pub";
  private static final String SFS_KEY_SIG_P256 = "sigP256";
  private static final String SFS_KEY_NEG_TYPES = "auth.negTypes";
  private static final String FIELD_PEER_NODE_STATUS = "peerNodeStatus";
  private static final String FIELD_CONNECTED_TIME = "connectedTime";

  @Mock private OpennetManager opennetManager;
  @Mock private NodeCrypto nodeCryptoForPeer;
  @Mock private PeerManager peerManager;

  private Node node;

  @BeforeEach
  void setUp() {
    node = mock(Node.class);
    // Deterministic random for PeerNode internals
    when(node.createRandom()).thenReturn(new network.crypta.support.math.MersenneTwister(1234));
    when(node.getBootId()).thenReturn(42L);
    // Default USM started in the far past unless a test overrides
    MessageCore usm = mock(MessageCore.class);
    when(usm.getStartedTime()).thenReturn(System.currentTimeMillis() - TimeUnit.DAYS.toMillis(1));
    when(node.getUSM()).thenReturn(usm);
    // Default ticker: ignore scheduled jobs
    network.crypta.support.Ticker ticker = mock(network.crypta.support.Ticker.class);
    when(node.getTicker()).thenReturn(ticker);
    // Default environment for linkLengthClass
    when(opennetManager.getNode()).thenReturn(node);
    when(node.getLocation()).thenReturn(0.0);
    // NodeCrypto required by PeerNode constructor
    when(nodeCryptoForPeer.isOpennet()).thenReturn(true);
    when(nodeCryptoForPeer.getPacketMangler()).thenReturn(mock(FNPPacketMangler.class));
    when(nodeCryptoForPeer.getIdentityHash())
        .thenReturn(new byte[32]); // any 32 bytes for SHA-256 length
    when(nodeCryptoForPeer.getIdentityHashHash()).thenReturn(new byte[32]);
  }

  private static SimpleFieldSet createMinimalOpennetRef(String location) {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    // Minimal acceptable version string for parsing (Cryptad,<build>,<protocol>)
    fs.putSingle("version", "Cryptad,1,1.0");
    if (location != null) fs.putSingle("location", location);
    fs.putSingle(SFS_KEY_OPENNET, "true");
    // Provide at least one negotiation type
    fs.putAppend(SFS_KEY_NEG_TYPES, "1");
    fs.putAppend(SFS_KEY_NEG_TYPES, "2");
    // Identity (32 bytes base64) – any deterministic value is OK
    byte[] id = new byte[32];
    for (int i = 0; i < id.length; i++) id[i] = (byte) i;
    fs.putSingle("identity", network.crypta.support.Base64.encode(id));

    // ECDSA P-256 public key in X.509 (SubjectPublicKeyInfo) format
    ECDSA ecdsa = new ECDSA(Curves.P256);
    ECPublicKey pub = ecdsa.getPublicKey();
    SimpleFieldSet ecdsaCurve = new SimpleFieldSet(true);
    ecdsaCurve.putSingle(SFS_KEY_PUB, network.crypta.support.Base64.encode(pub.getEncoded()));
    SimpleFieldSet ecdsaRoot = new SimpleFieldSet(true);
    ecdsaRoot.put(SFS_KEY_ECDSA_P256, ecdsaCurve);
    fs.put(SFS_KEY_ECDSA, ecdsaRoot);

    // Provide an empty metadata subset (constructor expects it to exist)
    SimpleFieldSet metadata = new SimpleFieldSet(true);
    metadata.put("timeLastSuccess", 0L);
    fs.put("metadata", metadata);
    return fs;
  }

  /** Creates a minimal, signed opennet noderef suitable for fromLocal=false paths. */
  private static SimpleFieldSet createSignedOpennetRef() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("version", "Cryptad,1,1.0");
    // Pick a valid location for the signed ref
    fs.putSingle("location", "0.42");
    fs.putSingle(SFS_KEY_OPENNET, "true");
    fs.putAppend(SFS_KEY_NEG_TYPES, "1");
    fs.putAppend(SFS_KEY_NEG_TYPES, "2");

    byte[] id = new byte[32];
    for (int i = 0; i < id.length; i++) id[i] = (byte) (255 - i);
    fs.putSingle("identity", network.crypta.support.Base64.encode(id));

    // Generate a keypair and embed pub
    ECDSA ecdsa = new ECDSA(Curves.P256);
    ECPublicKey pub = ecdsa.getPublicKey();
    SimpleFieldSet ecdsaCurve = new SimpleFieldSet(true);
    ecdsaCurve.putSingle(SFS_KEY_PUB, network.crypta.support.Base64.encode(pub.getEncoded()));
    SimpleFieldSet ecdsaRoot = new SimpleFieldSet(true);
    ecdsaRoot.put(SFS_KEY_ECDSA_P256, ecdsaCurve);
    fs.put(SFS_KEY_ECDSA, ecdsaRoot);

    // Sign the ordered string (without signature fields present)
    byte[] toVerify = fs.toOrderedString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
    byte[] sig = ecdsa.sign(toVerify);
    fs.putSingle(SFS_KEY_SIG_P256, network.crypta.support.Base64.encode(sig));
    return fs;
  }

  private OpennetPeerNode newPeerLocal(String location) throws Exception {
    SimpleFieldSet fs = createMinimalOpennetRef(location);
    return new OpennetPeerNode(fs, node, nodeCryptoForPeer, opennetManager, true, peerManager);
  }

  @Test
  void validateRef_whenOpennetFlag_expectBooleanMatches() {
    SimpleFieldSet fsTrue = new SimpleFieldSet(true);
    fsTrue.putSingle(SFS_KEY_OPENNET, "true");
    assertTrue(OpennetPeerNode.validateRef(fsTrue));

    SimpleFieldSet fsFalse = new SimpleFieldSet(true);
    fsFalse.putSingle(SFS_KEY_OPENNET, "false");
    assertFalse(OpennetPeerNode.validateRef(fsFalse));

    SimpleFieldSet fsMissing = new SimpleFieldSet(true);
    assertFalse(OpennetPeerNode.validateRef(fsMissing));
  }

  @Test
  void ctor_and_simpleFlags_expectFixedBooleans() throws Exception {
    OpennetPeerNode pn = newPeerLocal("0.25");
    assertTrue(pn.isOpennet());
    assertFalse(pn.isDarknet());
    assertFalse(pn.isSeed());
    assertTrue(pn.isRealConnection());
    assertTrue(pn.recordStatus());
    assertNotNull(pn.getStatus(true));
  }

  @Test
  void ctor_fromRemoteSigned_refAccepted() throws Exception {
    // Exercise fromLocal=false path with a signed noderef
    SimpleFieldSet fs = createSignedOpennetRef();
    OpennetPeerNode pn =
        new OpennetPeerNode(fs, node, nodeCryptoForPeer, opennetManager, false, peerManager);
    assertTrue(pn.isOpennet());
  }

  @Test
  void onSuccess_whenInsertOrSSK_true_doesNotUpdateOrNotify() throws Exception {
    OpennetPeerNode pn = newPeerLocal("0.25");
    long before = pn.timeLastSuccess();

    pn.onSuccess(true, false); // insert
    pn.onSuccess(false, true); // ssk

    assertEquals(before, pn.timeLastSuccess());
    verify(opennetManager, times(0)).onSuccess(pn);
  }

  @Test
  void onSuccess_whenFetchSuccess_updatesAndNotifies() throws Exception {
    OpennetPeerNode pn = newPeerLocal("0.25");
    long before = pn.timeLastSuccess();
    pn.onSuccess(false, false);
    assertTrue(pn.timeLastSuccess() >= before);
    verify(opennetManager, times(1)).onSuccess(pn);
  }

  @Test
  void exportMetadataFieldSet_includesTimeLastSuccess() throws Exception {
    OpennetPeerNode pn = newPeerLocal("0.25");
    pn.onSuccess(false, false);
    long now = System.currentTimeMillis();
    SimpleFieldSet meta = pn.exportMetadataFieldSet(now);
    assertEquals(pn.timeLastSuccess(), meta.getLong("timeLastSuccess"));
  }

  @Test
  void setAndGetAddedReason_roundTrip() throws Exception {
    OpennetPeerNode pn = newPeerLocal("0.25");
    pn.setAddedReason(ConnectionType.ANNOUNCE.ordinal());
    assertEquals(ConnectionType.ANNOUNCE.ordinal(), pn.getAddedReason());
  }

  @Test
  void dropReason_whenTooNewPeer_variants() throws Exception {
    OpennetPeerNode pn = newPeerLocal("0.25");

    // Make node uptime large enough so we don't hit the startup guard
    when(node.getUSM().getStartedTime())
        .thenReturn(System.currentTimeMillis() - OpennetManager.DROP_STARTUP_DELAY - 1000);

    // Case A: NEVER_CONNECTED and age < DROP_MIN_AGE_DISCONNECTED
    setPrivateField(pn, FIELD_PEER_NODE_STATUS, PeerManager.PEER_NODE_STATUS_NEVER_CONNECTED);
    pn.peerAddedTime =
        System.currentTimeMillis() - (OpennetManager.DROP_MIN_AGE_DISCONNECTED - 500);
    assertEquals(OpennetPeerNode.NOT_DROP_REASON.TOO_NEW_PEER, pn.isDroppableWithReason(false));

    // Case B: CONNECTED and age < DROP_MIN_AGE
    setPrivateField(pn, FIELD_PEER_NODE_STATUS, PeerManager.PEER_NODE_STATUS_CONNECTED);
    pn.peerAddedTime = System.currentTimeMillis() - (OpennetManager.DROP_MIN_AGE - 500);
    assertEquals(OpennetPeerNode.NOT_DROP_REASON.TOO_NEW_PEER, pn.isDroppableWithReason(false));
  }

  @Test
  void dropReason_whenGraceExpired_thenUptimeGuard() throws Exception {
    OpennetPeerNode pn = newPeerLocal("0.25");

    // Age beyond min age should clear added fields and not return TOO_NEW_PEER
    pn.setAddedReason(ConnectionType.PATH_FOLDING.ordinal());
    pn.peerAddedTime = System.currentTimeMillis() - (OpennetManager.DROP_MIN_AGE + 1000);
    setPrivateField(pn, FIELD_PEER_NODE_STATUS, PeerManager.PEER_NODE_STATUS_CONNECTED);

    // But if node uptime is too low, it should return TOO_LOW_UPTIME
    when(node.getUSM().getStartedTime())
        .thenReturn(System.currentTimeMillis() - (OpennetManager.DROP_STARTUP_DELAY - 1000));

    assertEquals(OpennetPeerNode.NOT_DROP_REASON.TOO_LOW_UPTIME, pn.isDroppableWithReason(false));

    // Now make uptime large enough and verify state reset + DROPPABLE
    when(node.getUSM().getStartedTime())
        .thenReturn(System.currentTimeMillis() - (OpennetManager.DROP_STARTUP_DELAY + 1000));
    OpennetPeerNode.NOT_DROP_REASON res = pn.isDroppableWithReason(false);
    assertEquals(OpennetPeerNode.NOT_DROP_REASON.DROPPABLE, res);
    assertEquals(0L, pn.getPeerAddedTime());
    assertEquals(PeerNode.ADDED_REASON_UNKNOWN, pn.getAddedReason());
  }

  @Test
  void dropReason_whenReconnectGracePeriod_activeUnlessIgnored() throws Exception {
    OpennetPeerNode pn = newPeerLocal("0.25");

    when(node.getUSM().getStartedTime())
        .thenReturn(System.currentTimeMillis() - (OpennetManager.DROP_STARTUP_DELAY + 1000));

    // Configure status and disconnect timers per condition
    setPrivateField(pn, FIELD_PEER_NODE_STATUS, PeerManager.PEER_NODE_STATUS_DISCONNECTED);
    pn.neverConnected = false;
    long now = System.currentTimeMillis();
    pn.timeLastDisconnect = now - (OpennetManager.DROP_DISCONNECT_DELAY - 500);
    pn.timePrevDisconnect = now - (OpennetManager.DROP_DISCONNECT_DELAY_COOLDOWN + 500);
    pn.peerAddedTime = now - (OpennetManager.DROP_MIN_AGE + 1000);

    assertEquals(
        OpennetPeerNode.NOT_DROP_REASON.RECONNECT_GRACE_PERIOD, pn.isDroppableWithReason(false));
    // Ignoring disconnect removes the grace period
    assertEquals(OpennetPeerNode.NOT_DROP_REASON.DROPPABLE, pn.isDroppableWithReason(true));
  }

  @Test
  void linkLengthClass_whenInvalidLocation_returnsShort() throws Exception {
    OpennetPeerNode pn = newPeerLocal(null); // No location => invalid
    assertEquals(LinkLengthClass.SHORT, pn.linkLengthClass());
  }

  @Test
  void linkLengthClass_whenDistanceBoundary() throws Exception {
    // Distance slightly above threshold => LONG
    OpennetPeerNode longLink = newPeerLocal("0.0111");
    assertEquals(LinkLengthClass.LONG, longLink.linkLengthClass());

    // Distance below threshold => SHORT
    OpennetPeerNode shortLink = newPeerLocal("0.009");
    assertEquals(LinkLengthClass.SHORT, shortLink.linkLengthClass());
  }

  @Test
  void onConnect_setsAddressTrackerPresumedGuilty() throws Exception {
    // Wire node.getOpennet() so super.onConnect() can notify
    when(node.getOpennet()).thenReturn(opennetManager);

    // Prepare AddressTracker chain
    AddressTracker tracker = mock(AddressTracker.class);
    UdpSocketHandler socket = mock(UdpSocketHandler.class);
    when(socket.getAddressTracker()).thenReturn(tracker);
    NodeCrypto opennetCrypto = mock(NodeCrypto.class);
    when(opennetCrypto.getSocket()).thenReturn(socket);
    when(opennetManager.getCrypto()).thenReturn(opennetCrypto);

    OpennetPeerNode pn = newPeerLocal("0.25");
    long t0 = System.currentTimeMillis();
    pn.onConnect();

    ArgumentCaptor<Long> cap = ArgumentCaptor.forClass(Long.class);
    verify(tracker, times(1)).setPresumedGuiltyAt(cap.capture());
    long scheduled = cap.getValue();
    long expected = t0 + TimeUnit.HOURS.toMillis(1);
    assertTrue(Math.abs(scheduled - expected) <= TimeUnit.MINUTES.toMillis(2));
  }

  @Test
  void equals_whenSameKeyOrDifferentType() throws Exception {
    // Build first peer, then construct second using the same ecdsa public key
    SimpleFieldSet fsA = createMinimalOpennetRef("0.25");
    OpennetPeerNode a =
        new OpennetPeerNode(fsA, node, nodeCryptoForPeer, opennetManager, true, peerManager);

    String pub = fsA.subset(SFS_KEY_ECDSA).subset(SFS_KEY_ECDSA_P256).get(SFS_KEY_PUB);
    SimpleFieldSet fsB = createMinimalOpennetRef("0.30");
    fsB.subset(SFS_KEY_ECDSA).subset(SFS_KEY_ECDSA_P256).putOverwrite(SFS_KEY_PUB, pub);
    OpennetPeerNode b =
        new OpennetPeerNode(fsB, node, nodeCryptoForPeer, opennetManager, true, peerManager);

    //noinspection EqualsWithItself
    assertEquals(a, a);
    assertEquals(a, b);
    assertNotEquals(new Object(), a);
  }

  @Test
  void shouldDisconnectAndRemoveNow_variousBranches() throws Exception {
    OpennetPeerNode pn = newPeerLocal("0.25");

    // Helper: mark connected by flipping the internal tracker
    BooleanLastTrueTracker conn = getIsConnectedTracker(pn);
    conn.set(true, System.currentTimeMillis());

    // Case: not unroutable -> false
    assertFalse(pn.shouldDisconnectAndRemoveNow());

    // Mark as unroutable due to older version
    pn.unroutableOlderVersion = true;

    // Uptime < 30s => false
    setPrivateField(
        pn, FIELD_CONNECTED_TIME, System.currentTimeMillis() - TimeUnit.SECONDS.toMillis(10));
    assertFalse(pn.shouldDisconnectAndRemoveNow());

    // Uptime ~1h10m, updater == null => true
    setPrivateField(
        pn, FIELD_CONNECTED_TIME, System.currentTimeMillis() - TimeUnit.MINUTES.toMillis(70));
    when(node.getNodeUpdater()).thenReturn(null);
    assertTrue(pn.shouldDisconnectAndRemoveNow());

    // Updater present but no UOM => true
    NodeUpdateManager updater = mock(NodeUpdateManager.class);
    when(node.getNodeUpdater()).thenReturn(updater);
    when(updater.getUpdateOverMandatory()).thenReturn(null);
    assertTrue(pn.shouldDisconnectAndRemoveNow());

    // UOM present and lastSentUOM just now => false (within 60s grace)
    UpdateOverMandatoryManager uom = mock(UpdateOverMandatoryManager.class);
    when(updater.getUpdateOverMandatory()).thenReturn(uom);
    pn.finishedSendingUOMJar(false); // sets lastSentUOM = now
    assertFalse(pn.shouldDisconnectAndRemoveNow());

    // Uptime > 2h => true regardless
    setPrivateField(
        pn, FIELD_CONNECTED_TIME, System.currentTimeMillis() - TimeUnit.HOURS.toMillis(3));
    assertTrue(pn.shouldDisconnectAndRemoveNow());
  }

  @Test
  void wasDropped_flags_cycle() throws Exception {
    OpennetPeerNode pn = newPeerLocal("0.25");
    assertFalse(pn.wasDropped());
    pn.setWasDropped();
    assertTrue(pn.wasDropped());
    assertTrue(pn.grabWasDropped());
    assertFalse(pn.grabWasDropped());
  }

  @Test
  void shallWeRouteAccordingToOurPeersLocation_delegatesToNode() throws Exception {
    OpennetPeerNode pn = newPeerLocal("0.25");
    when(node.shallWeRouteAccordingToOurPeersLocation(10)).thenReturn(true);
    assertTrue(pn.shallWeRouteAccordingToOurPeersLocation(10));
    when(node.shallWeRouteAccordingToOurPeersLocation(1)).thenReturn(false);
    assertFalse(pn.shallWeRouteAccordingToOurPeersLocation(1));
  }

  @Test
  void writePeers_invokesPeerManager() throws Exception {
    OpennetPeerNode pn = newPeerLocal("0.25");
    // Ensure strictly one observed invocation from this call
    org.mockito.Mockito.reset(peerManager);
    pn.writePeers();
    verify(peerManager, times(1)).writePeers(true);
  }

  // --- Reflection helpers (package-local test utility) ---
  @SuppressWarnings("java:S3011")
  private static void setPrivateField(Object target, String name, Object value)
      throws ReflectiveOperationException {
    Field f = getDeclaredField(target.getClass(), name);
    f.setAccessible(true);
    f.set(target, value);
  }

  @SuppressWarnings("java:S3011")
  private static BooleanLastTrueTracker getIsConnectedTracker(Object target)
      throws ReflectiveOperationException {
    Field internalsField = getDeclaredField(target.getClass(), "internals");
    internalsField.setAccessible(true);
    Object internals = internalsField.get(target);

    Field connectionStateField = getDeclaredField(internals.getClass(), "connectionState");
    connectionStateField.setAccessible(true);
    Object connectionState = connectionStateField.get(internals);

    Field trackerField = getDeclaredField(connectionState.getClass(), "connectedTracker");
    trackerField.setAccessible(true);
    return (BooleanLastTrueTracker) trackerField.get(connectionState);
  }

  private static Field getDeclaredField(Class<?> type, String name) throws NoSuchFieldException {
    Class<?> t = type;
    while (t != null) {
      try {
        return t.getDeclaredField(name);
      } catch (NoSuchFieldException _) {
        t = t.getSuperclass();
      }
    }
    throw new NoSuchFieldException(name);
  }
}

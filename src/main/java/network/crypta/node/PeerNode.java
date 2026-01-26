package network.crypta.node;

import static java.util.concurrent.TimeUnit.DAYS;
import static java.util.concurrent.TimeUnit.HOURS;
import static java.util.concurrent.TimeUnit.MINUTES;
import static java.util.concurrent.TimeUnit.SECONDS;

import java.lang.ref.WeakReference;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Random;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.crypt.BlockCipher;
import network.crypta.crypt.KeyAgreementSchemeContext;
import network.crypta.io.comm.FreenetInetAddress;
import network.crypta.io.comm.Peer;
import network.crypta.io.comm.Peer.LocalAddressException;
import network.crypta.io.comm.PeerContext;
import network.crypta.keys.Key;
import network.crypta.support.SimpleFieldSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents a remote peer that this node can handshake with, route to, and exchange traffic
 * through.
 *
 * <p>The class aggregates the peer's identity, negotiated session keys, and routing status across
 * the lifetime of a connection. It owns the handshake state machine, manages session key rotation,
 * and exposes a routing view that higher layers can use to decide whether the peer is eligible for
 * traffic at a given time. Callers typically construct a {@code PeerNode} from a noderef, allow it
 * to perform handshakes, and then poll or react to status changes as traffic is sent and received.
 *
 * <p>State is mutable and heavily synchronized. The peer lock protects most fields, while some
 * inner helpers use narrower locks for high-frequency counters. The class relies on a strict lock
 * order: acquire {@link PeerManager} first, then the {@code PeerNode} instance. Breaking the order
 * can deadlock and must be avoided.
 *
 * <ul>
 *   <li>Tracks identity, version compatibility, and routability decisions.
 *   <li>Coordinates handshakes, key promotion, and packet/message numbering.
 *   <li>Maintains counters and timestamps used by routing and backoff logic.
 * </ul>
 *
 * @author amphibian
 * @see PeerManager
 * @see SessionKey
 */
public abstract class PeerNode implements BasePeerNode, PeerNodeUnlocked {
  private static final Logger LOG = LoggerFactory.getLogger(PeerNode.class);

  // SFS keys used more than once: keep as constants to avoid duplication warnings
  private static final String SFS_KEY_VERSION = "version";
  private static final String SFS_KEY_LOCATION = "location";
  private static final String SFS_KEY_LAST_GOOD_VERSION = "lastGoodVersion";
  static final String SFS_KEY_TESTNET = "testnet";
  private static final String SFS_KEY_NEG_TYPES = "auth.negTypes";
  static final String SFS_KEY_OPENNET = "opennet";
  static final String SFS_KEY_IDENTITY = "identity";
  private static final String SFS_KEY_PHYSICAL_UDP = "physical.udp";
  private static final String SFS_KEY_METADATA = "metadata";
  private static final String SFS_KEY_PEER_ADDED_TIME = "peerAddedTime";
  private static final String SFS_KEY_DETECTED_UDP = "detected.udp";
  private static final String STR_MS_FOR = "ms for ";
  private static final String STR_FOR = " for ";
  private static final String STR_MS_ON = "ms on ";
  static final String STR_ON = ") on ";
  private static final String STR_WORKING_ON = ") working on ";
  private static final String STR_P_REJECTED = " : pRejected=";
  static final String STR_INVALID_HOST_OR_IP_WHILE_PARSING =
      "Invalid hostname or IP Address syntax error while parsing new peer reference: ";
  static final String SFS_KEY_ARK_PUBURI = "ark.pubURI";
  static final String SFS_KEY_ARK_NUMBER = "ark.number";
  static final String SFS_KEY_SIG_P256 = "sigP256";

  private final PeerNodeInternals internals;

  private String lastGoodVersion;

  /**
   * True if this peer has a build number older than our last-known-good build number. Note that
   * even if this is true, the node can still be 'connected'.
   */
  protected boolean unroutableOlderVersion;

  /**
   * True if this peer reports that our build number is before their last-known-good build number.
   * Note that even if this is true, the node can still be 'connected'.
   */
  protected boolean unroutableNewerVersion;

  /**
   * Indicates whether routing to this peer is currently disabled by policy. When true, routing
   * decisions treat the peer as ineligible even if it is otherwise connected; control traffic may
   * still flow. Updated under the peer lock as configuration or remote signals change.
   */
  protected boolean disableRouting;

  /**
   * Records whether local configuration explicitly set {@link #disableRouting}. This flag lets the
   * node distinguish local intent from remote requests and preserves local overrides across later
   * updates. It is read and written under the peer lock only.
   */
  protected boolean disableRoutingHasBeenSetLocally;

  /**
   * Records whether the remote peer has asked us to disable routing. The flag is advisory and may
   * be overridden by local policy. It is maintained under the peer lock and influences the
   * effective routing eligibility calculation.
   */
  protected boolean disableRoutingHasBeenSetRemotely;

  /*
   * Buffer of Ni,Nr,g^i,g^r,ID
   */
  private byte[] jfkBuffer;

  // Note: consider additional synchronization if needed

  /**
   * Ephemeral JFK key agreement output used during handshake processing. The byte array is
   * short-lived, may be cleared after handshake completion, and must be treated as sensitive keying
   * material. Access is synchronized via the handshake logic.
   */
  protected byte[] jfkKa;

  /**
   * Session key for inbound packet decryption once a tracker becomes active. This is negotiated
   * during a handshake, rotated during rekeying, and cleared when the tracker is discarded. Treat
   * as sensitive key material and never log.
   */
  protected byte[] incommingKey;

  /**
   * Ephemeral JFK key agreement output used for handshake encryption. It is derived during
   * handshake, used to derive session keys, and cleared after promotion to an active tracker. This
   * buffer is sensitive and may be nulled to reduce retention.
   */
  protected byte[] jfkKe;

  /**
   * Session key for outbound packet encryption once a tracker becomes active. It is negotiated in
   * the handshake, rotated during rekeying, and cleared when the tracker is discarded. Treat as
   * sensitive key material and never log.
   */
  protected byte[] outgoingKey;

  /**
   * Cached serialized noderef used during JFK handshake negotiation. The value is only relevant
   * during connection setup and may be cleared afterward. It is treated as a transient state and
   * should not be assumed to persist across reconnections.
   */
  protected byte[] jfkMyRef;

  /**
   * HMAC key used to authenticate messages in the active session. It is negotiated during a
   * handshake, rotated during rekeying, and cleared when the tracker is discarded. This key is
   * sensitive and must not be logged or persisted.
   */
  protected byte[] hmacKey;

  /**
   * IV derivation key for the active session. The value is negotiated during handshake and used
   * alongside {@link #ivNonce} to derive per-packet IVs. It is sensitive and cleared when the
   * session tracker is discarded.
   */
  protected byte[] ivKey;

  /**
   * Nonce material used with {@link #ivKey} for per-packet IV derivation. The value is negotiated
   * during a handshake and must remain paired with the current tracker; it is cleared when the
   * tracker is discarded.
   */
  protected byte[] ivNonce;

  /**
   * Initial outbound packet sequence number for the most recent handshake. The value seeds packet
   * numbering for a new tracker and is updated when a new session is negotiated.
   */
  protected int ourInitialSeqNum;

  /**
   * Initial inbound packet sequence number for the most recent handshake. The value seeds packet
   * numbering expectations for a new tracker and is updated when a new session is negotiated.
   */
  protected int theirInitialSeqNum;

  /**
   * Initial outbound message identifier for the most recent handshake. The value seeds message
   * numbering for a new tracker and is updated when a new session is negotiated.
   */
  protected int ourInitialMsgID;

  /**
   * Initial inbound message identifier for the most recent handshake. The value seeds message
   * numbering expectations for a new tracker and is updated when a new session is negotiated.
   */
  protected int theirInitialMsgID;

  // The following is used only if we are the initiator

  /**
   * Lifetime in milliseconds for JFK handshake context data. A value of zero means no lifetime has
   * been established yet. This is used to expire handshake state and is updated under the peer
   * lock.
   */
  protected long jfkContextLifetime = 0;

  /** My low-level address for SocketManager purposes */
  private Peer detectedPeer = null;

  /** My OutgoingPacketMangler i.e., the object which encrypts packets sent to this node */
  private final OutgoingPacketMangler outgoingMangler;

  /** Advertised addresses */
  List<Peer> nominalPeer;

  /** The PeerNode's report of our IP address */
  private Peer remoteDetectedPeer;

  /** Is this a testnet node? */
  public final boolean testnetEnabled;

  /** Packets sent/received on the current preferred key */
  private SessionKey currentTracker;

  /** Previous key - has a separate packet number space */
  private SessionKey previousTracker;

  /** When did we last rekey (promote the unverified tracker to new)? */
  private long timeLastRekeyed;

  /** How much data did we send with the current tracker? */
  private long totalBytesExchangedWithCurrentTracker = 0;

  /** Are we rekeying? */
  private boolean isRekeying = false;

  /** Unverified tracker - will be promoted to the currentTracker if we receive packets on it */
  private SessionKey unverifiedTracker;

  /** When did we last send a packet? */
  private long timeLastSentPacket;

  /** When did we last receive a packet? */
  private long timeLastReceivedPacket;

  /** When did we last receive a non-auth packet? */
  private long timeLastReceivedDataPacket;

  /** When did we last receive an ack? */
  private long timeLastReceivedAck;

  /** When was isRoutingCompatible() last true? */
  private long timeLastRoutable;

  /** Time added or restarted (reset on startup unlike peerAddedTime) */
  private final long timeAddedOrRestarted;

  private long countSelectionsSinceConnected = 0;

  /**
   * Percentage threshold that triggers a selection warning for this peer. The value is expressed as
   * a whole percent in the range {@code 0..100}, and comparisons are performed against recent
   * selection counts while connected. This is a diagnostic threshold only; it does not alter
   * routing behavior.
   */
  public static final int SELECTION_PERCENTAGE_WARNING = 30;

  /**
   * Minimum number of routable peers required before selection warnings are meaningful. Below this
   * count the selection warning logic is intentionally suppressed to avoid noisy alerts in small
   * networks. The value is a peer-count threshold, not a percentage.
   */
  public static final int SELECTION_MIN_PEERS = 5;

  // Note: isRoutable() depends on more than this flag.
  private boolean isRoutable;

  /** Used by maybeOnConnect */
  private boolean wasDisconnected = true;

  /**
   * Were we removed from the routing table? Used as a cache to avoid accessing PeerManager if not
   * needed.
   */
  private boolean removed;

  /** Number of handshake attempts since the last successful connection or ARK fetch */
  private int handshakeCount;

  /** After these many failed handshakes, we start the ARK fetcher. */
  private static final int MAX_HANDSHAKE_COUNT = 2;

  /**
   * Node "identity". This is a random 32-byte block of data, which may be derived from the node's
   * public key. It cannot be changed and is only used for the outer keyed obfuscation on connection
   * setup packets in FNPPacketMangler.
   */
  final byte[] identity;

  final String identityAsBase64String;

  /** Hash of node identity. Used in setup keys. */
  final byte[] identityHash;

  /** Hash of node identity. Used in setup keys. */
  final byte[] identityHashHash;

  /**
   * Semi-unique ID used to help in mapping the network (see the code that uses it). Note this is
   * for diagnostic purposes only and should be removed along with the code that uses it eventually.
   */
  final long swapIdentifier;

  /** Negotiation types supported */
  int[] negTypes;

  /** Integer hash of the peer's public key. Used as hashCode(). */
  final int hashCode;

  /** The Node we serve */
  final Node node;

  /** The PeerManager we serve */
  final PeerManager peers;

  /**
   * MessageItem's to send ASAP. LOCKING: Lock on self, always take that lock last. Sometimes used
   * inside the peer lock.
   */
  private final PeerMessageQueue messageQueue;

  /** When did we last receive a SwapRequest? */
  private long timeLastReceivedSwapRequest;

  /** When did we last receive a probe request? */
  private long timeLastReceivedProbeRequest;

  /**
   * Should we decrement HTL when it is at the maximum? This decision is made once per node to
   * prevent giving away information that can make correlation attacks much easier.
   */
  final boolean decrementHTLAtMaximum;

  /** Should we decrement HTL when it is at the minimum (1)? */
  final boolean decrementHTLAtMinimum;

  /** Time at which we should send the next handshake request */
  protected long sendHandshakeTime;

  /** Version of the node */
  private String version;

  /** Cached parsed version components to avoid reparsing */
  private final AtomicReference<String[]> parsedVersionComponents = new AtomicReference<>();

  /** Total bytes received since startup */
  private long totalInputSinceStartup;

  /** Total bytes sent since startup */
  private long totalOutputSinceStartup;

  /** Peer node public key; changing this means a new noderef */
  final ECPublicKey peerECDSAPubKey;

  /** Note: Used by the N2NChat plugin because the getter is protected. */
  public final byte[] peerECDSAPubKeyHash;

  private boolean isSignatureVerificationSuccessfull;

  /**
   * Incoming setup key. Used to decrypt incoming auth packets. Specifically: K_node XOR
   * H(setupKey).
   */
  final byte[] incomingSetupKey;

  /**
   * Outgoing setup key. Used to encrypt outgoing auth packets. Specifically: setupKey XOR
   * H(K_node).
   */
  final byte[] outgoingSetupKey;

  private final PeerNodeHandshake handshake;

  /**
   * The other side's boot ID. This is a random number generated at startup. LOCKING: It is far too
   * dangerous to hold the main (this) lock while accessing bootID given that we ask for it in the
   * messaging code and so on. This is essentially a "the other side restarted" flag, so there isn't
   * really a consistency issue with the rest of PeerNode. So it's okay to effectively use a
   * separate lock for it.
   */
  private volatile long bootID;

  /**
   * Our boot ID. This is set to a random number on startup, and then reset whenever we dump the
   * in-flight messages and call disconnected() on their clients, i.e., whenever we call
   * disconnected(true, ...)
   */
  private long myBootID;

  /** myBootID at the time of the last successful completed handshake. */
  private long myLastSuccessfulBootID;

  /** If true, this means the last time we tried, we got a bogus noderef */
  private boolean bogusNoderef;

  /** The time at which we last completed a connection setup. */
  private long connectedTime;

  /** The status of this peer node in terms of Node.PEER_NODE_STATUS_* */
  private int peerNodeStatus = PeerManager.PEER_NODE_STATUS_DISCONNECTED;

  /**
   * Holds a String-Long pair that shows which message types (as name) have been sent to this peer.
   */
  private final java.util.HashMap<String, Long> localNodeSentMessageTypes =
      new java.util.HashMap<>();

  /**
   * Holds a String-Long pair that shows which message types (as name) have been received by this
   * peer.
   */
  private final java.util.HashMap<String, Long> localNodeReceivedMessageTypes =
      new java.util.HashMap<>();

  /** Hold collected IP addresses for handshake attempts, populated by DNSRequestor */
  private Peer[] handshakeIPs;

  /** True if we have never connected to this peer since it was added to this node */
  protected boolean neverConnected;

  /**
   * When this peer was added to this node. This is used differently by opennet and darknet nodes.
   * Darknet nodes clear it after connecting but persist it across restarts and clear it on restart
   * unless the peer has never connected, or if it is more than 30 days ago. Opennet nodes clear it
   * after the post-connection grace period elapses and don't persist it across restarts.
   */
  protected long peerAddedTime;

  /** Bytes received at/before startup */
  private final long bytesInAtStartup;

  /** Bytes sent at/before startup */
  private final long bytesOutAtStartup;

  /** Times had a routable connection when checked */
  private long hadRoutableConnectionCount;

  /** Times checked for routable connection */
  private long routableConnectionCheckCount;

  /**
   * Delta between our clock and his clock (positive = his clock is fast, negative = our clock is
   * fast)
   */
  private long clockDelta;

  /** Percentage uptime of this node, 0 if they haven't said */
  private byte uptime;

  /**
   * If the clock delta is more than this constant, we don't talk to the node. Reason: It may not be
   * up to date, it will have difficulty resolving date-based content etc.
   */
  private static final long MAX_CLOCK_DELTA = DAYS.toMillis(1);

  /**
   * 1 hour after the node is disconnected, if it is still disconnected and hasn't connected in that
   * time, clear the message queue
   */
  private static final long CLEAR_MESSAGE_QUEUE_AFTER = HOURS.toMillis(1);

  /**
   * A WeakReference to this object. Can be taken whenever a node object needs to refer to this
   * object for a long time, but without preventing it from being GC'ed.
   */
  final WeakReference<PeerNode> myRef;

  /**
   * A {@link PeerContext}-typed view of {@link #myRef} for APIs that operate on the transport view.
   * The reference object itself is shared to avoid additional allocations.
   */
  private final WeakReference<PeerContext> contextRef;

  /** The node is being disconnected, but it may take a while. */
  private boolean disconnecting;

  /** When did we last disconnect? Not Disconnected because of a discrete event */
  long timeLastDisconnect;

  /** Previous time of disconnection */
  long timePrevDisconnect;

  // Burst-only mode
  /** True if we are currently sending this peer a burst of handshake requests */
  private boolean isBursting;

  /** Number of handshake attempts (while in ListenOnly mode) since the beginning of this burst */
  private int listeningHandshakeBurstCount;

  /** Total number of handshake attempts (while in ListenOnly mode) to be in this burst */
  private int listeningHandshakeBurstSize;

  // NodeCrypto for the relevant node reference for this peer's type (Darknet or Opennet at this
  // time)
  final NodeCrypto crypto;

  /** Backoff guard used by {@link #shouldBeExcludedFromPeerList()}. */
  public static final long BLACK_MAGIC_BACKOFF_PRUNING_TIME = MINUTES.toMillis(5);

  /**
   * Fractional threshold used to prune stale backoff data. The value is a proportion in the range
   * {@code 0.0..1.0} and is applied alongside {@link #BLACK_MAGIC_BACKOFF_PRUNING_TIME} to decide
   * when to drop old backoff entries. This value is intentionally conservative and read-only.
   */
  public static final double BLACK_MAGIC_BACKOFF_PRUNING_PERCENTAGE = 0.9;

  /** Non-cryptographic random source scoped to this PeerNode. Thread-safe. */
  protected final Random random;

  /**
   * Cached full noderef field set when available. This may be {@code null} if only a partial
   * noderef has been observed. The value is mutable, accessed under the peer lock, and used for
   * persistence and export.
   */
  protected SimpleFieldSet fullFieldSet;

  /**
   * Returns whether to ignore last-known-good version checks for this peer.
   *
   * <p>Subclasses can override this to bypass compatibility checks in special cases such as seed or
   * test configurations. The default returns {@code false} to enforce compatibility.
   *
   * @return {@code true} to ignore last-good version checks
   */
  protected boolean ignoreLastGoodVersion() {
    return false;
  }

  @SuppressWarnings("unchecked")
  private static WeakReference<PeerContext> castPeerContextRef(WeakReference<PeerNode> ref) {
    // Safe because PeerNode implements PeerContext and the WeakReference only exposes get().
    return (WeakReference<PeerContext>) (WeakReference<?>) ref;
  }

  /**
   * Returns this instance as the {@link PeerNode} API type.
   *
   * <p>This helper is used when passing {@code this} to APIs that expect the public type. It does
   * not create a new object and is safe to call repeatedly. The returned reference is the same
   * instance, so callers must still respect the locking rules described on the class.
   *
   * @return this instance typed as {@link PeerNode} for API convenience
   */
  protected final PeerNode selfPeerNode() {
    return this;
  }

  /**
   * Creates a PeerNode from a {@link SimpleFieldSet} node reference.
   *
   * <p>Does not register the instance with {@link PeerManager}.
   *
   * @param fs node reference to parse
   * @param node2 running node instance
   * @param crypto crypto context for this peer type
   * @param fromLocal whether the noderef originated from the local peers file (may include unsigned
   *     local metadata); otherwise the noderef must be signed and should not contain metadata
   * @param peers peer manager instance
   * @throws FSParseException if the field set is malformed
   */
  PeerNode(SimpleFieldSet fs, Node node2, NodeCrypto crypto, boolean fromLocal, PeerManager peers)
      throws FSParseException {
    boolean noSig = fromLocal || fromAnonymousInitiator();
    // Core finals
    myRef = new WeakReference<>(selfPeerNode());
    contextRef = castPeerContextRef(myRef);
    this.checkStatusAfterBackoff = new PeerNodeBackoffStatusChecker(myRef);
    this.outgoingMangler = crypto.getPacketMangler();
    this.node = node2;
    this.crypto = crypto;
    if (crypto.isOpennet() != isOpennetForNoderef()) {
      throw new IllegalArgumentException("Mismatched NodeCrypto for noderef type");
    }
    this.random = node.bootstrap().createRandom();
    if (peers == null) throw new NullPointerException("peers");
    this.peers = peers;
    this.internals = new PeerNodeInternals(selfPeerNode(), node2, fs.get(SFS_KEY_LOCATION));
    this.myBootID = node2.getBootId();
    this.bootID = 0;

    parseAndSetVersion(fs);
    // Location & routing
    disableRouting = disableRoutingHasBeenSetLocally = false;
    disableRoutingHasBeenSetRemotely = false;
    lastGoodVersion = fs.get(SFS_KEY_LAST_GOOD_VERSION);
    updateVersionRoutablity();
    // Testnet flag (final)
    this.testnetEnabled = readTestnetEnabled(fs);
    if (testnetEnabled) {
      String err = "Ignoring incompatible testnet node " + fs.toOrderedString();
      LOG.error(err);
      throw new FSParseException(err);
    }
    parseNegotiationTypes(fs);
    validateOpennetFlag(fs);
    // Peer key (final)
    this.peerECDSAPubKey = readPeerEcdsaKeyReturn(fs);
    this.peerECDSAPubKeyHash = internals.computePeerPublicKeyHash(peerECDSAPubKey);
    verifySignatureIfPresent(fs, noSig);
    // Identity (finals)
    IdentityValues ids = readIdentityValues(fs);
    this.identity = ids.identity;
    this.identityAsBase64String = ids.identityAsBase64String;
    this.identityHash = ids.identityHash;
    this.identityHashHash = ids.identityHashHash;
    this.swapIdentifier = ids.swapIdentifier;
    this.hashCode = ids.hashCode;
    // Setup keys & ciphers (finals)
    this.incomingSetupKey = computeIncomingSetupKey(crypto, identityHashHash);
    this.outgoingSetupKey = computeOutgoingSetupKey(crypto, identityHash);
    this.handshake = new PeerNodeHandshake(incomingSetupKey, outgoingSetupKey, identityHash);

    parseNominalPeers(fs, fromLocal);
    // Runtime state (finals first)
    // Don't create trackers until we have a key
    currentTracker = null;
    previousTracker = null;
    timeLastSentPacket = -1;
    timeLastReceivedPacket = -1;
    timeLastReceivedSwapRequest = -1;
    timeLastRoutable = -1;
    this.timeAddedOrRestarted = System.currentTimeMillis();
    this.messageQueue = new PeerMessageQueue(random);
    this.decrementHTLAtMaximum = random.nextFloat() < Node.DECREMENT_AT_MAX_PROB;
    this.decrementHTLAtMinimum = random.nextFloat() < Node.DECREMENT_AT_MIN_PROB;
    pingNumber = random.nextLong();
    // ARK info
    parseARK(fs, true, false);
    // Metadata and counters
    long now = System.currentTimeMillis();
    MetadataInit meta = parseMetadata(fs, fromLocal, now);
    if (meta.detectedPeer != null) this.detectedPeer = meta.detectedPeer;
    // Refresh cached short string now that detectedPeer may have changed.
    updateShortToString();
    this.timeLastReceivedPacket = meta.timeLastReceivedPacket;
    this.timeLastRoutable = meta.timeLastRoutable;
    this.peerAddedTime = meta.peerAddedTime;
    this.neverConnected = meta.neverConnected;
    this.hadRoutableConnectionCount = meta.hadRoutableConnectionCount;
    this.routableConnectionCheckCount = meta.routableConnectionCheckCount;
    internals.initConnectionState(meta.timeLastConnected);
    // Apply restart-time adjustments after fields are populated from metadata so overrides can
    // act on persisted values and persist their changes.
    if (fromLocal) maybeClearPeerAddedTimeOnRestart(now);
    // Populate handshake IPs quickly
    internals.resetHandshakeIpUpdateTimer();
    // Handshake scheduling
    scheduleFirstHandshake(fromLocal, now);
    // Byte counters (finals)
    this.bytesInAtStartup = fs.getLong("totalInput", 0);
    this.bytesOutAtStartup = fs.getLong("totalOutput", 0);
    if (fromLocal) {
      SimpleFieldSet f = fs.subset("full");
      if (fullFieldSet == null && f != null) fullFieldSet = f;
    }
    // If we got here, odds are we should consider writing to the peer-file
    writePeers();
    // status may have changed from PEER_NODE_STATUS_DISCONNECTED to
    // PEER_NODE_STATUS_NEVER_CONNECTED
  }

  private void parseAndSetVersion(SimpleFieldSet fs) throws FSParseException {
    version = fs.get(SFS_KEY_VERSION);
    parsedVersionComponents.set(null); // Invalidate cache
    Version.seenVersion(version);
    try {
      simpleVersion = Version.parseBuildNumberFromVersionStr(version);
    } catch (VersionParseException e2) {
      throw new FSParseException("Invalid version " + version + " : " + e2);
    }
  }

  private boolean readTestnetEnabled(SimpleFieldSet fs) {
    return fs.getBoolean(SFS_KEY_TESTNET, false);
  }

  private void parseNegotiationTypes(SimpleFieldSet fs) throws FSParseException {
    negTypes = fs.getIntArray(SFS_KEY_NEG_TYPES);
    if (negTypes == null || negTypes.length == 0) {
      if (fromAnonymousInitiator()) {
        negTypes = outgoingMangler.supportedNegTypes(false);
      } else {
        throw new FSParseException("No negTypes!");
      }
    }
  }

  private void validateOpennetFlag(SimpleFieldSet fs) throws FSParseException {
    if (fs.getBoolean(SFS_KEY_OPENNET, false) != isOpennetForNoderef()) {
      throw new FSParseException(
          "Trying to parse a darknet peer as opennet or an opennet peer as darknet isOpennet="
              + isOpennetForNoderef()
              + " boolean = "
              + fs.getBoolean(SFS_KEY_OPENNET, false)
              + " string = \""
              + fs.get(SFS_KEY_OPENNET)
              + "\"");
    }
  }

  private ECPublicKey readPeerEcdsaKeyReturn(SimpleFieldSet fs) throws FSParseException {
    try {
      return internals.readPeerEcdsaKeyReturn(fs);
    } catch (Exception e) {
      if (e instanceof FSParseException fsParseException) {
        throw fsParseException;
      }
      throw new FSParseException("Invalid peer ECDSA key", e);
    }
  }

  private void verifySignatureIfPresent(SimpleFieldSet fs, boolean noSig) throws FSParseException {
    try {
      internals.verifySignatureIfPresent(fs, noSig);
    } catch (Exception e) {
      throw new FSParseException("Invalid peer noderef signature", e);
    }
  }

  private IdentityValues readIdentityValues(SimpleFieldSet fs) throws FSParseException {
    try {
      return internals.readIdentityValues(fs);
    } catch (Exception e) {
      if (e instanceof FSParseException fsParseException) {
        throw fsParseException;
      }
      throw new FSParseException("Invalid peer identity", e);
    }
  }

  private byte[] computeIncomingSetupKey(NodeCrypto crypto, byte[] identityHashHash) {
    return internals.computeIncomingSetupKey(crypto, identityHashHash);
  }

  private byte[] computeOutgoingSetupKey(NodeCrypto crypto, byte[] identityHash) {
    return internals.computeOutgoingSetupKey(crypto, identityHash);
  }

  private void parseNominalPeers(SimpleFieldSet fs, boolean fromLocal) {
    nominalPeer = new ArrayList<>();
    String[] physical = fs.getAll(SFS_KEY_PHYSICAL_UDP);
    if (physical != null) {
      for (String phys : physical) {
        for (Peer p : parsePeerEntryCompat(phys, fromLocal)) {
          if (p != null && !nominalPeer.contains(p)) nominalPeer.add(p);
        }
      }
    }
    if (nominalPeer.isEmpty()) {
      LOG.atInfo()
          .addArgument(() -> identityAsBase64String)
          .addArgument(internals::locationToString)
          .addArgument(this::userToString)
          .log("No IP addresses found for identity '{}', possibly at location '{}: {}");
    }
    updateShortToString();
  }

  /**
   * Parses a physical.udp entry. In addition to the standard "host:port" form, tolerates a
   * comma-separated host list with a shared port suffix (e.g., "A,B:port") or multiple
   * comma-separated full entries (e.g., "A:port,B:port"). Returns zero or more parsed peers.
   */
  private List<Peer> parsePeerEntryCompat(String phys, boolean fromLocal) {
    return internals.parsePeerEntryCompat(phys, fromLocal);
  }

  private MetadataInit parseMetadata(SimpleFieldSet fs, boolean fromLocal, long now) {
    MetadataInit result = new MetadataInit();
    if (!fromLocal) {
      result.timeLastConnected = -1;
      result.neverConnected = true;
      result.peerAddedTime = now;
      return result;
    }
    SimpleFieldSet metadata = fs.subset(SFS_KEY_METADATA);
    if (metadata == null) {
      result.timeLastConnected = -1;
      return result;
    }
    return buildMetadataFromSubset(fs, metadata);
  }

  private MetadataInit buildMetadataFromSubset(SimpleFieldSet rootFs, SimpleFieldSet metadata) {
    MetadataInit result = new MetadataInit();
    internals.setPeerLocations(rootFs.getAll("peersLocation"));
    result.detectedPeer = internals.parseDetectedPeer(metadata);
    result.timeLastReceivedPacket = metadata.getLong("timeLastReceivedPacket", -1);
    long timeLastConnected = metadata.getLong("timeLastConnected", -1);
    result.timeLastRoutable = metadata.getLong("timeLastRoutable", -1);
    if (timeLastConnected < 1 && result.timeLastReceivedPacket > 1)
      timeLastConnected = result.timeLastReceivedPacket;
    result.timeLastConnected = timeLastConnected;
    if (result.timeLastRoutable < 1 && result.timeLastReceivedPacket > 1)
      result.timeLastRoutable = result.timeLastReceivedPacket;
    result.peerAddedTime = metadata.getLong(SFS_KEY_PEER_ADDED_TIME, 0);
    result.neverConnected = metadata.getBoolean("neverConnected", false);
    result.hadRoutableConnectionCount = metadata.getLong("hadRoutableConnectionCount", 0);
    result.routableConnectionCheckCount = metadata.getLong("routableConnectionCheckCount", 0);
    return result;
  }

  private void scheduleFirstHandshake(boolean fromLocal, long now) {
    listeningHandshakeBurstCount = 0;
    listeningHandshakeBurstSize =
        Node.MIN_BURSTING_HANDSHAKE_BURST_SIZE
            + random.nextInt(Node.RANDOMIZED_BURSTING_HANDSHAKE_BURST_SIZE);
    if (isBurstOnly()) {
      LOG.debug(
          "First BurstOnly mode handshake in {}" + STR_MS_FOR + "{} (count: {}, size: {})",
          sendHandshakeTime - now,
          shortToString(),
          listeningHandshakeBurstCount,
          listeningHandshakeBurstSize);
    }
    if (fromLocal)
      innerCalcNextHandshake(false, now); // Let them connect so we can recognize we are NATed
    else sendHandshakeTime = now; // Be sure we're ready to handshake right away
  }

  static final class IdentityValues {
    final byte[] identity;
    final String identityAsBase64String;
    final byte[] identityHash;
    final byte[] identityHashHash;
    final long swapIdentifier;
    final int hashCode;

    IdentityValues(
        byte[] identity,
        String identityAsBase64String,
        byte[] identityHash,
        byte[] identityHashHash,
        long swapIdentifier,
        int hashCode) {
      this.identity = identity;
      this.identityAsBase64String = identityAsBase64String;
      this.identityHash = identityHash;
      this.identityHashHash = identityHashHash;
      this.swapIdentifier = swapIdentifier;
      this.hashCode = hashCode;
    }
  }

  private static final class MetadataInit {
    Peer detectedPeer;
    long timeLastReceivedPacket;
    long timeLastRoutable;
    long timeLastConnected;
    long peerAddedTime;
    boolean neverConnected;
    long hadRoutableConnectionCount;
    long routableConnectionCheckCount;
  }

  private static final class PeerNodeInternals {
    private final PeerNode peerNode;
    private final Node node;
    private final PeerNodeReferenceSupport referenceSupport;
    private final PeerNodeOfferSupport offerSupport;
    private final PeerNodeTransport transport;
    private final PeerNodeArkManager arkManager;
    private final PeerNodeAddressManager addressManager;
    private final PeerNodeRoutingStats routingStats;
    private final PeerLocation location;
    private final PeerNodeLoadTracker loadTracker;
    private final PeerNodeJfkNonces jfkNoncesSent = new PeerNodeJfkNonces();

    private PeerNodeConnectionState connectionState = new PeerNodeConnectionState(0);
    private PacketFormat packetFormat;

    PeerNodeInternals(PeerNode peerNode, Node node, String locationString) {
      this.peerNode = peerNode;
      this.node = node;
      referenceSupport = new PeerNodeReferenceSupport(peerNode);
      offerSupport = new PeerNodeOfferSupport(peerNode);
      transport = new PeerNodeTransport(peerNode);
      arkManager = new PeerNodeArkManager(peerNode);
      addressManager = new PeerNodeAddressManager(peerNode);
      routingStats = new PeerNodeRoutingStats(node);
      location = new PeerLocation(locationString);
      loadTracker = new PeerNodeLoadTracker(peerNode);
    }

    byte[] computePeerPublicKeyHash(ECPublicKey peerEcdsaPubKey) {
      return referenceSupport.computePeerPublicKeyHash(peerEcdsaPubKey);
    }

    ECPublicKey readPeerEcdsaKeyReturn(SimpleFieldSet fs) throws FSParseException {
      try {
        return referenceSupport.readPeerEcdsaKeyReturn(fs);
      } catch (Exception e) {
        if (e instanceof FSParseException fsParseException) {
          throw fsParseException;
        }
        throw new FSParseException("Invalid peer ECDSA key", e);
      }
    }

    void verifySignatureIfPresent(SimpleFieldSet fs, boolean noSig) throws FSParseException {
      try {
        referenceSupport.verifySignatureIfPresent(fs, noSig);
      } catch (Exception e) {
        throw new FSParseException("Invalid peer noderef signature", e);
      }
    }

    IdentityValues readIdentityValues(SimpleFieldSet fs) throws FSParseException {
      try {
        return referenceSupport.readIdentityValues(fs);
      } catch (Exception e) {
        if (e instanceof FSParseException fsParseException) {
          throw fsParseException;
        }
        throw new FSParseException("Invalid peer identity", e);
      }
    }

    byte[] computeIncomingSetupKey(NodeCrypto crypto, byte[] identityHashHash) {
      return referenceSupport.computeIncomingSetupKey(crypto, identityHashHash);
    }

    byte[] computeOutgoingSetupKey(NodeCrypto crypto, byte[] identityHash) {
      return referenceSupport.computeOutgoingSetupKey(crypto, identityHash);
    }

    BlockCipher buildRijndaelCipher(byte[] keyBytes) {
      return referenceSupport.buildRijndaelCipher(keyBytes);
    }

    String formatDuration(long millis) {
      return referenceSupport.formatDuration(millis);
    }

    String formatPeerKeyHash(byte[] hash) {
      return referenceSupport.formatPeerKeyHash(hash);
    }

    boolean verifyReferenceSignature(SimpleFieldSet fs) throws FSParseException {
      try {
        return referenceSupport.verifyReferenceSignature(fs);
      } catch (Exception e) {
        throw new FSParseException("Invalid signature", e);
      }
    }

    Peer tryParsePeer(String phys) {
      return referenceSupport.tryParsePeer(phys);
    }

    void checkTestnetAndOpennet(SimpleFieldSet fs, boolean forDiffNodeRef, boolean forFullNodeRef)
        throws FSParseException {
      referenceSupport.checkTestnetAndOpennet(fs, forDiffNodeRef, forFullNodeRef);
    }

    void validateIdentity(SimpleFieldSet fs, boolean forDiffNodeRef, boolean forFullNodeRef)
        throws FSParseException {
      referenceSupport.validateIdentity(fs, forDiffNodeRef, forFullNodeRef);
    }

    void parseEcdsaFields(SimpleFieldSet fs) throws FSParseException {
      referenceSupport.parseEcdsaFields(fs);
    }

    void putEcdsaFields(SimpleFieldSet fs, ECPublicKey key) {
      referenceSupport.putEcdsaFields(fs, key);
    }

    boolean parseArk(SimpleFieldSet fs, boolean onStartup, boolean forDiffNodeRef) {
      return arkManager.parseArk(fs, onStartup, forDiffNodeRef);
    }

    void appendArkFields(SimpleFieldSet fs) {
      arkManager.appendArkFields(fs);
    }

    void handleArkUpdate(SimpleFieldSet fs, long fetchedEdition) {
      arkManager.handleArkUpdate(fs, fetchedEdition);
    }

    boolean isFetchingArk() {
      return arkManager.isFetching();
    }

    void startArkFetcher() {
      arkManager.startFetcher();
    }

    void stopArkFetcher() {
      arkManager.stopFetcher();
    }

    void offer(Key key) {
      offerSupport.offer(key);
    }

    void notifyOpennetOnDisconnect(Node node) {
      OpennetManager om = node.network().opennet();
      if (om != null) om.onDisconnect();
    }

    void notifyOpennetOnConnect(Node node, PeerNode peerNode) {
      OpennetManager om = node.network().opennet();
      if (om != null) {
        // OpennetManager must be notified of a new connection even if it is a darknet peer.
        om.onConnectedPeer(peerNode);
      }
    }

    void resetHandshakeIpUpdateTimer() {
      addressManager.resetHandshakeIpUpdateTimer();
    }

    Peer parseDetectedPeer(SimpleFieldSet metadata) {
      return addressManager.parseDetectedPeer(metadata);
    }

    List<Peer> parsePeerEntryCompat(String phys, boolean fromLocal) {
      return referenceSupport.parsePeerEntryCompat(phys, fromLocal);
    }

    void maybeUpdateHandshakeIPs(boolean ignoreHostnames) {
      addressManager.maybeUpdateHandshakeIPs(ignoreHostnames);
    }

    Peer getHandshakeIP() {
      return addressManager.getHandshakeIP();
    }

    void markHandshakeIpUpdateAttempted(long now) {
      addressManager.markHandshakeIpUpdateAttempted(now);
    }

    boolean isConnected() {
      return connectionState.isConnected();
    }

    boolean setConnected(boolean connected, long now) {
      return connectionState.setConnected(connected, now);
    }

    long timeLastConnected(long now) {
      return connectionState.timeLastConnected(now);
    }

    boolean isBurstOnly(OutgoingPacketMangler outgoingMangler, Random random) {
      return connectionState.isBurstOnly(outgoingMangler, random);
    }

    void registerStatusChangeListener(Object listener) {
      connectionState.registerStatusChangeListener((PeerManager.PeerStatusChangeListener) listener);
    }

    void notifyStatusChangeListeners() {
      connectionState.notifyStatusChangeListeners();
    }

    void initConnectionState(long lastConnectedTime) {
      connectionState = new PeerNodeConnectionState(lastConnectedTime);
    }

    PeerTransport transport() {
      return transport;
    }

    void maybeDisconnected() {
      transport.getThrottle().maybeDisconnected();
    }

    double bandwidth() {
      return transport.getThrottle().getBandwidth();
    }

    void sendIPAddressMessage() {
      transport.sendIPAddressMessage();
    }

    void sendInitialMessages() {
      transport.sendInitialMessages();
    }

    void sendNodeToNodeMessage(
        SimpleFieldSet fs,
        int n2nType,
        boolean includeSentTime,
        long now,
        boolean queueOnNotConnected) {
      transport.sendNodeToNodeMessage(fs, n2nType, includeSentTime, now, queueOnNotConnected);
    }

    long getResendBytesSent() {
      return transport.getResendBytesSent();
    }

    void resendBytes(int bytesToResend) {
      transport.resendBytes(bytesToResend);
    }

    @SuppressWarnings("unused")
    PeerNodeJfkNonces jfkNoncesSent() {
      return jfkNoncesSent;
    }

    void clearJfkNoncesSent() {
      jfkNoncesSent.clear();
    }

    void rememberJfkNonce(byte[] nonce, int maxNoncesPerPeer) {
      jfkNoncesSent.rememberNonce(nonce, maxNoncesPerPeer);
    }

    byte[] findOriginalJfkNonceByHash(byte[] nonceHash) {
      return jfkNoncesSent.findOriginalNonceByHash(nonceHash);
    }

    void setPacketFormat(PacketFormat packetFormat) {
      this.packetFormat = packetFormat;
    }

    void clearPacketFormat() {
      packetFormat = null;
    }

    PacketFormat packetFormat() {
      return packetFormat;
    }

    boolean maybeSendPacket(long now, boolean ackOnly) {
      PacketFormat pf;
      synchronized (peerNode) {
        pf = packetFormat;
        if (pf == null) return false;
      }
      try {
        return pf.maybeSendPacket(now, ackOnly);
      } catch (BlockedTooLongException e) {
        LOG.error(
            "Packet number allocation blocked {} (peer={}, version={}) - disconnecting",
            formatDuration(e.delta),
            peerNode,
            peerNode.getBuildNumber());
        peerNode.forceDisconnect();
        return false;
      }
    }

    void reportLoadStatus(Object stat) {
      loadTracker.reportLoadStatus((PeerLoadStats) stat);
    }

    void noLongerRoutingTo(Object tag, boolean offeredKey) {
      loadTracker.noLongerRoutingTo(tag, offeredKey);
    }

    void maybeNotifySlotWaiter(boolean realTime) {
      loadTracker.maybeNotifySlotWaiter(realTime);
    }

    void postUnlock(Object tag) {
      loadTracker.postUnlock(tag);
    }

    PeerNodeLoadTracker.OutputLoadTracker outputLoadTracker(boolean realTime) {
      return loadTracker.outputLoadTracker(realTime);
    }

    PeerNodeLoadTracker.IncomingLoadSummaryStats getIncomingLoadStats(boolean realTime) {
      return loadTracker.getIncomingLoadStats(realTime);
    }

    boolean missingLastIncomingLoadStats(boolean realTime) {
      return loadTracker.getLastIncomingLoadStats(realTime) == null;
    }

    boolean isLowCapacity(boolean isRealtime) {
      PeerLoadStats stats = loadTracker.getLastIncomingLoadStats(isRealtime);
      if (stats == null) return false;
      NodePinger pinger = node.network().stats().nodePinger;
      if (pinger.capacityThreshold(isRealtime, true) > stats.peerLimit(true)) return true;
      return pinger.capacityThreshold(isRealtime, false) > stats.peerLimit(false);
    }

    void failSlotWaiters(boolean realTime) {
      loadTracker.failSlotWaiters(realTime);
    }

    void setPeerLocations(String[] peerLocationsString) {
      location.setPeerLocations(peerLocationsString);
    }

    double getLocation() {
      return location.getLocation();
    }

    double[] getPeersLocationArray() {
      return location.getPeersLocationArray();
    }

    long getLocationSetTime() {
      return location.getLocationSetTime();
    }

    boolean isValidLocation() {
      return location.isValidLocation();
    }

    int getLocationDegree() {
      return location.getDegree();
    }

    boolean updateLocation(double newLoc, double[] newLocs) {
      return location.updateLocation(newLoc, newLocs);
    }

    double setLocation(double newLoc) {
      return location.setLocation(newLoc);
    }

    String locationToString() {
      return location.toString();
    }

    long[] getLocationSnapshot() {
      synchronized (location) {
        return new long[] {
          Double.doubleToRawLongBits(location.getLocation()), location.getLocationSetTime()
        };
      }
    }

    @SuppressWarnings("unchecked")
    double getClosestPeerLocation(double target, Object excludeLocations) {
      java.util.Set<Double> exclude = null;
      if (excludeLocations != null) {
        exclude = (java.util.Set<Double>) excludeLocations;
      }
      return location.getClosestPeerLocation(target, exclude);
    }

    void reportSwapInterval(long timeSinceLastTime) {
      routingStats.reportSwapInterval(timeSinceLastTime);
    }

    double averageSwapInterval() {
      return routingStats.averageSwapInterval();
    }

    void reportProbeInterval(long timeSinceLastTime) {
      routingStats.reportProbeInterval(timeSinceLastTime);
    }

    double averageProbeInterval() {
      return routingStats.averageProbeInterval();
    }

    double backedOffPercent() {
      return routingStats.backedOffPercent();
    }

    void reportBackoffStatus(
        long now, long routingBackedOffUntilRT, long routingBackedOffUntilBulk) {
      routingStats.reportBackoffStatus(now, routingBackedOffUntilRT, routingBackedOffUntilBulk);
    }

    void reportRejectedOverload() {
      routingStats.reportRejectedOverload();
    }

    void reportNotRejectedOverload() {
      routingStats.reportNotRejectedOverload();
    }

    double pRejected() {
      return routingStats.pRejected();
    }

    double averagePingTime() {
      return routingStats.averagePingTime();
    }

    void reportPing(long t) {
      routingStats.reportPing(t);
    }

    double backedOffPercentRT() {
      return routingStats.backedOffPercentRT();
    }

    double backedOffPercentBulk() {
      return routingStats.backedOffPercentBulk();
    }
  }

  final class PeerNodeHandshake {
    private final BlockCipher incomingSetupCipher;
    private final BlockCipher outgoingSetupCipher;
    private final BlockCipher anonymousInitiatorSetupCipher;
    private KeyAgreementSchemeContext ctx;

    PeerNodeHandshake(
        byte[] incomingSetupKey, byte[] outgoingSetupKey, byte[] anonymousInitiatorKey) {
      incomingSetupCipher = internals.buildRijndaelCipher(incomingSetupKey);
      outgoingSetupCipher = internals.buildRijndaelCipher(outgoingSetupKey);
      anonymousInitiatorSetupCipher = internals.buildRijndaelCipher(anonymousInitiatorKey);
    }

    BlockCipher incomingSetupCipher() {
      return incomingSetupCipher;
    }

    BlockCipher outgoingSetupCipher() {
      return outgoingSetupCipher;
    }

    BlockCipher anonymousInitiatorSetupCipher() {
      return anonymousInitiatorSetupCipher;
    }

    synchronized KeyAgreementSchemeContext getKeyAgreementSchemeContext() {
      return ctx;
    }

    synchronized void setKeyAgreementSchemeContext(KeyAgreementSchemeContext ctx2) {
      ctx = ctx2;
      if (LOG.isDebugEnabled()) {
        LOG.debug("setKeyAgreementSchemeContext({}" + STR_ON + "{}", ctx2, PeerNode.this);
      }
    }

    synchronized void clearKeyAgreementSchemeContext() {
      ctx = null;
    }

    boolean hasLiveHandshake(long now) {
      KeyAgreementSchemeContext c;
      synchronized (this) {
        c = ctx;
      }
      if (c != null && LOG.isDebugEnabled()) {
        LOG.debug("Last used (handshake): {}", now - c.lastUsedTime());
      }
      return !((c == null) || (now - c.lastUsedTime() > Node.HANDSHAKE_TIMEOUT));
    }

    /**
     * Completes the handshake by applying the negotiated session state and finalizing connection
     * bookkeeping.
     *
     * <p>The method validates the received noderef, updates routability flags, promotes or creates
     * a session tracker, and initializes packet/message counters for the new session. It also
     * updates connection timestamps and scheduling to reflect the new handshake. The call is not
     * idempotent; callers should invoke it exactly once per successful handshake.
     *
     * <ul>
     *   <li>Processes the new noderef and updates derived peer metadata.
     *   <li>Applies version and routability decisions for the peer.
     *   <li>Installs new session keys and tracker identifiers.
     *   <li>Finalizes connection state and timestamps.
     * </ul>
     *
     * @param params handshake completion inputs, including noderef data, keys, and counters
     * @return the active tracker identifier, or {@code -1} on failure
     */
    long completedHandshake(HandshakeCompletionParams params) {
      long now = System.currentTimeMillis();
      long trackerID = params.trackerID;
      // If trackerID is negative, pick a random positive ID; then keep using trackerID.
      // Avoid Math.abs(Long.MIN_VALUE) overflow; mask a sign bit instead.
      trackerID = trackerID < 0 ? (random.nextLong() & Long.MAX_VALUE) : trackerID;
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Tracker ID {} isJFK4={} jfk4SameAsOld={}",
            trackerID,
            params.isJFK4,
            params.jfk4SameAsOld);

      // Update sendHandshakeTime; don't send another handshake for a while.
      // If unverified, "a while" determines the timeout; if not, it's just good practice to avoid a
      // race below.
      if (!(isSeed() && PeerNode.this instanceof SeedServerPeerNode))
        calcNextHandshake(true, true, false);
      stopARKFetcher();
      try {
        // First, the new noderef
        processNewNoderef(params.data, params.length);
      } catch (FSParseException e1) {
        synchronized (PeerNode.this) {
          bogusNoderef = true;
          // Disconnect, something broke
          internals.setConnected(false, now);
        }
        LOG.error("Failed to parse new noderef for {}: {}", PeerNode.this, e1, e1);
        node.network().peers().disconnected(selfPeerNode());
        return -1;
      }
      RoutabilityDecision rd = decideRoutability();
      changedIP(params.replyTo);
      HandshakeParams hp = new HandshakeParams();
      hp.thisBootID = params.thisBootID;
      hp.rd = rd;
      hp.outgoingCipher = params.outgoingCipher;
      hp.outgoingKey = params.outgoingKey;
      hp.incommingCipher = params.incommingCipher;
      hp.incommingKey = params.incommingKey;
      hp.ivCipher = params.ivCipher;
      hp.ivNonce = params.ivNonce;
      hp.hmacKey = params.hmacKey;
      hp.unverified = params.unverified;
      hp.trackerID = trackerID;
      hp.ourInitialSeqNum = params.ourInitialSeqNum;
      hp.theirInitialSeqNum = params.theirInitialSeqNum;
      hp.ourInitialMsgID = params.ourInitialMsgID;
      hp.theirInitialMsgID = params.theirInitialMsgID;
      hp.negType = params.negType;
      hp.now = now;
      HandshakeApplyResult har = applyHandshakeState(hp);
      if (har == null) return -1;
      finalizeHandshake(har, rd, params.replyTo, params.thisBootID, now);

      return trackerID;
    }

    private void finalizeHandshake(
        HandshakeApplyResult har, RoutabilityDecision rd, Peer replyTo, long thisBootID, long now) {
      applyDisconnectSideEffects(har);
      logAndUpdateThrottle(replyTo, thisBootID);
      setPeerNodeStatus(now);
      if (rd.newer || rd.older || !isConnected())
        node.network().peers().disconnected(selfPeerNode());
      else if (!har.wasARekey) {
        node.network().peers().addConnectedPeer(selfPeerNode());
        maybeOnConnect();
      }
      crypto.maybeBootConnection(selfPeerNode(), replyTo.getFreenetAddress());
    }

    private void applyDisconnectSideEffects(HandshakeApplyResult har) {
      if (har.messagesTellDisconnected != null) {
        for (MessageItem item : har.messagesTellDisconnected) item.onDisconnect();
      }
      if (har.bootIDChanged) {
        node.network().locationManager().lostOrRestartedNode(selfPeerNode());
        node.network().usm().onRestart(PeerNode.this);
        node.routing().tracker().onRestartOrDisconnect(selfPeerNode());
      }
      if (har.oldPrev != null) har.oldPrev.disconnected();
      if (har.oldCur != null) har.oldCur.disconnected();
      if (har.oldPacketFormat != null) {
        List<MessageItem> tellDisconnect = har.oldPacketFormat.onDisconnect();
        if (tellDisconnect != null) for (MessageItem item : tellDisconnect) item.onDisconnect();
      }
    }

    private void logAndUpdateThrottle(Peer replyTo, long thisBootID) {
      internals.maybeDisconnected();
      LOG.info(
          "Completed handshake with {} on {} - current: {} old: {} unverified: {} bootID: {}"
              + STR_FOR
              + "{}",
          PeerNode.this,
          replyTo,
          currentTracker,
          previousTracker,
          unverifiedTracker,
          thisBootID,
          shortToString());
    }

    private record RoutabilityDecision(boolean routable, boolean newer, boolean older) {}

    private RoutabilityDecision decideRoutability() {
      boolean routable = true;
      boolean newer = false;
      boolean older = false;
      if (isSeed()) {
        routable = false;
        if (LOG.isDebugEnabled())
          LOG.debug("Routing disabled (announcement-only seed): peer={}", PeerNode.this);
      } else if (bogusNoderef) {
        LOG.info("Routing disabled (bogus noderef): peer={}", PeerNode.this);
        routable = false;
      } else if (reverseInvalidVersion()) {
        LOG.info(
            "Routing disabled (reverse version check): peer={}, localVersion={},"
                + " peerLastGoodVersion={}",
            PeerNode.this,
            Version.getVersionString(),
            getLastGoodVersion());
        newer = true;
      }
      if (forwardInvalidVersion()) {
        LOG.info(
            "Routing disabled (forward version check): peer={}, peerVersion={}",
            PeerNode.this,
            getVersion());
        older = true;
        routable = false;
      } else if (Math.abs(clockDelta) > MAX_CLOCK_DELTA) {
        LOG.info("Routing disabled (clock skew): peer={}", PeerNode.this);
        routable = false;
      }
      return new RoutabilityDecision(routable, newer, older);
    }

    private static final class HandshakeApplyResult {
      boolean bootIDChanged;
      boolean wasARekey;
      SessionKey oldPrev;
      SessionKey oldCur;
      MessageItem[] messagesTellDisconnected;
      PacketFormat oldPacketFormat;
    }

    private static final class HandshakeParams {
      long thisBootID;
      RoutabilityDecision rd;
      BlockCipher outgoingCipher;
      byte[] outgoingKey;
      BlockCipher incommingCipher;
      byte[] incommingKey;
      BlockCipher ivCipher;
      byte[] ivNonce;
      byte[] hmacKey;
      boolean unverified;
      long trackerID;
      int ourInitialSeqNum;
      int theirInitialSeqNum;
      int ourInitialMsgID;
      int theirInitialMsgID;
      int negType;
      long now;
    }

    private HandshakeApplyResult applyHandshakeState(HandshakeParams p) {
      HandshakeApplyResult r = new HandshakeApplyResult();
      synchronized (PeerNode.this) {
        disconnecting = false;
        if (isReplayedKey(p)) return null;
        updateRoutabilityAndBootId(p, r);
        SessionKey newTracker = buildSessionKey(p);
        if (LOG.isDebugEnabled())
          LOG.debug(
              "New key tracker in completedHandshake: {}" + STR_FOR + "{} neg type {}",
              newTracker,
              shortToString(),
              p.negType);
        assignTrackersAndTimes(p, r, newTracker);
      }
      return r;
    }

    private boolean isReplayedKey(HandshakeParams p) {
      if (currentTracker != null
          && Arrays.equals(p.outgoingKey, currentTracker.outgoingKey)
          && Arrays.equals(p.incommingKey, currentTracker.incommingKey)) {
        LOG.error("Handshake replay suspected: new keys match current tracker");
        return true;
      }
      if (previousTracker != null
          && Arrays.equals(p.outgoingKey, previousTracker.outgoingKey)
          && Arrays.equals(p.incommingKey, previousTracker.incommingKey)) {
        LOG.error("Handshake replay suspected: new keys match previous tracker");
        return true;
      }
      if (unverifiedTracker != null
          && Arrays.equals(p.outgoingKey, unverifiedTracker.outgoingKey)
          && Arrays.equals(p.incommingKey, unverifiedTracker.incommingKey)) {
        LOG.error("Handshake replay suspected: new keys match unverified tracker");
        return true;
      }
      return false;
    }

    private void updateRoutabilityAndBootId(HandshakeParams p, HandshakeApplyResult r) {
      handshakeCount = 0;
      bogusNoderef = false;
      if (!isConnected()) {
        connectedTime = p.now;
        countSelectionsSinceConnected = 0;
        sentInitialMessages = false;
      } else r.wasARekey = true;
      disableRouting = disableRoutingHasBeenSetLocally || disableRoutingHasBeenSetRemotely;
      isRoutable = p.rd.routable;
      unroutableNewerVersion = p.rd.newer;
      unroutableOlderVersion = p.rd.older;
      long oldBootID = bootID;
      bootID = p.thisBootID;
      r.bootIDChanged = oldBootID != p.thisBootID;
      if (myLastSuccessfulBootID != myBootID) {
        r.bootIDChanged = true;
        myLastSuccessfulBootID = myBootID;
      }
      if (r.bootIDChanged && r.wasARekey) {
        LOG.info(
            "Changed boot ID while rekeying! from {} to {}" + STR_FOR + "{}",
            oldBootID,
            p.thisBootID,
            getPeer());
        r.wasARekey = false;
        connectedTime = p.now;
        countSelectionsSinceConnected = 0;
        sentInitialMessages = false;
      } else if (r.bootIDChanged && LOG.isDebugEnabled())
        LOG.debug(
            "Changed boot ID from {} to {}" + STR_FOR + "{}", oldBootID, p.thisBootID, getPeer());
      if (r.bootIDChanged) {
        r.oldPrev = previousTracker;
        r.oldCur = currentTracker;
        previousTracker = null;
        currentTracker = null;
        r.messagesTellDisconnected = grabQueuedMessageItems();
        offeredMainJarVersion = 0;
        r.oldPacketFormat = internals.packetFormat();
        internals.clearPacketFormat();
      }
    }

    private SessionKey buildSessionKey(HandshakeParams p) {
      return new SessionKey(
          selfPeerNode(),
          new SessionKeyCryptoMaterial(
              p.outgoingCipher,
              p.outgoingKey,
              p.incommingCipher,
              p.incommingKey,
              p.ivCipher,
              p.ivNonce,
              p.hmacKey),
          new NewPacketFormatKeyContext(p.ourInitialSeqNum, p.theirInitialSeqNum),
          p.trackerID);
    }

    private void assignTrackersAndTimes(
        HandshakeParams p, HandshakeApplyResult r, SessionKey newTracker) {
      if (p.unverified) {
        if (unverifiedTracker != null && previousTracker == null)
          previousTracker = unverifiedTracker;
        unverifiedTracker = newTracker;
      } else {
        r.oldPrev = previousTracker;
        previousTracker = currentTracker;
        currentTracker = newTracker;
        neverConnected = false;
        maybeClearPeerAddedTimeOnConnect();
      }
      internals.setConnected(currentTracker != null, p.now);
      clearKeyAgreementSchemeContext();
      isRekeying = false;
      timeLastRekeyed =
          p.now - (p.unverified ? 0 : FNPPacketMangler.MAX_SESSION_KEY_REKEYING_DELAY / 2);
      totalBytesExchangedWithCurrentTracker = 0;
      if (currentTracker != null
          && previousTracker != null
          && Arrays.equals(currentTracker.outgoingKey, previousTracker.outgoingKey)
          && Arrays.equals(currentTracker.incommingKey, previousTracker.incommingKey))
        LOG.error(
            "currentTracker key equals previousTracker key: cur {} prev {}",
            currentTracker,
            previousTracker);
      if (previousTracker != null
          && unverifiedTracker != null
          && Arrays.equals(previousTracker.outgoingKey, unverifiedTracker.outgoingKey)
          && Arrays.equals(previousTracker.incommingKey, unverifiedTracker.incommingKey))
        LOG.error(
            "previousTracker key equals unverifiedTracker key: prev {} unv {}",
            previousTracker,
            unverifiedTracker);
      timeLastSentPacket = p.now;
      if (internals.packetFormat() == null) {
        internals.setPacketFormat(
            new NewPacketFormat(PeerNode.this, p.ourInitialMsgID, p.theirInitialMsgID));
      }
      timeLastReceivedPacket = p.now;
      timeLastReceivedDataPacket = p.now;
      timeLastReceivedAck = p.now;
    }

    private void processNewNoderef(byte[] data, int length) throws FSParseException {
      SimpleFieldSet fs = compressedNoderefToFieldSet(data, length);
      PeerNode.this.processNewNoderef(fs, false, false, false);
    }
  }

  /**
   * Returns whether this is a temporary connection initiated by an anonymous peer.
   *
   * <p>True, when the node connects and provides a noderef we did not already have (e.g., on
   * seednodes).
   *
   * @return {@code true} if the peer is an anonymous initiator
   */
  protected boolean fromAnonymousInitiator() {
    return false;
  }

  abstract boolean dontKeepFullFieldSet();

  /**
   * Clears or adjusts the stored peer-added time on restart when appropriate.
   *
   * <p>Implementations can reset the persisted peer-added timestamp to avoid conflating a restart
   * with a long-running connection. This hook is invoked during initialization and should avoid
   * blocking operations.
   *
   * @param now current time in milliseconds used for comparison and updates
   */
  protected abstract void maybeClearPeerAddedTimeOnRestart(long now);

  private boolean parseARK(SimpleFieldSet fs, boolean onStartup, boolean forDiffNodeRef) {
    return internals.parseArk(fs, onStartup, forDiffNodeRef);
  }

  /**
   * Returns the most recently detected low-level address for this peer.
   *
   * <p>If no packets have been observed yet, returns the first advertised address from the noderef
   * (after sorting). The result may be {@code null} when no addresses are available.
   *
   * @return the detected address if available, otherwise the best advertised address; may be {@code
   *     null} when unknown
   */
  @Override
  public synchronized Peer getPeer() {
    if (detectedPeer == null && !nominalPeer.isEmpty()) {
      sortNominalPeer();
      detectedPeer = nominalPeer.getFirst();
      updateShortToString();
    }
    return detectedPeer;
  }

  /**
   * Determines whether the supplied address matches this peer's detected or nominal addresses.
   *
   * <p>This method synchronizes on {@code this} to ensure a consistent view of peer addresses.
   *
   * @param addr address to compare against this peer's known addresses
   * @param strict whether to use strict or relaxed comparison semantics
   * @return {@code true} if the address matches; {@code false} otherwise
   */
  boolean matchesIP(FreenetInetAddress addr, boolean strict) {
    synchronized (this) {
      if (strict) {
        return PeerNodeAddressManager.strictMatch(this, addr);
      }
      return PeerNodeAddressManager.nonStrictMatch(this, addr);
    }
  }

  private void sortNominalPeer() {
    nominalPeer.sort(Peer.PEER_COMPARATOR);
  }

  /**
   * Returns the list of addresses considered for handshakes.
   *
   * <p>The array may include both advertised addresses and the last detected address; it may be
   * {@code null} when none are known. Callers must not modify the returned array.
   *
   * @return an array of candidate addresses, or {@code null} if unknown
   */
  protected synchronized Peer[] getHandshakeIPs() {
    return handshakeIPs;
  }

  private String handshakeIPsToString() {
    Peer[] localHandshakeIPs;
    synchronized (this) {
      localHandshakeIPs = handshakeIPs;
    }
    if (localHandshakeIPs == null) return "null";
    Arrays.sort(localHandshakeIPs, Peer.PEER_COMPARATOR);
    StringBuilder toOutputString = new StringBuilder(1024);
    toOutputString.append("[ ");
    if (localHandshakeIPs.length != 0) {
      for (Peer localHandshakeIP : localHandshakeIPs) {
        if (localHandshakeIP == null) {
          toOutputString.append("null, ");
          continue;
        }
        toOutputString.append('\'');
        // Actually do the DNS request for the member Peer of localHandshakeIPs
        toOutputString.append(localHandshakeIP.getAddress(false));
        toOutputString.append('\'');
        toOutputString.append(", ");
      }
      // assert(toOutputString.length() >= 2) -- always true as localHandshakeIPs.length != 0
      // remove the last ", "
      toOutputString.deleteCharAt(toOutputString.length() - 1);
      toOutputString.deleteCharAt(toOutputString.length() - 1);
    }
    toOutputString.append(" ]");
    return toOutputString.toString();
  }

  /**
   * Refreshes the cached set of candidate handshake addresses.
   *
   * <p>Combines the detected address (if any) with advertised addresses from the noderef and
   * host-derived candidates. When {@code ignoreHostnames} is true, skips DNS lookups and relies on
   * already-resolved or literal IP addresses.
   *
   * @param ignoreHostnames whether to avoid hostname resolution while refreshing
   */
  public void maybeUpdateHandshakeIPs(boolean ignoreHostnames) {
    internals.maybeUpdateHandshakeIPs(ignoreHostnames);
  }

  void applyHandshakeIPs(Peer[] localHandshakeIPs, Peer localDetectedPeer, Peer detectedDuplicate) {
    synchronized (this) {
      handshakeIPs = localHandshakeIPs;
      if ((detectedDuplicate != null) && detectedDuplicate.equals(localDetectedPeer))
        localDetectedPeer = detectedPeer = detectedDuplicate;
      updateShortToString();
    }
    if (LOG.isDebugEnabled()) {
      if (localDetectedPeer != null)
        LOG.debug(
            "3: detectedPeer = {} ({})", localDetectedPeer, localDetectedPeer.getAddress(false));
      LOG.debug("3: maybeUpdateHandshakeIPs got a result of: {}", handshakeIPsToString());
    }
  }

  /**
   * Returns this peer's current keyspace location.
   *
   * <p>Returns a value in the implementation-defined keyspace (typically in [0,1)). Returns {@code
   * -1} when unknown.
   *
   * @return keyspace location, or {@code -1} if unknown
   */
  public double getLocation() {
    return internals.getLocation();
  }

  /**
   * Returns whether this peer should be temporarily hidden from peer listings.
   *
   * <p>The decision considers recent backoff proportion and a minimum backoff duration to avoid
   * oscillation.
   *
   * @return {@code true} when the peer should be hidden from listings
   */
  public boolean shouldBeExcludedFromPeerList() {
    long now = System.currentTimeMillis();
    synchronized (this) {
      if (BLACK_MAGIC_BACKOFF_PRUNING_PERCENTAGE < internals.backedOffPercent()) return true;
      return BLACK_MAGIC_BACKOFF_PRUNING_TIME + now < getRoutingBackedOffUntilMax();
    }
  }

  /** Returns an array copy of locations of this PeerNode's peers, or null if unknown. */
  double[] getPeersLocationArray() {
    return internals.getPeersLocationArray();
  }

  long[] getLocationSnapshot() {
    return internals.getLocationSnapshot();
  }

  double getClosestPeerLocation(double target, Object excludeLocations) {
    return internals.getClosestPeerLocation(target, excludeLocations);
  }

  /**
   * Returns the time the current location value was last set.
   *
   * @return epoch time in milliseconds
   */
  @SuppressWarnings("unused")
  public long getLocSetTime() {
    return internals.getLocationSetTime();
  }

  /**
   * Returns a stable hash identifier for this peer.
   *
   * <p>Useful for quick identity comparisons and map keys.
   *
   * @return the integer hash derived from the peer's public key
   */
  @SuppressWarnings("unused")
  public int getIdentityHash() {
    return hashCode;
  }

  /**
   * Returns whether this peer is considered unroutable due to an older build.
   *
   * <p>This reflects version compatibility only and does not imply the peer is disconnected or in
   * backoff. The flag is updated during noderef parsing and handshake processing. Callers should
   * combine this with {@link #isConnected()} or {@link #isRoutable()} when making routing
   * decisions.
   *
   * @return {@code true} when the peer's build is below the accepted minimum
   */
  public synchronized boolean isUnroutableOlderVersion() {
    return unroutableOlderVersion;
  }

  /**
   * Returns whether this peer is considered unroutable due to our build being reported as older.
   *
   * <p>This reflects version compatibility only and does not imply the peer is disconnected or in
   * backoff. The flag is set based on the peer's advertised compatibility information. Callers
   * should pair this with connection and backoff checks to decide effective routability.
   *
   * @return {@code true} when the peer rejects our build as too old
   */
  @SuppressWarnings("unused")
  public synchronized boolean isUnroutableNewerVersion() {
    return unroutableNewerVersion;
  }

  /**
   * Returns true if requests can be routed through this peer. True if the peer's location is known,
   * presently connected, and routing-compatible. That is, ignoring backoff, the peer's location is
   * known, the build number is compatible, and routing has not been explicitly disabled.
   *
   * <p>Note possible deadlocks! PeerManager calls this; we call PeerManager in e.g., verified.
   */
  @Override
  public boolean isRoutable() {
    if ((!isConnected()) || (!isRoutingCompatible())) return false;
    return internals.isValidLocation();
  }

  synchronized boolean isInMandatoryBackoff(long now, boolean realTime) {
    long mandatoryBackoffUntil = realTime ? mandatoryBackoffUntilRT : mandatoryBackoffUntilBulk;
    if ((mandatoryBackoffUntil > -1 && now < mandatoryBackoffUntil)) {
      if (LOG.isDebugEnabled()) LOG.debug("In mandatory backoff");
      return true;
    }
    return false;
  }

  /**
   * Returns true if (apart from actually knowing the peer's location), it is presumed that this
   * peer could route requests. True if this peer's build number is not 'too-old' or 'too-new',
   * actively connected, and not marked as explicity disabled. Does not reflect any 'backoff' logic.
   *
   * <p>The method updates {@link #timeLastRoutable} when the peer is considered compatible. It is a
   * lightweight eligibility check and does not validate the current location or bandwidth
   * availability. Callers typically combine this with {@link #isRoutable()} to ensure location
   * validity.
   *
   * @return {@code true} when version and local routing policy allow traffic
   */
  @SuppressWarnings("BooleanMethodIsAlwaysInverted")
  public boolean isRoutingCompatible() {
    long now = System.currentTimeMillis(); // no System.currentTimeMillis in synchronized
    synchronized (this) {
      if (isRoutable && !disableRouting) {
        timeLastRoutable = now;
        return true;
      }
      if (LOG.isDebugEnabled()) LOG.debug("Not routing compatible");
      return false;
    }
  }

  /**
   * Returns whether this peer is currently connected.
   *
   * <p>Based on recent successful traffic and session state; does not imply routability.
   *
   * @return {@code true} if connected
   */
  @Override
  public boolean isConnected() {
    return internals.isConnected();
  }

  /**
   * Returns the transport abstraction used to communicate with this peer.
   *
   * <p>The transport reflects the currently negotiated protocol and may change when handshakes
   * renegotiate session parameters. Callers should not cache the result across reconnections.
   *
   * @return the current transport for this peer; never {@code null}
   */
  @Override
  public PeerTransport transport() {
    return internals.transport();
  }

  /** Wakes the packet sender to process queued messages immediately. */
  @Override
  public void wakeUpSender() {
    if (LOG.isDebugEnabled()) LOG.debug("Waking up PacketSender");
    node.network().packetSender().wakeUp();
  }

  /**
   * Attempts to remove a queued message before it is transmitted.
   *
   * @param message message item to remove
   * @return {@code true} if the item was removed
   */
  @Override
  public boolean unqueueMessage(MessageItem message) {
    if (LOG.isDebugEnabled()) LOG.debug("Unqueueing message on {} : {}", this, message);
    return messageQueue.removeMessage(message);
  }

  /**
   * Returns the current size of the outgoing message queue in bytes.
   *
   * <p>The value reflects queued messages waiting for packetization and transmission. It is
   * approximate and can change immediately as packets are sent or new messages are queued.
   *
   * @return queued outbound message size in bytes
   */
  public long getMessageQueueLengthBytes() {
    return messageQueue.getMessageQueueLengthBytes();
  }

  /**
   * Returns the number of milliseconds that it is estimated to take to transmit the currently
   * queued packets.
   *
   * <p>The estimate is derived from the current queue size and the peer's effective bandwidth,
   * including throttling rules. The calculation is a heuristic and may change quickly as bandwidth
   * limits or queue size change. It should be used for UI and diagnostics rather than strict
   * scheduling decisions.
   *
   * @return estimated milliseconds to drain the current send queue
   */
  public long getProbableSendQueueTime() {
    double bandwidth = (internals.bandwidth() + 1.0);
    if (shouldThrottle())
      bandwidth = Math.min(bandwidth, (double) node.network().outputBandwidthLimit() / 2);
    long length = getMessageQueueLengthBytes();
    return (long) (1000.0 * length / bandwidth);
  }

  /**
   * Returns the last time any packet was received from this peer, in milliseconds.
   *
   * <p>The timestamp is updated on all incoming packets, including handshake traffic. The value may
   * be {@code -1} if no packets have been observed yet.
   *
   * @return epoch time in milliseconds, or {@code -1} if unknown
   */
  public synchronized long lastReceivedPacketTime() {
    return timeLastReceivedPacket;
  }

  /**
   * Returns the last time a non-authentication packet was received, in milliseconds.
   *
   * <p>Authentication-only packets are excluded to avoid masking a lack of data traffic. The value
   * may be {@code -1} if no data packets have been observed yet.
   *
   * @return epoch time in milliseconds, or {@code -1} if unknown
   */
  public synchronized long lastReceivedDataPacketTime() {
    return timeLastReceivedDataPacket;
  }

  /**
   * Returns the last time an acknowledgement was received, in milliseconds.
   *
   * <p>This reflects inbound ACK traffic on the active session and may be {@code -1} if no ACKs
   * have been observed yet.
   *
   * @return epoch time in milliseconds, or {@code -1} if unknown
   */
  public synchronized long lastReceivedAckTime() {
    return timeLastReceivedAck;
  }

  /**
   * Returns the last time this peer was observed connected.
   *
   * @param now a time reference used by the tracker
   * @return epoch time in milliseconds
   */
  public long timeLastConnected(long now) {
    return internals.timeLastConnected(now);
  }

  /**
   * Returns the last time this peer was considered routing-compatible, in milliseconds.
   *
   * <p>The value is updated when {@link #isRoutingCompatible()} returns {@code true}. It can be
   * used for diagnostics and stale-peer detection. The timestamp may be {@code -1} if the peer has
   * never been considered compatible.
   *
   * @return epoch time in milliseconds, or {@code -1} if unknown
   */
  public synchronized long timeLastRoutable() {
    return timeLastRoutable;
  }

  /** Checks key lifetime/usage thresholds and initiates a rekey when appropriate. */
  @Override
  public void maybeRekey() {
    long now = System.currentTimeMillis();
    boolean shouldDisconnect;
    boolean shouldReturn;
    boolean shouldRekey;
    long timeWhenRekeyingShouldOccur;

    synchronized (this) {
      timeWhenRekeyingShouldOccur =
          timeLastRekeyed + FNPPacketMangler.SESSION_KEY_REKEYING_INTERVAL;
      shouldDisconnect =
          (timeWhenRekeyingShouldOccur + FNPPacketMangler.MAX_SESSION_KEY_REKEYING_DELAY < now)
              && isRekeying;
      shouldReturn = isRekeying || !isConnected();
      shouldRekey = (timeWhenRekeyingShouldOccur < now);
      if ((!shouldRekey)
          && totalBytesExchangedWithCurrentTracker
              > FNPPacketMangler.AMOUNT_OF_BYTES_ALLOWED_BEFORE_WE_REKEY) {
        shouldRekey = true;
      }
    }

    if (shouldDisconnect) {
      String time = internals.formatDuration(FNPPacketMangler.MAX_SESSION_KEY_REKEYING_DELAY);
      LOG.error("The peer ({}) has been asked to rekey {} ago... force disconnect.", this, time);
      forceDisconnect();
      return;
    }
    if (shouldRekey && !shouldReturn && !hasLiveHandshake(now)) {
      startRekeying();
    }
  }

  /**
   * Initiates a session rekey handshake if not already in progress.
   *
   * <p>Schedules an immediate handshake attempt and clears any transient negotiation context.
   */
  @Override
  public void startRekeying() {
    long now = System.currentTimeMillis();
    synchronized (this) {
      if (isRekeying) return;
      isRekeying = true;
      sendHandshakeTime = now; // Immediately
      handshake.clearKeyAgreementSchemeContext();
    }
    LOG.info("We are asking for the key to be renewed ({})", this.getPeer());
  }

  /**
   * Returns when this peer was added to the node.
   *
   * @return epoch time in milliseconds; persists across restarts
   */
  public synchronized long getPeerAddedTime() {
    return peerAddedTime;
  }

  /**
   * Returns the time elapsed since the peer was added, or since node start.
   *
   * @return duration in milliseconds
   */
  public synchronized long timeSinceAddedOrRestarted() {
    return System.currentTimeMillis() - timeAddedOrRestarted;
  }

  /**
   * Disconnected e.g., due to not receiving a packet for ages.
   *
   * @param dumpMessageQueue If true, clear the messages-to-send queue and change the bootID, so
   *     even if we reconnect, the other side will know that a disconnect happened. If false, don't
   *     clear the messages yet. They will be cleared after an hour if the peer is disconnected at
   *     that point.
   * @param dumpTrackers If true, dump the SessionKey's (i.e., dump the cryptographic data so we
   *     don't understand any packets they send us). <br>
   *     Possible arguments:
   *     <ul>
   *       <li>true, true => dump everything, immediate disconnect
   *       <li>true, false => dump messages but keep trackers so we can acknowledge messages on
   *           their end for a while.
   *       <li>false, false => tell the rest of the node that we have disconnected but do not
   *           immediately drop messages, continue to respond to their messages.
   *       <li>false, true => dump crypto but keep messages. DOES NOT MAKE SENSE!!! DO NOT USE!!!
   *     </ul>
   *
   * @return True if the node was connected, false if it was not.
   */
  public boolean disconnected(boolean dumpMessageQueue, boolean dumpTrackers) {
    if (!dumpMessageQueue && dumpTrackers) {
      throw new IllegalArgumentException(
          "Invalid combination: dumpTrackers cannot be true when dumpMessageQueue is false");
    }
    final long now = System.currentTimeMillis();
    if (isRealConnection()) LOG.info("Disconnect complete (active): peer={}", this);
    else if (LOG.isDebugEnabled()) LOG.debug("Disconnect complete (transient): peer={}", this);
    node.network().usm().onDisconnect(selfPeerNode());
    if (dumpMessageQueue) node.routing().tracker().onRestartOrDisconnect(selfPeerNode());
    node.routing().failureTable().onDisconnect(selfPeerNode());
    node.network().peers().disconnected(selfPeerNode());
    node.services().nodeUpdater().disconnected(selfPeerNode());
    DisconnectState st = performSynchronizedDisconnect(dumpMessageQueue, dumpTrackers, now);
    if (st.oldPacketFormat != null) {
      st.moreMessagesTellDisconnected = st.oldPacketFormat.onDisconnect();
    }
    dumpDisconnectedMessages(st.messagesTellDisconnected, st.moreMessagesTellDisconnected);
    if (st.cur != null) st.cur.disconnected();
    if (st.prev != null) st.prev.disconnected();
    if (st.unv != null) st.unv.disconnected();
    internals.maybeDisconnected();
    node.network().locationManager().lostOrRestartedNode(selfPeerNode());
    if (peers.havePeer(selfPeerNode())) setPeerNodeStatus(now);
    if (!dumpMessageQueue) queueDelayedDropMessages(now);
    // Tell opennet manager even if this is darknet, because we may need more opennet peers now.
    internals.notifyOpennetOnDisconnect(node);
    internals.failSlotWaiters(true);
    internals.failSlotWaiters(false);
    return st.ret;
  }

  private void dumpDisconnectedMessages(
      MessageItem[] messagesTellDisconnected, List<MessageItem> moreMessagesTellDisconnected) {
    if (messagesTellDisconnected != null) {
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Disconnect cleanup: queued messages to dump (array)={}",
            messagesTellDisconnected.length);
      for (MessageItem mi : messagesTellDisconnected) mi.onDisconnect();
    }
    if (moreMessagesTellDisconnected != null) {
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Disconnect cleanup: queued messages to dump (list)={}",
            moreMessagesTellDisconnected.size());
      for (MessageItem mi : moreMessagesTellDisconnected) mi.onDisconnect();
    }
  }

  private void queueDelayedDropMessages(final long now) {
    node.network()
        .ticker()
        .queueTimedJob(
            new Runnable() {
              @Override
              public void run() {
                if ((!selfPeerNode().isConnected()) && timeLastDisconnect == now) {
                  PacketFormat oldPacketFormatLocal;
                  synchronized (this) {
                    if (isConnected()) return;
                    myBootID = random.nextLong();
                    oldPacketFormatLocal = internals.packetFormat();
                    internals.clearPacketFormat();
                  }
                  MessageItem[] msgs = grabQueuedMessageItems();
                  dumpDisconnectedMessages(
                      msgs,
                      oldPacketFormatLocal == null ? null : oldPacketFormatLocal.onDisconnect());
                }
              }
            },
            CLEAR_MESSAGE_QUEUE_AFTER);
  }

  private static final class DisconnectState {
    boolean ret;
    SessionKey cur;
    SessionKey prev;
    SessionKey unv;
    MessageItem[] messagesTellDisconnected;
    List<MessageItem> moreMessagesTellDisconnected;
    PacketFormat oldPacketFormat;
  }

  private DisconnectState performSynchronizedDisconnect(
      boolean dumpMessageQueue, boolean dumpTrackers, long now) {
    DisconnectState st = new DisconnectState();
    synchronized (this) {
      disconnecting = false;
      st.ret = internals.setConnected(false, now);
      isRoutable = false;
      isRekeying = false;
      st.cur = currentTracker;
      st.prev = previousTracker;
      st.unv = unverifiedTracker;
      if (dumpTrackers) {
        currentTracker = null;
        previousTracker = null;
        unverifiedTracker = null;
      }
      sendHandshakeTime = now;
      countFailedRevocationTransfers = 0;
      timePrevDisconnect = timeLastDisconnect;
      timeLastDisconnect = now;
      if (dumpMessageQueue) {
        myBootID = random.nextLong();
        st.messagesTellDisconnected = grabQueuedMessageItems();
        st.oldPacketFormat = internals.packetFormat();
        internals.clearPacketFormat();
      }
    }
    return st;
  }

  /** Forces an immediate disconnect from this peer, without waiting for a graceful teardown. */
  @Override
  public void forceDisconnect() {
    LOG.warn("Forcing disconnect on {}", this);
    disconnected(true, true); // always dump trackers, maybe dump messages
  }

  /**
   * Returns and clears the current queue of pending messages to this peer.
   *
   * <p>The returned array is a snapshot of the queue at call time and is detached from further
   * queue mutations. Callers typically use this during disconnect handling to notify upstream
   * components. The order reflects current queue ordering and may be empty when no messages are
   * pending.
   *
   * @return an array of pending messages; never {@code null} and may be empty
   */
  public MessageItem[] grabQueuedMessageItems() {
    return messageQueue.grabQueuedMessageItems();
  }

  /**
   * Returns the earliest next time an urgent action is required for this peer.
   *
   * @param now current time in milliseconds
   * @return epoch time for the next action, or {@link Long#MAX_VALUE} if none pending
   */
  public long getNextUrgentTime(long now) {
    long t = Long.MAX_VALUE;
    SessionKey cur;
    SessionKey prev;
    PacketFormat pf;
    synchronized (this) {
      if (!isConnected()) return Long.MAX_VALUE;
      cur = currentTracker;
      prev = previousTracker;
      pf = internals.packetFormat();
      if (cur == null && prev == null) return Long.MAX_VALUE;
    }
    if (pf != null) {
      boolean canSend = cur != null && pf.canSend(cur);
      if (canSend) { // New messages are only sent on cur.
        long l =
            messageQueue.getNextUrgentTime(t, 0); // Need an accurate value even if in the past.
        if (l < now && LOG.isTraceEnabled()) {
          LOG.debug("Next urgent time from message queue less than now");
        } else if (LOG.isTraceEnabled()) {
          LOG.trace("Next urgent time is {}" + STR_MS_ON + "{}", l - now, this);
        }
        t = l;
      }
      long l = pf.timeNextUrgent(canSend, now);
      if (l < now && LOG.isDebugEnabled())
        LOG.debug("Next urgent time from packet format less than now on {}", this);
      t = Math.min(t, l);
    }
    return t;
  }

  /**
   * Returns the last time a packet was sent to this peer, in milliseconds.
   *
   * <p>The timestamp is updated on outbound packet transmission, including handshake traffic. The
   * value may be {@code -1} if no packets have been sent yet.
   *
   * @return epoch time in milliseconds, or {@code -1} if unknown
   */
  public long lastSentPacketTime() {
    return timeLastSentPacket;
  }

  /**
   * Returns whether a handshake should be sent now based on scheduling and state.
   *
   * <p>This method checks timers, connection state, and burst-only behavior. It may schedule burst
   * bookkeeping as a side effect when burst mode is active. Callers should avoid invoking it in
   * tight loops; it uses current time and may log debug details.
   *
   * @return {@code true} if a handshake sending should be attempted now
   */
  public boolean shouldSendHandshake() {
    long now = System.currentTimeMillis();
    boolean tempShouldSendHandshake = false;
    synchronized (this) {
      if (disconnecting) return false;
      if (now > sendHandshakeTime) {
        maybeUpdateHandshakeIPs(true);
        tempShouldSendHandshake =
            ((now > sendHandshakeTime)
                && (getHandshakeIPs() != null)
                && (isRekeying || !isConnected()));
      }
    }
    if (LOG.isDebugEnabled())
      LOG.debug("shouldSendHandshake(): initial = {}", tempShouldSendHandshake);
    if (tempShouldSendHandshake && (hasLiveHandshake(now))) tempShouldSendHandshake = false;
    if (tempShouldSendHandshake) {
      if (isBurstOnly()) {
        synchronized (this) {
          isBursting = true;
        }
        setPeerNodeStatus(System.currentTimeMillis());
      } else return true;
    }
    if (LOG.isDebugEnabled())
      LOG.debug("shouldSendHandshake(): final = {}", tempShouldSendHandshake);
    return tempShouldSendHandshake;
  }

  /**
   * Returns the scheduled time for the next handshake send attempt.
   *
   * @param now current time in milliseconds
   * @return epoch time when the handshake should be sent
   */
  public long timeSendHandshake(long now) {
    if (hasLiveHandshake(now)) return Long.MAX_VALUE;
    synchronized (this) {
      if (disconnecting) return Long.MAX_VALUE;
      if (handshakeIPs == null) return Long.MAX_VALUE;
      if (!(isRekeying || !isConnected())) return Long.MAX_VALUE;
      return sendHandshakeTime;
    }
  }

  /**
   * Does the node have a live handshake in progress?
   *
   * <p>A live handshake indicates that negotiation is ongoing and has not exceeded the handshake
   * timeout. This is used to suppress duplicate handshake attempts while the current one is still
   * valid.
   *
   * @param now current time in milliseconds used for timeout evaluation
   * @return {@code true} if a handshake is active and within timeout
   */
  public boolean hasLiveHandshake(long now) {
    return handshake.hasLiveHandshake(now);
  }

  PeerNodeHandshake handshake() {
    return handshake;
  }

  boolean firstHandshake = true;

  /**
   * Computes the next handshake send time and decides whether to (re)start ARK fetching.
   *
   * @param successfulHandshakeSend whether a handshake was just sent successfully
   * @param now current time in milliseconds since epoch
   * @return {@code true} if the ARK fetcher should be started
   */
  protected boolean innerCalcNextHandshake(boolean successfulHandshakeSend, long now) {
    if (isBurstOnly()) return calcNextHandshakeBurstOnly(now);
    synchronized (this) {
      long delay;
      if (unroutableOlderVersion || unroutableNewerVersion || disableRouting) {
        // Let them know we're here but have no hope of routing general data to them.
        delay =
            (long) Node.MIN_TIME_BETWEEN_VERSION_SENDS
                + (long) random.nextInt(Node.RANDOMIZED_TIME_BETWEEN_VERSION_SENDS);
      } else if (invalidVersion() && !firstHandshake) {
        delay =
            (long) Node.MIN_TIME_BETWEEN_VERSION_PROBES
                + (long) random.nextInt(Node.RANDOMIZED_TIME_BETWEEN_VERSION_PROBES);
      } else {
        delay =
            (long) Node.MIN_TIME_BETWEEN_HANDSHAKE_SENDS
                + (long) random.nextInt(Node.RANDOMIZED_TIME_BETWEEN_HANDSHAKE_SENDS);
      }
      // Note: multi-homing support is not implemented yet
      delay /= (handshakeIPs == null ? 1 : handshakeIPs.length);
      if (delay < 3000) delay = 3000;
      sendHandshakeTime = now + delay;
      if (LOG.isDebugEnabled()) LOG.debug("Next handshake in {} on {}", delay, this);

      if (successfulHandshakeSend) firstHandshake = false;
      handshakeCount++;
      return handshakeCount == MAX_HANDSHAKE_COUNT;
    }
  }

  private synchronized boolean calcNextHandshakeBurstOnly(long now) {
    boolean fetchARKFlag = false;
    listeningHandshakeBurstCount++;
    if (isBurstOnly() && listeningHandshakeBurstCount >= listeningHandshakeBurstSize) {
      listeningHandshakeBurstCount = 0;
      fetchARKFlag = true;
    }
    long delay;
    if (listeningHandshakeBurstCount == 0) { // 0 only if we just reset it above
      delay =
          (long) Node.MIN_TIME_BETWEEN_BURSTING_HANDSHAKE_BURSTS
              + (long) random.nextInt(Node.RANDOMIZED_TIME_BETWEEN_BURSTING_HANDSHAKE_BURSTS);
      listeningHandshakeBurstSize =
          Node.MIN_BURSTING_HANDSHAKE_BURST_SIZE
              + random.nextInt(Node.RANDOMIZED_BURSTING_HANDSHAKE_BURST_SIZE);
      isBursting = false;
    } else {
      delay =
          (long) Node.MIN_TIME_BETWEEN_HANDSHAKE_SENDS
              + (long) random.nextInt(Node.RANDOMIZED_TIME_BETWEEN_HANDSHAKE_SENDS);
    }
    // Note: multi-homing support is not implemented yet
    delay /= (handshakeIPs == null ? 1 : handshakeIPs.length);
    if (delay < 3000) delay = 3000;

    sendHandshakeTime = now + delay;
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Next BurstOnly mode handshake in {}"
              + STR_MS_FOR
              + "{} (count: {}, size: {}"
              + STR_ON
              + "{}",
          sendHandshakeTime - now,
          shortToString(),
          listeningHandshakeBurstCount,
          listeningHandshakeBurstSize,
          this,
          new Exception("double-called debug"));
    return fetchARKFlag;
  }

  /**
   * Computes the next handshake time and optionally starts ARK fetching.
   *
   * <p>This method updates internal timers and may start ARK fetching based on the connection
   * state. It is called after handshake attempts and must be invoked under the peer lock to keep
   * scheduling consistent. The method is not idempotent: it advances internal counters each call.
   *
   * @param successfulHandshakeSend whether a handshake was just sent successfully
   * @param dontFetchARK whether ARK fetching should be suppressed for now
   * @param notRegistered whether the peer is not yet registered in PeerManager
   */
  protected void calcNextHandshake(
      boolean successfulHandshakeSend, boolean dontFetchARK, boolean notRegistered) {
    long now = System.currentTimeMillis();
    boolean fetchARKFlag;
    fetchARKFlag = innerCalcNextHandshake(successfulHandshakeSend, now);
    if (!notRegistered)
      setPeerNodeStatus(now); // Because of isBursting being set above, and it can't hurt others
    // Don't fetch ARKs for peers we have verified (through handshake) to be incompatible with us
    if (fetchARKFlag && !dontFetchARK) {
      long arkFetcherStartTime1 = System.currentTimeMillis();
      startARKFetcher();
      long arkFetcherStartTime2 = System.currentTimeMillis();
      if ((arkFetcherStartTime2 - arkFetcherStartTime1) > 500)
        LOG.info(
            "arkFetcherStartTime2 is more than half a second after arkFetcherStartTime1 ({}"
                + STR_WORKING_ON
                + "{}",
            arkFetcherStartTime2 - arkFetcherStartTime1,
            shortToString());
    }
  }

  /**
   * Returns whether the connection should use burst‑only handshake behavior.
   *
   * <p>Burst-only mode limits handshake attempts to short bursts separated by longer pauses. It is
   * typically enabled when the local address appears port‑forwarded or otherwise sensitive to
   * repeated probes. The decision is derived from the current configuration and peer state and may
   * change over time.
   *
   * @return {@code true} if burst-only handshake scheduling is active
   */
  public boolean isBurstOnly() {
    return internals.isBurstOnly(outgoingMangler, random);
  }

  /**
   * Records that a handshake request was sent and schedules the next attempt.
   *
   * @param notRegistered whether this peer is not registered in the routing table yet
   */
  public void sentHandshake(boolean notRegistered) {
    if (LOG.isDebugEnabled()) LOG.debug("sentHandshake(): {}", this);
    calcNextHandshake(true, false, notRegistered);
  }

  /**
   * Call this when a handshake request could not be sent (e.g., no usable address available).
   *
   * @param notRegistered whether the peer is not yet registered in routing
   */
  public void couldNotSendHandshake(boolean notRegistered) {
    if (LOG.isDebugEnabled()) LOG.debug("couldNotSendHandshake(): {}", this);
    calcNextHandshake(false, false, notRegistered);
  }

  /**
   * Returns the maximum allowed idle interval between received packets, in milliseconds.
   *
   * <p>The value is a soft threshold for idle detection and is not a strict protocol timeout. It is
   * used by monitoring and routing logic to determine whether a peer has been quiet for too long.
   *
   * @return maximum idle interval in milliseconds between any packets
   */
  public long maxTimeBetweenReceivedPackets() {
    return Node.MAX_PEER_INACTIVITY;
  }

  /**
   * Returns the maximum allowed idle interval between received acknowledgements, in milliseconds.
   *
   * <p>The value is used to detect stalls in acknowledgement flow and may be identical to the
   * general packet inactivity threshold. It is primarily used for diagnostics and heuristic backoff
   * decisions.
   *
   * @return maximum idle interval in milliseconds between acknowledgements
   */
  public long maxTimeBetweenReceivedAcks() {
    return Node.MAX_PEER_INACTIVITY;
  }

  /**
   * Decrement the HTL (or not), in accordance with our probabilistic HTL rules. Whether to
   * decrement is determined once for each connection, rather than for every request. If we don't,
   * we would get a predictable fraction of requests with each HTL - this pattern could give away a
   * lot of information close to the originator. Although it's debatable whether it's worth worrying
   * about given all the other information they have if close by ...
   *
   * @param htl The old HTL.
   * @return The new HTL.
   */
  public short decrementHTL(short htl) {
    short max = node.maxHTL();
    if (htl > max) htl = max;
    if (htl <= 0) return 0;
    if (htl == max) {
      if (decrementHTLAtMaximum || node.isDisableProbabilisticHTLs()) htl--;
      return htl;
    }
    if (htl == 1) {
      if (decrementHTLAtMinimum || node.isDisableProbabilisticHTLs()) htl--;
      return htl;
    }
    htl--;
    return htl;
  }

  /**
   * Determines the degree of the peer via the locations of its peers it provides.
   *
   * @return The number of peers this peer reports having, or 0 if this peer does not provide that
   *     information.
   */
  public int getDegree() {
    return internals.getLocationDegree();
  }

  /**
   * Updates the peer's current location and the set of its peers' locations.
   *
   * @param newLoc this peer's reported location
   * @param newLocs array of locations reported for this peer's neighbors; may be {@code null}
   */
  public void updateLocation(double newLoc, double[] newLocs) {
    boolean anythingChanged = internals.updateLocation(newLoc, newLocs);
    node.network().peers().updatePMUserAlert();
    if (anythingChanged) writePeers();
    setPeerNodeStatus(System.currentTimeMillis());
  }

  /**
   * Persists or updates the peers list to reflect changes made by this node.
   *
   * <p>Implementations should write any modified peer state to durable storage or notify the
   * appropriate manager so that changes survive process restarts and the UI state remains
   * consistent.
   */
  protected abstract void writePeers();

  /**
   * Returns whether an incoming swap request should be rejected due to rate limiting.
   *
   * <p>Uses a time-decaying average interval and compares it to {@link
   * Node#MIN_INTERVAL_BETWEEN_INCOMING_SWAP_REQUESTS}.
   *
   * @return {@code true} to reject the request; {@code false} to accept
   */
  public boolean shouldRejectSwapRequest() {
    long now = System.currentTimeMillis();
    synchronized (this) {
      if (timeLastReceivedSwapRequest > 0) {
        long timeSinceLastTime = now - timeLastReceivedSwapRequest;
        internals.reportSwapInterval(timeSinceLastTime);
        double averageInterval = internals.averageSwapInterval();
        if (averageInterval >= Node.MIN_INTERVAL_BETWEEN_INCOMING_SWAP_REQUESTS) {
          timeLastReceivedSwapRequest = now;
          return false;
        } else return true;
      }
      timeLastReceivedSwapRequest = now;
    }
    return false;
  }

  /**
   * Returns whether an incoming probe request should be rejected due to rate limiting.
   *
   * <p>Uses a time-decaying average interval and compares it to {@link
   * Node#MIN_INTERVAL_BETWEEN_INCOMING_PROBE_REQUESTS}.
   *
   * @return {@code true} to reject the request; {@code false} to accept
   */
  @SuppressWarnings("unused")
  public boolean shouldRejectProbeRequest() {
    long now = System.currentTimeMillis();
    synchronized (this) {
      if (timeLastReceivedProbeRequest > 0) {
        long timeSinceLastTime = now - timeLastReceivedProbeRequest;
        internals.reportProbeInterval(timeSinceLastTime);
        double averageInterval = internals.averageProbeInterval();
        if (averageInterval >= Node.MIN_INTERVAL_BETWEEN_INCOMING_PROBE_REQUESTS) {
          timeLastReceivedProbeRequest = now;
          return false;
        } else return true;
      }
      timeLastReceivedProbeRequest = now;
    }
    return false;
  }

  /**
   * IP on the other side appears to have changed...
   *
   * @param newPeer The new address of the peer.
   */
  public void changedIP(Peer newPeer) {
    setDetectedPeer(newPeer);
  }

  private void setDetectedPeer(Peer newPeer) {
    // Also, we need to call .equals() to propagate any DNS lookups that have been done if the two
    // have the same domain.
    Peer p = newPeer;
    newPeer = newPeer.dropHostName();
    if (newPeer == null) {
      LOG.error("Impossible: No address for detected peer! {} on {}", p, this);
      return;
    }
    synchronized (this) {
      Peer oldPeer = getPeer();
      if ((oldPeer == null) || !oldPeer.equals(newPeer)) {
        this.detectedPeer = newPeer;
        updateShortToString();
        // IP has changed, it is worth looking up the DNS address again.
        internals.resetHandshakeIpUpdateTimer();
        if (!isConnected()) return;
      } else return;
    }
    internals.maybeDisconnected();
    internals.sendIPAddressMessage();
  }

  /**
   * @return The current primary SessionKey, or null if we don't have one.
   */
  @Override
  public synchronized SessionKey getCurrentKeyTracker() {
    return currentTracker;
  }

  /**
   * @return The previous primary SessionKey, or null if we don't have one.
   */
  @Override
  public synchronized SessionKey getPreviousKeyTracker() {
    return previousTracker;
  }

  /**
   * @return The unverified SessionKey, if any, or null if we don't have one. The caller MUST call
   *     verified(KT) if a decrypt succeeds with this KT.
   */
  @Override
  public synchronized SessionKey getUnverifiedKeyTracker() {
    return unverifiedTracker;
  }

  private String shortToString;

  private void updateShortToString() {
    shortToString =
        super.toString()
            + '@'
            + detectedPeer
            + '@'
            + internals.formatPeerKeyHash(peerECDSAPubKeyHash);
  }

  /**
   * @return short version of toString() *** Note that this is not synchronized! It is used by
   *     logging in code paths that will deadlock if it is synchronized! ***
   */
  @Override
  public String shortToString() {
    return shortToString;
  }

  @Override
  public String toString() {
    // Note: include object identity hash for quick debugging correlation.
    return shortToString() + '@' + Integer.toHexString(super.hashCode());
  }

  /**
   * Records receipt of a packet from this peer.
   *
   * @param dontLog when true, suppresses error logging if not connected (e.g., during handshake)
   * @param dataPacket whether the packet carried non-authentication data
   */
  @Override
  public void receivedPacket(boolean dontLog, boolean dataPacket) {
    synchronized (this) {
      if ((!isConnected()) && (!dontLog)) {
        // Don't log if we are disconnecting, because receiving packets during disconnecting is
        // normal.
        // That includes receiving packets after we have technically disconnected already.
        // A race condition involving forceCancelDisconnecting causing a mistaken log message anyway
        // is conceivable but unlikely...
        if ((unverifiedTracker == null) && (currentTracker == null) && !disconnecting)
          LOG.warn("Received packet while disconnected (no trackers) on {}", this);
        else if (LOG.isDebugEnabled())
          LOG.debug("Received packet while disconnected (recent disconnect) on {}", this);
      } else {
        if (LOG.isDebugEnabled()) LOG.debug("Received packet on {}", this);
      }
    }
    long now = System.currentTimeMillis();
    synchronized (this) {
      timeLastReceivedPacket = now;
      if (dataPacket) timeLastReceivedDataPacket = now;
    }
  }

  /**
   * Records receipt of an acknowledgement at the given time.
   *
   * @param now time in milliseconds when the ack was received
   */
  @Override
  public synchronized void receivedAck(long now) {
    if (timeLastReceivedAck < now) timeLastReceivedAck = now;
  }

  /** Records the time the last packet was sent to this peer. */
  @Override
  public void sentPacket() {
    timeLastSentPacket = System.currentTimeMillis();
  }

  /**
   * Clears or adjusts the stored peer-added time after a successful connection.
   *
   * <p>Implementations decide whether to reset or preserve the persisted peer-added timestamp based
   * on peer type and restart behavior. The method is invoked after a successful handshake and
   * should not perform heavyweight work or blocking I/O. It is not expected to be idempotent across
   * reconnections.
   */
  protected abstract void maybeClearPeerAddedTimeOnConnect();

  @Override
  public long getBootID() {
    return bootID;
  }

  /**
   * Starts the ARK fetcher to refresh this peer's noderef.
   *
   * <p>This is typically called after repeated handshake failures. It schedules background work and
   * does not block.
   */
  void startARKFetcher() {
    internals.startArkFetcher();
  }

  /**
   * Stops the ARK fetcher if it is currently running.
   *
   * <p>The method cancels any ongoing ARK fetch work and is safe to call even when no fetch is in
   * progress. It should be invoked under appropriate synchronization when called from subclass
   * logic.
   */
  protected void stopARKFetcher() {
    internals.stopArkFetcher();
  }

  // Both use priority class 2 (immediate splitfile) because we want to compete with FMS,
  // not wipe it out.

  /**
   * Returns the polling priority used for normal updates.
   *
   * <p>This value is used by the polling scheduler to assign a priority class. It is a small
   * integer where lower numbers indicate higher priority.
   *
   * @return polling priority for normal updates
   */
  public short getPollingPriorityNormal() {
    return 2;
  }

  /**
   * Returns the polling priority used for progress updates.
   *
   * <p>This value is used by the polling scheduler for progress-only operations such as splitfile
   * updates. It mirrors the normal priority to keep polling behavior consistent.
   *
   * @return polling priority for progress updates
   */
  public short getPollingPriorityProgress() {
    return 2;
  }

  boolean sentInitialMessages;

  void maybeSendInitialMessages() {
    synchronized (this) {
      if (sentInitialMessages) return;
      if (currentTracker != null) sentInitialMessages = true;
      else return;
    }

    sendInitialMessages();
  }

  /**
   * Sends initial high-level messages after a successful handshake.
   *
   * <p>Subclasses may override to extend the initial announcement set.
   */
  protected void sendInitialMessages() {
    internals.sendInitialMessages();
  }

  /**
   * Marks the given session key as verified and promotes it to an active routing state as needed.
   *
   * <p>Called when a packet is successfully decrypted on a given {@link SessionKey}. May promote
   * the {@code unverifiedTracker} when appropriate.
   *
   * @param tracker the session key that successfully decrypted a packet
   */
  @Override
  public void verified(SessionKey tracker) {
    long now = System.currentTimeMillis();
    SessionKey completelyDeprecatedTracker;
    synchronized (this) {
      if (tracker == unverifiedTracker) {
        if (LOG.isDebugEnabled())
          LOG.debug("Promoting unverified tracker {}" + STR_FOR + "{}", tracker, getPeer());
        completelyDeprecatedTracker = previousTracker;
        previousTracker = currentTracker;
        currentTracker = unverifiedTracker;
        unverifiedTracker = null;
        internals.setConnected(true, now);
        neverConnected = false;
        maybeClearPeerAddedTimeOnConnect();
        handshake.clearKeyAgreementSchemeContext();
      } else return;
    }
    maybeSendInitialMessages();
    setPeerNodeStatus(now);
    node.network().peers().addConnectedPeer(selfPeerNode());
    maybeOnConnect();
    if (completelyDeprecatedTracker != null) {
      completelyDeprecatedTracker.disconnected();
    }
  }

  private synchronized boolean invalidVersion() {
    return bogusNoderef || forwardInvalidVersion() || reverseInvalidVersion();
  }

  private synchronized boolean forwardInvalidVersion() {
    return !Version.isCompatibleVersion(version);
  }

  private synchronized boolean reverseInvalidVersion() {
    if (ignoreLastGoodVersion()) return false;
    return !Version.isCompatibleVersionWithLastGood(Version.getVersionString(), lastGoodVersion);
  }

  /**
   * Non-synchronized accessor for {@link #isUnroutableOlderVersion()}.
   *
   * @return {@code true} if this peer is unroutable due to an older build
   */
  public boolean publicInvalidVersion() {
    return unroutableOlderVersion;
  }

  /**
   * Synchronized accessor for {@link #isUnroutableNewerVersion()}.
   *
   * @return {@code true} if this peer reports our build as too old
   */
  public synchronized boolean publicReverseInvalidVersion() {
    return unroutableNewerVersion;
  }

  /**
   * Returns whether routing to this peer is currently disabled.
   *
   * <p>This reflects the effective routing-disable flag set by local configuration and/or remote
   * requests. It does not imply anything about connectivity or backoff status; callers should
   * combine it with other routing checks if making forwarding decisions.
   *
   * @return {@code true} if routing to this peer is disabled
   */
  @SuppressWarnings("unused")
  public synchronized boolean dontRoute() {
    return disableRouting;
  }

  /** Process a differential node reference The identity must not change, or we throw. */
  void processDiffNoderef(SimpleFieldSet fs) throws FSParseException {
    processNewNoderef(fs, false, true, false);
    // Send UOMAnnouncement only *after* we know what the other side's version.
    if (isRealConnection()) node.services().nodeUpdater().maybeSendUOMAnnounce(selfPeerNode());
  }

  static SimpleFieldSet compressedNoderefToFieldSet(byte[] data, int length)
      throws FSParseException {
    return PeerNodeReferenceSupport.compressedNoderefToFieldSet(data, 0, length);
  }

  /**
   * Processes a new node reference described by a {@link SimpleFieldSet}.
   *
   * @param fs noderef field set to apply
   * @param forARK whether this update was fetched via ARK
   * @param forDiffNodeRef whether this is a differential noderef update
   * @param forFullNodeRef whether this is a complete noderef
   * @throws FSParseException if the field set cannot be parsed or is inconsistent
   */
  void processNewNoderef(
      SimpleFieldSet fs, boolean forARK, boolean forDiffNodeRef, boolean forFullNodeRef)
      throws FSParseException {
    if (LOG.isDebugEnabled()) LOG.debug("Parsing: \n{}", fs);
    boolean changedAnything =
        innerProcessNewNoderef(fs, forARK, forDiffNodeRef, forFullNodeRef) || forARK;
    if (changedAnything && !isSeed()) writePeers();
    // Note: urgency when IPs change is not critical; keep default behavior
  }

  /**
   * Synchronized portion of {@link #processNewNoderef(SimpleFieldSet, boolean, boolean, boolean)}.
   *
   * @param fs noderef field set to apply
   * @param forARK whether this update was fetched via ARK
   * @param forDiffNodeRef whether this is a differential noderef update
   * @param forFullNodeRef whether this is a complete noderef
   * @return {@code true} if any local state changed as a result of the update
   * @throws FSParseException if the field set cannot be parsed or is inconsistent
   */
  synchronized boolean innerProcessNewNoderef(
      SimpleFieldSet fs, boolean forARK, boolean forDiffNodeRef, boolean forFullNodeRef)
      throws FSParseException {

    boolean[] shouldUpdatePeerCounts = new boolean[1];

    // Anything may be omitted for a differential node reference
    boolean changedAnything;
    verifyFullRefSignature(fs, forFullNodeRef);
    checkTestnetAndOpennet(fs, forDiffNodeRef, forFullNodeRef);
    boolean changedIdentityAndVersion =
        parseIdentityAndVersion(fs, forARK, forDiffNodeRef, forFullNodeRef);
    boolean changedLocation = parseLocationAndMaybePeerCounts(fs, shouldUpdatePeerCounts);
    boolean changedPhysical = parsePhysicalUdp(fs, forARK, forFullNodeRef);
    boolean changedNegTypes = updateNegTypes(fs, forDiffNodeRef);
    parseEcdsaFields(fs);

    changedAnything =
        changedIdentityAndVersion || changedLocation || changedPhysical || changedNegTypes;

    if (LOG.isDebugEnabled())
      LOG.debug("Parsed successfully; changedAnything = {}", changedAnything);

    if (parseARK(fs, false, forDiffNodeRef)) changedAnything = true;
    if (shouldUpdatePeerCounts[0]) {
      node.network().executor().execute(() -> node.network().peers().updatePMUserAlert());
    }
    return changedAnything;
  }

  private void verifyFullRefSignature(SimpleFieldSet fs, boolean forFullNodeRef)
      throws FSParseException {
    if (!forFullNodeRef) return;
    // verifyReferenceSignature() returns true on success, or throws on failure; no need to test.
    verifyReferenceSignature(fs);
  }

  private void checkTestnetAndOpennet(
      SimpleFieldSet fs, boolean forDiffNodeRef, boolean forFullNodeRef) throws FSParseException {
    internals.checkTestnetAndOpennet(fs, forDiffNodeRef, forFullNodeRef);
  }

  private boolean parseIdentityAndVersion(
      SimpleFieldSet fs, boolean forARK, boolean forDiffNodeRef, boolean forFullNodeRef)
      throws FSParseException {
    boolean changedAnything;
    validateIdentity(fs, forDiffNodeRef, forFullNodeRef);
    changedAnything = updateVersionInfo(fs, forARK, forDiffNodeRef, forFullNodeRef);
    updateVersionRoutablity();
    return changedAnything;
  }

  private void validateIdentity(SimpleFieldSet fs, boolean forDiffNodeRef, boolean forFullNodeRef)
      throws FSParseException {
    internals.validateIdentity(fs, forDiffNodeRef, forFullNodeRef);
  }

  private boolean updateVersionInfo(
      SimpleFieldSet fs, boolean forARK, boolean forDiffNodeRef, boolean forFullNodeRef)
      throws FSParseException {
    boolean changed = false;
    String newVersion = fs.get(SFS_KEY_VERSION);
    if (newVersion == null) {
      // Version may be omitted for an ARK.
      if (!forARK && !forDiffNodeRef) throw new FSParseException("No version");
    } else {
      if (!newVersion.equals(version)) changed = true;
      version = newVersion;
      parsedVersionComponents.set(null); // Invalidate cache
      try {
        simpleVersion = Version.parseBuildNumberFromVersionStr(version);
      } catch (VersionParseException e) {
        LOG.error("Bad version: {} : {}", version, e, e);
      }
      Version.seenVersion(newVersion);
    }
    String newLastGoodVersion = fs.get(SFS_KEY_LAST_GOOD_VERSION);
    if (newLastGoodVersion != null) {
      // Can be null if anon auth or if forDiffNodeRef.
      lastGoodVersion = newLastGoodVersion;
    } else if (forFullNodeRef) throw new FSParseException("No lastGoodVersion");
    return changed;
  }

  private boolean parseLocationAndMaybePeerCounts(
      SimpleFieldSet fs, boolean[] shouldUpdatePeerCounts) {
    boolean changedAnything = false;
    String locationString = fs.get(SFS_KEY_LOCATION);
    if (locationString != null) {
      double newLoc = Location.getLocation(locationString);
      if (!Location.isValid(newLoc)) {
        if (LOG.isDebugEnabled())
          LOG.debug(
              "Invalid or null location, waiting for FNPLocChangeNotification: locationString={}",
              locationString);
      } else {
        double oldLoc = internals.setLocation(newLoc);
        if (!Location.equals(oldLoc, newLoc)) {
          if (!Location.isValid(oldLoc)) shouldUpdatePeerCounts[0] = true;
          changedAnything = true;
        }
      }
    }
    return changedAnything;
  }

  private boolean parsePhysicalUdp(SimpleFieldSet fs, boolean forARK, boolean forFullNodeRef)
      throws FSParseException {
    boolean changedAnything = false;
    String[] physical = fs.getAll(SFS_KEY_PHYSICAL_UDP);
    if (physical != null) {
      List<Peer> oldNominalPeer = nominalPeer;
      Peer[] oldPeers = oldNominalPeer.toArray(new Peer[0]);
      nominalPeer = collectPeersFromPhysical(physical);
      sortNominalPeer();
      changedAnything = applyNominalPeersChange(oldPeers);
    } else if (forARK || forFullNodeRef) {
      // Connection setup doesn't include a physical.udp.
      // Differential noderefs only include it on the first one after connection.
      LOG.error("ARK noderef has no physical.udp for {} : forARK={}", this, forARK);
      if (forFullNodeRef) throw new FSParseException("ARK noderef has no physical.udp");
    }
    return changedAnything;
  }

  private List<Peer> collectPeersFromPhysical(String[] physical) {
    List<Peer> list = new ArrayList<>(physical.length);
    for (String phys : physical) {
      if (phys.indexOf(',') >= 0) {
        // Apply the same compatibility splitting we use for local parsing.
        for (Peer p : parsePeerEntryCompat(phys, /* fromLocal= */ false)) {
          if (p != null && !list.contains(p)) list.add(p);
        }
        continue;
      }
      Peer p = tryParsePeer(phys);
      if (p != null && !list.contains(p)) list.add(p);
    }
    return list;
  }

  private boolean applyNominalPeersChange(Peer[] oldPeers) {
    if (!Arrays.equals(oldPeers, nominalPeer.toArray(new Peer[0]))) {
      if (LOG.isDebugEnabled())
        LOG.debug("Got new physical.udp for {} : {}", this, Arrays.toString(nominalPeer.toArray()));
      // Look up the DNS names if any ASAP
      internals.resetHandshakeIpUpdateTimer();
      // Clear nonces to prevent leak. Will kill any in-progress connect attempts, but that is
      // okay because either we got an ARK which changed our peers list, or we just connected.
      internals.clearJfkNoncesSent();
      return true;
    }
    return false;
  }

  private Peer tryParsePeer(String phys) {
    return internals.tryParsePeer(phys);
  }

  private boolean updateNegTypes(SimpleFieldSet fs, boolean forDiffNodeRef) {
    boolean changed = false;
    int[] newNegTypes = fs.getIntArray(SFS_KEY_NEG_TYPES);
    boolean refHadNegTypes = false;
    if (newNegTypes == null || newNegTypes.length == 0) {
      newNegTypes = new int[] {0};
    } else {
      refHadNegTypes = true;
    }
    if ((!forDiffNodeRef || refHadNegTypes) && !Arrays.equals(negTypes, newNegTypes)) {
      changed = true;
      negTypes = newNegTypes;
    }
    return changed;
  }

  private void parseEcdsaFields(SimpleFieldSet fs) throws FSParseException {
    internals.parseEcdsaFields(fs);
  }

  /**
   * Returns a {@link PeerNodeStatus} snapshot for this peer.
   *
   * <p>The status summarizes connection, routability, and backoff state for UI and diagnostics.
   * Implementations may consult runtime counters or caches; callers can request a lightweight
   * evaluation to avoid expensive lookups. The returned status is a snapshot and may change soon
   * after the call.
   *
   * @param noHeavy whether to avoid expensive status computations
   * @return current status snapshot for this peer
   */
  public abstract PeerNodeStatus getStatus(boolean noHeavy);

  /**
   * Returns a tab-separated diagnostic string for the TMCI interface.
   *
   * <p>Includes peer address, identity, location, status, and idle time in seconds. The output is
   * intended for human-readable diagnostics and is not a stable machine API. Callers should expect
   * fields to be populated with the most recent cached values.
   *
   * @return a tab-separated diagnostic line for the peer
   */
  public String getTMCIPeerInfo() {
    long now = System.currentTimeMillis();
    int idle;
    synchronized (this) {
      idle = (int) ((now - timeLastReceivedPacket) / 1000);
    }
    if ((getPeerNodeStatus() == PeerManager.PEER_NODE_STATUS_NEVER_CONNECTED)
        && (getPeerAddedTime() > 1)) idle = (int) ((now - getPeerAddedTime()) / 1000);
    return String.valueOf(getPeer())
        + '\t'
        + getIdentityString()
        + '\t'
        + getLocation()
        + '\t'
        + getPeerNodeStatusString()
        + '\t'
        + idle;
  }

  /**
   * Returns the peer's reported software version string.
   *
   * <p>The version is parsed from the peer's noderef and may be {@code null} if no version has been
   * observed yet. The value is cached and updated when noderefs or handshakes are processed.
   *
   * @return the peer's version string, or {@code null} if unknown
   */
  public synchronized String getVersion() {
    return version;
  }

  private synchronized String getLastGoodVersion() {
    return lastGoodVersion;
  }

  private int simpleVersion;

  /**
   * Returns a simplified numeric version for fast comparisons.
   *
   * <p>The value is derived from the peer's version string during noderef parsing. It is used for
   * coarse comparisons and may be {@code 0} if the version could not be parsed. Callers should not
   * treat it as a full semantic version; it is a convenience for ordering and thresholds.
   *
   * @return numeric version component derived from the peer's version
   */
  public int getSimpleVersion() {
    return simpleVersion;
  }

  /**
   * Exports the noderef and metadata in a single {@link SimpleFieldSet} for persistence.
   *
   * <p>Includes the main noderef fields plus a {@code metadata} subset and, when present, the
   * optional {@code full} subset. The resulting field set is intended for on-disk persistence and
   * should not be edited by callers. Values are snapshots taken under the peer lock and may change
   * immediately after export.
   *
   * @return a combined field set suitable for writing to disk
   */
  public synchronized SimpleFieldSet exportDiskFieldSet() {
    SimpleFieldSet fs = exportFieldSet();
    SimpleFieldSet meta = exportMetadataFieldSet(System.currentTimeMillis());
    if (!meta.isEmpty()) fs.put(SFS_KEY_METADATA, meta);
    if (fullFieldSet != null) fs.put("full", fullFieldSet);
    return fs;
  }

  /**
   * Exports volatile metadata about this peer.
   *
   * @param now current time in milliseconds
   * @return a {@link SimpleFieldSet} containing metadata such as last activity timestamps and
   *     routing statistics
   */
  public synchronized SimpleFieldSet exportMetadataFieldSet(long now) {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    if (getPeer() != null) fs.putSingle(SFS_KEY_DETECTED_UDP, getPeer().toStringPrefNumeric());
    if (lastReceivedPacketTime() > 0) fs.put("timeLastReceivedPacket", timeLastReceivedPacket);
    if (lastReceivedAckTime() > 0) fs.put("timeLastReceivedAck", timeLastReceivedAck);
    long timeLastConnected = internals.timeLastConnected(now);
    if (timeLastConnected > 0) fs.put("timeLastConnected", timeLastConnected);
    if (timeLastRoutable() > 0) fs.put("timeLastRoutable", timeLastRoutable);
    if (getPeerAddedTime() > 0 && shouldExportPeerAddedTime())
      fs.put(SFS_KEY_PEER_ADDED_TIME, peerAddedTime);
    if (neverConnected) fs.putSingle("neverConnected", "true");
    if (hadRoutableConnectionCount > 0)
      fs.put("hadRoutableConnectionCount", hadRoutableConnectionCount);
    if (routableConnectionCheckCount > 0)
      fs.put("routableConnectionCheckCount", routableConnectionCheckCount);
    double[] peerLocs = getPeersLocationArray();
    if (peerLocs != null) fs.put("peersLocation", peerLocs);
    return fs;
  }

  /**
   * Returns whether the peer-added time should be exported and persisted.
   *
   * <p>Opennet peers typically do not persist this value, while darknet peers usually do. This hook
   * allows subclasses to select the appropriate behavior.
   *
   * @return {@code true} if the peer-added time should be exported
   */
  protected abstract boolean shouldExportPeerAddedTime();

  /**
   * Exports volatile, UI-oriented status for this peer.
   *
   * @return a {@link SimpleFieldSet} with human-readable status and timing values
   */
  public SimpleFieldSet exportVolatileFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    long now = System.currentTimeMillis();
    synchronized (this) {
      fs.put("averagePingTime", averagePingTime());
      long idle = now - lastReceivedPacketTime();
      if (idle > SECONDS.toMillis(60) && -1 != lastReceivedPacketTime()) fs.put("idle", idle);

      if (peerAddedTime > 1) fs.put(SFS_KEY_PEER_ADDED_TIME, peerAddedTime);
      fs.putSingle("lastRoutingBackoffReasonRT", lastRoutingBackoffReasonRT);
      fs.putSingle("lastRoutingBackoffReasonBulk", lastRoutingBackoffReasonBulk);
      fs.put("routingBackoffPercent", internals.backedOffPercent() * 100);
      fs.put(
          "routingBackoffRT",
          Math.max(Math.max(routingBackedOffUntilRT, transferBackedOffUntilRT) - now, 0));
      fs.put(
          "routingBackoffBulk",
          Math.max(Math.max(routingBackedOffUntilBulk, transferBackedOffUntilBulk) - now, 0));
      fs.put("routingBackoffLengthRT", routingBackoffLengthRT);
      fs.put("routingBackoffLengthBulk", routingBackoffLengthBulk);
      fs.put("overloadProbability", getPRejected() * 100);
      fs.put("percentTimeRoutableConnection", getPercentTimeRoutableConnection() * 100);
    }
    fs.putSingle("status", getPeerNodeStatusString());
    return fs;
  }

  /**
   * Exports the peer's noderef (without metadata) as a {@link SimpleFieldSet}.
   *
   * @return a field set suitable for exchange with other nodes
   */
  public synchronized SimpleFieldSet exportFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    if (getLastGoodVersion() != null) fs.putSingle(SFS_KEY_LAST_GOOD_VERSION, lastGoodVersion);
    for (Peer peer : nominalPeer) fs.putAppend(SFS_KEY_PHYSICAL_UDP, peer.toString());
    fs.put(SFS_KEY_NEG_TYPES, negTypes);
    fs.putSingle(SFS_KEY_IDENTITY, getIdentityString());
    fs.put(SFS_KEY_LOCATION, getLocation());
    fs.put(SFS_KEY_TESTNET, testnetEnabled);
    fs.putSingle(SFS_KEY_VERSION, version);
    internals.putEcdsaFields(fs, peerECDSAPubKey);
    internals.appendArkFields(fs);
    fs.put(SFS_KEY_OPENNET, isOpennetForNoderef());
    fs.put("seed", isSeed());
    fs.put("totalInput", getTotalInputBytes());
    fs.put("totalOutput", getTotalOutputBytes());
    return fs;
  }

  /**
   * Returns whether this peer is a full darknet peer ("Friend").
   *
   * <p>Darknet peers are typically managed by the darknet routing table and represent explicitly
   * trusted peers. This flag does not imply the peer is currently connected; it reflects the peer
   * classification derived from configuration and noderef data.
   *
   * @return {@code true} if the peer is a full darknet peer
   */
  public abstract boolean isDarknet();

  /**
   * Returns whether this peer is a full opennet peer ("Stranger").
   *
   * <p>Opennet peers are typically managed by {@link OpennetManager} and used for opportunistic
   * routing. This flag reflects peer classification and does not imply active connectivity.
   *
   * @return {@code true} if the peer is a full opennet peer
   */
  public abstract boolean isOpennet();

  /**
   * Returns the expected {@code opennet=} value for the noderef.
   *
   * <p>This returns {@code true} for opennet peers and for seed peers whose noderefs are labeled as
   * opennet even though they are not part of the routing table. The value also determines whether
   * opennet or darknet cryptographic parameters are used for this peer.
   *
   * @return {@code true} if the noderef should indicate opennet behavior
   */
  public abstract boolean isOpennetForNoderef();

  /**
   * Returns whether this peer is a seed client or seed server.
   *
   * <p>Seed peers are not part of the routing table but still advertise {@code opennet=true} to
   * allow initial bootstrapping. This classification is based on noderef or configuration metadata
   * and is independent of current connectivity.
   *
   * @return {@code true} if the peer is a seed client or seed server
   */
  public abstract boolean isSeed();

  /**
   * Returns the time at which we last connected (or reconnected).
   *
   * <p>The timestamp is recorded when a handshake completes and the peer transitions to a connected
   * state. It may be {@code 0} if the peer has never been connected in this process lifetime.
   *
   * @return epoch time in milliseconds for the last completed connection
   */
  public synchronized long timeLastConnectionCompleted() {
    return connectedTime;
  }

  @Override
  public boolean equals(Object o) {
    if (o == this) return true;
    if (o instanceof PeerNode pn) {
      return Arrays.equals(pn.peerECDSAPubKeyHash, peerECDSAPubKeyHash);
    } else return false;
  }

  @Override
  public final int hashCode() {
    return hashCode;
  }

  /**
   * Returns whether routing is currently backed off beyond a minimum threshold.
   *
   * <p>This checks routing and transfer backoff timers, mandatory backoff, and latency thresholds.
   * The {@code ignoreBackoffUnder} parameter suppresses short backoff windows to avoid oscillation
   * for transient conditions. The result is a snapshot and may change immediately after the call.
   *
   * @param ignoreBackoffUnder minimum backoff duration in milliseconds to consider
   * @param realTime whether to check real-time or bulk backoff state
   * @return {@code true} if routing is backed off beyond the threshold
   */
  public boolean isRoutingBackedOff(long ignoreBackoffUnder, boolean realTime) {
    long now = System.currentTimeMillis();
    double pingTime;
    synchronized (this) {
      long routingBackedOffUntil = realTime ? routingBackedOffUntilRT : routingBackedOffUntilBulk;
      if (now < routingBackedOffUntil && routingBackedOffUntil - now >= ignoreBackoffUnder)
        return true;
      long transferBackedOffUntil =
          realTime ? transferBackedOffUntilRT : transferBackedOffUntilBulk;
      if (now < transferBackedOffUntil && transferBackedOffUntil - now >= ignoreBackoffUnder)
        return true;
      if (isInMandatoryBackoff(now, realTime)) return true;
      pingTime = averagePingTime();
    }
    return pingTime > maxPeerPingTime();
  }

  /**
   * Returns whether routing is currently backed off for the given traffic class.
   *
   * <p>This checks routing and transfer backoff timers and the ping threshold for the specified
   * class. It is intended for routing decisions and status reporting.
   *
   * @param realTime whether to check real-time or bulk backoff state
   * @return {@code true} if routing is backed off for the class
   */
  public boolean isRoutingBackedOff(boolean realTime) {
    long now = System.currentTimeMillis();
    double pingTime;
    synchronized (this) {
      long routingBackedOffUntil = realTime ? routingBackedOffUntilRT : routingBackedOffUntilBulk;
      long transferBackedOffUntil =
          realTime ? transferBackedOffUntilRT : transferBackedOffUntilBulk;
      if (now < routingBackedOffUntil || now < transferBackedOffUntil) return true;
      pingTime = averagePingTime();
    }
    return pingTime > maxPeerPingTime();
  }

  /**
   * Returns whether routing is backed off for either real-time or bulk traffic.
   *
   * <p>This method uses the maximum of the backoff timers and the current ping threshold to detect
   * the general backoff state. It is useful for UI summaries and coarse routing decisions.
   *
   * @return {@code true} if either traffic class is backed off
   */
  public boolean isRoutingBackedOffEither() {
    long now = System.currentTimeMillis();
    double pingTime;
    synchronized (this) {
      long routingBackedOffUntil = Math.max(routingBackedOffUntilRT, routingBackedOffUntilBulk);
      long transferBackedOffUntil = Math.max(transferBackedOffUntilRT, transferBackedOffUntilBulk);
      if (now < routingBackedOffUntil || now < transferBackedOffUntil) return true;
      pingTime = averagePingTime();
    }
    return pingTime > maxPeerPingTime();
  }

  long routingBackedOffUntilRT = -1;
  long routingBackedOffUntilBulk = -1;

  /** Initial nominal routing backoff length */
  static final int INITIAL_ROUTING_BACKOFF_LENGTH = (int) SECONDS.toMillis(1);

  /** How much to multiply by during fast routing backoff */
  static final int BACKOFF_MULTIPLIER = 2;

  /** Maximum upper limit to routing backoff slow or fast */
  static final int MAX_ROUTING_BACKOFF_LENGTH = (int) MINUTES.toMillis(8);

  /** Current nominal routing backoff length */

  // Transfer Backoff

  long transferBackedOffUntilRT = -1;

  long transferBackedOffUntilBulk = -1;
  static final int INITIAL_TRANSFER_BACKOFF_LENGTH =
      (int) SECONDS.toMillis(30); // 60 seconds, but it starts at twice this.
  static final int TRANSFER_BACKOFF_MULTIPLIER = 2;
  static final int MAX_TRANSFER_BACKOFF_LENGTH = (int) MINUTES.toMillis(8);

  int transferBackoffLengthRT = INITIAL_TRANSFER_BACKOFF_LENGTH;
  int transferBackoffLengthBulk = INITIAL_TRANSFER_BACKOFF_LENGTH;

  int routingBackoffLengthRT = INITIAL_ROUTING_BACKOFF_LENGTH;
  int routingBackoffLengthBulk = INITIAL_ROUTING_BACKOFF_LENGTH;

  /** Last backoff reason */
  String lastRoutingBackoffReasonRT;

  String lastRoutingBackoffReasonBulk;

  /** Previous backoff reason (used by setPeerNodeStatus) */
  String previousRoutingBackoffReasonRT;

  String previousRoutingBackoffReasonBulk;

  // Separate, mandatory backoff mechanism for when nodes are consistently sending unexpected soft
  // rejects.
  // E.g., when load management predicts GUARANTEED, and yet we are rejected.
  // This can happen when the peer's view of how many of our requests are running is different to
  // our view.
  // But there has not been a timeout, so we haven't called fatalTimeout() and reconnected.

  // Note: there are three backoff mechanisms; consolidation may be possible

  long mandatoryBackoffUntilRT = -1;
  int mandatoryBackoffLengthRT = INITIAL_MANDATORY_BACKOFF_LENGTH;
  long mandatoryBackoffUntilBulk = -1;
  int mandatoryBackoffLengthBulk = INITIAL_MANDATORY_BACKOFF_LENGTH;
  static final int INITIAL_MANDATORY_BACKOFF_LENGTH = (int) SECONDS.toMillis(1);
  static final int MANDATORY_BACKOFF_MULTIPLIER = 2;

  /**
   * Enters mandatory backoff due to a guaranteed rejection anomaly.
   *
   * @param reason short token describing the cause
   * @param realTime whether the backoff applies to real-time traffic
   */
  public void enterMandatoryBackoff(String reason, boolean realTime) {
    long now = System.currentTimeMillis();
    synchronized (this) {
      long mandatoryBackoffUntil = realTime ? mandatoryBackoffUntilRT : mandatoryBackoffUntilBulk;
      int mandatoryBackoffLength = realTime ? mandatoryBackoffLengthRT : mandatoryBackoffLengthBulk;
      if (mandatoryBackoffUntil > -1 && mandatoryBackoffUntil > now) return;
      LOG.error("Entering mandatory backoff for {}{}", this, realTime ? " (realtime)" : " (bulk)");
      mandatoryBackoffUntil =
          now + (mandatoryBackoffLength / 2) + random.nextInt(mandatoryBackoffLength / 2);
      mandatoryBackoffLength *= MANDATORY_BACKOFF_MULTIPLIER;
      node.network().stats().reportMandatoryBackoff(reason, mandatoryBackoffUntil - now, realTime);
      if (realTime) {
        mandatoryBackoffLengthRT = mandatoryBackoffLength;
        mandatoryBackoffUntilRT = mandatoryBackoffUntil;
      } else {
        mandatoryBackoffLengthBulk = mandatoryBackoffLength;
        mandatoryBackoffUntilBulk = mandatoryBackoffUntil;
      }
      setLastBackoffReason(reason, realTime);
    }
    internals.failSlotWaiters(realTime);
  }

  /**
   * Resets the mandatory backoff length to its initial value after a request is accepted.
   *
   * @param realTime whether to reset the real-time ({@code true}) or bulk backoff length
   */
  public synchronized void resetMandatoryBackoff(boolean realTime) {
    if (realTime) mandatoryBackoffLengthRT = INITIAL_MANDATORY_BACKOFF_LENGTH;
    else mandatoryBackoffLengthBulk = INITIAL_MANDATORY_BACKOFF_LENGTH;
  }

  /**
   * Updates time-decaying averages of the proportion of time spent in routing backoff.
   *
   * @param now current time in milliseconds
   */
  void reportBackoffStatus(long now) {
    long rt;
    long bulk;
    synchronized (this) {
      rt = routingBackedOffUntilRT;
      bulk = routingBackedOffUntilBulk;
    }
    internals.reportBackoffStatus(now, rt, bulk);
  }

  /**
   * Handles a local RejectedOverload event by increasing backoff against this peer.
   *
   * @param reason short token without spaces describing the cause
   * @param realTime whether the event applies to real-time traffic ({@code true}) or bulk
   */
  public void localRejectedOverload(String reason, boolean realTime) {
    if (reason.indexOf(' ') != -1) {
      throw new IllegalArgumentException("reason must not contain spaces");
    }
    internals.reportRejectedOverload();
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Local rejected overload ({}" + STR_ON + "{}" + STR_P_REJECTED + "{}",
          reason,
          this,
          internals.pRejected());
    long now = System.currentTimeMillis();
    Peer peer = getPeer();
    reportBackoffStatus(now);
    if (!applyRoutingBackoff(reason, realTime, now, peer)) return;
    setLastBackoffReason(reason, realTime);
    setPeerNodeStatus(now);
    internals.failSlotWaiters(realTime);
  }

  /**
   * Clears routing backoff when a request succeeds without overload.
   *
   * @param realTime whether the success applies to real-time or bulk routing state
   */
  public void successNotOverload(boolean realTime) {
    internals.reportNotRejectedOverload();
    if (LOG.isDebugEnabled())
      LOG.debug("Success not overload on {}" + STR_P_REJECTED + "{}", this, internals.pRejected());
    Peer peer = getPeer();
    long now = System.currentTimeMillis();
    reportBackoffStatus(now);
    if (!resetRoutingBackoffIfExpired(realTime, now, peer)) return;
    setPeerNodeStatus(now);
  }

  private boolean applyRoutingBackoff(String reason, boolean realTime, long now, Peer peer) {
    synchronized (this) {
      long routingBackedOffUntil = realTime ? routingBackedOffUntilRT : routingBackedOffUntilBulk;
      int routingBackoffLength = realTime ? routingBackoffLengthRT : routingBackoffLengthBulk;
      if (now <= routingBackedOffUntil) {
        if (LOG.isDebugEnabled())
          LOG.debug(
              "Ignoring localRejectedOverload: {}ms remaining on routing backoff on {}",
              routingBackedOffUntil - now,
              peer);
        return false;
      }
      routingBackoffLength = routingBackoffLength * BACKOFF_MULTIPLIER;
      if (routingBackoffLength > MAX_ROUTING_BACKOFF_LENGTH)
        routingBackoffLength = MAX_ROUTING_BACKOFF_LENGTH;
      int x = random.nextInt(routingBackoffLength);
      routingBackedOffUntil = now + x;
      node.network().stats().reportRoutingBackoff(reason, x, realTime);
      if (LOG.isDebugEnabled()) {
        String reasonWrapper = "";
        if (!reason.isEmpty()) reasonWrapper = " because of '" + reason + '\'';
        LOG.debug(
            "Backing off{}: routingBackoffLength={}, until {}" + STR_MS_ON + "{}",
            reasonWrapper,
            routingBackoffLength,
            x,
            peer);
      }
      if (realTime) {
        routingBackedOffUntilRT = routingBackedOffUntil;
        routingBackoffLengthRT = routingBackoffLength;
      } else {
        routingBackedOffUntilBulk = routingBackedOffUntil;
        routingBackoffLengthBulk = routingBackoffLength;
      }
      return true;
    }
  }

  private boolean resetRoutingBackoffIfExpired(boolean realTime, long now, Peer peer) {
    synchronized (this) {
      long until = realTime ? routingBackedOffUntilRT : routingBackedOffUntilBulk;
      if (now > until) {
        if (realTime) routingBackoffLengthRT = INITIAL_ROUTING_BACKOFF_LENGTH;
        else routingBackoffLengthBulk = INITIAL_ROUTING_BACKOFF_LENGTH;
        if (LOG.isDebugEnabled()) LOG.debug("Resetting routing backoff on {}", peer);
        return true;
      }
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Ignoring successNotOverload: {}ms remaining on routing backoff on {}",
            until - now,
            peer);
      return false;
    }
  }

  /**
   * Handles a transfer failure by backing off this peer for a randomized duration.
   *
   * @param reason short token without spaces describing the cause
   * @param realTime whether the failure applies to real-time ({@code true}) or bulk traffic
   */
  @Override
  public void transferFailed(String reason, boolean realTime) {
    if (reason.indexOf(' ') != -1) {
      throw new IllegalArgumentException("reason must not contain spaces");
    }
    internals.reportRejectedOverload();
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Transfer failed ({}" + STR_ON + "{}" + STR_P_REJECTED + "{}",
          reason,
          this,
          internals.pRejected());
    long now = System.currentTimeMillis();
    Peer peer = getPeer();
    reportBackoffStatus(now);
    if (!applyTransferBackoff(reason, realTime, now, peer)) return;
    setLastBackoffReason(reason, realTime);
    internals.failSlotWaiters(realTime);
    setPeerNodeStatus(now);
  }

  private boolean applyTransferBackoff(String reason, boolean realTime, long now, Peer peer) {
    // We need it because of nested locking on getStatus()
    synchronized (this) {
      long transferUntil = realTime ? transferBackedOffUntilRT : transferBackedOffUntilBulk;
      int transferLen = realTime ? transferBackoffLengthRT : transferBackoffLengthBulk;
      if (now <= transferUntil) {
        if (LOG.isDebugEnabled())
          LOG.debug(
              "Ignoring transfer failure: {}ms remaining on transfer backoff on {}",
              transferUntil - now,
              peer);
        return false;
      }
      transferLen = transferLen * TRANSFER_BACKOFF_MULTIPLIER;
      if (transferLen > MAX_TRANSFER_BACKOFF_LENGTH) transferLen = MAX_TRANSFER_BACKOFF_LENGTH;
      int x = random.nextInt(transferLen);
      long newUntil = now + x;
      node.network().stats().reportTransferBackoff(reason, x, realTime);
      if (LOG.isDebugEnabled()) {
        String reasonWrapper = reason.isEmpty() ? "" : " because of '" + reason + '\'';
        LOG.debug(
            "Backing off (transfer){}: transferBackoffLength={}, until {}" + STR_MS_ON + "{}",
            reasonWrapper,
            transferLen,
            x,
            peer);
      }
      if (realTime) {
        transferBackedOffUntilRT = newUntil;
        transferBackoffLengthRT = transferLen;
      } else {
        transferBackedOffUntilBulk = newUntil;
        transferBackoffLengthBulk = transferLen;
      }
      return true;
    }
  }

  /**
   * Handles a successful transfer by resetting the transfer backoff if it has expired.
   *
   * @param realTime whether the success applies to real-time or bulk transfer state
   */
  public void transferSuccess(boolean realTime) {
    internals.reportNotRejectedOverload();
    if (LOG.isDebugEnabled())
      LOG.debug("Transfer success on {}" + STR_P_REJECTED + "{}", this, internals.pRejected());
    Peer peer = getPeer();
    long now = System.currentTimeMillis();
    reportBackoffStatus(now);
    synchronized (this) {
      // Don't un-backoff if still backed off
      long until;
      if (now > (until = realTime ? transferBackedOffUntilRT : transferBackedOffUntilBulk)) {
        if (realTime) transferBackoffLengthRT = INITIAL_TRANSFER_BACKOFF_LENGTH;
        else transferBackoffLengthBulk = INITIAL_TRANSFER_BACKOFF_LENGTH;
        if (LOG.isDebugEnabled()) LOG.debug("Resetting transfer backoff on {}", peer);
      } else {
        if (LOG.isDebugEnabled())
          LOG.debug(
              "Ignoring transfer success: {}ms remaining on transfer backoff on {}",
              until - now,
              peer);
        return;
      }
    }
    setPeerNodeStatus(now);
  }

  // Relatively few as we only get one every 200ms*#nodes
  // We want to get reasonably early feedback if it's dropping all of them...

  long pingNumber;

  /**
   * Returns the locally observed rejection probability for this peer.
   *
   * <p>The value represents the probability that a request is either preemptively rejected due to
   * overload or accepted and later times out. It is derived from recent routing outcomes and is
   * used as an input to backoff and routing decisions.
   *
   * @return probability of local rejection or timeout for requests to this peer
   */
  public double getPRejected() {
    return internals.pRejected();
  }

  @Override
  public double averagePingTime() {
    return internals.averagePingTime();
  }

  private boolean reportedRTT;
  private double srtt = 1000;
  private double rttVar = 0;
  private double rto = 1000;

  /**
   * Returns the retransmission timeout (RTO) estimate in milliseconds.
   *
   * <p>Calculated as per RFC 2988 using SRTT and RTTVAR.
   */
  @Override
  public synchronized double averagePingTimeCorrected() {
    return rto;
  }

  @Override
  public void reportThrottledPacketSendTime(long timeDiff, boolean realTime) {
    // Note: debug hook for throttled packet send time visibility.
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Reporting throttled packet send time: {} to {} ({})",
          timeDiff,
          getPeer(),
          realTime ? "realtime" : "bulk");
  }

  /**
   * Records the peer-reported view of our address.
   *
   * <p>This value is informational and is typically updated from handshake data. It does not affect
   * routing directly but may be displayed or used for diagnostics.
   *
   * @param p peer-reported address instance, or {@code null} if unknown
   */
  public void setRemoteDetectedPeer(Peer p) {
    this.remoteDetectedPeer = p;
  }

  /**
   * Returns the peer's reported view of our address.
   *
   * <p>The value may be {@code null} if the peer has not yet reported an address.
   *
   * @return peer-reported address, or {@code null} if unavailable
   */
  public Peer getRemoteDetectedPeer() {
    return remoteDetectedPeer;
  }

  /**
   * Returns the current routing backoff duration for the given traffic class.
   *
   * <p>The value represents the length used when extending routing backoff and is not necessarily
   * the remaining backoff time.
   *
   * @param realTime whether to return the real-time or bulk backoff length
   * @return backoff duration in milliseconds
   */
  public synchronized long getRoutingBackoffLength(boolean realTime) {
    return realTime ? routingBackoffLengthRT : routingBackoffLengthBulk;
  }

  /**
   * Returns the backoff deadline for the given traffic class.
   *
   * <p>The value is the maximum of routing, transfer, and mandatory backoff timers. It represents
   * the earliest time the peer may be eligible again for the specified class.
   *
   * @param realTime whether to compute the real-time or bulk deadline
   * @return epoch time in milliseconds for backoff expiry
   */
  public synchronized long getRoutingBackedOffUntil(boolean realTime) {
    return Math.max(
        realTime ? mandatoryBackoffUntilRT : mandatoryBackoffUntilBulk,
        Math.max(
            realTime ? routingBackedOffUntilRT : routingBackedOffUntilBulk,
            realTime ? transferBackedOffUntilRT : transferBackedOffUntilBulk));
  }

  /**
   * Returns the maximum backoff deadline across real-time and bulk traffic.
   *
   * <p>This is a convenience method for UI and diagnostics and represents the worst-case backoff
   * across both traffic classes.
   *
   * @return latest backoff expiry time in milliseconds
   */
  public synchronized long getRoutingBackedOffUntilMax() {
    return Math.max(
        Math.max(mandatoryBackoffUntilRT, mandatoryBackoffUntilBulk),
        Math.max(
            Math.max(routingBackedOffUntilRT, routingBackedOffUntilBulk),
            Math.max(transferBackedOffUntilRT, transferBackedOffUntilBulk)));
  }

  /**
   * Returns the backoff deadline for real-time traffic.
   *
   * <p>This excludes mandatory backoff and returns the maximum of routing and transfer backoff
   * timers for real-time traffic.
   *
   * @return epoch time in milliseconds for real-time backoff expiry
   */
  @SuppressWarnings("unused")
  public synchronized long getRoutingBackedOffUntilRT() {
    return Math.max(routingBackedOffUntilRT, transferBackedOffUntilRT);
  }

  /**
   * Returns the backoff deadline for bulk traffic.
   *
   * <p>This excludes mandatory backoff and returns the maximum of routing and transfer backoff
   * timers for bulk traffic.
   *
   * @return epoch time in milliseconds for bulk backoff expiry
   */
  @SuppressWarnings("unused")
  public synchronized long getRoutingBackedOffUntilBulk() {
    return Math.max(routingBackedOffUntilBulk, transferBackedOffUntilBulk);
  }

  /**
   * Returns the most recent routing backoff reason for the given traffic class.
   *
   * <p>The reason is a diagnostic string and may be {@code null} if no backoff has been recorded.
   *
   * @param realTime whether to fetch the real-time or bulk reason
   * @return last recorded backoff reason, or {@code null} if none
   */
  public synchronized String getLastBackoffReason(boolean realTime) {
    return realTime ? lastRoutingBackoffReasonRT : lastRoutingBackoffReasonBulk;
  }

  /**
   * Returns the previous routing backoff reason for the given traffic class.
   *
   * <p>The previous reason is retained for diagnostics when the current reason changes. It may be
   * {@code null} if there is no prior value.
   *
   * @param realTime whether to fetch the real-time or bulk previous reason
   * @return previous backoff reason, or {@code null} if none
   */
  public synchronized String getPreviousBackoffReason(boolean realTime) {
    return realTime ? previousRoutingBackoffReasonRT : previousRoutingBackoffReasonBulk;
  }

  /**
   * Updates the last routing backoff reason for the given traffic class.
   *
   * <p>The reason is stored for diagnostics and status reporting. Callers should supply {@code
   * null} to clear the reason.
   *
   * @param s backoff reason string, or {@code null} to clear
   * @param realTime whether to update the real-time or bulk reason
   */
  public synchronized void setLastBackoffReason(String s, boolean realTime) {
    if (realTime) lastRoutingBackoffReasonRT = s;
    else lastRoutingBackoffReasonBulk = s;
  }

  /**
   * Increments the sent-message counter for the given message spec name.
   *
   * @param messageSpecName message spec name to tally
   */
  public void incrementSentMessageType(String messageSpecName) {
    Long count;
    // Synchronize to make increments atomic.
    synchronized (localNodeSentMessageTypes) {
      count = localNodeSentMessageTypes.get(messageSpecName);
      if (count == null) count = 1L;
      else count = count + 1;
      localNodeSentMessageTypes.put(messageSpecName, count);
    }
  }

  /**
   * Increments the received-message counter for the given message spec name.
   *
   * @param messageSpecName message spec name to tally
   */
  public void incrementReceivedMessageType(String messageSpecName) {
    Long count;
    // Synchronize to make increments atomic.
    synchronized (localNodeReceivedMessageTypes) {
      count = localNodeReceivedMessageTypes.get(messageSpecName);
      if (count == null) count = 1L;
      else count = count + 1;
      localNodeReceivedMessageTypes.put(messageSpecName, count);
    }
  }

  java.util.Map<String, Long> getLocalNodeSentMessagesToStatistic() {
    // Must be synchronized *during the copy*
    synchronized (localNodeSentMessageTypes) {
      return new java.util.HashMap<>(localNodeSentMessageTypes);
    }
  }

  java.util.Map<String, Long> getLocalNodeReceivedMessagesFromStatistic() {
    // Must be synchronized *during the copy*
    synchronized (localNodeReceivedMessageTypes) {
      return new java.util.HashMap<>(localNodeReceivedMessageTypes);
    }
  }

  /**
   * Applies an ARK noderef update obtained via USK retrieval.
   *
   * @param fs decoded noderef field set
   * @param fetchedEdition edition that was fetched
   */
  @SuppressWarnings("unused")
  public void gotARK(SimpleFieldSet fs, long fetchedEdition) {
    internals.handleArkUpdate(fs, fetchedEdition);
  }

  /**
   * Resets the handshake retry counter after a successful ARK fetch.
   *
   * <p>Invoked by {@link PeerNodeArkManager} to avoid embedding ARK state in this class.
   */
  void resetHandshakeCountAfterArkFetch() {
    synchronized (this) {
      handshakeCount = 0;
    }
  }

  /**
   * Marks the ARK fetch as failed so the next handshake cycle can retry.
   *
   * <p>Invoked by {@link PeerNodeArkManager} after a malformed ARK update.
   */
  void markHandshakeCountAfterArkFailure() {
    synchronized (this) {
      handshakeCount = MAX_HANDSHAKE_COUNT;
    }
  }

  /**
   * Returns the current peer status code.
   *
   * <p>The status is a coarse-grained indicator used by UI and routing logic. It is updated as
   * connection, backoff, and load conditions change. The integer values correspond to constants in
   * {@link PeerManager}; callers should prefer {@link #getPeerNodeStatusString()} for display.
   *
   * @return status code representing the peer's current state
   */
  public synchronized int getPeerNodeStatus() {
    return peerNodeStatus;
  }

  /**
   * Returns a human-readable string for the current peer status.
   *
   * <p>The string values are intended for diagnostics and UI display and may change in the future.
   * Callers should not parse the string; use the numeric status for logic.
   *
   * @return display-friendly status string
   */
  public String getPeerNodeStatusString() {
    int status = getPeerNodeStatus();
    return getPeerNodeStatusString(status);
  }

  /**
   * Returns a human-readable string for a status code.
   *
   * <p>The mapping is stable for UI output but should not be treated as a protocol contract. If an
   * unknown code is supplied, a fallback string is returned.
   *
   * @param status status code from {@link PeerManager}
   * @return display-friendly status string
   */
  public static String getPeerNodeStatusString(int status) {
    if (status == PeerManager.PEER_NODE_STATUS_CONNECTED) return "CONNECTED";
    if (status == PeerManager.PEER_NODE_STATUS_ROUTING_BACKED_OFF) return "BACKED OFF";
    if (status == PeerManager.PEER_NODE_STATUS_TOO_NEW) return "TOO NEW";
    if (status == PeerManager.PEER_NODE_STATUS_TOO_OLD) return "TOO OLD";
    if (status == PeerManager.PEER_NODE_STATUS_DISCONNECTED) return "DISCONNECTED";
    if (status == PeerManager.PEER_NODE_STATUS_NEVER_CONNECTED) return "NEVER CONNECTED";
    if (status == PeerManager.PEER_NODE_STATUS_DISABLED) return "DISABLED";
    if (status == PeerManager.PEER_NODE_STATUS_CLOCK_PROBLEM) return "CLOCK PROBLEM";
    if (status == PeerManager.PEER_NODE_STATUS_CONN_ERROR) return "CONNECTION ERROR";
    if (status == PeerManager.PEER_NODE_STATUS_ROUTING_DISABLED) return "ROUTING DISABLED";
    if (status == PeerManager.PEER_NODE_STATUS_LISTEN_ONLY) return "LISTEN ONLY";
    if (status == PeerManager.PEER_NODE_STATUS_LISTENING) return "LISTENING";
    if (status == PeerManager.PEER_NODE_STATUS_BURSTING) return "BURSTING";
    if (status == PeerManager.PEER_NODE_STATUS_DISCONNECTING) return "DISCONNECTING";
    if (status == PeerManager.PEER_NODE_STATUS_NO_LOAD_STATS) return "NO LOAD STATS";
    return "UNKNOWN STATUS";
  }

  /**
   * Returns a CSS class name corresponding to the current peer status.
   *
   * <p>The returned value is suitable for web UI styling and is derived from the numeric status.
   * Callers should not assume the class names are stable across releases.
   *
   * @return CSS class name describing the current status
   */
  public String getPeerNodeStatusCSSClassName() {
    int status = getPeerNodeStatus();
    return getPeerNodeStatusCSSClassName(status);
  }

  /**
   * Returns a CSS class name corresponding to a status code.
   *
   * <p>Unknown status codes map to a generic class name. This method is intended for UI display and
   * is not part of the networking protocol.
   *
   * @param status status code from {@link PeerManager}
   * @return CSS class name for UI styling
   */
  public static String getPeerNodeStatusCSSClassName(int status) {
    return switch (status) {
      case PeerManager.PEER_NODE_STATUS_CONNECTED -> "peer_connected";
      case PeerManager.PEER_NODE_STATUS_ROUTING_BACKED_OFF -> "peer_backed_off";
      case PeerManager.PEER_NODE_STATUS_TOO_NEW -> "peer_too_new";
      case PeerManager.PEER_NODE_STATUS_TOO_OLD -> "peer_too_old";
      case PeerManager.PEER_NODE_STATUS_DISCONNECTED -> "peer_disconnected";
      case PeerManager.PEER_NODE_STATUS_NEVER_CONNECTED -> "peer_never_connected";
      case PeerManager.PEER_NODE_STATUS_DISABLED -> "peer_disabled";
      case PeerManager.PEER_NODE_STATUS_ROUTING_DISABLED -> "peer_routing_disabled";
      case PeerManager.PEER_NODE_STATUS_BURSTING -> "peer_bursting";
      case PeerManager.PEER_NODE_STATUS_CLOCK_PROBLEM -> "peer_clock_problem";
      case PeerManager.PEER_NODE_STATUS_LISTENING -> "peer_listening";
      case PeerManager.PEER_NODE_STATUS_LISTEN_ONLY -> "peer_listen_only";
      case PeerManager.PEER_NODE_STATUS_DISCONNECTING -> "peer_disconnecting";
      case PeerManager.PEER_NODE_STATUS_NO_LOAD_STATS -> "peer_no_load_stats";
      default -> "peer_unknown_status";
    };
  }

  /**
   * Computes the status code for this peer using the supplied state snapshot.
   *
   * <p>This method is called by {@link #setPeerNodeStatus(long, boolean)} while holding the peer
   * lock to avoid re-entrant status updates. Callers must supply current timing and backoff values
   * computed outside the lock to minimize contention.
   *
   * @param now current time in milliseconds for comparison checks
   * @param routingBackedOffUntilRT realtime routing backoff deadline in millis
   * @param routingBackedOffUntilBulk bulk routing backoff deadline in millis
   * @param overPingTime whether the current average ping exceeds the threshold
   * @param noLoadStats whether load stats are missing for routing
   * @return status code representing the peer's computed state
   */
  protected synchronized int getPeerNodeStatus(
      long now,
      long routingBackedOffUntilRT,
      long routingBackedOffUntilBulk,
      boolean overPingTime,
      boolean noLoadStats) {
    if (disconnecting) return PeerManager.PEER_NODE_STATUS_DISCONNECTING;
    boolean connectedNow = isConnected();
    if (isRoutable()) { // Function use also updates timeLastConnected and timeLastRoutable
      if (noLoadStats) peerNodeStatus = PeerManager.PEER_NODE_STATUS_NO_LOAD_STATS;
      else {
        peerNodeStatus = PeerManager.PEER_NODE_STATUS_CONNECTED;
        updateRTBackoffStatus(connectedNow, overPingTime, now, routingBackedOffUntilRT);
        updateBulkBackoffStatus(connectedNow, overPingTime, now, routingBackedOffUntilBulk);
      }
    } else {
      peerNodeStatus = computeNonRoutableStatus(connectedNow);
      if (peerNodeStatus == PeerManager.PEER_NODE_STATUS_BURSTING)
        return PeerManager.PEER_NODE_STATUS_BURSTING;
    }
    if (!isConnected() && (previousRoutingBackoffReasonRT != null)) {
      peers.removePeerNodeRoutingBackoffReason(
          previousRoutingBackoffReasonRT, selfPeerNode(), true);
      previousRoutingBackoffReasonRT = null;
    }
    if (!isConnected() && (previousRoutingBackoffReasonBulk != null)) {
      peers.removePeerNodeRoutingBackoffReason(
          previousRoutingBackoffReasonBulk, selfPeerNode(), false);
      previousRoutingBackoffReasonBulk = null;
    }
    return peerNodeStatus;
  }

  private void updateRTBackoffStatus(
      boolean connectedNow, boolean overPingTime, long now, long routingBackedOffUntilRT) {
    if (connectedNow
        && overPingTime
        && (lastRoutingBackoffReasonRT == null || now >= routingBackedOffUntilRT)) {
      lastRoutingBackoffReasonRT = "TooHighPing";
    }
    if (now < routingBackedOffUntilRT || overPingTime || isInMandatoryBackoff(now, true)) {
      peerNodeStatus = PeerManager.PEER_NODE_STATUS_ROUTING_BACKED_OFF;
      if (nullSafeNotEquals(lastRoutingBackoffReasonRT, previousRoutingBackoffReasonRT)) {
        if (previousRoutingBackoffReasonRT != null) {
          peers.removePeerNodeRoutingBackoffReason(
              previousRoutingBackoffReasonRT, selfPeerNode(), true);
        }
        peers.addPeerNodeRoutingBackoffReason(lastRoutingBackoffReasonRT, selfPeerNode(), true);
        previousRoutingBackoffReasonRT = lastRoutingBackoffReasonRT;
      }
    } else if (previousRoutingBackoffReasonRT != null) {
      peers.removePeerNodeRoutingBackoffReason(
          previousRoutingBackoffReasonRT, selfPeerNode(), true);
      previousRoutingBackoffReasonRT = null;
    }
  }

  private void updateBulkBackoffStatus(
      boolean connectedNow, boolean overPingTime, long now, long routingBackedOffUntilBulk) {
    if (connectedNow
        && overPingTime
        && (lastRoutingBackoffReasonBulk == null || now >= routingBackedOffUntilBulk)) {
      lastRoutingBackoffReasonBulk = "TooHighPing";
    }
    if (now < routingBackedOffUntilBulk || overPingTime || isInMandatoryBackoff(now, false)) {
      peerNodeStatus = PeerManager.PEER_NODE_STATUS_ROUTING_BACKED_OFF;
      if (nullSafeNotEquals(lastRoutingBackoffReasonBulk, previousRoutingBackoffReasonBulk)) {
        if (previousRoutingBackoffReasonBulk != null) {
          peers.removePeerNodeRoutingBackoffReason(
              previousRoutingBackoffReasonBulk, selfPeerNode(), false);
        }
        peers.addPeerNodeRoutingBackoffReason(lastRoutingBackoffReasonBulk, selfPeerNode(), false);
        previousRoutingBackoffReasonBulk = lastRoutingBackoffReasonBulk;
      }
    } else if (previousRoutingBackoffReasonBulk != null) {
      peers.removePeerNodeRoutingBackoffReason(
          previousRoutingBackoffReasonBulk, selfPeerNode(), false);
      previousRoutingBackoffReasonBulk = null;
    }
  }

  private int computeNonRoutableStatus(boolean connectedNow) {
    if (connectedNow && bogusNoderef) return PeerManager.PEER_NODE_STATUS_CONN_ERROR;
    if (connectedNow && unroutableNewerVersion) return PeerManager.PEER_NODE_STATUS_TOO_NEW;
    if (connectedNow && unroutableOlderVersion) return PeerManager.PEER_NODE_STATUS_TOO_OLD;
    if (connectedNow && disableRouting) return PeerManager.PEER_NODE_STATUS_ROUTING_DISABLED;
    if (connectedNow && Math.abs(clockDelta) > MAX_CLOCK_DELTA)
      return PeerManager.PEER_NODE_STATUS_CLOCK_PROBLEM;
    if (neverConnected) return PeerManager.PEER_NODE_STATUS_NEVER_CONNECTED;
    if (isBursting) return PeerManager.PEER_NODE_STATUS_BURSTING;
    return PeerManager.PEER_NODE_STATUS_DISCONNECTED;
  }

  private static boolean nullSafeNotEquals(Object a, Object b) {
    return !Objects.equals(a, b);
  }

  /**
   * Recomputes and applies the peer status using the current time.
   *
   * <p>This method recalculates routing and connection status and notifies {@link PeerManager}
   * listeners when the status changes. It is a convenience overload that performs normal logging
   * and delegates to {@link #setPeerNodeStatus(long, boolean)}.
   *
   * @param now current time in milliseconds used for status computation
   * @return the newly computed status code
   */
  @SuppressWarnings("UnusedReturnValue")
  public int setPeerNodeStatus(long now) {
    return setPeerNodeStatus(now, false);
  }

  /**
   * Recomputes and applies the peer status using the current time.
   *
   * <p>This method updates internal status fields and notifies listeners when the status changes.
   * It also schedules a follow-up check if the peer is currently backed off. Callers should supply
   * a consistent {@code now} timestamp to keep related calculations aligned.
   *
   * @param now current time in milliseconds used for status computation
   * @param noLog whether to suppress peer status change logging
   * @return the newly computed status code
   */
  public int setPeerNodeStatus(long now, boolean noLog) {
    long localRoutingBackedOffUntilRT = getRoutingBackedOffUntil(true);
    long localRoutingBackedOffUntilBulk = getRoutingBackedOffUntil(false);
    int oldPeerNodeStatus;
    long threshold = maxPeerPingTime();
    boolean noLoadStats = noLoadStats();
    synchronized (this) {
      oldPeerNodeStatus = peerNodeStatus;
      peerNodeStatus =
          getPeerNodeStatus(
              now,
              localRoutingBackedOffUntilRT,
              localRoutingBackedOffUntilBulk,
              averagePingTime() > threshold,
              noLoadStats);

      if (peerNodeStatus != oldPeerNodeStatus && recordStatus()) {
        peers.changePeerNodeStatus(selfPeerNode(), oldPeerNodeStatus, peerNodeStatus, noLog);
      }
    }
    if (LOG.isDebugEnabled())
      LOG.debug("Peer node status now {} was {}", peerNodeStatus, oldPeerNodeStatus);
    if (peerNodeStatus != oldPeerNodeStatus) {
      if (oldPeerNodeStatus == PeerManager.PEER_NODE_STATUS_ROUTING_BACKED_OFF) {
        internals.maybeNotifySlotWaiter(true);
        internals.maybeNotifySlotWaiter(false);
      }
      notifyPeerNodeStatusChangeListeners();
    }
    if (peerNodeStatus == PeerManager.PEER_NODE_STATUS_ROUTING_BACKED_OFF) {
      long delta = Math.max(localRoutingBackedOffUntilRT, localRoutingBackedOffUntilBulk) - now + 1;
      if (delta > 0)
        node.network()
            .ticker()
            .queueTimedJob(checkStatusAfterBackoff, "Update status for " + this, delta, true, true);
    }
    return peerNodeStatus;
  }

  /**
   * @return True if either bulk or realtime has not yet received a valid peer load stats message.
   *     If so, we will not be able to route requests to the node under new load management.
   */
  private boolean noLoadStats() {
    if (node.network().enableNewLoadManagement(false)
        || node.network().enableNewLoadManagement(true)) {
      if (internals.missingLastIncomingLoadStats(true)) {
        if (isRoutable()) LOG.info("No realtime load stats on {}", this);
        return true;
      }
      if (internals.missingLastIncomingLoadStats(false)) {
        if (isRoutable()) LOG.info("No bulk load stats on {}", this);
        return true;
      }
    }
    return false;
  }

  private final Runnable checkStatusAfterBackoff;

  /**
   * Returns whether status changes should be recorded in {@link PeerManager}.
   *
   * <p>Implementations can disable status recording for transient or special-purpose peers to
   * reduce noise in user-facing reports. This is a policy hook; it should not perform blocking
   * work.
   *
   * @return {@code true} if status changes should be recorded
   */
  public abstract boolean recordStatus();

  /**
   * Returns the base64-encoded identity string for this peer.
   *
   * <p>The value is stable for the lifetime of the peer and is derived from the peer's public key.
   * It is safe for display but should not be used as a cryptographic key.
   *
   * @return base64 identity string for the peer
   */
  public String getIdentityString() {
    return identityAsBase64String;
  }

  /**
   * Returns whether an ARK fetch is currently in progress for this peer.
   *
   * <p>The ARK fetcher is used to refresh noderefs when handshakes fail repeatedly. This method
   * reports the current fetcher state as tracked by the internal ARK manager.
   *
   * @return {@code true} if an ARK fetch is active
   */
  public boolean isFetchingARK() {
    return internals.isFetchingArk();
  }

  /**
   * Returns the number of handshake attempts since the last successful connection or ARK fetch.
   *
   * <p>The count is reset after a successful ARK fetch or when a connection completes. It is used
   * to decide when to start the ARK fetcher as a fallback discovery mechanism.
   *
   * @return number of recent handshake attempts
   */
  public synchronized int getHandshakeCount() {
    return handshakeCount;
  }

  /**
   * Queries the Version class to determine if this peers advertised build-number is either too-old
   * or too-new for the routing of requests.
   */
  synchronized void updateVersionRoutablity() {
    unroutableOlderVersion = forwardInvalidVersion();
    unroutableNewerVersion = reverseInvalidVersion();
  }

  /**
   * Returns whether routing to this node is disallowed due to policy or version incompatibility.
   *
   * <p>This is a routing policy check rather than a connectivity check. It returns {@code false}
   * for disconnected peers because the intent is to indicate explicit disqualification rather than
   * transient reachability.
   *
   * @return {@code true} if routing is explicitly disabled or version-incompatible
   */
  public synchronized boolean noLongerRoutable() {
    return unroutableNewerVersion || unroutableOlderVersion || disableRouting;
  }

  final void invalidate() {
    synchronized (this) {
      isRoutable = false;
    }
    LOG.info("Invalidated {}", this);
    setPeerNodeStatus(System.currentTimeMillis());
  }

  /**
   * Invokes the on-connect hook once per connected session.
   *
   * <p>This method tracks connection transitions and triggers {@link #onConnect()} only when the
   * peer transitions from disconnected to connected. It should be called after connection status
   * updates to ensure an accurate state.
   */
  public void maybeOnConnect() {
    if (wasDisconnected && isConnected()) {
      synchronized (this) {
        wasDisconnected = false;
      }
      onConnect();
    } else if (!isConnected()) {
      synchronized (this) {
        wasDisconnected = true;
      }
    }
  }

  /**
   * One-time hook executed at the start of each connected session.
   *
   * <p>Resets UOM-related counters/flags and informs the {@link OpennetManager} of the connection.
   */
  protected void onConnect() {
    synchronized (this) {
      uomCount = 0;
      lastSentUOM = -1;
      sendingUOMMainJar = false;
      sendingUOMLegacyExtJar = false;
    }
    internals.notifyOpennetOnConnect(node, selfPeerNode());
  }

  /**
   * Returns whether we currently have any contact details for this peer.
   *
   * <p>When {@code true}, there are no handshake addresses available, so handshake attempts should
   * be skipped until new noderef data arrives.
   *
   * @return {@code true} if no handshake addresses are available
   */
  public synchronized boolean noContactDetails() {
    return handshakeIPs == null || handshakeIPs.length == 0;
  }

  /**
   * Reports inbound bytes observed for this peer.
   *
   * <p>The counter is used for statistics and does not affect routing decisions directly. The value
   * should be the number of bytes received in a single packet or message.
   *
   * @param length number of bytes received, in bytes
   */
  public synchronized void reportIncomingBytes(int length) {
    totalInputSinceStartup += length;
    totalBytesExchangedWithCurrentTracker += length;
  }

  /**
   * Reports outbound bytes sent to this peer.
   *
   * <p>The counter is used for statistics and does not affect routing decisions directly. The value
   * should be the number of bytes sent in a single packet or message.
   *
   * @param length number of bytes sent, in bytes
   */
  public synchronized void reportOutgoingBytes(int length) {
    totalOutputSinceStartup += length;
    totalBytesExchangedWithCurrentTracker += length;
  }

  /**
   * Returns total inbound bytes observed for this peer, including previous runs.
   *
   * <p>The value includes bytes counted since startup plus persisted counters from disk. It is
   * intended for diagnostics and statistics and may not be exact at high update rates.
   *
   * @return total inbound byte count for this peer
   */
  public synchronized long getTotalInputBytes() {
    return bytesInAtStartup + totalInputSinceStartup;
  }

  /**
   * Returns total outbound bytes sent to this peer, including previous runs.
   *
   * <p>The value includes bytes counted since startup plus persisted counters from disk. It is
   * intended for diagnostics and statistics and may not be exact at high update rates.
   *
   * @return total outbound byte count for this peer
   */
  public synchronized long getTotalOutputBytes() {
    return bytesOutAtStartup + totalOutputSinceStartup;
  }

  /**
   * Returns inbound bytes recorded since the current process started.
   *
   * <p>This value excludes persisted counters from previous runs and resets to zero on startup.
   *
   * @return inbound bytes since startup
   */
  public synchronized long getTotalInputSinceStartup() {
    return totalInputSinceStartup;
  }

  /**
   * Returns outbound bytes recorded since the current process started.
   *
   * <p>This value excludes persisted counters from previous runs and resets to zero on startup.
   *
   * @return outbound bytes since startup
   */
  public synchronized long getTotalOutputSinceStartup() {
    return totalOutputSinceStartup;
  }

  /**
   * Returns whether signature verification has succeeded for this peer.
   *
   * <p>This is a cached indicator used by diagnostics and may be unset until a signature check is
   * performed.
   *
   * @return {@code true} if signature verification succeeded
   */
  @SuppressWarnings("unused")
  public boolean isSignatureVerificationSuccessfull() {
    return isSignatureVerificationSuccessfull;
  }

  void setSignatureVerificationSuccessfull(boolean success) {
    this.isSignatureVerificationSuccessfull = success;
  }

  /**
   * Updates the rolling routable-connection ratio counters.
   *
   * <p>This method samples whether the peer is routable and updates counters used to compute the
   * fraction of time the peer is routable. Counters are capped and decayed to avoid long-term
   * precision and correlation issues.
   */
  public void checkRoutableConnectionStatus() {
    synchronized (this) {
      if (isRoutable()) hadRoutableConnectionCount += 1;
      routableConnectionCheckCount += 1;
      // prevent the average from moving too slowly by capping the checkcount to 200,000,
      // which, at 7 seconds between counts, works out to about 2 weeks.  This also prevents
      // knowing how long we've had a particular peer long term.
      if (routableConnectionCheckCount >= 200000) {
        // divide both sides by the same amount to keep the same ratio
        hadRoutableConnectionCount = hadRoutableConnectionCount / 2;
        routableConnectionCheckCount = routableConnectionCheckCount / 2;
      }
    }
  }

  /**
   * Returns the fraction of samples where the peer was routable.
   *
   * <p>The value is derived from {@link #checkRoutableConnectionStatus()} sampling and ranges from
   * {@code 0.0} to {@code 1.0}. When no samples are available, the method returns {@code 0.0}.
   *
   * @return fraction of time the peer was routable
   */
  public synchronized double getPercentTimeRoutableConnection() {
    if (hadRoutableConnectionCount == 0) return 0.0;
    return ((double) hadRoutableConnectionCount) / routableConnectionCheckCount;
  }

  @Override
  public int getBuildNumber() {
    String[] components = getParsedVersionComponents();
    if (components.length == 0) return -1;
    try {
      // Cryptad format: Cryptad,buildNumber,protocol,buildNumber (build number is in component 1)
      // Fred format: Fred,series,protocol,buildNumber (build number is in component 3)
      if ("Cryptad".equals(components[0])) {
        return Integer.parseInt(components[1]);
      } else if ("Fred".equals(components[0]) && components.length >= 4) {
        return Integer.parseInt(components[3]);
      }
    } catch (NumberFormatException | ArrayIndexOutOfBoundsException _) {
      // Fall through to return -1
    }
    return -1;
  }

  /**
   * Gets the node name from the version string.
   *
   * @return The node name (e.g., "Cryptad", "Fred") or null if the version is invalid
   */
  public String getNodeName() {
    String[] components = getParsedVersionComponents();
    return components.length > 0 ? components[0] : null;
  }

  /**
   * Helper method to parse and cache version components to avoid repeated parsing.
   *
   * @return Parsed version components array, or empty array if parsing fails
   */
  private String[] getParsedVersionComponents() {
    String[] cached = parsedVersionComponents.get();
    if (cached != null) {
      return cached;
    }

    String versionStr = getVersion();
    if (versionStr == null) {
      return new String[0];
    }

    String[] components = PeerNodeReferenceSupport.splitVersionComponents(versionStr);
    if (components.length >= 3) {
      parsedVersionComponents.set(components);
      return components;
    }

    return new String[0];
  }

  /**
   * Selects the most appropriate negotiation type, honoring user preference and common support.
   *
   * @param mangler packet mangler used to query locally supported negotiation types
   * @return {@code -1} if no common negotiation type can be found
   */
  public int selectNegType(OutgoingPacketMangler mangler) {
    int[] hisNegTypes;
    int[] myNegTypes = mangler.supportedNegTypes(false);
    synchronized (this) {
      hisNegTypes = negTypes;
    }
    int bestNegType = -1;
    for (int negType : myNegTypes) {
      for (int hisNegType : hisNegTypes) {
        if (hisNegType == negType) {
          bestNegType = negType;
          break;
        }
      }
    }
    return bestNegType;
  }

  /**
   * Returns a user-facing string representation of the peer.
   *
   * <p>The default implementation returns the detected peer address if available. This is intended
   * for diagnostics and UI display rather than stable identifiers.
   *
   * @return user-friendly string representation of the peer
   */
  public String userToString() {
    return String.valueOf(getPeer());
  }

  /**
   * Sets the clock delta between this node and the peer.
   *
   * <p>The delta is used to detect clock skew issues. When the absolute delta exceeds the maximum
   * threshold, the peer is marked non-routable and status is recomputed.
   *
   * @param delta clock delta in milliseconds (peer time minus local time)
   */
  public void setTimeDelta(long delta) {
    synchronized (this) {
      clockDelta = delta;
      if (Math.abs(clockDelta) > MAX_CLOCK_DELTA) isRoutable = false;
    }
    setPeerNodeStatus(System.currentTimeMillis());
  }

  /**
   * Returns the most recently observed clock delta for this peer.
   *
   * <p>The delta is expressed in milliseconds and may be {@code 0} if unknown. Positive values
   * indicate the peer clock is ahead of the local clock.
   *
   * @return clock delta in milliseconds
   */
  public long getClockDelta() {
    return clockDelta;
  }

  /**
   * Offers a key to this peer for potential retrieval.
   *
   * @param key content key to announce
   */
  public void offer(Key key) {
    internals.offer(key);
  }

  /** Returns the packet mangler responsible for encrypting and sending packets to this peer. */
  @Override
  public OutgoingPacketMangler getOutgoingMangler() {
    return outgoingMangler;
  }

  /**
   * Returns whether this peer is disabled (e.g., explicitly disabled by the user).
   *
   * @return {@code true} if disabled; {@code false} otherwise
   */
  public boolean isDisabled() {
    return false;
  }

  /**
   * Returns whether connections to local addresses are allowed for this peer.
   *
   * <p>If {@code false}, the node will not connect to a local (RFC1918/loopback) address even if
   * the peer advertises one. This is a policy hook used to avoid unintended local routing.
   *
   * @return {@code true} if local addresses are allowed for this peer
   */
  public boolean allowLocalAddresses() {
    return this.outgoingMangler.alwaysAllowLocalAddresses();
  }

  /**
   * Returns whether this peer is configured to ignore source addresses.
   *
   * <p>When enabled, replies are always sent to the peer's official address, even if packets arrive
   * from a different source. This is used to enforce strict address expectations for some peer
   * types.
   *
   * @return {@code true} if source addresses should be ignored
   */
  public boolean isIgnoreSource() {
    return false;
  }

  /**
   * Returns whether this peer has never completed a successful connection.
   *
   * <p>This flag is updated when a handshake completes. It remains {@code true} until the first
   * successful connection and does not reset on disconnects.
   *
   * @return {@code true} if the peer has never connected
   */
  public boolean neverConnected() {
    return neverConnected;
  }

  /**
   * Called when a request or insert succeeds.
   *
   * <p>Used by opennet peers to update success counters and routing heuristics.
   *
   * @param insert whether the operation was an insert
   * @param ssk whether the operation used an SSK key
   */
  public abstract void onSuccess(boolean insert, boolean ssk);

  /**
   * Called when a delayed disconnect is occurring. Tell the node that it is being disconnected, but
   * that the process may take a while. After this point, requests will not be accepted from the
   * peer nor routed to it.
   *
   * @param dumpMessageQueue If true, immediately dump the message queue, since we are closing the
   *     connection due to some low-level trouble e.g., not acknowledging. We will continue to try
   *     to send anything already in flight. It is possible to send more messages after this point,
   *     for instance, the message telling it we are disconnecting, but see above - no requests will
   *     be routed across this connection.
   * @return True if we have already started disconnecting, false otherwise.
   */
  public boolean notifyDisconnecting(boolean dumpMessageQueue) {
    MessageItem[] messagesTellDisconnected = null;
    synchronized (this) {
      if (disconnecting) return true;
      disconnecting = true;
      internals.clearJfkNoncesSent();
      if (dumpMessageQueue) {
        // Reset the boot ID so that we get different trackers next time.
        myBootID = random.nextLong();
        messagesTellDisconnected = grabQueuedMessageItems();
      }
    }
    setPeerNodeStatus(System.currentTimeMillis());
    if (messagesTellDisconnected != null) {
      if (LOG.isDebugEnabled())
        LOG.debug("Disconnecting: queued messages to dump={}", messagesTellDisconnected.length);
      for (MessageItem mi : messagesTellDisconnected) {
        mi.onDisconnect();
      }
    }
    return false;
  }

  /**
   * Called to cancel a delayed disconnect. Always succeeds even if the node was not being
   * disconnected.
   */
  public void forceCancelDisconnecting() {
    synchronized (this) {
      removed = false;
      if (!disconnecting) return;
      disconnecting = false;
    }
    setPeerNodeStatus(System.currentTimeMillis(), true);
  }

  /**
   * Called when the peer is removed from the {@link PeerManager}.
   *
   * <p>Marks the peer as removed, cancels status checks, disconnects, and stops ARK fetching.
   */
  public void onRemove() {
    synchronized (this) {
      removed = true;
    }
    node.network().ticker().removeQueuedJob(checkStatusAfterBackoff);
    disconnected(true, true);
    stopARKFetcher();
  }

  /**
   * @return True if we have been removed from the peers list.
   */
  synchronized boolean cachedRemoved() {
    return removed;
  }

  /**
   * Returns whether this peer is currently in the process of disconnecting.
   *
   * <p>When {@code true}, the peer will not accept new requests and shutdown logic is underway.
   *
   * @return {@code true} if a disconnect sequence is active
   */
  public synchronized boolean isDisconnecting() {
    return disconnecting;
  }

  /**
   * Returns the current JFK handshake buffer.
   *
   * <p>The buffer contains ephemeral handshake material and may be {@code null} when no handshake
   * is in progress. Callers must treat the contents as sensitive and avoid logging it.
   *
   * @return handshake buffer, or {@code null} if not available
   */
  protected byte[] getJFKBuffer() {
    return jfkBuffer;
  }

  /**
   * Sets the JFK handshake buffer for the current handshake.
   *
   * <p>The buffer should contain ephemeral handshake material and may be cleared by passing {@code
   * null} after the handshake completes.
   *
   * @param bufferJFK handshake buffer to store, or {@code null} to clear
   */
  protected void setJFKBuffer(byte[] bufferJFK) {
    this.jfkBuffer = bufferJFK;
  }

  static final int MAX_SIMULTANEOUS_ANNOUNCEMENTS = 1;
  static final int MAX_ANNOUNCE_DELAY = 1000;
  private long timeLastAcceptedAnnouncement;
  private long[] runningAnnounceUIDs = new long[0];

  /**
   * Protection against too many simultaneous announcements over a single connection.
   *
   * @param uid The announcement UID.
   * @return True if we should accept the announcement. False to reject it.
   */
  public synchronized boolean shouldAcceptAnnounce(long uid) {
    long now = System.currentTimeMillis();
    if (runningAnnounceUIDs.length < MAX_SIMULTANEOUS_ANNOUNCEMENTS
        && now - timeLastAcceptedAnnouncement > MAX_ANNOUNCE_DELAY) {
      long[] newList = Arrays.copyOf(runningAnnounceUIDs, runningAnnounceUIDs.length + 1);
      newList[runningAnnounceUIDs.length] = uid;
      runningAnnounceUIDs = newList;
      timeLastAcceptedAnnouncement = now;
      return true;
    } else {
      return false;
    }
  }

  /**
   * Reports that a previously accepted announcement has finished.
   *
   * @param uid announcement identifier originally passed to {@link #shouldAcceptAnnounce(long)}
   * @return {@code true} if the UID was removed from the running set; {@code false} if it was not
   *     found
   */
  @SuppressWarnings("UnusedReturnValue")
  public synchronized boolean completedAnnounce(long uid) {
    if (runningAnnounceUIDs.length < 1) return false;
    long[] newList = new long[runningAnnounceUIDs.length - 1];
    int x = 0;
    for (long l : runningAnnounceUIDs) {
      if (l == uid) continue;
      if (x == newList.length) {
        LOG.warn("UID not found in completedAnnounce, should not happen");
        // uid was not found in runningAnnounceUIDs
        return false;
      }
      newList[x++] = l;
    }
    if (x < newList.length) {
      LOG.error("Duplicated UID, should not happen");
      newList = Arrays.copyOf(newList, x);
    }
    runningAnnounceUIDs = newList;
    return true;
  }

  /**
   * Returns the time of the most recent disconnect event.
   *
   * <p>The timestamp is updated whenever a disconnect is recorded. It may be {@code 0} if no
   * disconnect has occurred.
   *
   * @return epoch time in milliseconds for the last disconnect
   */
  @SuppressWarnings("unused")
  public synchronized long timeLastDisconnect() {
    return timeLastDisconnect;
  }

  /**
   * Should this peer be returned by roster lookups (for example {@link PeerRoster#getByPeer})?
   * False means seed nodes or other entries that are never routed.
   *
   * @return {@code true} if the peer should be considered a real connection
   */
  public abstract boolean isRealConnection();

  /**
   * Returns whether announcements from this peer are accepted.
   *
   * <p>This is a policy decision that depends on peer type and configuration.
   *
   * @return {@code true} if announcements are accepted
   */
  public abstract boolean canAcceptAnnouncements();

  /**
   * Returns whether the handshake initiator is unknown for this peer.
   *
   * <p>Some peer types allow anonymous initiators; this hook allows subclass control.
   *
   * @return {@code true} if the handshake initiator is unknown
   */
  public boolean handshakeUnknownInitiator() {
    return false;
  }

  /**
   * Returns the handshake setup type identifier for this peer.
   *
   * <p>The default implementation returns {@code -1}. Subclasses may override to provide concrete
   * handshake types for specialized peers.
   *
   * @return handshake setup type identifier, or {@code -1} if not defined
   */
  public int handshakeSetupType() {
    return -1;
  }

  @Override
  public WeakReference<PeerContext> getWeakRef() {
    return contextRef;
  }

  /**
   * Get a single address to send a handshake to. The current code doesn't work well with multiple
   * simultaneous handshakes. Alternates between valid values.
   *
   * @return selected handshake address, or {@code null} if none available
   */
  public Peer getHandshakeIP() {
    return internals.getHandshakeIP();
  }

  /**
   * Sends a node-to-node message immediately or queues it for later delivery.
   *
   * <p>This is a thin wrapper around the internal message-sending logic. Callers can request
   * inclusion of an already sent timestamp and can choose to queue the message when the peer is not
   * connected.
   *
   * @param fs field set representing the message payload
   * @param n2nType message type identifier
   * @param includeSentTime whether to include an already sent timestamp field
   * @param now current time in milliseconds for timestamping
   * @param queueOnNotConnected whether to queue if the peer is not connected
   */
  public void sendNodeToNodeMessage(
      SimpleFieldSet fs,
      int n2nType,
      boolean includeSentTime,
      long now,
      boolean queueOnNotConnected) {
    internals.sendNodeToNodeMessage(fs, n2nType, includeSentTime, now, queueOnNotConnected);
  }

  /**
   * Queues a node-to-node message (N2NM) for this peer.
   *
   * <p>Default implementation returns {@code -1}. DarknetPeerNode provides the actual queueing to
   * an extra peer data file.
   *
   * @param fs field set representing the message
   * @return a file identifier for the queued message, or {@code -1} if not queued
   */
  @SuppressWarnings("java:S1172")
  public int queueN2NM(SimpleFieldSet fs) {
    return -1; // Do nothing in the default impl
  }

  /**
   * Returns the local node reference appropriate for this peer's type (darknet/opennet).
   *
   * @return a {@link SimpleFieldSet} containing the public noderef fields
   */
  protected SimpleFieldSet getLocalNoderef() {
    return crypto.exportPublicFieldSet();
  }

  /**
   * Sends a differential noderef to the peer after a successful handshake.
   *
   * <p>Includes fields not required during handshake, such as ARK-related values. Intended to be
   * invoked right after the connection is established by the handshake completion path.
   *
   * <p>Note: this should also be sent when our noderef changes.
   */
  protected void sendConnectedDiffNoderef() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    SimpleFieldSet nfs = getLocalNoderef();
    if (null == nfs) return;
    String s;
    s = nfs.get(SFS_KEY_ARK_PUBURI);
    if (null != s) {
      fs.putOverwrite(SFS_KEY_ARK_PUBURI, s);
    }
    s = nfs.get(SFS_KEY_ARK_NUMBER);
    if (null != s) {
      fs.putOverwrite(SFS_KEY_ARK_NUMBER, s);
    }
    if (isDarknet() && null != (s = nfs.get("myName"))) {
      fs.putOverwrite("myName", s);
    }
    String[] physicalUDPEntries = nfs.getAll(SFS_KEY_PHYSICAL_UDP);
    if (physicalUDPEntries != null) {
      fs.putOverwrite(SFS_KEY_PHYSICAL_UDP, physicalUDPEntries);
    }
    if (!fs.isEmpty()) {
      if (LOG.isDebugEnabled()) LOG.debug("fs is '{}'", fs);
      sendNodeToNodeMessage(fs, Node.N2N_MESSAGE_TYPE_DIFFNODEREF, false, 0, false);
    } else {
      if (LOG.isDebugEnabled()) LOG.debug("fs is empty");
    }
  }

  @Override
  public boolean shouldThrottle() {
    return PeerNodeAddressManager.shouldThrottle(getPeer(), node);
  }

  static final long MAX_RTO = SECONDS.toMillis(60);
  static final long MIN_RTO = 50;
  private int consecutiveRTOBackoffs;

  // Clock generally has 20ms granularity or better, right?
  // Note: clock granularity depends on the platform.
  private static final int CLOCK_GRANULARITY = 20;

  @Override
  public void reportPing(long t) {
    internals.reportPing(t);
    synchronized (this) {
      consecutiveRTOBackoffs = 0;
      // Update RTT according to RFC 2988.
      if (!reportedRTT) initializeRtt(t);
      else updateRtt(t);
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Reported ping {} avg is now {} RTO is {} SRTT is {} RTTVAR is {}" + STR_FOR + "{}",
            t,
            internals.averagePingTime(),
            rto,
            srtt,
            rttVar,
            shortToString());
    }
  }

  private void initializeRtt(long t) {
    double oldRTO = rto;
    srtt = t;
    rttVar = (double) t / 2;
    rto = srtt + Math.max(CLOCK_GRANULARITY, rttVar * 4);
    enforceRtoBounds();
    reportedRTT = true;
    if (LOG.isDebugEnabled())
      LOG.debug("Received first packet on {} setting RTO to {}", shortToString(), rto);
    if (oldRTO > rto && LOG.isDebugEnabled()) {
      LOG.debug(
          "Received first packet after backing off on resend. RTO is {} but was {}", rto, oldRTO);
    }
  }

  private void updateRtt(long t) {
    rttVar = 0.75 * rttVar + 0.25 * Math.abs(srtt - t);
    srtt = 0.875 * srtt + 0.125 * t;
    rto = srtt + Math.max(CLOCK_GRANULARITY, rttVar * 4);
    // Use 50ms minimum to reduce retransmit storms on modern networks.
    enforceRtoBounds();
  }

  private void enforceRtoBounds() {
    if (rto < MIN_RTO) rto = MIN_RTO;
    if (rto > MAX_RTO) rto = MAX_RTO;
  }

  /**
   * RFC 2988: Note that a TCP implementation MAY clear SRTT and RTTVAR after backing off the timer
   * multiple times as it is likely that the current SRTT and RTTVAR are bogus in this situation.
   * Once SRTT and RTTVAR are cleared, they should be initialized with the next RTT sample taken per
   * (2.2) rather than using (2.3).
   */
  static final int MAX_CONSECUTIVE_RTO_BACKOFFS = 5;

  @Override
  public synchronized void backoffOnResend() {
    if (rto >= MAX_RTO) {
      LOG.error(
          "Major packet loss on {} - RTO is already at limit and still losing packets!", this);
    }
    rto = rto * 2;
    if (rto > MAX_RTO) rto = MAX_RTO;
    consecutiveRTOBackoffs++;
    if (consecutiveRTOBackoffs > MAX_CONSECUTIVE_RTO_BACKOFFS) {
      LOG.warn(
          "Resetting RTO for {} after {} consecutive backoffs due to packet loss",
          this,
          consecutiveRTOBackoffs);
      consecutiveRTOBackoffs = 0;
      reportedRTT = false;
    }
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Backed off on resend, RTO is now {}" + STR_FOR + "{} consecutive RTO backoffs is {}",
          rto,
          shortToString(),
          consecutiveRTOBackoffs);
  }

  /**
   * Returns the number of bytes sent as resends for this peer.
   *
   * <p>This value is maintained by the transport and reflects retransmissions. It is intended for
   * diagnostics and performance analysis rather than strict accounting.
   *
   * @return total resend bytes sent to this peer
   */
  public long getResendBytesSent() {
    return internals.getResendBytesSent();
  }

  /**
   * Returns whether this peer should be disconnected and removed immediately.
   *
   * <p>Default implementation returns {@code false}.
   *
   * @return {@code true} if the peer should be removed immediately
   */
  public boolean shouldDisconnectAndRemoveNow() {
    return false;
  }

  /**
   * Sets the remote-reported uptime value for this peer.
   *
   * <p>The value is stored as an unsigned byte and interpreted by {@link #getUptime()}.
   *
   * @param uptime2 uptime value encoded as an unsigned byte
   */
  public void setUptime(byte uptime2) {
    this.uptime = uptime2;
  }

  /**
   * Returns the peer-reported uptime as an unsigned short.
   *
   * <p>This is derived from the stored uptime byte and is used for routing heuristics.
   *
   * @return uptime value as an unsigned short in the range {@code 0..255}
   */
  public short getUptime() {
    return (short) (uptime & 0xFF);
  }

  /**
   * Increments the count of times this peer has been selected since connection.
   *
   * <p>The counter is used to compute selection rates for diagnostics and scheduling heuristics.
   */
  public void incrementNumberOfSelections() {
    // Note: a compact bit-field could reduce memory; retained simple counter for clarity.
    synchronized (this) {
      countSelectionsSinceConnected++;
    }
  }

  /**
   * Returns the rate at which this peer has been selected since it connected.
   *
   * <p>The rate is expressed as selections per millisecond since connection. To avoid bias from
   * very short uptimes, the method returns {@code 0.0} until at least ten seconds have elapsed.
   *
   * @return selection rate in selections per millisecond
   */
  public synchronized double selectionRate() {
    long timeSinceConnected = System.currentTimeMillis() - this.connectedTime;
    // Avoid bias due to short uptime.
    if (timeSinceConnected < SECONDS.toMillis(10)) return 0.0;
    return countSelectionsSinceConnected / (double) timeSinceConnected;
  }

  private volatile int offeredMainJarVersion;

  /**
   * Records the main JAR version most recently offered by this peer.
   *
   * <p>This is used by the update subsystem to track advertised core versions.
   *
   * @param mainJarVersion offered the main JAR version number
   */
  public void setMainJarOfferedVersion(int mainJarVersion) {
    offeredMainJarVersion = mainJarVersion;
  }

  /**
   * Returns the main JAR version most recently offered by this peer.
   *
   * <p>The value may be {@code 0} if no version has been offered yet.
   *
   * @return offered the main JAR version number
   */
  public int getMainJarOfferedVersion() {
    return offeredMainJarVersion;
  }

  /**
   * Maybe send something. A SINGLE PACKET. Don't send everything at once, for two reasons: 1. It is
   * possible for a node to have a very long backlog. 2. Sometimes sending a packet can take a long
   * time. 3. Soon PacketSender will be responsible for output bandwidth throttling. So it makes
   * sense to send a single packet and round-robin.
   *
   * @param now current time in milliseconds
   * @param ackOnly when true, only send acknowledgements/housekeeping
   */
  boolean maybeSendPacket(long now, boolean ackOnly) {
    return internals.maybeSendPacket(now, ackOnly);
  }

  /**
   * Returns the tracker ID that can be reused for new messages, if available.
   *
   * <p>The value is derived from the current session tracker. If no tracker is active, the method
   * returns {@code -1}. This is used to correlate packets for the current session.
   *
   * @return reusable tracker ID, or {@code -1} if none is available
   */
  public long getReusableTrackerID() {
    SessionKey cur;
    synchronized (this) {
      cur = currentTracker;
    }
    if (cur == null) {
      if (LOG.isDebugEnabled()) LOG.debug("getReusableTrackerID(): cur = null on {}", this);
      return -1;
    }
    if (LOG.isDebugEnabled()) LOG.debug("getReusableTrackerID(): {} on {}", cur.trackerID, this);
    return cur.trackerID;
  }

  // Note: lastFailedRevocationTransfer was unused; removing avoids dead code.

  /** Reset on disconnection */
  private int countFailedRevocationTransfers;

  /** Records a failed revocation transfer and schedules a fresh handshake IP update attempt. */
  public void failedRevocationTransfer() {
    // Something odd happened, possibly a disconnect, maybe looking up the DNS names will help?
    internals.markHandshakeIpUpdateAttempted(System.currentTimeMillis());
    countFailedRevocationTransfers++;
  }

  /**
   * Returns the number of failed revocation transfers since the last disconnect.
   *
   * <p>The counter resets when the peer disconnects. It is used to decide whether to trigger
   * additional handshake address refresh attempts.
   *
   * @return count of failed revocation transfers since last disconnect
   */
  public int countFailedRevocationTransfers() {
    return countFailedRevocationTransfers;
  }

  /**
   * Registers a listener to be notified when the peer status changes.
   *
   * <p>Listeners are held via {@link java.lang.ref.WeakReference}, so explicit deregistration is
   * not required.
   *
   * @param listener listener to register
   */
  void registerPeerNodeStatusChangeListener(Object listener) {
    internals.registerStatusChangeListener(listener);
  }

  /** Notifies all registered listeners that the peer status changed. */
  private void notifyPeerNodeStatusChangeListeners() {
    internals.notifyStatusChangeListeners();
  }

  /**
   * Returns whether the peer's reported uptime is below the store-key threshold.
   *
   * <p>This is a heuristic used by routing and storage decisions. The threshold is defined by
   * {@link Node#MIN_UPTIME_STORE_KEY}.
   *
   * @return {@code true} if the peer is considered low-uptime
   */
  public boolean isLowUptime() {
    return getUptime() < Node.MIN_UPTIME_STORE_KEY;
  }

  static final int ADDED_REASON_UNKNOWN = -1;

  synchronized void setAddedReason(int addedReason) {
    // Do nothing.
  }

  synchronized int getAddedReason() {
    return ADDED_REASON_UNKNOWN;
  }

  void removeUIDsFromMessageQueues(Long[] list) {
    this.messageQueue.removeUIDsFromMessageQueues(list);
  }

  PeerNodeLoadTracker.OutputLoadTracker outputLoadTracker(boolean realTime) {
    return internals.outputLoadTracker(realTime);
  }

  void reportLoadStatus(Object stat) {
    internals.reportLoadStatus(stat);
    node.network().executor().execute(checkStatusAfterBackoff);
  }

  /**
   * Stops routing the given request through this peer.
   *
   * @param tag the request identifier
   * @param offeredKey whether this was an offered key fetch
   */
  void noLongerRoutingTo(Object tag, boolean offeredKey) {
    internals.noLongerRoutingTo(tag, offeredKey);
    if (LOG.isDebugEnabled()) LOG.debug("No longer routing {} to {}", tag, this);
  }

  void postUnlock(Object tag) {
    internals.postUnlock(tag);
  }

  PeerNodeLoadTracker.IncomingLoadSummaryStats getIncomingLoadStats(boolean realTime) {
    return internals.getIncomingLoadStats(realTime);
  }

  /**
   * Handles a fatal timeout for a specific request routed to this peer.
   *
   * @param tag the request identifier
   * @param offeredKey whether this was an offered key fetch
   */
  void fatalTimeout(Object tag, boolean offeredKey) {
    // Note: Placeholder; currently disconnects. A richer implementation would
    // require additional protocol messages to query/confirm remote state.
    noLongerRoutingTo(tag, offeredKey);
    fatalTimeout();
  }

  /**
   * After a fatal timeout - that is, a timeout that we reasonably believe originated on the node
   * rather than downstream - we do not know whether the node thinks the request is still running.
   * Hence, load management will get really confused and likely start to send requests over and
   * over, which are repeatedly rejected.
   *
   * <p>So we have some alternatives: 1) Lock the slot forever (or at least until the node
   * reconnects). So every time a node times out, it loses a slot, and gradually it becomes
   * completely catatonic. 2) Wait forever for an acknowledgement of the timeout. This may be worth
   * investigating. One problem with this is that the slot would still count towards our overall
   * load management, which is surely a bad thing, although we could make it only count towards this
   * node. Also, if it doesn't arrive in a reasonable time, maybe there has been a severe problem
   * e.g., out of memory, bug, etc.; in that case, waiting forever may not be sensible. 3)
   * Disconnect the node. This makes perfect sense for opennet. For darknet it's a bit more
   * problematic. 4) Turn off routing to the node, possibly for a limited period. This would need to
   * include the effects of disconnection. It might open up some cheapish local DoS's.
   *
   * <p>For all nodes, at present, we disconnect. For darknet nodes, we log an error and allow them
   * to reconnect.
   */
  public abstract void fatalTimeout();

  /**
   * Returns whether routing should proceed based on peer location and remaining HTL.
   *
   * <p>Subclasses may apply opennet/darknet-specific heuristics. The method should be fast and
   * deterministic for a given input.
   *
   * @param htl remaining hop-to-live value for the request
   * @return {@code true} if routing should proceed based on location heuristics
   */
  public abstract boolean shallWeRouteAccordingToOurPeersLocation(int htl);

  @Override
  public PeerMessageQueue getMessageQueue() {
    return messageQueue;
  }

  /**
   * Delegates handling of an incoming packet to the current packet format.
   *
   * <p>The method returns {@code false} when no packet format is available. It does not throw for
   * format changes; callers should treat a {@code false} return as a no-op.
   *
   * @param buf packet buffer containing the received data
   * @param offset offset into {@code buf} where the packet starts
   * @param length number of bytes in the packet
   * @param now current time in milliseconds for timeout accounting
   * @param replyTo address to use for any immediate replies
   * @return {@code true} if the packet was accepted for processing
   */
  public boolean handleReceivedPacket(byte[] buf, int offset, int length, long now, Peer replyTo) {
    PacketFormat pf;
    synchronized (this) {
      pf = internals.packetFormat();
      if (pf == null) return false;
    }
    return pf.handleReceivedPacket(buf, offset, length, now, replyTo);
  }

  /**
   * Requests the packet format to check for lost packets.
   *
   * <p>If no packet format is active, the method returns immediately. Timers use this to trigger
   * retransmission checks.
   */
  public void checkForLostPackets() {
    PacketFormat pf;
    synchronized (this) {
      pf = internals.packetFormat();
      if (pf == null) return;
    }
    pf.checkForLostPackets();
  }

  /**
   * Returns the next time to check for lost packets for this peer.
   *
   * @return epoch time in milliseconds, or {@link Long#MAX_VALUE} if not applicable
   */
  public long timeCheckForLostPackets() {
    PacketFormat pf;
    synchronized (this) {
      pf = internals.packetFormat();
      if (pf == null) return Long.MAX_VALUE;
    }
    return pf.timeCheckForLostPackets();
  }

  /**
   * Drops references to a session key when it is considered broken.
   *
   * <p>Only called for new-format connections where per-key packet tracking is not used. Updates
   * the connected state when the current key is dropped.
   *
   * @param brokenKey session key to discard
   */
  @SuppressWarnings("unused")
  public void dumpTracker(SessionKey brokenKey) {
    long now = System.currentTimeMillis();
    synchronized (this) {
      if (currentTracker == brokenKey) {
        currentTracker = null;
        internals.setConnected(false, now);
      } else if (previousTracker == brokenKey) previousTracker = null;
      else if (unverifiedTracker == brokenKey) unverifiedTracker = null;
    }
    // Update connected vs. not connected status.
    isConnected();
    setPeerNodeStatus(System.currentTimeMillis());
  }

  @Override
  public void sendEncryptedPacket(byte[] data) throws LocalAddressException {
    crypto.getSocket().sendPacket(data, getPeer(), allowLocalAddresses());
  }

  @Override
  public int getMaxPacketSize() {
    return crypto.getSocket().getMaxPacketSize();
  }

  @Override
  public boolean shouldPadDataPackets() {
    return crypto.getConfig().paddDataPackets();
  }

  @Override
  public void sentThrottledBytes(int count) {
    node.network().outputThrottle().forceGrab(count);
  }

  @Override
  public void onNotificationOnlyPacketSent(int length) {
    node.network().stats().reportNotificationOnlyPacketSent(length);
  }

  @Override
  public void resentBytes(int length) {
    internals.resendBytes(length);
  }

  // Note: consider moving this to PacketFormat in the future.
  @Override
  public Random paddingGen() {
    return random;
  }

  /**
   * Returns whether the supplied peer address matches this peer by address and port.
   *
   * <p>This checks the detected peer and all nominal peers using lax equality. The comparison is
   * intended for incoming packet correlation and is not a strict identity check.
   *
   * @param peer address to compare
   * @return {@code true} if the address matches any known peer entry
   */
  public synchronized boolean matchesPeerAndPort(Peer peer) {
    if (getPeer() != null && getPeer().laxEquals(peer)) return true;
    if (nominalPeer != null) { // Note: condition retained for safety
      for (Peer p : nominalPeer) {
        if (p != null && p.laxEquals(peer)) return true;
      }
    }
    return false;
  }

  /**
   * Returns whether this peer is considered low capacity for the given traffic class.
   *
   * <p>This is derived from recent load stats and is used to avoid overloading peers. It returns
   * {@code false} when no load stats are available.
   *
   * @param isRealtime whether to evaluate real-time or bulk capacity
   * @return {@code true} if the peer is currently low capacity
   */
  public boolean isLowCapacity(boolean isRealtime) {
    return internals.isLowCapacity(isRealtime);
  }

  private long maxPeerPingTime() {
    if (node == null) return NodeStats.DEFAULT_MAX_PING_TIME * 2;
    NodeStats stats = node.network().stats();
    if (node.network().stats() == null) return NodeStats.DEFAULT_MAX_PING_TIME * 2;
    else return stats.maxPeerPingTime();
  }

  /** Whether we are sending the main jar to this peer */
  protected boolean sendingUOMMainJar;

  /** Whether we are sending the ext jar (legacy) to this peer */
  protected boolean sendingUOMLegacyExtJar;

  /**
   * The number of UOM transfers in progress to this peer. Note that there are mechanisms in UOM to
   * limit this.
   */
  private int uomCount;

  /** The time when we last had UOM transfers in progress to this peer, if uomCount == 0. */
  private long lastSentUOM;

  // Note: limiting individual dependencies might or might not improve DoS
  // resilience; the current approach relies on natural failure behavior.

  /**
   * Start sending a UOM jar to this peer.
   *
   * @param isExt whether the legacy external jar is being sent
   * @return {@code true} unless it was already sending; otherwise {@code false}
   */
  public synchronized boolean sendingUOMJar(boolean isExt) {
    if (isExt) {
      if (sendingUOMLegacyExtJar) return false;
      sendingUOMLegacyExtJar = true;
    } else {
      if (sendingUOMMainJar) return false;
      sendingUOMMainJar = true;
    }
    return true;
  }

  /**
   * Marks completion of a UOM jar sending.
   *
   * @param isExt whether the legacy external jar was sent
   */
  public synchronized void finishedSendingUOMJar(boolean isExt) {
    if (isExt) {
      sendingUOMLegacyExtJar = false;
      if (!(sendingUOMMainJar || uomCount > 0)) lastSentUOM = System.currentTimeMillis();
    } else {
      sendingUOMMainJar = false;
      if (!(sendingUOMLegacyExtJar || uomCount > 0)) lastSentUOM = System.currentTimeMillis();
    }
  }

  /**
   * Returns the time elapsed since the last UOM transfer completed.
   *
   * <p>If a UOM transfer is currently in progress, the method returns {@code 0}. If no transfer has
   * ever completed, it returns {@link Long#MAX_VALUE}.
   *
   * @return elapsed time in milliseconds since the last completed UOM transfer
   */
  protected synchronized long timeSinceSentUOM() {
    if (sendingUOMMainJar || sendingUOMLegacyExtJar) return 0;
    if (uomCount > 0) return 0;
    if (lastSentUOM <= 0) return Long.MAX_VALUE;
    return System.currentTimeMillis() - lastSentUOM;
  }

  /**
   * Increments the count of in-progress UOM transfers.
   *
   * <p>This should be called when a UOM transfer begins.
   */
  public synchronized void incrementUOMSends() {
    uomCount++;
  }

  /**
   * Decrements the count of in-progress UOM transfers.
   *
   * <p>When the count reaches zero and no UOM jar is being sent, the last-sent timestamp is
   * updated.
   */
  public synchronized void decrementUOMSends() {
    uomCount--;
    if (uomCount == 0 && (!sendingUOMMainJar) && (!sendingUOMLegacyExtJar))
      lastSentUOM = System.currentTimeMillis();
  }

  /**
   * Returns the boot ID exposed to the peer.
   *
   * <p>The value is randomized at startup and reset when message queues are dumped. It is used by
   * the peer to detect restarts and session resets.
   *
   * @return outgoing boot ID for this peer
   */
  public synchronized long getOutgoingBootID() {
    return this.myBootID;
  }

  private long lastIncomingRekey;

  static final long THROTTLE_REKEY = 1000;

  /**
   * Returns whether an incoming rekey should be throttled.
   *
   * <p>If rekeys arrive too quickly, the method logs an error and returns {@code true} to indicate
   * throttling. It also updates the last rekey time on success.
   *
   * @return {@code true} if the rekey should be throttled
   */
  public synchronized boolean throttleRekey() {
    long now = System.currentTimeMillis();
    if (now - lastIncomingRekey < THROTTLE_REKEY) {
      LOG.error("Two rekeys initiated by other side within " + THROTTLE_REKEY + "ms");
      return true;
    }
    lastIncomingRekey = now;
    return false;
  }

  /**
   * Returns whether the packet queue is full for a packet of maximum size.
   *
   * <p>This is a convenience check used to avoid enqueuing large packets when the queue cannot
   * accept them.
   *
   * @return {@code true} if the queue would reject a full-size packet
   */
  public boolean fullPacketQueued() {
    PacketFormat pf;
    synchronized (this) {
      pf = internals.packetFormat();
      if (pf == null) return false;
    }
    return pf.fullPacketQueued(getMaxPacketSize());
  }

  /**
   * Returns the next time acknowledgements should be sent.
   *
   * <p>If no packet format is active, the method returns {@link Long#MAX_VALUE}.
   *
   * @return epoch time in milliseconds for next ACK send, or {@link Long#MAX_VALUE}
   */
  public long timeSendAcks() {
    PacketFormat pf;
    synchronized (this) {
      pf = internals.packetFormat();
      if (pf == null) return Long.MAX_VALUE;
    }
    return pf.timeSendAcks();
  }

  /**
   * Calculates the maximum number of concurrent outgoing transfers allowed to this peer.
   *
   * @param timeout time window in milliseconds
   * @param nonOverheadFraction fraction of bandwidth available to payload (0.0–1.0)
   * @return maximum number of concurrent transfers
   */
  public int calculateMaxTransfersOut(int timeout, double nonOverheadFraction) {
    // First, get usable bandwidth.
    double bandwidth = (internals.bandwidth() + 1.0);
    if (shouldThrottle())
      bandwidth = Math.min(bandwidth, (double) node.network().outputBandwidthLimit() / 2);
    bandwidth *= nonOverheadFraction;
    // Transfers are divided into packets. Packets are 1KB. There are 1-2
    // of these for SSKs and 32 of them for CHKs, but that's irrelevant here.
    // We are only concerned here with the time that a transfer will have to
    // wait after sending a packet for it to have an opportunity to send
    // another one. Or equivalently the delay between starting and sending
    // the first packet.
    double packetsPerSecond = bandwidth / 1024.0;
    return (int) Math.clamp(packetsPerSecond * timeout, 1.0, Integer.MAX_VALUE);
  }

  /**
   * Returns whether a full noderef has been cached for this peer.
   *
   * <p>A full noderef includes the complete field set and may be missing if only partial noderefs
   * have been observed.
   *
   * @return {@code true} if a full noderef is available
   */
  public synchronized boolean hasFullNoderef() {
    return fullFieldSet != null;
  }

  /**
   * Returns the cached full noderef field set if available.
   *
   * <p>The returned field set may be {@code null} when no full noderef has been observed. Callers
   * should treat the value as read-only.
   *
   * @return full noderef field set, or {@code null} if unavailable
   */
  public synchronized SimpleFieldSet getFullNoderef() {
    return fullFieldSet;
  }

  private int consecutiveGuaranteedRejectsRT = 0;
  private int consecutiveGuaranteedRejectsBulk = 0;

  private static final int CONSECUTIVE_REJECTS_MANDATORY_BACKOFF = 5;

  /**
   * After 5 consecutive GUARANTEED soft rejections, we enter mandatory backoff. The reason why we
   * don't immediately enter mandatory backoff is as follows: PROBLEM: Requests could have completed
   * between the time when the request was rejected and now. SOLUTION A: Tracking all possible
   * requests that are completed since the request was sent. CON: This would be rather complex, and
   * I'm not sure how well it would work when there are many requests in flight; would it even be
   * possible without stopping sending requests after some arbitrary threshold? We might need a time
   * element, and would probably need parameters... SOLUTION B: Enforcing a hard peer limit on both
   * sides, as opposed to accepting a request if the *current* usage, without the new request, is
   * over the limit. CON: This would break fairness between request types.
   *
   * <p>Of course, the problem with just using a counter is it may need to be changed frequently ...
   * Note: a better solution may exist; counter-based approach retained for simplicity.
   *
   * <p>Fortunately, this is pretty rare. It happens when e.g., we send an SSK, then we send a CHK,
   * the messages are reordered and the CHK is accepted, and then the SSK is rejected. Both were
   * GUARANTEED because if they are accepted in order, thanks to the mechanism referred to in
   * solution B, they will both be accepted.
   *
   * @param realTimeFlag whether the rejected request was real-time
   */
  public void rejectedGuaranteed(boolean realTimeFlag) {
    synchronized (this) {
      if (realTimeFlag) {
        consecutiveGuaranteedRejectsRT++;
        if (consecutiveGuaranteedRejectsRT != CONSECUTIVE_REJECTS_MANDATORY_BACKOFF) {
          return;
        }
        consecutiveGuaranteedRejectsRT = 0;
      } else {
        consecutiveGuaranteedRejectsBulk++;
        if (consecutiveGuaranteedRejectsBulk != CONSECUTIVE_REJECTS_MANDATORY_BACKOFF) {
          return;
        }
        consecutiveGuaranteedRejectsBulk = 0;
      }
    }
    enterMandatoryBackoff("Mandatory:RejectedGUARANTEED", realTimeFlag);
  }

  /**
   * Accepting any request resets the counters for consecutive guaranteed rejections.
   *
   * @param realTimeFlag whether the accepted request was real-time
   */
  public void acceptedAny(boolean realTimeFlag) {
    synchronized (this) {
      if (realTimeFlag) {
        consecutiveGuaranteedRejectsRT = 0;
      } else {
        consecutiveGuaranteedRejectsBulk = 0;
      }
    }
  }

  @SuppressWarnings("UnusedReturnValue")
  private boolean verifyReferenceSignature(SimpleFieldSet fs) throws FSParseException {
    try {
      return internals.verifyReferenceSignature(fs);
    } catch (Exception e) {
      throw new FSParseException("Invalid signature", e);
    }
  }

  /**
   * Remembers recently sent JFK nonce for replay protection during handshake processing.
   *
   * <p>Package-private for use by {@link FNPPacketMangler}.
   */
  void rememberJfkNonce(byte[] nonce, int maxNoncesPerPeer) {
    internals.rememberJfkNonce(nonce, maxNoncesPerPeer);
  }

  /**
   * Returns the original nonce matching the given hash, or {@code null} when unknown.
   *
   * <p>Package-private for use by {@link FNPPacketMangler}.
   */
  byte[] findOriginalJfkNonceByHash(byte[] nonceHash) {
    return internals.findOriginalJfkNonceByHash(nonceHash);
  }

  /**
   * Clears the sent-JFK-nonce cache.
   *
   * <p>Package-private for use by {@link FNPPacketMangler} when handshake state is reset.
   */
  void clearJfkNoncesSent() {
    internals.clearJfkNoncesSent();
  }

  /**
   * Returns the hash of the peer's public key.
   *
   * <p>The returned array is the internal cached value and should be treated as read-only. Callers
   * must not modify its contents.
   *
   * @return peer public key hash byte array
   */
  protected final byte[] getPubKeyHash() {
    return peerECDSAPubKeyHash;
  }

  double getBackedOffPercentRT() {
    return internals.backedOffPercentRT();
  }

  double getBackedOffPercentBulk() {
    return internals.backedOffPercentBulk();
  }
}

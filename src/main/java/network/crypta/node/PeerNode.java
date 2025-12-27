package network.crypta.node;

import static java.util.concurrent.TimeUnit.DAYS;
import static java.util.concurrent.TimeUnit.HOURS;
import static java.util.concurrent.TimeUnit.MINUTES;
import static java.util.concurrent.TimeUnit.SECONDS;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Writer;
import java.lang.ref.WeakReference;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.EnumMap;
import java.util.GregorianCalendar;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.Random;
import java.util.Set;
import java.util.TimeZone;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;
import network.crypta.client.FetchResult;
import network.crypta.client.async.USKRetriever;
import network.crypta.client.async.USKRetrieverCallback;
import network.crypta.crypt.BlockCipher;
import network.crypta.crypt.DSAPublicKey;
import network.crypta.crypt.ECDSA;
import network.crypta.crypt.ECDSA.Curves;
import network.crypta.crypt.Global;
import network.crypta.crypt.HMAC;
import network.crypta.crypt.KeyAgreementSchemeContext;
import network.crypta.crypt.SHA256;
import network.crypta.crypt.UnsupportedCipherException;
import network.crypta.crypt.ciphers.Rijndael;
import network.crypta.io.AddressTracker;
import network.crypta.io.comm.AsyncMessageCallback;
import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.DisconnectedException;
import network.crypta.io.comm.FreenetInetAddress;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.MessageFilter;
import network.crypta.io.comm.NotConnectedException;
import network.crypta.io.comm.Peer;
import network.crypta.io.comm.Peer.LocalAddressException;
import network.crypta.io.comm.PeerParseException;
import network.crypta.io.comm.ReferenceSignatureVerificationException;
import network.crypta.io.comm.SocketHandler;
import network.crypta.io.xfer.PacketThrottle;
import network.crypta.keys.ClientSSK;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.Key;
import network.crypta.keys.USK;
import network.crypta.node.NodeStats.PeerLoadStats;
import network.crypta.node.NodeStats.RequestType;
import network.crypta.node.NodeStats.RunningRequestsSnapshot;
import network.crypta.node.OpennetManager.ConnectionType;
import network.crypta.support.Base64;
import network.crypta.support.BooleanLastTrueTracker;
import network.crypta.support.Fields;
import network.crypta.support.HexUtil;
import network.crypta.support.IllegalBase64Exception;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.TimeUtil;
import network.crypta.support.WeakHashSet;
import network.crypta.support.api.Bucket;
import network.crypta.support.math.RunningAverage;
import network.crypta.support.math.SimpleRunningAverage;
import network.crypta.support.math.TimeDecayingRunningAverage;
import network.crypta.support.transport.ip.HostnameSyntaxException;
import network.crypta.support.transport.ip.IPUtil;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents a remote peer known to and contacted by this node.
 *
 * <p>This class tracks link setup, routing eligibility, and per-key session state with the remote.
 * Rekeying and restarts are handled by promoting or replacing {@link SessionKey} instances; each
 * session maintains independent packet and message identifier spaces.
 *
 * <p>Locking: acquire {@link PeerManager} first, then lock this {@code PeerNode}. Do not hold a
 * {@code PeerNode} lock while attempting to lock {@code PeerManager}.
 *
 * @author amphibian
 */
public abstract class PeerNode implements USKRetrieverCallback, BasePeerNode, PeerNodeUnlocked {
  private static final Logger LOG = LoggerFactory.getLogger(PeerNode.class);

  // SFS keys used more than once: keep as constants to avoid duplication warnings
  private static final String SFS_KEY_VERSION = "version";
  private static final String SFS_KEY_LOCATION = "location";
  private static final String SFS_KEY_LAST_GOOD_VERSION = "lastGoodVersion";
  private static final String SFS_KEY_TESTNET = "testnet";
  private static final String SFS_KEY_NEG_TYPES = "auth.negTypes";
  private static final String SFS_KEY_OPENNET = "opennet";
  private static final String SFS_KEY_IDENTITY = "identity";
  private static final String SFS_KEY_PHYSICAL_UDP = "physical.udp";
  private static final String SFS_KEY_METADATA = "metadata";
  private static final String SFS_KEY_PEER_ADDED_TIME = "peerAddedTime";
  private static final String SFS_KEY_DETECTED_UDP = "detected.udp";
  private static final String STR_MS_FOR = "ms for ";
  private static final String STR_FOR = " for ";
  private static final String STR_ERROR = "error";
  private static final String STR_MESSAGES_TO_DUMP = "Messages to dump: ";
  private static final String STR_MS_ON = "ms on ";
  private static final String STR_ON = ") on ";
  private static final String STR_WORKING_ON = ") working on ";
  private static final String STR_NOT_ROUTING_TO = "Not routing traffic to ";
  private static final String STR_NOT_SENDING_HANDSHAKE_TO = "Not sending handshake to ";
  private static final String STR_P_REJECTED = " : pRejected=";
  private static final String STR_WAITED = "Waited ";
  private static final String STR_REALTIME_EQ = " realtime=";
  private static final String STR_INVALID_HOST_OR_IP_WHILE_PARSING =
      "Invalid hostname or IP Address syntax error while parsing new peer reference: ";
  private static final String STR_ACCEPT_STATE_IS = "Accept state is ";
  private static final String SFS_KEY_ARK_PUBURI = "ark.pubURI";
  private static final String SFS_KEY_ARK_NUMBER = "ark.number";
  private static final String SFS_KEY_SIG_P256 = "sigP256";

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

  protected boolean disableRouting;
  protected boolean disableRoutingHasBeenSetLocally;
  protected boolean disableRoutingHasBeenSetRemotely;
  /*
   * Buffer of Ni,Nr,g^i,g^r,ID
   */
  private byte[] jfkBuffer;
  // Note: consider additional synchronization if needed

  protected byte[] jfkKa;
  protected byte[] incommingKey;
  protected byte[] jfkKe;
  protected byte[] outgoingKey;
  protected byte[] jfkMyRef;
  protected byte[] hmacKey;
  protected byte[] ivKey;
  protected byte[] ivNonce;
  protected int ourInitialSeqNum;
  protected int theirInitialSeqNum;
  protected int ourInitialMsgID;
  protected int theirInitialMsgID;
  // The following is used only if we are the initiator

  protected long jfkContextLifetime = 0;

  /** My low-level address for SocketManager purposes */
  private Peer detectedPeer = null;

  /** My OutgoingPacketMangler i.e. the object which encrypts packets sent to this node */
  private final OutgoingPacketMangler outgoingMangler;

  /** Advertised addresses */
  protected List<Peer> nominalPeer;

  /** The PeerNode's report of our IP address */
  private Peer remoteDetectedPeer;

  /** Is this a testnet node? */
  public final boolean testnetEnabled;

  /** Packets sent/received on the current preferred key */
  private SessionKey currentTracker;

  /** Previous key - has a separate packet number space */
  private SessionKey previousTracker;

  /** When did we last rekey (promote the unverified tracker to new) ? */
  private long timeLastRekeyed;

  /** How much data did we send with the current tracker ? */
  private long totalBytesExchangedWithCurrentTracker = 0;

  /** Are we rekeying ? */
  private boolean isRekeying = false;

  /** Unverified tracker - will be promoted to currentTracker if we receive packets on it */
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
  // 30%; yes it's alchemy too! and probably *way* too high to serve any purpose
  public static final int SELECTION_PERCENTAGE_WARNING = 30;
  // Minimum number of routable peers to have for the selection code to have any effect
  public static final int SELECTION_MIN_PEERS = 5;

  /**
   * Is the peer connected? If currentTracker == null then we have no way to send packets (though we
   * may be able to receive them on the other trackers), and are disconnected. So we MUST set
   * isConnected to false when currentTracker = null, but the other way around isn't always true.
   * LOCKING: Locks itself, safe to read atomically, however we should take (this) when setting it.
   */
  private final BooleanLastTrueTracker isConnected;

  // Note: isRoutable() depends on more than this flag.
  private boolean isRoutable;

  /** Used by maybeOnConnect */
  private boolean wasDisconnected = true;

  /**
   * Were we removed from the routing table? Used as a cache to avoid accessing PeerManager if not
   * needed.
   */
  private boolean removed;

  /** ARK fetcher. */
  private USKRetriever arkFetcher;

  /**
   * My ARK SSK public key; edition is the next one, not the current one, so this is what we want to
   * fetch.
   */
  private USK myARK;

  /** Number of handshake attempts since last successful connection or ARK fetch */
  private int handshakeCount;

  /** After this many failed handshakes, we start the ARK fetcher. */
  private static final int MAX_HANDSHAKE_COUNT = 2;

  final PeerLocation location;

  /**
   * Node "identity". This is a random 32 byte block of data, which may be derived from the node's
   * public key. It cannot be changed, and is only used for the outer keyed obfuscation on
   * connection setup packets in FNPPacketMangler.
   */
  final byte[] identity;

  final String identityAsBase64String;

  /** Hash of node identity. Used in setup key. */
  final byte[] identityHash;

  /** Hash of node identity. Used in setup key. */
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
   * inside PeerNode.this lock.
   */
  private final PeerMessageQueue messageQueue;

  /** When did we last receive a SwapRequest? */
  private long timeLastReceivedSwapRequest;

  /** Average interval between SwapRequest's */
  private final RunningAverage swapRequestsInterval;

  /** When did we last receive a probe request? */
  private long timeLastReceivedProbeRequest;

  /** Average interval between probe requests */
  private final RunningAverage probeRequestsInterval;

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

  /** Peer node public key; changing this means new noderef */
  public final ECPublicKey peerECDSAPubKey;

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

  /** Incoming setup cipher (see above) */
  final BlockCipher incomingSetupCipher;

  /** Outgoing setup cipher (see above) */
  final BlockCipher outgoingSetupCipher;

  /**
   * Anonymous-connect cipher. This is used in link setup if we are trying to get a connection to
   * this node even though it doesn't know us, e.g. as a seednode.
   */
  final BlockCipher anonymousInitiatorSetupCipher;

  /** The context object for the currently running negotiation. */
  private KeyAgreementSchemeContext ctx;

  /**
   * The other side's boot ID. This is a random number generated at startup. LOCKING: It is far too
   * dangerous to hold the main (this) lock while accessing bootID given that we ask for it in the
   * messaging code and so on. This is essentially a "the other side restarted" flag, so there isn't
   * really a consistency issue with the rest of PeerNode. So it's okay to effectively use a
   * separate lock for it.
   */
  private final AtomicLong bootID;

  /**
   * Our boot ID. This is set to a random number on startup, and then reset whenever we dump the
   * in-flight messages and call disconnected() on their clients, i.e. whenever we call
   * disconnected(true, ...)
   */
  private long myBootID;

  /** myBootID at the time of the last successful completed handshake. */
  private long myLastSuccessfulBootID;

  /** If true, this means last time we tried, we got a bogus noderef */
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

  /** The last time we attempted to update handshakeIPs */
  private long lastAttemptedHandshakeIPUpdateTime;

  /** True if we have never connected to this peer since it was added to this node */
  protected boolean neverConnected;

  /**
   * When this peer was added to this node. This is used differently by opennet and darknet nodes.
   * Darknet nodes clear it after connecting but persist it across restarts, and clear it on restart
   * unless the peer has never connected, or if it is more than 30 days ago. Opennet nodes clear it
   * after the post-connect grace period elapses, and don't persist it across restarts.
   */
  protected long peerAddedTime;

  /** Average proportion of requests which are rejected or timed out */
  private final TimeDecayingRunningAverage pRejected;

  /** Bytes received at/before startup */
  private final long bytesInAtStartup;

  /** Bytes sent at/before startup */
  private final long bytesOutAtStartup;

  /** Times had routable connection when checked */
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

  /** The node is being disconnected, but it may take a while. */
  private boolean disconnecting;

  /** When did we last disconnect? Not Disconnected because a discrete event */
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

  /**
   * The set of the listeners that needs to be notified when status changes. It uses WeakReference,
   * so there is no need to deregister
   */
  private final Set<PeerManager.PeerStatusChangeListener> listeners =
      Collections.synchronizedSet(new WeakHashSet<>());

  // NodeCrypto for the relevant node reference for this peer's type (Darknet or Opennet at this
  // time)
  protected final NodeCrypto crypto;

  /** Backoff guard used by {@link #shouldBeExcludedFromPeerList()}. */
  public static final long BLACK_MAGIC_BACKOFF_PRUNING_TIME = MINUTES.toMillis(5);

  public static final double BLACK_MAGIC_BACKOFF_PRUNING_PERCENTAGE = 0.9;

  /**
   * For FNP link setup: the initiator must ensure that nonces sent back by the responder in {@code
   * message2} match what was chosen in {@code message1}.
   */
  protected final LinkedList<byte[]> jfkNoncesSent = new LinkedList<>();

  // No static initialisation required.

  private PacketFormat packetFormat;

  /** Non-cryptographic random source scoped to this PeerNode. Thread-safe. */
  protected final Random random;

  protected SimpleFieldSet fullFieldSet;

  protected boolean ignoreLastGoodVersion() {
    return false;
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
   * @throws PeerParseException if the noderef contains invalid values
   * @throws ReferenceSignatureVerificationException if a signature is present but invalid
   * @throws PeerTooOldException if the peer is too old to be parsed with the current protocols
   */
  protected PeerNode(
      SimpleFieldSet fs, Node node2, NodeCrypto crypto, boolean fromLocal, PeerManager peers)
      throws FSParseException,
          PeerParseException,
          ReferenceSignatureVerificationException,
          PeerTooOldException {
    boolean noSig = fromLocal || fromAnonymousInitiator();
    // Core finals
    myRef = new WeakReference<>(this);
    this.checkStatusAfterBackoff = new PeerNodeBackoffStatusChecker(myRef);
    this.outgoingMangler = crypto.getPacketMangler();
    this.node = node2;
    this.crypto = crypto;
    if (crypto.isOpennet() != isOpennetForNoderef()) {
      throw new IllegalArgumentException("Mismatched NodeCrypto for noderef type");
    }
    this.random = node.createRandom();
    this.peers = Objects.requireNonNull(peers, "peers");
    this.backedOffPercent = new TimeDecayingRunningAverage(0.0, 180000, 0.0, 1.0, node);
    this.backedOffPercentRT = new TimeDecayingRunningAverage(0.0, 180000, 0.0, 1.0, node);
    this.backedOffPercentBulk = new TimeDecayingRunningAverage(0.0, 180000, 0.0, 1.0, node);
    this.myBootID = node2.getBootId();
    this.bootID = new AtomicLong();

    parseAndSetVersion(fs);
    // Location & routing
    this.location = createPeerLocation(fs);
    disableRouting = disableRoutingHasBeenSetLocally = false;
    disableRoutingHasBeenSetRemotely = false;
    lastGoodVersion = fs.get(SFS_KEY_LAST_GOOD_VERSION);
    updateVersionRoutablity();
    // Testnet flag (final)
    this.testnetEnabled = readTestnetEnabled(fs);
    if (testnetEnabled) {
      String err = "Ignoring incompatible testnet node " + fs.toOrderedString();
      LOG.error(err);
      throw new PeerParseException(err);
    }
    parseNegotiationTypes(fs);
    validateOpennetFlag(fs);
    // Peer key (final)
    this.peerECDSAPubKey = readPeerEcdsaKeyReturn(fs);
    this.peerECDSAPubKeyHash = SHA256.digest(peerECDSAPubKey.getEncoded());
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
    this.incomingSetupCipher = buildRijndaelCipher(incomingSetupKey);
    this.outgoingSetupCipher = buildRijndaelCipher(outgoingSetupKey);
    this.anonymousInitiatorSetupCipher = buildRijndaelCipher(identityHash);

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
    this.swapRequestsInterval =
        new SimpleRunningAverage(50, Node.MIN_INTERVAL_BETWEEN_INCOMING_SWAP_REQUESTS);
    this.probeRequestsInterval =
        new SimpleRunningAverage(50, Node.MIN_INTERVAL_BETWEEN_INCOMING_PROBE_REQUESTS);
    this.messageQueue = new PeerMessageQueue(random);
    this.decrementHTLAtMaximum = random.nextFloat() < Node.DECREMENT_AT_MAX_PROB;
    this.decrementHTLAtMinimum = random.nextFloat() < Node.DECREMENT_AT_MIN_PROB;
    pingNumber = random.nextLong();
    this.pingAverage =
        new TimeDecayingRunningAverage(
            1, SECONDS.toMillis(30), 0, NodePinger.CRAZY_MAX_PING_TIME, node);
    this.pRejected = new TimeDecayingRunningAverage(0, MINUTES.toMillis(4), 0.0, 1.0, node);
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
    this.isConnected = meta.isConnectedTracker;
    // Apply restart-time adjustments after fields are populated from metadata so overrides can
    // act on persisted values and persist their changes.
    if (fromLocal) maybeClearPeerAddedTimeOnRestart(now);
    // Populate handshake IPs quickly
    lastAttemptedHandshakeIPUpdateTime = 0;
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

  private PeerLocation createPeerLocation(SimpleFieldSet fs) {
    String locationString = fs.get(SFS_KEY_LOCATION);
    return new PeerLocation(locationString);
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

  private ECPublicKey readPeerEcdsaKeyReturn(SimpleFieldSet fs)
      throws FSParseException, PeerTooOldException {
    SimpleFieldSet sfs = fs.subset("ecdsa.P256");
    if (sfs == null) {
      GregorianCalendar gc = new GregorianCalendar(2013, Calendar.JULY, 20);
      gc.setTimeZone(TimeZone.getTimeZone("GMT"));
      throw new PeerTooOldException("No ECC support", 1449, gc.getTime());
    }
    byte[] pub;
    try {
      pub = Base64.decode(sfs.get("pub"));
    } catch (IllegalBase64Exception e) {
      throw new FSParseException("Invalid base64 in ecdsa.P256.pub", e);
    }
    if (pub.length > Curves.P256.modulusSize)
      throw new FSParseException("ecdsa.P256.pub is not the right size!");
    ECPublicKey key = ECDSA.getPublicKey(pub, Curves.P256);
    if (key == null) throw new FSParseException("ecdsa.P256.pub is invalid!");
    return key;
  }

  private void verifySignatureIfPresent(SimpleFieldSet fs, boolean noSig)
      throws ReferenceSignatureVerificationException {
    if (noSig) {
      this.isSignatureVerificationSuccessfull = true;
      return;
    }
    // When present, verifyReferenceSignature() sets the flag and may throw on failure.
    verifyReferenceSignature(fs);
  }

  private IdentityValues readIdentityValues(SimpleFieldSet fs)
      throws FSParseException, PeerParseException {
    String identityString = fs.get(SFS_KEY_IDENTITY);
    if (identityString == null && isDarknet()) throw new PeerParseException("No identity!");
    try {
      byte[] id;
      if (identityString != null) {
        id = Base64.decode(identityString);
      } else {
        // We might be talking to a pre-1471 node
        // We need to generate it from the DSA key
        SimpleFieldSet sfs = fs.subset("dsaPubKey");
        id = SHA256.digest(DSAPublicKey.create(sfs, Global.DSAgroupBigA).asBytes());
      }
      if (id == null) throw new FSParseException("No identity");
      String b64 = Base64.encode(id);
      byte[] idHash = SHA256.digest(id);
      byte[] idHashHash = SHA256.digest(idHash);
      long swapId = Fields.bytesToLong(idHashHash);
      int hc = Fields.hashCode(peerECDSAPubKeyHash);
      return new IdentityValues(id, b64, idHash, idHashHash, swapId, hc);
    } catch (NumberFormatException | IllegalBase64Exception e) {
      throw new FSParseException(e);
    }
  }

  private byte[] computeIncomingSetupKey(NodeCrypto crypto, byte[] identityHashHash) {
    byte[] nodeKey = crypto.getIdentityHash();
    int digestLength = SHA256.getDigestLength();
    byte[] key = new byte[digestLength];
    for (int i = 0; i < key.length; i++) key[i] = (byte) (nodeKey[i] ^ identityHashHash[i]);
    return key;
  }

  private byte[] computeOutgoingSetupKey(NodeCrypto crypto, byte[] identityHash) {
    byte[] nodeKeyHash = crypto.getIdentityHashHash();
    int digestLength = SHA256.getDigestLength();
    byte[] key = new byte[digestLength];
    for (int i = 0; i < key.length; i++) key[i] = (byte) (nodeKeyHash[i] ^ identityHash[i]);
    return key;
  }

  private BlockCipher buildRijndaelCipher(byte[] keyBytes) {
    try {
      BlockCipher c = new Rijndael(256, 256);
      c.initialize(keyBytes);
      return c;
    } catch (UnsupportedCipherException e1) {
      throw new IllegalStateException("Failed to initialize Rijndael(256,256)", e1);
    }
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
          .addArgument(() -> location)
          .addArgument(this::userToString)
          .log("No IP addresses found for identity '{}', possibly at location '{}: {}");
    }
    updateShortToString();
  }

  /**
   * Parses a physical.udp entry. In addition to the standard "host:port" form, tolerates a
   * comma-separated host list with a shared port suffix (e.g., "A,B:port") or multiple comma-
   * separated full entries (e.g., "A:port,B:port"). Returns zero or more parsed peers.
   */
  private List<Peer> parsePeerEntryCompat(String phys, boolean fromLocal) {
    ArrayList<Peer> out = new ArrayList<>(2);
    try {
      out.add(new Peer(phys, true, true));
      return out;
    } catch (HostnameSyntaxException | PeerParseException | UnknownHostException _) {
      // Try compatibility forms only if a comma appears.
      if (phys.indexOf(',') >= 0) {
        // Pattern: A,B,C:port → apply trailing port to each host
        int lastColon = phys.lastIndexOf(':');
        if (lastColon > 0 && lastColon < phys.length() - 1) {
          String portStr = phys.substring(lastColon + 1);
          boolean portOk = true;
          try {
            int p = Integer.parseInt(portStr);
            if (p < 0 || p > 65535) portOk = false;
          } catch (NumberFormatException _) {
            portOk = false;
          }
          if (portOk) {
            String hostList = phys.substring(0, lastColon);
            String[] hosts = hostList.split(",");
            for (String h : hosts) {
              String cand = h.trim() + ":" + portStr;
              try {
                out.add(new Peer(cand, true, true));
              } catch (Exception _) {
                // try next
              }
            }
          }
        }
        // Additionally try: split by comma and parse each token as-is (covers A:port,B:port)
        for (String token : phys.split(",")) {
          String cand = token.trim();
          if (cand.isEmpty()) continue;
          try {
            Peer parsed = new Peer(cand, true, true);
            if (!out.contains(parsed)) out.add(parsed);
          } catch (Exception _) {
            // continue
          }
        }
        if (!out.isEmpty()) {
          LOG.info("Parsed {} into {} peer(s) via compatibility split", phys, out.size());
          return out;
        }
      }
      if (fromLocal) {
        LOG.error(
            "Invalid hostname or IP Address syntax error while parsing peer reference in local"
                + " peers list: {}",
            phys);
      } else {
        LOG.warn(
            "Invalid hostname or IP Address syntax error while parsing peer reference: {}", phys);
      }
      return out;
    }
  }

  private MetadataInit parseMetadata(SimpleFieldSet fs, boolean fromLocal, long now) {
    MetadataInit result = new MetadataInit();
    if (!fromLocal) {
      result.isConnectedTracker = new BooleanLastTrueTracker();
      result.neverConnected = true;
      result.peerAddedTime = now;
      return result;
    }
    SimpleFieldSet metadata = fs.subset(SFS_KEY_METADATA);
    if (metadata == null) {
      result.isConnectedTracker = new BooleanLastTrueTracker();
      return result;
    }
    return buildMetadataFromSubset(fs, metadata);
  }

  private MetadataInit buildMetadataFromSubset(SimpleFieldSet rootFs, SimpleFieldSet metadata) {
    MetadataInit result = new MetadataInit();
    location.setPeerLocations(rootFs.getAll("peersLocation"));
    result.detectedPeer = parseDetectedPeer(metadata);
    result.timeLastReceivedPacket = metadata.getLong("timeLastReceivedPacket", -1);
    long timeLastConnected = metadata.getLong("timeLastConnected", -1);
    result.timeLastRoutable = metadata.getLong("timeLastRoutable", -1);
    if (timeLastConnected < 1 && result.timeLastReceivedPacket > 1)
      timeLastConnected = result.timeLastReceivedPacket;
    result.isConnectedTracker = new BooleanLastTrueTracker(timeLastConnected);
    if (result.timeLastRoutable < 1 && result.timeLastReceivedPacket > 1)
      result.timeLastRoutable = result.timeLastReceivedPacket;
    result.peerAddedTime = metadata.getLong(SFS_KEY_PEER_ADDED_TIME, 0);
    result.neverConnected = metadata.getBoolean("neverConnected", false);
    result.hadRoutableConnectionCount = metadata.getLong("hadRoutableConnectionCount", 0);
    result.routableConnectionCheckCount = metadata.getLong("routableConnectionCheckCount", 0);
    return result;
  }

  private Peer parseDetectedPeer(SimpleFieldSet metadata) {
    try {
      String detectedUDPString = metadata.get(SFS_KEY_DETECTED_UDP);
      if (detectedUDPString == null) return null;
      return new Peer(detectedUDPString, false);
    } catch (UnknownHostException | PeerParseException e) {
      LOG.error("detected.udp = {} - {}", metadata.get(SFS_KEY_DETECTED_UDP), e, e);
      return null;
    }
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
      innerCalcNextHandshake(false, now); // Let them connect so we can recognise we are NATed
    else sendHandshakeTime = now; // Be sure we're ready to handshake right away
  }

  private static final class IdentityValues {
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
    long peerAddedTime;
    boolean neverConnected;
    long hadRoutableConnectionCount;
    long routableConnectionCheckCount;
    BooleanLastTrueTracker isConnectedTracker;
  }

  // Wraps Inflater so we can use try-with-resources even on JDKs where Inflater is not
  // AutoCloseable.
  private static final class InflaterHolder implements AutoCloseable {
    final Inflater inflater = new Inflater();

    @Override
    public void close() {
      inflater.end();
    }
  }

  /**
   * Returns whether this is a temporary connection initiated by an anonymous peer.
   *
   * <p>True when the node connects and provides a noderef we did not already have (e.g., on
   * seednodes).
   *
   * @return {@code true} if the peer is an anonymous initiator
   */
  protected boolean fromAnonymousInitiator() {
    return false;
  }

  abstract boolean dontKeepFullFieldSet();

  protected abstract void maybeClearPeerAddedTimeOnRestart(long now);

  private boolean parseARK(SimpleFieldSet fs, boolean onStartup, boolean forDiffNodeRef) {
    USK ark = computeArk(fs, onStartup, forDiffNodeRef);
    if (ark == null) return false;
    synchronized (this) {
      if ((myARK == null) || ((myARK != ark) && !myARK.equals(ark))) {
        myARK = ark;
        return true;
      }
    }
    return false;
  }

  private USK computeArk(SimpleFieldSet fs, boolean onStartup, boolean forDiffNodeRef) {
    try {
      String arkPubKey = fs.get(SFS_KEY_ARK_PUBURI);
      long arkNo = fs.getLong(SFS_KEY_ARK_NUMBER, -1);
      if (arkPubKey == null && arkNo <= -1) return null; // pair is optional
      if (arkPubKey != null && arkNo > -1) {
        if (onStartup) arkNo++;
        FreenetURI uri = new FreenetURI(arkPubKey);
        ClientSSK ssk = new ClientSSK(uri);
        return new USK(ssk, arkNo);
      }
      if (forDiffNodeRef && arkPubKey == null && myARK != null) {
        return myARK.copy(arkNo);
      }
      if (forDiffNodeRef && arkPubKey != null && myARK != null) {
        LOG.error(
            "Got a differential node reference from {} with an arkPubKey but no ARK edition", this);
        return null;
      }
    } catch (MalformedURLException | NumberFormatException e) {
      LOG.error("Couldn't parse ARK info for {}: {}", this, e, e);
    }
    return null;
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
      // remove last ", "
      toOutputString.deleteCharAt(toOutputString.length() - 1);
      toOutputString.deleteCharAt(toOutputString.length() - 1);
    }
    toOutputString.append(" ]");
    return toOutputString.toString();
  }

  /**
   * Performs DNS resolution for handshake addresses when hostnames are allowed.
   *
   * <p>Removes duplicates after lookup. Intended to be called only from {@link
   * #maybeUpdateHandshakeIPs(boolean)}.
   *
   * @param localHandshakeIPs candidate addresses to resolve and de-duplicate
   * @param ignoreHostnames when true, skips hostname resolution
   * @return the updated, de-duplicated address array
   */
  private Peer[] updateHandshakeIPs(Peer[] localHandshakeIPs, boolean ignoreHostnames) {
    for (Peer localHandshakeIP : localHandshakeIPs) {
      if (ignoreHostnames) {
        // Don't do a DNS request on the first cycle through PeerNodes by DNSRequest
        // upon startup (I suspect the following won't do anything, but just in case)
        if (LOG.isDebugEnabled())
          LOG.debug(
              "updateHandshakeIPs: calling getAddress(false) on Peer '{}' for {} ({})",
              localHandshakeIP,
              shortToString(),
              true);
        localHandshakeIP.getAddress(false);
      } else {
        // Actually do the DNS request for the member Peer of localHandshakeIPs
        if (LOG.isDebugEnabled())
          LOG.debug(
              "updateHandshakeIPs: calling getHandshakeAddress() on Peer '{}' for {} ({})",
              localHandshakeIP,
              shortToString(),
              false);
        localHandshakeIP.getHandshakeAddress();
      }
    }
    // De-dupe while preserving encounter order
    return Arrays.stream(localHandshakeIPs).distinct().toArray(Peer[]::new);
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
    long now = System.currentTimeMillis();
    Peer localDetectedPeer;
    synchronized (this) {
      localDetectedPeer = getPeer();
      if ((now - lastAttemptedHandshakeIPUpdateTime) < MINUTES.toMillis(5)) return;
      if (!ignoreHostnames) lastAttemptedHandshakeIPUpdateTime = now;
    }
    if (LOG.isDebugEnabled())
      LOG.debug("Updating handshake IPs for peer '{}' ({})", shortToString(), ignoreHostnames);

    Peer[] myNominalPeer;
    synchronized (this) {
      myNominalPeer = nominalPeer.toArray(new Peer[0]);
    }
    if (handleNoNominalPeersCase(localDetectedPeer, myNominalPeer, ignoreHostnames)) return;

    FreenetInetAddress localhost = node.getFreenetLocalhostAddress();
    Peer[] nodePeers = outgoingMangler.getPrimaryIPAddress();
    List<Peer> basePeers;
    synchronized (this) {
      basePeers = new ArrayList<>(nominalPeer);
    }
    PeersBuildResult build =
        prepareLocalPeers(myNominalPeer, localDetectedPeer, nodePeers, localhost, basePeers);
    Peer[] localHandshakeIPs =
        updateHandshakeIPs(build.localPeers.toArray(new Peer[0]), ignoreHostnames);
    applyHandshakeIPs(localHandshakeIPs, localDetectedPeer, build.detectedDuplicate);
  }

  private boolean handleNoNominalPeersCase(
      Peer localDetectedPeer, Peer[] myNominalPeer, boolean ignoreHostnames) {
    if (myNominalPeer.length != 0) return false;
    if (localDetectedPeer == null) {
      synchronized (this) {
        handshakeIPs = null;
      }
      if (LOG.isDebugEnabled())
        LOG.debug("1: maybeUpdateHandshakeIPs got a result of: {}", handshakeIPsToString());
      return true;
    }
    Peer[] localHandshakeIPs = updateHandshakeIPs(new Peer[] {localDetectedPeer}, ignoreHostnames);
    synchronized (this) {
      handshakeIPs = localHandshakeIPs;
    }
    if (LOG.isDebugEnabled())
      LOG.debug("2: maybeUpdateHandshakeIPs got a result of: {}", handshakeIPsToString());
    return true;
  }

  private void applyHandshakeIPs(
      Peer[] localHandshakeIPs, Peer localDetectedPeer, Peer detectedDuplicate) {
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

  private PeersBuildResult prepareLocalPeers(
      Peer[] myNominalPeer,
      Peer localDetectedPeer,
      Peer[] nodePeers,
      FreenetInetAddress localhost,
      List<Peer> localPeers) {
    boolean addedLocalhost = false;
    Peer detectedDuplicate = null;
    for (Peer p : myNominalPeer) {
      if (p == null) continue;
      if (isDuplicateLocalDetectedPeer(p, localDetectedPeer)) detectedDuplicate = p;
      FreenetInetAddress addr = p.getFreenetAddress();
      boolean skip = shouldSkipForLocalhost(addr, localhost, addedLocalhost);
      if (!skip) {
        addedLocalhost =
            maybeAddLocalhostPeerWhenMatch(
                addr, nodePeers, addedLocalhost, localPeers, localhost, p.getPort());
        if (!localPeers.contains(p)) localPeers.add(p);
      }
    }
    return new PeersBuildResult(localPeers, detectedDuplicate);
  }

  private boolean addressMatchesNodePeers(FreenetInetAddress addr, Peer[] nodePeers) {
    for (Peer nodePeer : nodePeers) {
      FreenetInetAddress myAddr = nodePeer.getFreenetAddress();
      if (myAddr.equals(addr)) return true;
    }
    return false;
  }

  private boolean isDuplicateLocalDetectedPeer(Peer p, Peer localDetectedPeer) {
    return localDetectedPeer != null && (p != localDetectedPeer) && p.equals(localDetectedPeer);
  }

  private boolean shouldSkipForLocalhost(
      FreenetInetAddress addr, FreenetInetAddress localhost, boolean addedLocalhost) {
    if (!addr.equals(localhost)) return false;
    return addedLocalhost; // skip when we've already added localhost once
  }

  private boolean maybeAddLocalhostPeerWhenMatch(
      FreenetInetAddress addr,
      Peer[] nodePeers,
      boolean addedLocalhost,
      List<Peer> localPeers,
      FreenetInetAddress localhost,
      int port) {
    if (addressMatchesNodePeers(addr, nodePeers) && !addedLocalhost) {
      localPeers.add(new Peer(localhost, port));
      return true;
    }
    return addedLocalhost;
  }

  private record PeersBuildResult(List<Peer> localPeers, Peer detectedDuplicate) {}

  /**
   * Returns this peer's current keyspace location.
   *
   * <p>Returns a value in the implementation-defined keyspace (typically in [0,1)). Returns {@code
   * -1} when unknown.
   *
   * @return keyspace location, or {@code -1} if unknown
   */
  public double getLocation() {
    return location.getLocation();
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
      if (BLACK_MAGIC_BACKOFF_PRUNING_PERCENTAGE < backedOffPercent.currentValue()) return true;
      else return BLACK_MAGIC_BACKOFF_PRUNING_TIME + now < getRoutingBackedOffUntilMax();
    }
  }

  /** Returns an array copy of locations of this PeerNode's peers, or null if unknown. */
  double[] getPeersLocationArray() {
    return location.getPeersLocationArray();
  }

  /**
   * Finds the closest non-excluded peer location to the target.
   *
   * @param l target location
   * @param exclude set of locations to exclude; may be {@code null}
   * @return the best candidate location, or {@code Double.NaN} if none is found
   */
  public double getClosestPeerLocation(double l, Set<Double> exclude) {
    return location.getClosestPeerLocation(l, exclude);
  }

  /**
   * Returns the time the current location value was last set.
   *
   * @return epoch time in milliseconds
   */
  @SuppressWarnings("unused")
  public long getLocSetTime() {
    return location.getLocationSetTime();
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
   * <p>Does not imply anything about the current connection status.
   */
  public synchronized boolean isUnroutableOlderVersion() {
    return unroutableOlderVersion;
  }

  /**
   * Returns whether this peer is considered unroutable due to our build being reported as older.
   *
   * <p>Does not imply anything about the current connection status.
   */
  @SuppressWarnings("unused")
  public synchronized boolean isUnroutableNewerVersion() {
    return unroutableNewerVersion;
  }

  /**
   * Returns true if requests can be routed through this peer. True if the peer's location is known,
   * presently connected, and routing-compatible. That is, ignoring backoff, the peer's location is
   * known, build number is compatible, and routing has not been explicitly disabled.
   *
   * <p>Note possible deadlocks! PeerManager calls this, we call PeerManager in e.g. verified.
   */
  @Override
  public boolean isRoutable() {
    if ((!isConnected()) || (!isRoutingCompatible())) return false;
    return location.isValidLocation();
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
    return isConnected.isTrue();
  }

  /**
   * Send a message, off-thread, to this node.
   *
   * @param msg The message to be sent.
   * @param cb The callback to be called when the packet has been sent, or null.
   * @param ctr A callback to tell how many bytes were used to send this message.
   */
  @Override
  public MessageItem sendAsync(Message msg, AsyncMessageCallback cb, ByteCounter ctr)
      throws NotConnectedException {
    if (ctr == null)
      LOG.error(
          "ByteCounter null, so bandwidth usage cannot be logged. Refusing to send.",
          new Exception("debug"));
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Sending async: {} : {} on {}" + STR_FOR + "{} priority {}",
          msg,
          cb,
          this,
          node.getDarknetPortNumber(),
          msg.getPriority());
    if (!isConnected()) {
      if (cb != null) cb.disconnected();
      throw new NotConnectedException();
    }
    if (msg.getSource() != null) {
      LOG.error(
          "Messages should NOT be relayed as-is, they should always be re-created to clear any"
              + " sub-messages etc, see comments in Message.java!: {}",
          msg,
          new Exception(STR_ERROR));
    }
    addToLocalNodeSentMessagesToStatistic(msg);
    MessageItem item =
        new MessageItem(msg, cb == null ? null : new AsyncMessageCallback[] {cb}, ctr);
    long now = System.currentTimeMillis();
    reportBackoffStatus(now);
    int maxSize = getMaxPacketSize();
    int x = messageQueue.queueAndEstimateSize(item, maxSize);
    if (x > maxSize || !node.isEnablePacketCoalescing()) {
      // If there is a packet's worth to send, wake up the packetsender.
      wakeUpSender();
    }
    // Otherwise we do not need to wake up the PacketSender
    // It will wake up before the maximum coalescing delay (100ms) because
    // it wakes up every 100ms *anyway*.
    return item;
  }

  /** Wakes the packet sender to process queued messages immediately. */
  @Override
  public void wakeUpSender() {
    if (LOG.isDebugEnabled()) LOG.debug("Waking up PacketSender");
    node.getPacketSender().wakeUp();
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

  public long getMessageQueueLengthBytes() {
    return messageQueue.getMessageQueueLengthBytes();
  }

  /**
   * Returns the number of milliseconds that it is estimated to take to transmit the currently
   * queued packets.
   */
  public long getProbableSendQueueTime() {
    double bandwidth = (getThrottle().getBandwidth() + 1.0);
    if (shouldThrottle())
      bandwidth = Math.min(bandwidth, (double) node.getOutputBandwidthLimit() / 2);
    long length = getMessageQueueLengthBytes();
    return (long) (1000.0 * length / bandwidth);
  }

  /** Returns the last time any packet was received from this peer, in milliseconds. */
  public synchronized long lastReceivedPacketTime() {
    return timeLastReceivedPacket;
  }

  /** Returns the last time a non-authentication packet was received, in milliseconds. */
  public synchronized long lastReceivedDataPacketTime() {
    return timeLastReceivedDataPacket;
  }

  /** Returns the last time an acknowledgement was received, in milliseconds. */
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
    return isConnected.getTimeLastTrue(now);
  }

  /** Returns the last time this peer was considered routing-compatible, in milliseconds. */
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
      String time = TimeUtil.formatTime(FNPPacketMangler.MAX_SESSION_KEY_REKEYING_DELAY);
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
      ctx = null;
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
   * Disconnected e.g. due to not receiving a packet for ages.
   *
   * @param dumpMessageQueue If true, clear the messages-to-send queue, and change the bootID so
   *     even if we reconnect the other side will know that a disconnect happened. If false, don't
   *     clear the messages yet. They will be cleared after an hour if the peer is disconnected at
   *     that point.
   * @param dumpTrackers If true, dump the SessionKey's (i.e. dump the cryptographic data so we
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
    if (isRealConnection()) LOG.info("Disconnected {}", this);
    else if (LOG.isDebugEnabled()) LOG.debug("Disconnected {}", this);
    node.getUSM().onDisconnect(this);
    if (dumpMessageQueue) node.getTracker().onRestartOrDisconnect(this);
    node.getFailureTable().onDisconnect(this);
    node.getPeers().disconnected(this);
    node.getNodeUpdater().disconnected(this);
    DisconnectState st = performSynchronizedDisconnect(dumpMessageQueue, dumpTrackers, now);
    if (st.oldPacketFormat != null) {
      st.moreMessagesTellDisconnected = st.oldPacketFormat.onDisconnect();
    }
    dumpDisconnectedMessages(st.messagesTellDisconnected, st.moreMessagesTellDisconnected);
    if (st.cur != null) st.cur.disconnected();
    if (st.prev != null) st.prev.disconnected();
    if (st.unv != null) st.unv.disconnected();
    lastThrottle.maybeDisconnected();
    node.getLocationManager().lostOrRestartedNode(this);
    if (peers.havePeer(this)) setPeerNodeStatus(now);
    if (!dumpMessageQueue) queueDelayedDropMessages(now);
    // Tell opennet manager even if this is darknet, because we may need more opennet peers now.
    OpennetManager om = node.getOpennet();
    if (om != null) om.onDisconnect();
    outputLoadTrackerRealTime.failSlotWaiters();
    outputLoadTrackerBulk.failSlotWaiters();
    return st.ret;
  }

  private void dumpDisconnectedMessages(
      MessageItem[] messagesTellDisconnected, List<MessageItem> moreMessagesTellDisconnected) {
    if (messagesTellDisconnected != null) {
      if (LOG.isDebugEnabled())
        LOG.debug(STR_MESSAGES_TO_DUMP + "{}", messagesTellDisconnected.length);
      for (MessageItem mi : messagesTellDisconnected) mi.onDisconnect();
    }
    if (moreMessagesTellDisconnected != null) {
      if (LOG.isDebugEnabled())
        LOG.debug(STR_MESSAGES_TO_DUMP + "{}", moreMessagesTellDisconnected.size());
      for (MessageItem mi : moreMessagesTellDisconnected) mi.onDisconnect();
    }
  }

  private void queueDelayedDropMessages(final long now) {
    node.getTicker()
        .queueTimedJob(
            new Runnable() {
              @Override
              public void run() {
                if ((!PeerNode.this.isConnected()) && timeLastDisconnect == now) {
                  PacketFormat oldPacketFormatLocal;
                  synchronized (this) {
                    if (isConnected()) return;
                    myBootID = random.nextLong();
                    oldPacketFormatLocal = packetFormat;
                    packetFormat = null;
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
      st.ret = isConnected.set(false, now);
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
        st.oldPacketFormat = packetFormat;
        packetFormat = null;
      }
    }
    return st;
  }

  /** Forces an immediate disconnect from this peer, without waiting for graceful teardown. */
  @Override
  public void forceDisconnect() {
    LOG.warn("Forcing disconnect on {}", this);
    disconnected(true, true); // always dump trackers, maybe dump messages
  }

  /**
   * Returns and clears the current queue of pending messages to this peer.
   *
   * @return an array of messages that were pending; may be empty
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
      pf = packetFormat;
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

  /** Returns the last time a packet was sent to this peer, in milliseconds. */
  public long lastSentPacketTime() {
    return timeLastSentPacket;
  }

  /** Returns whether a handshake should be sent now based on scheduling and state. */
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
   * @param now The current time.
   */
  public boolean hasLiveHandshake(long now) {
    KeyAgreementSchemeContext c;
    synchronized (this) {
      c = ctx;
    }
    if (c != null && LOG.isDebugEnabled())
      LOG.debug("Last used (handshake): {}", now - c.lastUsedTime());
    return !((c == null) || (now - c.lastUsedTime() > Node.HANDSHAKE_TIMEOUT));
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
        // Let them know we're here, but have no hope of routing general data to them.
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
   * If the outgoingMangler allows bursting, we still don't want to burst *all the time*, because it
   * may be mistaken in its detection of a port forward. So from time to time we will aggressively
   * handshake anyway. This flag is set once every UPDATE_BURST_NOW_PERIOD.
   */
  private boolean burstNow;

  private long timeSetBurstNow;
  static final long UPDATE_BURST_NOW_PERIOD = MINUTES.toMillis(5);

  /**
   * Burst only 19 in 20 times if definitely port forwarded. Save entropy by writing this as 20 not
   * 0.95.
   */
  static final int P_BURST_IF_DEFINITELY_FORWARDED = 20;

  /**
   * Returns whether the connection should use burst‑only handshake behavior.
   *
   * <p>Primarily true when the local address appears port‑forwarded and periodic bursting is used
   * to reduce false positives.
   */
  public boolean isBurstOnly() {
    AddressTracker.Status status = outgoingMangler.getConnectivityStatus();
    if (status == AddressTracker.Status.DONT_KNOW) return false;
    if (status == AddressTracker.Status.DEFINITELY_NATED
        || status == AddressTracker.Status.MAYBE_NATED) return false;

    // Note: consider using a lower probability once packet-deltas
    // mechanisms are validated in production environments.
    if (status == AddressTracker.Status.MAYBE_PORT_FORWARDED) return false;
    long now = System.currentTimeMillis();
    if (now - timeSetBurstNow > UPDATE_BURST_NOW_PERIOD) {
      burstNow = (random.nextInt(P_BURST_IF_DEFINITELY_FORWARDED) == 0);
      timeSetBurstNow = now;
    }
    return burstNow;
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

  /** Returns the maximum allowed idle interval between received packets, in milliseconds. */
  public long maxTimeBetweenReceivedPackets() {
    return Node.MAX_PEER_INACTIVITY;
  }

  /**
   * Returns the maximum allowed idle interval between received acknowledgements, in milliseconds.
   */
  public long maxTimeBetweenReceivedAcks() {
    return Node.MAX_PEER_INACTIVITY;
  }

  /**
   * Sends a low-level ping and waits for a pong.
   *
   * @param pingID sequence identifier echoed by the pong
   * @return {@code true} if a reply arrives within 2,000 ms; {@code false} otherwise
   * @throws NotConnectedException if the connection drops while waiting
   */
  public boolean ping(int pingID) throws NotConnectedException {
    Message ping = DMT.createFNPPing(pingID);
    node.getUSM().send(this, ping, node.getDispatcher().pingCounter);
    Message msg;
    try {
      msg =
          node.getUSM()
              .waitFor(
                  MessageFilter.create()
                      .setTimeout(2000)
                      .setType(DMT.FNPPong)
                      .setField(DMT.PING_SEQNO, pingID),
                  null);
    } catch (DisconnectedException _) {
      throw new NotConnectedException("Disconnected while waiting for pong");
    }
    return msg != null;
  }

  /**
   * Decrement the HTL (or not), in accordance with our probabilistic HTL rules. Whether to
   * decrement is determined once for each connection, rather than for every request, because if we
   * don't we would get a predictable fraction of requests with each HTL - this pattern could give
   * away a lot of information close to the originator. Although it's debatable whether it's worth
   * worrying about given all the other information they have if close by ...
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
   * Enqueues a message and blocks until it is transmitted and acknowledged, or times out.
   *
   * @param req message to send
   * @param ctr bandwidth accounting callback
   * @param realTime whether to treat the send as real-time
   * @throws NotConnectedException if the peer disconnects before the send completes
   * @throws SyncSendWaitedTooLongException if the acknowledgement does not arrive in time
   */
  public void sendSync(Message req, ByteCounter ctr, boolean realTime)
      throws NotConnectedException, SyncSendWaitedTooLongException {
    SyncMessageCallback cb = new SyncMessageCallback();
    MessageItem item = sendAsync(req, cb, ctr);
    cb.waitForSend(MINUTES.toMillis(1));
    if (!cb.done) {
      LOG.warn(
          "Waited too long for a blocking send for {} to {}",
          req,
          PeerNode.this,
          new Exception(STR_ERROR));
      this.localRejectedOverload("SendSyncTimeout", realTime);
      // Try to unqueue it, since it presumably won't be of any use now.
      if (!messageQueue.removeMessage(item)) {
        cb.waitForSend(SECONDS.toMillis(10));
        if (!cb.done) {
          LOG.error(
              "Waited too long for blocking send and then could not unqueue for {} to {}",
              req,
              PeerNode.this,
              new Exception(STR_ERROR));
          // Can't cancel yet can't send, something seriously wrong.
          // Treat as fatal timeout as probably their fault.
          // Note: We have already waited more than the no-messages timeout; do not wait again.
          fatalTimeout();
          // Then throw the error.
        } else {
          return;
        }
      }
      throw new SyncSendWaitedTooLongException();
    }
  }

  private class SyncMessageCallback implements AsyncMessageCallback {

    private boolean done = false;
    private boolean disconnected = false;
    private boolean sent = false;

    public synchronized void waitForSend(long maxWaitInterval) throws NotConnectedException {
      long now = System.currentTimeMillis();
      long end = now + maxWaitInterval;
      while ((now = System.currentTimeMillis()) < end) {
        if (done) {
          if (disconnected) throw new NotConnectedException();
          return;
        }
        int waitTime = (int) (Math.min(end - now, Integer.MAX_VALUE));
        try {
          wait(waitTime);
        } catch (InterruptedException _) {
          // Re-interrupt current thread and stop waiting
          Thread.currentThread().interrupt();
          return;
        }
      }
    }

    @Override
    public void acknowledged() {
      synchronized (this) {
        if (!done) {
          if (!sent) {
            // Can happen due to lag.
            LOG.info(
                "Acknowledged but not sent?! on {}" + STR_FOR + "{} - lag ???",
                this,
                PeerNode.this);
          }
        } else return;
        done = true;
        notifyAll();
      }
    }

    @Override
    public void disconnected() {
      synchronized (this) {
        done = true;
        disconnected = true;
        notifyAll();
      }
    }

    @Override
    public void fatalError() {
      synchronized (this) {
        done = true;
        notifyAll();
      }
    }

    @Override
    public void sent() {
      // It might have been lost, we wait until it is acked.
      synchronized (this) {
        sent = true;
      }
    }
  }

  /**
   * Determines the degree of the peer via the locations of its peers it provides.
   *
   * @return The number of peers this peer reports having, or 0 if this peer does not provide that
   *     information.
   */
  public int getDegree() {
    return location.getDegree();
  }

  /**
   * Updates the peer's current location and the set of its peers' locations.
   *
   * @param newLoc this peer's reported location
   * @param newLocs array of locations reported for this peer's neighbors; may be {@code null}
   */
  public void updateLocation(double newLoc, double[] newLocs) {
    boolean anythingChanged = location.updateLocation(newLoc, newLocs);
    node.getPeers().updatePMUserAlert();
    if (anythingChanged) writePeers();
    setPeerNodeStatus(System.currentTimeMillis());
  }

  /**
   * Persists or updates the peers list to reflect changes made by this node.
   *
   * <p>Implementations should write any modified peer state to durable storage or notify the
   * appropriate manager so that changes survive process restarts and UI state remains consistent.
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
        swapRequestsInterval.report(timeSinceLastTime);
        double averageInterval = swapRequestsInterval.currentValue();
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
        probeRequestsInterval.report(timeSinceLastTime);
        double averageInterval = probeRequestsInterval.currentValue();
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
        this.lastAttemptedHandshakeIPUpdateTime = 0;
        if (!isConnected()) return;
      } else return;
    }
    getThrottle().maybeDisconnected();
    sendIPAddressMessage();
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
        super.toString() + '@' + detectedPeer + '@' + HexUtil.bytesToHex(peerECDSAPubKeyHash);
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
        // is conceivable, but unlikely...
        if ((unverifiedTracker == null) && (currentTracker == null) && !disconnecting)
          LOG.warn("Received packet while disconnected!: {}", this);
        else if (LOG.isDebugEnabled())
          LOG.debug("Received packet while disconnected on {} - recently disconnected() ?", this);
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

  /** Returns the current key agreement context used during handshake, or {@code null}. */
  public synchronized KeyAgreementSchemeContext getKeyAgreementSchemeContext() {
    return ctx;
  }

  /**
   * Sets the key agreement context for an in-flight handshake.
   *
   * @param ctx2 key agreement context to use
   */
  public synchronized void setKeyAgreementSchemeContext(KeyAgreementSchemeContext ctx2) {
    this.ctx = ctx2;
    if (LOG.isDebugEnabled())
      LOG.debug("setKeyAgreementSchemeContext({}" + STR_ON + "{}", ctx2, this);
  }

  /**
   * Called when we have completed a handshake, and have a new session key. Creates a new tracker
   * and demotes the old one. Deletes the old one if the bootID isn't recognized, since if the node
   * has restarted we cannot recover old messages. In more detail:
   *
   * <ul>
   *   <li>Process the new noderef (check if it's valid, pick up any new information etc.).
   *   <li>Handle version conflicts (if the node is too old, or we are too old, we mark it as
   *       non-routable, but some messages will still be exchanged e.g. Update Over Mandatory
   *       stuff).
   *   <li>Deal with key trackers (if we just got message 4, the new key tracker becomes current; if
   *       we just got message 3, it's possible that our message 4 will be lost in transit, so we
   *       make the new tracker unverified. It will be promoted to current if we get a packet on it.
   *       if the node has restarted, we dump the old key trackers, otherwise current becomes
   *       previous).
   *   <li>Complete the connection process: update the node's status, send initial messages, update
   *       the last-received-packet timestamp, etc.
   *
   * @param thisBootID The boot ID of the peer we have just connected to. This is simply a random
   *     number regenerated on every startup of the node. We use it to determine whether the node
   *     has restarted since we last saw it.
   * @param data Byte array from which to read the new noderef.
   * @param offset Offset to start reading at.
   * @param length Number of bytes to read.
   * @param outgoingCipher Cipher for outbound packets on the new session.
   * @param outgoingKey Key material for {@code outgoingCipher}.
   * @param incommingCipher Cipher for inbound packets on the new session.
   * @param incommingKey Key material for {@code incommingCipher}.
   * @param replyTo The IP the handshake came in on.
   * @param trackerID The tracker ID proposed by the other side. If -1, create a new tracker. If any
   *     other value, check whether we have it, and if we do, return that, otherwise return the ID
   *     of the new tracker.
   * @param unverified whether the new session should begin in an unverified state
   * @param negType negotiated link setup type
   * @param isJFK4 If true, we are processing a JFK(4) and must respect the tracker ID chosen by the
   *     responder. If false, we are processing a JFK(3) and we can either reuse the suggested
   *     tracker ID, which the other side is able to reuse, or we can create a new tracker ID.
   * @param jfk4SameAsOld If true, the responder chose to use the tracker ID that we provided. If we
   *     don't have it now the connection fails.
   * @param hmacKey HMAC key for authenticated messages on the new session.
   * @param ivCipher Cipher used to derive IVs/nonce material for the session.
   * @param ivNonce Nonce material for the session IV derivation.
   * @param ourInitialSeqNum Initial outbound packet sequence number.
   * @param theirInitialSeqNum Initial inbound packet sequence number.
   * @param ourInitialMsgID Initial outbound message ID.
   * @param theirInitialMsgID Initial inbound message ID.
   * @return The ID of the new PacketTracker. If this is different to the passed-in trackerID, then
   *     it's a new tracker. -1 to indicate failure.
   */
  public long completedHandshake(
      long thisBootID,
      byte[] data,
      int offset,
      int length,
      BlockCipher outgoingCipher,
      byte[] outgoingKey,
      BlockCipher incommingCipher,
      byte[] incommingKey,
      Peer replyTo,
      boolean unverified,
      int negType,
      long trackerID,
      boolean isJFK4,
      boolean jfk4SameAsOld,
      byte[] hmacKey,
      BlockCipher ivCipher,
      byte[] ivNonce,
      int ourInitialSeqNum,
      int theirInitialSeqNum,
      int ourInitialMsgID,
      int theirInitialMsgID) {
    long now = System.currentTimeMillis();
    // If trackerID is negative, pick a random positive ID; then keep using trackerID.
    // Avoid Math.abs(Long.MIN_VALUE) overflow; mask sign bit instead.
    trackerID = trackerID < 0 ? (random.nextLong() & Long.MAX_VALUE) : trackerID;
    if (LOG.isDebugEnabled())
      LOG.debug("Tracker ID {} isJFK4={} jfk4SameAsOld={}", trackerID, isJFK4, jfk4SameAsOld);

    // Update sendHandshakeTime; don't send another handshake for a while.
    // If unverified, "a while" determines the timeout; if not, it's just good practice to avoid a
    // race below.
    if (!(isSeed() && this instanceof SeedServerPeerNode)) calcNextHandshake(true, true, false);
    stopARKFetcher();
    try {
      // First, the new noderef
      processNewNoderef(data, offset, length);
    } catch (FSParseException e1) {
      synchronized (this) {
        bogusNoderef = true;
        // Disconnect, something broke
        isConnected.set(false, now);
      }
      LOG.error("Failed to parse new noderef for {}: {}", this, e1, e1);
      node.getPeers().disconnected(this);
      return -1;
    }
    RoutabilityDecision rd = decideRoutability();
    changedIP(replyTo);
    HandshakeParams hp = new HandshakeParams();
    hp.thisBootID = thisBootID;
    hp.rd = rd;
    hp.outgoingCipher = outgoingCipher;
    hp.outgoingKey = outgoingKey;
    hp.incommingCipher = incommingCipher;
    hp.incommingKey = incommingKey;
    hp.ivCipher = ivCipher;
    hp.ivNonce = ivNonce;
    hp.hmacKey = hmacKey;
    hp.unverified = unverified;
    hp.trackerID = trackerID;
    hp.ourInitialSeqNum = ourInitialSeqNum;
    hp.theirInitialSeqNum = theirInitialSeqNum;
    hp.ourInitialMsgID = ourInitialMsgID;
    hp.theirInitialMsgID = theirInitialMsgID;
    hp.negType = negType;
    hp.now = now;
    HandshakeApplyResult har = applyHandshakeState(hp);
    if (har == null) return -1;
    finalizeHandshake(har, rd, replyTo, thisBootID, now);

    return trackerID;
  }

  private void finalizeHandshake(
      HandshakeApplyResult har, RoutabilityDecision rd, Peer replyTo, long thisBootID, long now) {
    applyDisconnectSideEffects(har);
    logAndUpdateThrottle(replyTo, thisBootID);
    setPeerNodeStatus(now);
    if (rd.newer || rd.older || !isConnected()) node.getPeers().disconnected(this);
    else if (!har.wasARekey) {
      node.getPeers().addConnectedPeer(this);
      maybeOnConnect();
    }
    crypto.maybeBootConnection(this, replyTo.getFreenetAddress());
  }

  private void applyDisconnectSideEffects(HandshakeApplyResult har) {
    if (har.messagesTellDisconnected != null) {
      for (MessageItem item : har.messagesTellDisconnected) item.onDisconnect();
    }
    if (har.bootIDChanged) {
      node.getLocationManager().lostOrRestartedNode(this);
      node.getUSM().onRestart(this);
      node.getTracker().onRestartOrDisconnect(this);
    }
    if (har.oldPrev != null) har.oldPrev.disconnected();
    if (har.oldCur != null) har.oldCur.disconnected();
    if (har.oldPacketFormat != null) {
      List<MessageItem> tellDisconnect = har.oldPacketFormat.onDisconnect();
      if (tellDisconnect != null) for (MessageItem item : tellDisconnect) item.onDisconnect();
    }
  }

  private void logAndUpdateThrottle(Peer replyTo, long thisBootID) {
    PacketThrottle throttle;
    synchronized (this) {
      throttle = lastThrottle;
    }
    throttle.maybeDisconnected();
    LOG.info(
        "Completed handshake with {} on {} - current: {} old: {} unverified: {} bootID: {}"
            + STR_FOR
            + "{}",
        this,
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
      if (LOG.isDebugEnabled()) LOG.debug(STR_NOT_ROUTING_TO + "{} it's for announcement.", this);
    } else if (bogusNoderef) {
      LOG.info(STR_NOT_ROUTING_TO + "{} - bogus noderef", this);
      routable = false;
    } else if (reverseInvalidVersion()) {
      LOG.info(
          STR_NOT_ROUTING_TO + "{} - reverse invalid version {} for peer's lastGoodversion: {}",
          this,
          Version.getVersionString(),
          getLastGoodVersion());
      newer = true;
    }
    if (forwardInvalidVersion()) {
      LOG.info(STR_NOT_ROUTING_TO + "{} - invalid version {}", this, getVersion());
      older = true;
      routable = false;
    } else if (Math.abs(clockDelta) > MAX_CLOCK_DELTA) {
      LOG.info(STR_NOT_ROUTING_TO + "{} - clock problems", this);
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
    synchronized (this) {
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
      LOG.error("completedHandshake() with identical key to current, maybe replayed JFK(4)?");
      return true;
    }
    if (previousTracker != null
        && Arrays.equals(p.outgoingKey, previousTracker.outgoingKey)
        && Arrays.equals(p.incommingKey, previousTracker.incommingKey)) {
      LOG.error("completedHandshake() with identical key to previous, maybe replayed JFK(4)?");
      return true;
    }
    if (unverifiedTracker != null
        && Arrays.equals(p.outgoingKey, unverifiedTracker.outgoingKey)
        && Arrays.equals(p.incommingKey, unverifiedTracker.incommingKey)) {
      LOG.error("completedHandshake() with identical key to unverified, maybe replayed JFK(4)?");
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
    long oldBootID = bootID.getAndSet(p.thisBootID);
    r.bootIDChanged = oldBootID != p.thisBootID;
    if (myLastSuccessfulBootID != this.myBootID) {
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
      this.offeredMainJarVersion = 0;
      r.oldPacketFormat = packetFormat;
      packetFormat = null;
    }
  }

  private SessionKey buildSessionKey(HandshakeParams p) {
    return new SessionKey(
        this,
        p.outgoingCipher,
        p.outgoingKey,
        p.incommingCipher,
        p.incommingKey,
        p.ivCipher,
        p.ivNonce,
        p.hmacKey,
        new NewPacketFormatKeyContext(p.ourInitialSeqNum, p.theirInitialSeqNum),
        p.trackerID);
  }

  private void assignTrackersAndTimes(
      HandshakeParams p, HandshakeApplyResult r, SessionKey newTracker) {
    if (p.unverified) {
      if (unverifiedTracker != null && previousTracker == null) previousTracker = unverifiedTracker;
      unverifiedTracker = newTracker;
    } else {
      r.oldPrev = previousTracker;
      previousTracker = currentTracker;
      currentTracker = newTracker;
      neverConnected = false;
      maybeClearPeerAddedTimeOnConnect();
    }
    isConnected.set(currentTracker != null, p.now);
    ctx = null;
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
    if (packetFormat == null) {
      packetFormat = new NewPacketFormat(this, p.ourInitialMsgID, p.theirInitialMsgID);
    }
    timeLastReceivedPacket = p.now;
    timeLastReceivedDataPacket = p.now;
    timeLastReceivedAck = p.now;
  }

  protected abstract void maybeClearPeerAddedTimeOnConnect();

  @Override
  public long getBootID() {
    return bootID.get();
  }

  private final Object arkFetcherSync = new Object();

  void startARKFetcher() {
    // Note: keep locking minimal; avoid holding locks across callbacks
    if (!node.isEnableARKs()) return;
    synchronized (arkFetcherSync) {
      if (myARK == null) {
        LOG.debug("No ARK for {} !!!!", this);
        return;
      }
      if (arkFetcher == null) {
        LOG.debug("Starting ARK fetcher for {} : {}", this, myARK);
        arkFetcher =
            node.getClientCore()
                .getUskManager()
                .subscribeContent(
                    myARK,
                    this,
                    true,
                    node.getArkFetcherContext(),
                    RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS,
                    node.getNonPersistentClientRT());
      }
    }
  }

  protected void stopARKFetcher() {
    if (!node.isEnableARKs()) return;
    LOG.debug("Stopping ARK fetcher for {} : {}", this, myARK);
    // Note: keep locking minimal; avoid holding locks across callbacks
    USKRetriever ret;
    synchronized (arkFetcherSync) {
      if (arkFetcher == null) {
        if (LOG.isDebugEnabled()) LOG.debug("ARK fetcher not running for {}", this);
        return;
      }
      ret = arkFetcher;
      arkFetcher = null;
    }
    final USKRetriever unsub = ret;
    node.getExecutor()
        .execute(() -> node.getClientCore().getUskManager().unsubscribeContent(myARK, unsub, true));
  }

  // Both at IMMEDIATE_SPLITFILE_PRIORITY_CLASS because we want to compete with FMS, not
  // wipe it out!

  @Override
  public short getPollingPriorityNormal() {
    return RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS;
  }

  @Override
  public short getPollingPriorityProgress() {
    return RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS;
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
   * <p>Currently includes location, detected IP address, and time synchronization messages.
   * Implementations may extend this to include protocol-specific announcements.
   */
  protected void sendInitialMessages() {
    Message locMsg =
        DMT.createFNPLocChangeNotificationNew(
            node.getLocationManager().getLocation(), node.getPeers().getPeerLocationDoubles(true));
    Message ipMsg = DMT.createFNPDetectedIPAddress(getPeer());
    Message timeMsg = DMT.createFNPTime(System.currentTimeMillis());
    Message dRoutingMsg = DMT.createRoutingStatus(!disableRoutingHasBeenSetLocally);
    Message uptimeMsg =
        DMT.createFNPUptime((byte) (int) (100 * node.getUptimeEstimator().getUptime()));

    try {
      if (isRealConnection()) sendAsync(locMsg, null, node.getNodeStats().initialMessagesCtr);
      sendAsync(ipMsg, null, node.getNodeStats().initialMessagesCtr);
      sendAsync(timeMsg, null, node.getNodeStats().initialMessagesCtr);
      sendAsync(dRoutingMsg, null, node.getNodeStats().initialMessagesCtr);
      sendAsync(uptimeMsg, null, node.getNodeStats().initialMessagesCtr);
    } catch (NotConnectedException e) {
      LOG.error(
          "Completed handshake with {} but disconnected ({}:{}!!!: {}",
          getPeer(),
          isConnected,
          currentTracker,
          e,
          e);
    }

    sendConnectedDiffNoderef();
  }

  private void sendIPAddressMessage() {
    Message ipMsg = DMT.createFNPDetectedIPAddress(getPeer());
    try {
      sendAsync(ipMsg, null, node.getNodeStats().changedIPCtr);
    } catch (NotConnectedException e) {
      LOG.info("Sending IP change message to {} but disconnected: {}", this, e, e);
    }
  }

  /**
   * Marks the given session key as verified and promotes it to active routing state as needed.
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
        isConnected.set(true, now);
        neverConnected = false;
        maybeClearPeerAddedTimeOnConnect();
        ctx = null;
      } else return;
    }
    maybeSendInitialMessages();
    setPeerNodeStatus(now);
    node.getPeers().addConnectedPeer(this);
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

  @SuppressWarnings("unused")
  public synchronized boolean dontRoute() {
    return disableRouting;
  }

  /** Process a differential node reference The identity must not change, or we throw. */
  public void processDiffNoderef(SimpleFieldSet fs) throws FSParseException {
    processNewNoderef(fs, false, true, false);
    // Send UOMAnnouncement only *after* we know what the other side's version.
    if (isRealConnection()) node.getNodeUpdater().maybeSendUOMAnnounce(this);
  }

  /** Process a new nodereference, in compressed form. The identity must not change, or we throw. */
  private void processNewNoderef(byte[] data, int offset, int length) throws FSParseException {
    SimpleFieldSet fs = compressedNoderefToFieldSet(data, offset, length);
    processNewNoderef(fs, false, false, false);
  }

  static SimpleFieldSet compressedNoderefToFieldSet(byte[] data, int offset, int length)
      throws FSParseException {
    if (length <= 5) throw new FSParseException("Too short");
    int firstByte = data[offset];
    offset++;
    length--;
    if ((firstByte & 0x2) == 2) { // DSAcompressed group; legacy
      offset++;
      length--;
    }
    // Is it compressed?
    if ((firstByte & 1) == 1) {
      try (InflaterHolder ih = new InflaterHolder()) {
        Inflater i = ih.inflater;
        i.setInput(data, offset, length);
        // We shouldn't ever need 4096 bytes long ref!
        byte[] output = new byte[4096];
        length = i.inflate(output, 0, output.length);
        // Finished
        data = output;
        offset = 0;
        if (LOG.isDebugEnabled())
          LOG.debug("We have decompressed a {} bytes big reference.", length);
      } catch (DataFormatException _) {
        throw new FSParseException("Invalid compressed data");
      }
    }
    if (LOG.isDebugEnabled())
      LOG.debug("Reference: {}({})", HexUtil.bytesToHex(data, offset, length), length);

    // Now decode it
    ByteArrayInputStream bais = new ByteArrayInputStream(data, offset, length);
    InputStreamReader isr = new InputStreamReader(bais, StandardCharsets.UTF_8);
    BufferedReader br = new BufferedReader(isr);
    try {
      return new SimpleFieldSet(br, false, true);
    } catch (IOException e) {
      throw new FSParseException("Impossible: " + e, e);
    }
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
  protected void processNewNoderef(
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
  protected synchronized boolean innerProcessNewNoderef(
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
      node.getExecutor().execute(() -> node.getPeers().updatePMUserAlert());
    }
    return changedAnything;
  }

  private void verifyFullRefSignature(SimpleFieldSet fs, boolean forFullNodeRef)
      throws FSParseException {
    if (!forFullNodeRef) return;
    try {
      // verifyReferenceSignature() returns true on success, or throws on failure; no need to test.
      verifyReferenceSignature(fs);
    } catch (ReferenceSignatureVerificationException _) {
      throw new FSParseException("Invalid signature");
    }
  }

  private void checkTestnetAndOpennet(
      SimpleFieldSet fs, boolean forDiffNodeRef, boolean forFullNodeRef) throws FSParseException {
    if (!forDiffNodeRef && (fs.getBoolean(SFS_KEY_TESTNET, false))) {
      String err = "Preventing connection to node " + getPeer() + " - testnet is enabled!";
      LOG.error(err);
      throw new FSParseException(err);
    }
    String s = fs.get(SFS_KEY_OPENNET);
    if (s == null && forFullNodeRef) throw new FSParseException("No opennet ref");
    else if (s != null) {
      try {
        boolean b = Fields.stringToBool(s);
        if (b != isOpennetForNoderef())
          throw new FSParseException(
              "Changed opennet status?!?!?!? expected="
                  + isOpennetForNoderef()
                  + " but got "
                  + b
                  + " ("
                  + s
                  + STR_ON
                  + this);
      } catch (NumberFormatException e) {
        throw new FSParseException("Cannot parse opennet=\"" + s + "\"", e);
      }
    }
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
    String identityString = fs.get(SFS_KEY_IDENTITY);
    if (identityString != null) {
      try {
        byte[] id = Base64.decode(identityString);
        if (!Arrays.equals(id, identity)) throw new FSParseException("Changing the identity");
      } catch (NumberFormatException | IllegalBase64Exception e) {
        throw new FSParseException(e);
      }
      return;
    }
    // Missing identity is allowed for differential or partial noderefs (e.g., during handshake).
    // Only full noderefs must include identity.
    if (forFullNodeRef && !forDiffNodeRef) {
      if (isDarknet()) throw new FSParseException("No identity!");
      else if (LOG.isDebugEnabled())
        LOG.debug("didn't send an identity; let's assume it's pre-1471");
    }
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
        double oldLoc = location.setLocation(newLoc);
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
      // Differential noderefs only include it on the first one after connect.
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
      lastAttemptedHandshakeIPUpdateTime = 0;
      // Clear nonces to prevent leak. Will kill any in-progress connect attempts, but that is
      // okay because either we got an ARK which changed our peers list, or we just connected.
      jfkNoncesSent.clear();
      return true;
    }
    return false;
  }

  private Peer tryParsePeer(String phys) {
    try {
      return new Peer(phys, true, true);
    } catch (UnknownHostException _) {
      // Host appears syntactically valid but cannot be resolved here (e.g., link‑local scope name
      // not present on this host). Lower severity to INFO to avoid noisy logs.
      LOG.info(
          STR_INVALID_HOST_OR_IP_WHILE_PARSING
              + "{} (unresolvable here; likely host-local scope or transient DNS)",
          phys);
      return null;
    } catch (HostnameSyntaxException | PeerParseException _) {
      // True syntax issues: keep ERROR to surface malformed noderefs.
      LOG.error(STR_INVALID_HOST_OR_IP_WHILE_PARSING + "{}", phys);
      return null;
    }
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
    /* Read the ECDSA key material for the peer */
    SimpleFieldSet sfs = fs.subset("ecdsa.P256");
    if (sfs != null) {
      byte[] pub;
      try {
        pub = Base64.decode(sfs.get("pub"));
      } catch (IllegalBase64Exception e) {
        throw new FSParseException("Invalid base64 in ecdsa.P256.pub", e);
      }
      if (pub.length > ECDSA.Curves.P256.modulusSize)
        throw new FSParseException("ecdsa.P256.pub is not the right size!");
      ECPublicKey key = ECDSA.getPublicKey(pub, ECDSA.Curves.P256);
      if (key == null) throw new FSParseException("ecdsa.P256.pub is invalid!");
      if (!key.equals(peerECDSAPubKey)) {
        LOG.atError()
            .addArgument(this::userToString)
            .log("Tried to change ECDSA key on {} - did neighbour try to downgrade? Rejecting...");
        throw new FSParseException("Changing ECDSA key not allowed!");
      }
    }
  }

  /**
   * Get a PeerNodeStatus for this node.
   *
   * @param noHeavy If true, avoid any expensive operations e.g. the message count hashtables.
   */
  public abstract PeerNodeStatus getStatus(boolean noHeavy);

  /**
   * Returns a tab-separated diagnostic string for the TMCI interface.
   *
   * <p>Includes peer address, identity, location, status, and idle time (seconds).
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

  /** Returns the peer's reported software version string; may be {@code null}. */
  public synchronized String getVersion() {
    return version;
  }

  private synchronized String getLastGoodVersion() {
    return lastGoodVersion;
  }

  private int simpleVersion;

  /** Returns a simplified numeric version for fast comparisons. */
  public int getSimpleVersion() {
    return simpleVersion;
  }

  /**
   * Writes this peer's noderef (and metadata) to a {@link Writer}.
   *
   * @param w destination writer; not closed by this method
   * @throws IOException if writing the field set fails
   */
  public void write(Writer w) throws IOException {
    SimpleFieldSet fs = exportFieldSet();
    SimpleFieldSet meta = exportMetadataFieldSet(System.currentTimeMillis());
    if (!meta.isEmpty()) fs.put(SFS_KEY_METADATA, meta);
    fs.writeTo(w);
  }

  /**
   * Exports the noderef and metadata in a single {@link SimpleFieldSet} for persistence.
   *
   * <p>Includes the main noderef fields plus a {@code metadata} subset and, when present, the
   * optional {@code full} subset.
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
    long timeLastConnected = isConnected.getTimeLastTrue(now);
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

  // Opennet peers don't persist or export the peer added time.
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
      fs.put("routingBackoffPercent", backedOffPercent.currentValue() * 100);
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
    fs.put("ecdsa", ECDSA.Curves.P256.getSFS(peerECDSAPubKey));

    if (myARK != null) {
      // Decrement it because we keep the number we would like to fetch, not the last one fetched.
      fs.put(SFS_KEY_ARK_NUMBER, myARK.suggestedEdition - 1);
      fs.putSingle(SFS_KEY_ARK_PUBURI, myARK.getBaseSSK().toString(false, false));
    }
    fs.put(SFS_KEY_OPENNET, isOpennetForNoderef());
    fs.put("seed", isSeed());
    fs.put("totalInput", getTotalInputBytes());
    fs.put("totalOutput", getTotalOutputBytes());
    return fs;
  }

  /**
   * @return True if the node is a full darknet peer ("Friend"), which should usually be in the
   *     darknet routing table.
   */
  public abstract boolean isDarknet();

  /**
   * @return True if the node is a full opennet peer ("Stranger"), which should usually be in the
   *     OpennetManager and opennet routing table.
   */
  public abstract boolean isOpennet();

  /**
   * @return Expected value of "opennet=" in the noderef. This returns true if the node is an actual
   *     opennet peer, but also if the node is a seed client or seed server, even though they are
   *     never part of the routing table. This also determines whether we use the opennet or darknet
   *     NodeCrypto.
   */
  public abstract boolean isOpennetForNoderef();

  /**
   * @return True if the node is a seed client or seed server. These are never in the routing table,
   *     but their noderefs should still say opennet=true.
   */
  public abstract boolean isSeed();

  /**
   * @return The time at which we last connected (or reconnected).
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
  /* percent of time this peer is backed off */
  private final RunningAverage backedOffPercent;
  private final RunningAverage backedOffPercentRT;
  private final RunningAverage backedOffPercentBulk;
  /* time of last sample */
  private long lastSampleTime = Long.MAX_VALUE;

  // Separate, mandatory backoff mechanism for when nodes are consistently sending unexpected soft
  // rejects.
  // E.g. when load management predicts GUARANTEED, and yet we are rejected.
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
      node.getNodeStats().reportMandatoryBackoff(reason, mandatoryBackoffUntil - now, realTime);
      if (realTime) {
        mandatoryBackoffLengthRT = mandatoryBackoffLength;
        mandatoryBackoffUntilRT = mandatoryBackoffUntil;
      } else {
        mandatoryBackoffLengthBulk = mandatoryBackoffLength;
        mandatoryBackoffUntilBulk = mandatoryBackoffUntil;
      }
      setLastBackoffReason(reason, realTime);
    }
    if (realTime) outputLoadTrackerRealTime.failSlotWaiters();
    else outputLoadTrackerBulk.failSlotWaiters();
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
  private void reportBackoffStatus(long now) {
    synchronized (this) {
      if (now > lastSampleTime) { // don't report twice in the same millisecond
        double rt = computeAndReportBackoff(now, routingBackedOffUntilRT, backedOffPercentRT);
        double bulk = computeAndReportBackoff(now, routingBackedOffUntilBulk, backedOffPercentBulk);
        backedOffPercent.report(Math.min(rt, bulk));
      }
      lastSampleTime = now;
    }
  }

  private double computeAndReportBackoff(long now, long backedOffUntil, RunningAverage avg) {
    if (now > backedOffUntil) { // not backed off
      if (lastSampleTime > backedOffUntil) { // last sample after last backoff
        avg.report(0.0);
        return 0.0;
      } else if (backedOffUntil > 0) {
        double fraction =
            (double) (backedOffUntil - lastSampleTime) / (double) (now - lastSampleTime);
        avg.report(fraction);
        return fraction;
      } else {
        return 0.0;
      }
    } else {
      avg.report(1.0);
      return 1.0;
    }
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
    pRejected.report(1.0);
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Local rejected overload ({}" + STR_ON + "{}" + STR_P_REJECTED + "{}",
          reason,
          this,
          pRejected.currentValue());
    long now = System.currentTimeMillis();
    Peer peer = getPeer();
    reportBackoffStatus(now);
    if (!applyRoutingBackoff(reason, realTime, now, peer)) return;
    setLastBackoffReason(reason, realTime);
    setPeerNodeStatus(now);
    if (realTime) outputLoadTrackerRealTime.failSlotWaiters();
    else outputLoadTrackerBulk.failSlotWaiters();
  }

  /**
   * Clears routing backoff when a request succeeds without overload.
   *
   * @param realTime whether the success applies to real-time or bulk routing state
   */
  public void successNotOverload(boolean realTime) {
    pRejected.report(0.0);
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Success not overload on {}" + STR_P_REJECTED + "{}", this, pRejected.currentValue());
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
      node.getNodeStats().reportRoutingBackoff(reason, x, realTime);
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
    pRejected.report(1.0);
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Transfer failed ({}" + STR_ON + "{}" + STR_P_REJECTED + "{}",
          reason,
          this,
          pRejected.currentValue());
    long now = System.currentTimeMillis();
    Peer peer = getPeer();
    reportBackoffStatus(now);
    if (!applyTransferBackoff(reason, realTime, now, peer)) return;
    setLastBackoffReason(reason, realTime);
    if (realTime) outputLoadTrackerRealTime.failSlotWaiters();
    else outputLoadTrackerBulk.failSlotWaiters();
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
      node.getNodeStats().reportTransferBackoff(reason, x, realTime);
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
   * Handles a successful transfer by resetting transfer backoff if it has expired.
   *
   * @param realTime whether the success applies to real-time or bulk transfer state
   */
  public void transferSuccess(boolean realTime) {
    pRejected.report(0.0);
    if (LOG.isDebugEnabled())
      LOG.debug("Transfer success on {}" + STR_P_REJECTED + "{}", this, pRejected.currentValue());
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
  private final RunningAverage pingAverage;

  /**
   * @return The probability of a request sent to this peer being rejected (locally) due to
   *     overload, or timing out after being accepted.
   */
  public double getPRejected() {
    return pRejected.currentValue();
  }

  @Override
  public double averagePingTime() {
    return pingAverage.currentValue();
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

  public void setRemoteDetectedPeer(Peer p) {
    this.remoteDetectedPeer = p;
  }

  public Peer getRemoteDetectedPeer() {
    return remoteDetectedPeer;
  }

  public synchronized long getRoutingBackoffLength(boolean realTime) {
    return realTime ? routingBackoffLengthRT : routingBackoffLengthBulk;
  }

  public synchronized long getRoutingBackedOffUntil(boolean realTime) {
    return Math.max(
        realTime ? mandatoryBackoffUntilRT : mandatoryBackoffUntilBulk,
        Math.max(
            realTime ? routingBackedOffUntilRT : routingBackedOffUntilBulk,
            realTime ? transferBackedOffUntilRT : transferBackedOffUntilBulk));
  }

  public synchronized long getRoutingBackedOffUntilMax() {
    return Math.max(
        Math.max(mandatoryBackoffUntilRT, mandatoryBackoffUntilBulk),
        Math.max(
            Math.max(routingBackedOffUntilRT, routingBackedOffUntilBulk),
            Math.max(transferBackedOffUntilRT, transferBackedOffUntilBulk)));
  }

  public synchronized long getRoutingBackedOffUntilRT() {
    return Math.max(routingBackedOffUntilRT, transferBackedOffUntilRT);
  }

  public synchronized long getRoutingBackedOffUntilBulk() {
    return Math.max(routingBackedOffUntilBulk, transferBackedOffUntilBulk);
  }

  public synchronized String getLastBackoffReason(boolean realTime) {
    return realTime ? lastRoutingBackoffReasonRT : lastRoutingBackoffReasonBulk;
  }

  public synchronized String getPreviousBackoffReason(boolean realTime) {
    return realTime ? previousRoutingBackoffReasonRT : previousRoutingBackoffReasonBulk;
  }

  public synchronized void setLastBackoffReason(String s, boolean realTime) {
    if (realTime) lastRoutingBackoffReasonRT = s;
    else lastRoutingBackoffReasonBulk = s;
  }

  public void addToLocalNodeSentMessagesToStatistic(Message m) {
    String messageSpecName;
    Long count;

    messageSpecName = m.getSpec().getName();
    // Synchronize to make increments atomic.
    synchronized (localNodeSentMessageTypes) {
      count = localNodeSentMessageTypes.get(messageSpecName);
      if (count == null) count = 1L;
      else count = count + 1;
      localNodeSentMessageTypes.put(messageSpecName, count);
    }
  }

  public void addToLocalNodeReceivedMessagesFromStatistic(Message m) {
    String messageSpecName;
    Long count;

    messageSpecName = m.getSpec().getName();
    // Synchronize to make increments atomic.
    synchronized (localNodeReceivedMessageTypes) {
      count = localNodeReceivedMessageTypes.get(messageSpecName);
      if (count == null) count = 1L;
      else count = count + 1;
      localNodeReceivedMessageTypes.put(messageSpecName, count);
    }
  }

  public java.util.Map<String, Long> getLocalNodeSentMessagesToStatistic() {
    // Must be synchronized *during the copy*
    synchronized (localNodeSentMessageTypes) {
      return new java.util.HashMap<>(localNodeSentMessageTypes);
    }
  }

  public java.util.Map<String, Long> getLocalNodeReceivedMessagesFromStatistic() {
    // Must be synchronized *during the copy*
    synchronized (localNodeReceivedMessageTypes) {
      return new java.util.HashMap<>(localNodeReceivedMessageTypes);
    }
  }

  @SuppressWarnings("unused")
  synchronized USK getARK() {
    return myARK;
  }

  public void gotARK(SimpleFieldSet fs, long fetchedEdition) {
    try {
      synchronized (this) {
        handshakeCount = 0;
        // edition +1 because we store the ARK edition that we want to fetch.
        if (myARK.suggestedEdition < fetchedEdition + 1) myARK = myARK.copy(fetchedEdition + 1);
      }
      processNewNoderef(fs, true, false, false);
    } catch (FSParseException e) {
      LOG.error("Invalid ARK update: {}", e, e);
      // This is ok as ARKs are limited to 4K anyway.
      LOG.error("Data was: \n{}", fs);
      synchronized (this) {
        handshakeCount = PeerNode.MAX_HANDSHAKE_COUNT;
      }
    }
  }

  public synchronized int getPeerNodeStatus() {
    return peerNodeStatus;
  }

  public String getPeerNodeStatusString() {
    int status = getPeerNodeStatus();
    return getPeerNodeStatusString(status);
  }

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

  public String getPeerNodeStatusCSSClassName() {
    int status = getPeerNodeStatus();
    return getPeerNodeStatusCSSClassName(status);
  }

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
      peers.removePeerNodeRoutingBackoffReason(previousRoutingBackoffReasonRT, this, true);
      previousRoutingBackoffReasonRT = null;
    }
    if (!isConnected() && (previousRoutingBackoffReasonBulk != null)) {
      peers.removePeerNodeRoutingBackoffReason(previousRoutingBackoffReasonBulk, this, false);
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
      if (!Objects.equals(lastRoutingBackoffReasonRT, previousRoutingBackoffReasonRT)) {
        if (previousRoutingBackoffReasonRT != null) {
          peers.removePeerNodeRoutingBackoffReason(previousRoutingBackoffReasonRT, this, true);
        }
        peers.addPeerNodeRoutingBackoffReason(lastRoutingBackoffReasonRT, this, true);
        previousRoutingBackoffReasonRT = lastRoutingBackoffReasonRT;
      }
    } else if (previousRoutingBackoffReasonRT != null) {
      peers.removePeerNodeRoutingBackoffReason(previousRoutingBackoffReasonRT, this, true);
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
      if (!Objects.equals(lastRoutingBackoffReasonBulk, previousRoutingBackoffReasonBulk)) {
        if (previousRoutingBackoffReasonBulk != null) {
          peers.removePeerNodeRoutingBackoffReason(previousRoutingBackoffReasonBulk, this, false);
        }
        peers.addPeerNodeRoutingBackoffReason(lastRoutingBackoffReasonBulk, this, false);
        previousRoutingBackoffReasonBulk = lastRoutingBackoffReasonBulk;
      }
    } else if (previousRoutingBackoffReasonBulk != null) {
      peers.removePeerNodeRoutingBackoffReason(previousRoutingBackoffReasonBulk, this, false);
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

  @SuppressWarnings("UnusedReturnValue")
  public int setPeerNodeStatus(long now) {
    return setPeerNodeStatus(now, false);
  }

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
        peers.changePeerNodeStatus(this, oldPeerNodeStatus, peerNodeStatus, noLog);
      }
    }
    if (LOG.isDebugEnabled())
      LOG.debug("Peer node status now {} was {}", peerNodeStatus, oldPeerNodeStatus);
    if (peerNodeStatus != oldPeerNodeStatus) {
      if (oldPeerNodeStatus == PeerManager.PEER_NODE_STATUS_ROUTING_BACKED_OFF) {
        outputLoadTrackerRealTime.maybeNotifySlotWaiter();
        outputLoadTrackerBulk.maybeNotifySlotWaiter();
      }
      notifyPeerNodeStatusChangeListeners();
    }
    if (peerNodeStatus == PeerManager.PEER_NODE_STATUS_ROUTING_BACKED_OFF) {
      long delta = Math.max(localRoutingBackedOffUntilRT, localRoutingBackedOffUntilBulk) - now + 1;
      if (delta > 0)
        node.getTicker()
            .queueTimedJob(checkStatusAfterBackoff, "Update status for " + this, delta, true, true);
    }
    return peerNodeStatus;
  }

  /**
   * @return True if either bulk or realtime has not yet received a valid peer load stats message.
   *     If so, we will not be able to route requests to the node under new load management.
   */
  private boolean noLoadStats() {
    if (node.enableNewLoadManagement(false) || node.enableNewLoadManagement(true)) {
      if (outputLoadTrackerRealTime.getLastIncomingLoadStats() == null) {
        if (isRoutable()) LOG.info("No realtime load stats on {}", this);
        return true;
      }
      if (outputLoadTrackerBulk.getLastIncomingLoadStats() == null) {
        if (isRoutable()) LOG.info("No bulk load stats on {}", this);
        return true;
      }
    }
    return false;
  }

  private final Runnable checkStatusAfterBackoff;

  public abstract boolean recordStatus();

  public String getIdentityString() {
    return identityAsBase64String;
  }

  public boolean isFetchingARK() {
    return arkFetcher != null;
  }

  public synchronized int getHandshakeCount() {
    return handshakeCount;
  }

  /**
   * Queries the Version class to determine if this peers advertised build-number is either too-old
   * or to new for the routing of requests.
   */
  synchronized void updateVersionRoutablity() {
    unroutableOlderVersion = forwardInvalidVersion();
    unroutableNewerVersion = reverseInvalidVersion();
  }

  /**
   * Will return true if routing to this node is either explictly disabled, or disabled due to noted
   * incompatiblity in build-version numbers. Logically: "not(isRoutable())", but will return false
   * even if disconnected (meaning routing is not disabled).
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
    OpennetManager om = node.getOpennet();
    if (om != null) {
      // OpennetManager must be notified of a new connection even if it is a darknet peer.
      om.onConnectedPeer(this);
    }
  }

  @Override
  public void onFound(USK origUSK, long edition, FetchResult result) {
    try (Bucket ignored = result.asBucket()) {
      if (isConnected() || myARK.suggestedEdition > edition) {
        return;
      }

      byte[] data;
      try {
        data = result.asByteArray();
      } catch (IOException e) {
        LOG.error("I/O error reading fetched ARK: {}", e, e);
        return;
      }

      String ref = new String(data, StandardCharsets.UTF_8);

      try {
        SimpleFieldSet fs = new SimpleFieldSet(ref, false, true, false);
        if (LOG.isDebugEnabled()) LOG.debug("Got ARK for {}", this);
        gotARK(fs, edition);
      } catch (IOException e) {
        // Corrupt ref.
        LOG.error(
            "Corrupt ARK reference? Fetched {} got while parsing: {} from:\n{}",
            myARK.copy(edition),
            e,
            ref,
            e);
      }
    }
  }

  public synchronized boolean noContactDetails() {
    return handshakeIPs == null || handshakeIPs.length == 0;
  }

  public synchronized void reportIncomingBytes(int length) {
    totalInputSinceStartup += length;
    totalBytesExchangedWithCurrentTracker += length;
  }

  public synchronized void reportOutgoingBytes(int length) {
    totalOutputSinceStartup += length;
    totalBytesExchangedWithCurrentTracker += length;
  }

  public synchronized long getTotalInputBytes() {
    return bytesInAtStartup + totalInputSinceStartup;
  }

  public synchronized long getTotalOutputBytes() {
    return bytesOutAtStartup + totalOutputSinceStartup;
  }

  public synchronized long getTotalInputSinceStartup() {
    return totalInputSinceStartup;
  }

  public synchronized long getTotalOutputSinceStartup() {
    return totalOutputSinceStartup;
  }

  @SuppressWarnings("unused")
  public boolean isSignatureVerificationSuccessfull() {
    return isSignatureVerificationSuccessfull;
  }

  public void checkRoutableConnectionStatus() {
    synchronized (this) {
      if (isRoutable()) hadRoutableConnectionCount += 1;
      routableConnectionCheckCount += 1;
      // prevent the average from moving too slowly by capping the checkcount to 200000,
      // which, at 7 seconds between counts, works out to about 2 weeks.  This also prevents
      // knowing how long we've had a particular peer long term.
      if (routableConnectionCheckCount >= 200000) {
        // divide both sides by the same amount to keep the same ratio
        hadRoutableConnectionCount = hadRoutableConnectionCount / 2;
        routableConnectionCheckCount = routableConnectionCheckCount / 2;
      }
    }
  }

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

    try {
      String[] components = Fields.commaList(versionStr);
      if (components.length >= 3) {
        parsedVersionComponents.set(components);
        return components;
      }
    } catch (Exception _) {
      // Parsing failed, return empty array
    }

    return new String[0];
  }

  private final PacketThrottle lastThrottle = new PacketThrottle(Node.PACKET_SIZE);

  @Override
  public PacketThrottle getThrottle() {
    return lastThrottle;
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

  public String userToString() {
    return String.valueOf(getPeer());
  }

  public void setTimeDelta(long delta) {
    synchronized (this) {
      clockDelta = delta;
      if (Math.abs(clockDelta) > MAX_CLOCK_DELTA) isRoutable = false;
    }
    setPeerNodeStatus(System.currentTimeMillis());
  }

  public long getClockDelta() {
    return clockDelta;
  }

  /**
   * Offers a key to this peer for potential retrieval.
   *
   * @param key content key to announce
   */
  public void offer(Key key) {
    byte[] keyBytes = key.getFullKey();
    // Note: authenticator size is 32 bytes for HMAC-SHA256.
    byte[] authenticator =
        HMAC.macWithSHA256(node.getFailureTable().offerAuthenticatorKey, keyBytes);
    Message msg = DMT.createFNPOfferKey(key, authenticator);
    try {
      sendAsync(msg, null, node.getNodeStats().sendOffersCtr);
    } catch (NotConnectedException _) {
      // Ignore
    }
  }

  /** Returns the packet mangler responsible for encrypting and sending packets to this peer. */
  @Override
  public OutgoingPacketMangler getOutgoingMangler() {
    return outgoingMangler;
  }

  /** Returns the underlying socket handler used by the outgoing mangler. */
  @Override
  public SocketHandler getSocketHandler() {
    return outgoingMangler.getSocketHandler();
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
   * Is this peer allowed local addresses? If false, we will never connect to this peer via a local
   * address even if it advertises them.
   */
  public boolean allowLocalAddresses() {
    return this.outgoingMangler.alwaysAllowLocalAddresses();
  }

  /**
   * Is this peer set to ignore source address? If so, we will always reply to the peer's official
   * address, even if we get packets from somewhere else. @see DarknetPeerNode.isIgnoreSourcePort().
   */
  public boolean isIgnoreSource() {
    return false;
  }

  /**
   * Creates a {@code DarknetPeerNode} or an {@code OpennetPeerNode}, as appropriate.
   *
   * @param fs node reference to parse
   * @param node2 running node instance
   * @param crypto crypto context for this peer type
   * @param opennet opennet manager (required for opennet peers)
   * @param peers peer manager instance
   * @return a new {@link PeerNode}
   * @throws FSParseException if the field set is malformed
   * @throws PeerParseException if the noderef contains invalid values
   * @throws ReferenceSignatureVerificationException if a signature is present but invalid
   * @throws PeerTooOldException if the peer is too old for current protocols
   */
  public static PeerNode create(
      SimpleFieldSet fs, Node node2, NodeCrypto crypto, OpennetManager opennet, PeerManager peers)
      throws FSParseException,
          PeerParseException,
          ReferenceSignatureVerificationException,
          PeerTooOldException {
    if (crypto.isOpennet()) return new OpennetPeerNode(fs, node2, crypto, opennet, true, peers);
    else return new DarknetPeerNode(fs, node2, crypto, true, null, null, peers);
  }

  public boolean neverConnected() {
    return neverConnected;
  }

  /** Called when a request or insert succeeds. Used by opennet. */
  public abstract void onSuccess(boolean insert, boolean ssk);

  /**
   * Called when a delayed disconnect is occurring. Tell the node that it is being disconnected, but
   * that the process may take a while. After this point, requests will not be accepted from the
   * peer nor routed to it.
   *
   * @param dumpMessageQueue If true, immediately dump the message queue, since we are closing the
   *     connection due to some low level trouble e.g. not acknowledging. We will continue to try to
   *     send anything already in flight, and it is possible to send more messages after this point,
   *     for instance the message telling it we are disconnecting, but see above - no requests will
   *     be routed across this connection.
   * @return True if we have already started disconnecting, false otherwise.
   */
  public boolean notifyDisconnecting(boolean dumpMessageQueue) {
    MessageItem[] messagesTellDisconnected = null;
    synchronized (this) {
      if (disconnecting) return true;
      disconnecting = true;
      jfkNoncesSent.clear();
      if (dumpMessageQueue) {
        // Reset the boot ID so that we get different trackers next time.
        myBootID = random.nextLong();
        messagesTellDisconnected = grabQueuedMessageItems();
      }
    }
    setPeerNodeStatus(System.currentTimeMillis());
    if (messagesTellDisconnected != null) {
      if (LOG.isDebugEnabled())
        LOG.debug(STR_MESSAGES_TO_DUMP + "{}", messagesTellDisconnected.length);
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
    node.getTicker().removeQueuedJob(checkStatusAfterBackoff);
    disconnected(true, true);
    stopARKFetcher();
  }

  /**
   * @return True if we have been removed from the peers list.
   */
  synchronized boolean cachedRemoved() {
    return removed;
  }

  public synchronized boolean isDisconnecting() {
    return disconnecting;
  }

  protected byte[] getJFKBuffer() {
    return jfkBuffer;
  }

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

  @SuppressWarnings("unused")
  public synchronized long timeLastDisconnect() {
    return timeLastDisconnect;
  }

  /**
   * Should this peer be returned by roster lookups (for example {@link PeerRoster#getByPeer})?
   * False means seed nodes or other entries that are never routed.
   */
  public abstract boolean isRealConnection();

  /** Can we accept announcements from this node? */
  public abstract boolean canAcceptAnnouncements();

  public boolean handshakeUnknownInitiator() {
    return false;
  }

  public int handshakeSetupType() {
    return -1;
  }

  @Override
  public WeakReference<PeerNode> getWeakRef() {
    return myRef;
  }

  /**
   * Get a single address to send a handshake to. The current code doesn't work well with multiple
   * simultaneous handshakes. Alternates between valid values.
   */
  public Peer getHandshakeIP() {
    Peer[] localHandshakeIPs;
    if (!shouldSendHandshake()) {
      if (LOG.isDebugEnabled())
        LOG.debug(
            STR_NOT_SENDING_HANDSHAKE_TO + "{} because pn.shouldSendHandshake() returned false",
            detectedPeer);
      return null;
    }
    long firstTime = System.currentTimeMillis();
    localHandshakeIPs = getHandshakeIPs();
    long secondTime = System.currentTimeMillis();
    if ((secondTime - firstTime) > 1000)
      LOG.atError()
          .addArgument(() -> secondTime - firstTime)
          .addArgument(this::userToString)
          .log("getHandshakeIPs() took more than a second to execute ({}" + STR_WORKING_ON + "{}");
    if (localHandshakeIPs.length == 0) {
      long thirdTime = System.currentTimeMillis();
      if ((thirdTime - secondTime) > 1000)
        LOG.atError()
            .addArgument(() -> thirdTime - secondTime)
            .addArgument(this::userToString)
            .log(
                "couldNotSendHandshake() (after getHandshakeIPs()) took more than a second to"
                    + " execute ({}"
                    + STR_WORKING_ON
                    + "{}");
      return null;
    }
    long loopTime1 = System.currentTimeMillis();
    List<Peer> validIPs = new ArrayList<>(localHandshakeIPs.length);
    boolean allowLocalAddresses = allowLocalAddresses();
    for (Peer peer : localHandshakeIPs) {
      if (isValidHandshakePeer(peer, allowLocalAddresses)) validIPs.add(peer);
    }
    Peer ret;
    if (validIPs.isEmpty()) {
      ret = null;
    } else if (validIPs.size() == 1) {
      ret = validIPs.getFirst();
    } else {
      // Don't need to synchronize for this value as we're only called from one thread anyway.
      handshakeIPAlternator %= validIPs.size();
      ret = validIPs.get(handshakeIPAlternator);
      handshakeIPAlternator++;
    }
    long loopTime2 = System.currentTimeMillis();
    if ((loopTime2 - loopTime1) > 1000)
      LOG.atInfo()
          .addArgument(() -> loopTime2 - loopTime1)
          .addArgument(this::userToString)
          .log("loopTime2 is more than a second after loopTime1 ({}" + STR_WORKING_ON + "{}");
    return ret;
  }

  private boolean isValidHandshakePeer(Peer peer, boolean allowLocalAddressesFlag) {
    FreenetInetAddress addr = peer.getFreenetAddress();
    if (peer.getAddress(false) == null) {
      if (LOG.isDebugEnabled())
        LOG.debug(
            STR_NOT_SENDING_HANDSHAKE_TO
                + "{}"
                + STR_FOR
                + "{} because the DNS lookup failed or it's a currently unsupported IPv6 address",
            peer,
            getPeer());
      return false;
    }
    if (!peer.isRealInternetAddress(false, false, allowLocalAddressesFlag)) {
      if (LOG.isDebugEnabled())
        LOG.debug(
            STR_NOT_SENDING_HANDSHAKE_TO
                + "{}"
                + STR_FOR
                + "{} because it's not a real Internet address and metadata.allowLocalAddresses is"
                + " not true",
            peer,
            getPeer());
      return false;
    }
    // If we are connected, we are rekeying. We have separate code to boot out connections.
    if (!isConnected() && !outgoingMangler.allowConnection(this, addr)) {
      if (LOG.isDebugEnabled())
        LOG.debug("Not sending handshake packet to {}" + STR_FOR + "{}", peer, this);
      return false;
    }
    return true;
  }

  private int handshakeIPAlternator;

  public void sendNodeToNodeMessage(
      SimpleFieldSet fs,
      int n2nType,
      boolean includeSentTime,
      long now,
      boolean queueOnNotConnected) {
    fs.putOverwrite("n2nType", Integer.toString(n2nType));
    if (includeSentTime) {
      fs.put("sentTime", now);
    }
    Message n2nm =
        DMT.createNodeToNodeMessage(n2nType, fs.toString().getBytes(StandardCharsets.UTF_8));
    UnqueueMessageOnAckCallback cb = null;
    if (isDarknet() && queueOnNotConnected) {
      int fileNumber = queueN2NM(fs);
      cb = new UnqueueMessageOnAckCallback((DarknetPeerNode) this, fileNumber);
    }
    try {
      sendAsync(n2nm, cb, node.getNodeStats().nodeToNodeCounter);
    } catch (NotConnectedException _) {
      if (includeSentTime) {
        fs.removeValue("sentTime");
      }
    }
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
    return shouldThrottle(getPeer(), node);
  }

  public static boolean shouldThrottle(Peer peer, Node node) {
    if (node.isThrottleLocalData()) return true;
    if (peer == null) return true; // presumably
    InetAddress addr = peer.getAddress(false);
    if (addr == null) return true; // presumably
    return IPUtil.isValidAddress(addr, false);
  }

  static final long MAX_RTO = SECONDS.toMillis(60);
  static final long MIN_RTO = 50;
  private int consecutiveRTOBackoffs;

  // Clock generally has 20ms granularity or better, right?
  // Note: clock granularity depends on platform.
  private static final int CLOCK_GRANULARITY = 20;

  @Override
  public void reportPing(long t) {
    this.pingAverage.report(t);
    synchronized (this) {
      consecutiveRTOBackoffs = 0;
      // Update RTT according to RFC 2988.
      if (!reportedRTT) initializeRtt(t);
      else updateRtt(t);
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Reported ping {} avg is now {} RTO is {} SRTT is {} RTTVAR is {}" + STR_FOR + "{}",
            t,
            pingAverage.currentValue(),
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
   * Once SRTT and RTTVAR are cleared they should be initialized with the next RTT sample taken per
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

  private long resendBytesSent;

  public final ByteCounter resendByteCounter =
      new ByteCounter() {

        @Override
        public void receivedBytes(int x) {
          // Ignore
        }

        @Override
        public void sentBytes(int x) {
          synchronized (PeerNode.this) {
            resendBytesSent += x;
          }
          node.getNodeStats().resendByteCounter.sentBytes(x);
        }

        @Override
        public void sentPayload(int x) {
          // Ignore
        }
      };

  public long getResendBytesSent() {
    return resendBytesSent;
  }

  /**
   * Returns whether this peer should be disconnected and removed immediately.
   *
   * <p>Default implementation returns {@code false}.
   */
  public boolean shouldDisconnectAndRemoveNow() {
    return false;
  }

  public void setUptime(byte uptime2) {
    this.uptime = uptime2;
  }

  public short getUptime() {
    return (short) (uptime & 0xFF);
  }

  public void incrementNumberOfSelections() {
    // Note: a compact bit-field could reduce memory; retained simple counter for clarity.
    synchronized (this) {
      countSelectionsSinceConnected++;
    }
  }

  /**
   * @return The rate at which this peer has been selected since it connected.
   */
  public synchronized double selectionRate() {
    long timeSinceConnected = System.currentTimeMillis() - this.connectedTime;
    // Avoid bias due to short uptime.
    if (timeSinceConnected < SECONDS.toMillis(10)) return 0.0;
    return countSelectionsSinceConnected / (double) timeSinceConnected;
  }

  private volatile int offeredMainJarVersion;

  public void setMainJarOfferedVersion(int mainJarVersion) {
    offeredMainJarVersion = mainJarVersion;
  }

  public int getMainJarOfferedVersion() {
    return offeredMainJarVersion;
  }

  /**
   * Maybe send something. A SINGLE PACKET. Don't send everything at once, for two reasons: 1. It is
   * possible for a node to have a very long backlog. 2. Sometimes sending a packet can take a long
   * time. 3. In the near future PacketSender will be responsible for output bandwidth throttling.
   * So it makes sense to send a single packet and round-robin.
   *
   * @param now current time in milliseconds
   * @param ackOnly when true, only send acknowledgements/housekeeping
   * @throws BlockedTooLongException if packet generation or queueing is blocked excessively
   */
  public boolean maybeSendPacket(long now, boolean ackOnly) throws BlockedTooLongException {
    PacketFormat pf;
    synchronized (this) {
      if (packetFormat == null) return false;
      pf = packetFormat;
    }
    return pf.maybeSendPacket(now, ackOnly);
  }

  /**
   * @return The ID of a reusable PacketTracker if there is one, otherwise -1.
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
    lastAttemptedHandshakeIPUpdateTime = System.currentTimeMillis();
    countFailedRevocationTransfers++;
  }

  /** Returns the number of failed revocation transfers since the last disconnect. */
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
  public void registerPeerNodeStatusChangeListener(PeerManager.PeerStatusChangeListener listener) {
    listeners.add(listener);
  }

  /** Notifies all registered listeners that the peer status changed. */
  private void notifyPeerNodeStatusChangeListeners() {
    synchronized (listeners) {
      for (PeerManager.PeerStatusChangeListener l : listeners) {
        l.onPeerStatusChange();
      }
    }
  }

  /** Returns {@code true} when the peer's reported uptime is below the store-key threshold. */
  public boolean isLowUptime() {
    return getUptime() < Node.MIN_UPTIME_STORE_KEY;
  }

  public synchronized void setAddedReason(ConnectionType connectionType) {
    // Do nothing.
  }

  public synchronized ConnectionType getAddedReason() {
    return null;
  }

  private final Object routedToLock = new Object();

  void removeUIDsFromMessageQueues(Long[] list) {
    this.messageQueue.removeUIDsFromMessageQueues(list);
  }

  public static class IncomingLoadSummaryStats {
    public IncomingLoadSummaryStats(
        int totalRequests, Limits limits, Usage used, Usage othersUsed) {
      runningRequestsTotal = totalRequests;
      peerCapacityOutputBytes = (int) limits.peerOutput;
      peerCapacityInputBytes = (int) limits.peerInput;
      totalCapacityOutputBytes = (int) limits.totalOutput;
      totalCapacityInputBytes = (int) limits.totalInput;
      usedCapacityOutputBytes = (int) used.output;
      usedCapacityInputBytes = (int) used.input;
      othersUsedCapacityOutputBytes = (int) othersUsed.output;
      othersUsedCapacityInputBytes = (int) othersUsed.input;
    }

    public final int runningRequestsTotal;
    public final int peerCapacityOutputBytes;
    public final int peerCapacityInputBytes;
    public final int totalCapacityOutputBytes;
    public final int totalCapacityInputBytes;
    public final int usedCapacityOutputBytes;
    public final int usedCapacityInputBytes;
    public final int othersUsedCapacityOutputBytes;
    public final int othersUsedCapacityInputBytes;
  }

  // Small containers to reduce constructor parameter count
  public record Limits(
      double peerOutput, double peerInput, double totalOutput, double totalInput) {}

  public record Usage(double output, double input) {}

  enum RequestLikelyAcceptedState {
    GUARANTEED, // guaranteed to be accepted, under the per-peer guaranteed limit
    LIKELY, // likely to be accepted even though above the per-peer guaranteed limit, as overall is
    // below the overall lower limit
    UNLIKELY, // not likely to be accepted; peer is over the per-peer guaranteed limit, and global
    // is over the overall lower limit
    UNKNOWN // no data but accepting anyway
  }

  // Consider adding LOW_CAPACITY/BROKEN status when capacity is far below median.

  OutputLoadTracker outputLoadTrackerRealTime = new OutputLoadTracker(true);
  OutputLoadTracker outputLoadTrackerBulk = new OutputLoadTracker(false);

  OutputLoadTracker outputLoadTracker(boolean realTime) {
    return realTime ? outputLoadTrackerRealTime : outputLoadTrackerBulk;
  }

  public void reportLoadStatus(PeerLoadStats stat) {
    outputLoadTracker(stat.realTime).reportLoadStatus(stat);
    node.getExecutor().execute(checkStatusAfterBackoff);
  }

  public static class SlotWaiter {

    final PeerNode source;
    private final HashSet<PeerNode> waitingFor;
    private PeerNode acceptedBy;
    private RequestLikelyAcceptedState acceptedState;
    final UIDTag tag;
    // Offered-key path not used in this SlotWaiter creation flow; always handles normal routing.
    final RequestType requestType;
    private boolean failed;
    private SlotWaiterFailedException fe;
    final boolean realTime;

    // Note: the counter preserves original ordering even after failures (transfer
    // failures, backoffs). A future enhancement could make the wait loop in
    // RequestSender asynchronous and rely on callbacks instead.

    final long counter;
    private static long waiterCounter;

    SlotWaiter(UIDTag tag, RequestType type, boolean realTime, PeerNode source) {
      this.tag = tag;
      this.requestType = type;
      this.waitingFor = new HashSet<>();
      this.realTime = realTime;
      this.source = source;
      synchronized (SlotWaiter.class) {
        counter = waiterCounter++;
      }
    }

    /**
     * Adds a peer to the set being waited on for a slot.
     *
     * @param peer peer to add
     * @return {@code true} if the peer was added or already satisfied; {@code false} if it could
     *     not be queued
     */
    public boolean addWaitingFor(PeerNode peer) {
      boolean cantQueue =
          (!peer.isRoutable()) || peer.isInMandatoryBackoff(System.currentTimeMillis(), realTime);
      synchronized (this) {
        if (acceptedBy != null) {
          if (LOG.isDebugEnabled())
            LOG.debug("Not adding {} because already matched on {}", peer.shortToString, this);
          return true;
        }
        if (failed) {
          if (LOG.isDebugEnabled())
            LOG.debug("Not adding {} because already failed on {}", peer.shortToString, this);
          return true;
        }
        if (waitingFor.contains(peer)) return true;
        // Race condition if contains() && cantQueue (i.e. it was accepted then it became backed
        // off), but probably not serious.
        if (cantQueue) return false;
        waitingFor.add(peer);
        tag.setWaitingForSlot();
      }
      if (!peer.outputLoadTracker(realTime).queueSlotWaiter(this)) {
        synchronized (this) {
          waitingFor.remove(peer);
          if (acceptedBy != null || failed) return true;
        }
        return false;
      } else return true;
    }

    /**
     * First part of wake-up callback. If this returns null, we have already woken up, but if it
     * returns a PeerNode[], the SlotWaiter has been woken up, and the caller **must** call
     * unregister() with the returned data.
     *
     * @param peer The peer waking up the SlotWaiter.
     * @param state The accept state we are waking up with.
     * @return Null if already woken up or not waiting for this peer, otherwise an array of all the
     *     PeerNode's the slot was registered on, which *must* be passed to unregister() as soon as
     *     the caller has unlocked everything that reasonably can be unlocked.
     */
    synchronized PeerNode[] innerOnWaited(PeerNode peer, RequestLikelyAcceptedState state) {
      if (LOG.isDebugEnabled()) LOG.debug("Waking slot waiter {} on {}", this, peer);
      if (acceptedBy != null) {
        if (LOG.isDebugEnabled()) LOG.debug("Already accepted on {}", this);
        removeTagForPeerIfDifferent(peer);
        return new PeerNode[0];
      }
      if (!waitingFor.contains(peer)) {
        if (LOG.isDebugEnabled()) LOG.debug("Not waiting for peer {} on {}", peer, this);
        removeTagForPeerIfDifferent(peer);
        return new PeerNode[0];
      }
      acceptedBy = peer;
      acceptedState = state;
      if (!tag.addRoutedTo(peer, false)) {
        LOG.info("onWaited for {} added on {} but already added - race condition?", this, tag);
      }
      notifyAll();
      // Because we are no longer in the slot queue we must remove it.
      // If we want to wait for it again it must be re-queued.
      PeerNode[] toUnreg = waitingFor.toArray(new PeerNode[0]);
      waitingFor.clear();
      tag.clearWaitingForSlot();
      return toUnreg;
    }

    private void removeTagForPeerIfDifferent(PeerNode peer) {
      if (acceptedBy != peer) {
        tag.removeRoutingTo(peer);
      }
    }

    /**
     * Caller should not hold locks while calling this.
     *
     * @param exclude only set when the caller already removed the slot waiter for this peer
     * @param all set of peers from which to unregister the slot waiter
     */
    void unregister(PeerNode exclude, PeerNode[] all) {
      for (PeerNode p : all) {
        if (p != exclude) p.outputLoadTracker(realTime).unqueueSlotWaiter(this);
      }
    }

    /**
     * Some sort of failure.
     *
     * @param peer the peer for which routing likely failed or should be reconsidered
     */
    void onFailed(PeerNode peer) {
      if (LOG.isDebugEnabled()) LOG.debug("onFailed() on {}", this);
      synchronized (this) {
        if (acceptedBy != null) {
          if (LOG.isDebugEnabled()) LOG.debug("Already matched on {}", this);
          return;
        }
        // Always wake up.
        // Whether it's a backoff or a disconnect, we probably want to add another peer.
        // Note: retained for compatibility with existing call sites.
        failed = true;
        fe = new SlotWaiterFailedException(peer, true);
        tag.clearWaitingForSlot();
        notifyAll();
      }
    }

    public java.util.Set<PeerNode> waitingForList() {
      synchronized (this) {
        return new HashSet<>(waitingFor);
      }
    }

    /**
     * Wait for any of the PeerNode's we have queued on to accept (locally i.e. to allocate a local
     * slot to) this request.
     *
     * @param maxWait The time to wait for. Can be 0, but if it is 0, this is a "peek", i.e. if we
     *     return null, the queued slots remain live. Whereas if maxWait is not 0, we will
     *     unregister when we timeout.
     * @param timeOutIsFatal If true, if we timeout, count it for each node involved as a fatal
     *     timeout.
     * @return A matched node, or null.
     * @throws SlotWaiterFailedException If a peer actually failed.
     */
    PeerNode waitForAny(long maxWait, boolean timeOutIsFatal) throws SlotWaiterFailedException {
      PreGrabResult pre = preGrabAndSnapshot();
      if (pre.grabbed) {
        unregister(pre.ret, pre.all);
        if (pre.f != null && pre.ret == null) throw pre.f;
        return pre.ret;
      }
      if (pre.all.length == 0) {
        if (LOG.isDebugEnabled()) LOG.debug("None to wait for on {}", this);
        return null;
      }
      // Double-check before blocking, prevent race condition.
      EarlyResult early = tryImmediateAccept(pre.all);
      if (early.accepted != null) return early.accepted;
      if (maxWait == 0) return null;
      if (!early.anyValid) return handleNoValidAndReturn();
      WaitOutcome w = performTimedWait(maxWait);
      if (timeOutIsFatal) {
        for (PeerNode pn : w.toUnregister) {
          pn.outputLoadTracker(realTime).reportFatalTimeoutInWait(isLocal());
        }
      }
      unregister(w.ret, w.toUnregister);
      return w.ret;
    }

    private PreGrabResult preGrabAndSnapshot() {
      PeerNode[] all;
      PeerNode ret = null;
      boolean grabbed = false;
      SlotWaiterFailedException f = null;
      synchronized (this) {
        if (shouldGrab()) {
          if (LOG.isDebugEnabled()) LOG.debug("Already matched on {}", this);
          ret = grab();
          grabbed = true;
        }
        if (fe != null) {
          f = fe;
          fe = null;
          grabbed = true;
        }
        all = waitingFor.toArray(new PeerNode[0]);
        // Clear waiter registrations regardless of whether a peer was actually returned.
        // This ensures that after a failure (grab() returns null but we were marked as grabbed),
        // we do not keep stale entries that prevent re-queuing on subsequent attempts.
        if (grabbed) waitingFor.clear();
        if (grabbed || all.length == 0) tag.clearWaitingForSlot();
      }
      return new PreGrabResult(all, ret, grabbed, f);
    }

    private EarlyResult tryImmediateAccept(PeerNode[] all) {
      boolean anyValid = false;
      long now = System.currentTimeMillis();
      for (PeerNode p : all) {
        if ((!p.isRoutable()) || p.isInMandatoryBackoff(now, realTime)) {
          if (LOG.isDebugEnabled()) LOG.debug("Peer is not valid in waitForAny(): {}", p);
          continue;
        }
        anyValid = true;
        RequestLikelyAcceptedState accept =
            p.outputLoadTracker(realTime).tryRouteTo(tag, RequestLikelyAcceptedState.LIKELY);
        if (accept != null) return new EarlyResult(true, processPreAccept(p, accept));
      }
      return new EarlyResult(anyValid, null);
    }

    private PeerNode processPreAccept(PeerNode p, RequestLikelyAcceptedState accept) {
      if (LOG.isDebugEnabled()) LOG.debug("tryRouteTo() pre-wait check returned {}", accept);
      PeerNode[] unreg;
      PeerNode other = null;
      synchronized (this) {
        if (LOG.isDebugEnabled())
          LOG.debug(
              "tryRouteTo() succeeded to {} on {} with {} - checking whether we have already"
                  + " accepted.",
              p,
              this,
              accept);
        unreg = innerOnWaited(p, accept);
        if (unreg.length == 0 && shouldGrab()) {
          other = grab();
        }
        if (other == null) {
          if (LOG.isDebugEnabled()) LOG.debug("Trying the original tryRouteTo() on {}", this);
          acceptedBy = null;
          failed = false;
          fe = null;
        }
        tag.clearWaitingForSlot();
      }
      if (unreg.length > 0) unregister(null, unreg);
      if (other != null) {
        LOG.info(
            "Race condition: tryRouteTo() succeeded on {} but already matched on {} on {}",
            p.shortToString(),
            other.shortToString(),
            this);
        tag.removeRoutingTo(p);
        return other;
      }
      p.outputLoadTracker(realTime).reportAllocated(isLocal());
      return p;
    }

    private PeerNode handleNoValidAndReturn() throws SlotWaiterFailedException {
      PeerNode[] all;
      PeerNode ret;
      SlotWaiterFailedException fLocal = null;
      synchronized (this) {
        if (fe != null) {
          fLocal = fe;
          fe = null;
        }
        ret = shouldGrab() ? grab() : null;
        all = waitingFor.toArray(new PeerNode[0]);
        waitingFor.clear();
        failed = false;
        acceptedBy = null;
      }
      if (LOG.isDebugEnabled()) LOG.debug("None valid to wait for on {}", this);
      unregister(ret, all);
      if (fLocal != null && ret == null) throw fLocal;
      tag.clearWaitingForSlot();
      return ret;
    }

    private WaitOutcome performTimedWait(long maxWait) {
      PeerNode ret;
      PeerNode[] all;
      long waitStart;
      boolean timedOut;
      synchronized (this) {
        if (LOG.isDebugEnabled())
          LOG.debug(
              "Waiting for any node to wake up {} : {} (for up to {}ms)",
              this,
              Arrays.toString(waitingFor.toArray()),
              maxWait);
        waitStart = System.currentTimeMillis();
        long deadline = waitStart + maxWait;
        timedOut = runTimedWaitLoop(deadline, maxWait);
        logWaitDurationIfNeeded(waitStart, timedOut);
        if (LOG.isDebugEnabled())
          LOG.debug(
              "Returning after waiting: accepted by {} waiting for {} failed {} on {}",
              acceptedBy,
              waitingFor.size(),
              failed,
              this);
        ret = acceptedBy;
        acceptedBy = null; // Allow for it to wait again if necessary
        all = waitingFor.toArray(new PeerNode[0]);
        waitingFor.clear();
        failed = false;
        fe = null;
        tag.clearWaitingForSlot();
      }
      return new WaitOutcome(ret, all);
    }

    private synchronized boolean runTimedWaitLoop(long deadline, long maxWait) {
      if (maxWait == Long.MAX_VALUE) {
        while (shouldContinueWaiting()) {
          try {
            wait();
          } catch (InterruptedException _) {
            Thread.currentThread().interrupt();
          }
        }
        return false;
      }
      boolean timedOut = false;
      while (shouldContinueWaiting()) {
        try {
          long remaining = deadline - System.currentTimeMillis();
          if (remaining <= 0) {
            timedOut = onDeadlineElapsed();
            break;
          }
          int millis = (int) Math.min(Integer.MAX_VALUE, remaining);
          wait(millis);
          if (LOG.isDebugEnabled()) LOG.debug("Maximum wait time exceeded on {}", this);
        } catch (InterruptedException _) {
          Thread.currentThread().interrupt();
        }
      }
      return timedOut;
    }

    private boolean shouldContinueWaiting() {
      return acceptedBy == null && (!waitingFor.isEmpty()) && !failed;
    }

    private boolean onDeadlineElapsed() {
      if (!shouldGrab()) {
        waitingFor.clear();
        return true;
      }
      return false;
    }

    private void logWaitDurationIfNeeded(long waitStart, boolean timedOut) {
      if (timedOut) return;
      long waitEnd = System.currentTimeMillis();
      long waited = waitEnd - waitStart;
      if (waited > (realTime ? 6000 : 60000)) {
        LOG.warn(STR_WAITED + "{}" + STR_MS_FOR + "{}", waited, this);
      } else if (waited > (realTime ? 1000 : 10000)) {
        LOG.info(STR_WAITED + "{}" + STR_MS_FOR + "{}", waited, this);
      } else {
        if (LOG.isDebugEnabled()) LOG.debug(STR_WAITED + "{}" + STR_MS_FOR + "{}", waited, this);
      }
    }

    private record PreGrabResult(
        PeerNode[] all, PeerNode ret, boolean grabbed, SlotWaiterFailedException f) {
      @Override
      public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof PreGrabResult(var otherAll, var otherRet, var otherGrabbed, var otherF)))
          return false;
        return grabbed == otherGrabbed
            && java.util.Objects.equals(ret, otherRet)
            && java.util.Objects.equals(f, otherF)
            && java.util.Arrays.equals(all, otherAll);
      }

      @Override
      public int hashCode() {
        int result = java.util.Objects.hash(ret, grabbed, f);
        result = 31 * result + java.util.Arrays.hashCode(all);
        return result;
      }

      @Override
      public @NotNull String toString() {
        return "PreGrabResult[all="
            + java.util.Arrays.toString(all)
            + ", ret="
            + ret
            + ", grabbed="
            + grabbed
            + ", f="
            + f
            + "]";
      }
    }

    private record EarlyResult(boolean anyValid, PeerNode accepted) {}

    private record WaitOutcome(PeerNode ret, PeerNode[] toUnregister) {
      @Override
      public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof WaitOutcome(var otherRet, var otherToUnregister))) return false;
        return java.util.Objects.equals(ret, otherRet)
            && java.util.Arrays.equals(toUnregister, otherToUnregister);
      }

      @Override
      public int hashCode() {
        int result = java.util.Objects.hash(ret);
        result = 31 * result + java.util.Arrays.hashCode(toUnregister);
        return result;
      }

      @Override
      public @NotNull String toString() {
        return "WaitOutcome[ret="
            + ret
            + ", toUnregister="
            + java.util.Arrays.toString(toUnregister)
            + "]";
      }
    }

    final boolean isLocal() {
      return source == null;
    }

    private boolean shouldGrab() {
      return acceptedBy != null || waitingFor.isEmpty() || failed;
    }

    private synchronized PeerNode grab() {
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Returning in first check: accepted by {} waiting for {} failed {} accepted state {}",
            acceptedBy,
            waitingFor.size(),
            failed,
            acceptedState);
      failed = false;
      PeerNode got = acceptedBy;
      acceptedBy = null; // Allow for it to wait again if necessary
      return got;
    }

    synchronized RequestLikelyAcceptedState getAcceptedState() {
      return acceptedState;
    }

    @Override
    public String toString() {
      return super.toString() + ":" + counter + ":" + requestType + ":" + realTime;
    }

    public synchronized int waitingForCount() {
      return waitingFor.size();
    }
  }

  static class SlotWaiterFailedException extends Exception {
    final transient PeerNode pn;
    final boolean fatal;

    SlotWaiterFailedException(PeerNode p, boolean f) {
      this.pn = p;
      this.fatal = f;
      // Optimization: consider arranging for empty stack trace.
    }
  }

  static class SlotWaiterList {

    private final LinkedHashMap<PeerNode, TreeMap<Long, SlotWaiter>> lru = new LinkedHashMap<>();

    public synchronized void put(SlotWaiter waiter) {
      PeerNode source = waiter.source;
      TreeMap<Long, SlotWaiter> map = lru.computeIfAbsent(source, k -> new TreeMap<>());
      map.put(waiter.counter, waiter);
    }

    public synchronized void remove(SlotWaiter waiter) {
      PeerNode source = waiter.source;
      TreeMap<Long, SlotWaiter> map = lru.get(source);
      if (map == null) {
        if (LOG.isDebugEnabled()) LOG.debug("SlotWaiter {} was not queued", waiter);
        return;
      }
      map.remove(waiter.counter);
      if (map.isEmpty()) lru.remove(source);
    }

    public synchronized boolean isEmpty() {
      return lru.isEmpty();
    }

    public synchronized SlotWaiter removeFirst() {
      if (lru.isEmpty()) return null;
      // Consider using LRUMap; would need to update to use Iterator and other modern APIs.
      PeerNode source = lru.keySet().iterator().next();
      TreeMap<Long, SlotWaiter> map = lru.get(source);
      Long key = map.firstKey();
      SlotWaiter ret = map.get(key);
      map.remove(key);
      lru.remove(source);
      if (!map.isEmpty()) lru.put(source, map);
      return ret;
    }

    public synchronized List<SlotWaiter> values() {
      ArrayList<SlotWaiter> list = new ArrayList<>();
      for (TreeMap<Long, SlotWaiter> map : lru.values()) {
        list.addAll(map.values());
      }
      return list;
    }

    public String toString() {
      return super.toString() + ":peers=" + lru.size();
    }
  }

  /** cached RequestType.values(). Never modify or pass this array to outside code! */
  private static final RequestType[] RequestType_values = RequestType.values();

  /**
   * Uses the information we receive on the load on the target node to determine whether we can
   * route to it and when we can route to it.
   */
  class OutputLoadTracker {

    final boolean realTime;

    private PeerLoadStats lastIncomingLoadStats;

    private boolean dontSendUnlessGuaranteed;

    // These only count remote timeouts.
    // Strictly local and remote should be the same in new load management, but
    // local often produces more load than can be handled by our peers.
    // Fair sharing in SlotWaiterList ensures that this doesn't cause excessive
    // timeouts for others, but we want the stats that determine their RecentlyFailed
    // times to be based on remote requests only. Also, local requests by definition
    // do not cause downstream problems.
    private long totalFatalTimeouts;
    private long totalAllocated;

    public void reportLoadStatus(PeerLoadStats stat) {
      if (LOG.isDebugEnabled()) LOG.debug("Got load status : {}", stat);
      synchronized (routedToLock) {
        lastIncomingLoadStats = stat;
      }
      maybeNotifySlotWaiter();
    }

    synchronized /* lock only used for counter */ void reportFatalTimeoutInWait(boolean local) {
      if (!local) totalFatalTimeouts++;
      node.getNodeStats().reportFatalTimeoutInWait(local);
    }

    synchronized /* lock only used for counter */ void reportAllocated(boolean local) {
      if (!local) totalAllocated++;
      node.getNodeStats().reportAllocatedSlot(local);
    }

    public synchronized double proportionTimingOutFatallyInWait() {
      if (totalFatalTimeouts == 1 && totalAllocated == 0)
        return 0.5; // Limit impact if the first one is rejected.
      return (double) totalFatalTimeouts / ((double) (totalFatalTimeouts + totalAllocated));
    }

    public PeerLoadStats getLastIncomingLoadStats() {
      synchronized (routedToLock) {
        return lastIncomingLoadStats;
      }
    }

    OutputLoadTracker(boolean realTime) {
      this.realTime = realTime;
    }

    public IncomingLoadSummaryStats getIncomingLoadStats() {
      PeerLoadStats loadStats;
      synchronized (routedToLock) {
        if (lastIncomingLoadStats == null) return null;
        loadStats = lastIncomingLoadStats;
      }
      RunningRequestsSnapshot runningRequests =
          node.getNodeStats().getRunningRequestsTo(PeerNode.this, realTime);
      RunningRequestsSnapshot otherRunningRequests = loadStats.getOtherRunningRequests();
      boolean ignoreLocalVsRemoteBandwidthLiability =
          node.getNodeStats().ignoreLocalVsRemoteBandwidthLiability();
      Limits limits =
          new Limits(
              loadStats.outputBandwidthPeerLimit,
              loadStats.inputBandwidthPeerLimit,
              loadStats.outputBandwidthUpperLimit,
              loadStats.inputBandwidthUpperLimit);
      Usage used =
          new Usage(
              runningRequests.calculate(ignoreLocalVsRemoteBandwidthLiability, false),
              runningRequests.calculate(ignoreLocalVsRemoteBandwidthLiability, true));
      Usage othersUsed =
          new Usage(
              otherRunningRequests.calculate(ignoreLocalVsRemoteBandwidthLiability, false),
              otherRunningRequests.calculate(ignoreLocalVsRemoteBandwidthLiability, true));
      return new IncomingLoadSummaryStats(
          runningRequests.totalRequests(), limits, used, othersUsed);
    }

    /**
     * Can we route the tag to this peer? If so (including if we are accepting because we don't have
     * any load stats), and we haven't already, addRoutedTo() and return the accepted state.
     * Otherwise, return null.
     *
     * @param tag request identifier
     * @param worstAcceptable lowest acceptable state to consider a route viable
     * @return the decided accept state, or {@code null} if routing is not viable
     */
    public RequestLikelyAcceptedState tryRouteTo(
        UIDTag tag, RequestLikelyAcceptedState worstAcceptable) {
      PeerLoadStats loadStats;
      boolean ignoreLocalVsRemote = node.getNodeStats().ignoreLocalVsRemoteBandwidthLiability();
      if (!isRoutable()) return null;
      if (isInMandatoryBackoff(System.currentTimeMillis(), realTime)) return null;
      synchronized (routedToLock) {
        loadStats = lastIncomingLoadStats;
        if (loadStats == null) {
          LOG.error(
              "Accepting because no load stats from {} ({})",
              PeerNode.this.shortToString(),
              PeerNode.this.getBuildNumber());
          if (tag.addRoutedTo(PeerNode.this, false)) {
            // Consider waiting a bit or checking the other side's version first.
            return RequestLikelyAcceptedState.UNKNOWN;
          } else return null;
        }
        if (dontSendUnlessGuaranteed) worstAcceptable = RequestLikelyAcceptedState.GUARANTEED;
        // Requests already running to this node
        RunningRequestsSnapshot runningRequests =
            node.getNodeStats().getRunningRequestsTo(PeerNode.this, realTime);
        runningRequests.log(PeerNode.this);
        // Requests running from its other peers
        RunningRequestsSnapshot otherRunningRequests = loadStats.getOtherRunningRequests();
        RequestLikelyAcceptedState acceptState =
            getRequestLikelyAcceptedState(
                runningRequests, otherRunningRequests, ignoreLocalVsRemote, loadStats);
        if (LOG.isDebugEnabled())
          LOG.debug(
              "Predicted acceptance state for request: {} must beat {}",
              acceptState,
              worstAcceptable);
        if (acceptState.ordinal() > worstAcceptable.ordinal()) return null;
        if (tag.addRoutedTo(PeerNode.this, false)) return acceptState;
        else {
          if (LOG.isDebugEnabled()) LOG.debug("Already routed to peer");
          return null;
        }
      }
    }

    // Consider responding to capacity/backoff changes by adding another node.

    private final EnumMap<RequestType, SlotWaiterList> slotWaiters =
        new EnumMap<>(RequestType.class);

    boolean queueSlotWaiter(SlotWaiter waiter) {
      if (!canQueueNow()) return false;
      QueueResult r = enqueueOrWake(waiter);
      if (r.wokeUpImmediately()) {
        reportAllocated(waiter.isLocal());
        waiter.unregister(null, r.toUnregister);
        return true;
      }
      // If we queued but conditions changed, fail fast
      if (r.queued
          && ((!isRoutable()) || (isInMandatoryBackoff(System.currentTimeMillis(), realTime)))) {
        if (LOG.isDebugEnabled())
          LOG.debug("Queued but not routable or in mandatory backoff, failing");
        waiter.onFailed(PeerNode.this);
        return false;
      }
      return r.queued;
    }

    private boolean canQueueNow() {
      if (!isRoutable()) {
        if (LOG.isDebugEnabled()) LOG.debug("Not routable, so not queueing");
        return false;
      }
      if (isInMandatoryBackoff(System.currentTimeMillis(), realTime)) {
        if (LOG.isDebugEnabled()) LOG.debug("In mandatory backoff, so not queueing");
        return false;
      }
      return true;
    }

    private record QueueResult(boolean queued, PeerNode[] toUnregister) {

      boolean wokeUpImmediately() {
        return toUnregister.length > 0;
      }

      @Override
      public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof QueueResult(var otherQueued, var otherToUnregister))) return false;
        return queued == otherQueued && java.util.Arrays.equals(toUnregister, otherToUnregister);
      }

      @Override
      public int hashCode() {
        int result = java.lang.Boolean.hashCode(queued);
        result = 31 * result + java.util.Arrays.hashCode(toUnregister);
        return result;
      }

      @Override
      public @NotNull String toString() {
        return "QueueResult[queued="
            + queued
            + ", toUnregister="
            + java.util.Arrays.toString(toUnregister)
            + "]";
      }
    }

    private QueueResult enqueueOrWake(SlotWaiter waiter) {
      boolean queued = false;
      PeerNode[] all = new PeerNode[0];
      synchronized (routedToLock) {
        boolean noLoadStats = (this.lastIncomingLoadStats == null);
        if (!noLoadStats) {
          SlotWaiterList list = makeSlotWaiters(waiter.requestType);
          list.put(waiter);
          if (LOG.isDebugEnabled())
            LOG.debug(
                "Queued slot {} waiter for {} on {} on {}" + STR_FOR + "{}",
                waiter,
                waiter.requestType,
                list,
                this,
                PeerNode.this);
          queued = true;
        } else {
          if (LOG.isDebugEnabled()) LOG.debug("Not waiting for {} as no load stats", this);
          all = waiter.innerOnWaited(PeerNode.this, RequestLikelyAcceptedState.UNKNOWN);
        }
      }
      return new QueueResult(queued, all);
    }

    private SlotWaiterList makeSlotWaiters(RequestType requestType) {
      return slotWaiters.computeIfAbsent(requestType, k -> new SlotWaiterList());
    }

    void unqueueSlotWaiter(SlotWaiter waiter) {
      synchronized (routedToLock) {
        SlotWaiterList map = slotWaiters.get(waiter.requestType);
        if (map == null) return;
        map.remove(waiter);
      }
    }

    private void failSlotWaiters() {
      for (RequestType type : RequestType_values) {
        SlotWaiterList slots;
        synchronized (routedToLock) {
          slots = slotWaiters.get(type);
          if (slots == null) continue;
          slotWaiters.remove(type);
        }
        for (SlotWaiter w : slots.values()) w.onFailed(PeerNode.this);
      }
    }

    private int slotWaiterTypeCounter = 0;

    private void maybeNotifySlotWaiter() {
      if (!isRoutable()) return;
      boolean ignoreLocalVsRemote = node.getNodeStats().ignoreLocalVsRemoteBandwidthLiability();
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Maybe waking up slot waiters for {}" + STR_REALTIME_EQ + "{}" + STR_FOR + "{}",
            this,
            realTime,
            PeerNode.this.shortToString());
      while (true) {
        int typeNum;
        PeerLoadStats loadStats;
        synchronized (routedToLock) {
          loadStats = lastIncomingLoadStats;
          if (slotWaiters.isEmpty()) {
            if (LOG.isDebugEnabled()) LOG.debug("No slot waiters for {}", this);
            return;
          }
          typeNum = slotWaiterTypeCounter;
        }
        typeNum = nextTypeIndex(typeNum);
        if (!processCycle(loadStats, ignoreLocalVsRemote, typeNum)) return;
      }
    }

    private boolean processCycle(
        PeerLoadStats loadStats, boolean ignoreLocalVsRemote, int typeNumStart) {
      boolean foundAny = false;
      int typeNum = typeNumStart;
      for (int i = 0; i < RequestType_values.length; i++) {
        RequestType type = RequestType_values[typeNum];
        if (LOG.isDebugEnabled()) LOG.debug("Checking slot waiter list for {}", type);
        Decision d = evaluateForType(type, loadStats, ignoreLocalVsRemote, typeNum);
        if (d == null) return false; // early-exit conditions inside evaluator
        if (d.slot != null) {
          d.slot.unregister(PeerNode.this, d.peersForSuccessfulSlot);
          if (LOG.isDebugEnabled())
            LOG.debug(
                STR_ACCEPT_STATE_IS + "{}" + STR_FOR + "{} - waking up", d.acceptState, d.slot);
        }
        foundAny = foundAny || d.foundOne;
        typeNum = nextTypeIndex(typeNum);
      }
      return foundAny;
    }

    private int nextTypeIndex(int current) {
      current++;
      if (current == RequestType_values.length) current = 0;
      return current;
    }

    private record Decision(
        SlotWaiter slot,
        RequestLikelyAcceptedState acceptState,
        PeerNode[] peersForSuccessfulSlot,
        boolean foundOne) {

      private Decision(
          SlotWaiter slot,
          RequestLikelyAcceptedState acceptState,
          PeerNode[] peersForSuccessfulSlot,
          boolean foundOne) {
        this.slot = slot;
        this.acceptState = acceptState;
        this.peersForSuccessfulSlot =
            peersForSuccessfulSlot == null ? new PeerNode[0] : peersForSuccessfulSlot;
        this.foundOne = foundOne;
      }

      @Override
      public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o
            instanceof
            Decision(
                var otherSlot,
                var otherAcceptState,
                var otherPeersForSuccessfulSlot,
                var otherFoundOne))) return false;
        return foundOne == otherFoundOne
            && java.util.Objects.equals(slot, otherSlot)
            && acceptState == otherAcceptState
            && java.util.Arrays.equals(peersForSuccessfulSlot, otherPeersForSuccessfulSlot);
      }

      @Override
      public int hashCode() {
        int result = java.util.Objects.hash(slot, acceptState, foundOne);
        result = 31 * result + java.util.Arrays.hashCode(peersForSuccessfulSlot);
        return result;
      }

      @Override
      public @NotNull String toString() {
        return "Decision[slot="
            + slot
            + ", acceptState="
            + acceptState
            + ", peersForSuccessfulSlot="
            + java.util.Arrays.toString(peersForSuccessfulSlot)
            + ", foundOne="
            + foundOne
            + "]";
      }
    }

    private Decision evaluateForType(
        RequestType type, PeerLoadStats loadStats, boolean ignoreLocalVsRemote, int typeNum) {
      SlotWaiterList list;
      SlotWaiter slot = null;
      RequestLikelyAcceptedState acceptState;
      PeerNode[] peersForSuccessfulSlot = null;
      synchronized (routedToLock) {
        list = slotWaiters.get(type);
        if (list == null || list.isEmpty()) {
          if (LOG.isDebugEnabled()) LOG.debug(list == null ? "No list" : "List empty");
          return new Decision(null, null, null, false);
        }
        if (LOG.isDebugEnabled()) LOG.debug("Checking slot waiters for {}", type);
        RunningRequestsSnapshot runningRequests =
            node.getNodeStats().getRunningRequestsTo(PeerNode.this, realTime);
        runningRequests.log(PeerNode.this);
        RunningRequestsSnapshot otherRunningRequests = loadStats.getOtherRunningRequests();
        acceptState =
            computeAcceptState(
                runningRequests, otherRunningRequests, ignoreLocalVsRemote, loadStats);
        if (shouldEarlyExit(acceptState, type)) return null; // early exit
        if (!list.isEmpty()) {
          SlotWakeResult r = maybePopSlot(list, acceptState, typeNum);
          slot = r.slot;
          peersForSuccessfulSlot = r.peersForSuccessfulSlot;
        }
      }
      return new Decision(slot, acceptState, peersForSuccessfulSlot, true);
    }

    private RequestLikelyAcceptedState computeAcceptState(
        RunningRequestsSnapshot runningRequests,
        RunningRequestsSnapshot otherRunningRequests,
        boolean ignoreLocalVsRemote,
        PeerLoadStats loadStats) {
      return getRequestLikelyAcceptedState(
          runningRequests, otherRunningRequests, ignoreLocalVsRemote, loadStats);
    }

    private boolean shouldEarlyExit(RequestLikelyAcceptedState acceptState, RequestType type) {
      if (acceptState == RequestLikelyAcceptedState.UNLIKELY) {
        if (LOG.isDebugEnabled())
          LOG.debug(STR_ACCEPT_STATE_IS + "{} - not waking up - type is {}", acceptState, type);
        return true;
      }
      if (dontSendUnlessGuaranteed && acceptState != RequestLikelyAcceptedState.GUARANTEED) {
        if (LOG.isDebugEnabled())
          LOG.debug(
              "Not accepting until guaranteed for {}" + STR_REALTIME_EQ + "{}",
              PeerNode.this,
              realTime);
        return true;
      }
      return false;
    }

    private record SlotWakeResult(SlotWaiter slot, PeerNode[] peersForSuccessfulSlot) {
      @Override
      public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof SlotWakeResult(var otherSlot, var otherPeers))) return false;
        return java.util.Objects.equals(slot, otherSlot)
            && java.util.Arrays.equals(peersForSuccessfulSlot, otherPeers);
      }

      @Override
      public int hashCode() {
        int result = java.util.Objects.hash(slot);
        result = 31 * result + java.util.Arrays.hashCode(peersForSuccessfulSlot);
        return result;
      }

      @Override
      public @NotNull String toString() {
        return "SlotWakeResult[slot="
            + slot
            + ", peersForSuccessfulSlot="
            + java.util.Arrays.toString(peersForSuccessfulSlot)
            + "]";
      }
    }

    private SlotWakeResult maybePopSlot(
        SlotWaiterList list, RequestLikelyAcceptedState acceptState, int typeNum) {
      SlotWaiter slot = list.removeFirst();
      if (LOG.isDebugEnabled())
        LOG.debug(
            STR_ACCEPT_STATE_IS + "{}" + STR_FOR + "{} - waking up on {}", acceptState, slot, this);
      PeerNode[] peersForSuccessfulSlot = slot.innerOnWaited(PeerNode.this, acceptState);
      if (peersForSuccessfulSlot.length > 0) {
        reportAllocated(slot.isLocal());
        slotWaiterTypeCounter = typeNum;
        return new SlotWakeResult(slot, peersForSuccessfulSlot);
      }
      return new SlotWakeResult(null, new PeerNode[0]);
    }

    /**
     * LOCKING: Call inside routedToLock.
     *
     * @param runningRequests snapshot of this peer's running requests
     * @param otherRunningRequests snapshot of other peers' running requests
     * @param ignoreLocalVsRemote whether to ignore local vs remote origin when evaluating
     * @param stats most recent load statistics for this peer
     */
    private RequestLikelyAcceptedState getRequestLikelyAcceptedState(
        RunningRequestsSnapshot runningRequests,
        RunningRequestsSnapshot otherRunningRequests,
        boolean ignoreLocalVsRemote,
        PeerLoadStats stats) {
      RequestLikelyAcceptedState outputState =
          getRequestLikelyAcceptedStateBandwidth(
              false, runningRequests, otherRunningRequests, ignoreLocalVsRemote, stats);
      RequestLikelyAcceptedState inputState =
          getRequestLikelyAcceptedStateBandwidth(
              true, runningRequests, otherRunningRequests, ignoreLocalVsRemote, stats);
      RequestLikelyAcceptedState transfersState =
          getRequestLikelyAcceptedStateTransfers(runningRequests, otherRunningRequests, stats);
      RequestLikelyAcceptedState ret = inputState;

      if (outputState.ordinal() > ret.ordinal()) ret = outputState;
      if (transfersState.ordinal() > ret.ordinal()) ret = transfersState;
      return ret;
    }

    private RequestLikelyAcceptedState getRequestLikelyAcceptedStateBandwidth(
        boolean input,
        RunningRequestsSnapshot runningRequests,
        RunningRequestsSnapshot otherRunningRequests,
        boolean ignoreLocalVsRemote,
        PeerLoadStats stats) {
      double ourUsage = runningRequests.calculate(ignoreLocalVsRemote, input);
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Our usage is {} peer limit is {} lower limit is {} realtime {} input {}",
            ourUsage,
            stats.peerLimit(input),
            stats.lowerLimit(input),
            realTime,
            input);
      if (ourUsage < stats.peerLimit(input)) return RequestLikelyAcceptedState.GUARANTEED;
      otherRunningRequests.log(PeerNode.this);
      double theirUsage = otherRunningRequests.calculate(ignoreLocalVsRemote, input);
      if (LOG.isDebugEnabled()) LOG.debug("Their usage is {}", theirUsage);
      if (ourUsage + theirUsage < stats.lowerLimit(input)) return RequestLikelyAcceptedState.LIKELY;
      else return RequestLikelyAcceptedState.UNLIKELY;
    }

    private RequestLikelyAcceptedState getRequestLikelyAcceptedStateTransfers(
        RunningRequestsSnapshot runningRequests,
        RunningRequestsSnapshot otherRunningRequests,
        PeerLoadStats stats) {

      int ourUsage = runningRequests.totalOutTransfers();
      int maxTransfersOutPeerLimit =
          Math.min(stats.maxTransfersOutPeerLimit, stats.maxTransfersOut);
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Our usage is {} peer limit is {} lower limit is {} realtime {}",
            ourUsage,
            maxTransfersOutPeerLimit,
            stats.maxTransfersOutLowerLimit,
            realTime);
      if (ourUsage < maxTransfersOutPeerLimit) return RequestLikelyAcceptedState.GUARANTEED;
      otherRunningRequests.log(PeerNode.this);
      int theirUsage = otherRunningRequests.totalOutTransfers();
      if (LOG.isDebugEnabled()) LOG.debug("Their usage is {}", theirUsage);
      if (ourUsage + theirUsage < stats.maxTransfersOutLowerLimit)
        return RequestLikelyAcceptedState.LIKELY;
      else return RequestLikelyAcceptedState.UNLIKELY;
    }

    public void setDontSendUnlessGuaranteed() {
      synchronized (routedToLock) {
        if (!dontSendUnlessGuaranteed) {
          LOG.error(
              "Setting don't-send-unless-guaranteed for {}" + STR_REALTIME_EQ + "{}",
              PeerNode.this,
              realTime);
          dontSendUnlessGuaranteed = true;
        }
      }
    }

    public void clearDontSendUnlessGuaranteed() {
      synchronized (routedToLock) {
        if (dontSendUnlessGuaranteed) {
          LOG.error(
              "Clearing don't-send-unless-guaranteed for {}" + STR_REALTIME_EQ + "{}",
              PeerNode.this,
              realTime);
          dontSendUnlessGuaranteed = false;
        }
      }
    }
  }

  /**
   * Stops routing the given request through this peer.
   *
   * @param tag the request identifier
   * @param offeredKey whether this was an offered key fetch
   */
  public void noLongerRoutingTo(UIDTag tag, boolean offeredKey) {
    if (offeredKey && !(tag instanceof RequestTag))
      throw new IllegalArgumentException("Only requests can have offeredKey=true");
    synchronized (routedToLock) {
      if (offeredKey) tag.removeFetchingOfferedKeyFrom(this);
      else tag.removeRoutingTo(this);
    }
    if (LOG.isDebugEnabled()) LOG.debug("No longer routing {} to {}", tag, this);
    outputLoadTracker(tag.realTimeFlag).maybeNotifySlotWaiter();
  }

  public void postUnlock(UIDTag tag) {
    outputLoadTracker(tag.realTimeFlag).maybeNotifySlotWaiter();
  }

  static SlotWaiter createSlotWaiter(
      UIDTag tag, RequestType type, boolean realTime, PeerNode source) {
    return new SlotWaiter(tag, type, realTime, source);
  }

  public IncomingLoadSummaryStats getIncomingLoadStats(boolean realTime) {
    return outputLoadTracker(realTime).getIncomingLoadStats();
  }

  /**
   * Handles a fatal timeout for a specific request routed to this peer.
   *
   * @param tag the request identifier
   * @param offeredKey whether this was an offered key fetch
   */
  public void fatalTimeout(UIDTag tag, boolean offeredKey) {
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
   * node. Also, if it doesn't arrive in a reasonable time maybe there has been a severe problem
   * e.g. out of memory, bug etc.; in that case, waiting forever may not be sensible. 3) Disconnect
   * the node. This makes perfect sense for opennet. For darknet it's a bit more problematic. 4)
   * Turn off routing to the node, possibly for a limited period. This would need to include the
   * effects of disconnection. It might open up some cheapish local DoS's.
   *
   * <p>For all nodes, at present, we disconnect. For darknet nodes, we log an error, and allow them
   * to reconnect.
   */
  public abstract void fatalTimeout();

  public abstract boolean shallWeRouteAccordingToOurPeersLocation(int htl);

  @Override
  public PeerMessageQueue getMessageQueue() {
    return messageQueue;
  }

  public boolean handleReceivedPacket(byte[] buf, int offset, int length, long now, Peer replyTo) {
    PacketFormat pf;
    synchronized (this) {
      pf = packetFormat;
      if (pf == null) return false;
    }
    return pf.handleReceivedPacket(buf, offset, length, now, replyTo);
  }

  public void checkForLostPackets() {
    PacketFormat pf;
    synchronized (this) {
      pf = packetFormat;
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
      pf = packetFormat;
      if (pf == null) return Long.MAX_VALUE;
    }
    return pf.timeCheckForLostPackets();
  }

  /**
   * Drops references to a session key when it is considered broken.
   *
   * <p>Only called for new-format connections where per-key packet tracking is not used. Updates
   * connected state when the current key is dropped.
   *
   * @param brokenKey session key to discard
   */
  @SuppressWarnings("unused")
  public void dumpTracker(SessionKey brokenKey) {
    long now = System.currentTimeMillis();
    synchronized (this) {
      if (currentTracker == brokenKey) {
        currentTracker = null;
        isConnected.set(false, now);
      } else if (previousTracker == brokenKey) previousTracker = null;
      else if (unverifiedTracker == brokenKey) unverifiedTracker = null;
    }
    // Update connected vs not connected status.
    isConnected();
    setPeerNodeStatus(System.currentTimeMillis());
  }

  @Override
  public void handleMessage(Message m) {
    node.getUSM().checkFilters(m, crypto.getSocket());
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
    node.getOutputThrottle().forceGrab(count);
  }

  @Override
  public void onNotificationOnlyPacketSent(int length) {
    node.getNodeStats().reportNotificationOnlyPacketSent(length);
  }

  @Override
  public void resentBytes(int length) {
    resendByteCounter.sentBytes(length);
  }

  // Note: consider moving this to PacketFormat in the future.
  @Override
  public Random paddingGen() {
    return random;
  }

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
   * Does this PeerNode match the given IP address?
   *
   * @param addr address to test
   * @param strict If true, only match if the IP is actually in use. If false, also match from
   *     nominal IP addresses and domain names etc.
   */
  public synchronized boolean matchesIP(FreenetInetAddress addr, boolean strict) {
    return strict ? strictMatch(addr) : nonStrictMatch(addr);
  }

  private boolean strictMatch(FreenetInetAddress addr) {
    Peer p = getPeer();
    if (p == null) return false;
    FreenetInetAddress a = p.getFreenetAddress();
    return a != null && a.equals(addr);
  }

  private boolean nonStrictMatch(FreenetInetAddress addr) {
    Peer p = getPeer();
    if (p != null) {
      FreenetInetAddress a = p.getFreenetAddress();
      if (a != null && a.laxEquals(addr)) return true;
    }
    if (nominalPeer != null) {
      for (Peer np : nominalPeer) {
        if (np != null) {
          FreenetInetAddress a = np.getFreenetAddress();
          if (a != null && a.laxEquals(addr)) return true;
        }
      }
    }
    return false;
  }

  @Override
  public DecodingMessageGroup startProcessingDecryptedMessages(int size) {
    return new MyDecodingMessageGroup(size);
  }

  class MyDecodingMessageGroup implements DecodingMessageGroup {

    private final ArrayList<Message> messages;
    private final ArrayList<Message> messagesWantSomething;

    public MyDecodingMessageGroup(int size) {
      messages = new ArrayList<>(size);
      messagesWantSomething = new ArrayList<>(size);
    }

    @Override
    public void processDecryptedMessage(byte[] data, int offset, int length, int overhead) {
      Message m = node.getUSM().decodeSingleMessage(data, offset, length, PeerNode.this, overhead);
      if (m == null) {
        if (LOG.isDebugEnabled())
          LOG.debug(
              "Message not decoded from {} ({})", PeerNode.this, PeerNode.this.getBuildNumber());
        return;
      }
      if (DMT.isPeerLoadStatusMessage(m)) {
        handleMessage(m);
        return;
      }
      if (DMT.isLoadLimitedRequest(m)) {
        messagesWantSomething.add(m);
      } else {
        messages.add(m);
      }
    }

    @Override
    public void complete() {
      for (Message msg : messages) {
        handleMessage(msg);
      }
      for (Message msg : messagesWantSomething) {
        handleMessage(msg);
      }
    }
  }

  public boolean isLowCapacity(boolean isRealtime) {
    PeerLoadStats stats = outputLoadTracker(isRealtime).getLastIncomingLoadStats();
    if (stats == null) return false;
    NodePinger pinger = node.getNodeStats().nodePinger;
    if (pinger == null) return false; // Note: pinger can be null in some environments.
    if (pinger.capacityThreshold(isRealtime, true) > stats.peerLimit(true)) return true;
    return pinger.capacityThreshold(isRealtime, false) > stats.peerLimit(false);
  }

  public void reportRoutedTo(
      double target,
      boolean isLocal,
      boolean realTime,
      PeerNode prev,
      Set<PeerNode> routedTo,
      int htl) {
    double distance = Location.distance(target, getLocation());

    double myLoc = node.getLocation();
    double prevLoc;
    if (prev != null) prevLoc = prev.getLocation();
    else prevLoc = -1.0;

    Set<Double> excludeLocations = new HashSet<>();
    excludeLocations.add(myLoc);
    excludeLocations.add(prevLoc);
    for (PeerNode routedToNode : routedTo) {
      excludeLocations.add(routedToNode.getLocation());
    }

    if (shallWeRouteAccordingToOurPeersLocation(htl)) {
      double l = getClosestPeerLocation(target, excludeLocations);
      if (!Double.isNaN(l)) {
        double newDiff = Location.distance(l, target);
        if (newDiff < distance) {
          distance = newDiff;
        }
      }
      if (LOG.isDebugEnabled())
        LOG.debug(
            "The peer {} has published his peer's locations and the closest we have found to the"
                + " target is {} away.",
            this,
            distance);
    }

    node.getNodeStats().routingMissDistanceOverall.report(distance);
    (isLocal
            ? node.getNodeStats().routingMissDistanceLocal
            : node.getNodeStats().routingMissDistanceRemote)
        .report(distance);
    (realTime
            ? node.getNodeStats().routingMissDistanceRT
            : node.getNodeStats().routingMissDistanceBulk)
        .report(distance);
    node.getPeers().incrementSelectionSamples(this);
  }

  private long maxPeerPingTime() {
    if (node == null) return NodeStats.DEFAULT_MAX_PING_TIME * 2;
    NodeStats stats = node.getNodeStats();
    if (node.getNodeStats() == null) return NodeStats.DEFAULT_MAX_PING_TIME * 2;
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
  // resilience; current approach relies on natural failure behavior.

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
   * Marks completion of a UOM jar send.
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

  protected synchronized long timeSinceSentUOM() {
    if (sendingUOMMainJar || sendingUOMLegacyExtJar) return 0;
    if (uomCount > 0) return 0;
    if (lastSentUOM <= 0) return Long.MAX_VALUE;
    return System.currentTimeMillis() - lastSentUOM;
  }

  public synchronized void incrementUOMSends() {
    uomCount++;
  }

  public synchronized void decrementUOMSends() {
    uomCount--;
    if (uomCount == 0 && (!sendingUOMMainJar) && (!sendingUOMLegacyExtJar))
      lastSentUOM = System.currentTimeMillis();
  }

  /**
   * Get the boot ID for purposes of the other node. This is set to a random number on startup, but
   * also whenever we disconnected(true,...) i.e. whenever we dump the message queues and
   * PacketFormat's.
   */
  public synchronized long getOutgoingBootID() {
    return this.myBootID;
  }

  private long lastIncomingRekey;

  static final long THROTTLE_REKEY = 1000;

  public synchronized boolean throttleRekey() {
    long now = System.currentTimeMillis();
    if (now - lastIncomingRekey < THROTTLE_REKEY) {
      LOG.error("Two rekeys initiated by other side within " + THROTTLE_REKEY + "ms");
      return true;
    }
    lastIncomingRekey = now;
    return false;
  }

  public boolean fullPacketQueued() {
    PacketFormat pf;
    synchronized (this) {
      pf = packetFormat;
      if (pf == null) return false;
    }
    return pf.fullPacketQueued(getMaxPacketSize());
  }

  public long timeSendAcks() {
    PacketFormat pf;
    synchronized (this) {
      pf = packetFormat;
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
    // First get usable bandwidth.
    double bandwidth = (getThrottle().getBandwidth() + 1.0);
    if (shouldThrottle())
      bandwidth = Math.min(bandwidth, (double) node.getOutputBandwidthLimit() / 2);
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

  public synchronized boolean hasFullNoderef() {
    return fullFieldSet != null;
  }

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
   * requests which completed since the request was sent. CON: This would be rather complex, and I'm
   * not sure how well it would work when there are many requests in flight; would it even be
   * possible without stopping sending requests after some arbitrary threshold? We might need a time
   * element, and would probably need parameters... SOLUTION B: Enforcing a hard peer limit on both
   * sides, as opposed to accepting a request if the *current* usage, without the new request, is
   * over the limit. CON: This would break fairness between request types.
   *
   * <p>Of course, the problem with just using a counter is it may need to be changed frequently ...
   * Note: a better solution may exist; counter-based approach retained for simplicity.
   *
   * <p>Fortunately, this is pretty rare. It happens when e.g. we send an SSK, then we send a CHK,
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

  /**
   * @return The largest throttle window size of our throttles. This is just for guesstimating how
   *     many blocks we can have in flight.
   */
  @Override
  public int getThrottleWindowSize() {
    PacketThrottle throttle = getThrottle();
    if (throttle != null) return (int) (Math.min(throttle.getWindowSize(), Integer.MAX_VALUE));
    else return Integer.MAX_VALUE;
  }

  @SuppressWarnings("UnusedReturnValue")
  private boolean verifyReferenceSignature(SimpleFieldSet fs)
      throws ReferenceSignatureVerificationException {
    // Assume we failed at validating
    boolean failed;
    String signatureP256 = fs.get(SFS_KEY_SIG_P256);
    try {
      // If we have:
      // - the new P256 signature AND the P256 pubkey
      // OR
      // - the old DSA signature the pubkey and the groups
      // THEN
      // verify the signatures
      fs.removeValue("sig");
      fs.removeValue(SFS_KEY_SIG_P256);
      byte[] toVerifyECDSA = fs.toOrderedString().getBytes(StandardCharsets.UTF_8);

      boolean isECDSAsigPresent = (signatureP256 != null && peerECDSAPubKey != null);
      boolean verifyECDSA = false; // assume it failed.

      // Is there a new ECDSA sig?
      if (isECDSAsigPresent) {
        fs.putSingle(SFS_KEY_SIG_P256, signatureP256);
        verifyECDSA =
            ECDSA.verify(Curves.P256, peerECDSAPubKey, Base64.decode(signatureP256), toVerifyECDSA);
      }

      // If there is no signature, FAIL
      // If there is an ECDSA signature, and it doesn't verify, FAIL
      boolean hasNoSignature = (!isECDSAsigPresent);
      boolean isECDSAsigInvalid = (isECDSAsigPresent && !verifyECDSA);
      failed = hasNoSignature || isECDSAsigInvalid;
      if (failed) {
        String errCause = "";
        if (hasNoSignature) errCause += " (No signature)";
        if (isECDSAsigInvalid) errCause += " (ECDSA signature is invalid)";
        errCause += " (VERIFICATION FAILED)";
        LOG.atError()
            .addArgument(errCause)
            .addArgument(fs::toOrderedString)
            .log("The integrity of the reference has been compromised!{} fs was\n{}");
        this.isSignatureVerificationSuccessfull = false;
        throw new ReferenceSignatureVerificationException(
            "The integrity of the reference has been compromised!" + errCause);
      } else {
        this.isSignatureVerificationSuccessfull = true;
        if (!dontKeepFullFieldSet()) this.fullFieldSet = fs;
      }
    } catch (IllegalBase64Exception e) {
      LOG.error("Invalid reference: {}", e, e);
      throw new ReferenceSignatureVerificationException(
          "The node reference you added is invalid: It does not have a valid ECDSA signature.");
    }
    return true;
  }

  protected final byte[] getPubKeyHash() {
    return peerECDSAPubKeyHash;
  }

  RunningAverage getBackedOffPercentRT() {
    return backedOffPercentRT;
  }

  RunningAverage getBackedOffPercentBulk() {
    return backedOffPercentBulk;
  }
}

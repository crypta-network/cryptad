package network.crypta.node;

import static java.util.concurrent.TimeUnit.DAYS;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.InflaterInputStream;
import network.crypta.client.DefaultMIMETypes;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.DisconnectedException;
import network.crypta.io.comm.FreenetInetAddress;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.NotConnectedException;
import network.crypta.io.comm.Peer;
import network.crypta.io.comm.RetrievalException;
import network.crypta.io.xfer.BulkReceiver;
import network.crypta.io.xfer.BulkTransmitter;
import network.crypta.io.xfer.PartiallyReceivedBulk;
import network.crypta.keys.FreenetURI;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.useralerts.AbstractNodeToNodeFileOfferUserAlert;
import network.crypta.node.useralerts.BookmarkFeedUserAlert;
import network.crypta.node.useralerts.DownloadFeedUserAlert;
import network.crypta.node.useralerts.N2NTMUserAlert;
import network.crypta.node.useralerts.NodeToNodeAlertContext;
import network.crypta.node.useralerts.UserAlert;
import network.crypta.support.Base64;
import network.crypta.support.HTMLNode;
import network.crypta.support.IllegalBase64Exception;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.SizeUtil;
import network.crypta.support.api.HTTPUploadedFile;
import network.crypta.support.api.RandomAccessBuffer;
import network.crypta.support.io.BucketTools;
import network.crypta.support.io.ByteArrayRandomAccessBuffer;
import network.crypta.support.io.FileRandomAccessBuffer;
import network.crypta.support.io.FileUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A darknet (friend-to-friend) peer connection.
 *
 * <p>This class extends {@link PeerNode} with behaviors specific to manually added friends
 * ("darknet"). It manages handshake policy (disabled/listen-only/burst-only), visibility and trust
 * levels, optional LAN/localhost allowances, handling of extra peer data files (notes, queued
 * node-to-node messages, feeds), lightweight node-to-node messaging, and user-facing file offer
 * flows. Methods that modify persisted peer metadata notify {@link PeerManager} so the on-disk
 * peers list remains consistent.
 */
@SuppressWarnings({
  "java:S2160",
  "java:S1206"
}) // hashCode() is inherited; equals() restricts to subclass type
public final class DarknetPeerNode extends PeerNode {
  private static final Logger LOG = LoggerFactory.getLogger(DarknetPeerNode.class);

  // Sonar: de-duplicate repeated string literals
  private static final String FS_KEY_MY_NAME = "myName";
  private static final String LOG_FOR = " for ";
  private static final String SFS_KEY_EXTRA_PEER_DATA_TYPE = "extraPeerDataType";
  private static final String SFS_KEY_N2N_TYPE = "n2nType";
  private static final String SFS_KEY_SENDER_FILE_NUMBER = "senderFileNumber";
  private static final String SFS_KEY_SENT_TIME = "sentTime";
  private static final String SFS_KEY_RECEIVED_TIME = "receivedTime";
  private static final String FS_KEY_FILENAME = "filename";
  private static final String L10N_FILE_LABEL = "fileLabel";
  private static final String L10N_SIZE_LABEL = "sizeLabel";
  private static final String L10N_MIME_LABEL = "mimeLabel";
  private static final String L10N_SENDER_LABEL = "senderLabel";
  private static final String L10N_COMMENT_LABEL = "commentLabel";
  private static final String L10N_FILE_OFFER_PREFIX = "FileOffer.";
  // Sonar: de-duplicate repeated HTML literals
  private static final String HTML_TAG_INPUT = "input";
  private static final String HTML_ATTR_VALUE = "value";
  // Sonar: deduplicate repeated SimpleFieldSet keys
  private static final String FS_KEY_COMPOSED_TIME = "composedTime";
  private static final String FS_KEY_DESCRIPTION = "Description";

  /** Name of this node */
  String myName;

  /** True if this peer is not to be connected with */
  private boolean isDisabled;

  /** True if we don't send handshake requests to this peer, but will connect if we receive one */
  private boolean isListenOnly;

  /** True if we send handshake requests to this peer in infrequent bursts */
  private boolean isBurstOnly;

  /**
   * True if we want to ignore the source port of the node's sent packets. This is normally set when
   * dealing with an Evil Corporate Firewall which rewrites the port on outgoing packets but does
   * not redirect incoming packets destined to the rewritten port. What it does is this: If we have
   * an address with the same IP but a different port, to the detectedPeer, we use that instead.
   */
  private boolean ignoreSourcePort;

  /** True if we want to allow LAN/localhost addresses. */
  private boolean allowLocalAddresses;

  /** Extra peer data file numbers */
  private final LinkedHashSet<Integer> extraPeerDataFileNumbers;

  /** Private comment on the peer for /friends/ page */
  private String privateDarknetComment;

  /** Private comment on the peer for /friends/ page's extra peer data file number */
  private int privateDarknetCommentFileNumber;

  /** Queued-to-send N2NM extra peer data file numbers */
  private final LinkedHashSet<Integer> queuedToSendN2NMExtraPeerDataFileNumbers;

  private FRIEND_TRUST trustLevel;

  private FRIEND_VISIBILITY ourVisibility;
  private FRIEND_VISIBILITY theirVisibility;

  // no static initialization required

  /**
   * Trust level for a friend.
   *
   * <p>The trust level influences routing decisions (e.g., whether to route using a peer's
   * location) and certain UI defaults. Lower trust may disable some behaviors.
   */
  public enum FRIEND_TRUST {
    LOW,
    NORMAL,
    HIGH;

    private static final FRIEND_TRUST[] valuesBackwards;

    static {
      final FRIEND_TRUST[] values = values();
      valuesBackwards = new FRIEND_TRUST[values.length];
      for (int i = 0; i < values.length; i++) valuesBackwards[i] = values[values.length - i - 1];
    }

    /**
     * Returns the enum constants in reverse declaration order.
     *
     * @return a new array containing the constants from {@link #values()} reversed.
     */
    public static FRIEND_TRUST[] valuesBackwards() {
      return valuesBackwards.clone();
    }

    /**
     * Indicates whether this value is the default for new friends.
     *
     * @return {@code true} when equal to {@link #NORMAL}.
     */
    public boolean isDefaultValue() {
      return equals(FRIEND_TRUST.NORMAL);
    }
  }

  /**
   * Visibility preference for a friend.
   *
   * <p>The {@link #code} is serialized on the wire and must remain stable; do not change values or
   * rely on {@link Enum#ordinal()}.
   */
  public enum FRIEND_VISIBILITY {
    YES((short) 0), // Visible
    NAME_ONLY((short) 1), // Only the name is visible, but other friends can ask for a connection
    NO((short) 2); // Not visible to our other friends at all

    /**
     * The codes are persistent and used to communicate between nodes, so they must not change.
     * Which is why we are not using ordinal().
     */
    final short code;

    FRIEND_VISIBILITY(short code) {
      this.code = code;
    }

    /**
     * Compares this visibility against another for strictness.
     *
     * @param theirVisibility the other visibility or {@code null}.
     * @return {@code true} if this instance is stricter than {@code theirVisibility}, or if {@code
     *     theirVisibility} is {@code null}.
     */
    public boolean isStricterThan(FRIEND_VISIBILITY theirVisibility) {
      if (theirVisibility == null) return true;
      // Higher number = more strict.
      return theirVisibility.code < code;
    }

    /**
     * Resolves visibility by its stable serialized code.
     *
     * @param code stable on-the-wire code.
     * @return the matching visibility, or {@code null} if unknown.
     */
    public static FRIEND_VISIBILITY getByCode(short code) {
      for (FRIEND_VISIBILITY f : values()) {
        if (f.code == code) return f;
      }
      return null;
    }

    /**
     * Indicates whether this value is the default for new friends.
     *
     * @return {@code true} when equal to {@link #YES}.
     */
    public boolean isDefaultValue() {
      return equals(FRIEND_VISIBILITY.YES);
    }
  }

  /**
   * Creates a darknet peer from a serialized {@link SimpleFieldSet}.
   *
   * <p>When {@code fromLocal} is {@code true}, enforces local metadata (e.g., disabled/listen
   * only/burst settings, visibility, trust), otherwise applies the provided {@code trust} and
   * {@code visibility2} as initial values for a newly added friend.
   *
   * @param fs serialized noderef and metadata for the peer; must contain {@code myName}.
   * @param node2 owning {@link Node} instance.
   * @param crypto node cryptography context.
   * @param fromLocal whether {@code fs} originated from local disk (persisted peers) as opposed to
   *     a remote transmission.
   * @param trust initial trust, required when {@code fromLocal == false}.
   * @param visibility2 our initial visibility, used when {@code fromLocal == false}.
   * @param peers owning {@link PeerManager}.
   * @throws FSParseException if {@code fs} is malformed or missing required fields.
   */
  public DarknetPeerNode(
      SimpleFieldSet fs,
      Node node2,
      NodeCrypto crypto,
      boolean fromLocal,
      FRIEND_TRUST trust,
      FRIEND_VISIBILITY visibility2,
      PeerManager peers)
      throws FSParseException {
    super(prepareConstructorInit(fs, node2, crypto, fromLocal, peers, ConstructorProfile.DARKNET));

    String name = fs.get(FS_KEY_MY_NAME);
    if (name == null) throw new FSParseException("No name");
    myName = name;

    if (fromLocal) {
      initializeFromLocalMetadata(fs, name);
    } else {
      initializeFromRemoteDefaults(trust, visibility2);
    }

    // Set up the private darknet comment note
    privateDarknetComment = "";
    privateDarknetCommentFileNumber = -1;

    // Set up the extraPeerDataFileNumbers
    extraPeerDataFileNumbers = new LinkedHashSet<>();

    // Set up the queuedToSendN2NMExtraPeerDataFileNumbers
    queuedToSendN2NMExtraPeerDataFileNumbers = new LinkedHashSet<>();
  }

  private synchronized void initializeFromLocalMetadata(SimpleFieldSet fs, String name) {
    SimpleFieldSet metadata = fs.subset("metadata");
    if (metadata == null) metadata = new SimpleFieldSet(true);

    isDisabled = metadata.getBoolean("isDisabled", false);
    isListenOnly = metadata.getBoolean("isListenOnly", false);
    isBurstOnly = metadata.getBoolean("isBurstOnly", false);
    disableRouting =
        disableRoutingHasBeenSetLocally =
            metadata.getBoolean("disableRoutingHasBeenSetLocally", false);
    ignoreSourcePort = metadata.getBoolean("ignoreSourcePort", false);
    allowLocalAddresses = metadata.getBoolean("allowLocalAddresses", false);
    String s = metadata.get("trustLevel");
    if (s != null) {
      trustLevel = FRIEND_TRUST.valueOf(s);
    } else {
      trustLevel = node.services().securityLevels().getDefaultFriendTrust();
      LOG.info("Assuming friend ({}) trust is opposite of friend seclevel: {}", name, trustLevel);
    }
    s = metadata.get("ourVisibility");
    if (s != null) {
      ourVisibility = FRIEND_VISIBILITY.valueOf(s);
    } else {
      LOG.info("Assuming friend ({}) wants to be invisible", name);
      node.services().createVisibilityAlert();
      ourVisibility = FRIEND_VISIBILITY.NO;
    }
    s = metadata.get("theirVisibility");
    if (s != null) {
      theirVisibility = FRIEND_VISIBILITY.valueOf(s);
    } else {
      theirVisibility = FRIEND_VISIBILITY.NO;
    }
  }

  private synchronized void initializeFromRemoteDefaults(
      FRIEND_TRUST trust, FRIEND_VISIBILITY visibility2) {
    if (trust == null) throw new IllegalArgumentException();
    trustLevel = trust;
    ourVisibility = visibility2;
  }

  /**
   * Returns the effective contact address for this peer.
   *
   * <p>By default, this is the most recently observed address from inbound packets. When {@code
   * ignoreSourcePort} is enabled, the method prefers a noderef address with the same IP but a
   * different port (to compensate for firewalls/NAT rewriting the source port).
   *
   * @return the preferred {@link Peer} to contact, or {@code null} if unknown.
   */
  @Override
  public synchronized Peer getPeer() {
    Peer detectedPeer = super.getPeer();
    if (ignoreSourcePort) {
      FreenetInetAddress addr = detectedPeer == null ? null : detectedPeer.getFreenetAddress();
      int port = detectedPeer == null ? -1 : detectedPeer.getPort();
      List<Peer> localNominalPeer = nominalPeer.get();
      if (localNominalPeer == null) return detectedPeer;
      for (Peer p : localNominalPeer) {
        if (p.getPort() != port && p.getFreenetAddress().equals(addr)) {
          return p;
        }
      }
    }
    return detectedPeer;
  }

  /**
   * Determines whether we should attempt a handshake now.
   *
   * @return {@code true} if connected state and throttle/backoff allow sending a handshake attempt;
   *     {@code false} if disabled or listen-only, or if the superclass vetoes the attempt.
   */
  @Override
  public boolean shouldSendHandshake() {
    synchronized (this) {
      if (isDisabled) return false;
      if (isListenOnly) return false;
      if (!super.shouldSendHandshake()) return false;
    }
    return true;
  }

  /**
   * Incorporates name changes from a new noderef.
   *
   * @param fs noderef field set.
   * @param forARK whether this update is from an ARK fetch.
   * @param forDiffNodeRef whether this is a diff noderef.
   * @param forFullNodeRef whether this is a full noderef.
   * @return {@code true} if any peer attribute changed.
   * @throws FSParseException when a full noderef omits required fields (e.g., {@code myName}).
   */
  @Override
  protected synchronized boolean innerProcessNewNoderef(
      SimpleFieldSet fs, boolean forARK, boolean forDiffNodeRef, boolean forFullNodeRef)
      throws FSParseException {
    boolean changedAnything =
        super.innerProcessNewNoderef(fs, forARK, forDiffNodeRef, forFullNodeRef);
    String name = fs.get(FS_KEY_MY_NAME);
    if (name == null && forFullNodeRef) throw new FSParseException("No name in full noderef");
    if (name != null && !name.equals(myName)) {
      changedAnything = true;
      myName = name;
    }
    return changedAnything;
  }

  /**
   * Serializes the public noderef fields for this peer.
   *
   * @return a new {@link SimpleFieldSet} including {@code myName} and the base fields.
   */
  @Override
  public synchronized SimpleFieldSet exportFieldSet() {
    SimpleFieldSet fs = super.exportFieldSet();
    fs.putSingle(FS_KEY_MY_NAME, getName());
    return fs;
  }

  /**
   * Serializes local metadata for persistence.
   *
   * @param now wall-clock time used by the superclass for time-based fields.
   * @return a new {@link SimpleFieldSet} with local-only toggles (disabled/listen-only/burst-only,
   *     source-port and local-address allowances, routing flags), visibility, and trust.
   */
  @Override
  public synchronized SimpleFieldSet exportMetadataFieldSet(long now) {
    SimpleFieldSet fs = super.exportMetadataFieldSet(now);
    if (isDisabled) fs.putSingle("isDisabled", "true");
    if (isListenOnly) fs.putSingle("isListenOnly", "true");
    if (isBurstOnly) fs.putSingle("isBurstOnly", "true");
    if (ignoreSourcePort) fs.putSingle("ignoreSourcePort", "true");
    if (allowLocalAddresses) fs.putSingle("allowLocalAddresses", "true");
    if (disableRoutingHasBeenSetLocally) fs.putSingle("disableRoutingHasBeenSetLocally", "true");
    fs.putSingle("trustLevel", trustLevel.name());
    fs.putSingle("ourVisibility", ourVisibility.name());
    if (theirVisibility != null) fs.putSingle("theirVisibility", theirVisibility.name());

    return fs;
  }

  /**
   * Returns the human-assigned name of the peer as advertised in its noderef.
   *
   * @return non-null display name.
   */
  public synchronized String getName() {
    return myName;
  }

  /**
   * Computes the current status code used by UI and management endpoints.
   *
   * @param now current time in milliseconds since epoch.
   * @param backedOffUntilRT end time of RT backoff.
   * @param backedOffUntilBulk end time of bulk backoff.
   * @param overPingThreshold whether ping is beyond the acceptable threshold.
   * @param noLoadStats whether load statistics are unavailable.
   * @return a {@link PeerManager} status code (e.g., connected, disabled, listen-only).
   */
  @Override
  protected synchronized int getPeerNodeStatus(
      long now,
      long backedOffUntilRT,
      long backedOffUntilBulk,
      boolean overPingThreshold,
      boolean noLoadStats) {
    if (isDisabled) {
      return PeerManager.PEER_NODE_STATUS_DISABLED;
    }
    int status =
        super.getPeerNodeStatus(
            now, backedOffUntilRT, backedOffUntilBulk, overPingThreshold, noLoadStats);
    if (status == PeerManager.PEER_NODE_STATUS_CONNECTED
        || status == PeerManager.PEER_NODE_STATUS_CLOCK_PROBLEM
        || status == PeerManager.PEER_NODE_STATUS_ROUTING_BACKED_OFF
        || status == PeerManager.PEER_NODE_STATUS_CONN_ERROR
        || status == PeerManager.PEER_NODE_STATUS_TOO_NEW
        || status == PeerManager.PEER_NODE_STATUS_TOO_OLD
        || status == PeerManager.PEER_NODE_STATUS_ROUTING_DISABLED
        || status == PeerManager.PEER_NODE_STATUS_DISCONNECTING
        || status == PeerManager.PEER_NODE_STATUS_NO_LOAD_STATS) return status;
    if (isListenOnly) return PeerManager.PEER_NODE_STATUS_LISTEN_ONLY;
    if (isBurstOnly) return PeerManager.PEER_NODE_STATUS_LISTENING;
    return status;
  }

  /** Enables the peer and updates persisted metadata. */
  public void enablePeer() {
    synchronized (this) {
      isDisabled = false;
    }
    setPeerNodeStatus(System.currentTimeMillis());
    node.network().peers().writePeersDarknetUrgent();
  }

  /** Disables the peer, disconnects if needed, stops ARK fetching, and persists metadata. */
  public void disablePeer() {
    synchronized (this) {
      isDisabled = true;
    }
    if (isConnected()) {
      forceDisconnect();
    }
    stopARKFetcher();
    setPeerNodeStatus(System.currentTimeMillis());
    node.network().peers().writePeersDarknetUrgent();
  }

  /**
   * Returns whether this friend is disabled locally.
   *
   * @return {@code true} if disabled.
   */
  @Override
  public synchronized boolean isDisabled() {
    return isDisabled;
  }

  /**
   * Sets listen-only mode.
   *
   * <p>In listen-only mode we do not initiate handshakes, but we accept inbound connections. This
   * method clears burst-only if enabling listen-only.
   *
   * @param setting {@code true} to enable, {@code false} to disable.
   */
  public synchronized void setListenOnly(boolean setting) {
    isListenOnly = setting;
    if (setting && isBurstOnly()) {
      setBurstOnly(false);
    }
    if (setting) {
      stopARKFetcher();
    }
    setPeerNodeStatus(System.currentTimeMillis());
    node.network().peers().writePeersDarknetUrgent();
  }

  /**
   * Returns whether this peer is in listen-only mode.
   *
   * @return {@code true} if we do not actively handshake with the peer.
   */
  public synchronized boolean isListenOnly() {
    return isListenOnly;
  }

  /**
   * Sets burst-only mode.
   *
   * <p>When enabled, handshakes are attempted in occasional bursts. Enabling burst-only clears
   * listen-only. Disabling resets any long handshake delay grew under burst-only.
   *
   * @param setting {@code true} to enable, {@code false} to disable.
   */
  public void setBurstOnly(boolean setting) {
    synchronized (this) {
      isBurstOnly = setting;
    }
    if (setting && isListenOnly()) {
      setListenOnly(false);
    }
    long now = System.currentTimeMillis();
    if (!setting) {
      synchronized (this) {
        sendHandshakeTime =
            now; // don't keep any long handshake delays we might have had under BurstOnly
      }
    }
    setPeerNodeStatus(now);
    node.network().peers().writePeersDarknetUrgent();
  }

  /**
   * Enables ignoring the observed source port when selecting a contact address.
   *
   * @param setting {@code true} to prefer noderef port over observed source port.
   */
  public void setIgnoreSourcePort(boolean setting) {
    synchronized (this) {
      ignoreSourcePort = setting;
    }
  }

  /**
   * Changes whether we accept routed traffic from/to this peer.
   *
   * @param shouldRoute {@code true} to enable routing via this peer; {@code false} to disable.
   * @param localRequest {@code true} when invoked locally (e.g., UI) to notify the peer; {@code
   *     false} when applying a remote update so no notification is sent.
   */
  public void setRoutingStatus(boolean shouldRoute, boolean localRequest) {
    synchronized (this) {
      if (localRequest) disableRoutingHasBeenSetLocally = !shouldRoute;
      else disableRoutingHasBeenSetRemotely = !shouldRoute;

      disableRouting = disableRoutingHasBeenSetLocally || disableRoutingHasBeenSetRemotely;
    }

    if (localRequest) {
      Message msg = DMT.createRoutingStatus(shouldRoute);
      try {
        transport().sendAsync(msg, null, node.network().stats().setRoutingStatusCtr);
      } catch (NotConnectedException _) {
        // ok
      }
    }
    setPeerNodeStatus(System.currentTimeMillis());
    node.network().peers().writePeersDarknetUrgent();
  }

  /** Returns whether the observed source port is ignored when picking a contact address. */
  @Override
  public synchronized boolean isIgnoreSource() {
    return ignoreSourcePort;
  }

  /** Returns whether burst-only mode is active for this peer. */
  @Override
  public boolean isBurstOnly() {
    synchronized (this) {
      if (isBurstOnly) return true;
    }
    return super.isBurstOnly();
  }

  /** Returns whether LAN/localhost addresses are permitted for this peer. */
  @Override
  public boolean allowLocalAddresses() {
    synchronized (this) {
      if (allowLocalAddresses) return true;
    }
    return super.allowLocalAddresses();
  }

  /**
   * Allows or forbids LAN/localhost addresses for this peer.
   *
   * @param setting {@code true} to allow local addresses; {@code false} to forbid.
   */
  public void setAllowLocalAddresses(boolean setting) {
    synchronized (this) {
      allowLocalAddresses = setting;
    }
    node.network().peers().writePeersDarknetUrgent();
  }

  /**
   * Loads and parses extra peer data files from disk.
   *
   * @return {@code true} if all files were parsed successfully; {@code false} if any parse failed
   *     (errors are logged).
   */
  @SuppressWarnings("UnusedReturnValue")
  public boolean readExtraPeerData() {
    String extraPeerDataDirPath = node.getExtraPeerDataDir();
    File extraPeerDataPeerDir =
        new File(extraPeerDataDirPath + File.separator + getIdentityString());
    if (!extraPeerDataPeerDir.exists()) {
      return false;
    }
    if (!extraPeerDataPeerDir.isDirectory()) {
      LOG.error(
          "Extra peer data directory is not a directory while listing files: {}",
          extraPeerDataPeerDir.getPath());
      return false;
    }
    File[] extraPeerDataFiles = extraPeerDataPeerDir.listFiles();
    if (extraPeerDataFiles == null) {
      return false;
    }
    boolean gotError = false;
    boolean readResult;
    for (File extraPeerDataFile : extraPeerDataFiles) {
      int fileNumber;
      try {
        fileNumber = Integer.parseInt(extraPeerDataFile.getName());
      } catch (NumberFormatException _) {
        gotError = true;
        continue;
      }
      synchronized (extraPeerDataFileNumbers) {
        extraPeerDataFileNumbers.add(fileNumber);
      }
      readResult = readExtraPeerDataFile(extraPeerDataFile, fileNumber);
      if (!readResult) {
        gotError = true;
      }
    }
    return !gotError;
  }

  /**
   * Re-reads a single extra peer data file from the disk and re-applies its effect.
   *
   * @param fileNumber file identifier within the peer's extra-data directory.
   * @return {@code true} on success; {@code false} if the file was missing or invalid.
   */
  @SuppressWarnings("UnusedReturnValue")
  public boolean rereadExtraPeerDataFile(int fileNumber) {
    if (LOG.isDebugEnabled())
      LOG.debug("Rereading peer data file {}" + LOG_FOR + "{}", fileNumber, shortToString());
    String extraPeerDataDirPath = node.getExtraPeerDataDir();
    File extraPeerDataPeerDir =
        new File(extraPeerDataDirPath + File.separator + getIdentityString());
    if (!extraPeerDataPeerDir.exists()) {
      LOG.error(
          "Extra peer data directory missing while rereading file: {}",
          extraPeerDataPeerDir.getPath());
      return false;
    }
    if (!extraPeerDataPeerDir.isDirectory()) {
      LOG.error(
          "Extra peer data directory not a directory while rereading file: {}",
          extraPeerDataPeerDir.getPath());
      return false;
    }
    File extraPeerDataFile =
        new File(
            extraPeerDataDirPath
                + File.separator
                + getIdentityString()
                + File.separator
                + fileNumber);
    if (!extraPeerDataFile.exists()) {
      LOG.error(
          "Extra peer data file missing while rereading file: {}", extraPeerDataFile.getPath());
      return false;
    }
    return readExtraPeerDataFile(extraPeerDataFile, fileNumber);
  }

  /**
   * Reads and applies a specific extra peer data file.
   *
   * @param extraPeerDataFile path to the file.
   * @param fileNumber numeric identifier used for logging and follow-up actions.
   * @return {@code true} if parsed and applied successfully; {@code false} otherwise.
   */
  public boolean readExtraPeerDataFile(File extraPeerDataFile, int fileNumber) {
    if (LOG.isDebugEnabled())
      LOG.debug("Reading {} : {}" + LOG_FOR + "{}", extraPeerDataFile, fileNumber, shortToString());
    boolean gotError = false;
    if (!extraPeerDataFile.exists()) {
      if (LOG.isDebugEnabled()) LOG.debug("Does not exist");
      return false;
    }
    LOG.info("extraPeerDataFile: {}", extraPeerDataFile.getPath());
    FileInputStream fis;
    try {
      fis = new FileInputStream(extraPeerDataFile);
    } catch (FileNotFoundException _) {
      LOG.info("Extra peer data file not found: {}", extraPeerDataFile.getPath());
      return false;
    }
    InputStreamReader isr = new InputStreamReader(fis, StandardCharsets.UTF_8);
    BufferedReader br = new BufferedReader(isr);
    SimpleFieldSet fs = null;
    try {
      // Read in the single SimpleFieldSet
      fs = new SimpleFieldSet(br, false, true);
    } catch (EOFException _) {
      // End of file, fine
    } catch (IOException e4) {
      LOG.error("Could not read extra peer data file: {}", e4, e4);
    } finally {
      try {
        br.close();
      } catch (IOException e5) {
        LOG.error("Ignoring {} caught reading {}", e5, extraPeerDataFile.getPath(), e5);
      }
    }
    if (fs == null) {
      LOG.info("Deleting corrupt (too short?) file: {}", extraPeerDataFile);
      deleteExtraPeerDataFile(fileNumber);
      return true;
    }
    boolean parseResult;
    try {
      parseResult = parseExtraPeerData(fs, extraPeerDataFile, fileNumber);
      if (!parseResult) {
        gotError = true;
      }
    } catch (FSParseException e2) {
      LOG.error("Could not parse extra peer data: {}\n{}", e2, fs, e2);
      gotError = true;
    }
    return !gotError;
  }

  private boolean parseExtraPeerData(SimpleFieldSet fs, File extraPeerDataFile, int fileNumber)
      throws FSParseException {
    String extraPeerDataTypeString = fs.get(SFS_KEY_EXTRA_PEER_DATA_TYPE);
    if (extraPeerDataTypeString == null) {
      LOG.error("Missing {} in file {}", SFS_KEY_EXTRA_PEER_DATA_TYPE, extraPeerDataFile.getPath());
      return false;
    }
    final int extraPeerDataType;
    try {
      extraPeerDataType = Integer.parseInt(extraPeerDataTypeString);
    } catch (NumberFormatException _) {
      LOG.error(
          "NumberFormatException parsing " + SFS_KEY_EXTRA_PEER_DATA_TYPE + " ({}) in file {}",
          extraPeerDataTypeString,
          extraPeerDataFile.getPath());
      return false;
    }

    switch (extraPeerDataType) {
      case Node.EXTRA_PEER_DATA_TYPE_N2NTM -> {
        node.messaging().handleNodeToNodeTextMessageSimpleFieldSet(fs, this, fileNumber);
        return true;
      }
      case Node.EXTRA_PEER_DATA_TYPE_PEER_NOTE -> {
        return handlePeerNote(fs, extraPeerDataFile, fileNumber);
      }
      case Node.EXTRA_PEER_DATA_TYPE_QUEUED_TO_SEND_N2NM -> {
        return handleQueuedToSendN2NM(fs, fileNumber);
      }
      case Node.EXTRA_PEER_DATA_TYPE_BOOKMARK -> {
        LOG.info("Read friend bookmark{}", fs);
        handleFproxyBookmarkFeed(fs, fileNumber);
        return true;
      }
      case Node.EXTRA_PEER_DATA_TYPE_DOWNLOAD -> {
        LOG.info("Read friend download{}", fs);
        handleFproxyDownloadFeed(fs, fileNumber);
        return true;
      }
      default -> {
        LOG.error(
            "Read unknown extra peer data type '{}' from file {}",
            extraPeerDataType,
            extraPeerDataFile.getPath());
        return false;
      }
    }
  }

  private boolean handlePeerNote(SimpleFieldSet fs, File extraPeerDataFile, int fileNumber) {
    String peerNoteTypeString = fs.get("peerNoteType");
    if (peerNoteTypeString == null) {
      LOG.error("Missing peerNoteType in file {}", extraPeerDataFile.getPath());
      return false;
    }
    final int peerNoteType;
    try {
      peerNoteType = Integer.parseInt(peerNoteTypeString);
    } catch (NumberFormatException _) {
      LOG.error(
          "NumberFormatException parsing peerNoteType ({}) in file {}",
          peerNoteTypeString,
          extraPeerDataFile.getPath());
      return false;
    }
    if (peerNoteType == Node.PEER_NOTE_TYPE_PRIVATE_DARKNET_COMMENT) {
      synchronized (this) {
        try {
          privateDarknetComment = Base64.decodeUTF8(fs.get("privateDarknetComment"));
        } catch (IllegalBase64Exception e) {
          LOG.error("Bad Base64 encoding decoding private darknet comment peer note", e);
          return false;
        }
        privateDarknetCommentFileNumber = fileNumber;
      }
      return true;
    }
    LOG.error(
        "Read unknown peer note type '{}' from file {}", peerNoteType, extraPeerDataFile.getPath());
    return false;
  }

  private boolean handleQueuedToSendN2NM(SimpleFieldSet fs, int fileNumber)
      throws FSParseException {
    int type = fs.getInt(SFS_KEY_N2N_TYPE);
    if (isConnected()) {
      if (fs.get(SFS_KEY_EXTRA_PEER_DATA_TYPE) != null) {
        fs.removeValue(SFS_KEY_EXTRA_PEER_DATA_TYPE);
      }
      if (fs.get(SFS_KEY_SENDER_FILE_NUMBER) != null) {
        fs.removeValue(SFS_KEY_SENDER_FILE_NUMBER);
      }
      fs.putOverwrite(SFS_KEY_SENDER_FILE_NUMBER, String.valueOf(fileNumber));
      if (fs.get(SFS_KEY_SENT_TIME) != null) {
        fs.removeValue(SFS_KEY_SENT_TIME);
      }
      fs.putOverwrite(SFS_KEY_SENT_TIME, Long.toString(System.currentTimeMillis()));

      Message n2nm =
          DMT.createNodeToNodeMessage(type, fs.toString().getBytes(StandardCharsets.UTF_8));
      // the callback ensures that n2ns are only unqueued after being acknowledged
      UnqueueMessageOnAckCallback cb = new UnqueueMessageOnAckCallback(this, fileNumber);
      try {
        transport().sendAsync(n2nm, cb, null);
        LOG.info("Sending queued ({}) N2NM to '{}': {}", fileNumber, getName(), n2nm);
      } catch (NotConnectedException _) {
        fs.removeValue(SFS_KEY_SENT_TIME);
      }
    }
    return true;
  }

  /**
   * Writes a new extra peer data file with the provided contents.
   *
   * @param fs contents to write.
   * @param extraPeerDataType optional type tag; when {@code > 0} the {@code extraPeerDataType}
   *     field is added to {@code fs} before writing.
   * @return the allocated file number on success, or {@code -1} if writing failed.
   */
  public int writeNewExtraPeerDataFile(SimpleFieldSet fs, int extraPeerDataType) {
    String extraPeerDataDirPath = node.getExtraPeerDataDir();
    if (extraPeerDataType > 0)
      fs.putOverwrite(SFS_KEY_EXTRA_PEER_DATA_TYPE, Integer.toString(extraPeerDataType));
    File extraPeerDataPeerDir =
        new File(extraPeerDataDirPath + File.separator + getIdentityString());
    if (!extraPeerDataPeerDir.exists() && !extraPeerDataPeerDir.mkdir()) {
      LOG.error(
          "Extra peer data directory for peer could not be created: {}",
          extraPeerDataPeerDir.getPath());
      return -1;
    }
    if (!extraPeerDataPeerDir.isDirectory()) {
      LOG.error(
          "Extra peer data directory not a directory while creating new file: {}",
          extraPeerDataPeerDir.getPath());
      return -1;
    }
    Integer[] localFileNumbers;
    int nextFileNumber = 0;
    synchronized (extraPeerDataFileNumbers) {
      // Find the first free slot
      localFileNumbers = extraPeerDataFileNumbers.toArray(new Integer[0]);
      Arrays.sort(localFileNumbers);
      for (int localFileNumber : localFileNumbers) {
        if (localFileNumber > nextFileNumber) {
          break;
        }
        nextFileNumber = localFileNumber + 1;
      }
      extraPeerDataFileNumbers.add(nextFileNumber);
    }
    FileOutputStream fos;
    File extraPeerDataFile =
        new File(extraPeerDataPeerDir.getPath() + File.separator + nextFileNumber);
    if (extraPeerDataFile.exists()) {
      LOG.error("Extra peer data file already exists: {}", extraPeerDataFile.getPath());
      return -1;
    }
    String f = extraPeerDataFile.getPath();
    try {
      fos = new FileOutputStream(f);
    } catch (FileNotFoundException e2) {
      LOG.error("Failed to create new extra peer data file on disk: {} - {}", f, e2, e2);
      return -1;
    }
    OutputStreamWriter w = new OutputStreamWriter(fos, StandardCharsets.UTF_8);
    BufferedWriter bw = new BufferedWriter(w);
    try {
      fs.writeTo(bw);
      bw.close();
    } catch (IOException e) {
      try {
        fos.close();
      } catch (IOException _) {
        LOG.error("Cannot close extra peer data file after new write: {}", e, e);
      }
      LOG.error("Cannot write new extra peer data file: {}", e, e);
      return -1;
    }
    return nextFileNumber;
  }

  /**
   * Deletes an extra peer data file and forgets its file number.
   *
   * @param fileNumber identifier of the file to delete.
   */
  public void deleteExtraPeerDataFile(int fileNumber) {
    String extraPeerDataDirPath = node.getExtraPeerDataDir();
    File extraPeerDataPeerDir = new File(extraPeerDataDirPath, getIdentityString());
    if (!extraPeerDataPeerDir.exists()) {
      LOG.error(
          "Extra peer data directory missing while deleting file: {}",
          extraPeerDataPeerDir.getPath());
      return;
    }
    if (!extraPeerDataPeerDir.isDirectory()) {
      LOG.error(
          "Extra peer data directory not a directory while deleting file: {}",
          extraPeerDataPeerDir.getPath());
      return;
    }
    File extraPeerDataFile = new File(extraPeerDataPeerDir, Integer.toString(fileNumber));
    if (!extraPeerDataFile.exists()) {
      LOG.error(
          "Extra peer data file missing while deleting file: {}", extraPeerDataFile.getPath());
      return;
    }
    synchronized (extraPeerDataFileNumbers) {
      extraPeerDataFileNumbers.remove(fileNumber);
    }
    try {
      Files.delete(extraPeerDataFile.toPath());
    } catch (IOException e) {
      if (extraPeerDataFile.exists()) {
        LOG.error(
            "Cannot delete file {} after sending message to {} - it may be resent on resting the"
                + " node",
            extraPeerDataFile,
            getPeer(),
            e);
      } else {
        LOG.info(
            "File does not exist when deleting: {} after sending message to {}",
            extraPeerDataFile,
            getPeer());
      }
    }
  }

  /** Deletes all extra peer data files for this peer and removes the directory. */
  public void removeExtraPeerDataDir() {
    String extraPeerDataDirPath = node.getExtraPeerDataDir();
    File extraPeerDataPeerDir =
        new File(extraPeerDataDirPath + File.separator + getIdentityString());
    if (!extraPeerDataPeerDir.exists()) {
      LOG.error(
          "Extra peer data directory missing while removing data directory: {}",
          extraPeerDataPeerDir.getPath());
      return;
    }
    if (!extraPeerDataPeerDir.isDirectory()) {
      LOG.error(
          "Extra peer data directory not a directory while removing data directory: {}",
          extraPeerDataPeerDir.getPath());
      return;
    }
    Integer[] localFileNumbers;
    synchronized (extraPeerDataFileNumbers) {
      localFileNumbers = extraPeerDataFileNumbers.toArray(new Integer[0]);
    }
    for (Integer localFileNumber : localFileNumbers) {
      deleteExtraPeerDataFile(localFileNumber);
    }
    try {
      Files.delete(extraPeerDataPeerDir.toPath());
    } catch (IOException e) {
      LOG.error(
          "Failed to delete extra peer data directory: {}", extraPeerDataPeerDir.getPath(), e);
    }
  }

  /**
   * Overwrites an existing extra peer data file with new contents.
   *
   * @param fs new contents.
   * @param extraPeerDataType optional type tag; when {@code > 0} the {@code extraPeerDataType}
   *     field is added to {@code fs} before writing.
   * @param fileNumber identifier of the file to overwrite.
   * @return {@code true} on success; {@code false} if the file does not exist or writing fails.
   */
  @SuppressWarnings("UnusedReturnValue")
  public boolean rewriteExtraPeerDataFile(
      SimpleFieldSet fs, int extraPeerDataType, int fileNumber) {
    String extraPeerDataDirPath = node.getExtraPeerDataDir();
    if (extraPeerDataType > 0)
      fs.putOverwrite(SFS_KEY_EXTRA_PEER_DATA_TYPE, Integer.toString(extraPeerDataType));
    File extraPeerDataPeerDir =
        new File(extraPeerDataDirPath + File.separator + getIdentityString());
    if (!extraPeerDataPeerDir.exists()) {
      LOG.error(
          "Extra peer data directory missing while rewriting file: {}",
          extraPeerDataPeerDir.getPath());
      return false;
    }
    if (!extraPeerDataPeerDir.isDirectory()) {
      LOG.error(
          "Extra peer data directory not a directory while rewriting file: {}",
          extraPeerDataPeerDir.getPath());
      return false;
    }
    File extraPeerDataFile =
        new File(
            extraPeerDataDirPath
                + File.separator
                + getIdentityString()
                + File.separator
                + fileNumber);
    if (!extraPeerDataFile.exists()) {
      LOG.error(
          "Extra peer data file missing while rewriting file: {}", extraPeerDataFile.getPath());
      return false;
    }
    String f = extraPeerDataFile.getPath();
    FileOutputStream fos;
    try {
      fos = new FileOutputStream(f);
    } catch (FileNotFoundException e2) {
      LOG.error("Failed to open extra peer data file for rewrite on disk: {} - {}", f, e2, e2);
      return false;
    }
    OutputStreamWriter w = new OutputStreamWriter(fos, StandardCharsets.UTF_8);
    BufferedWriter bw = new BufferedWriter(w);
    try {
      fs.writeTo(bw);
      bw.close();
    } catch (IOException e) {
      try {
        fos.close();
      } catch (IOException _) {
        LOG.error("Cannot close extra peer data file after rewrite: {}", e, e);
      }
      LOG.error("Cannot rewrite extra peer data file: {}", e, e);
      return false;
    }
    return true;
  }

  /** Returns the private comment associated with this friend (shown on the friends page). */
  public synchronized String getPrivateDarknetCommentNote() {
    return privateDarknetComment;
  }

  /**
   * Sets or updates the private comment associated with this friend.
   *
   * <p>The comment is persisted in an extra peer data file (created on first use, then rewritten on
   * updates).
   *
   * @param comment UTF-8 text; persisted Base64-encoded.
   */
  public synchronized void setPrivateDarknetCommentNote(String comment) {
    int localFileNumber;
    privateDarknetComment = comment;
    localFileNumber = privateDarknetCommentFileNumber;
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.put("peerNoteType", Node.PEER_NOTE_TYPE_PRIVATE_DARKNET_COMMENT);
    fs.putSingle("privateDarknetComment", Base64.encodeUTF8(comment));
    if (localFileNumber == -1) {
      localFileNumber = writeNewExtraPeerDataFile(fs, Node.EXTRA_PEER_DATA_TYPE_PEER_NOTE);
      privateDarknetCommentFileNumber = localFileNumber;
    } else {
      rewriteExtraPeerDataFile(fs, Node.EXTRA_PEER_DATA_TYPE_PEER_NOTE, localFileNumber);
    }
  }

  /**
   * Queues a node-to-node message for delivery when connected.
   *
   * @param fs message fields; the method augments metadata before writing to disk.
   * @return the file number used to persist the queued message.
   */
  @Override
  public int queueN2NM(SimpleFieldSet fs) {
    int fileNumber = writeNewExtraPeerDataFile(fs, Node.EXTRA_PEER_DATA_TYPE_QUEUED_TO_SEND_N2NM);
    synchronized (queuedToSendN2NMExtraPeerDataFileNumbers) {
      queuedToSendN2NMExtraPeerDataFileNumbers.add(fileNumber);
    }
    return fileNumber;
  }

  /**
   * Removes a previously queued node-to-node message and deletes the backing file.
   *
   * @param fileNumber identifier returned by {@link #queueN2NM(SimpleFieldSet)}.
   */
  public void unqueueN2NM(int fileNumber) {
    synchronized (queuedToSendN2NMExtraPeerDataFileNumbers) {
      queuedToSendN2NMExtraPeerDataFileNumbers.add(fileNumber);
    }
    deleteExtraPeerDataFile(fileNumber);
  }

  /** Sends all queued node-to-node messages if connected. */
  public void sendQueuedN2NMs() {
    if (LOG.isDebugEnabled()) LOG.debug("Queue drain: sending N2NMs for {}", shortToString());
    Integer[] localFileNumbers;
    synchronized (queuedToSendN2NMExtraPeerDataFileNumbers) {
      localFileNumbers = queuedToSendN2NMExtraPeerDataFileNumbers.toArray(new Integer[0]);
    }
    Arrays.sort(localFileNumbers);
    for (Integer localFileNumber : localFileNumbers) {
      rereadExtraPeerDataFile(localFileNumber);
    }
  }

  @Override
  void startARKFetcher() {
    synchronized (this) {
      if (isListenOnly) {
        LOG.debug("Not starting ark fetcher for {} as it's in listen-only mode.", this);
        return;
      }
    }
    super.startARKFetcher();
  }

  /** Returns a tab-separated summary for the text-mode client interface. */
  @Override
  public String getTMCIPeerInfo() {
    return getName() + '\t' + super.getTMCIPeerInfo();
  }

  /** A hook called once when the connection transitions to connected. */
  @Override
  protected void onConnect() {
    super.onConnect();
    sendQueuedN2NMs();
  }

  // File transfer offers
  // Note: This likely belongs with other N2NM code; evaluate relocation.
  // Note: Persistence across node restarts is not implemented.

  /** Files I have offered to this peer */
  private final HashMap<Long, FileOffer> myFileOffersByUID = new HashMap<>();

  /** Files this peer has offered to me */
  private final HashMap<Long, FileOffer> hisFileOffersByUID = new HashMap<>();

  private void storeOffers() {
    // Pending: implement persistence for file offers if required.
  }

  // Note: Consider refactoring so file transfers can be initiated outside of fproxy.
  // Note: Future enhancement: allow interaction with plugins on other nodes.
  // Note: Types exist already; wider support is currently not implemented.
  // See also e.g., fcp/SendTextMessage.
  /**
   * Represents a single file offer exchanged over node-to-node messaging.
   *
   * <p>Instances are short-lived and not persisted. Depending on {@link #amIOffering}, an instance
   * either sends or receives a bulk transfer. Alerts are posted on success/failure.
   */
  final class FileOffer {
    final long uid;
    final String filename;
    final String mimeType;
    final String comment;

    /** Only valid if {@code amIOffering == false}. Set when receiving starts. */
    private File destination;

    private RandomAccessBuffer data;
    final long size;

    /**
     * Who is offering it? {@code true} = I am offering it, {@code false} = I am being offered it.
     */
    final boolean amIOffering;

    private PartiallyReceivedBulk prb;
    private BulkTransmitter transmitter;
    private BulkReceiver receiver;

    /** {@code true} once the offer is accepted or rejected. */
    private boolean acceptedOrRejected;

    FileOffer(long uid, RandomAccessBuffer data, String filename, String mimeType, String comment) {
      this.uid = uid;
      this.data = data;
      this.filename = filename;
      this.mimeType = mimeType;
      this.comment = comment;
      size = data.size();
      amIOffering = true;
    }

    /**
     * Constructs a file offer from a received field set.
     *
     * @param fs serialized offer fields.
     * @param amIOffering whether this side originated the offer.
     * @throws FSParseException if required, fields are missing or invalid.
     */
    public FileOffer(SimpleFieldSet fs, boolean amIOffering) throws FSParseException {
      uid = fs.getLong("uid");
      size = fs.getLong("size");
      mimeType = fs.get("metadata.contentType");
      filename = FileUtil.sanitize(fs.get(FS_KEY_FILENAME), mimeType);
      destination = null;
      String s = fs.get("comment");
      if (s != null) {
        try {
          s = Base64.decodeUTF8(s);
        } catch (IllegalBase64Exception e) {
          // Maybe it wasn't encoded? legacy input tolerated
          LOG.error("Bad Base64 encoding decoding file offer comment", e);
        }
      }
      comment = s;
      this.amIOffering = amIOffering;
    }

    /** Writes this offer to a field set suitable for transmission. */
    public void toFieldSet(SimpleFieldSet fs) {
      fs.put("uid", uid);
      fs.putSingle(FS_KEY_FILENAME, filename);
      fs.putSingle("metadata.contentType", mimeType);
      fs.putSingle("comment", Base64.encodeUTF8(comment));
      fs.put("size", size);
    }

    /** Accepts the offer and starts receiving the file to the downloads' directory. */
    @SuppressWarnings("java:S1181")
    public void accept() {
      acceptedOrRejected = true;
      final String baseFilename = "direct-" + FileUtil.sanitize(getName()) + "-" + filename;
      final File dest =
          new File(node.services().clientCore().getDownloadsDir(), baseFilename + ".part");
      destination = new File(node.services().clientCore().getDownloadsDir(), baseFilename);
      try {
        data = new FileRandomAccessBuffer(dest, size, false);
      } catch (IOException e) {
        // Should not happen; FileRandomAccessBuffer opened with rw
        throw new IllegalStateException(
            "Unexpected failure opening RandomAccessBuffer for destination file", e);
      }
      prb = new PartiallyReceivedBulk(node.network().usm(), size, Node.PACKET_SIZE, data, false);
      receiver = new BulkReceiver(prb, DarknetPeerNode.this, uid, null);
      // Note: Persistence is not implemented here
      node.network()
          .executor()
          .execute(
              new Runnable() {
                @Override
                public void run() {
                  if (LOG.isDebugEnabled()) LOG.debug("Receiving file");
                  try {
                    if (!receiver.receive()) {
                      String err = "Failed to receive " + this;
                      LOG.error(err);
                      onReceiveFailure();
                    } else {
                      data.close();
                      if (!dest.renameTo(
                          new File(node.services().clientCore().getDownloadsDir(), baseFilename))) {
                        LOG.error("Failed to rename {} to remove .part suffix.", dest.getName());
                      }
                      onReceiveSuccess();
                    }
                  } catch (Throwable t) {
                    LOG.error("Caught {} receiving file", t, t);
                    onReceiveFailure();
                  } finally {
                    remove();
                  }
                  if (LOG.isDebugEnabled()) LOG.debug("Receive file finished");
                }
              },
              "Receiver for bulk transfer " + uid + ":" + filename);
      sendFileOfferAccepted(uid);
    }

    /** Removes this offer from internal maps and closes buffers. */
    private void remove() {
      Long l = uid;
      synchronized (DarknetPeerNode.this) {
        myFileOffersByUID.remove(l);
        hisFileOffersByUID.remove(l);
      }
      data.close();
    }

    /** Starts sending the offered file using a bulk transmitter. */
    @SuppressWarnings("java:S1181")
    public void send() throws DisconnectedException {
      prb = new PartiallyReceivedBulk(node.network().usm(), size, Node.PACKET_SIZE, data, true);
      transmitter =
          new BulkTransmitter(
              prb,
              DarknetPeerNode.this,
              uid,
              false,
              node.network().stats().nodeToNodeCounter,
              false);
      if (LOG.isDebugEnabled()) LOG.debug("Bulk send start uid={}", uid);
      node.network()
          .executor()
          .execute(
              () -> {
                if (LOG.isDebugEnabled()) LOG.debug("Sending file");
                try {
                  if (!transmitter.send()) {
                    String err =
                        "Failed to send "
                            + uid
                            + LOG_FOR
                            + filename
                            + " ("
                            + java.util.Objects.toIdentityString(FileOffer.this)
                            + ')';
                    LOG.error(err);
                  }
                } catch (Throwable t) {
                  LOG.error("Caught {} sending file", t, t);
                  remove();
                }
                if (LOG.isDebugEnabled()) LOG.debug("Sent file");
              },
              "Sender for bulk transfer " + uid + ":" + filename);
    }

    /** Rejects the offer and notifies the remote peer. */
    public void reject() {
      acceptedOrRejected = true;
      sendFileOfferRejected(uid);
    }

    /** Cancels an in-flight transmission when the remote rejected the offer. */
    public void onRejected() {
      transmitter.cancel("FileOffer: Offer rejected");
      // Note: prb instances are not shared here
      prb.abort(RetrievalException.CANCELLED_BY_RECEIVER, "Cancelled by receiver");
    }

    /** Posts a user alert describing a failed file reception. */
    private void onReceiveFailure() {
      UserAlert alert =
          new AbstractNodeToNodeFileOfferUserAlert() {
            @Override
            public String dismissButtonText() {
              return NodeL10n.getBase().getString("UserAlert.hide");
            }

            @Override
            public HTMLNode getHTMLText() {
              HTMLNode div = new HTMLNode("div");

              div.addChild(
                  "p",
                  l10n(
                      "failedReceiveHeader",
                      new String[] {FS_KEY_FILENAME, "node"},
                      new String[] {filename, getName()}));

              // Descriptive table
              describeFile(div);

              return div;
            }

            @Override
            public short getPriorityClass() {
              return UserAlert.MINOR;
            }

            @Override
            public String getText() {
              StringBuilder sb = new StringBuilder();
              sb.append(
                  l10n(
                      "failedReceiveHeader",
                      new String[] {FS_KEY_FILENAME, "node"},
                      new String[] {filename, getName()}));
              sb.append('\n');
              sb.append(l10n(L10N_FILE_LABEL));
              sb.append(' ');
              sb.append(filename);
              sb.append('\n');
              sb.append(l10n(L10N_SIZE_LABEL));
              sb.append(' ');
              sb.append(SizeUtil.formatSize(size));
              sb.append('\n');
              sb.append(l10n(L10N_MIME_LABEL));
              sb.append(' ');
              sb.append(mimeType);
              sb.append('\n');
              sb.append(l10n(L10N_SENDER_LABEL));
              sb.append(' ');
              sb.append(getName());
              sb.append('\n');
              if (comment != null && !comment.isEmpty()) {
                sb.append(l10n(L10N_COMMENT_LABEL));
                sb.append(' ');
                sb.append(comment);
              }
              return sb.toString();
            }

            @Override
            public String getTitle() {
              return l10n("failedReceiveTitle");
            }

            @Override
            public boolean isValid() {
              return true;
            }

            @Override
            public void isValid(boolean validity) {
              // Ignore
            }

            @Override
            public void onDismiss() {
              // Ignore
            }

            @Override
            public boolean shouldUnregisterOnDismiss() {
              return true;
            }

            @Override
            public boolean userCanDismiss() {
              return true;
            }

            @Override
            public String getShortText() {
              return l10n(
                  "failedReceiveShort",
                  new String[] {FS_KEY_FILENAME, "node"},
                  new String[] {filename, getName()});
            }
          };
      node.services().clientCore().getAlerts().register(alert);
    }

    private void onReceiveSuccess() {
      UserAlert alert =
          new AbstractNodeToNodeFileOfferUserAlert() {
            @Override
            public String dismissButtonText() {
              return NodeL10n.getBase().getString("UserAlert.hide");
            }

            @Override
            public HTMLNode getHTMLText() {
              HTMLNode div = new HTMLNode("div");

              // Note: localisation handled via l10n()

              div.addChild(
                  "p",
                  l10n(
                      "succeededReceiveHeader",
                      new String[] {FS_KEY_FILENAME, "node"},
                      new String[] {filename, getName()}));

              // Descriptive table
              describeFile(div);

              return div;
            }

            @Override
            public short getPriorityClass() {
              return UserAlert.MINOR;
            }

            @Override
            public String getText() {
              String header =
                  l10n(
                      "succeededReceiveHeader",
                      new String[] {FS_KEY_FILENAME, "node"},
                      new String[] {filename, getName()});

              return describeFileText(header);
            }

            @Override
            public String getTitle() {
              return l10n("succeededReceiveTitle");
            }

            @Override
            public boolean isValid() {
              return true;
            }

            @Override
            public void isValid(boolean validity) {
              // Ignore
            }

            @Override
            public void onDismiss() {
              // Ignore
            }

            @Override
            public boolean shouldUnregisterOnDismiss() {
              return true;
            }

            @Override
            public boolean userCanDismiss() {
              return true;
            }

            @Override
            public String getShortText() {
              return l10n(
                  "succeededReceiveShort",
                  new String[] {FS_KEY_FILENAME, "node"},
                  new String[] {filename, getName()});
            }
          };
      node.services().clientCore().getAlerts().register(alert);
    }

    /** Ask the user whether (s)he wants to download a file from a direct peer */
    public UserAlert askUserUserAlert() {
      return new AbstractNodeToNodeFileOfferUserAlert() {

        @Override
        public String dismissButtonText() {
          return null; // Cannot hide but can reject
        }

        @Override
        public HTMLNode getHTMLText() {
          HTMLNode div = new HTMLNode("div");

          div.addChild("p", l10nOfferedFileHeader(getName()));

          // Descriptive table
          describeFile(div);

          // Accept/reject form

          // Hopefully, we will have a container when this function is called!
          HTMLNode form =
              node.services()
                  .clientCore()
                  .getEndpoints()
                  .getToadletContainer()
                  .addFormChild(div, "/friends/", "f2fFileOfferAcceptForm");

          // Note: node_ attribute retained for current implementation
          form.addChild(
              HTML_TAG_INPUT,
              new String[] {"type", "name"},
              new String[] {"hidden", "node_" + DarknetPeerNode.this.hashCode()});

          form.addChild(
              HTML_TAG_INPUT,
              new String[] {"type", "name", HTML_ATTR_VALUE},
              new String[] {"hidden", "id", Long.toString(uid)});

          form.addChild(
              HTML_TAG_INPUT,
              new String[] {"type", "name", HTML_ATTR_VALUE},
              new String[] {"submit", "acceptTransfer", l10n("acceptTransferButton")});

          form.addChild(
              HTML_TAG_INPUT,
              new String[] {"type", "name", HTML_ATTR_VALUE},
              new String[] {"submit", "rejectTransfer", l10n("rejectTransferButton")});

          return div;
        }

        @Override
        public short getPriorityClass() {
          return UserAlert.MINOR;
        }

        @Override
        public String getText() {
          String header = l10nOfferedFileHeader(getName());
          return describeFileText(header);
        }

        @Override
        public String getTitle() {
          return l10n("askUserTitle");
        }

        @Override
        public boolean isValid() {
          if (acceptedOrRejected) {
            node.services().clientCore().getAlerts().unregister(this);
            return false;
          }
          return true;
        }

        @Override
        public void isValid(boolean validity) {
          // Ignore
        }

        @Override
        public void onDismiss() {
          // Ignore
        }

        @Override
        public boolean shouldUnregisterOnDismiss() {
          return false;
        }

        @Override
        public boolean userCanDismiss() {
          return false; // should accept or reject
        }

        @Override
        public String getShortText() {
          return l10n(
              "offeredFileShort",
              new String[] {FS_KEY_FILENAME, "node"},
              new String[] {filename, getName()});
        }
      };
    }

    private void addComment(HTMLNode node) {
      List<String> lines = new ArrayList<>();
      if (comment.isEmpty()) {
        lines.add("");
      } else {
        int start = 0;
        for (int i = 0; i < comment.length(); i++) {
          if (comment.charAt(i) == '\n') {
            lines.add(comment.substring(start, i));
            start = i + 1;
          }
        }
        if (start < comment.length()) {
          lines.add(comment.substring(start));
        }
      }
      for (int i = 0, c = lines.size(); i < c; i++) {
        node.addChild("#", lines.get(i));
        if (i != c - 1) node.addChild("br");
      }
    }

    private String l10n(String key) {
      return NodeL10n.getBase().getString(L10N_FILE_OFFER_PREFIX + key);
    }

    /**
     * Localize the "offered file" header using the node name placeholder. Maps to key {@code
     * FileOffer.offeredFileHeader} with pattern {@code name}.
     */
    private String l10nOfferedFileHeader(String nodeName) {
      return NodeL10n.getBase()
          .getString(L10N_FILE_OFFER_PREFIX + "offeredFileHeader", "name", nodeName);
    }

    private String l10n(String key, String[] pattern, String[] value) {
      return NodeL10n.getBase().getString(L10N_FILE_OFFER_PREFIX + key, pattern, value);
    }

    private String describeFileText(String header) {
      StringBuilder sb = new StringBuilder();
      sb.append(header);
      sb.append('\n');
      sb.append(l10n(L10N_FILE_LABEL));
      sb.append(' ');
      sb.append(filename);
      sb.append('\n');
      sb.append(l10n(L10N_SIZE_LABEL));
      sb.append(' ');
      sb.append(SizeUtil.formatSize(size));
      sb.append('\n');
      sb.append(l10n(L10N_MIME_LABEL));
      sb.append(' ');
      sb.append(mimeType);
      sb.append('\n');
      sb.append(l10n(L10N_SENDER_LABEL));
      sb.append(' ');
      sb.append(userToString());
      sb.append('\n');
      if (comment != null && !comment.isEmpty()) {
        sb.append(l10n(L10N_COMMENT_LABEL));
        sb.append(' ');
        sb.append(comment);
      }
      return sb.toString();
    }

    private void describeFile(HTMLNode div) {
      HTMLNode table = div.addChild("table", "border", "0");
      HTMLNode row = table.addChild("tr");
      row.addChild("td").addChild("#", l10n(L10N_FILE_LABEL));
      row.addChild("td").addChild("#", filename);
      if (destination != null) {
        row = table.addChild("tr");
        row.addChild("td").addChild("#", l10n("fileSavedToLabel"));
        row.addChild("td").addChild("#", destination.getPath());
      }
      row = table.addChild("tr");
      row.addChild("td").addChild("#", l10n(L10N_SIZE_LABEL));
      row.addChild("td").addChild("#", SizeUtil.formatSize(size));
      row = table.addChild("tr");
      row.addChild("td").addChild("#", l10n(L10N_MIME_LABEL));
      row.addChild("td").addChild("#", mimeType);
      row = table.addChild("tr");
      row.addChild("td").addChild("#", l10n(L10N_SENDER_LABEL));
      row.addChild("td").addChild("#", getName());
      row = table.addChild("tr");
      if (comment != null && !comment.isEmpty()) {
        row.addChild("td").addChild("#", l10n(L10N_COMMENT_LABEL));
        addComment(row.addChild("td"));
      }
    }
  }

  public int sendBookmarkFeed(
      FreenetURI uri, String name, String description, boolean hasAnActiveLink) {
    long now = System.currentTimeMillis();
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("URI", uri.toString());
    fs.putSingle("Name", name);
    fs.put(FS_KEY_COMPOSED_TIME, now);
    fs.put("hasAnActivelink", hasAnActiveLink);
    if (description != null) fs.putSingle(FS_KEY_DESCRIPTION, Base64.encodeUTF8(description));
    fs.put("type", Node.N2N_TEXT_MESSAGE_TYPE_BOOKMARK);
    sendNodeToNodeMessage(fs, Node.N2N_MESSAGE_TYPE_FPROXY, true, now, true);
    setPeerNodeStatus(System.currentTimeMillis());
    return getPeerNodeStatus();
  }

  /**
   * Sends a download entry to the peer's feed via node-to-node messaging.
   *
   * @param uri content to download.
   * @param description optional description; Base64-encoded on the wire.
   * @return updated peer status code after the message is queued.
   */
  public int sendDownloadFeed(FreenetURI uri, String description) {
    long now = System.currentTimeMillis();
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("URI", uri.toString());
    fs.put(FS_KEY_COMPOSED_TIME, now);
    if (description != null) {
      fs.putSingle(FS_KEY_DESCRIPTION, Base64.encodeUTF8(description));
    }
    fs.put("type", Node.N2N_TEXT_MESSAGE_TYPE_DOWNLOAD);
    sendNodeToNodeMessage(fs, Node.N2N_MESSAGE_TYPE_FPROXY, true, now, true);
    setPeerNodeStatus(System.currentTimeMillis());
    return getPeerNodeStatus();
  }

  /**
   * Sends a text message to the peer's feed.
   *
   * <p>Messages larger than 1024 characters are split into multiple parts with a shared message id
   * so the receiver can reassemble user alerts.
   *
   * @param message UTF-8 text.
   * @return updated peer status code after the message is queued.
   */
  public int sendTextFeed(String message) {
    long now = System.currentTimeMillis();
    // Avoid Math.abs on nextLong(): Long.MIN_VALUE overflows; use the original value.
    long msgid = random.nextLong();
    // split large messages
    int requiredN2nCount = 1 + ((message.length() - 1) / 1024);
    String messagePart;
    for (int i = 0; i < requiredN2nCount; i++) {
      messagePart = message.substring(i * 1024, Math.min((i + 1) * 1024, message.length()));
      SimpleFieldSet fs = new SimpleFieldSet(true);
      fs.put("type", Node.N2N_TEXT_MESSAGE_TYPE_USERALERT);
      fs.putSingle("text", Base64.encodeUTF8(messagePart));
      fs.put("msgid", msgid);
      fs.put("requiredParts", requiredN2nCount);
      fs.put("partIndex", i);
      // increment compose time to allow sorting messages
      fs.put(FS_KEY_COMPOSED_TIME, now + i);
      sendNodeToNodeMessage(fs, Node.N2N_MESSAGE_TYPE_FPROXY, true, now, true);
      this.setPeerNodeStatus(System.currentTimeMillis());
    }
    return getPeerNodeStatus();
  }

  /**
   * Notifies the remote that we accepted the file offer identified by {@code uid}.
   *
   * @param uid offer identifier.
   * @return updated peer status code after the message is queued.
   */
  @SuppressWarnings("UnusedReturnValue")
  public int sendFileOfferAccepted(long uid) {
    long now = System.currentTimeMillis();
    storeOffers();

    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.put("type", Node.N2N_TEXT_MESSAGE_TYPE_FILE_OFFER_ACCEPTED);
    fs.put("uid", uid);
    if (LOG.isDebugEnabled()) {
      LOG.debug("N2N file offer accepted outbound message:\n{}", fs);
    }

    sendNodeToNodeMessage(fs, Node.N2N_MESSAGE_TYPE_FPROXY, true, now, true);
    setPeerNodeStatus(System.currentTimeMillis());
    return getPeerNodeStatus();
  }

  /**
   * Notifies the remote that we rejected the file offer identified by {@code uid}.
   *
   * @param uid offer identifier.
   * @return updated peer status code after the message is queued.
   */
  @SuppressWarnings("UnusedReturnValue")
  public int sendFileOfferRejected(long uid) {
    long now = System.currentTimeMillis();
    storeOffers();

    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.put("type", Node.N2N_TEXT_MESSAGE_TYPE_FILE_OFFER_REJECTED);
    fs.put("uid", uid);
    if (LOG.isDebugEnabled()) LOG.debug("N2N file offer rejected outbound message:\n{}", fs);

    sendNodeToNodeMessage(fs, Node.N2N_MESSAGE_TYPE_FPROXY, true, now, true);
    setPeerNodeStatus(System.currentTimeMillis());
    return getPeerNodeStatus();
  }

  private int sendFileOffer(String fnam, String mime, String message, RandomAccessBuffer data) {
    long uid = random.nextLong();
    long now = System.currentTimeMillis();
    FileOffer fo = new FileOffer(uid, data, fnam, mime, message);
    synchronized (this) {
      myFileOffersByUID.put(uid, fo);
    }
    storeOffers();
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fo.toFieldSet(fs);
    if (LOG.isDebugEnabled()) {
      LOG.debug("N2N file offer outbound message:\n{}", fs);
    }
    fs.put("type", Node.N2N_TEXT_MESSAGE_TYPE_FILE_OFFER);
    sendNodeToNodeMessage(fs, Node.N2N_MESSAGE_TYPE_FPROXY, true, now, true);
    setPeerNodeStatus(System.currentTimeMillis());
    return getPeerNodeStatus();
  }

  /**
   * Offers a local file to the peer.
   *
   * @param file file on disk.
   * @param message optional human-readable note.
   * @return updated peer status code after the message is queued.
   * @throws IOException if the file cannot be read.
   */
  @SuppressWarnings("UnusedReturnValue")
  public int sendFileOffer(File file, String message) throws IOException {
    String fnam = file.getName();
    String mime = DefaultMIMETypes.guessMIMEType(fnam, false);
    RandomAccessBuffer data = new FileRandomAccessBuffer(file, true);
    return sendFileOffer(fnam, mime, message, data);
  }

  /**
   * Offers an uploaded file to the peer.
   *
   * @param file uploaded body.
   * @param message optional human-readable note.
   * @return updated peer status code after the message is queued.
   * @throws IOException if the upload buffer cannot be read.
   */
  @SuppressWarnings("UnusedReturnValue")
  public int sendFileOffer(HTTPUploadedFile file, String message) throws IOException {
    String fnam = file.getFilename();
    String mime = file.getContentType();
    RandomAccessBuffer data =
        new ByteArrayRandomAccessBuffer(BucketTools.toByteArray(file.getData()));
    return sendFileOffer(fnam, mime, message, data);
  }

  // handler for sendTextFeed
  /**
   * Handles a received FProxy node-to-node text message and posts a user alert.
   *
   * @param fs message field set.
   * @param fileNumber backing file number used for persistence/merging.
   */
  public void handleFproxyN2NTM(SimpleFieldSet fs, int fileNumber) {
    String text;
    long composedTime = fs.getLong(FS_KEY_COMPOSED_TIME, -1);
    long sentTime = fs.getLong(SFS_KEY_SENT_TIME, -1);
    long receivedTime = fs.getLong(SFS_KEY_RECEIVED_TIME, -1);
    try {
      text = Base64.decodeUTF8(fs.get("text"));
    } catch (IllegalBase64Exception e) {
      LOG.error("Bad Base64 encoding decoding N2NTM text message", e);
      return;
    }
    long msgid = fs.getLong("msgid", -1);

    List<UserAlert> merged = new ArrayList<>();
    String newText =
        (msgid != -1) ? mergeExistingN2NTMAlerts(msgid, composedTime, text, merged) : text;

    int newFileNumber = handlePersistMergedIfAny(fs, fileNumber, newText, merged, text);

    showN2NTMAlertAndDismissMerged(
        newText, newFileNumber, composedTime, sentTime, receivedTime, msgid, merged);
  }

  @SuppressWarnings("java:S1643")
  private String mergeExistingN2NTMAlerts(
      long msgid, long composedTime, String currentText, List<UserAlert> merged) {
    String newText = currentText;
    // NOTE: Merge is linear time over existing alerts; keep an alert list bounded upstream.
    synchronized (node.services().clientCore().getAlerts()) {
      for (UserAlert userAlert : node.services().clientCore().getAlerts().getAlerts()) {
        if (!(userAlert instanceof N2NTMUserAlert alert) || msgid != alert.getMsgid()) {
          continue;
        }
        if (composedTime == alert.getComposedTime()) {
          String alertText = alert.getMessageText();
          if (newText.contains(alertText)) {
            merged.add(userAlert);
          } else if (alertText.contains(newText)) {
            newText = alertText;
            merged.add(userAlert);
          } else if (LOG.isDebugEnabled()) {
            LOG.debug(
                """
                failed to merge N2NTMs; there will be at least one duplicate and text might be garbled:
                {}
                {}
                """,
                newText,
                alertText);
          }
        }
        if (composedTime == alert.getComposedTime() + 1) {
          newText = alert.getMessageText() + newText;
          merged.add(userAlert);
        } else if (composedTime == alert.getComposedTime() - 1) {
          newText = newText + alert.getMessageText();
          merged.add(userAlert);
        }
      }
    }
    return newText;
  }

  private int handlePersistMergedIfAny(
      SimpleFieldSet fs,
      int fileNumber,
      String newText,
      List<UserAlert> merged,
      String originalText) {
    if (merged.isEmpty()) {
      return fileNumber;
    }
    fs.putOverwrite("text", Base64.encodeUTF8(newText));
    if (fs.getInt(SFS_KEY_N2N_TYPE, -1) == -1) {
      fs.put(SFS_KEY_N2N_TYPE, Node.N2N_MESSAGE_TYPE_FPROXY);
    }
    synchronized (this) {
      int newFileNumber = writeNewExtraPeerDataFile(fs, Node.EXTRA_PEER_DATA_TYPE_N2NTM);
      if (newFileNumber == -1) {
        LOG.error("Failed to write new N2NTM to extra peer data file for N2NTM sfs{}", fs);
        // roll back to avoid losing data
        merged.clear();
        fs.putOverwrite("text", Base64.encodeUTF8(originalText));
        return fileNumber;
      }
      deleteExtraPeerDataFile(fileNumber);
      return newFileNumber;
    }
  }

  private void showN2NTMAlertAndDismissMerged(
      String newText,
      int newFileNumber,
      long composedTime,
      long sentTime,
      long receivedTime,
      long msgid,
      List<UserAlert> merged) {
    NodeToNodeAlertContext alertContext =
        new NodeToNodeAlertContext(this, newFileNumber, composedTime, sentTime, receivedTime);
    N2NTMUserAlert userAlert = new N2NTMUserAlert(alertContext, newText, msgid);
    node.services().clientCore().getAlerts().register(userAlert);
    for (UserAlert alert : merged) {
      node.services().clientCore().getAlerts().dismissAlert(alert.hashCode());
    }
  }

  public void handleFproxyFileOffer(SimpleFieldSet fs, int fileNumber) {
    final FileOffer offer;
    try {
      offer = new FileOffer(fs, false);
    } catch (FSParseException e) {
      LOG.error("Could not parse offer: {} on {} :\n{}", e, this, fs, e);
      return;
    }
    Long u = offer.uid;
    synchronized (this) {
      if (hisFileOffersByUID.containsKey(u)) return; // Ignore re-advertisement
      hisFileOffersByUID.put(u, offer);
    }

    // Note: do not persist for now
    this.deleteExtraPeerDataFile(fileNumber);

    UserAlert alert = offer.askUserUserAlert();

    node.services().clientCore().getAlerts().register(alert);
  }

  public void acceptTransfer(long id) {
    if (LOG.isDebugEnabled()) LOG.debug("Accepting transfer {} on {}", id, this);
    FileOffer fo;
    synchronized (this) {
      fo = hisFileOffersByUID.get(id);
    }
    if (fo == null) {
      LOG.error("Cannot accept transfer {} - does not exist", id);
      return;
    }
    fo.accept();
  }

  public void rejectTransfer(long id) {
    FileOffer fo;
    synchronized (this) {
      fo = hisFileOffersByUID.remove(id);
    }
    if (fo == null) {
      LOG.error("Cannot reject transfer {} - does not exist", id);
      return;
    }
    fo.reject();
  }

  public void handleFproxyFileOfferAccepted(SimpleFieldSet fs, int fileNumber) {
    // Note: do not persist for now
    this.deleteExtraPeerDataFile(fileNumber);

    long uid;
    try {
      uid = fs.getLong("uid");
    } catch (FSParseException e) {
      LOG.error("Could not parse offer accepted: {} on {} :\n{}", e, this, fs, e);
      return;
    }
    if (LOG.isDebugEnabled()) LOG.debug("Offer accepted for {}", uid);
    FileOffer fo;
    synchronized (this) {
      fo = myFileOffersByUID.get(uid);
    }
    if (fo == null) {
      LOG.error("No such offer: {}", uid);
      try {
        transport()
            .sendAsync(
                DMT.createFNPBulkSendAborted(uid), null, node.network().stats().nodeToNodeCounter);
      } catch (NotConnectedException _) {
        // Fine by me!
      }
      return;
    }
    try {
      fo.send();
    } catch (DisconnectedException e) {
      LOG.error(
          "Cannot send because node disconnected: {}" + LOG_FOR + "{}:{}", e, uid, fo.filename, e);
    }
  }

  public void handleFproxyFileOfferRejected(SimpleFieldSet fs, int fileNumber) {
    // Note: do not persist for now
    this.deleteExtraPeerDataFile(fileNumber);

    long uid;
    try {
      uid = fs.getLong("uid");
    } catch (FSParseException e) {
      LOG.error("Could not parse offer rejected: {} on {} :\n{}", e, this, fs, e);
      return;
    }

    FileOffer fo;
    synchronized (this) {
      fo = myFileOffersByUID.remove(uid);
    }
    fo.onRejected();
  }

  public void handleFproxyBookmarkFeed(SimpleFieldSet fs, int fileNumber) {
    String name = fs.get("Name");
    String description = null;
    FreenetURI uri;
    boolean hasAnActiveLink = fs.getBoolean("hasAnActivelink", false);
    long composedTime = fs.getLong(FS_KEY_COMPOSED_TIME, -1);
    long sentTime = fs.getLong(SFS_KEY_SENT_TIME, -1);
    long receivedTime = fs.getLong(SFS_KEY_RECEIVED_TIME, -1);
    try {
      String s = fs.get(FS_KEY_DESCRIPTION);
      if (s != null) description = Base64.decodeUTF8(s);
      uri = new FreenetURI(fs.get("URI"));
    } catch (MalformedURLException _) {
      LOG.error("Malformed URI in N2NTM Bookmark Feed message");
      return;
    } catch (IllegalBase64Exception e) {
      LOG.error("Bad Base64 encoding decoding N2NTM bookmark feed description", e);
      return;
    }
    NodeToNodeAlertContext alertContext =
        new NodeToNodeAlertContext(this, fileNumber, composedTime, sentTime, receivedTime);
    BookmarkFeedUserAlert userAlert =
        new BookmarkFeedUserAlert(alertContext, name, description, hasAnActiveLink, uri);
    node.services().clientCore().getAlerts().register(userAlert);
  }

  public void handleFproxyDownloadFeed(SimpleFieldSet fs, int fileNumber) {
    FreenetURI uri;
    String description = null;
    long composedTime = fs.getLong(FS_KEY_COMPOSED_TIME, -1);
    long sentTime = fs.getLong(SFS_KEY_SENT_TIME, -1);
    long receivedTime = fs.getLong(SFS_KEY_RECEIVED_TIME, -1);
    try {
      String s = fs.get(FS_KEY_DESCRIPTION);
      if (s != null) description = Base64.decodeUTF8(s);
      uri = new FreenetURI(fs.get("URI"));
    } catch (MalformedURLException _) {
      LOG.error("Malformed URI in N2NTM File Feed message");
      return;
    } catch (IllegalBase64Exception e) {
      LOG.error("Bad Base64 encoding decoding N2NTM download feed description", e);
      return;
    }
    NodeToNodeAlertContext alertContext =
        new NodeToNodeAlertContext(this, fileNumber, composedTime, sentTime, receivedTime);
    DownloadFeedUserAlert userAlert = new DownloadFeedUserAlert(alertContext, description, uri);
    node.services().clientCore().getAlerts().register(userAlert);
  }

  @Override
  public String userToString() {
    return getPeer() + " : " + getName();
  }

  @Override
  public PeerNodeStatus getStatus(boolean noHeavy) {
    return new DarknetPeerNodeStatus(this, noHeavy);
  }

  @Override
  public boolean isDarknet() {
    return true;
  }

  @Override
  public boolean isOpennet() {
    return false;
  }

  @Override
  public boolean isSeed() {
    return false;
  }

  @Override
  public void onSuccess(boolean insert, boolean ssk) {
    // Ignore it
  }

  @Override
  public void onRemove() {
    // Do nothing (no cleanup required here)
  }

  @Override
  public boolean isRealConnection() {
    return true;
  }

  @Override
  public boolean recordStatus() {
    return true;
  }

  /** Darknet peers clear peerAddedTime on connecting. */
  @Override
  protected void maybeClearPeerAddedTimeOnConnect() {
    peerAddedTime = 0; // don't store anymore
  }

  /**
   * Darknet nodes *do* export the peer added time. However, it gets cleared on connecting: It is
   * only kept for never-connected peers, so we can see that we haven't had a connection in a long
   * time and offer to get rid of them.
   */
  @Override
  protected boolean shouldExportPeerAddedTime() {
    return true;
  }

  /**
   * Clears or retains {@code peerAddedTime} across restarts based on age and first-connection.
   *
   * @param now current time in milliseconds since epoch.
   */
  @Override
  protected void maybeClearPeerAddedTimeOnRestart(long now) {
    if ((now - peerAddedTime) > DAYS.toMillis(30)) peerAddedTime = 0;
    if (!neverConnected) peerAddedTime = 0;
  }

  // Note: fatal timeout handling logs and disconnects
  /** Handles a fatal timeout by disconnecting and logging a warning for the user. */
  @Override
  public void fatalTimeout() {
    if (node.isStopping()) return;
    LOG.error(
        "Disconnecting from darknet node {} because of fatal timeout",
        this,
        new Exception("error"));
    LOG.warn(
        "Your friend node \"{}\" ({}, version {}) is having severe problems. We have disconnected"
            + " to try to limit the effect on us. It will reconnect soon.",
        getName(),
        getPeer(),
        getVersion());
    // Note: consider posting a user alert for better visibility
    // Disconnect.
    forceDisconnect();
  }

  /** Returns the current trust level for this friend. */
  public synchronized FRIEND_TRUST getTrustLevel() {
    return trustLevel;
  }

  /**
   * Returns whether to route, according to the peer's location for a given HTL.
   *
   * @param htl hop-to-live value.
   * @return {@code true} unless globally disabled or trust is {@link FRIEND_TRUST#LOW}.
   */
  @Override
  public boolean shallWeRouteAccordingToOurPeersLocation(int htl) {
    if (!node.shallWeRouteAccordingToOurPeersLocation(htl)) return false; // Globally disabled
    return getTrustLevel() != FRIEND_TRUST.LOW;
  }

  /** Sets the trust level and persists peer metadata. */
  public synchronized void setTrustLevel(FRIEND_TRUST trust) {
    trustLevel = trust;
    node.network().peers().writePeersDarknetUrgent();
  }

  /**
   * Visibility is the stricter of our setting and what the peer reports, to maintain reciprocity.
   */
  public synchronized FRIEND_VISIBILITY getVisibility() {
    // ourVisibility can't be null.
    if (ourVisibility.isStricterThan(theirVisibility)) return ourVisibility;
    return theirVisibility;
  }

  /** Returns our local visibility preference (non-null). */
  public synchronized FRIEND_VISIBILITY getOurVisibility() {
    return ourVisibility;
  }

  /**
   * Updates our visibility preference and sends it to the peer when connected.
   *
   * @param visibility new preference.
   */
  public synchronized void setVisibility(FRIEND_VISIBILITY visibility) {
    if (ourVisibility == visibility) return;
    ourVisibility = visibility;
    node.network().peers().writePeersDarknetUrgent();
    try {
      sendVisibility();
    } catch (NotConnectedException _) {
      LOG.info("Disconnected while sending visibility update");
    }
  }

  private void sendVisibility() throws NotConnectedException {
    transport()
        .sendAsync(
            DMT.createFNPVisibility(getOurVisibility().code),
            null,
            node.network().stats().initialMessagesCtr);
  }

  /** Applies a visibility update received from the peer. */
  public void handleVisibility(Message m) {
    FRIEND_VISIBILITY v = FRIEND_VISIBILITY.getByCode(m.getShort(DMT.FRIEND_VISIBILITY));
    if (v == null) {
      LOG.error(
          "Bogus visibility setting from peer {} : code {}",
          this,
          m.getShort(DMT.FRIEND_VISIBILITY));
      v = FRIEND_VISIBILITY.NO;
    }
    synchronized (this) {
      if (theirVisibility == v) return;
      theirVisibility = v;
    }
    node.network().peers().writePeersDarknet();
  }

  /** Returns the peer-reported visibility, or {@link FRIEND_VISIBILITY#NO} if unknown. */
  public synchronized FRIEND_VISIBILITY getTheirVisibility() {
    if (theirVisibility == null) return FRIEND_VISIBILITY.NO;
    return theirVisibility;
  }

  @Override
  boolean dontKeepFullFieldSet() {
    return false;
  }

  private boolean sendingFullNoderef;

  /**
   * Sends our full (compressed) noderef to the peer using a bulk transfer.
   *
   * <p>Concurrent sends are suppressed to avoid redundant work.
   */
  @SuppressWarnings("java:S1181")
  public void sendFullNoderef() {
    synchronized (this) {
      if (sendingFullNoderef) return; // DoS????
      sendingFullNoderef = true;
    }
    RandomAccessBuffer raf = null;
    try {
      SimpleFieldSet myFullNoderef = node.network().exportDarknetPublicFieldSet();
      byte[] data = compressNoderef(myFullNoderef);
      if (data.length == 0) {
        synchronized (this) {
          sendingFullNoderef = false;
        }
        return;
      }
      long uid = random.nextLong();
      raf = new ByteArrayRandomAccessBuffer(data);
      PartiallyReceivedBulk prb =
          new PartiallyReceivedBulk(node.network().usm(), data.length, Node.PACKET_SIZE, raf, true);
      if (!trySendMyFullNoderefHeader(uid, data.length)) {
        synchronized (this) {
          sendingFullNoderef = false;
        }
        raf.close();
        return;
      }
      final BulkTransmitter bt;
      bt = createBulkTransmitterOrNull(prb, uid);
      if (bt == null) {
        synchronized (this) {
          sendingFullNoderef = false;
        }
        raf.close();
        return;
      }
      final RandomAccessBuffer raf0 = raf; // hand off to worker and avoid closing in catch
      raf = null;
      node.network()
          .executor()
          .execute(
              () -> {
                try {
                  bt.send();
                } catch (DisconnectedException _) {
                  // :|
                } finally {
                  synchronized (DarknetPeerNode.this) {
                    sendingFullNoderef = false;
                  }
                  // Ensure the temporary in-memory buffer is released.
                  raf0.close();
                }
              });
    } catch (RuntimeException | Error e) {
      synchronized (this) {
        sendingFullNoderef = false;
      }
      if (raf != null) {
        raf.close();
      }
      throw e;
    }
  }

  private byte[] compressNoderef(SimpleFieldSet myFullNoderef) {
    try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DeflaterOutputStream dos = new DeflaterOutputStream(baos)) {
      myFullNoderef.writeTo(dos);
      return baos.toByteArray();
    } catch (IOException e) {
      LOG.error("Impossible: Caught error while writing compressed noderef: {}", e, e);
      return new byte[0];
    }
  }

  private void sendMyFullNoderefHeader(long uid, int length) throws NotConnectedException {
    transport()
        .sendAsync(
            DMT.createFNPMyFullNoderef(uid, length), null, node.network().stats().foafCounter);
  }

  private BulkTransmitter createBulkTransmitter(PartiallyReceivedBulk prb, long uid)
      throws DisconnectedException {
    return new BulkTransmitter(prb, this, uid, false, node.network().stats().foafCounter, false);
  }

  private boolean trySendMyFullNoderefHeader(long uid, int length) {
    try {
      sendMyFullNoderefHeader(uid, length);
      return true;
    } catch (NotConnectedException _) {
      return false;
    }
  }

  private BulkTransmitter createBulkTransmitterOrNull(PartiallyReceivedBulk prb, long uid) {
    try {
      return createBulkTransmitter(prb, uid);
    } catch (DisconnectedException _) {
      return null;
    }
  }

  private boolean receivingFullNoderef;

  /**
   * Receives, inflates, and applies a full noderef sent by the peer.
   *
   * <p>Concurrent receives are suppressed to avoid excessive resource usage.
   */
  @SuppressWarnings("java:S1181")
  public void handleFullNoderef(Message m) {
    long uid = m.getLong(DMT.UID);
    int length = m.getInt(DMT.NODEREF_LENGTH);
    if (length > 8 * 1024) {
      // Way too long!
      return;
    }
    synchronized (this) {
      if (receivingFullNoderef) return; // DoS????
      receivingFullNoderef = true;
    }
    RandomAccessBuffer raf = null;
    try {
      final byte[] data = new byte[length];
      raf = new ByteArrayRandomAccessBuffer(data);
      PartiallyReceivedBulk prb =
          new PartiallyReceivedBulk(node.network().usm(), length, Node.PACKET_SIZE, raf, false);
      final BulkReceiver br = new BulkReceiver(prb, this, uid, node.network().stats().foafCounter);
      final RandomAccessBuffer raf0 =
          raf; // hand off to worker; avoid closing in catch when scheduled
      raf = null;
      node.network()
          .executor()
          .execute(
              () -> {
                try {
                  if (br.receive()) {
                    SimpleFieldSet fs;
                    try (ByteArrayInputStream bais = new ByteArrayInputStream(data);
                        InflaterInputStream dis = new InflaterInputStream(bais);
                        BufferedReader reader =
                            new BufferedReader(
                                new InputStreamReader(dis, StandardCharsets.UTF_8))) {
                      fs = new SimpleFieldSet(reader, false, false);
                    } catch (IOException e) {
                      synchronized (DarknetPeerNode.this) {
                        receivingFullNoderef = false;
                      }
                      LOG.error("Impossible: {}", e, e);
                      return;
                    }
                    try {
                      processNewNoderef(fs, false, false, true);
                    } catch (FSParseException e) {
                      LOG.error("Peer {} sent bogus full noderef: {}", DarknetPeerNode.this, e, e);
                      synchronized (DarknetPeerNode.this) {
                        receivingFullNoderef = false;
                      }
                      return;
                    }
                    synchronized (DarknetPeerNode.this) {
                      fullFieldSet.set(fs);
                    }
                    node.network().peers().writePeersDarknet();
                  } else {
                    LOG.error("Failed to receive noderef from {}", DarknetPeerNode.this);
                  }
                } finally {
                  synchronized (DarknetPeerNode.this) {
                    receivingFullNoderef = false;
                  }
                  // Ensure the temporary buffer is released.
                  raf0.close();
                }
              });
    } catch (RuntimeException | Error e) {
      synchronized (this) {
        receivingFullNoderef = false;
      }
      if (raf != null) {
        raf.close();
      }
      throw e;
    }
  }

  /** Sends initial post-handshake messages (visibility and optional full-noderef request). */
  @Override
  protected void sendInitialMessages() {
    super.sendInitialMessages();
    try {
      sendVisibility();
    } catch (NotConnectedException e) {
      LOG.error("Completed handshake with {} but disconnected: {}", getPeer(), e, e);
    }
    try {
      transport()
          .sendAsync(DMT.createFNPGetYourFullNoderef(), null, node.network().stats().foafCounter);
    } catch (NotConnectedException _) {
      // Ignore
    }
  }

  /** Returns {@code false}; darknet peers never expose opennet noderefs. */
  @Override
  public boolean isOpennetForNoderef() {
    return false;
  }

  /**
   * Returns whether opennet refs may be passed through this darknet peer according to node policy.
   */
  @Override
  public boolean canAcceptAnnouncements() {
    return node.passOpennetRefsThroughDarknet();
  }

  /** Persists the peers list without forcing a darknet-only write. */
  @Override
  protected void writePeers() {
    peers.writePeers(false);
  }

  @Override
  public boolean equals(Object o) {
    if (o == this) return true;
    // Only equal to a DarknetPeerNode with the same identity; prevent cross-type equality.
    if (o instanceof DarknetPeerNode) {
      return super.equals(o);
    } else return false;
  }
}

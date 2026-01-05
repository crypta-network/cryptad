package network.crypta.node;

import static java.util.concurrent.TimeUnit.HOURS;
import static java.util.concurrent.TimeUnit.SECONDS;

import network.crypta.io.comm.PeerParseException;
import network.crypta.io.comm.ReferenceSignatureVerificationException;
import network.crypta.node.OpennetManager.LinkLengthClass;
import network.crypta.node.updater.NodeUpdateManager;
import network.crypta.node.updater.UpdateOverMandatoryManager;
import network.crypta.support.SimpleFieldSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Opennet-specific {@link PeerNode} implementation.
 *
 * <p>This type represents a peer discovered or maintained by the Opennet subsystem rather than the
 * darknet/friend-to-friend subsystem. It adds Opennet-oriented lifecycle and policy hooks such as
 * droppability decisions, success tracking, and limited export of metadata. Unless stated
 * otherwise, semantics match those of the base {@link PeerNode}.
 */
@SuppressWarnings("java:S1206") // hashCode() is inherited; equals() restricts to subclass type
public class OpennetPeerNode extends PeerNode {
  private static final Logger LOG = LoggerFactory.getLogger(OpennetPeerNode.class);

  final OpennetManager opennet;
  private long timeLastSuccess;
  // Not persisted across restarts: startup resets grace semantics (disconnection handling is
  // managed separately).
  private int opennetNodeAddedReason = ADDED_REASON_UNKNOWN;

  /**
   * Creates a new Opennet peer instance from a noderef.
   *
   * @param fs structured noderef and metadata. When {@code fromLocal} is true, the constructor
   *     reads {@code metadata.timeLastSuccess} from it.
   * @param node2 owning node instance.
   * @param crypto cryptographic utilities used by the peer.
   * @param opennet Opennet manager that coordinates Opennet peers.
   * @param fromLocal whether the reference originates locally (enables loading of persisted
   *     metadata).
   * @param peers peer manager to register with.
   * @throws FSParseException if the field set cannot be parsed.
   * @throws PeerParseException if mandatory peer fields are invalid.
   * @throws ReferenceSignatureVerificationException if the noderef signature fails verification.
   * @throws PeerTooOldException if the referenced peer does not meet minimum version requirements.
   */
  public OpennetPeerNode(
      SimpleFieldSet fs,
      Node node2,
      NodeCrypto crypto,
      OpennetManager opennet,
      boolean fromLocal,
      PeerManager peers)
      throws FSParseException,
          PeerParseException,
          ReferenceSignatureVerificationException,
          PeerTooOldException {
    super(fs, node2, crypto, fromLocal, peers);

    if (fromLocal) {
      SimpleFieldSet metadata = fs.subset("metadata");
      timeLastSuccess = metadata.getLong("timeLastSuccess", 0);
    }

    this.opennet = opennet;
  }

  /**
   * Returns the current status snapshot for this peer.
   *
   * @param noHeavy when {@code true}, avoids expensive computations and I/O.
   * @return an {@link OpennetPeerNodeStatus} view of the current state.
   */
  @Override
  public PeerNodeStatus getStatus(boolean noHeavy) {
    return new OpennetPeerNodeStatus(this, noHeavy);
  }

  /**
   * Indicates whether routing to or through this peer is currently permitted.
   *
   * <p>Routing is allowed only when Opennet is enabled on the owning node and the base routing
   * compatibility checks succeed.
   */
  @Override
  public boolean isRoutingCompatible() {
    if (!node.network().isOpennetEnabled()) return false;
    return super.isRoutingCompatible();
  }

  /** Always {@code false} for Opennet peers. */
  @Override
  public boolean isDarknet() {
    return false;
  }

  /** Always {@code true} for Opennet peers. */
  @Override
  public boolean isOpennet() {
    return true;
  }

  /** Opennet peers are not seed nodes. Returns {@code false}. */
  @Override
  public boolean isSeed() {
    return false;
  }

  /** Enumerates reasons why a peer must not be dropped during pruning. */
  public enum NOT_DROP_REASON {
    /** No reason to keep the peer; it is eligible for dropping. */
    DROPPABLE,
    /** Peer was added recently and has not had sufficient time to connect. */
    TOO_NEW_PEER,
    /** Our node uptime is still low; allow time for initial connections. */
    TOO_LOW_UPTIME,
    /** Recently disconnected; honor a short reconnection grace period. */
    RECONNECT_GRACE_PERIOD
  }

  /**
   * Convenience wrapper for {@link #isDroppableWithReason(boolean)} returning a boolean.
   *
   * @param ignoreDisconnect whether to ignore the reconnection grace-period checks.
   * @return {@code true} if the peer may be dropped.
   */
  public boolean isDroppable(boolean ignoreDisconnect) {
    return isDroppableWithReason(ignoreDisconnect) == NOT_DROP_REASON.DROPPABLE;
  }

  /**
   * Determines whether the peer is droppable and explains why if not.
   *
   * <p>Side effect: when the initial grace period has elapsed, this method resets the internal
   * {@code peerAddedTime} and {@code opennetPeerAddedReason} markers used to enforce that period.
   * The caller must perform any additional version/age checks separately.
   *
   * @param ignoreDisconnect when {@code true}, omits the reconnection grace-period check applied to
   *     recently disconnected peers.
   * @return a {@link NOT_DROP_REASON} indicating why the peer must be retained, or {@link
   *     NOT_DROP_REASON#DROPPABLE} when it may be removed.
   */
  public NOT_DROP_REASON isDroppableWithReason(boolean ignoreDisconnect) {
    long now = System.currentTimeMillis();
    int status = getPeerNodeStatus();
    long age = now - getPeerAddedTime();
    if (age < OpennetManager.DROP_MIN_AGE) {
      if (status == PeerManager.PEER_NODE_STATUS_NEVER_CONNECTED) {
        // New peer, never connected.
        // Allow it 1 minute to connect.
        if (age < OpennetManager.DROP_MIN_AGE_DISCONNECTED) return NOT_DROP_REASON.TOO_NEW_PEER;
      } else if (status != PeerManager.PEER_NODE_STATUS_DISCONNECTED) {
        // Based on the time added, *not* the last connected time.
        // This prevents various dubious ways of staying connected while not delivering anything
        // useful.
        return NOT_DROP_REASON.TOO_NEW_PEER; // New node
      }
    } else {
      synchronized (this) {
        peerAddedTime = 0;
        opennetNodeAddedReason = ADDED_REASON_UNKNOWN;
      }
    }
    if (now - node.network().usm().getStartedTime() < OpennetManager.DROP_STARTUP_DELAY)
      return NOT_DROP_REASON.TOO_LOW_UPTIME; // Give them time to connect after we startup
    if (!ignoreDisconnect) {
      synchronized (this) {
        // This only applies after it has connected, and only if !ignoreDisconnect.
        // Hence only DISCONNECTED and not NEVER CONNECTED.
        if ((status == PeerManager.PEER_NODE_STATUS_DISCONNECTED)
            && (!super.neverConnected())
            && now - timeLastDisconnect < OpennetManager.DROP_DISCONNECT_DELAY
            && now - timePrevDisconnect > OpennetManager.DROP_DISCONNECT_DELAY_COOLDOWN) {
          // Grace period for node restarting
          return NOT_DROP_REASON.RECONNECT_GRACE_PERIOD;
        }
      }
    }
    return NOT_DROP_REASON.DROPPABLE;
  }

  /**
   * Records a successful transfer for routing decisions.
   *
   * <p>Only counts pure data fetch successes (not inserts or SSK traffic). Updates {@link
   * #timeLastSuccess} and notifies the {@link OpennetManager}.
   *
   * @param insert whether the success was an insert operation.
   * @param ssk whether the success was related to SSK.
   */
  @Override
  public void onSuccess(boolean insert, boolean ssk) {
    if (insert || ssk) return;
    timeLastSuccess = System.currentTimeMillis();
    opennet.onSuccess(this);
  }

  /**
   * Notifies the {@link OpennetManager} that the peer is being removed and then delegates to the
   * base implementation.
   */
  @Override
  public void onRemove() {
    opennet.onRemove(this);
    super.onRemove();
  }

  /**
   * Exports Opennet-specific transient metadata.
   *
   * <p>Adds {@code timeLastSuccess} to the base metadata. The value is a millisecond epoch time.
   *
   * @param now current time in milliseconds since the epoch (forwarded to the base exporter).
   * @return a field set containing peer metadata.
   */
  @Override
  public synchronized SimpleFieldSet exportMetadataFieldSet(long now) {
    SimpleFieldSet fs = super.exportMetadataFieldSet(now);
    fs.put("timeLastSuccess", timeLastSuccess);
    return fs;
  }

  /**
   * Returns the timestamp of the last successful data fetch.
   *
   * @return milliseconds since the epoch, or {@code 0} when unknown.
   */
  public final long timeLastSuccess() {
    return timeLastSuccess;
  }

  /**
   * Checks whether the provided {@link SimpleFieldSet} marks a noderef as Opennet-capable.
   *
   * @param ref noderef field set.
   * @return {@code true} when the field {@code opennet} is present and truthy.
   */
  public static boolean validateRef(SimpleFieldSet ref) {
    return ref.getBoolean("opennet", false);
  }

  /** Always treated as a real connection for Opennet peers. */
  @Override
  public boolean isRealConnection() {
    return true;
  }

  /** Whether we record status snapshots for this peer. Always {@code true}. */
  @Override
  public boolean recordStatus() {
    return true;
  }

  /**
   * Equality is restricted to the same concrete type. Two peers are equal when the base identity
   * comparison succeeds and the other object is also an {@code OpennetPeerNode}.
   */
  @Override
  public boolean equals(Object o) {
    if (o == this) return true;
    // Only equal to an OpennetPeerNode with the same identity; prevent cross-type equality.
    if (o instanceof OpennetPeerNode) {
      return super.equals(o);
    } else return false;
  }

  /**
   * Determines whether an immediate disconnect and removal is required.
   *
   * <p>When connected to a peer that is too old, allows a short window for update-over-mandatory
   * (UOM) coordination via {@link #shouldDisconnectTooOld()}.
   *
   * @return {@code true} when the connection should be severed now.
   */
  @Override
  public final boolean shouldDisconnectAndRemoveNow() {
    // Allow announced peers 15 minutes to download the auto-update.
    if (isConnected() && isUnroutableOlderVersion()) {
      return shouldDisconnectTooOld();
    }
    return false;
  }

  /**
   * If a node is TOO OLD, we should keep it connected for a brief period for it to allow it to
   * issue a UOM request, we should keep it connected while the UOM transfer is in progress, but
   * otherwise we should disconnect.
   */
  private boolean shouldDisconnectTooOld() {
    long uptime = System.currentTimeMillis() - timeLastConnectionCompleted();
    if (uptime < SECONDS.toMillis(30))
      // Allow 30 seconds to send the UOM request.
      return false;
    // Paranoia guard: retain extra delay for safety
    if (uptime < HOURS.toMillis(1)) return false;
    NodeUpdateManager updater = node.services().nodeUpdater();
    if (updater == null) return true; // Not going to UOM.
    UpdateOverMandatoryManager uom = updater.getUpdateOverMandatory();
    if (uom == null) return true; // Not going to UOM
    if (uptime > HOURS.toMillis(2)) {
      // UOM transfers can take ages, but there has to be some limit...
      return true;
    }
    // Let it finish.
    // 60 seconds extra to ensure it has time to parse the jar and start fetching dependencies.
    return timeSinceSentUOM() >= SECONDS.toMillis(60);
  }

  /**
   * Called on successful connect. Marks the address as presumed guilty for a short period so that
   * address tracking can prefer other paths temporarily.
   */
  @Override
  protected void onConnect() {
    super.onConnect();
    opennet
        .getCrypto()
        .getSocket()
        .getAddressTracker()
        .setPresumedGuiltyAt(System.currentTimeMillis() + HOURS.toMillis(1));
  }

  private boolean wasDropped;

  synchronized void setWasDropped() {
    wasDropped = true;
  }

  synchronized boolean wasDropped() {
    return wasDropped;
  }

  synchronized boolean grabWasDropped() {
    boolean ret = wasDropped;
    wasDropped = false;
    return ret;
  }

  /** Remembers why the node was added to enforce the initial grace period. */
  @Override
  public synchronized void setAddedReason(int addedReason) {
    opennetNodeAddedReason = addedReason;
  }

  /** Returns the reason recorded when the node was added, or {@code null} if unknown. */
  @Override
  public synchronized int getAddedReason() {
    return opennetNodeAddedReason;
  }

  /**
   * Schedules deferred clearing of the added-time markers once the grace period has elapsed.
   *
   * <p>Opennet peers keep the markers across the first successful connect to enforce the initial
   * grace period; the timed job will trigger {@link #isDroppableWithReason(boolean)} after the
   * minimum age to clear them.
   */
  @Override
  protected void maybeClearPeerAddedTimeOnConnect() {
    // Ensure the markers are cleared after the grace window.
    node.network()
        .ticker()
        .queueTimedJob(
            (FastRunnable) () -> isDroppableWithReason(false), OpennetManager.DROP_MIN_AGE + 1);
  }

  /**
   * Opennet peers do not export {@code peerAddedTime}; it is only meaningful locally for grace
   * period enforcement.
   */
  @Override
  protected boolean shouldExportPeerAddedTime() {
    return false;
  }

  /**
   * No-op on restart. Opennet peers intentionally retain the added-time markers until the timed
   * grace-period check clears them.
   */
  @Override
  protected void maybeClearPeerAddedTimeOnRestart(long now) {
    // Do nothing.
  }

  /**
   * Handles a fatal communication timeout by forcefully disconnecting unless the node is stopping.
   */
  @Override
  public void fatalTimeout() {
    if (node.isStopping()) return;
    LOG.error("Disconnecting {} because of fatal timeout", this);
    // Disconnect.
    forceDisconnect();
  }

  /** Delegates location-based routing decisions to the owning node. */
  @Override
  public boolean shallWeRouteAccordingToOurPeersLocation(int htl) {
    return node.shallWeRouteAccordingToOurPeersLocation(htl);
  }

  @Override
  boolean dontKeepFullFieldSet() {
    return true;
  }

  LinkLengthClass linkLengthClass() {
    if (!Location.isValid(getLocation())) {
      LOG.warn("No location on {}", this);
      // Default to SHORT; introducing an UNKNOWN value would require broader handling
      return LinkLengthClass.SHORT;
    }
    // Optimization: this should not change since we don't swap on opennet
    if (Location.distance(this, opennet.getNode().network().location())
        > OpennetManager.LONG_DISTANCE) return LinkLengthClass.LONG;
    else return LinkLengthClass.SHORT;
  }

  /** Opennet noderefs are advertised as Opennet-capable. */
  @Override
  public boolean isOpennetForNoderef() {
    return true;
  }

  /** Opennet peers may receive and handle announcements. */
  @Override
  public boolean canAcceptAnnouncements() {
    return true;
  }

  /** Writes peer state, including Opennet peers. */
  @Override
  protected void writePeers() {
    peers.writePeers(true);
  }
}

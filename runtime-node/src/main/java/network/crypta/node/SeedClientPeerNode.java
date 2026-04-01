package network.crypta.node;

import network.crypta.io.comm.PeerParseException;
import network.crypta.io.comm.ReferenceSignatureVerificationException;
import network.crypta.support.SimpleFieldSet;

import static java.util.concurrent.TimeUnit.HOURS;
import static java.util.concurrent.TimeUnit.SECONDS;

/**
 * Seed-side representation of a remote client that connects only to announce.
 *
 * <p>This peer type exists, so seeds can receive announcements and hand out references without
 * treating the connection like a regular Opennet/Darknet link. It deliberately avoids persisting
 * state, routing traffic, or initiating handshakes. Equality is restricted to this concrete type; a
 * {@code SeedClientPeerNode} is not equal to an {@link OpennetPeerNode} even if the identities
 * match.
 *
 * @author toad
 */
@SuppressWarnings("java:S1206")
public class SeedClientPeerNode extends PeerNode {

  /**
   * Creates a new seed-client peer from a noderef field set.
   *
   * @param fs structured noderef and metadata.
   * @param node2 owning node instance.
   * @param crypto cryptographic utilities used by the peer.
   * @param peers peer manager to register/coordinate with.
   * @throws FSParseException if the field set cannot be parsed.
   * @throws PeerParseException if mandatory peer fields are invalid.
   * @throws ReferenceSignatureVerificationException if the noderef signature fails verification.
   * @throws PeerTooOldException if the referenced peer does not meet minimum version requirements.
   */
  public SeedClientPeerNode(SimpleFieldSet fs, Node node2, NodeCrypto crypto, PeerManager peers)
      throws FSParseException,
          PeerParseException,
          ReferenceSignatureVerificationException,
          PeerTooOldException {
    super(
        PeerNodeConstructorSupport.prepareConstructorInit(
            fs, node2, crypto, false, peers, ConstructorProfile.SEED_CLIENT));
  }

  /**
   * Returns a lightweight status snapshot for this peer.
   *
   * @param noHeavy when {@code true}, avoids expensive computations and I/O.
   * @return a {@link PeerNodeStatus} view of the current state.
   */
  @Override
  public PeerNodeStatus getStatus(boolean noHeavy) {
    return new PeerNodeStatus(this, noHeavy);
  }

  /** Always {@code false}; seed clients are not darknet peers. */
  @Override
  public boolean isDarknet() {
    return false;
  }

  /**
   * Returns {@code false} for connection classification.
   *
   * <p>Seed clients are not regular Opennet links. For noderef advertisement they report as
   * Opennet-capable via {@link #isOpennetForNoderef()}.
   */
  @Override
  public boolean isOpennet() {
    return false;
  }

  /** Always {@code true}; this peer exists only on seed nodes. */
  @Override
  public boolean isSeed() {
    return true;
  }

  /**
   * Not a real routed connection.
   *
   * <p>A seed may also have a normal connection to the same remote identity; this representation
   * remains separate and is not used for routing.
   */
  @Override
  public boolean isRealConnection() {
    return false;
  }

  /**
   * Equality is restricted to the same concrete type.
   *
   * <p>Two peers are equal when the base identity comparison succeeds and the other object is also
   * a {@code SeedClientPeerNode}. This prevents cross-type equality with {@link OpennetPeerNode}.
   */
  @Override
  public boolean equals(Object o) {
    if (o == this) return true;
    // Only equal to a seed client of the same type; not equal to an Opennet peer with the same
    // identity.
    if (o instanceof SeedClientPeerNode) {
      return super.equals(o);
    } else return false;
  }

  /** Seed clients do not track success metrics. */
  @Override
  public void onSuccess(boolean insert, boolean ssk) {
    // Intentionally ignored.
  }

  /** Seed clients never participate in routing. Always {@code false}. */
  @Override
  public boolean isRoutingCompatible() {
    return false;
  }

  /** Seed clients are allowed to accept announce messages. Returns {@code true}. */
  @Override
  public boolean canAcceptAnnouncements() {
    return true;
  }

  /** Seed clients do not record periodic status snapshots. Returns {@code false}. */
  @Override
  public boolean recordStatus() {
    return false;
  }

  /** Handshakes may arrive from unknown initiators. Returns {@code true}. */
  @Override
  public boolean handshakeUnknownInitiator() {
    return true;
  }

  /**
   * Returns the setup type used for seed-client handshakes.
   *
   * @return {@link FNPPacketMangler#SETUP_OPENNET_SEEDNODE}.
   */
  @Override
  public int handshakeSetupType() {
    return FNPPacketMangler.SETUP_OPENNET_SEEDNODE;
  }

  /** Seed clients do not initiate handshakes. Returns {@code false}. */
  @Override
  public boolean shouldSendHandshake() {
    return false;
  }

  /**
   * Disconnects and removes this peer from the manager, delegating to the base implementation
   * first.
   *
   * @param dumpMessageQueue ignored; the method always dumps queues.
   * @param dumpTrackers ignored; the method always dumps trackers.
   * @return whether the base {@code disconnected()} returned {@code true}.
   */
  @Override
  public boolean disconnected(boolean dumpMessageQueue, boolean dumpTrackers) {
    boolean ret = super.disconnected(true, true);
    node.network().peers().messenger().disconnectAndRemove(this, false, false, false);
    return ret;
  }

  /** Seed clients ignore the "last good version" heuristic. Returns {@code true}. */
  @Override
  protected boolean ignoreLastGoodVersion() {
    return true;
  }

  /** Seed clients do not start ARK fetchers. */
  @Override
  void startARKFetcher() {
    // No-op by design.
  }

  /**
   * Determines whether the peer should be disconnected and removed immediately.
   *
   * <p>Heuristics:
   *
   * <ul>
   *   <li>When connected: disconnect after one hour from the last completed connection.
   *   <li>When not connected: if a connection was completed previously and no packets have been
   *       received for 60 seconds, remove the peer.
   * </ul>
   *
   * @return {@code true} when the peer must be dropped now.
   */
  @Override
  public boolean shouldDisconnectAndRemoveNow() {
    if (!isConnected()) {
      // Start unverified; if no packets arrive for 60 seconds after a completed connection,
      // remove the peer. Synchronize to avoid races on timestamps.
      synchronized (this) {
        if (timeLastConnectionCompleted() > 0
            && System.currentTimeMillis() - lastReceivedPacketTime() > SECONDS.toMillis(60))
          return true;
      }
    } else {
      // Enforce a maximum connected lifetime of one hour.
      return System.currentTimeMillis() - timeLastConnectionCompleted() > HOURS.toMillis(1);
    }
    return false;
  }

  /** No-op; seed clients do not clear added-time markers on connection. */
  @Override
  protected void maybeClearPeerAddedTimeOnConnect() {
    // Intentionally empty.
  }

  /** Exports {@code peerAddedTime} for diagnostics only. Returns {@code true}. */
  @Override
  protected boolean shouldExportPeerAddedTime() {
    return true;
  }

  /** No-op on restart; seed clients never clear the added-time marker here. */
  @Override
  protected void maybeClearPeerAddedTimeOnRestart(long now) {
    // Intentionally empty.
  }

  /** Handles a fatal timeout by forcefully disconnecting. */
  @Override
  public void fatalTimeout() {
    // Disconnect immediately.
    forceDisconnect();
  }

  /** Seed clients never route based on peer location. Always {@code false}. */
  @Override
  public boolean shallWeRouteAccordingToOurPeersLocation(int htl) {
    return false;
  }

  /**
   * Notifies the {@link OpennetManager}'s seed tracker on connection and then delegates to the base
   * implementation.
   */
  @Override
  protected void onConnect() {
    OpennetManager om = node.network().opennet();
    if (om != null) om.getSeedTracker().onConnectSeed(this);
    super.onConnect();
  }

  @Override
  boolean dontKeepFullFieldSet() {
    return true;
  }

  /** Advertise this noderef as Opennet-capable. Returns {@code true}. */
  @Override
  public boolean isOpennetForNoderef() {
    return true;
  }

  /** No-op. Seed clients are not persisted in the peers list and therefore do not write state. */
  @Override
  protected void writePeers() {
    // Intentionally empty: seed clients are not saved.
  }

  /** Seed-client inbound handshakes originate from anonymous initiators. Returns {@code true}. */
  @Override
  protected boolean fromAnonymousInitiator() {
    return true;
  }
}

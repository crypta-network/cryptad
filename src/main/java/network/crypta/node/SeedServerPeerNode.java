package network.crypta.node;

import static java.util.concurrent.TimeUnit.MINUTES;
import static java.util.concurrent.TimeUnit.SECONDS;

import java.net.InetAddress;
import java.util.ArrayList;
import network.crypta.io.comm.FreenetInetAddress;
import network.crypta.io.comm.Peer;
import network.crypta.io.comm.PeerParseException;
import network.crypta.io.comm.ReferenceSignatureVerificationException;
import network.crypta.support.SimpleFieldSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Sender-side representation of a seed server peer.
 *
 * <p>A {@code SeedServerPeerNode} models a remote seed used to bootstrap Opennet. It is not treated
 * as a regular routing peer: it never counts toward routing compatibility, does not accept
 * announcements, and is removed once the node has maintained enough Opennet peers for a period of
 * time. Equality is limited to the same subclass (see {@link #equals(Object)}), while {@link
 * #hashCode()} is inherited from {@link PeerNode}.
 *
 * @author toad
 */
@SuppressWarnings("java:S1206") // hashCode() is inherited; equals() restricts to subclass type
public class SeedServerPeerNode extends PeerNode {
  private static final Logger LOG = LoggerFactory.getLogger(SeedServerPeerNode.class);

  /**
   * Creates a seed peer from a node reference.
   *
   * @param fs parsed node reference ({@link SimpleFieldSet}).
   * @param node2 owning node instance.
   * @param crypto crypto helper bound to the owning node.
   * @param fromLocal whether the reference originates from the local system.
   * @param peers peer manager used for lifecycle operations.
   * @throws FSParseException if the reference cannot be parsed.
   * @throws PeerParseException if mandatory peer fields are invalid.
   * @throws ReferenceSignatureVerificationException if signature verification fails.
   * @throws PeerTooOldException if the peer is below the supported minimum.
   */
  public SeedServerPeerNode(
      SimpleFieldSet fs, Node node2, NodeCrypto crypto, boolean fromLocal, PeerManager peers)
      throws FSParseException,
          PeerParseException,
          ReferenceSignatureVerificationException,
          PeerTooOldException {
    super(fs, node2, crypto, fromLocal, peers);
  }

  /**
   * Returns a snapshot of this peer's status.
   *
   * @param noHeavy when {@code true}, avoids expensive computations.
   * @return status for UI/monitoring; lightweight when {@code noHeavy} is {@code true}.
   */
  @Override
  public PeerNodeStatus getStatus(boolean noHeavy) {
    return new PeerNodeStatus(this, noHeavy);
  }

  /** Seed peers are not Darknet connections. */
  @Override
  public boolean isDarknet() {
    return false;
  }

  /**
   * Returns {@code false} because seeds are not handled as regular Opennet peers for runtime
   * routing logic. See {@link #isOpennetForNoderef()} for noderef export semantics.
   */
  @Override
  public boolean isOpennet() {
    return false;
  }

  /** Identifies this peer as a seed. */
  @Override
  public boolean isSeed() {
    return true;
  }

  /** Seed connections are not considered "real" for connection accounting. */
  @Override
  public boolean isRealConnection() {
    return false;
  }

  /**
   * Compares by {@link PeerNode} identity but only for the same subclass.
   *
   * <p>This ensures a seed is never equal to an {@code OpennetPeerNode} with the same underlying
   * identity.
   */
  @Override
  public boolean equals(Object o) {
    if (o == this) return true;
    // Only equal to seed nodes of the same type. Different from an Opennet peer with the
    // same identity by design.
    if (o instanceof SeedServerPeerNode) {
      return super.equals(o);
    } else return false;
  }

  /** No-op for seeds; request success does not affect seed peer state. */
  @Override
  public void onSuccess(boolean insert, boolean ssk) {
    // Intentionally ignored.
  }

  /** Seeds are never used for routing decisions. */
  @Override
  public boolean isRoutingCompatible() {
    return false;
  }

  /** Status persistence is disabled for seed peers. */
  @Override
  public boolean recordStatus() {
    return false;
  }

  /**
   * Sends initial messages after connection establishment.
   *
   * <p>If Opennet is enabled, schedules a delayed announcement via the {@code OpennetManager}
   * announcer after 5 seconds to avoid concentrating early announcements on the quickest
   * connection. Any unexpected error is logged with the throwable.
   */
  @Override
  @SuppressWarnings("java:S1181")
  protected void sendInitialMessages() {
    super.sendInitialMessages();
    final OpennetManager om = node.network().opennet();
    if (om == null) {
      LOG.info("Opennet turned off while connecting to seednodes");
      node.network().peers().messenger().disconnectAndRemove(this, true, true, true);
    } else {
      // Delay announcements: another node may connect first; avoid biasing toward the
      // fastest initial connection.
      node.network()
          .ticker()
          .queueTimedJob(
              () -> {
                try {
                  om.getAnnouncer().maybeSendAnnouncement();
                } catch (Throwable t) {
                  LOG.error("Caught {}", t, t);
                }
              },
              SECONDS.toMillis(5));
    }
  }

  /**
   * Returns all resolved IP addresses for this seed.
   *
   * <p>Collects unique {@link InetAddress} values from the handshake addresses, dropping any
   * hostnames. Logs an error and returns an empty array if none are available.
   *
   * @return an array of unique addresses (never {@code null}).
   */
  public InetAddress[] getInetAddresses() {
    ArrayList<InetAddress> v = new ArrayList<>();
    for (Peer peer : getHandshakeIPs()) {
      FreenetInetAddress fa = peer.getFreenetAddress().dropHostname();
      if (fa != null) {
        InetAddress ia = fa.getAddress();
        if (!v.contains(ia)) {
          v.add(ia);
        }
      }
    }
    if (v.isEmpty()) {
      LOG.error("No valid addresses for seed node {}", this);
    }
    return v.toArray(new InetAddress[0]);
  }

  /** Allows handshakes where the initiator is not yet known. */
  @Override
  public boolean handshakeUnknownInitiator() {
    return true;
  }

  /**
   * Advertises the setup type used for Opennet seed nodes.
   *
   * @return the constant {@link FNPPacketMangler#SETUP_OPENNET_SEEDNODE}.
   */
  @Override
  public int handshakeSetupType() {
    return FNPPacketMangler.SETUP_OPENNET_SEEDNODE;
  }

  /**
   * Disconnects and removes the seed after delegating to the superclass.
   *
   * @return the result from {@link PeerNode#disconnected(boolean, boolean)}.
   */
  @Override
  public boolean disconnected(boolean dumpMessageQueue, boolean dumpTrackers) {
    boolean ret = super.disconnected(dumpMessageQueue, dumpTrackers);
    node.network().peers().messenger().disconnectAndRemove(this, false, false, false);
    return ret;
  }

  /**
   * Determines whether this seed should be disconnected now.
   *
   * <p>Disconnect immediately when Opennet is disabled. Otherwise, keep the seed until there are
   * enough Opennet peers; once that condition has been stable for 5 minutes, disconnect.
   *
   * @return {@code true} if the connection should be dropped now.
   */
  @Override
  public boolean shouldDisconnectAndRemoveNow() {
    OpennetManager om = node.network().opennet();
    if (om == null) return true;
    if (!om.getAnnouncer().enoughPeers()) return false;
    // Enough peers can fluctuate; require 5 minutes of stability before dropping the seed.
    return System.currentTimeMillis() - om.getAnnouncer().timeGotEnoughPeers()
        > MINUTES.toMillis(5);
  }

  /** Seeds keep their recorded added time unchanged when connecting. */
  @Override
  protected void maybeClearPeerAddedTimeOnConnect() {
    // No change for seeds.
  }

  /** Exports the peer-added timestamp for diagnostics. */
  @Override
  protected boolean shouldExportPeerAddedTime() {
    // Used only for diagnostics.
    return true;
  }

  /** Seeds keep their recorded added time unchanged on restart. */
  @Override
  protected void maybeClearPeerAddedTimeOnRestart(long now) {
    // No change for seeds.
  }

  /** Handles a fatal timeout by forcefully disconnecting. */
  @Override
  public void fatalTimeout() {
    // Drop the connection immediately.
    forceDisconnect();
  }

  /** Routing by peer location does not apply to seeds. */
  @Override
  public boolean shallWeRouteAccordingToOurPeersLocation(int htl) {
    return false; // Irrelevant
  }

  @Override
  boolean dontKeepFullFieldSet() {
    return false;
  }

  /**
   * When exporting a node reference, treat the seed as Opennet-capable.
   *
   * <p>This differs from {@link #isOpennet()} which returns {@code false} to exclude seeds from
   * runtime Opennet peer logic.
   */
  @Override
  public boolean isOpennetForNoderef() {
    return true;
  }

  /** Seeds never accept announcements. */
  @Override
  public boolean canAcceptAnnouncements() {
    return false; // Announcement intake is disabled for seeds.
  }

  /** Suppresses writing peers; seeds are persisted separately. */
  @Override
  protected void writePeers() {
    // No-op: seeds are stored via a separate mechanism.
  }
}

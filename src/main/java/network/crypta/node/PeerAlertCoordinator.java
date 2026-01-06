package network.crypta.node;

import network.crypta.node.useralerts.PeerManagerUserAlert;

/**
 * Updates and maintains the peer manager user alert based on current roster and status data.
 *
 * <p>This coordinator centralizes the mapping between live peer state and the user-facing alert
 * object. Callers construct it with the node, roster, and status book that supply the underlying
 * metrics, then invoke {@link #start()} once during node startup to create and register the alert.
 * After startup, {@link #update()} should be called whenever peer connectivity or status counters
 * change so the alert reflects the latest counts and flags.
 *
 * <p>The alert instance is created lazily in {@link #start()}, and {@link #update()} is a no-op
 * until that initialization completes. Updates synchronize on an internal lock to ensure that the
 * alert state is updated as a consistent snapshot. The coordinator itself is mutable and not
 * intended to be externally synchronized; callers should avoid concurrent calls that race with
 * startup or teardown.
 *
 * <p><strong>Responsibilities:</strong>
 *
 * <ul>
 *   <li>Translate peer roster sizes and status counts into alert fields.
 *   <li>Expose NAT and port-forwarding hints from darknet and opennet state.
 *   <li>Trigger connected-peer notifications when any peer is connected.
 * </ul>
 *
 * @see PeerManagerUserAlert
 * @see PeerRoster
 * @see PeerStatusBook
 */
public class PeerAlertCoordinator {
  private final Node node;
  private final PeerRoster roster;
  private final PeerStatusBook statusBook;

  private final Object uaLock = new Object();
  private PeerManagerUserAlert alert;

  /**
   * Creates a coordinator that derives alert values from the provided node, roster, and status
   * book.
   *
   * <p>The coordinator does not allocate or register the user alert until {@link #start()} is
   * called. The supplied references are used directly; they are expected to remain valid for the
   * lifetime of this instance. Passing {@code null} is not supported and will result in a {@link
   * NullPointerException} at construction time.
   *
   * @param node owning node that exposes opennet/darknet state and alert registration
   * @param roster peer roster used to compute current peer totals and connectivity
   * @param statusBook peer status counters used to populate detailed alert fields
   */
  public PeerAlertCoordinator(Node node, PeerRoster roster, PeerStatusBook statusBook) {
    this.node = node;
    this.roster = roster;
    this.statusBook = statusBook;
  }

  /**
   * Initializes the user alert and registers it with the node's alert manager.
   *
   * <p>This method allocates the {@link PeerManagerUserAlert}, populates it with the current
   * snapshot by calling {@link #update()}, and then registers it so it can be surfaced to users. It
   * should be invoked once during startup and is not designed to be idempotent; calling it multiple
   * times may overwrite the existing alert reference and cause duplicate registrations.
   *
   * <pre>{@code
   * PeerAlertCoordinator coordinator = new PeerAlertCoordinator(node, roster, statusBook);
   * coordinator.start();
   * }</pre>
   */
  public void start() {
    alert = new PeerManagerUserAlert(node.network().stats(), node.services().nodeUpdater());
    update();
    node.services().clientCore().getAlerts().register(alert);
  }

  /**
   * Updates the alert state from the latest peer roster and status counters.
   *
   * <p>If the alert has not yet been initialized, this method returns without side effects. When
   * initialized, it computes peer totals and connectivity counts, propagates NAT and port-forward
   * hints, and updates alert counters within a synchronized block so values reflect a coherent
   * snapshot. The method is safe to call frequently and is intended to run in response to changes
   * in peer connectivity or status bookkeeping.
   */
  public void update() {
    PeerManagerUserAlert ua = alert;
    if (ua == null) return;

    int darknetPeers = roster.getDarknetPeers().length;
    int opennetPeers = roster.getOpennetPeers().length;
    int peers = darknetPeers + opennetPeers;

    OpennetManager om = node.network().opennet();
    boolean opennetEnabled = om != null;
    boolean opennetDefinitelyPortForwarded = om != null && om.getCrypto().definitelyPortForwarded();
    boolean opennetAssumeNAT =
        om != null && om.getCrypto().getConfig().alwaysHandshakeAggressively();
    boolean darknetDefinitelyPortForwarded = node.network().darknetDefinitelyPortForwarded();
    boolean darknetAssumeNAT =
        node.network().darknetCrypto().getConfig().alwaysHandshakeAggressively();

    synchronized (uaLock) {
      ua.setOpennetDefinitelyPortForwarded(opennetDefinitelyPortForwarded);
      ua.setDarknetDefinitelyPortForwarded(darknetDefinitelyPortForwarded);
      ua.setOpennetAssumeNAT(opennetAssumeNAT);
      ua.setDarknetAssumeNAT(darknetAssumeNAT);
      int darknetConnsVal =
          statusBook.getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_CONNECTED, true)
              + statusBook.getPeerNodeStatusSize(
                  PeerManager.PEER_NODE_STATUS_ROUTING_BACKED_OFF, true);
      ua.setDarknetConns(darknetConnsVal);
      ua.setConns(
          statusBook.getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_CONNECTED, false)
              + statusBook.getPeerNodeStatusSize(
                  PeerManager.PEER_NODE_STATUS_ROUTING_BACKED_OFF, false));
      ua.setDarknetPeers(darknetPeers);
      ua.setDisconnDarknetPeers(darknetPeers - darknetConnsVal);
      ua.setPeers(peers);
      ua.setNeverConn(
          statusBook.getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_NEVER_CONNECTED, true));
      ua.setClockProblem(
          statusBook.getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_CLOCK_PROBLEM, false));
      ua.setConnError(
          statusBook.getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_CONN_ERROR, true));
      ua.setOpennetEnabled(opennetEnabled);
      ua.setTooNewPeersDarknet(
          statusBook.getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_TOO_NEW, true));
      ua.setTooNewPeersTotal(
          statusBook.getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_TOO_NEW, false));
    }
    if (roster.anyConnectedPeers()) node.network().onConnectedPeer();
  }
}

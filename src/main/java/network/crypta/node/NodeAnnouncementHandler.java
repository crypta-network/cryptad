package network.crypta.node;

import network.crypta.io.comm.DMT;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.MessageType;
import network.crypta.io.comm.NotConnectedException;
import network.crypta.io.comm.OpennetAnnounceRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Handles inbound opennet announcement requests for a node instance.
 *
 * <p>This handler is the first-stage dispatcher for announcement messages arriving from peers. It
 * extracts request fields, validates basic invariants (location range, HTL bounds, and noderef
 * sizing), and applies admission gates based on opennet availability, load-based decisions, per
 * peer limits, and seed-tracker policies. When an announcement is accepted, it schedules an {@link
 * AnnounceSender} on the node executor to perform the multi-hop announcement flow; when rejected,
 * it replies immediately with the appropriate protocol message and records completion or stats as
 * needed. The class holds no mutable state beyond the node reference and relies on collaborators
 * for synchronization.
 *
 * <p>Callers typically invoke {@link #handle(Message, PeerNode)} from the message-processing path
 * for opennet peers. The method is lightweight and non-blocking; all long-running work is deferred
 * to background executors.
 *
 * <ul>
 *   <li>Validates incoming announce requests and replies with protocol-level rejections.
 *   <li>Coordinates admission checks with {@link OpennetManager} and {@link NodeStats}.
 *   <li>Schedules {@link AnnounceSender} to perform the actual announcement routing.
 * </ul>
 *
 * @see AnnounceSender
 * @see OpennetManager
 * @see NodeStats
 */
final class NodeAnnouncementHandler {

  /** Logger for announcement admission and callback diagnostics. */
  private static final Logger LOG = LoggerFactory.getLogger(NodeAnnouncementHandler.class);

  /** Owning node used to access network subsystems and configuration. */
  private final Node node;

  /**
   * Creates a handler bound to a single node instance.
   *
   * <p>The node reference is used to access network subsystems, configuration limits, and
   * statistics counters required to validate and accept announcements. Callers should construct one
   * handler per node and reuse it for all incoming message handling.
   *
   * @param node owning node used for admission checks and scheduling; must be non-null
   */
  NodeAnnouncementHandler(Node node) {
    this.node = node;
  }

  /**
   * Attempts to handle a message as an opennet announcement request.
   *
   * <p>If the message is an {@link DMT#FNPOpennetAnnounceRequest}, this method performs validation
   * and admission checks, sends any rejection messages, and schedules an {@link AnnounceSender} on
   * success. For other message types, it performs no work and returns {@code false}. The method is
   * intentionally non-blocking and delegates long-running work to the node executor.
   *
   * @param m incoming message to inspect for announcement handling; must be non-null
   * @param source peer that sent the message and receives any rejection; must be non-null
   * @return {@code true} when the message is an announcement request, {@code false} otherwise
   */
  boolean handle(Message m, PeerNode source) {
    MessageType spec = m.getSpec();
    if (spec == DMT.FNPOpennetAnnounceRequest) {
      handleAnnounceRequest(m, source);
      return true;
    }
    return false;
  }

  /**
   * Processes a validated announcement request and performs admission gating.
   *
   * <p>The method extracts all fields, normalizes HTL, applies multiple rejection criteria, and
   * schedules the announcement sender if accepted. It always ensures that peer-local announce state
   * is completed when a rejection happens after admission begins.
   *
   * @param m announce request message containing all required fields; must be non-null
   * @param source peer that initiated the announcement; must be non-null
   */
  private void handleAnnounceRequest(Message m, PeerNode source) {
    long uid = m.getLong(DMT.UID);
    double target = m.getDouble(DMT.TARGET_LOCATION);
    short htl = (short) Math.min(m.getShort(DMT.HTL), node.maxHTL());
    long xferUID = m.getLong(DMT.TRANSFER_UID);
    int noderefLength = m.getInt(DMT.NODEREF_LENGTH);
    int paddedLength = m.getInt(DMT.PADDED_LENGTH);
    OpennetAnnounceRequest request =
        new OpennetAnnounceRequest(uid, xferUID, noderefLength, paddedLength, target, htl);

    if (rejectIfInvalidAnnounce(source, request)) return;

    OpennetManager om = node.network().opennet();
    if (rejectIfAnnouncementsDisabled(om, source, uid)) return;

    boolean success = false;
    try {
      NodeStats.AnnouncementDecision decision =
          node.network().stats().shouldAcceptAnnouncement(uid);
      if (rejectBasedOnDecision(om, source, uid, decision)) return;
      if (rejectIfPeerLimit(om, source, uid)) return;
      if (rejectIfSeedTrackerLimit(om, source, uid)) return;
      htl = normalizeHtlForSeedClient(source, htl);
      request = new OpennetAnnounceRequest(uid, xferUID, noderefLength, paddedLength, target, htl);
      AnnouncementCallback cb = buildAnnounceCallback(source, htl);
      AnnounceSender sender = new AnnounceSender(request, source, om, node, cb);
      node.network().executor().execute(sender, "Announcement sender for " + uid);
      success = true;
      if (LOG.isDebugEnabled()) LOG.debug("Accepted announcement from {}", source);
    } finally {
      if (!success) source.completedAnnounce(uid);
    }
  }

  /**
   * Validates the basic announcement request invariants before admission checks.
   *
   * <p>Requests are rejected when the target location is outside {@code [0.0, 1.0)}, HTL is not
   * positive, or the noderef sizes are inconsistent with configured bounds. Rejections are replied
   * to immediately using the overload rejection message.
   *
   * @param source peer that sent the request and receives the rejection; must be non-null
   * @param request announce request metadata to validate
   * @return {@code true} if the announcement is rejected for invalid parameters; {@code false} if
   *     valid
   */
  private boolean rejectIfInvalidAnnounce(PeerNode source, OpennetAnnounceRequest request) {
    if (request.target() >= 0.0
        && request.target() < 1.0
        && request.htl() > 0
        && request.paddedLength() >= 0
        && request.paddedLength() <= OpennetManager.MAX_OPENNET_NODEREF_LENGTH
        && request.noderefLength() <= request.paddedLength()) {
      return false;
    }
    Message msg = DMT.createFNPRejectedOverload(request.uid(), true);
    try {
      source.transport().sendAsync(msg, null, node.network().stats().announceByteCounter);
    } catch (NotConnectedException _) {
      // OK
    }
    if (LOG.isDebugEnabled()) LOG.debug("Got bogus announcement message from {}", source);
    return true;
  }

  /**
   * Rejects the announcement when opennet or announcements are disabled.
   *
   * <p>If opennet is unavailable or the peer cannot accept announcements, the method optionally
   * updates the seed tracker and sends an opennet-disabled response to the peer.
   *
   * @param om opennet manager, or {@code null} if opennet is disabled
   * @param source peer that sent the announcement and will receive the rejection; must be non-null
   * @param uid unique announce identifier used in the rejection message
   * @return {@code true} if the announcement is rejected due to disabled announcements; {@code
   *     false} otherwise
   */
  private boolean rejectIfAnnouncementsDisabled(OpennetManager om, PeerNode source, long uid) {
    if (om != null && source.canAcceptAnnouncements()) return false;
    if (om != null && source instanceof SeedClientPeerNode peerNode)
      om.getSeedTracker().rejectedAnnounce(peerNode);
    Message msg = DMT.createFNPOpennetDisabled(uid);
    try {
      source.transport().sendAsync(msg, null, node.network().stats().announceByteCounter);
    } catch (NotConnectedException _) {
      // OK
    }
    if (LOG.isDebugEnabled())
      LOG.debug("Reject announcement; opennet or announcements disabled (source={})", source);
    return true;
  }

  /**
   * Rejects the announcement based on the global admission decision.
   *
   * <p>Decisions other than {@link NodeStats.AnnouncementDecision#ACCEPT} cause a rejection reply
   * to be sent to the peer and, for seed clients, update the seed tracker. The method throws an
   * {@link IllegalStateException} if an unsupported decision is provided.
   *
   * @param om opennet manager used for seed tracking; may be {@code null}
   * @param source peer that sent the announcement and will receive the rejection; must be non-null
   * @param uid unique announce identifier used in replies
   * @param decision admission decision from {@link NodeStats}
   * @return {@code true} if the announcement is rejected; {@code false} if it is accepted
   * @throws IllegalStateException if an unknown decision enum value is supplied
   */
  private boolean rejectBasedOnDecision(
      OpennetManager om, PeerNode source, long uid, NodeStats.AnnouncementDecision decision) {
    if (NodeStats.AnnouncementDecision.ACCEPT == decision) return false;
    if (om != null && source instanceof SeedClientPeerNode peerNode)
      om.getSeedTracker().rejectedAnnounce(peerNode);
    Message msg;
    switch (decision) {
      case NodeStats.AnnouncementDecision.OVERLOAD -> {
        msg = DMT.createFNPRejectedOverload(uid, true);
        if (LOG.isDebugEnabled()) {
          LOG.debug("Reject announcement due to overall overload (source={})", source);
        }
      }
      case NodeStats.AnnouncementDecision.LOOP -> {
        msg = DMT.createFNPRejectedLoop(uid);
        if (LOG.isDebugEnabled()) {
          LOG.debug("Reject announcement due to loop (source={})", source);
        }
      }
      default -> throw new IllegalStateException("This shouldn't happen. Please report");
    }
    try {
      source.transport().sendAsync(msg, null, node.network().stats().announceByteCounter);
    } catch (NotConnectedException _) {
      // OK
    }
    return true;
  }

  /**
   * Enforces the per-peer announce concurrency limit.
   *
   * <p>If the peer refuses to accept the announcement due to its local limit, the method reports
   * the end of the announcement in {@link NodeStats} and sends a rejection reply.
   *
   * @param om opennet manager used for seed tracking; may be {@code null}
   * @param source peer that sent the announcement and will receive the rejection; must be non-null
   * @param uid unique announce identifier used in replies
   * @return {@code true} if the announcement is rejected due to peer limit; {@code false} otherwise
   */
  private boolean rejectIfPeerLimit(OpennetManager om, PeerNode source, long uid) {
    if (source.shouldAcceptAnnounce(uid)) return false;
    if (om != null && source instanceof SeedClientPeerNode peerNode)
      om.getSeedTracker().rejectedAnnounce(peerNode);
    node.network().stats().endAnnouncement(uid);
    Message msg = DMT.createFNPRejectedOverload(uid, true);
    try {
      source.transport().sendAsync(msg, null, node.network().stats().announceByteCounter);
    } catch (NotConnectedException _) {
      // OK
    }
    if (LOG.isDebugEnabled())
      LOG.debug("Reject announcement due to peer limit (source={})", source);
    return true;
  }

  /**
   * Applies seed-tracker throttling rules for seed clients.
   *
   * <p>This check only applies to {@link SeedClientPeerNode}. If the seed tracker refuses the
   * announcement, the method records completion in {@link NodeStats} and sends an overload
   * rejection response.
   *
   * @param om opennet manager providing the seed tracker; may be {@code null}
   * @param source peer that sent the announcement; must be non-null
   * @param uid unique announce identifier used in replies
   * @return {@code true} if the announcement is rejected due to seed tracker limits; {@code false}
   *     otherwise
   */
  private boolean rejectIfSeedTrackerLimit(OpennetManager om, PeerNode source, long uid) {
    if (!(om != null && source instanceof SeedClientPeerNode peerNode)) return false;
    if (om.getSeedTracker().acceptAnnounce(peerNode, node.bootstrap().fastWeakRandom()))
      return false;
    node.network().stats().endAnnouncement(uid);
    Message msg = DMT.createFNPRejectedOverload(uid, true);
    try {
      source.transport().sendAsync(msg, null, node.network().stats().announceByteCounter);
    } catch (NotConnectedException _) {
      // OK
    }
    if (LOG.isDebugEnabled())
      LOG.debug("Reject announcement due to seednode limit (source={})", source);
    return true;
  }

  /**
   * Normalizes HTL values for seed-client announces to preserve protocol expectations.
   *
   * <p>Seed clients are expected to announce at the node maximum HTL. If they present a lower
   * value, this method logs the discrepancy and returns the node maximum instead.
   *
   * @param source peer that sent the announcement; used to detect a seed-client type
   * @param htl requested hop-to-live value
   * @return normalized HTL, potentially raised to {@link Node#maxHTL()}
   */
  private short normalizeHtlForSeedClient(PeerNode source, short htl) {
    if (source instanceof SeedClientPeerNode) {
      short maxHTL = node.maxHTL();
      if (htl < maxHTL - 1) {
        LOG.error("Seed client announcement not at max HTL: {} (source={})", htl, source);
        return maxHTL;
      }
    }
    return htl;
  }

  /**
   * Builds a verbose announcement callback when debug logging is enabled.
   *
   * <p>The callback captures per-announce counters and emits detailed logs about added nodes,
   * failures, and completion outcomes. When debug logging is disabled, this method returns {@code
   * null} to avoid unnecessary allocations.
   *
   * @param source peer that originated the announcement; used for log context
   * @param htl effective hop-to-live value used in the announcement
   * @return a callback for detailed logging, or {@code null} when logging is disabled
   */
  private AnnouncementCallback buildAnnounceCallback(PeerNode source, short htl) {
    if (!LOG.isDebugEnabled()) return null;
    final String origin = source + " (htl " + htl + ")";
    return new AnnouncementCallback() {
      private int totalAdded;
      private int totalNotWanted;
      private boolean acceptedSomewhere;

      @Override
      public synchronized void acceptedSomewhere() {
        acceptedSomewhere = true;
      }

      @Override
      public void addedNode(PeerNode pn) {
        synchronized (this) {
          totalAdded++;
        }
        LOG.debug(
            "Announcement {} adds node {}{}",
            origin,
            pn,
            (pn instanceof SeedClientPeerNode ? " (seed server added the peer directly)" : ""));
      }

      @Override
      public void bogusNoderef(String reason) {
        LOG.debug(
            "Announcement {} has invalid noderef: {}", origin, reason, new Exception("debug"));
      }

      @Override
      public void completed() {
        synchronized (this) {
          LOG.debug("Announcement {} completes", origin);
        }
        int shallow = node.maxHTL() - (totalAdded + totalNotWanted);
        if (acceptedSomewhere)
          LOG.debug(
              "Announcement {} completes (added={}, notWanted={}, shallow={})",
              origin,
              totalAdded,
              totalNotWanted,
              shallow);
        else LOG.debug("Announcement {} not accepted anywhere.", origin);
      }

      @Override
      public void nodeFailed(PeerNode pn, String reason) {
        LOG.debug("Announcement {} fails: {}", origin, reason);
      }

      @Override
      public void noMoreNodes() {
        LOG.debug("Announcement {} runs out of nodes (route not found)", origin);
      }

      @Override
      public void nodeNotWanted() {
        synchronized (this) {
          totalNotWanted++;
        }
        LOG.debug("Announcement {}: node not wanted; total={}", origin, totalNotWanted);
      }

      @Override
      public void nodeNotAdded() {
        LOG.debug("Announcement {}: node not added (already present or routing disabled)", origin);
      }

      @Override
      public void relayedNoderef() {
        synchronized (this) {
          totalAdded++;
          LOG.debug(
              "Announcement from {} accepted by a downstream node, relaying noderef for a total of"
                  + " {} from this announcement)",
              origin,
              totalAdded);
        }
      }
    };
  }
}

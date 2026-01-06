package network.crypta.node;

import network.crypta.io.comm.DMT;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.MessageType;
import network.crypta.io.comm.NotConnectedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Handles opennet announcement requests. */
final class NodeAnnouncementHandler {

  private static final Logger LOG = LoggerFactory.getLogger(NodeAnnouncementHandler.class);

  private final Node node;

  NodeAnnouncementHandler(Node node) {
    this.node = node;
  }

  boolean handle(Message m, PeerNode source) {
    MessageType spec = m.getSpec();
    if (spec == DMT.FNPOpennetAnnounceRequest) {
      handleAnnounceRequest(m, source);
      return true;
    }
    return false;
  }

  private void handleAnnounceRequest(Message m, PeerNode source) {
    long uid = m.getLong(DMT.UID);
    double target = m.getDouble(DMT.TARGET_LOCATION);
    short htl = (short) Math.min(m.getShort(DMT.HTL), node.maxHTL());
    long xferUID = m.getLong(DMT.TRANSFER_UID);
    int noderefLength = m.getInt(DMT.NODEREF_LENGTH);
    int paddedLength = m.getInt(DMT.PADDED_LENGTH);

    if (rejectIfInvalidAnnounce(source, uid, target, htl, noderefLength, paddedLength)) return;

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
      AnnouncementCallback cb = buildAnnounceCallback(source, htl);
      AnnounceSender sender =
          new AnnounceSender(
              target, htl, uid, source, om, node, xferUID, noderefLength, paddedLength, cb);
      node.network().executor().execute(sender, "Announcement sender for " + uid);
      success = true;
      if (LOG.isDebugEnabled()) LOG.debug("Accepted announcement from {}", source);
    } finally {
      if (!success) source.completedAnnounce(uid);
    }
  }

  private boolean rejectIfInvalidAnnounce(
      PeerNode source, long uid, double target, short htl, int noderefLength, int paddedLength) {
    if (target >= 0.0
        && target < 1.0
        && htl > 0
        && paddedLength >= 0
        && paddedLength <= OpennetManager.MAX_OPENNET_NODEREF_LENGTH
        && noderefLength <= paddedLength) {
      return false;
    }
    Message msg = DMT.createFNPRejectedOverload(uid, true);
    try {
      source.transport().sendAsync(msg, null, node.network().stats().announceByteCounter);
    } catch (NotConnectedException _) {
      // OK
    }
    if (LOG.isDebugEnabled()) LOG.debug("Got bogus announcement message from {}", source);
    return true;
  }

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
        else LOG.debug("Announcement {} not accepted anywhere.");
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
        LOG.debug("Announcement {}: node not added (already present or routing disabled)");
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

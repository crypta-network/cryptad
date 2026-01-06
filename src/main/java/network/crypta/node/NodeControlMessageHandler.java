package network.crypta.node;

import java.util.Arrays;
import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.MessageType;
import network.crypta.io.comm.NotConnectedException;
import network.crypta.io.comm.Peer;
import network.crypta.support.Fields;
import network.crypta.support.ShortBuffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Handles control and pre-routability messages for the node dispatcher. */
final class NodeControlMessageHandler {

  private static final Logger LOG = LoggerFactory.getLogger(NodeControlMessageHandler.class);

  private final Node node;
  private final ByteCounter pingCounter;

  NodeControlMessageHandler(Node node, ByteCounter pingCounter) {
    this.node = node;
    this.pingCounter = pingCounter;
  }

  boolean handle(Message m, PeerNode source) {
    MessageType spec = m.getSpec();
    if (spec == DMT.FNPPing) {
      Message reply = DMT.createFNPPong(m.getInt(DMT.PING_SEQNO));
      try {
        source.transport().sendAsync(reply, null, pingCounter);
      } catch (NotConnectedException _) {
        if (LOG.isDebugEnabled()) LOG.debug("Lost connection while replying to {}", m);
      }
      return true;
    }
    if (spec == DMT.FNPDetectedIPAddress) {
      Peer p = (Peer) m.getObject(DMT.EXTERNAL_ADDRESS);
      source.setRemoteDetectedPeer(p);
      node.network().ipDetector().redetectAddress();
      return true;
    }
    if (spec == DMT.FNPTime) return handleTime(m, source);
    if (spec == DMT.FNPUptime) return handleUptime(m, source);
    if (spec == DMT.FNPVisibility && source instanceof DarknetPeerNode peerNode) {
      peerNode.handleVisibility(m);
      return true;
    }
    if (spec == DMT.FNPVoid) return true;
    if (spec == DMT.FNPDisconnect) {
      handleDisconnect(m, source);
      return true;
    }
    if (spec == DMT.nodeToNodeMessage) {
      node.messaging().receivedNodeToNodeMessage(m, source);
      return true;
    }
    if (handleUomMessages(m, source, spec)) return true;
    if (spec == DMT.FNPRoutingStatus) {
      if (source instanceof DarknetPeerNode peerNode) {
        boolean value = m.getBoolean(DMT.ROUTING_ENABLED);
        if (LOG.isDebugEnabled()) LOG.debug("Peer {} requests routing={}", source, value);
        peerNode.setRoutingStatus(value, false);
      }
      return true;
    }
    if (handleLocationChangeIfRealConnection(m, source, spec)) return true;
    return handlePeerLoadStatuses(m, source, spec);
  }

  private boolean handleUomMessages(Message m, PeerNode source, MessageType spec) {
    if (spec == DMT.CryptadUOMAnnouncement && source.isRealConnection()) {
      return node.services().nodeUpdater().getUpdateOverMandatory().handleAnnounce(m, source);
    }
    if (spec == DMT.CryptadUOMRequestRevocation && source.isRealConnection()) {
      return node.services()
          .nodeUpdater()
          .getUpdateOverMandatory()
          .handleRequestRevocation(m, source);
    }
    if (spec == DMT.CryptadUOMSendingRevocation && source.isRealConnection()) {
      return node.services()
          .nodeUpdater()
          .getUpdateOverMandatory()
          .handleSendingRevocation(m, source);
    }
    if (spec == DMT.CryptadUOMRequestMainJar
        && node.services().nodeUpdater().supportsJarUOM()
        && source.isRealConnection()) {
      node.services().nodeUpdater().getUpdateOverMandatory().handleRequestJar(m, source);
      return true;
    }
    if (spec == DMT.CryptadUOMSendingMainJar
        && node.services().nodeUpdater().supportsJarUOM()
        && source.isRealConnection()) {
      return node.services().nodeUpdater().getUpdateOverMandatory().handleSendingMain(m, source);
    }
    if (spec == DMT.CryptadUOMFetchDependency
        && node.services().nodeUpdater().supportsJarUOM()
        && source.isRealConnection()) {
      node.services().nodeUpdater().getUpdateOverMandatory().handleFetchDependency(m, source);
      return true;
    }
    return false;
  }

  private boolean handleLocationChangeIfRealConnection(
      Message m, PeerNode source, MessageType spec) {
    if (!(source.isRealConnection() && spec == DMT.FNPLocChangeNotificationNew)) return false;

    double newLoc = m.getDouble(DMT.LOCATION);
    ShortBuffer buffer = ((ShortBuffer) m.getObject(DMT.PEER_LOCATIONS));
    double[] locs = Fields.bytesToDoubles(buffer.getData());

    // See: http://archives.freenetproject.org/message/20080718.144240.359e16d3.en.html
    if ((OpennetManager.MAX_PEERS_FOR_SCALING < locs.length) && (source.isOpennet())) {
      if (locs.length > OpennetManager.PANIC_MAX_PEERS) {
        LOG.error(
            "Received {} locations from {}; unexpected count; possible attack",
            locs.length,
            source);
        source.forceDisconnect();
        return true;
      } else {
        LOG.info(
            "Received locations from {}: count={}; using first {}",
            source,
            locs.length,
            OpennetManager.MAX_PEERS_FOR_SCALING);
        locs = Arrays.copyOf(locs, OpennetManager.MAX_PEERS_FOR_SCALING);
      }
    }
    source.updateLocation(newLoc, locs);
    return true;
  }

  private boolean handlePeerLoadStatuses(Message m, PeerNode source, MessageType spec) {
    if (spec == DMT.FNPPeerLoadStatusByte
        || spec == DMT.FNPPeerLoadStatusShort
        || spec == DMT.FNPPeerLoadStatusInt) {
      return handlePeerLoadStatus(m, source);
    }
    return false;
  }

  private boolean handlePeerLoadStatus(Message m, PeerNode source) {
    PeerLoadStats stat = new PeerLoadStats(source, m);
    source.reportLoadStatus(stat);
    return true;
  }

  private boolean handleUptime(Message m, PeerNode source) {
    byte uptime = m.getByte(DMT.UPTIME_PERCENT_48H);
    source.setUptime(uptime);
    return true;
  }

  private boolean handleTime(Message m, PeerNode source) {
    long delta = m.getLong(DMT.TIME) - System.currentTimeMillis();
    source.setTimeDelta(delta);
    return true;
  }

  private void handleDisconnect(final Message m, final PeerNode source) {
    // Wait for 1 second to ensure that the ack gets sent first.
    node.network().ticker().queueTimedJob(() -> finishDisconnect(m, source), 1000);
  }

  private void finishDisconnect(final Message m, final PeerNode source) {
    source.disconnected(true, true);
    // If true, remove from active routing table, likely to be down for a while.
    // Otherwise, just dump all current connection state and keep trying to connect.
    boolean remove = m.getBoolean(DMT.REMOVE);
    if (remove) {
      node.network().peers().messenger().disconnectAndRemove(source, false, false, false);
      if (source instanceof DarknetPeerNode peerNode)
        LOG.info(
            "Disconnecting permanently from your friend \"{}\" because they asked us to remove"
                + " them.",
            peerNode.getName());
    }
    // If true, purge all references to this node. Otherwise, we can keep the node
    // around in secondary tables etc. in order to more easily reconnect later.
    // (Mostly used on opennet)
    boolean purge = m.getBoolean(DMT.PURGE);
    if (purge) {
      OpennetManager om = node.network().opennet();
      if (om != null && source instanceof OpennetPeerNode peerNode)
        om.purgeOldOpennetPeer(peerNode);
    }
    // Process parting message
    int type = m.getInt(DMT.NODE_TO_NODE_MESSAGE_TYPE);
    ShortBuffer messageData = (ShortBuffer) m.getObject(DMT.NODE_TO_NODE_MESSAGE_DATA);
    if (messageData.getLength() == 0) return;
    node.messaging().receivedNodeToNodeMessage(source, type, messageData, true);
  }
}

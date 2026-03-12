package network.crypta.node;

import java.util.Arrays;
import java.util.Objects;
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

/**
 * Handles control-plane and pre-routability messages for the node dispatcher.
 *
 * <p>This handler is a small, message-type-driven router used by the dispatcher to process
 * low-level control traffic such as pings, uptime, time synchronization hints, peer load snapshots,
 * and disconnect requests. Callers typically create one instance per {@link Node} and invoke {@link
 * #handle(Message, PeerNode)} for each incoming control message on the dispatcher thread. The
 * handler delegates to subsystems (network, messaging, updater) to perform the actual side effects
 * and returns a boolean indicating whether the message was consumed.
 *
 * <p>State is limited to the owning node reference and a byte counter used when sending pong
 * replies. The class is intentionally package-private and does not synchronize; it relies on the
 * surrounding dispatcher and subsystem contracts to ensure thread safety. It does not mutate the
 * message contents and does not retain references to buffers beyond the call.
 *
 * <ul>
 *   <li>Routes specific message types to specialized helper methods.
 *   <li>Triggers immediate replies (e.g., ping) or deferred actions (e.g., disconnect).
 *   <li>Delegates to updater, messaging, and peer management subsystems for side effects.
 * </ul>
 *
 * @see NodeDispatcher
 * @see network.crypta.node.subsystem.NodeMessagingSubsystem
 */
final class NodeControlMessageHandler {

  /**
   * Logger for control-plane handling decisions and unusual peer inputs.
   *
   * <p>Used for debug-level diagnostics and error reporting. Log messages are emitted only when a
   * control path needs visibility and are designed to avoid exposing sensitive content.
   */
  private static final Logger LOG = LoggerFactory.getLogger(NodeControlMessageHandler.class);

  /**
   * The owning node used to access network, messaging, and updater subsystems.
   *
   * <p>This reference is stable for the lifetime of the handler and is not expected to be {@code
   * null}. It provides the necessary entry points for side effects triggered by control messages.
   */
  private final Node node;

  /**
   * Counter used when sending pong responses to incoming ping requests.
   *
   * <p>The counter tracks payload/byte accounting for replies and is passed to the transport layer.
   * It is treated as read-only by this handler.
   */
  private final ByteCounter pingCounter;

  /**
   * Creates a new control message handler bound to the provided node.
   *
   * <p>The handler stores references to the node and counter for later use and performs no I/O
   * during construction. Callers are expected to reuse a single instance for the node dispatcher
   * rather than allocating per-message handlers.
   *
   * @param node owning node used to reach network and messaging subsystems; must be non-null
   * @param pingCounter byte counter used for pong replies; must be non-null and thread-safe
   */
  NodeControlMessageHandler(Node node, ByteCounter pingCounter) {
    this.node = node;
    this.pingCounter = pingCounter;
  }

  /**
   * Attempts to handle an incoming control message from a peer.
   *
   * <p>The method inspects the message specification and routes to the appropriate helper. It may
   * synchronously reply (e.g., ping/pong), trigger a subsystem callback, or enqueue a delayed
   * disconnect. The message object is treated as read-only; ownership of any buffers remains with
   * the caller. The method is intentionally conservative: unknown message types are ignored and
   * reported as unhandled via the return value.
   *
   * @param m decoded control message to inspect; must not be null and must contain required fields
   * @param source peer that supplied the message; must not be null and must be connected
   * @return {@code true} if a known control path handled the message, {@code false} otherwise
   */
  boolean handle(Message m, PeerNode source) {
    MessageType spec = m.getSpec();
    if (handlePing(m, source, spec)) return true;
    if (handleDetectedAddress(m, source, spec)) return true;
    if (Objects.equals(spec, DMT.FNPTime)) return handleTime(m, source);
    if (Objects.equals(spec, DMT.FNPUptime)) return handleUptime(m, source);
    if (handleVisibility(m, source, spec)) return true;
    if (Objects.equals(spec, DMT.FNPVoid)) return true;
    if (handleDisconnectMessage(m, source, spec)) return true;
    if (handleNodeToNodeMessage(m, source, spec)) return true;
    if (handleUomMessages(m, source, spec)) return true;
    if (handleRoutingStatus(m, source, spec)) return true;
    if (handleLocationChangeIfRealConnection(m, source, spec)) return true;
    return handlePeerLoadStatuses(m, source, spec);
  }

  /**
   * Handles ping messages by replying with a corresponding pong.
   *
   * @param m message providing the ping sequence number; must not be null
   * @param source peer to which the reply is sent; must not be null
   * @param spec resolved message type for this message; must not be null
   * @return {@code true} when a ping was handled and a reply attempted
   */
  private boolean handlePing(Message m, PeerNode source, MessageType spec) {
    if (!Objects.equals(spec, DMT.FNPPing)) return false;
    Message reply = DMT.createFNPPong(m.getInt(DMT.PING_SEQNO));
    try {
      source.transport().sendAsync(reply, null, pingCounter);
    } catch (NotConnectedException _) {
      if (LOG.isDebugEnabled()) LOG.debug("Lost connection while replying to {}", m);
    }
    return true;
  }

  /**
   * Handles detected-address notifications by updating peer state and rechecking detection.
   *
   * @param m message containing the detected external address; must not be null
   * @param source peer whose address was detected; must not be null
   * @param spec resolved message type for this message; must not be null
   * @return {@code true} when the message was a detected-address notification
   */
  private boolean handleDetectedAddress(Message m, PeerNode source, MessageType spec) {
    if (!Objects.equals(spec, DMT.FNPDetectedIPAddress)) return false;
    Peer p = (Peer) m.getObject(DMT.EXTERNAL_ADDRESS);
    source.setRemoteDetectedPeer(p);
    node.network().ipDetector().redetectAddress();
    return true;
  }

  /**
   * Handles darknet visibility messages if the source supports them.
   *
   * @param m message carrying visibility payload; must not be null
   * @param source peer that sent the message; must not be null
   * @param spec resolved message type for this message; must not be null
   * @return {@code true} if a visibility message was consumed; otherwise {@code false}
   */
  private boolean handleVisibility(Message m, PeerNode source, MessageType spec) {
    if (Objects.equals(spec, DMT.FNPVisibility) && source instanceof DarknetPeerNode peerNode) {
      peerNode.handleVisibility(m);
      return true;
    }
    return false;
  }

  /**
   * Handles disconnect messages by scheduling the final disconnect workflow.
   *
   * @param m message carrying disconnect flags and parting data; must not be null
   * @param source peer requesting the disconnect; must not be null
   * @param spec resolved message type for this message; must not be null
   * @return {@code true} if the message is a disconnect request, otherwise {@code false}
   */
  private boolean handleDisconnectMessage(Message m, PeerNode source, MessageType spec) {
    if (!Objects.equals(spec, DMT.FNPDisconnect)) return false;
    handleDisconnect(m, source);
    return true;
  }

  /**
   * Handles node-to-node messages by delegating to the messaging subsystem.
   *
   * @param m wrapper message that contains node-to-node payload fields; must not be null
   * @param source peer that sent the message; must not be null
   * @param spec resolved message type for this message; must not be null
   * @return {@code true} if the message was dispatched, otherwise {@code false}
   */
  private boolean handleNodeToNodeMessage(Message m, PeerNode source, MessageType spec) {
    if (!Objects.equals(spec, DMT.nodeToNodeMessage)) return false;
    node.messaging().receivedNodeToNodeMessage(m, source);
    return true;
  }

  /**
   * Handles routing status updates requested by a darknet peer.
   *
   * @param m message containing the requested routing flag; must not be null
   * @param source peer requesting routing status changes; must not be null
   * @param spec resolved message type for this message; must not be null
   * @return {@code true} if the message was a routing-status request, otherwise {@code false}
   */
  private boolean handleRoutingStatus(Message m, PeerNode source, MessageType spec) {
    if (!Objects.equals(spec, DMT.FNPRoutingStatus)) return false;
    if (source instanceof DarknetPeerNode peerNode) {
      boolean value = m.getBoolean(DMT.ROUTING_ENABLED);
      if (LOG.isDebugEnabled()) LOG.debug("Peer {} requests routing={}", source, value);
      peerNode.setRoutingStatus(value, false);
    }
    return true;
  }

  /**
   * Handles update-over-mandatory (UOM) control messages for real connections.
   *
   * @param m message containing UOM request data; must not be null
   * @param source peer that sent the UOM message; must not be null
   * @param spec resolved message type for this message; must not be null
   * @return {@code true} if a UOM path handled the message, otherwise {@code false}
   */
  private boolean handleUomMessages(Message m, PeerNode source, MessageType spec) {
    if (Objects.equals(spec, DMT.CryptadUOMAnnouncement) && source.isRealConnection()) {
      return node.services().nodeUpdater().getUpdateOverMandatory().handleAnnounce(m, source);
    }
    if (Objects.equals(spec, DMT.CryptadUOMRequestRevocation) && source.isRealConnection()) {
      return node.services()
          .nodeUpdater()
          .getUpdateOverMandatory()
          .handleRequestRevocation(m, source);
    }
    if (Objects.equals(spec, DMT.CryptadUOMSendingRevocation) && source.isRealConnection()) {
      return node.services()
          .nodeUpdater()
          .getUpdateOverMandatory()
          .handleSendingRevocation(m, source);
    }
    return false;
  }

  /**
   * Handles location change notifications for real connections, with opennet guards.
   *
   * @param m message containing location and peer list fields; must not be null
   * @param source peer that sent the location update; must not be null
   * @param spec resolved message type for this message; must not be null
   * @return {@code true} if the location change was processed, otherwise {@code false}
   */
  private boolean handleLocationChangeIfRealConnection(
      Message m, PeerNode source, MessageType spec) {
    if (!(source.isRealConnection() && Objects.equals(spec, DMT.FNPLocChangeNotificationNew))) {
      return false;
    }

    double newLoc = m.getDouble(DMT.LOCATION);
    ShortBuffer buffer = ((ShortBuffer) m.getObject(DMT.PEER_LOCATIONS));
    double[] locs = Fields.bytesToDoubles(buffer.getData());

    // See: http://archives.freenetproject.org/message/20080718.144240.359e16d3.en.html
    if (OpennetManager.MAX_PEERS_FOR_SCALING < locs.length && source.isOpennet()) {
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

  /**
   * Determines whether a peer load status message should be processed.
   *
   * @param m message that may describe a peer load status; must not be null
   * @param source peer that reported the load status; must not be null
   * @param spec resolved message type for this message; must not be null
   * @return {@code true} if a supported load status was processed, otherwise {@code false}
   */
  private boolean handlePeerLoadStatuses(Message m, PeerNode source, MessageType spec) {
    if (Objects.equals(spec, DMT.FNPPeerLoadStatusByte)
        || Objects.equals(spec, DMT.FNPPeerLoadStatusShort)
        || Objects.equals(spec, DMT.FNPPeerLoadStatusInt)) {
      return handlePeerLoadStatus(m, source);
    }
    return false;
  }

  /**
   * Builds and reports a peer load status snapshot to the peer.
   *
   * @param m message containing the peer load status fields; must not be null
   * @param source peer that sent the load status update; must not be null
   * @return {@code true} because the load status is always consumed
   */
  private boolean handlePeerLoadStatus(Message m, PeerNode source) {
    PeerLoadStats stat = new PeerLoadStats(source, m);
    source.reportLoadStatus(stat);
    return true;
  }

  /**
   * Updates the peer's reported uptime percentage.
   *
   * @param m message carrying the uptime field; must not be null
   * @param source peer whose uptime should be updated; must not be null
   * @return {@code true} because the uptime message is always consumed
   */
  private boolean handleUptime(Message m, PeerNode source) {
    byte uptime = m.getByte(DMT.UPTIME_PERCENT_48H);
    source.setUptime(uptime);
    return true;
  }

  /**
   * Updates the peer's time delta based on the supplied timestamp.
   *
   * @param m message containing the peer's current time in milliseconds; must not be null
   * @param source peer whose time delta should be updated; must not be null
   * @return {@code true} because the time message is always consumed
   */
  private boolean handleTime(Message m, PeerNode source) {
    long delta = m.getLong(DMT.TIME) - System.currentTimeMillis();
    source.setTimeDelta(delta);
    return true;
  }

  /**
   * Schedules a delayed disconnect so any queued acknowledgements can be flushed.
   *
   * @param m disconnect request containing flags and parting data; must not be null
   * @param source peer that should be disconnected; must not be null
   */
  private void handleDisconnect(final Message m, final PeerNode source) {
    // Wait for 1 second to ensure that the ack gets sent first.
    node.network().ticker().queueTimedJob(() -> finishDisconnect(m, source), 1000);
  }

  /**
   * Performs the actual disconnect workflow and processes parting metadata.
   *
   * @param m the original disconnect message containing flags and node-to-node data; must not be
   *     null
   * @param source peer being disconnected; must not be null
   */
  private void finishDisconnect(final Message m, final PeerNode source) {
    source.disconnected(true, true);
    // If true, remove from the active routing table, likely to be down for a while.
    // Otherwise, just dump all current connection states and keep trying to connect.
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
    // around in secondary tables etc. to more easily reconnect later.
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

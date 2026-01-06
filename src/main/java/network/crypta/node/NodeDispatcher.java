package network.crypta.node;

import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.Dispatcher;
import network.crypta.io.comm.Message;
import network.crypta.node.probe.Listener;
import network.crypta.node.probe.Type;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Dispatches unmatched FNP messages and coordinates routed message flow.
 *
 * <p>This dispatcher is the entry point for messages not claimed by other subsystems. It handles
 * control messages (ping/pong, time/uptime, visibility), location and load updates, swap flows,
 * data/insert requests, announcement flows, and the small routed-to-node family (routed ping/pong
 * and rejections).
 *
 * <p>Threading: instances are shared across multiple I/O and worker threads. Incoming data requests
 * may be processed off-thread via the data request handler. Ephemeral routed message state is
 * tracked and pruned periodically by the routed message router.
 */
public class NodeDispatcher implements Dispatcher {

  private static final Logger LOG = LoggerFactory.getLogger(NodeDispatcher.class);

  final Node node;
  final ByteCounter pingCounter =
      new ByteCounter() {

        @Override
        public void receivedBytes(int x) {
          node.network().stats().pingCounterReceived(x);
        }

        @Override
        public void sentBytes(int x) {
          node.network().stats().pingCounterSent(x);
        }

        @Override
        public void sentPayload(int x) {
          // Ignore
        }
      };
  private final NodeControlMessageHandler controlHandler;
  private final NodeAnnouncementHandler announcementHandler;
  private final NodeNotRoutableHandler notRoutableHandler;
  private final NodeSwapMessageHandler swapHandler;
  private final NodeDataRequestHandler dataRequestHandler;
  private final NodeInsertRequestHandler insertRequestHandler;
  private final NodeRoutedMessageRouter routedMessageRouter;
  private final NodeOfferMessageHandler offerMessageHandler;
  private final NodeProbeHandler probeHandler;
  private NodeDispatcherCallback callback;

  public NodeDispatcher(Node node) {
    this.node = node;
    this.controlHandler = new NodeControlMessageHandler(node, pingCounter);
    this.announcementHandler = new NodeAnnouncementHandler(node);
    this.notRoutableHandler = new NodeNotRoutableHandler(node);
    this.swapHandler = new NodeSwapMessageHandler(node);
    this.dataRequestHandler = new NodeDataRequestHandler(node);
    this.insertRequestHandler = new NodeInsertRequestHandler(node);
    this.routedMessageRouter = new NodeRoutedMessageRouter(node);
    this.offerMessageHandler = new NodeOfferMessageHandler(node);
    this.probeHandler = new NodeProbeHandler(node);
  }

  /**
   * Starts a probe request using the internal probe handler.
   *
   * @param htl the initial HTL for the probe
   * @param uid unique identifier for the probe
   * @param type probe type
   * @param listener callback for probe progress
   */
  public void startProbe(byte htl, long uid, Type type, Listener listener) {
    probeHandler.startProbe(htl, uid, type, listener);
  }

  public static String peersUIDsToString(long[] peerUIDs, double[] peerLocs) {
    StringBuilder sb = new StringBuilder(peerUIDs.length * 23 + peerLocs.length * 26);
    int min = Math.min(peerUIDs.length, peerLocs.length);
    for (int i = 0; i < min; i++) {
      double loc = peerLocs[i];
      long uid = peerUIDs[i];
      sb.append(loc);
      sb.append('=');
      sb.append(uid);
      if (i != min - 1) sb.append('|');
    }
    if (peerUIDs.length > min) {
      for (int i = min; i < peerUIDs.length; i++) {
        sb.append("|U:");
        sb.append(peerUIDs[i]);
      }
    } else if (peerLocs.length > min) {
      for (int i = min; i < peerLocs.length; i++) {
        sb.append("|L:");
        sb.append(peerLocs[i]);
      }
    }
    return sb.toString();
  }

  @Override
  public boolean handleMessage(Message m) {
    PeerNode source = (PeerNode) m.getSource();
    if (source == null) {
      // Node has been disconnected and garbage collected already! Ouch.
      return true;
    }
    if (LOG.isDebugEnabled()) LOG.debug("Dispatch {} from {}", m, source);
    if (callback != null) {
      try {
        callback.snoop(m, node);
      } catch (Exception e) {
        LOG.error("Callback threw exception", e);
      }
    }

    // Fast-path handlers that don't depend on routability
    if (controlHandler.handle(m, source)) return true;
    if (announcementHandler.handle(m, source)) return true;

    // Reject early when the source is not routable
    if (!source.isRoutable()) return notRoutableHandler.handle(m);

    // Remaining message families
    if (swapHandler.handle(m, source)) return true;
    if (dataRequestHandler.handle(m)) return true;
    if (insertRequestHandler.handle(m, source)) return true;
    if (routedMessageRouter.handle(m, source)) return true;
    if (offerMessageHandler.handle(m, source)) return true;
    return probeHandler.handle(m, source);
  }

  /**
   * Handles a routed message received by the dispatcher.
   *
   * @param m message to route
   * @param source optional source peer, or {@code null} for local originators
   */
  public void handleRouted(Message m, PeerNode source) {
    routedMessageRouter.handleRouted(m, source);
  }

  boolean handleRoutedReply(Message m) {
    return routedMessageRouter.handleRoutedReply(m);
  }

  /**
   * Starts the dispatcher after core components are initialized.
   *
   * @param stats node statistics collector used for routing and diagnostics
   */
  public void start(NodeStats stats) {
    dataRequestHandler.start(stats);
    insertRequestHandler.start(stats);
    routedMessageRouter.start(stats);
    offerMessageHandler.start(stats);
  }

  /**
   * Sets an optional callback to inspect messages as they pass through the dispatcher.
   *
   * <p>Intended for tests and instrumentation. The callback runs on the caller's thread and should
   * return quickly.
   *
   * @param cb callback invoked for each handled message; may be {@code null} to clear
   */
  public void setHook(NodeDispatcherCallback cb) {
    this.callback = cb;
  }

  /** Callback interface for observing dispatcher traffic. */
  public interface NodeDispatcherCallback {
    /**
     * Invoked for each message handled by the dispatcher.
     *
     * @param m the message being processed (never {@code null})
     * @param n the node owning this dispatcher (never {@code null})
     */
    void snoop(Message m, Node n);
  }
}

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
 * <p>This dispatcher is the entry point for inbound messages that are not claimed by other
 * subsystems. It delegates to specialized handlers for control messages (ping/pong, time/uptime,
 * visibility), announcement flows, swaps, offers, data/insert requests, and the small
 * routed-to-node family (routed ping/pong and rejections). Messages are evaluated in a fixed order
 * so that fast-path and control traffic are handled quickly before more expensive request routing
 * occurs.
 *
 * <p>Threading: instances are shared across multiple I/O and worker threads. The dispatcher itself
 * is a thin coordinator and is safe to call concurrently as long as its collaborators are. Some
 * handlers process work asynchronously (for example, data requests may be handed off to worker
 * threads), while routed message state is tracked and periodically pruned by the routed message
 * router. The dispatcher does not own mutable shared state beyond a volatile callback reference.
 *
 * <p>Responsibilities include:
 *
 * <ul>
 *   <li>Prioritizing control and announcement traffic over routable requests.
 *   <li>Rejecting non-routable sources early with the appropriate overload response.
 *   <li>Delegating routed messages and tracking in-flight routed request state.
 * </ul>
 *
 * @see NodeControlMessageHandler
 * @see NodeRoutedMessageRouter
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

  /**
   * Creates a dispatcher bound to the provided node instance.
   *
   * <p>The constructor wires the dispatcher to the node's handlers and statistics hooks so it can
   * immediately accept traffic. The dispatcher does not start background work by itself; callers
   * should invoke {@link #start(NodeStats)} after core components are initialized. This constructor
   * expects a fully formed node and does not perform null checks.
   *
   * @param node owning node used to resolve handlers, stats, and network state
   */
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
   * <p>This method delegates to {@link NodeProbeHandler} and initiates the probe lifecycle using
   * the provided HTL, UID, and type. The probe handler is responsible for any message emission and
   * progress tracking, and the supplied listener is invoked as the probe advances or terminates.
   * Callers should treat the UID as opaque and unique within the node's probe context.
   *
   * @param htl initial hop-to-live value, typically decremented by forwarding logic
   * @param uid unique identifier used to correlate probe responses and completion
   * @param type probe type that determines the message format and routing path
   * @param listener callback for progress events; must be safe for concurrent calls
   */
  public void startProbe(byte htl, long uid, Type type, Listener listener) {
    probeHandler.startProbe(htl, uid, type, listener);
  }

  /**
   * Formats peer locations and UIDs into a compact diagnostic string.
   *
   * <p>The output pairs entries as {@code location=uid} separated by {@code |}. If the arrays are
   * mismatched in length, any remaining UIDs are appended with a {@code U:} prefix and any
   * remaining locations are appended with a {@code L:} prefix. This helper is intended for log
   * messages or debugging output and does not perform validation of ranges or uniqueness.
   *
   * @param peerUIDs array of peer UIDs; may be empty but not {@code null}
   * @param peerLocs array of peer locations; may be empty but not {@code null}
   * @return formatted string containing paired and trailing entries, never {@code null}
   */
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

  /**
   * Dispatches an incoming message to the first handler that can process it.
   *
   * <p>The dispatcher runs handlers in a defined order, prioritizing control and announcement
   * traffic. If the source is missing, the message is treated as already handled because the peer
   * is gone. When the source is not routable, the not-routable handler decides whether to reject
   * the message. For routable peers, the dispatcher tries swap, data request, insert, routed,
   * offer, and probe handlers in sequence until one reports success.
   *
   * @param m message to dispatch; must have a {@link PeerNode} source when remote
   * @return {@code true} if a handler accepted or safely ignored the message
   */
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
   * Routes a message that targets this node and participates in routed tracking.
   *
   * <p>This is a small entry point used by other components to inject routed messages into the
   * router. The router tracks in-flight routed message state and applies the normal routing rules.
   * A {@code null} source indicates that the message originates locally rather than from a peer.
   *
   * @param m message to route; must be a routed message type understood by the router
   * @param source optional source peer, or {@code null} for local originators
   */
  public void handleRouted(Message m, PeerNode source) {
    routedMessageRouter.handleRouted(m, source);
  }

  boolean handleRoutedReply(Message m) {
    return routedMessageRouter.handleRoutedReply(m);
  }

  /**
   * Starts handlers that require node statistics or background wiring.
   *
   * <p>This method wires statistics into the data, insert, routed, and offer handlers so they can
   * record counters and manage periodic cleanup. It should be called after core node components are
   * initialized and before handling live traffic. Calling this method more than once delegates to
   * the handlers without additional guards, so callers should avoid repeated invocation.
   *
   * @param stats node statistics collector used for routing counters and diagnostics
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
   * return quickly. The dispatcher does not synchronize around the callback; the most recently set
   * value is used for subsequent messages. Passing {@code null} disables the hook without affecting
   * message handling, and setting a new hook replaces any prior observer immediately.
   *
   * @param cb callback invoked for each handled message; {@code null} clears the hook
   */
  public void setHook(NodeDispatcherCallback cb) {
    this.callback = cb;
  }

  /**
   * Callback interface for observing dispatcher traffic.
   *
   * <p>This hook is primarily intended for tests or lightweight instrumentation. Implementations
   * must be fast and thread-safe because they run on the same thread that is processing the
   * incoming message.
   */
  public interface NodeDispatcherCallback {
    /**
     * Invoked for each message handled by the dispatcher.
     *
     * <p>The callback receives the message and the owning node so it can record diagnostics or
     * perform assertions. It must not mutate shared node state unless it is safe to do so under
     * concurrent access. Implementations should avoid blocking operations because the callback runs
     * inline with message dispatch and can delay other handlers if it is slow.
     *
     * @param m the message being processed; never {@code null} for handled calls
     * @param n the node owning this dispatcher; never {@code null}
     */
    void snoop(Message m, Node n);
  }
}

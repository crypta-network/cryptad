package network.crypta.node;

import java.util.Objects;
import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.MessageType;
import network.crypta.io.comm.NotConnectedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Handles early reject responses when a peer is not considered routable.
 *
 * <p>This helper inspects incoming request messages before they reach the normal routing and
 * request pipeline. For message types that expect routing, it sends a lightweight overload-style
 * rejection back to the source and increments the corresponding byte counter. The handler is
 * designed to be called from the node's message dispatch path so that non-routable peers are
 * rejected quickly and consistently.
 *
 * <p>The handler is intentionally stateless aside from a reference to the owning {@link Node}. It
 * does not maintain per-peer state, cache results, or schedule asynchronous work beyond the
 * transport send itself. Callers should treat it as a pure decision step: if it returns {@code
 * true}, a response has been queued; if it returns {@code false}, the caller should continue with
 * normal processing. No internal synchronization is performed, so callers are expected to invoke it
 * on threads that already coordinate node message handling.
 *
 * <p>Responsibilities include:
 *
 * <ul>
 *   <li>Identify request types that should be rejected for non-routable peers.
 *   <li>Send a rejection message that preserves the original request UID.
 *   <li>Record accounting in the appropriate network statistics counter.
 * </ul>
 */
final class NodeNotRoutableHandler {

  /** Logger used for trace-level diagnostics during early rejection decisions. */
  private static final Logger LOG = LoggerFactory.getLogger(NodeNotRoutableHandler.class);

  /** Owning node instance used to access routing state and network statistics. */
  private final Node node;

  /**
   * Creates a handler bound to the given node.
   *
   * <p>The node reference is used to access routing state and the network statistics counters
   * required for recording rejected requests. The handler does not take ownership of the node
   * instance and assumes the node lifecycle is managed elsewhere.
   *
   * @param node owning node used for routing state and accounting; must be non-null.
   */
  NodeNotRoutableHandler(Node node) {
    this.node = node;
  }

  /**
   * Attempts to reject a message if its source is not routable.
   *
   * <p>This method inspects the message type and, for known request types that cannot be routed
   * from the source, sends a rejection response that mirrors the request UID. The response is
   * queued through the transport layer and accounted against the appropriate byte counter. When the
   * message type is not handled by this class, the method returns {@code false} and performs no
   * side effects.
   *
   * <p>The method is idempotent with respect to its return value but not with respect to network
   * effects: calling it multiple times for the same message may send multiple rejection responses.
   * Callers should therefore invoke it at most once per message in the dispatch path.
   *
   * @param m message to inspect and potentially reject; must be non-null.
   * @return {@code true} if the message was rejected and a response was queued; {@code false} if
   *     the message type is not handled here.
   */
  boolean handle(Message m) {
    MessageType spec = m.getSpec();
    if (LOG.isTraceEnabled()) LOG.trace("Peer not routable");
    if (Objects.equals(spec, DMT.FNPCHKDataRequest)) {
      rejectRequest(m, node.network().stats().chkRequestCtr);
    } else if (Objects.equals(spec, DMT.FNPSSKDataRequest)) {
      rejectRequest(m, node.network().stats().sskRequestCtr);
    } else if (Objects.equals(spec, DMT.FNPInsertRequest)) {
      rejectRequest(m, node.network().stats().chkInsertCtr);
    } else if (Objects.equals(spec, DMT.FNPSSKInsertRequest)) {
      rejectRequest(m, node.network().stats().sskInsertCtr);
    } else if (Objects.equals(spec, DMT.FNPSSKInsertRequestNew)) {
      rejectRequest(m, node.network().stats().sskInsertCtr);
    } else if (Objects.equals(spec, DMT.FNPGetOfferedKey)) {
      rejectRequest(m, node.routing().failureTable().senderCounter);
    } else {
      return false;
    }
    return true;
  }

  /**
   * Sends a rejection response for the given message using the supplied counter.
   *
   * <p>This method extracts the request UID, builds a rejection response, and queues it on the
   * transport. If the peer disconnects before the send is queued, the exception is ignored so that
   * upstream dispatch logic can continue without additional error handling.
   *
   * @param m message whose UID is mirrored in the rejection response; must be non-null.
   * @param ctr byte counter used for accounting the reject response; must be non-null.
   */
  private void rejectRequest(Message m, ByteCounter ctr) {
    long uid = m.getLong(DMT.UID);
    Message msg = DMT.createFNPRejectedOverload(uid, true);
    try {
      m.getSource().transport().sendAsync(msg, null, ctr);
    } catch (NotConnectedException _) {
      // Ignore
    }
  }
}

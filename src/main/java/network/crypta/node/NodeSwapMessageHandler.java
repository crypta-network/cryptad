package network.crypta.node;

import network.crypta.io.comm.DMT;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.MessageType;

/**
 * Routes swap-related peer messages to the location manager.
 *
 * <p>This handler sits on the inbound message path and dispatches the swap message family to the
 * {@link network.crypta.node.LocationManager} associated with the owning {@link Node}. It
 * recognizes the specific {@link MessageType} values used for the swap protocol and forwards the
 * message plus source peer to the corresponding handler method. The class is intentionally small
 * and acts as a switchboard rather than encapsulating swap logic.
 *
 * <p>Instances are tied to a single {@link Node} and rely on that node's network subsystem to be
 * initialized. It performs no buffering and does not mutate the message; ordering and retry
 * policies remain the responsibility of the lower-level message processing and the location manager
 * implementation. This type is not thread-safe beyond the guarantees of the surrounding message
 * dispatch loop.
 *
 * <ul>
 *   <li>Recognizes swap request, reply, reject, commit, and completion messages.
 *   <li>Delegates all substantive processing to the location manager.
 *   <li>Reports whether the message was handled by this swap family.
 * </ul>
 *
 * @see network.crypta.node.LocationManager
 */
final class NodeSwapMessageHandler {

  /**
   * Owning node that provides access to the network and location manager.
   *
   * <p>This reference is immutable for the lifetime of the handler. It is expected to be a fully
   * constructed node whose network subsystem is available when {@link #handle(Message, PeerNode)}
   * is called; the handler does not perform null checks or lazy initialization.
   */
  private final Node node;

  /**
   * Creates a handler bound to the given node.
   *
   * <p>The handler stores the node reference and uses it to reach the network and location manager
   * for every message. The constructor performs no validation or side effects, so callers must
   * ensure the node is non-null and appropriately initialized for message dispatch. Creating
   * multiple handlers for the same node is allowed but typically unnecessary.
   *
   * @param node owning node whose location manager handles swap messages; must be non-null
   */
  NodeSwapMessageHandler(Node node) {
    this.node = node;
  }

  /**
   * Dispatches a swap-related message to the appropriate location manager handler.
   *
   * <p>The method inspects the {@link MessageType} of the supplied message and, when it matches a
   * swap protocol type, forwards the message and source peer to the corresponding handler on the
   * location manager. It returns {@code true} when the message belongs to the swap family and was
   * therefore routed, and {@code false} when the message type is unrelated and should be handled by
   * other message handlers. The method does not modify the message contents or perform retries, and
   * it does not catch exceptions thrown by the delegated handlers.
   *
   * @param m inbound message to classify and forward; must be non-null
   * @param source peer that originated the message; must be non-null and associated with {@code m}
   * @return {@code true} if the message was routed to the location manager; {@code false} otherwise
   */
  boolean handle(Message m, PeerNode source) {
    MessageType spec = m.getSpec();
    if (spec == DMT.FNPSwapRequest) {
      node.network().locationManager().handleSwapRequest(m, source);
      return true;
    } else if (spec == DMT.FNPSwapReply) {
      return node.network().locationManager().handleSwapReply(m, source);
    } else if (spec == DMT.FNPSwapRejected) {
      return node.network().locationManager().handleSwapRejected(m, source);
    } else if (spec == DMT.FNPSwapCommit) {
      return node.network().locationManager().handleSwapCommit(m, source);
    } else if (spec == DMT.FNPSwapComplete) {
      return node.network().locationManager().handleSwapComplete(m, source);
    }
    return false;
  }
}

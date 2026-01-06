package network.crypta.node;

import network.crypta.io.comm.DMT;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.MessageType;
import network.crypta.node.probe.Listener;
import network.crypta.node.probe.Probe;
import network.crypta.node.probe.Type;

/**
 * Dispatches probe-related messages to the node's {@link Probe} instance.
 *
 * <p>This helper acts as a thin, synchronous adapter between the node's message-handling pipeline
 * and the probe subsystem. It recognizes probe request messages and forwards them to the underlying
 * {@link Probe}, while also providing a direct entry point for starting locally initiated probes.
 * It does not maintain any mutable state beyond the owned probe reference and does not perform its
 * own validation beyond message-type checks.
 *
 * <p>Typical usage is internal to the node: a single instance is created per {@link Node} and is
 * invoked on inbound message dispatch. The handler is intentionally minimal to keep the routing
 * decision centralized in {@link Probe} and to avoid duplicating protocol rules in multiple places.
 *
 * <ul>
 *   <li>Responsibility: filter and forward probe request messages.
 *   <li>Responsibility: delegate local probe initiation to {@link Probe}.
 *   <li>Threading: no internal synchronization; delegation is immediate and synchronous.
 * </ul>
 *
 * @see Probe
 * @see DMT#ProbeRequest
 */
final class NodeProbeHandler {

  /** Probe helper that performs request handling and routing decisions for this node. */
  private final Probe probe;

  /**
   * Creates a probe handler bound to the provided node instance.
   *
   * <p>The handler constructs a new {@link Probe} that uses the supplied {@link Node} for routing
   * decisions, configuration, and statistics. Callers typically create exactly one handler per node
   * at startup and retain it for the lifetime of the node. Construction does not perform any I/O
   * and does not register external callbacks; it simply wires the handler to the probe helper.
   *
   * @param node owning node used by the probe subsystem for routing and configuration; must not be
   *     {@code null}
   */
  NodeProbeHandler(Node node) {
    this.probe = new Probe(node);
  }

  /**
   * Handles an inbound message and forwards probe requests to the probe subsystem.
   *
   * <p>If the message spec is {@link DMT#ProbeRequest}, the handler delegates to {@link
   * Probe#request(Message, PeerNode)} and reports that the message has been consumed. For all other
   * message types, the handler performs no action and returns {@code false} so the caller can
   * continue dispatching. This method is side-effect free for non-probe messages and makes no
   * attempt to validate message contents beyond the spec check.
   *
   * @param m inbound message to inspect and potentially forward; must not be {@code null}
   * @param source peer that supplied the message, used for attribution and routing; must not be
   *     {@code null}
   * @return {@code true} when the message is a probe request and was delegated; {@code false} when
   *     the message type is not handled
   */
  boolean handle(Message m, PeerNode source) {
    MessageType spec = m.getSpec();
    if (spec == DMT.ProbeRequest) {
      probe.request(m, source);
      return true;
    }
    return false;
  }

  /**
   * Starts a local probe request by delegating to {@link Probe#start(byte, long, Type, Listener)}.
   *
   * <p>This is a convenience entry point for initiating probes without exposing the {@link Probe}
   * instance directly. It forwards all parameters unchanged and relies on {@link Probe} to apply
   * validation, HTL clamping, and listener callbacks. The call is synchronous with respect to
   * delegation, but probe execution continues asynchronously according to the probe subsystem's
   * implementation.
   *
   * @param htl hops-to-live value forwarded to the probe subsystem, in hop units
   * @param uid unique request identifier used to match responses and callbacks
   * @param type probe type describing the measurement being requested; must not be {@code null}
   * @param listener callback target for results or terminal failure; must not be {@code null}
   */
  void startProbe(byte htl, long uid, Type type, Listener listener) {
    probe.start(htl, uid, type, listener);
  }
}

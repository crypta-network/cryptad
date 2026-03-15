package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;

/**
 * Client-to-node FCP message that requests an orderly shutdown of the running Crypta node.
 *
 * <p>This message is intentionally payload-free: it relies solely on the message name to convey
 * intent, and the receiver performs authorization and shutdown orchestration without consulting
 * additional fields. Typical clients issue it as the final command in a maintenance or automated
 * upgrade workflow once they have confirmed that no user-facing tasks remain. The handler enforces
 * that only peers with full access credentials can trigger the operation, ensuring that routine or
 * partially trusted connections cannot terminate the process unexpectedly.
 *
 * <p>Shutdown proceeds synchronously within the handler call: after an acknowledgment error message
 * is queued to the client, the node exits its process via {@link Node#exit(String)}. The class is
 * immutable and thread-safe; instances are stateless and may be reused across requests, though the
 * surrounding protocol usually allocates a fresh instance per inbound frame. Use this type when you
 * need a minimal, declarative way to signal server termination over FCP rather than invoking
 * out-of-band administration hooks.
 *
 * <ul>
 *   <li>Responsibilities: identify the shutdown intent and delegate execution to the node.
 *   <li>Access control: requires {@code hasFullAccess()} on the connection handler.
 *   <li>State: immutable; carries no parameters or mutable fields.
 * </ul>
 */
public class ShutdownMessage extends FCPMessage {

  /**
   * Protocol-level identifier used to encode and route the shutdown request on the FCP wire.
   * Exposed for callers that construct raw message frames or need to compare names without
   * instantiating the message class; the value is stable across releases.
   */
  public static final String NAME = "Shutdown";

  /**
   * Constructs a payload-free shutdown message ready to be dispatched over an FCP connection.
   *
   * <p>The instance holds no state and is safe to reuse for multiple send operations. Clients often
   * create it immediately before writing to the socket to avoid retaining references longer than
   * necessary. No additional initialization is required because all semantics are embedded in the
   * message name handled by the receiving endpoint.
   */
  public ShutdownMessage() {
    // Intentionally empty: shutdown carries no payload and needs no initialization.
  }

  /**
   * Returns {@code null} because shutdown messages never serialize auxiliary fields or parameters.
   *
   * <p>This keeps the wire format as compact as possible and signals to the serializer that only
   * the message name is required. Callers should not attempt to mutate the result or expect any
   * field-level validation when transmitting this message type.
   *
   * @return {@code null}, indicating that no {@link SimpleFieldSet} accompanies the shutdown
   *     message on the wire.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    return null;
  }

  /**
   * Provides the canonical FCP message name used to encode shutdown requests.
   *
   * <p>The value is constant and matches the identifier expected by the receiving side of the
   * protocol. Use this method when constructing outbound frames or for comparisons within dispatch
   * tables rather than duplicating the literal string.
   *
   * @return immutable message name {@code "Shutdown"} suitable for FCP routing decisions.
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Executes the shutdown request by validating access, notifying the client, and exiting the node.
   *
   * <p>The handler must expose full-access privileges; otherwise the method rejects the request
   * with a {@link MessageInvalidException}. On acceptance it first sends a {@link
   * ProtocolErrorMessage#SHUTTING_DOWN} response so the client can distinguish deliberate shutdown
   * from transport failures, and then calls {@link Node#exit(String)} to terminate the process. The
   * call is synchronous and does not retry; callers should therefore ensure idempotency upstream
   * because repeated invocations will request exit repeatedly once authorization passes.
   *
   * @param handler connection handler that issued the request; must provide full-access rights or
   *     the call fails with an exception
   * @throws MessageInvalidException when the connection lacks required privileges or protocol
   *     validation fails prior to triggering the shutdown
   */
  @Override
  public void run(FCPConnectionHandler handler) throws MessageInvalidException {
    if (!handler.hasFullAccess()) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.ACCESS_DENIED, "Shutdown requires full access", null, false);
    }
    FCPMessage msg =
        new ProtocolErrorMessage(
            ProtocolErrorMessage.SHUTTING_DOWN, true, "The node is shutting down", "Node", false);
    handler.send(msg);
    handler.getServer().getCore().getNode().exit("Received FCP shutdown message");
  }
}

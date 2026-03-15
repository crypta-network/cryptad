package network.crypta.clients.fcp;

import network.crypta.support.SimpleFieldSet;

/**
 * Represents the FCP notification emitted when a client-supplied identifier collides with an
 * existing one on the node. The message is immutable, created by the server side, and sent to the
 * client that attempted to register the duplicate identifier so the caller can pick a unique value
 * before retrying. The {@code global} flag conveys whether the collision originated from a broader
 * scope (for example, one shared across connections) or only within the current request context;
 * higher layers decide how to interpret that scope and whether to retry automatically.
 *
 * <p>The class only serializes the collision metadata; it does not attempt to resolve or mutate any
 * node state. It is safe for concurrent use because all fields are final and no mutable state is
 * exposed. Typical usage is server-side construction followed by {@link #getFieldSet()} when
 * marshalling an outbound FCP response. The {@link #run(FCPConnectionHandler)} method intentionally
 * rejects inbound execution because this message must not be sent from clients to the node.
 *
 * <ul>
 *   <li>Encapsulates the offending client identifier and collision scope.
 *   <li>Provides a stable, symbolic message name for FCP routing.
 * </ul>
 *
 * @see FCPMessage
 * @see FCPConnectionHandler
 */
public class IdentifierCollisionMessage extends FCPMessage {

  /** Client-specified identifier that triggered the collision. */
  final String clientIdentifier;

  final boolean global;

  /**
   * Builds a collision message carrying the identifier supplied by the client and the collision
   * scope indicator. The constructor performs no validation so that {@code null} identifiers and
   * both possible scope values are preserved exactly as observed by the node when the conflict was
   * detected. Instances produced here are intended for server-to-client delivery only.
   *
   * @param id client-provided identifier that already exists; may be {@code null} when the caller
   *     omitted a value or sent an empty token.
   * @param global whether the collision originated from a shared/global namespace rather than being
   *     limited to the current connection or request context.
   */
  public IdentifierCollisionMessage(String id, boolean global) {
    this.clientIdentifier = id;
    this.global = global;
  }

  /**
   * Produces the wire-ready {@link SimpleFieldSet} describing this collision. A fresh {@code
   * SimpleFieldSet} instance is created on every call so callers can further mutate the payload
   * without affecting other threads. The set always contains an {@code Identifier} entry reflecting
   * the provided client value (which may be {@code null} or empty) and a boolean {@code Global}
   * entry mirroring the stored scope flag. No normalization or de-duplication is performed here;
   * higher layers are expected to interpret or sanitize values as needed before transmission.
   *
   * @return new field set with {@code Identifier} and {@code Global} keys suitable for outbound FCP
   *     serialization; ownership is transferred to the caller.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    sfs.putSingle("Identifier", clientIdentifier);
    sfs.put("Global", global);
    return sfs;
  }

  /**
   * Returns the canonical FCP message name used on the wire. The value is constant across all
   * instances and callers and is suitable for routing, logging, or switch statements that dispatch
   * on message type names. The method performs no allocation and is safe to call frequently from
   * serialization pipelines or diagnostic code paths.
   *
   * @return the literal {@code "IdentifierCollision"} string identifying this message type in FCP
   *     exchanges.
   */
  @Override
  public String getName() {
    return "IdentifierCollision";
  }

  /**
   * Rejects attempts to execute this message in the client-to-server direction. If invoked, it
   * immediately throws a {@link MessageInvalidException} describing that {@code
   * IdentifierCollision} messages are outbound-only. The handler and node parameters are not used
   * because the method always fails fast; they remain in the signature to comply with the
   * superclass contract for inbound messages. Callers should never rely on this method returning
   * normally.
   *
   * @param handler connection handler that received the message; ignored because execution always
   *     aborts.
   * @throws MessageInvalidException always thrown to signal the invalid message direction before
   *     any state is modified or work is scheduled.
   */
  @Override
  public void run(FCPConnectionHandler handler) throws MessageInvalidException {
    throw new MessageInvalidException(
        ProtocolErrorMessage.INVALID_MESSAGE,
        "IdentifierCollision goes from server to client not the other way around",
        clientIdentifier,
        global);
  }
}

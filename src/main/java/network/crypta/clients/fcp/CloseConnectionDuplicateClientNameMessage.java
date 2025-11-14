package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;

/**
 * Message emitted by the node when it terminates an FCP connection because another session already
 * registered the same client {@code Name} value.
 *
 * <p>The server dispatches this type immediately after the duplicate is detected, usually while
 * finalizing the handshake. It communicates intent to close the socket rather than signalling a
 * transient failure, so a well-behaved client should drop its state, wait for the original
 * connection to exit, and then reconnect with a unique identifier. Because the warning targets the
 * offending connection, production clients rarely render it to end users; instead, it is logged for
 * diagnostic purposes when the connection was already half-closed.
 *
 * <p>The class carries no payload and is effectively immutable and stateless. Each call constructs
 * a fresh {@link SimpleFieldSet}, making concurrent use safe provided the caller does not mutate
 * the returned structure. Instances are typically short-lived serialization helpers created by the
 * server thread that detected the conflict.
 *
 * <ul>
 *   <li>Responsibility: represent a terminal condition for duplicate client names.
 *   <li>Threading: the object itself is thread-safe because it retains no internal state.
 *   <li>Lifecycle: create, serialize once onto the FCP stream, then discard.
 * </ul>
 *
 * @see FCPMessage
 */
public class CloseConnectionDuplicateClientNameMessage extends FCPMessage {

  /**
   * Creates a stateless message that can be sent as soon as a duplicate client name is observed.
   *
   * <p>The constructor performs no work beyond invoking the superclass default constructor, so
   * callers may instantiate one lazily for each offending connection without worrying about
   * resource retention. In practice, the instance is created on the I/O thread that handled the
   * handshake, serialized through the protocol layer, and then immediately eligible for garbage
   * collection once the handler closes. Keeping the constructor trivial preserves the expectation
   * that this type introduces zero overhead compared to emitting a bare protocol error.
   */
  public CloseConnectionDuplicateClientNameMessage() {
    // Constructor intentionally empty: this message carries no fields and inherits all behavior
    // from
    // FCPMessage, so doing work here would risk diverging from the stateless protocol contract.
  }

  /**
   * Returns an empty {@link SimpleFieldSet} used solely to satisfy the FCP framing contract for
   * messages that carry no additional key-value pairs.
   *
   * <p>The new instance is marked as {@linkplain SimpleFieldSet#SimpleFieldSet(boolean)
   * short-lived} so string interning is skipped, which avoids waste when the object exists only
   * long enough to be serialized. Callers are expected to treat the returned instance as read-only;
   * populating it with fields would contradict the protocol semantics and confuse peers that assume
   * this error message never bundles metadata. Each invocation returns a fresh container to prevent
   * accidental state sharing between different channel closures.
   *
   * @return newly constructed {@code SimpleFieldSet} whose lifetime matches a single serialization
   *     event and which contains no keys or values by design.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    return new SimpleFieldSet(true);
  }

  /**
   * Reports the symbolic name under which this message is advertised on the FCP wire.
   *
   * <p>The name is constant ({@code "CloseConnectionDuplicateClientName"}) and doubles as the
   * message identifier transmitted before any field set data. The handler layer compares this value
   * against the registration table associated with {@link FCPConnectionHandler} to determine
   * whether the message is valid in the current direction. Because the string is shared with
   * client-side implementations, changing it would break interoperability; therefore this accessor
   * exists to centralize the literal and discourage ad-hoc copies.
   *
   * @return canonical protocol message name guaranteeing compatibility with existing FCP clients
   *     and log analyzers.
   */
  @Override
  public String getName() {
    return "CloseConnectionDuplicateClientName";
  }

  /**
   * Rejects attempts to execute this message on the server side, because clients must not send it
   * upstream.
   *
   * <p>The {@link FCPConnectionHandler} invokes this method when a client-originated payload claims
   * to be {@code CloseConnectionDuplicateClientName}. Rather than ignoring the anomaly, the handler
   * throws a {@link MessageInvalidException} encoding {@link ProtocolErrorMessage#INVALID_MESSAGE},
   * which tells the caller that the protocol direction was violated. The exception is deliberately
   * non-retryable so malicious or buggy clients cannot degrade the node by sending illegal control
   * frames repeatedly. Callers should not attempt to swallow the exception; the connection should
   * be closed immediately after propagating it.
   *
   * @param handler connection-specific context that surfaced the offending message; never null.
   * @param node node instance receiving the invalid inbound request and orchestrating shutdown
   *     sequencing; never null.
   * @throws MessageInvalidException always thrown to stop processing because the message direction
   *     is unsupported and represents a client error.
   */
  @Override
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    throw new MessageInvalidException(
        ProtocolErrorMessage.INVALID_MESSAGE,
        "CloseConnectionDuplicateClientName goes from server to client not the other way around",
        null,
        false);
  }
}

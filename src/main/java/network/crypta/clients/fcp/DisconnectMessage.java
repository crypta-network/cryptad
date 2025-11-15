package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;

/**
 * Signals a protocol-level disconnect request to whichever client currently occupies the underlying
 * FCP connection.
 *
 * <p>The message carries no payload because enqueuing it on an {@link FCPConnectionHandler}
 * communicates the entire semantic intent: the node wishes to shut down the session, release any
 * outstanding request identifiers, and move the client back to an idle state. Typical emitters are
 * the server-side session manager after a terminal success or failure reply, or the guard rails
 * that detect abuse and demand a graceful cutoff instead of an abrupt socket reset.
 *
 * <p>Instances are immutable and therefore thread-safe; a single instance can be reused whenever
 * the protocol stack needs to convey the same action. Lifecycle management is straightforward: once
 * {@link #run(FCPConnectionHandler, Node)} executes, resources such as socket registrations,
 * throttling counters, and plugin callbacks are released as part of the handler's {@code close()}
 * routine, ensuring accounting remains balanced even under load.
 *
 * <ul>
 *   <li>Preserves explicit shutdown semantics rather than relying on TCP FIN/RST heuristics.
 *   <li>Helps {@link Node} enforce connection quotas by guaranteeing {@code close()} is invoked.
 * </ul>
 *
 * @author <a href="mailto:bombe@freenetproject.org">David ‘Bombe’ Roden</a>
 * @see FCPMessage
 * @see FCPConnectionHandler
 */
public class DisconnectMessage extends FCPMessage {

  /** The name of this message. */
  public static final String NAME = "Disconnect";

  /**
   * Builds a disconnect message from the parser-supplied metadata bundle.
   *
   * <p>The FCP parser constructs message types reflectively and therefore delivers the original
   * {@link SimpleFieldSet} even though this message does not consume any key-value pairs. Keeping
   * the signature uniform makes it possible to register the type beside other FCP messages without
   * adding special cases or branching logic.
   *
   * @param simpleFieldSet Incoming field set created by the parser; expected non-null even though
   *     the instance is ignored, preserving the reflective instantiation contract.
   */
  public DisconnectMessage(@SuppressWarnings("unused") SimpleFieldSet simpleFieldSet) {
    // FCP parser instantiates message types uniformly, so we still accept the field set even
    // though Disconnect carries no data; retaining the parameter preserves that contract.
  }

  /**
   * Returns the minimal field set describing this message when emitted back to a client.
   *
   * <p>The disconnect command never carries application data, so the returned {@link
   * SimpleFieldSet} is configured in read-only mode and contains zero entries. Serializers can
   * therefore flush it immediately without additional validation, and downstream code may treat the
   * object as disposable because a fresh instance is constructed for every call to avoid accidental
   * cross-thread sharing.
   *
   * @return a newly allocated read-only field set containing zero keys or values
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    return new SimpleFieldSet(true);
  }

  /**
   * Reports the canonical message identifier used on the wire.
   *
   * <p>The value is fixed to {@value #NAME}, matching the token defined by the FCP 2.0 draft, and
   * it allows dispatchers to route incoming frames without constructing a full object first.
   * Keeping the accessor here ensures parity with other {@link FCPMessage} subclasses and keeps
   * string ownership centralized, which helps avoid typos when logging or unit testing.
   *
   * @return the literal {@code Disconnect} identifier expected by the FCP dispatcher
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Executes the disconnect command against the provided handler and node context.
   *
   * <p>Calling this method is idempotent with respect to protocol semantics: on the first
   * invocation the handler closes its socket, cancels queued state, and notifies observers, while
   * subsequent calls simply operate on an already-closed channel. The {@link Node} reference is
   * supplied for parity with other messages yet remains unused, emphasizing that the logic lives
   * entirely in the connection layer.
   *
   * <pre>{@code
   * // Example: proactively terminate a misbehaving client
   * message.run(connectionHandler, node);
   * }</pre>
   *
   * @param handler Active connection handler whose {@code close()} method performs the shutdown and
   *     must not be {@code null} when this message executes.
   * @param node Node instance coordinating the broader session; provided for interface symmetry
   *     even though Disconnect does not manipulate node-local state.
   * @throws MessageInvalidException if the handler rejects the transition or detects a protocol
   *     violation while attempting to close.
   */
  @Override
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    handler.close();
  }
}

package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;

/**
 * Message issued by the node when it has finished streaming the peer list to an FCP client.
 *
 * <p>An {@code EndListPeersMessage} acts as the terminal marker for a {@code ListPeers} response
 * sequence, telling the recipient that no additional peer descriptions will follow for the
 * corresponding request cycle. The message itself is intentionally lightweight: it only conveys an
 * optional identifier and does not carry any payload or status code beyond the implicit
 * acknowledgement of completion. Instances are serialized directly onto the control connection,
 * making them suitable for reuse by code that multiplexes many peer-list operations over a single
 * handler. Despite the minimal state, the class participates fully in the {@link FCPMessage}
 * lifecycle and therefore integrates with the same serialization, dispatch, and validation
 * infrastructure used by more complex FCP messages.
 *
 * <p>Typical usage involves constructing the message with the client-provided identifier once the
 * server-side peer enumeration completes, passing the instance to {@link FCPConnectionHandler} so
 * that it can be emitted to the awaiting client. The class is immutable and thread-safe after
 * construction, meaning callers may freely share pre-built instances across request paths as long
 * as they do not mutate the underlying identifier reference. It is also safe to reuse across
 * threads, since all observable state is constant.
 *
 * <ul>
 *   <li>Signals completion of the peer-listing protocol exchange.
 *   <li>Associates the completion with the client-specified identifier when present.
 *   <li>Rejects any attempt to invoke it from client to server by raising {@link
 *       MessageInvalidException}.
 * </ul>
 */
public class EndListPeersMessage extends FCPMessage {
  static final String MESSAGE_NAME = "EndListPeers";
  private final String messageIdentifier;

  /**
   * Creates a new completion marker bound to the provided client identifier.
   *
   * <p>The identifier is echoed back to the client if it is non-{@code null}, allowing callers to
   * associate this completion event with a specific {@code ListPeers} request. The constructor does
   * not validate or copy the identifier string; callers should therefore ensure that either a
   * stable interned literal or an immutable string is supplied. Because instances are immutable,
   * they may be cached and reused for multiple dispatches that share the same identifier value.
   *
   * @param identifier textual token supplied by the client; may be {@code null} when no correlation
   *     is required or when the protocol session operates with implicit ordering.
   */
  public EndListPeersMessage(String identifier) {
    this.messageIdentifier = identifier;
  }

  /**
   * Builds the protocol field set emitted for this message.
   *
   * <p>The returned {@link SimpleFieldSet} always contains the {@code Identifier} key when the
   * message was constructed with a non-{@code null} identifier. Otherwise, the field set is empty,
   * which keeps the wire representation compact for anonymous operations. The method creates a new
   * field set on every invocation, so callers should cache the result if they need to marshal the
   * message multiple times during the same handshake.
   *
   * @return a mutable field set populated with any identifier metadata; callers may append
   *     additional diagnostic fields before serialization if needed.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    if (messageIdentifier != null) {
      fs.putSingle("Identifier", messageIdentifier);
    }
    return fs;
  }

  /**
   * Reports the literal name used on the FCP wire for this message type.
   *
   * <p>The name is stable across protocol versions and is required by {@link FCPMessage#send} to
   * prefix the textual representation before the accompanying field set. Returning a constant here
   * enables higher-level dispatchers to perform lookups without instantiating the message when they
   * only need to compare against the known literal.
   *
   * @return the fixed {@code "EndListPeers"} token recognized by the FCP protocol.
   */
  @Override
  public String getName() {
    return MESSAGE_NAME;
  }

  /**
   * Enforces the server-only semantics of this message by always raising an error when executed.
   *
   * <p>{@code EndListPeers} should never be received from an external FCP client, so the
   * implementation throws {@link MessageInvalidException} whenever {@link FCPConnectionHandler}
   * attempts to run it in the server context. This ensures misbehaving clients receive an explicit
   * protocol error rather than silently ignoring the command. The exception identifies the failure
   * as {@link ProtocolErrorMessage#INVALID_MESSAGE} and deliberately leaves the identifier unset,
   * because the server cannot trust the client-supplied identifier in this misuse scenario.
   *
   * @param handler connection handler invoking the message; ignored because execution always fails.
   * @param node node instance owning the FCP connection; ignored because execution always fails.
   * @throws MessageInvalidException always thrown to indicate that clients must not send this
   *     message to the node.
   */
  @Override
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    throw new MessageInvalidException(
        ProtocolErrorMessage.INVALID_MESSAGE,
        "EndListPeers goes from server to client not the other way around",
        null,
        false);
  }
}

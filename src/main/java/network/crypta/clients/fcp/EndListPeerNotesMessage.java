package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;

/**
 * Terminates a peer-note listing stream that the node sends to an FCP client.
 *
 * <p>This message acts as the final sentinel in a sequence of {@code ListPeerNotes} messages. It
 * carries only identifier metadata so that clients can match the completion signal to an ongoing
 * listing request regardless of transport framing. The type is immutable and thread-safe because it
 * exposes only constructor-injected state and never mutates shared resources. Consumers typically
 * instantiate it when preparing responses that enumerate darknet peers and their annotations.
 *
 * <p>Typical usage consists of constructing the message with the node identifier that initiated the
 * request, optionally adding the client-provided request identifier, and serializing the message
 * via {@link #getFieldSet()} and {@link #getName()} before handing it to the {@link
 * FCPConnectionHandler}. The message never runs server-side logic; attempts to execute it are
 * rejected so that rogue clients cannot spoof server-only control flow.
 *
 * <ul>
 *   <li>Immutable: all fields are {@code final} and populated by the constructor.
 *   <li>Stateless: does not reference external caches or the network layer.
 *   <li>Directional: valid only in the server-to-client direction.
 * </ul>
 */
public class EndListPeerNotesMessage extends FCPMessage {
  final String nodeIdentifier;
  static final String NAME = "EndListPeerNotes";
  private final String messageIdentifier;

  /**
   * Creates the terminal peer-note listing message with the required node identifier.
   *
   * <p>The constructor accepts optional client correlation metadata, enabling multiplexed request
   * flows to distinguish multiple concurrent listings. Callers should pass the exact node
   * identifier supplied by the client so downstream peers can validate provenance; do not reuse a
   * sentinel across different listing cycles.
   *
   * @param id canonical identifier of the node whose peer notes were listed; must not be {@code
   *     null}.
   * @param identifier optional application-level identifier that the client supplied when
   *     requesting the listing; {@code null} omits the field entirely.
   */
  public EndListPeerNotesMessage(String id, String identifier) {
    this.nodeIdentifier = id;
    this.messageIdentifier = identifier;
  }

  /**
   * Builds the {@link SimpleFieldSet} payload that will be serialized on the FCP wire.
   *
   * <p>The returned field set always includes {@code NodeIdentifier}. When the caller supplied a
   * client correlation token, the field set also includes {@code Identifier}. The field set is a
   * new instance on every invocation, so callers may mutate it after receipt without affecting
   * other message instances.
   *
   * @return a freshly allocated {@link SimpleFieldSet} containing mandatory and optional metadata;
   *     never {@code null}.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    sfs.putSingle("NodeIdentifier", nodeIdentifier);
    if (messageIdentifier != null) sfs.putSingle("Identifier", messageIdentifier);
    return sfs;
  }

  /**
   * Reports the protocol-level message name used during serialization.
   *
   * <p>The value is the fixed literal {@code EndListPeerNotes}, which instructs clients to treat
   * the message as the closing marker for a peer-note listing. Because the name never changes and
   * has no runtime dependencies, this method is safe to call repeatedly and requires no caching.
   *
   * @return the constant {@link #NAME} identifying this message type.
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Rejects execution because the message is server-to-client only.
   *
   * <p>Although {@link FCPMessage#run(FCPConnectionHandler, Node)} usually processes
   * client-originated requests, this message exists solely to inform clients that a server-side
   * listing completed. Therefore, invoking {@code run} always throws {@link
   * MessageInvalidException} with {@link ProtocolErrorMessage#INVALID_MESSAGE}. Callers should
   * never attempt to enqueue this message for inbound processing; instead, serialize it directly to
   * the client connection.
   *
   * @param handler connection handler attempting to process the message; unused because execution
   *     is forbidden.
   * @param node local node context; unused.
   * @throws MessageInvalidException always thrown to signal that the command is invalid in this
   *     direction and must not be executed.
   */
  @Override
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    throw new MessageInvalidException(
        ProtocolErrorMessage.INVALID_MESSAGE,
        "EndListPeerNotes goes from server to client not the other way around",
        null,
        false);
  }
}

package network.crypta.clients.fcp;

import network.crypta.keys.FreenetURI;
import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;

/**
 * Message emitted by the node to inform the client that a put request produced a fetchable URI.
 *
 * <p>The server sends this message when a client-initiated insert (PUT) results in a finalized key
 * that can later be retrieved via a {@code GetRequest}. It encapsulates the caller-supplied
 * identifier, whether the message is scoped to the global queue, and the resulting {@link
 * FreenetURI}. Instances are immutable and transport-only; they contain no back-references to the
 * originating request beyond the opaque identifier. Typical consumers forward the contained fields
 * directly to their own dispatch layer or surface them in higher-level client notifications.
 *
 * <p>Concurrency: the class is immutable and therefore thread-safe for publication across handler
 * threads. The payload values are supplied at construction time and never mutated afterward. Large
 * files may generate multiple protocol exchanges; this message is the terminal notification that
 * the content is now addressable within the network.
 *
 * <ul>
 *   <li>Responsibilities: expose the generated URI and client identifier to downstream handlers.
 *   <li>Notable behaviors: refuses to run on the client side and instead signals a protocol error.
 *   <li>Usage: typically read-only; callers invoke {@link #getFieldSet()} to serialize for FCP.
 * </ul>
 */
public class PutFetchableMessage extends FCPMessage {

  PutFetchableMessage(String ident, boolean global, FreenetURI uri) {
    this.identifier = ident;
    this.global = global;
    this.uri = uri;
  }

  final String identifier;
  final boolean global;
  final FreenetURI uri;

  /**
   * Builds a field set representing this message in the wire-level FCP format.
   *
   * <p>The method always includes the caller-provided identifier and the global flag. When a URI is
   * available, it serializes the value without metadata or annotations. The returned structure is
   * ready for transmission over the control connection and contains only immutable snapshot data
   * taken at message creation time. Callers should treat the result as transient and avoid caching
   * it across protocol cycles that may carry unrelated identifiers or URIs.
   *
   * @return a {@link SimpleFieldSet} containing identifier, global scope flag, and optional URI in
   *     string form; the caller owns the returned instance and may modify it without affecting this
   *     message.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", identifier);
    fs.put("Global", global);
    if (uri != null) fs.putSingle("URI", uri.toString(false, false));
    return fs;
  }

  /**
   * Returns the protocol-level name for this message type.
   *
   * <p>The name is stable across protocol versions and is used by the FCP parser to route incoming
   * messages to the appropriate handler or notification logic. It never returns {@code null} and
   * contains no whitespace.
   *
   * @return the literal string {@code "PutFetchable"} representing this FCP message identifier.
   */
  @Override
  public String getName() {
    return "PutFetchable";
  }

  /**
   * Rejects inbound client-side execution because this message is server-originated.
   *
   * <p>If a client attempts to send {@code PutFetchableMessage} to the node, the method throws a
   * {@link MessageInvalidException} explaining the correct directionality. This preserves protocol
   * invariants by ensuring the client cannot repurpose server notifications as requests. The method
   * is not idempotent because it always throws and does not attempt retries or recovery.
   *
   * @param handler connection handler receiving the message; must not be {@code null} but is unused
   *     because execution always fails on the client side.
   * @param node active node instance associated with the connection; not consulted before the
   *     exception is raised.
   * @throws MessageInvalidException always thrown to signal that the message cannot be executed
   *     from client to server.
   */
  @Override
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    throw new MessageInvalidException(
        ProtocolErrorMessage.INVALID_MESSAGE,
        "PutFetchable goes from server to client not the other way around",
        identifier,
        global);
  }
}

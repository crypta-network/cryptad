package network.crypta.clients.fcp;

import network.crypta.keys.FreenetURI;
import network.crypta.keys.InsertableClientSSK;
import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;

/**
 * Generates a new signed subspace key (SSK) pair for an FCP client and relays it back over the
 * connection. The message is created from the parsed field set of an inbound request and, when
 * executed, allocates a fresh {@link InsertableClientSSK} using the node's secure random source.
 * Clients use this flow when they need a write-capable insert URI and a corresponding request URI
 * without transmitting their own key material.
 *
 * <p>The instance is intentionally lightweight and stateless: all protocol information lives in the
 * supplied {@link SimpleFieldSet}, and all cryptographic material is produced during {@link
 * #run(FCPConnectionHandler, Node)}. This makes it safe to reuse a single instance per incoming
 * request in a multithreaded FCP server loop. The generated keypair is ephemeral until persisted
 * elsewhere; no on-disk side effects occur in this class. The optional client identifier is echoed
 * back so callers can correlate responses to their session or outstanding command queue. Typical
 * usage calls {@link #getFieldSet()} during serialization, then {@link #run(FCPConnectionHandler,
 * Node)} when the command should be fulfilled.
 *
 * <ul>
 *   <li>Parses the caller-supplied identifier, if present, from the inbound field set.
 *   <li>Creates a random SSK insert/request pair using the node's randomness provider.
 *   <li>Wraps the resulting URIs in an {@link SSKKeypairMessage} and sends it via the handler.
 * </ul>
 *
 * @see SSKKeypairMessage
 * @see InsertableClientSSK
 */
public class GenerateSSKMessage extends FCPMessage {

  static final String NAME = "GenerateSSK";
  final String clientIdentifier;

  GenerateSSKMessage(SimpleFieldSet fs) {
    clientIdentifier = fs.get("Identifier");
  }

  /**
   * Builds the field set representation of this request for transmission over FCP. The return value
   * contains only protocol fields required for the node to recognize the request type and, if
   * present, the optional client-specified correlation identifier.
   *
   * @return a mutable {@link SimpleFieldSet} containing {@code Identifier} when provided; callers
   *     may append additional entries before serialization without affecting existing semantics.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    if (clientIdentifier != null) fs.putSingle("Identifier", clientIdentifier);
    return fs;
  }

  /**
   * Returns the canonical FCP message name associated with this request. The name is used by
   * routing and serialization layers to map protocol frames back to handlers.
   *
   * @return immutable message name {@code GenerateSSK} used when emitting protocol frames.
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Generates a new random SSK keypair and sends it to the client as an {@link SSKKeypairMessage}.
   * The method is synchronous with respect to the caller: key generation occurs immediately using
   * the node's random source, and the response is dispatched on the provided connection handler. No
   * state is retained after sending; callers may invoke this repeatedly to obtain multiple
   * independent keypairs.
   *
   * @param handler active connection handler that delivers the generated keypair back to the
   *     requesting client; must not be {@code null}.
   * @param node running node that supplies randomness and environment context for creating the SSK
   *     pair; expected to be fully initialized.
   * @throws MessageInvalidException if the response message cannot be encoded or sent according to
   *     FCP protocol rules or if the handler rejects the outbound payload.
   */
  @Override
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    InsertableClientSSK key = InsertableClientSSK.createRandom(node.bootstrap().random(), "");
    FreenetURI insertURI = key.getInsertURI();
    FreenetURI requestURI = key.getURI();
    SSKKeypairMessage msg = new SSKKeypairMessage(insertURI, requestURI, clientIdentifier);
    handler.send(msg);
  }
}

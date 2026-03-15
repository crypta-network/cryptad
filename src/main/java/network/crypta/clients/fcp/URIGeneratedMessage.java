package network.crypta.clients.fcp;

import network.crypta.keys.FreenetURI;
import network.crypta.support.SimpleFieldSet;

/**
 * Message emitted by the node when a {@link FreenetURI} has been produced for a request that
 * previously supplied an identifier. The message carries the freshly generated URI along with the
 * client-provided identifier so receivers can correlate responses to their outstanding operations.
 *
 * <p>Typical use cases include responding to insert or key-generation requests where the caller did
 * not know the final URI ahead of time. The message is immutable and only exposes read-only state;
 * instances can therefore be safely shared between threads, but they are generally short-lived and
 * serialized immediately to the wire via {@link #getFieldSet()}.
 *
 * <p>Responsibilities include:
 *
 * <ul>
 *   <li>Expose the generated URI and identifier in the FCP wire format.
 *   <li>Advertise the standard message name {@code URIGenerated} to the protocol layer.
 *   <li>Guard against incorrect client-to-server usage by rejecting {@link
 *       #run(FCPConnectionHandler)} calls.
 * </ul>
 *
 * Concurrency: the object is immutable once constructed. Protocol handlers may reuse it across
 * threads, but outbound serialization should occur promptly to avoid holding stale references to
 * completed operations.
 */
public class URIGeneratedMessage extends FCPMessage {

  private final FreenetURI uri;
  private final String messageIdentifier;
  private final boolean global;

  /**
   * Builds a message that pairs a generated {@link FreenetURI} with the client-supplied identifier
   * that initiated the generation request.
   *
   * @param uri concrete {@link FreenetURI} produced by the node; must not be {@code null}.
   * @param identifier correlation token from requester; empty values allowed for response matching.
   * @param global flags identifier as connection-global or confined to single request.
   */
  public URIGeneratedMessage(FreenetURI uri, String identifier, boolean global) {
    this.uri = uri;
    this.messageIdentifier = identifier;
    this.global = global;
  }

  /**
   * Serializes this message into a {@link SimpleFieldSet} suitable for transmission over the FCP
   * wire protocol, including {@code URI}, {@code Identifier}, and {@code Global} entries.
   *
   * @return immutable snapshot of the message fields encoded for FCP serialization.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("URI", uri.toString());
    fs.putSingle("Identifier", messageIdentifier);
    fs.put("Global", global);
    return fs;
  }

  /**
   * Provides the canonical FCP message name associated with URI generation responses.
   *
   * @return constant string {@code "URIGenerated"} recognized by FCP peers.
   */
  @Override
  public String getName() {
    return "URIGenerated";
  }

  /**
   * Rejects inbound handling of this message from clients, enforcing its server-to-client direction
   * in the FCP protocol.
   *
   * @param handler active connection handler attempting to process the message.
   * @throws MessageInvalidException always thrown to indicate incorrect message direction on the
   *     wire.
   */
  @Override
  public void run(FCPConnectionHandler handler) throws MessageInvalidException {
    throw new MessageInvalidException(
        ProtocolErrorMessage.INVALID_MESSAGE,
        "URIGenerated goes from server to client not the other way around",
        messageIdentifier,
        false);
  }
}

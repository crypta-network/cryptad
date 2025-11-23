package network.crypta.clients.fcp;

import network.crypta.keys.FreenetURI;
import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;

/**
 * Represents the server-to-client FCP message that delivers a freshly generated SSK keypair.
 *
 * <p>The message packages the insertable and retrievable halves of a signed subspace key (SSK) into
 * a {@link SimpleFieldSet} so the client can store both URIs without additional parsing. It is
 * produced by the node when a client requests a new keypair and is intended to travel only from
 * server to client. Each instance is immutable after construction, making it safe to reuse across
 * threads once created, while avoiding shared mutable state during serialization. Typical usage is
 * to create the message, send the resulting field set through an {@link FCPConnectionHandler}, and
 * then persist or display the returned URIs to the caller.
 *
 * <p>Responsibilities include encapsulating both URIs, preserving an optional client identifier
 * used for request correlation, and providing the canonical protocol name for dispatch. Because the
 * message is outbound-only, executing it as an inbound command is rejected explicitly to guard
 * against protocol misuse.
 *
 * <ul>
 *   <li>Encapsulates insert and request URIs for an SSK keypair.
 *   <li>Preserves an optional client identifier for correlation.
 *   <li>Exports a field set ready for FCP wire transmission.
 * </ul>
 *
 * @see FCPMessage
 * @see FreenetURI
 */
public class SSKKeypairMessage extends FCPMessage {

  private final FreenetURI insertURI;
  private final FreenetURI requestURI;
  private final String clientIdentifier;

  /**
   * Creates a new message that holds both halves of an SSK keypair and an optional correlation
   * identifier.
   *
   * <p>The provided {@code insertURI} represents the URI that can be used to publish data under the
   * generated key, while {@code requestURI} is the corresponding retrieval URI the client will keep
   * for lookups. The identifier is passed through unmodified and may be {@code null}; when present,
   * it enables clients to match asynchronous replies to the originating request without additional
   * state.
   *
   * @param insertURI the insertion URI for the generated SSK, never {@code null} and expected to be
   *     prevalidated by the caller.
   * @param requestURI the retrieval URI for the same SSK, never {@code null}; used when issuing
   *     future fetch requests.
   * @param identifier optional client-provided token for correlation; may be {@code null} when no
   *     correlation is required.
   */
  public SSKKeypairMessage(FreenetURI insertURI, FreenetURI requestURI, String identifier) {
    this.insertURI = insertURI;
    this.requestURI = requestURI;
    this.clientIdentifier = identifier;
  }

  /**
   * Builds the serialized representation of this message for transmission over an FCP connection.
   *
   * <p>The returned {@link SimpleFieldSet} always contains {@code InsertURI} and {@code RequestURI}
   * entries derived from the supplied {@link FreenetURI} values. If a client identifier was
   * provided at construction time, it is emitted under the {@code Identifier} key; otherwise the
   * field is omitted entirely to keep the payload minimal. Callers receive a fresh field set on
   * every invocation, so the result can be modified or reused without affecting the message
   * instance. No network I/O is performed within this method.
   *
   * @return a new field set containing the URIs and optional identifier, ready for immediate wire
   *     encoding.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    sfs.putSingle("InsertURI", insertURI.toString());
    sfs.putSingle("RequestURI", requestURI.toString());
    if (clientIdentifier != null) { // is optional on these two only
      sfs.putSingle("Identifier", clientIdentifier);
    }
    return sfs;
  }

  /**
   * Returns the canonical protocol name for this message type.
   *
   * <p>The name is used by FCP dispatchers and loggers to route or categorize messages without
   * inspecting their contents. It always returns the literal {@code "SSKKeypair"}, matching the
   * server-to-client message defined by the protocol specification. Callers can rely on this value
   * being stable across releases because it is part of the external wire contract and not inferred
   * from the contained URIs or client identifier.
   *
   * @return the constant string {@code "SSKKeypair"} identifying this message type.
   */
  @Override
  public String getName() {
    return "SSKKeypair";
  }

  /**
   * Rejects inbound execution of this outbound-only message type.
   *
   * <p>In the FCP protocol, {@code SSKKeypair} is emitted by the server when a client asks for a
   * new keypair. Attempting to process it as a client-originating command violates the expected
   * directionality, so this method throws a {@link MessageInvalidException} immediately rather than
   * performing any side effects. The exception includes the optional client identifier to help the
   * caller correlate the failure with the triggering request.
   *
   * @param handler the connection handler receiving the message; must not be {@code null} even
   *     though the message is never executed successfully.
   * @param node the local node instance; present for signature consistency and not used prior to
   *     throwing the exception.
   * @throws MessageInvalidException always thrown to signal the message is invalid in this
   *     direction; callers should treat this as a protocol error.
   */
  @Override
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    throw new MessageInvalidException(
        ProtocolErrorMessage.INVALID_MESSAGE,
        "SSKKeypair goes from server to client not the other way around",
        clientIdentifier,
        false);
  }
}

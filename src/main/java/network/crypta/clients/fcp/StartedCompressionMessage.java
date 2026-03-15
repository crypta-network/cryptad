package network.crypta.clients.fcp;

import network.crypta.support.SimpleFieldSet;
import network.crypta.support.compress.Compressor.COMPRESSOR_TYPE;

/**
 * FCP notice emitted when a peer begins compressing traffic for a request or the entire connection.
 *
 * <p>The message carries a caller-supplied identifier so the receiver can match the compression
 * change to a specific client request or session scope. The {@code global} flag mirrors the wire
 * protocol hint that determines whether subsequent messages for the whole connection or only a
 * scoped exchange should be compressed. The chosen codec is exposed via its stable {@link
 * COMPRESSOR_TYPE#codecName} so the far end can initialize the corresponding decompressor without
 * inspecting implementation details.
 *
 * <p>Instances are immutable and safe to share across threads because all state is provided at
 * construction time and never mutated. Typical callers build the message server-side, hand it to
 * the FCP output pipeline, and never invoke {@link #run(FCPConnectionHandler)} because this type is
 * not meant to be received from clients. Client-side receipt is treated as a protocol violation and
 * rejected immediately.
 *
 * <ul>
 *   <li>Serializes as a {@link SimpleFieldSet} with {@code Identifier}, {@code Codec}, and {@code
 *       Global} keys.
 *   <li>Always reports the canonical FCP name {@code StartedCompression}.
 *   <li>{@link #run(FCPConnectionHandler)} exists only to guard against misrouted traffic.
 * </ul>
 *
 * @see FCPMessage
 * @see COMPRESSOR_TYPE
 */
public class StartedCompressionMessage extends FCPMessage {

  final String messageIdentifier;
  final boolean global;

  final COMPRESSOR_TYPE codec;

  /**
   * Creates a compression start message with the supplied identifier, scope, and codec metadata.
   *
   * <p>The constructor does not validate inputs; callers must ensure the identifier is unique for
   * the connection context and that the codec is negotiated or otherwise acceptable to the peer.
   * The {@code global} hint is written verbatim to the wire format so downstream handlers can
   * decide whether to apply compression to subsequent traffic for a single request or for all
   * messages on the connection. All parameters are stored exactly as provided to preserve protocol
   * fidelity.
   *
   * @param identifier correlation token provided by the sender; non-null and typically
   *     request-scoped
   * @param global {@code true} when compression applies to the entire connection; {@code false}
   *     when scoped
   * @param codec negotiated compressor implementation whose {@link COMPRESSOR_TYPE#codecName}
   *     travels on the wire
   */
  public StartedCompressionMessage(String identifier, boolean global, COMPRESSOR_TYPE codec) {
    this.messageIdentifier = identifier;
    this.codec = codec;
    this.global = global;
  }

  /**
   * Builds the {@link SimpleFieldSet} sent over FCP to announce compression activation.
   *
   * <p>The returned structure always includes the identifier, the stable codec name, and the
   * boolean global flag. The method allocates a fresh {@link SimpleFieldSet} on each invocation so
   * callers may modify the result without affecting other send operations. No null filtering or
   * value normalization is performed; inputs supplied at construction are inserted verbatim to
   * honor protocol expectations and avoid lossy transformations.
   *
   * @return newly allocated field set containing {@code Identifier}, {@code Codec}, and {@code
   *     Global} entries representing this message
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", messageIdentifier);
    fs.putSingle("Codec", codec.codecName);
    fs.put("Global", global);
    return fs;
  }

  /**
   * Reports the canonical FCP message name for routing and serialization.
   *
   * <p>The name is constant for all instances and is used by the framing layer to tag outgoing
   * messages and by client dispatch code when validating inbound traffic. Because the value is
   * immutable and universally recognized across the protocol, callers can safely use it as a map
   * key or switch discriminator without additional normalization.
   *
   * @return fixed string {@code StartedCompression} used by the FCP dispatcher
   */
  @Override
  public String getName() {
    return "StartedCompression";
  }

  /**
   * Rejects attempts to process this message from the client side by throwing a protocol error.
   *
   * <p>This type is emitted by servers and must not be accepted from clients. If a client sends it
   * inbound, the handler triggers {@link MessageInvalidException} with context about the invalid
   * direction, preserving the original identifier and scope flag for diagnostics. The method is
   * intentionally side effect free beyond raising the exception so no partial state is committed
   * before the failure is reported upstream.
   *
   * @param handler connection handler requesting execution; ignored because the message is invalid
   *     inbound
   * @throws MessageInvalidException always thrown to signal that the message direction violates the
   *     FCP contract
   */
  @Override
  public void run(FCPConnectionHandler handler) throws MessageInvalidException {
    throw new MessageInvalidException(
        ProtocolErrorMessage.INVALID_MESSAGE,
        "StartedCompression goes from server to client not the other way around",
        messageIdentifier,
        global);
  }
}

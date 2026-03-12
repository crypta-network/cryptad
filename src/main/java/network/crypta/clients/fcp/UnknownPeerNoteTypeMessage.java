package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;

/**
 * Represents a client-originated FCP message that references a peer note type unknown to the
 * server. The class exists to surface protocol misuse explicitly: the server never expects to
 * receive this message and will reject it immediately. Typical caller code should only construct
 * this message in test harnesses or diagnostic tools that validate error handling paths, not in
 * production client implementations. Instances are immutable after construction and carry only a
 * numeric peer note type plus an optional correlation identifier supplied by the caller.
 *
 * <p>Life cycle expectations:
 *
 * <ul>
 *   <li>Creation: a client builds the message when it encounters a peer note type code that does
 *       not map to any known peer note schema.
 *   <li>Transmission: {@link #getFieldSet()} serializes the numeric type and optional identifier to
 *       the wire format understood by the FCP layer.
 *   <li>Handling: {@link #run(FCPConnectionHandler, Node)} always fails fast with a {@link
 *       MessageInvalidException}, preventing the unknown type from propagating deeper into server
 *       logic.
 * </ul>
 *
 * <p>Thread safety: instances are read-only after creation and may be reused across threads if the
 * surrounding transport code does so. Because the message always represents an error case, callers
 * typically send it once and then discard it rather than caching.
 */
public class UnknownPeerNoteTypeMessage extends FCPMessage {

  final int peerNoteType;
  final String messageIdentifier;

  /**
   * Creates a message describing a peer note type the server does not recognize.
   *
   * @param peerNoteType numeric code reported by the client for the peer note type that failed
   *     resolution; negative values are accepted but will still trigger rejection.
   * @param identifier optional application-level identifier used to correlate responses; may be
   *     {@code null} when the sender does not need per-message correlation on errors.
   */
  public UnknownPeerNoteTypeMessage(int peerNoteType, String identifier) {
    this.peerNoteType = peerNoteType;
    this.messageIdentifier = identifier;
  }

  /**
   * Builds a {@link SimpleFieldSet} describing the unknown peer note type for transmission over the
   * FCP connection.
   *
   * <p>The returned field set is newly allocated on each invocation and contains the mandatory
   * {@code PeerNoteType} entry plus the optional {@code Identifier} when supplied at construction
   * time. Callers may modify the returned instance without affecting the message state.
   *
   * @return mutable field set containing the peer note type and optional identifier, ready for
   *     serialization by the FCP transport layer.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.put("PeerNoteType", peerNoteType);
    if (messageIdentifier != null) fs.putSingle(IDENTIFIER, messageIdentifier);
    return fs;
  }

  /**
   * Provides the protocol-level name for this message type.
   *
   * @return constant string {@code "UnknownPeerNoteType"} used by dispatch logic and wire encoding.
   */
  @Override
  public String getName() {
    return "UnknownPeerNoteType";
  }

  /**
   * Fails the message immediately because the server should not receive unknown peer note types
   * from clients.
   *
   * <p>This method always throws without side effects, ensuring the connection handler surfaces a
   * clear {@link ProtocolErrorMessage#INVALID_MESSAGE} response. It does not attempt retries or
   * partial handling, so callers should expect the enclosing request to terminate.
   *
   * @param handler connection handler invoking the message; not used beyond validation but must be
   *     non-null when provided by the framework.
   * @param node active node instance for context; unused because the method never proceeds to node
   *     operations.
   * @throws MessageInvalidException always thrown to signal that the message direction is invalid
   *     for the server and processing cannot continue.
   */
  @Override
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    throw new MessageInvalidException(
        ProtocolErrorMessage.INVALID_MESSAGE,
        "UnknownPeerNoteType goes from server to client not the other way around",
        messageIdentifier,
        false);
  }
}

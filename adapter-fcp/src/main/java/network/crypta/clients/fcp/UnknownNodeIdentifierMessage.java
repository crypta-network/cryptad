package network.crypta.clients.fcp;

import network.crypta.support.SimpleFieldSet;

/**
 * Represents the FCP notification the server returns when a client references a node identifier the
 * server does not recognize.
 *
 * <p>This message is part of the error-handling surface between an FCP client and the Crypta
 * server. It encapsulates the offending node identifier and an optional per-request identifier so
 * clients can correlate the failure with the original command. The message is intentionally simple
 * and immutable: once constructed, the identifier values are stored verbatim and rendered into a
 * {@link SimpleFieldSet} without further validation. Typical call paths originate on the server
 * when validating inbound traffic; the client side should not emit this message, and {@link
 * #run(FCPConnectionHandler)} throws if execution is attempted in that direction. Instances are
 * lightweight and thread-safe because they carry only final string fields and perform no mutable
 * operations. Use this type when you need a structured way to surface “unknown NodeIdentifier”
 * errors back to an FCP client while preserving the identifiers needed for diagnostics and logging.
 *
 * <ul>
 *   <li>Immutable payload carrying the unrecognized node identifier.
 *   <li>Optional correlation identifier for pairing with client-issued requests.
 *   <li>Server-to-client only; invocation on the client side is rejected.
 * </ul>
 *
 * @see FCPMessage
 * @see ProtocolErrorMessage
 */
public class UnknownNodeIdentifierMessage extends FCPMessage {

  final String nodeIdentifier;
  final String messageIdentifier;

  /**
   * Creates a new message describing an unrecognized node identifier supplied by a client.
   *
   * <p>The provided values are stored exactly as received so downstream handlers can echo them back
   * to the client or include them in logs. No null checks are enforced beyond what the caller
   * supplies, but the protocol typically expects {@code id} to be non-null. The optional {@code
   * identifier} correlates the error to a specific request so clients can distinguish responses
   * when multiple commands are in flight.
   *
   * @param id node identifier supplied by the client; expected to be the unknown value being
   *     reported back by the server.
   * @param identifier optional per-message correlation identifier; may be {@code null} when the
   *     origin request did not include one.
   */
  public UnknownNodeIdentifierMessage(String id, String identifier) {
    this.nodeIdentifier = id;
    this.messageIdentifier = identifier;
  }

  /**
   * Builds the field set representation used on the wire for this protocol message.
   *
   * <p>The returned {@link SimpleFieldSet} always includes {@code NodeIdentifier} populated with
   * the stored node identifier value. When a message identifier is present, it is emitted under the
   * {@code Identifier} key. No normalization or trimming is performed, so the caller retains full
   * control over the raw values that travel across the connection.
   *
   * @return field set containing protocol keys for the unknown node identifier and optional
   *     correlation identifier; always non-null and safe for reuse until modified externally.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    sfs.putSingle("NodeIdentifier", nodeIdentifier);
    if (messageIdentifier != null) sfs.putSingle("Identifier", messageIdentifier);
    return sfs;
  }

  /**
   * Returns the protocol-visible name for this FCP message type.
   *
   * <p>The name is fixed by the protocol specification and used during serialization to tag the
   * outgoing message, enabling clients to dispatch handlers without inspecting the payload fields.
   *
   * @return constant string {@code "UnknownNodeIdentifier"} representing this message type.
   */
  @Override
  public String getName() {
    return "UnknownNodeIdentifier";
  }

  /**
   * Rejects client-side execution of this server-only message by throwing immediately.
   *
   * <p>This implementation enforces the directionality constraint of the FCP protocol: an {@code
   * UnknownNodeIdentifier} notification is valid only from server to client. If invoked on the
   * client path, it signals a protocol violation via {@link MessageInvalidException}. No attempt is
   * made to inspect {@code handler} or {@code node}; they are unused because the method never
   * proceeds past the exception.
   *
   * @param handler connection handler provided by the caller; ignored because the method always
   *     throws to block processing.
   * @throws MessageInvalidException always thrown to indicate the message direction is invalid when
   *     executed on the client side.
   */
  @Override
  public void run(FCPConnectionHandler handler) throws MessageInvalidException {
    throw new MessageInvalidException(
        ProtocolErrorMessage.INVALID_MESSAGE,
        "UnknownNodeIdentifier goes from server to client not the other way around",
        nodeIdentifier,
        false);
  }
}

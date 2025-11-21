package network.crypta.clients.fcp;

import java.io.Serial;

/**
 * Indicates that a parsed FCP message failed validation and cannot be processed further.
 *
 * <p>The exception is raised after an incoming message has already been parsed into a
 * SimpleFieldSet but is missing required fields, carries unsupported combinations, or otherwise
 * violates the expectations of the FCP contract. Callers typically throw this from message
 * dispatchers or validators to signal to upstream routing code that a protocol-level error must be
 * reported back to the peer. Instances carry the protocol response code, a human-readable detail
 * string, and the optional message identifier to help operators correlate failures in logs.
 *
 * <p>The type is immutable and therefore thread-safe to share between threads when propagating
 * errors. It is intended for exceptional, fatal message handling paths rather than recoverable
 * retries; callers should treat its presence as a signal to terminate handling of the offending
 * message. Typical usage wraps validation blocks or parsing routines and lets outer handlers map
 * the contained protocol code to an {@code ProtocolError} reply.
 *
 * <ul>
 *   <li>Responsibility: represent validation failures for already parsed FCP messages.
 *   <li>State: holds a protocol error code, the optional identifier, and a human-readable reason.
 *   <li>Usage pattern: throw during validation; catch at protocol boundary to craft error replies.
 * </ul>
 */
public class MessageInvalidException extends Exception {
  @Serial private static final long serialVersionUID = -1;

  /**
   * Protocol-specific numeric code that should be echoed back in the resulting {@code
   * ProtocolError} reply. A value from the FCP message catalog; remains unchanged after
   * construction.
   */
  final int protocolCode;

  /**
   * Optional message identifier associated with the invalid request, allowing callers to correlate
   * error responses to client-issued identifiers. May be {@code null} or empty when the peer did
   * not supply an identifier.
   */
  public final String ident;

  /**
   * Flag indicating whether the error applies to the connection as a whole rather than a single
   * request. When {@code true}, callers should consider closing the session or treating the peer as
   * misbehaving.
   */
  public final boolean global;

  /**
   * Creates a new exception describing why an already-parsed FCP message cannot be processed.
   *
   * <p>The constructor captures the protocol error code that should appear in the outbound {@code
   * ProtocolError} response, the human-readable detail message, the optional message identifier
   * supplied by the peer, and whether the error applies globally to the connection. The instance is
   * immutable after creation and safe to propagate across threads if needed.
   *
   * @param protocolCode numeric code from the FCP error catalog to return to the peer; non-negative
   *     values map directly to {@code ProtocolError} responses.
   * @param extra human-readable description of what validation failed; should avoid sensitive peer
   *     data and may be displayed in logs.
   * @param ident optional identifier supplied with the inbound message; may be {@code null} or
   *     empty when the peer omitted it.
   * @param global whether the failure affects the overall connection integrity; {@code true} hints
   *     that clients should consider terminating or resetting the session.
   */
  public MessageInvalidException(int protocolCode, String extra, String ident, boolean global) {
    super(extra);
    this.protocolCode = protocolCode;
    this.ident = ident;
    this.global = global;
  }
}

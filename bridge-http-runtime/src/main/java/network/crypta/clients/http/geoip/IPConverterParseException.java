package network.crypta.clients.http.geoip;

import java.io.Serial;

/**
 * Signals that a textual IP address could not be parsed or converted into a usable representation.
 *
 * <p>This exception is part of the GeoIP-related HTTP implementation and is intended to represent
 * failures that happen at the boundary between untrusted input (for example, query parameters or
 * headers) and the code that consumes an IP address for subsequent processing. It gives callers a
 * dedicated, domain-specific signal that the input did not meet the syntactic expectations of the
 * converter, instead of overloading more general exceptions.
 *
 * <p>Instances of this type are immutable after construction and safe to share across threads in
 * the same way as {@link Exception}; the only mutable state is the standard stack trace managed by
 * the JVM. This exception carries no additional fields beyond what {@link Exception} provides, so
 * callers should rely on the detail message (when present) and the cause chain to convey parse
 * context.
 *
 * <p><b>Notable behaviors</b>
 *
 * <ul>
 *   <li>Represents input-shape problems (parse/convert failures) rather than downstream I/O or
 *       lookup failures.
 *   <li>Does not attempt recovery; callers decide whether to reject, sanitize, or fallback to a
 *       default.
 * </ul>
 */
public class IPConverterParseException extends Exception {
  /** Serialization identifier preserved for compatibility with prior builds of this exception. */
  @Serial private static final long serialVersionUID = 8465371657927636643L;

  /**
   * Creates a new exception without a detail message or a cause.
   *
   * <p>This constructor exists to explicitly document the default constructor for doclint. The
   * resulting instance has a {@code null} detail message and a {@code null} cause, and it is
   * otherwise equivalent to the compiler-generated no-argument constructor that would be provided
   * for this class.
   *
   * <p>Use this constructor when the call site already has an out-of-band mechanism to report parse
   * context (for example, returning a structured error response to an HTTP client) and the
   * exception itself is only used as a control-flow signal to abort the conversion.
   */
  public IPConverterParseException() {
    super();
  }
}

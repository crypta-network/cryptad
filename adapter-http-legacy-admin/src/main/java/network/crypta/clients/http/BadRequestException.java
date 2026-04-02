package network.crypta.clients.http;

import java.io.Serial;

/**
 * Signals that a request cannot be processed by a toadlet because required input is malformed or
 * missing.
 *
 * <p>This exception is thrown by HTTP-facing components when they detect client-side faults such as
 * absent query parameters, unreadable payloads, or unsupported encodings. It lets callers abort
 * processing early while retaining the specific part of the request that failed validation for
 * logging or error reporting. The class is mutable only through construction; once created, the
 * {@link #getInvalidRequestPart()} value remains stable, making instances safe to propagate across
 * threads for diagnostic purposes. Typical usage involves catching this exception at the toadlet
 * boundary, returning an HTTP 400 response, and including a human-friendly description derived from
 * the message or invalid component reference.
 *
 * <ul>
 *   <li><strong>Scope:</strong> Represents client errors only; server-side faults should use other
 *       exception types.
 *   <li><strong>Stability:</strong> Captures the failing request fragment for consistent reporting
 *       and logging.
 *   <li><strong>Thread-safety:</strong> Immutable after construction, allowing reuse across threads
 *       without synchronization.
 * </ul>
 *
 * @see #getInvalidRequestPart()
 */
public class BadRequestException extends Exception {
  @Serial private static final long serialVersionUID = 1L;

  /**
   * Name or description of the request fragment that failed validation and triggered this
   * exception, typically a parameter, header, or body section identifier.
   */
  private final String invalidRequestPart;

  /**
   * Creates an exception describing a bad request and the part that failed validation.
   *
   * <p>Use this constructor when no additional explanatory message is available beyond the
   * problematic request fragment. The stored request part should be concise, such as a parameter
   * name or header key, to aid error responses and logs.
   *
   * @param invalidRequestPart identifier for the malformed or missing portion of the request; may
   *     be {@code null} when the failing element cannot be isolated.
   */
  public BadRequestException(String invalidRequestPart) {
    this.invalidRequestPart = invalidRequestPart;
  }

  /**
   * Creates an exception with a detail message describing why the request is invalid.
   *
   * <p>The message should be suitable for operator logs or sanitized error responses. Include
   * contextual hints such as expected formats or missing keys when safe to expose.
   *
   * @param invalidRequestPart identifier for the malformed or missing portion of the request; may
   *     be {@code null} when unavailable or not applicable.
   * @param message human-readable detail explaining the validation failure; callers should avoid
   *     embedding sensitive request contents.
   */
  @SuppressWarnings("unused")
  public BadRequestException(String invalidRequestPart, String message) {
    super(message);
    this.invalidRequestPart = invalidRequestPart;
  }

  /**
   * Creates an exception that wraps a root cause while identifying the invalid request portion.
   *
   * <p>Use this overload when a downstream component throws an exception while parsing or
   * validating input, and the higher layer wants to mark the request as bad while retaining the
   * causal stack trace.
   *
   * @param invalidRequestPart identifier for the malformed or missing portion of the request; may
   *     be {@code null} when the failing element cannot be isolated.
   * @param cause originating exception encountered during request parsing or validation; may be
   *     {@code null} when no underlying throwable exists.
   */
  public BadRequestException(String invalidRequestPart, Throwable cause) {
    super(cause);
    this.invalidRequestPart = invalidRequestPart;
  }

  /**
   * Creates an exception with both a descriptive message and a root cause for invalid requests.
   *
   * <p>This overload is useful when callers need to surface a concise message to clients while
   * still preserving the original exception for logging or debugging. The message should focus on
   * client-actionable guidance, whereas the cause may contain lower-level parsing details.
   *
   * @param invalidRequestPart identifier for the malformed or missing portion of the request; may
   *     be {@code null} if the problematic fragment is unknown.
   * @param message explanatory text describing why the request is considered bad; keep sensitive
   *     data out of this string when it might reach clients.
   * @param cause underlying throwable that triggered the bad request determination; may be {@code
   *     null} when no specific cause is available.
   */
  @SuppressWarnings("unused")
  public BadRequestException(String invalidRequestPart, String message, Throwable cause) {
    super(message, cause);
    this.invalidRequestPart = invalidRequestPart;
  }

  /**
   * Returns the portion of the request that failed validation or was missing.
   *
   * <p>The value typically names a query parameter, form field, header, or body segment that
   * triggered the exception. Implementations do not modify this value after construction, making it
   * safe to cache or include in structured error payloads.
   *
   * @return identifier of the malformed or absent request fragment, or {@code null} if no precise
   *     part could be determined.
   */
  public String getInvalidRequestPart() {
    return invalidRequestPart;
  }
}

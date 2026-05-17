package network.crypta.runtime.spi;

import java.io.Serial;
import java.util.Objects;

/**
 * Checked exception for bounded runtime content fetch failures.
 *
 * <p>The {@linkplain #errorCode() error code} is the stable programmatic contract. Messages are for
 * logs and user-facing mapping context and may include implementation-specific detail.
 *
 * <p>This type belongs to the JDK-only runtime SPI. It deliberately uses strings rather than daemon
 * fetch enums so platform modules can map failures without depending on runtime-node classes. Code
 * that catches this exception should branch on {@link #errorCode()} and treat {@link #getMessage()}
 * as diagnostic text only. The message can be shown after normal UI sanitization, but it is not
 * part of the compatibility contract.
 */
public class ContentFetchException extends Exception {
  /** Serialization identifier for the checked exception type. */
  @Serial private static final long serialVersionUID = 1L;

  /**
   * Fetch could not complete successfully for a runtime or network reason.
   *
   * <p>Use this code when a bounded request is syntactically valid but the runtime cannot return
   * bytes: content is unavailable, fetch state fails, or the implementation cannot read the fetched
   * payload.
   */
  public static final String CATALOG_FETCH_FAILED = "catalog_fetch_failed";

  /**
   * Fetch produced content beyond the caller-supplied byte bound.
   *
   * <p>Use this code only for explicit size-limit failures after a syntactically valid request has
   * started. Generic fetch failures, redirect exhaustion, and retry-limit failures should keep
   * using {@link #CATALOG_FETCH_FAILED}.
   */
  public static final String CATALOG_FETCH_TOO_LARGE = "catalog_fetch_too_large";

  /**
   * Fetch did not complete before the caller-supplied timeout.
   *
   * <p>Callers can map this separately from generic failures when they want UI text or retry
   * behavior to distinguish slow content retrieval from permanent fetch errors.
   */
  public static final String CATALOG_FETCH_TIMEOUT = "catalog_fetch_timeout";

  /**
   * Caller supplied a URI that the runtime fetch implementation cannot parse or use.
   *
   * <p>The runtime implementation should use this code before starting a fetch when the URI string
   * is malformed or unsupported for that implementation.
   */
  public static final String INVALID_CATALOG_SOURCE = "invalid_catalog_source";

  /** Stable machine-readable code used by callers for API and UI mapping. */
  private final String errorCode;

  /**
   * Creates a fetch exception with a stable error code and detail message.
   *
   * <p>The constructor validates only the error code. The human-readable message follows normal
   * {@link Exception} behavior and should be written by callers as short diagnostic text.
   *
   * @param errorCode stable machine-readable error code; must be nonblank and single-line
   * @param message human-readable detail message
   */
  public ContentFetchException(String errorCode, String message) {
    super(message);
    this.errorCode = validateErrorCode(errorCode);
  }

  /**
   * Creates a fetch exception with a stable error code, detail message, and cause.
   *
   * <p>Use this overload when retaining a lower-level failure helps logs or callers that inspect
   * suppressed/causal chains. The stable error code remains the primary contract for API mapping.
   *
   * @param errorCode stable machine-readable error code; must be nonblank and single-line
   * @param message human-readable detail message
   * @param cause underlying failure retained for diagnostics
   */
  public ContentFetchException(String errorCode, String message, Throwable cause) {
    super(message, cause);
    this.errorCode = validateErrorCode(errorCode);
  }

  /**
   * Returns the stable machine-readable failure code.
   *
   * @return stable error code such as {@link #CATALOG_FETCH_FAILED}
   */
  public String errorCode() {
    return errorCode;
  }

  /**
   * Validates one stable error-code token.
   *
   * @param errorCode raw error-code text supplied by the throwing implementation
   * @return validated nonblank single-line error code
   */
  private static String validateErrorCode(String errorCode) {
    Objects.requireNonNull(errorCode, "errorCode");
    if (errorCode.isBlank()) {
      throw new IllegalArgumentException("errorCode must be nonblank");
    }
    if (errorCode.indexOf('\n') >= 0 || errorCode.indexOf('\r') >= 0) {
      throw new IllegalArgumentException("errorCode must be single-line");
    }
    return errorCode;
  }
}

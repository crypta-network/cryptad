package network.crypta.runtime.spi;

import java.time.Duration;
import java.util.Objects;

/**
 * Detached request for a bounded runtime content fetch.
 *
 * <p>The record deliberately carries only JDK-level values so callers can request content without
 * depending on daemon URI or fetch types. The {@code purpose} value is a caller-supplied diagnostic
 * label, not a policy selector; implementations may include it in logs and exception messages.
 * Callers should keep it short, stable, and free of secrets because it can appear in failure text.
 *
 * <p>Every request must define both a byte limit and a timeout. Implementations are expected to
 * apply the byte limit before returning materialized bytes and to stop waiting when the timeout
 * expires. The SPI does not prescribe URI syntax; a runtime implementation may accept Crypta keys,
 * content-addressed URIs, or other node-owned fetch locations and should report unsupported values
 * through {@link ContentFetchException#INVALID_CATALOG_SOURCE}.
 *
 * @param uri content URI string to fetch; must be nonblank and single-line
 * @param maxBytes maximum number of payload bytes the caller is willing to materialize
 * @param timeout maximum wall-clock wait for this fetch
 * @param purpose nonblank single-line diagnostic label for the caller's use case
 */
public record BoundedContentFetchRequest(
    String uri, long maxBytes, Duration timeout, String purpose) {
  /**
   * Creates a validated bounded content fetch request.
   *
   * <p>Validation is intentionally limited to transport-neutral constraints. The URI is required to
   * be a single-line nonblank string, but runtime-specific parsing remains the implementation's
   * responsibility. The byte and timeout bounds must be positive so a request can never mean
   * "unbounded" by accident.
   *
   * @throws NullPointerException if {@code uri}, {@code timeout}, or {@code purpose} is {@code
   *     null}
   * @throws IllegalArgumentException if a text value is blank or multi-line, {@code maxBytes} is
   *     not positive, or {@code timeout} is not positive
   */
  public BoundedContentFetchRequest {
    requireSingleLineText(uri, "uri");
    if (maxBytes <= 0) {
      throw new IllegalArgumentException("maxBytes must be positive");
    }
    Objects.requireNonNull(timeout, "timeout");
    if (timeout.isZero() || timeout.isNegative()) {
      throw new IllegalArgumentException("timeout must be positive");
    }
    requireSingleLineText(purpose, "purpose");
  }

  /**
   * Returns a diagnostic representation without echoing the content URI.
   *
   * <p>App-facing callers may receive user-supplied Crypta keys through this SPI. Logging the raw
   * URI or purpose can leak request paths, query-like tokens, or private local test fixtures, so
   * this representation keeps only bounds and diagnostic label length metadata.
   *
   * @return redacted request summary suitable for generic diagnostics
   */
  @SuppressWarnings("NullableProblems")
  @Override
  public String toString() {
    return "BoundedContentFetchRequest[uri=<redacted>, maxBytes="
        + maxBytes
        + ", timeout="
        + timeout
        + ", purposeLength="
        + purpose.length()
        + ']';
  }

  /**
   * Validates a request text field that may be copied into diagnostics.
   *
   * @param value raw text value to validate
   * @param name field name used in exception messages
   */
  private static void requireSingleLineText(String value, String name) {
    Objects.requireNonNull(value, name);
    if (value.isBlank()) {
      throw new IllegalArgumentException(name + " must be nonblank");
    }
    if (value.indexOf('\n') >= 0 || value.indexOf('\r') >= 0) {
      throw new IllegalArgumentException(name + " must be single-line");
    }
  }
}

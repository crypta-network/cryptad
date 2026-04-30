package network.crypta.runtime.spi;

import java.util.Arrays;
import java.util.Objects;

/**
 * Detached result for a bounded runtime content fetch.
 *
 * <p>The payload is defensively copied on construction and on access so callers can retain or
 * mutate the returned array without affecting the stored result. {@code resolvedUri} and {@code
 * statusMessage} are optional diagnostic values and may be {@code null}.
 *
 * <p>The result is intentionally a small in-memory value. Implementations should only create it
 * after they have enforced the caller's byte bound and released any runtime-owned temporary
 * storage. The {@code requestedUri} echoes the caller input for correlation, while {@code
 * resolvedUri} can report transport-specific resolution such as a newer USK edition. Neither field
 * is a trust signal for catalog or bundle verification.
 */
public final class BoundedContentFetchResult {
  private static final String REQUESTED_URI_FIELD = "requestedUri";

  private final byte[] bytes;
  private final String requestedUri;
  private final String resolvedUri;
  private final String statusMessage;
  private final int bytesLength;

  /**
   * Creates a detached fetch result.
   *
   * <p>All textual diagnostics are constrained to a single line so higher layers can safely place
   * them in logs, JSON fields, or source metadata without preserving arbitrary line breaks.
   * Optional fields may be {@code null}; when present they must be nonblank.
   *
   * @param bytes fetched content bytes; copied defensively
   * @param requestedUri original URI string requested by the caller; must be nonblank and
   *     single-line
   * @param resolvedUri final URI string reported by the implementation, or {@code null} when not
   *     available
   * @param statusMessage optional human-readable status text, or {@code null}
   * @throws NullPointerException if {@code bytes} or {@code requestedUri} is {@code null}
   * @throws IllegalArgumentException if a URI/status text value is blank where not nullable, or
   *     multi-line
   */
  public BoundedContentFetchResult(
      byte[] bytes, String requestedUri, String resolvedUri, String statusMessage) {
    this.bytes = Objects.requireNonNull(bytes, "bytes").clone();
    this.bytesLength = this.bytes.length;
    requireRequestedUri(requestedUri);
    requireNullableSingleLineText(resolvedUri, "resolvedUri");
    requireNullableSingleLineText(statusMessage, "statusMessage");
    this.requestedUri = requestedUri;
    this.resolvedUri = resolvedUri;
    this.statusMessage = statusMessage;
  }

  /**
   * Returns a defensive copy of the fetched bytes.
   *
   * @return copied payload bytes that the caller can mutate safely
   */
  public byte[] bytes() {
    return bytes.clone();
  }

  /**
   * Returns the URI originally requested by the caller.
   *
   * <p>This value is retained for diagnostics and correlation only. Catalog and bundle authenticity
   * must still be established by the signed catalog, artifact digest, and signed bundle
   * verification layers.
   *
   * @return original nonblank single-line URI string
   */
  public String requestedUri() {
    return requestedUri;
  }

  /**
   * Returns the final URI reported by the runtime fetch implementation.
   *
   * <p>Mutable Crypta keys such as USKs may resolve to a newer concrete edition. Implementations
   * that cannot provide a resolved value leave this field {@code null}.
   *
   * @return resolved URI string, or {@code null} when unavailable
   */
  public String resolvedUri() {
    return resolvedUri;
  }

  /**
   * Returns optional transport status text from the runtime fetch implementation.
   *
   * <p>The message is a bounded single-line diagnostic for operator display or logs. Callers must
   * not parse it for policy decisions.
   *
   * @return status message, or {@code null} when no message was supplied
   */
  public String statusMessage() {
    return statusMessage;
  }

  /**
   * Compares two detached fetch results by payload bytes and diagnostic fields.
   *
   * @param obj candidate object to compare
   * @return {@code true} when the payload and all diagnostic fields are equal
   */
  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (!(obj instanceof BoundedContentFetchResult other)) {
      return false;
    }
    return Arrays.equals(bytes, other.bytes)
        && Objects.equals(requestedUri, other.requestedUri)
        && Objects.equals(resolvedUri, other.resolvedUri)
        && Objects.equals(statusMessage, other.statusMessage);
  }

  /**
   * Returns a hash derived from the payload bytes and diagnostic fields.
   *
   * @return hash code consistent with {@link #equals(Object)}
   */
  @Override
  public int hashCode() {
    int result = Arrays.hashCode(bytes);
    result = 31 * result + Objects.hash(requestedUri, resolvedUri, statusMessage);
    return result;
  }

  /**
   * Returns a diagnostic representation without embedding the fetched payload.
   *
   * @return string containing the payload length and diagnostic fields
   */
  @Override
  public String toString() {
    return "BoundedContentFetchResult[bytesLength="
        + bytesLength
        + ", "
        + REQUESTED_URI_FIELD
        + "="
        + requestedUri
        + ", resolvedUri="
        + resolvedUri
        + ", statusMessage="
        + statusMessage
        + ']';
  }

  /**
   * Validates the required requested-URI diagnostic field.
   *
   * @param value raw requested URI text to validate
   */
  private static void requireRequestedUri(String value) {
    Objects.requireNonNull(value, REQUESTED_URI_FIELD);
    if (value.isBlank()) {
      throw new IllegalArgumentException(REQUESTED_URI_FIELD + " must be nonblank");
    }
    if (value.indexOf('\n') >= 0 || value.indexOf('\r') >= 0) {
      throw new IllegalArgumentException(REQUESTED_URI_FIELD + " must be single-line");
    }
  }

  /**
   * Validates an optional single-line diagnostic field.
   *
   * @param value optional text value to validate, or {@code null}
   * @param name field name used in exception messages
   */
  private static void requireNullableSingleLineText(String value, String name) {
    if (value == null) {
      return;
    }
    if (value.isBlank()) {
      throw new IllegalArgumentException(name + " must be nonblank when present");
    }
    if (value.indexOf('\n') >= 0 || value.indexOf('\r') >= 0) {
      throw new IllegalArgumentException(name + " must be single-line");
    }
  }
}

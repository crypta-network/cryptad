package network.crypta.keys;

import java.io.Serial;

/**
 * Signals a failure to decode a CHK (Content Hash Key) or CHK-encoded data.
 *
 * <p>This specialization of {@link KeyDecodeException} is used by code paths that parse or
 * reconstruct CHK-related entities (e.g., URIs, keys, or blocks) when the input is malformed,
 * truncated, uses an unsupported variant, or otherwise violates required invariants.
 *
 * @author amphibian
 */
public class CHKDecodeException extends KeyDecodeException {
  // Serialization identifier for binary compatibility of this exception type.
  @Serial private static final long serialVersionUID = -1;

  /**
   * Creates an exception with no detail message.
   *
   * <p>The cause is not initialized and may be set later via {@link Throwable#initCause}.
   */
  @SuppressWarnings("unused")
  public CHKDecodeException() {
    super();
  }

  /**
   * Creates an exception with the specified detail message.
   *
   * @param message human-readable description of the decode failure
   */
  public CHKDecodeException(String message) {
    super(message);
  }

  /**
   * Creates an exception with the specified detail message and cause.
   *
   * @param message human-readable description of the decode failure
   * @param cause the underlying reason; may be {@code null}
   */
  public CHKDecodeException(String message, Throwable cause) {
    super(message, cause);
  }

  /**
   * Creates an exception with the specified cause.
   *
   * <p>The detail message is set to {@code cause.toString()} if {@code cause} is not {@code null}.
   *
   * @param cause the underlying reason; may be {@code null}
   */
  @SuppressWarnings("unused")
  public CHKDecodeException(Throwable cause) {
    super(cause);
  }
}

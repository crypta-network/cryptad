package network.crypta.keys;

import java.io.Serial;

/**
 * Base exception indicating a failure to decode key-derived data or structures.
 *
 * <p>Decoding failures typically arise from malformed inputs, unsupported formats/variants,
 * truncated data, or violations of required invariants while reconstructing key-related entities
 * (for example, CHK/SSK URIs, keys, or blocks). Concrete subclasses such as {@link
 * CHKDecodeException} and {@link SSKDecodeException} provide additional context for specific key
 * types.
 */
public class KeyDecodeException extends Exception {
  // Serialization identifier for binary compatibility of this exception type.
  @Serial private static final long serialVersionUID = -1;

  /**
   * Creates an exception with the specified detail message.
   *
   * @param message human-readable description of the decode failure
   */
  public KeyDecodeException(String message) {
    super(message);
  }

  /**
   * Creates an exception with no detail message.
   *
   * <p>The cause is not initialized and may be set later via {@link Throwable#initCause}.
   */
  public KeyDecodeException() {
    super();
  }

  /**
   * Creates an exception with the specified detail message and cause.
   *
   * @param message human-readable description of the decode failure
   * @param cause the underlying reason; may be {@code null}
   */
  public KeyDecodeException(String message, Throwable cause) {
    super(message, cause);
  }

  /**
   * Creates an exception with the specified cause.
   *
   * <p>The detail message is set to {@code cause.toString()} if {@code cause} is not {@code null}.
   *
   * @param cause the underlying reason; may be {@code null}
   */
  public KeyDecodeException(Throwable cause) {
    super(cause);
  }
}

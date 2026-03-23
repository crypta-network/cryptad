package network.crypta.keys;

import java.io.Serial;

/**
 * Base exception indicating a failure to encode key-derived data or structures.
 *
 * <p>Encoding may fail due to inputs that exceed supported size limits, invalid parameters, or
 * unsupported formats/variants when constructing key-related entities (for example, CHK/SSK blocks
 * or URIs). Concrete subclasses such as {@link CHKEncodeException} and {@link SSKEncodeException}
 * provide key-type specific context.
 */
public class KeyEncodeException extends Exception {
  // Serialization identifier for binary compatibility of this exception type.
  @Serial private static final long serialVersionUID = -1;

  /**
   * Creates an exception with the specified detail message.
   *
   * @param string human-readable description of the encoding failure
   */
  public KeyEncodeException(String string) {
    super(string);
  }

  /**
   * Creates an exception with no detail message.
   *
   * <p>The cause is not initialized and may be set later via {@link Throwable#initCause}.
   */
  public KeyEncodeException() {
    super();
  }

  /**
   * Creates an exception with the specified detail message and cause.
   *
   * @param message human-readable description of the encoding failure
   * @param cause the underlying reason; may be {@code null}
   */
  public KeyEncodeException(String message, Throwable cause) {
    super(message, cause);
  }

  /**
   * Creates an exception with the specified cause.
   *
   * <p>The detail message is set to {@code cause.toString()} if {@code cause} is not {@code null}.
   *
   * @param cause the underlying reason; may be {@code null}
   */
  public KeyEncodeException(Throwable cause) {
    super(cause);
  }
}

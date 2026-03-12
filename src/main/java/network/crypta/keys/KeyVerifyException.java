package network.crypta.keys;

import java.io.Serial;

/**
 * Base exception indicating a failure to verify key-derived content or metadata.
 *
 * <p>Verification refers to integrity checks such as comparing computed hashes with expected
 * values, validating signatures, or confirming that decoded blocks match their associated keys.
 * Concrete specializations (for example, {@link CHKVerifyException} or {@link SSKVerifyException})
 * provide key-type specific context.
 */
public class KeyVerifyException extends Exception {
  // Serialization identifier for binary compatibility of this exception type.
  @Serial private static final long serialVersionUID = -1;

  /**
   * Creates an exception with the specified detail message.
   *
   * @param message human-readable description of the verification failure
   */
  public KeyVerifyException(String message) {
    super(message);
  }

  /**
   * Creates an exception with the specified detail message and cause.
   *
   * @param message human-readable description of the verification failure
   * @param cause the underlying reason; may be {@code null}
   */
  public KeyVerifyException(String message, Throwable cause) {
    super(message, cause);
  }

  /**
   * Creates an exception with no detail message.
   *
   * <p>The cause is not initialized and may be set later via {@link Throwable#initCause}.
   */
  public KeyVerifyException() {
    super();
  }

  /**
   * Creates an exception with the specified cause.
   *
   * <p>The detail message is set to {@code cause.toString()} if {@code cause} is not {@code null}.
   *
   * @param cause the underlying reason; may be {@code null}
   */
  public KeyVerifyException(Throwable cause) {
    super(cause);
  }
}

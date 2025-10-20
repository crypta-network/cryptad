package network.crypta.keys;

import java.io.Serial;

/**
 * Signals a failure to verify CHK (Content Hash Key) data.
 *
 * <p>This specialization of {@link KeyVerifyException} is thrown when decoded content or metadata
 * does not match the expected CHK (for example, a hash mismatch or corrupted block). It indicates
 * that decoding may have succeeded, but integrity checks failed.
 *
 * @author amphibian
 */
public class CHKVerifyException extends KeyVerifyException {
  // Serialization identifier for binary compatibility of this exception type.
  @Serial private static final long serialVersionUID = -1;

  /**
   * Creates an exception with no detail message.
   *
   * <p>The cause is not initialized and may be set later via {@link Throwable#initCause}.
   */
  public CHKVerifyException() {
    super();
  }

  /**
   * Creates an exception with the specified detail message.
   *
   * @param message human-readable description of the verification failure
   */
  public CHKVerifyException(String message) {
    super(message);
  }

  /**
   * Creates an exception with the specified detail message and cause.
   *
   * @param message human-readable description of the verification failure
   * @param cause the underlying reason; may be {@code null}
   */
  public CHKVerifyException(String message, Throwable cause) {
    super(message, cause);
  }

  /**
   * Creates an exception with the specified cause.
   *
   * <p>The detail message is set to {@code cause.toString()} if {@code cause} is not {@code null}.
   *
   * @param cause the underlying reason; may be {@code null}
   */
  public CHKVerifyException(Throwable cause) {
    super(cause);
  }
}

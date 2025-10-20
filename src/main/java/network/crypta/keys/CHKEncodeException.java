package network.crypta.keys;

import java.io.Serial;

/**
 * Signals a failure to encode CHK (Content Hash Key) data.
 *
 * <p>This specialization of {@link KeyEncodeException} is thrown by code that constructs
 * CHK-related entities (e.g., blocks or URIs) when an encoding precondition is not met. Typical
 * causes include inputs that exceed supported size limits, invalid parameters, or unsupported
 * variants.
 *
 * @author amphibian
 */
public class CHKEncodeException extends KeyEncodeException {
  // Serialization identifier for binary compatibility of this exception type.
  @Serial private static final long serialVersionUID = -1;

  /**
   * Creates an exception with no detail message.
   *
   * <p>The cause is not initialized and may be set later via {@link Throwable#initCause}.
   */
  public CHKEncodeException() {
    super();
  }

  /**
   * Creates an exception with the specified detail message.
   *
   * @param message human-readable description of the encoding failure
   */
  public CHKEncodeException(String message) {
    super(message);
  }

  /**
   * Creates an exception with the specified detail message and cause.
   *
   * @param message human-readable description of the encoding failure
   * @param cause the underlying reason; may be {@code null}
   */
  public CHKEncodeException(String message, Throwable cause) {
    super(message, cause);
  }

  /**
   * Creates an exception with the specified cause.
   *
   * <p>The detail message is set to {@code cause.toString()} if {@code cause} is not {@code null}.
   *
   * @param cause the underlying reason; may be {@code null}
   */
  public CHKEncodeException(Throwable cause) {
    super(cause);
  }
}

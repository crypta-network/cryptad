package network.crypta.io.comm;

import java.io.Serial;

/**
 * Exception indicating that verification of a reference signature failed.
 *
 * <p>This exception is thrown when a cryptographic signature associated with a reference cannot be
 * validated. Callers should treat this as an authentication failure and ignore or discard the
 * unverified data.
 *
 * @author amphibian
 */
public class ReferenceSignatureVerificationException extends Exception {
  @Serial private static final long serialVersionUID = -1;

  /**
   * Creates an instance that wraps the underlying cause.
   *
   * @param e the cause of the verification failure; may be {@code null}
   */
  public ReferenceSignatureVerificationException(Exception e) {
    super(e);
  }

  /** Creates an instance with no detail message or cause. */
  public ReferenceSignatureVerificationException() {
    super();
  }

  /**
   * Creates an instance with the specified detail message.
   *
   * @param string the detail message to include in this exception
   */
  public ReferenceSignatureVerificationException(String string) {
    super(string);
  }
}

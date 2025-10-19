package network.crypta.crypt;

import java.io.Serial;

/**
 * Thrown when a cipher algorithm, mode, or configuration is not supported by the current build or
 * available cryptographic providers.
 *
 * <p>This exception may be raised when parsing stored data that references a cipher the runtime
 * does not recognize, or when a caller requests an algorithm that is not enabled or compiled into
 * the node. Callers can inspect the message (when provided) for additional context.
 *
 * @see java.security.NoSuchAlgorithmException
 * @see javax.crypto.NoSuchPaddingException
 */
public class UnsupportedCipherException extends Exception {
  @Serial private static final long serialVersionUID = -1;

  /** Creates an exception with no detail message. */
  public UnsupportedCipherException() {}

  /**
   * Creates an exception with the provided detail message.
   *
   * @param s human-readable description of the unsupported cipher condition.
   */
  public UnsupportedCipherException(String s) {
    super(s);
  }
}

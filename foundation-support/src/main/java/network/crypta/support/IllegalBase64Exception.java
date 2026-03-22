package network.crypta.support;

import java.io.Serial;

/**
 * Signals that a Base64 input is malformed.
 *
 * <p>This checked exception indicates that a Base64-encoded string (or byte sequence) has an
 * illegal length or contains one or more characters not permitted by the Base64 alphabet. It may
 * also be used when padding is syntactically incorrect.
 *
 * <p>Usage: thrown by Base64 decoding utilities to report invalid input; callers should catch this
 * exception to surface a clear validation error or propagate it as appropriate. The instance is
 * immutable and carries only a human-readable description available via {@link #getMessage()}.
 *
 * <p>Thread-safety: immutable once constructed.
 *
 * @see java.util.Base64
 */
public class IllegalBase64Exception extends Exception {

  // Explicit serial version for consistent Java serialization.
  @Serial private static final long serialVersionUID = -1;

  /**
   * Creates a new instance with a detail message describing the Base64 validation failure.
   *
   * @param descr detail message used by {@link #getMessage()} to explain the reason.
   */
  public IllegalBase64Exception(String descr) {
    super(descr);
  }
}

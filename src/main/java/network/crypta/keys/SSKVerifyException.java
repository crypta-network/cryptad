package network.crypta.keys;

import java.io.Serial;

/**
 * Signals a failure to verify an SSK (Signed Subspace Key) or SSK-derived content.
 *
 * <p>This specialization of {@link KeyVerifyException} is thrown when decoded content or associated
 * metadata does not match the expected SSK, such as signature mismatches, corrupted blocks, or
 * inconsistent key parameters. It indicates that decoding may have succeeded, but integrity checks
 * failed.
 */
public class SSKVerifyException extends KeyVerifyException {
  // Serialization identifier for binary compatibility of this exception type.
  @Serial private static final long serialVersionUID = -1;

  /**
   * Creates an exception with the specified detail message.
   *
   * @param string human-readable description of the verification failure
   */
  public SSKVerifyException(String string) {
    super(string);
  }
}

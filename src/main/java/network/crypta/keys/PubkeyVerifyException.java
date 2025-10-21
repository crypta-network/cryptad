package network.crypta.keys;

import java.io.Serial;
import network.crypta.crypt.CryptFormatException;

/**
 * Indicates a failure to verify public-key related content or metadata.
 *
 * <p>Typical scenarios include invalid signatures, mismatched key material, or inconsistent
 * serialized formats discovered during verification. This is a specialization of {@link
 * KeyVerifyException} for public-key operations.
 */
public class PubkeyVerifyException extends KeyVerifyException {

  // Serialization identifier for binary compatibility of this exception type.
  @Serial private static final long serialVersionUID = 1L;

  /**
   * Creates an exception wrapping a low-level cryptographic formatting error.
   *
   * @param e the underlying formatting exception; may be {@code null}
   */
  public PubkeyVerifyException(CryptFormatException e) {
    super(e);
  }

  /**
   * Creates an exception with the specified detail message.
   *
   * @param msg human-readable description of the verification failure
   */
  public PubkeyVerifyException(String msg) {
    super(msg);
  }
}

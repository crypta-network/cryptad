package network.crypta.keys;

import java.io.Serial;

/**
 * Signals a failure to decode an SSK (Signed Subspace Key) or SSK-encoded data.
 *
 * <p>This specialization of {@link KeyDecodeException} is used by code that parses or reconstructs
 * SSK-related entities (for example, URIs, keys, or blocks) when the input is malformed, truncated,
 * uses an unsupported variant, or violates required invariants.
 */
public class SSKDecodeException extends KeyDecodeException {
  // Serialization identifier for binary compatibility of this exception type.
  @Serial private static final long serialVersionUID = -1;

  /**
   * Creates an exception with the specified detail message.
   *
   * @param string human-readable description of the decode failure
   */
  public SSKDecodeException(String string) {
    super(string);
  }
}

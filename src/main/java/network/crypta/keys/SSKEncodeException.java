package network.crypta.keys;

import java.io.Serial;

/**
 * Signals a failure to encode an SSK (Signed Subspace Key) or SSK-encoded data.
 *
 * <p>This specialization of {@link KeyEncodeException} is thrown when constructing SSK-related
 * entities (for example, blocks or URIs) fails due to invalid parameters, size limits, or
 * unsupported variants.
 */
public class SSKEncodeException extends KeyEncodeException {
  // Serialization identifier for binary compatibility of this exception type.
  @Serial private static final long serialVersionUID = -1;

  /**
   * Creates an exception with the specified detail message and cause.
   *
   * @param message human-readable description of the encoding failure
   * @param e the underlying encoding exception that triggered this failure; may be {@code null}
   */
  public SSKEncodeException(String message, KeyEncodeException e) {
    super(message, e);
  }
}

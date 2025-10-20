package network.crypta.keys;

import java.io.IOException;
import java.io.Serial;

/**
 * Indicates that an input exceeds the maximum supported size for the requested operation.
 *
 * <p>This exception is used for I/O or encoding/decoding paths that enforce upper bounds on content
 * or structure size. Callers may catch it to surface user-facing guidance (for example, asking to
 * reduce payload size or split data into smaller parts) or to select an alternative processing
 * strategy when available.
 */
public class TooBigException extends IOException {

  // Serialization identifier for binary compatibility of this exception type.
  @Serial private static final long serialVersionUID = 1L;

  /**
   * Creates an exception with the specified detail message.
   *
   * @param msg human-readable description of the size limit violation
   */
  public TooBigException(String msg) {
    super(msg);
  }
}

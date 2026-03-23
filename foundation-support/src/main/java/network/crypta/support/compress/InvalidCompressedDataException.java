package network.crypta.support.compress;

import java.io.IOException;
import java.io.Serial;

/**
 * Indicates that a compressed stream or buffer is malformed or internally inconsistent.
 *
 * <p>Codecs in this package throw this checked exception when the input cannot be interpreted as
 * valid compressed data. Typical causes include invalid header/properties, impossible or
 * unsupported dictionary sizes, truncated frames, or checksum mismatches. Callers should treat this
 * as a permanent data error rather than a transient I/O failure.
 *
 * <p>Thread-safety: instances are immutable and therefore safe to share across threads.
 *
 * @see TooBigDictionaryException
 */
public class InvalidCompressedDataException extends IOException {

  @Serial private static final long serialVersionUID = -1L;

  /** Creates an exception with no detail message. */
  public InvalidCompressedDataException() {
    super();
  }

  /**
   * Creates an exception with the provided detail message.
   *
   * @param msg human-readable description of the validation failure; may include codec-specific
   *     context such as the offending property or field
   */
  public InvalidCompressedDataException(String msg) {
    super(msg);
  }
}

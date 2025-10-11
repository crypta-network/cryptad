package network.crypta.support.compress;

import java.io.IOException;
import java.io.Serial;

/**
 * Signals that a write operation attempted to produce more output than the allowed maximum.
 *
 * <p>This checked exception is used by compression/decompression utilities to enforce
 * caller-specified output limits and to prevent unbounded growth of buffers or files. A common
 * source is a bounded {@link java.io.OutputStream} wrapper that counts bytes and throws when write
 * would exceed the configured limit.
 *
 * <p>Instances are immutable and therefore thread-safe.
 *
 * @see CompressionInputSizeException
 */
public class CompressionOutputSizeException extends IOException {

  @Serial private static final long serialVersionUID = -1;

  /**
   * Estimated number of bytes that would have been written when the limit was exceeded.
   *
   * <p>Units: bytes. The value may be {@code -1} when the size could not be determined precisely at
   * the throw site.
   */
  public final long estimatedSize;

  /**
   * Creates an exception with an unknown estimated size.
   *
   * <p>Use this when the violating write does not have an exact size available. The field {@link
   * #estimatedSize} is set to {@code -1}.
   */
  CompressionOutputSizeException() {
    this(-1);
  }

  /**
   * Creates an exception with the supplied estimated size in bytes.
   *
   * @param sz number of bytes that would have been written when the limit was reached; recorded in
   *     {@link #estimatedSize} and included in the message. Units: bytes.
   */
  CompressionOutputSizeException(long sz) {
    super("The output was too big for the buffer; estimated size: " + sz);
    estimatedSize = sz;
  }
}

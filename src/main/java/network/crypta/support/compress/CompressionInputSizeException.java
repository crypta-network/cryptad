package network.crypta.support.compress;

import java.io.IOException;
import java.io.Serial;

/**
 * Signals that an input source produced more data than the configured maximum.
 *
 * <p>This exception is used by compression/decompression utilities to enforce read budgets and
 * prevent unbounded memory usage. It is typically thrown by an {@link java.io.InputStream} wrapper
 * after it has already returned up to {@link #maxAllowed} bytes and detects that the underlying
 * stream still has more data beyond that limit.
 *
 * <p>Instances are immutable and therefore thread-safe.
 *
 * @see CompressionOutputSizeException
 */
public class CompressionInputSizeException extends IOException {

  @Serial private static final long serialVersionUID = -1L;

  /**
   * Maximum number of bytes permitted to be read before the input is considered oversized.
   *
   * <p>Units: bytes. The value is non-negative and corresponds to the caller-provided read limit
   * that triggered this exception.
   */
  public final long maxAllowed;

  /**
   * Creates a new exception with the supplied maximum allowed input size.
   *
   * @param maxAllowed maximum number of bytes permitted to be read before the exception is raised;
   *     the value is recorded in {@link #maxAllowed} and included in the message.
   */
  public CompressionInputSizeException(long maxAllowed) {
    super("The input exceeded the maximum allowed size: " + maxAllowed);
    this.maxAllowed = maxAllowed;
  }
}

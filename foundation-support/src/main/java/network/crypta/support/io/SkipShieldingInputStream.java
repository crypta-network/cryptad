package network.crypta.support.io;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import org.jetbrains.annotations.NotNull;

/**
 * InputStream wrapper whose {@link #skip(long)} is implemented via a single read into a shared
 * buffer.
 *
 * <p>Some {@link InputStream} implementations throw an exception from {@link
 * InputStream#skip(long)} (for example, {@link System#in}) when the stream is not seekable. For
 * such sources, callers must read and discard bytes instead of using {@code skip(long)}. This class
 * shields clients from those behaviors by overriding {@code skip(long)} to call {@link
 * #read(byte[], int, int)} once with a shared scratch buffer and returning the number of bytes
 * actually read.
 *
 * <p>Notes and limitations:
 *
 * <ul>
 *   <li>Each call to {@code skip(long)} performs at most one blocking read of up to 8 KiB (the size
 *       of the internal buffer), regardless of the requested amount. Callers that need to skip more
 *       than that should invoke {@code skip} in a loop and accumulate the result.
 *   <li>Negative {@code n} values result in {@code 0} and do not access the underlying stream.
 *   <li>At end-of-stream, {@code skip} returns {@code 0} (because {@code read(...)} returns {@code
 *       -1}).
 *   <li>The internal buffer is shared and used only for discarding data, so sharing is safe.
 *   <li>Thread-safety: instances are not thread-safe unless the wrapped stream is and callers
 *       ensure external synchronization.
 * </ul>
 *
 * @since 1.17
 */
public class SkipShieldingInputStream extends FilterInputStream {
  private static final int SKIP_BUFFER_SIZE = 8192;
  // Shared scratch buffer for skip(); safe because read bytes are discarded.
  private static final byte[] SKIP_BUFFER = new byte[SKIP_BUFFER_SIZE];

  /**
   * Creates a new wrapper around the given stream.
   *
   * <p>Precondition: {@code in} should not be {@code null}. Passing {@code null} will result in a
   * {@link NullPointerException} upon use.
   *
   * @param in the stream to wrap; not {@code null}
   */
  public SkipShieldingInputStream(InputStream in) {
    super(in);
  }

  /**
   * Reads bytes into the provided buffer by delegating directly to the wrapped stream.
   *
   * @param b the destination buffer; must not be {@code null}
   * @param off the start offset in {@code b}
   * @param len the maximum number of bytes to read
   * @return the number of bytes read, or {@code -1} if the end of the stream has been reached
   * @throws IOException if an I/O error occurs in the underlying stream
   */
  @Override
  public int read(byte @NotNull [] b, int off, int len) throws IOException {
    // Delegate directly to the wrapped stream for efficient bulk reads.
    return in.read(b, off, len);
  }

  /**
   * Skips (discards) up to {@code n} bytes by reading into an internal buffer once.
   *
   * <p>This method never calls the wrapped stream's {@link InputStream#skip(long)}. Instead, it
   * invokes {@link #read(byte[], int, int)} with a shared 8 KiB buffer and returns the number of
   * bytes read. The actual number of discarded bytes is therefore {@code min(max(0, n), 8192)} or
   * {@code 0} at end-of-stream.
   *
   * <p>To skip more than 8 KiB, call this method in a loop and accumulate the result until it
   * returns {@code 0} or the target count is reached.
   *
   * @param n the requested number of bytes to skip; negative values cause this method to return
   *     {@code 0} without I/O
   * @return the number of bytes actually skipped (discarded), never negative
   * @throws IOException if an I/O error occurs while reading from the underlying stream
   */
  @Override
  public long skip(long n) throws IOException {
    int retval;
    if (n < 0) {
      retval = 0;
    } else {
      retval = read(SKIP_BUFFER, 0, (int) Math.min(n, SKIP_BUFFER_SIZE));
      if (retval < 0) {
        retval = 0;
      }
    }
    return retval;
  }
}

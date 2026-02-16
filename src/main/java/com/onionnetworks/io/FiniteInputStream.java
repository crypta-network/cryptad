package com.onionnetworks.io;

import java.io.EOFException;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import org.jetbrains.annotations.NotNull;

/**
 * Fixed-length {@link InputStream} wrapper that exposes only a bounded slice of a parent stream.
 *
 * <p>This stream enforces a byte budget supplied at construction time, allowing callers to treat a
 * shared multiplexed stream as a sequence of independent finite segments. It keeps internal state
 * of remaining bytes and stops returning data once the limit reaches zero, while optionally
 * allowing the underlying stream to continue serving subsequent consumers. Closing this wrapper
 * closes the parent stream; leaving it open lets callers advance the parent manually after the
 * bounded read completes.
 *
 * <p>Typical usage reads or skips exactly the advertised payload length when parsing framed
 * messages, attachments, or encrypted blobs whose size is known up front. The class is not
 * thread-safe; each instance should be confined to a single reader. Read and skip operations
 * decrement the remaining byte counter atomically relative to this instance and will raise an
 * {@link java.io.EOFException} if the parent stream ends before the limit is satisfied.
 *
 * <ul>
 *   <li>Enforces a strict byte quota with predictable EOF semantics.
 *   <li>Allows continued access to the parent stream after the quota is consumed.
 *   <li>Prefers clarity over buffering: no additional buffering is added beyond the parent.
 * </ul>
 */
public final class FiniteInputStream extends FilterInputStream {

  /**
   * Remaining byte budget, in bytes, still permitted to flow through this view. Updated after every
   * successful read or skip, this value should never become negative and mirrors the quota
   * originally supplied to the constructor. State is local to the instance and is not synchronized
   * for cross-thread visibility.
   */
  long left;

  /**
   * Create a new bounded view onto an existing stream.
   *
   * <p>The wrapper maintains its own counter of bytes remaining and enforces an immediate end of
   * stream once the quota is depleted. Passing a null stream triggers a {@link
   * NullPointerException}; a negative {@code count} triggers an {@link IllegalArgumentException}.
   * If {@code count} is zero, reads immediately return {@code -1} while leaving the parent stream
   * untouched for subsequent consumers.
   *
   * @param is the parent {@link InputStream} that supplies bytes; must not be {@code null}.
   * @param count total number of bytes this wrapper will expose before reporting end of stream.
   * @throws NullPointerException if {@code is} is {@code null}.
   * @throws IllegalArgumentException if {@code count} is negative.
   */
  public FiniteInputStream(InputStream is, long count) {
    super(is);
    if (is == null) {
      throw new NullPointerException();
    }
    if (count < 0) {
      throw new IllegalArgumentException("count must be > 0");
    }
    left = count;
  }

  /**
   * Reads a single byte while honoring the configured byte budget.
   *
   * <p>The method delegates to {@link #read(byte[], int, int)} so it inherits the same
   * end-of-stream and early-EOF semantics. Once the remaining byte count reaches zero, this method
   * returns {@code -1} immediately. If the parent stream ends prematurely, the propagated {@link
   * EOFException} surfaces through the declared {@link IOException}.
   *
   * @return unsigned byte value in the range {@code 0..255}, or {@code -1} when the quota is
   *     exhausted.
   * @throws IOException if an I/O error occurs or the parent stream ends before the quota is met.
   */
  @Override
  public int read() throws IOException {
    byte[] b = new byte[1];
    if (read(b, 0, 1) == -1) {
      return -1;
    }
    return b[0] & 0xFF;
  }

  /**
   * Reads up to {@code len} bytes into the provided buffer without exceeding the remaining quota.
   *
   * <p>The method truncates the requested length to the current {@code left} value so that callers
   * never consume more than the advertised finite segment. When no bytes remain, it returns {@code
   * -1}. If the underlying stream signals end-of-file before the quota is satisfied, an {@link
   * EOFException} is thrown to highlight the truncated payload. Successful reads decrement the
   * internal counter by the number of bytes delivered.
   *
   * @param b destination buffer that receives the data; must be writable at the specified range.
   * @param off zero-based offset in {@code b} where bytes are written; must be within bounds.
   * @param len requested maximum number of bytes to read; values above the remaining quota are
   *     clamped.
   * @return number of bytes read into {@code b}, or {@code -1} when the quota reaches zero before
   *     the call.
   * @throws EOFException if the parent stream ends before the requested finite section is fully
   *     consumed.
   * @throws IOException if an I/O error occurs while reading from the underlying stream.
   */
  @Override
  public int read(byte @NotNull [] b, int off, int len) throws IOException {
    // check the len so that a 0 len returns a 0 result
    if (left == 0 && len > 0) {
      return -1;
    }

    // trunc the read if they want more than is left.
    // FIX unit test the LONG
    // The (int) cast is safe because len is an int and thus left will not
    // return if it would overflow an int.
    int c = in.read(b, off, (int) Math.min(len, left));
    if (c < 0) {
      throw new EOFException();
    }
    left -= c;
    return c;
  }

  /**
   * Skips up to {@code n} bytes while decrementing the remaining quota accordingly.
   *
   * <p>The skip length is clamped to the number of bytes still available so that the quota is never
   * exceeded. The returned value reflects the actual number of bytes skipped, which may be smaller
   * when the parent stream cannot advance as far as requested. The internal counter tracks the
   * skipped amount exactly, keeping subsequent reads in sync with the finite view.
   *
   * @param n maximum number of bytes to skip; negative values are treated as zero by the underlying
   *     stream.
   * @return actual number of bytes skipped, never exceeding the remaining quota at call time.
   * @throws IOException if the underlying stream reports an I/O error during the skip operation.
   */
  @Override
  public long skip(long n) throws IOException {
    long result = in.skip(Math.min(n, left));
    left -= result;
    return result;
  }

  /**
   * Reports the number of bytes that can be read without blocking, bounded by the remaining quota.
   *
   * <p>The returned value is the smaller of the parent stream's {@link InputStream#available()}
   * result and the remaining byte budget, ensuring callers do not assume access beyond the finite
   * segment. The value may change with subsequent reads or skips and should be treated as an
   * estimate.
   *
   * @return non-negative byte count that can be read immediately, limited by the quota.
   * @throws IOException if the underlying stream cannot report availability due to an I/O issue.
   */
  @Override
  public int available() throws IOException {
    // (int) cast is safe because in.available must be an int and thus
    // smaller than overflow.
    return (int) Math.min(in.available(), left);
  }
}

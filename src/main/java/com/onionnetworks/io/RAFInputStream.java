package com.onionnetworks.io;

import java.io.*;
import org.jetbrains.annotations.NotNull;

/**
 * InputStream view over a seekable {@link RAF} instance.
 *
 * <p>This stream adapts a random-access file abstraction to the {@link InputStream} contract so
 * callers can consume data with familiar streaming methods while the underlying storage remains
 * addressable by absolute position. It tracks a private cursor (`pos`) that advances only when a
 * read completes successfully, and it never performs writes or resizes the backing file. The stream
 * neither owns nor closes the provided {@link RAF}; closing this wrapper simply marks the adapter
 * unusable so subsequent reads throw {@link EOFException}.
 *
 * <p>Typical usage is to hand an already-positioned {@link RAF} to this class and then issue
 * sequential reads via {@link #read()}, {@link #read(byte[], int, int)}, or {@link #skip(long)}.
 * The implementation clamps skips so the cursor never moves past the current end of file, making it
 * safe to use with dynamically growing data where the caller wants a conservative view. Instances
 * are not thread-safe; callers should synchronize externally if multiple threads might share the
 * same adapter or its backing {@link RAF}.
 *
 * <ul>
 *   <li>Maintains its own offset without mutating external state on the {@link RAF}.
 *   <li>Ignores negative skips and treats end-of-file as a hard boundary for cursor movement.
 *   <li>Delegates all byte retrieval to {@link RAF#seekAndRead(long, byte[], int, int)} to keep the
 *       cursor consistent with random-access semantics.
 * </ul>
 *
 * @see RAF
 * @see InputStream
 */
public class RAFInputStream extends InputStream {

  RAF raf;
  long pos;

  /**
   * Create a new adapter that reads sequentially from the given random-access file while preserving
   * the caller-managed file state.
   *
   * <p>The supplied {@link RAF} is not closed by this stream, and its existing file pointer or any
   * external locks are left untouched. The adapter starts reading from offset zero and advances its
   * internal cursor only after successful reads. Passing {@code null} yields a stream that behaves
   * as if it were already closed and will raise {@link EOFException} on read attempts.
   *
   * @param raf non-null random-access source that provides seek-and-read capabilities; ownership
   *     and lifecycle remain with the caller.
   */
  public RAFInputStream(RAF raf) {
    this.raf = raf;
  }

  /**
   * Read a single unsigned byte from the current cursor position.
   *
   * <p>This method delegates to {@link #read(byte[], int, int)} with a one-byte buffer, ensuring
   * the cursor advances by exactly one on success. If the adapter has been closed or the end of
   * file is reached, it returns {@code -1} without altering the cursor. The returned value is
   * promoted to an {@code int} in the range {@code 0..255} to match {@link InputStream}
   * conventions.
   *
   * @return next byte as an unsigned integer or {@code -1} when no more data is available or the
   *     stream has been closed.
   * @throws IOException if an I/O failure occurs during delegation to the underlying {@link RAF}.
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
   * Read up to {@code len} bytes into the target buffer starting at {@code off}.
   *
   * <p>Data is retrieved by calling {@link RAF#seekAndRead(long, byte[], int, int)} at the current
   * cursor. When at least one byte is obtained, the cursor advances by the exact count read; when
   * {@code -1} is returned, the cursor stays unchanged and the caller can treat it as end-of-file.
   * Negative lengths or offsets are not validated here; callers must supply ranges that fit the
   * destination array.
   *
   * @param b destination array that must be non-null and large enough for {@code off + len} bytes.
   * @param off zero-based index within {@code b} at which bytes begin to be written.
   * @param len maximum number of bytes to attempt; zero yields an immediate {@code 0} result.
   * @return number of bytes copied (may be less than {@code len}) or {@code -1} when no more data
   *     can be read because the adapter has been closed or the end of file is reached.
   * @throws EOFException if the adapter has been closed and cannot provide further data.
   * @throws IOException if the underlying {@link RAF} signals a read failure or range error.
   */
  @Override
  public int read(byte @NotNull [] b, int off, int len) throws IOException {
    if (raf == null) {
      throw new EOFException();
    }
    int c = raf.seekAndRead(pos, b, off, len);
    if (c >= 0) {
      pos += c;
    }
    return c;
  }

  /**
   * Advance the cursor by at most {@code n} bytes without reading data.
   *
   * <p>Skipping is bounded to the current file length so callers never observe the cursor
   * surpassing the effective end of file. Negative skip requests are ignored and return {@code 0}.
   * A positive skip that would overshoot the file length is truncated to the number of remaining
   * bytes, making the operation idempotent at EOF.
   *
   * @param n number of bytes to attempt to skip; negative values are treated as zero.
   * @return actual number of bytes the cursor advanced, never negative and never exceeding
   *     remaining bytes in the file.
   * @throws IOException if querying the underlying {@link RAF#length()} fails.
   */
  @Override
  public long skip(long n) throws IOException {
    // don't skip if n < 0
    if (n > 0) {
      // don't skip beyond the EOF
      long result = Math.min(raf.length(), pos + n) - pos;
      pos += result;
      return result;
    }
    return 0;
  }

  /**
   * Mark this adapter as closed without touching the underlying {@link RAF}.
   *
   * <p>Closing sets the internal reference to {@code null}, causing subsequent reads to throw
   * {@link EOFException} and skips to behave as if end-of-file were reached. The backing {@link
   * RAF} remains open so callers that own it may continue to use it directly or wrap it again. This
   * method is idempotent and safe to call multiple times; after the first call it has no additional
   * effect.
   *
   * @throws IOException never thrown by this implementation but retained for {@link InputStream}
   *     compatibility.
   */
  @Override
  public void close() throws IOException {
    raf = null;
  }
}

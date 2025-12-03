package com.onionnetworks.io;

import java.io.EOFException;
import java.io.IOException;
import java.io.OutputStream;
import org.jetbrains.annotations.NotNull;

/**
 * OutputStream facade that writes sequentially to a backing {@link RAF} while keeping an internal
 * position cursor. It adapts random-access semantics to APIs that require an {@code OutputStream}
 * without assuming ownership of the underlying file handle.
 *
 * <p>Each write delegates to {@link RAF#seekAndWrite(long, byte[], int, int)} at the tracked
 * position and then advances that position by the number of bytes written. Closing this stream only
 * marks it as closed; it deliberately leaves the wrapped {@code RAF} open so callers remain in
 * control of lifecycle and can continue to reuse the file through other views.
 *
 * <p>The stream is stateful and not thread-safe. Use a single writer or provide external
 * synchronization if multiple threads share the same {@code RAF}. Once {@link #close()} is called,
 * subsequent writes will raise {@link EOFException} to signal the detached state rather than
 * attempting to flush to disk.
 *
 * <ul>
 *   <li>Use when third-party code expects an {@code OutputStream} but you must preserve {@code RAF}
 *       ownership.
 *   <li>Best suited for append-style or forward-only writes; callers manage positioning resets by
 *       creating a new instance.
 *   <li>Does not buffer; upstream callers should wrap in {@link java.io.BufferedOutputStream} if
 *       they need aggregation.
 * </ul>
 *
 * @see RAF
 */
public class RAFOutputStream extends OutputStream {

  RAF raf;
  long pos;

  /**
   * Create an output stream that writes to the provided random-access file from its current
   * position.
   *
   * <p>The caller retains ownership of {@code raf}; this constructor does not alter its seek
   * position or close it. The new stream begins writing from the current position and advances the
   * tracked offset after every operation, making it useful for adapting {@link RAF} storage to APIs
   * that only accept {@link OutputStream}.
   *
   * @param raf backing {@code RAF} that remains open for the lifetime of this stream; must support
   *     writing at arbitrary offsets and remain valid while the stream is used.
   */
  @SuppressWarnings("unused")
  public RAFOutputStream(RAF raf) {
    this.raf = raf;
  }

  /**
   * Write a single byte at the current stream position.
   *
   * <p>This method wraps {@link #write(byte[], int, int)} to satisfy the {@link OutputStream}
   * contract. Only the low eight bits of {@code b} are persisted; the internal position advances by
   * exactly one byte even when the backing {@code RAF} uses larger sector sizes.
   *
   * @param b byte value whose least significant eight bits are stored at the current position of
   *     the backing {@code RAF}.
   * @throws IOException if the stream has been closed or the underlying {@code RAF} rejects the
   *     write operation.
   */
  public void write(int b) throws IOException {
    write(new byte[] {(byte) b}, 0, 1);
  }

  /**
   * Write a range of bytes to the backing {@link RAF} starting at the tracked cursor.
   *
   * <p>The method forwards to {@link RAF#seekAndWrite(long, byte[], int, int)}, ensuring the
   * current position is used as the destination offset. After a successful call the cursor
   * increases by {@code len}. Passing a null buffer is not permitted; callers should also validate
   * that {@code off} and {@code len} describe a valid slice to avoid {@link
   * ArrayIndexOutOfBoundsException}.
   *
   * @param b byte array containing data to persist; must not be {@code null} and must remain stable
   *     for the duration of the write.
   * @param off starting index within {@code b} from which bytes are read; must be within the array
   *     bounds and non-negative.
   * @param len number of bytes to write beginning at {@code off}; must not exceed the remaining
   *     length of the array and may be zero for a no-op.
   * @throws EOFException if the stream has been closed via {@link #close()} and no backing {@code
   *     RAF} is available.
   * @throws IOException if the underlying {@code RAF} cannot complete the requested write for I/O
   *     reasons.
   */
  @Override
  public void write(byte @NotNull [] b, int off, int len) throws IOException {
    if (raf == null) {
      throw new EOFException();
    }
    raf.seekAndWrite(pos, b, off, len);
    pos += len;
  }

  // This does not close the underlying RAF.
  /**
   * Mark this stream as closed without closing the underlying {@link RAF}.
   *
   * <p>After invocation the internal reference to the backing file is cleared, and subsequent write
   * attempts will fail with {@link EOFException}. Use this when you must stop writing through this
   * view but continue managing the {@code RAF} elsewhere, such as coordinating multiple sequential
   * writers under external control.
   *
   * @throws IOException never thrown in the current implementation; declared to satisfy the {@link
   *     OutputStream} contract.
   */
  @Override
  public void close() throws IOException {
    raf = null;
  }
}

package network.crypta.support.io;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import network.crypta.support.api.RandomAccessBuffer;
import org.jetbrains.annotations.NotNull;

/**
 * An {@link InputStream} view backed by a {@link RandomAccessBuffer} over a fixed byte range.
 *
 * <p>This adapter treats the provided {@code offset} and {@code size} as the bounds of a read-only
 * window and maintains its own read pointer ({@code rafOffset}). Reads delegate to {@link
 * RandomAccessBuffer#pread(long, byte[], int, int)} so the underlying buffer's state is not mutated
 * by this stream. Instances are not thread-safe because they carry mutable position; if a caller
 * shares a single instance across threads, it must synchronize externally.
 *
 * <p>Note: the {@code size} parameter is the number of readable bytes within the window, not an
 * absolute end offset. For example, {@code new RAFInputStream(buf, 5, 4)} exposes the bytes at
 * absolute offsets {@code 5}, {@code 6}, {@code 7}, and {@code 8}.
 *
 * <p>End-of-stream semantics: when the current position reaches the end of the view, {@link
 * EOFException} is thrown (even for a 0-length request) rather than returning {@code -1}. This
 * differs from the general contract of {@link InputStream}; callers should be prepared to catch
 * {@code EOFException}.
 */
public class RAFInputStream extends InputStream {

  /**
   * Underlying random-access source. Contract: {@link RandomAccessBuffer#pread} must read fully.
   */
  private final RandomAccessBuffer underlying;

  /** Total number of readable bytes in this view, starting at {@code rafOffset}'s initial value. */
  private final long rafLength;

  /** Absolute base file offset for the start of this view. */
  private final long rafBase;

  // Current absolute position within this view (relative to the original {@code offset}).
  // Advances by the number of bytes successfully read.
  private long rafOffset;

  /**
   * Creates a new stream window over a {@link RandomAccessBuffer}.
   *
   * @param data the underlying buffer to read from; not {@code null}
   * @param offset the starting byte offset within {@code data}; may be any value accepted by {@link
   *     RandomAccessBuffer#pread(long, byte[], int, int)}
   * @param size the number of readable bytes in this view (bytes); this is not an absolute end
   *     offset.
   */
  public RAFInputStream(RandomAccessBuffer data, long offset, long size) {
    this.underlying = data;
    this.rafBase = offset;
    this.rafOffset = offset;
    this.rafLength = size;
  }

  /**
   * Reads a single unsigned byte from the stream.
   *
   * <p>Delegates to {@link #read(byte[], int, int)} with a 1-byte buffer and returns the value as
   * an unsigned integer in the range 0..255.
   *
   * @return the next byte value (0..255)
   * @throws EOFException when the stream is at end-of-view
   * @throws IOException if the underlying buffer fails to satisfy the read
   */
  @Override
  public int read() throws IOException {
    byte[] buf = new byte[1];
    int length = read(buf, 0, 1);
    if (length > 0) {
      return Byte.toUnsignedInt(buf[0]);
    }
    // This path is not expected in practice because read(byte[], int, int) either reads > 0 or
    // throws EOFException at end-of-view. Kept for defensive completeness.
    return -1;
  }

  /**
   * Reads into the entire buffer.
   *
   * <p>This is equivalent to {@link #read(byte[], int, int)} with {@code offset=0} and {@code
   * length=buf.length}.
   *
   * @param buf the destination buffer; must not be {@code null}
   * @return the number of bytes read; may be 0 if {@code length==0}
   * @throws EOFException when the stream is at end-of-view
   * @throws NullPointerException if {@code buf} is {@code null}
   * @throws IOException if the underlying buffer fails to satisfy the read
   */
  @Override
  public int read(byte @NotNull [] buf) throws IOException {
    return read(buf, 0, buf.length);
  }

  /**
   * Reads up to {@code length} bytes into {@code buf} starting at {@code offset}.
   *
   * <p>Behavior:
   *
   * <ul>
   *   <li>If the internal position is at or beyond the end of the view, throws {@link
   *       EOFException}.
   *   <li>Otherwise, clamps {@code length} to the remaining bytes in the view and delegates to
   *       {@link RandomAccessBuffer#pread(long, byte[], int, int)}.
   *   <li>Advances the internal position by the number of bytes read and returns that count.
   *   <li>If {@code length == 0} and not at end-of-view, returns 0 and does not advance.
   * </ul>
   *
   * @param buf the destination buffer; must not be {@code null}
   * @param offset the offset in {@code buf} to start storing bytes
   * @param length the requested number of bytes
   * @return the actual number of bytes read (in {@code 0..length})
   * @throws EOFException when at end-of-view (including a 0-length request at EOF)
   * @throws IndexOutOfBoundsException if {@code offset} or {@code length} is out of range for
   *     {@code buf}
   * @throws IllegalArgumentException if the underlying implementation rejects the arguments (e.g.,
   *     negative file offset)
   * @throws IOException if the underlying read fails
   */
  @Override
  public int read(byte @NotNull [] buf, int offset, int length) throws IOException {
    // Bytes consumed so far inside the view
    long consumed = rafOffset - rafBase;
    if (consumed >= rafLength) throw new EOFException();
    long remaining = rafLength - consumed;
    int toRead = (int) Math.min(length, remaining);
    underlying.pread(rafOffset, buf, offset, toRead);
    rafOffset += toRead;
    return toRead;
  }
}

package network.crypta.support.io;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import org.jetbrains.annotations.NotNull;

/**
 * An {@link InputStream} wrapper that counts bytes consumed from the underlying stream.
 *
 * <p>The counter increases for every successfully read byte and for bytes skipped via {@link
 * #skip(long)}. End-of-stream indicators (for example, {@code -1} from {@link #read()}) do not
 * increment the count. The count is monotonic and does not decrease on {@code reset()} — if the
 * underlying stream supports mark/reset and the caller rewinds the position, the counter continues
 * to reflect the total bytes that have been delivered or skipped through this wrapper over its
 * lifetime.
 *
 * <p>Thread-safety: like most {@link InputStream} implementations, this class is not inherently
 * thread-safe. If multiple threads access the same instance, external synchronization is required.
 */
public final class CountedInputStream extends FilterInputStream {

  /**
   * Cumulative number of bytes observed by this wrapper.
   *
   * <p>Units are bytes. The value increases on successful reads and positive {@link #skip(long)}
   * operations and never decreases. It is not automatically adjusted by {@code reset()} on the
   * underlying stream.
   */
  private long count = 0;

  /**
   * Creates a counting wrapper around the given input stream.
   *
   * @param in the underlying stream to read from; must not be {@code null}
   * @throws IllegalStateException if {@code in} is {@code null}
   */
  public CountedInputStream(InputStream in) {
    super(in);
    // Guard against accidental null wiring. Use IllegalStateException to match historical
    // behavior in this codebase.
    if (in == null) throw new IllegalStateException("null fed to CountedInputStream");
  }

  /**
   * Returns the number of bytes consumed so far.
   *
   * <p>The value includes both bytes returned by {@code read(...)} and bytes successfully skipped
   * via {@link #skip(long)}. It does not include unread bytes after {@code mark/reset} and does not
   * decrease.
   *
   * @return the cumulative byte count (never negative)
   */
  public final long count() {
    return count;
  }

  /**
   * Reads one byte and increments the counter if successful.
   *
   * @return the next byte as an unsigned {@code 0..255} value, or {@code -1} if end of stream
   * @throws IOException if an I/O error occurs in the underlying stream
   */
  @Override
  public int read() throws IOException {
    int ret = super.read();
    // Increment only when a real byte is obtained; -1 means EOF.
    if (ret != -1) ++count;
    return ret;
  }

  /**
   * Reads up to {@code len} bytes into the buffer and increments the counter by the number of bytes
   * actually read.
   *
   * <p>Note: This implementation calls the underlying {@code in.read(...)} directly to avoid any
   * double-counting and then updates the counter based on the returned length.
   *
   * @param buf destination buffer; must not be {@code null}
   * @param off offset in {@code buf} at which to start storing bytes
   * @param len maximum number of bytes to read
   * @return the number of bytes read, or {@code -1} if end of stream
   * @throws IOException if an I/O error occurs in the underlying stream
   * @throws IndexOutOfBoundsException if {@code off < 0}, {@code len < 0}, or {@code off + len >}
   *     {@code buf.length}
   */
  @Override
  public int read(byte @NotNull [] buf, int off, int len) throws IOException {
    int ret = in.read(buf, off, len);
    if (ret != -1) count += ret;
    return ret;
  }

  /**
   * Reads some bytes into the buffer and increments the counter by the number of bytes read.
   *
   * @param buf destination buffer; must not be {@code null}
   * @return the number of bytes read, or {@code -1} if end of stream
   * @throws IOException if an I/O error occurs in the underlying stream
   */
  @Override
  public int read(byte @NotNull [] buf) throws IOException {
    int ret = in.read(buf);
    if (ret != -1) count += ret;
    return ret;
  }

  /**
   * Skips up to {@code n} bytes and increments the counter by the number of bytes actually skipped.
   *
   * <p>Some {@link InputStream} implementations may skip fewer bytes than requested or return
   * {@code 0} if no bytes can be skipped at the moment.
   *
   * @param n the number of bytes to attempt to skip
   * @return the actual number of bytes skipped, which may be less than {@code n}
   * @throws IOException if an I/O error occurs in the underlying stream
   */
  @Override
  public long skip(long n) throws IOException {
    long l = in.skip(n);
    // Count only positive progress; some streams return 0 to indicate no-op.
    if (l > 0) count += l;
    return l;
  }
}

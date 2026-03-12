package network.crypta.support.io;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import org.jetbrains.annotations.NotNull;

/**
 * An {@link OutputStream} wrapper that counts the number of bytes successfully written.
 *
 * <p>All write operations delegate to the wrapped stream and, on success, increment an internal
 * counter. The current total can be queried via {@link #written()} and starts at {@code 0} when the
 * instance is constructed.
 *
 * <p>Thread-safety: This class is not thread-safe. If used by multiple threads, synchronize
 * externally.
 *
 * <p>Overflow: The counter is a {@code long}. No overflow checks are performed; if more than {@link
 * Long#MAX_VALUE} bytes are written, the value wraps according to two's-complement rules.
 */
public class CountedOutputStream extends FilterOutputStream {

  // Tracks the total number of bytes successfully written to 'out'. Not thread-safe. No overflow
  // checks are performed; extremely large totals may wrap.
  private long written;

  /**
   * Creates a counting output stream that forwards to the given stream.
   *
   * @param arg0 the underlying stream to which data is written; may be {@code null}, but any
   *     subsequent write will throw {@link NullPointerException}
   */
  public CountedOutputStream(OutputStream arg0) {
    super(arg0);
  }

  /**
   * Writes a single byte and increments the counter by one on success.
   *
   * @param x the byte value to write; only the low eight bits are used
   * @throws IOException if the underlying stream throws an I/O error
   * @throws NullPointerException if the underlying stream is {@code null}
   */
  @Override
  public void write(int x) throws IOException {
    super.write(x);
    written++;
  }

  /**
   * Writes the entire array and increments the counter by {@code buf.length} on success.
   *
   * <p>This method is equivalent to {@code write(buf, 0, buf.length)}.
   *
   * @param buf the data to write; must not be {@code null}
   * @throws IOException if the underlying stream throws an I/O error
   * @throws NullPointerException if {@code buf} is {@code null} or the underlying stream is {@code
   *     null}
   */
  @Override
  public void write(byte @NotNull [] buf) throws IOException {
    write(buf, 0, buf.length);
  }

  /**
   * Writes {@code length} bytes from {@code buf} starting at {@code offset} and increments the
   * counter by {@code length} on success.
   *
   * <p>As with {@link OutputStream#write(byte[], int, int)}, providing an invalid range typically
   * results in {@link IndexOutOfBoundsException}.
   *
   * @param buf the source buffer; must not be {@code null}
   * @param offset the starting index within {@code buf}
   * @param length the number of bytes to write; may be {@code 0}
   * @throws IOException if the underlying stream throws an I/O error
   * @throws NullPointerException if {@code buf} is {@code null} or the underlying stream is {@code
   *     null}
   * @throws IndexOutOfBoundsException if {@code offset} or {@code length} are out of range
   */
  @Override
  public void write(byte @NotNull [] buf, int offset, int length) throws IOException {
    out.write(buf, offset, length);
    written += length;
  }

  /**
   * Returns the number of bytes successfully written since construction.
   *
   * @return the total number of bytes written (may wrap on overflow)
   */
  public long written() {
    return written;
  }
}

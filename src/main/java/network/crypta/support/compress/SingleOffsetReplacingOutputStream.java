package network.crypta.support.compress;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.zip.GZIPOutputStream;
import org.jetbrains.annotations.NotNull;

/**
 * Writes to an underlying {@link OutputStream} while replacing exactly one byte at a specific
 * position in the logical stream.
 *
 * <p>Typical usage is to overwrite a known header byte without buffering the whole payload. For
 * example, this can change the Operating System byte in the header of a {@link GZIPOutputStream}.
 * The replacement is performed once at the zero-based global stream index provided at construction,
 * and all other bytes are forwarded unchanged.
 *
 * <p>Thread-safety: instances are not thread-safe. Use from a single thread or guard with external
 * synchronization.
 */
public class SingleOffsetReplacingOutputStream extends FilterOutputStream {

  // Zero-based index in the output stream to replace once. Negative means "never replace".
  private final int replacementOffset;
  // Byte value written at replacementOffset (low 8 bits used, per OutputStream#write(int)).
  private final int replacementValue;
  // Current number of bytes written so far; also the index of the next byte to be written.
  private int currentOffset = 0;

  /**
   * Creates a filter that replaces one byte at a fixed stream position.
   *
   * @param outputStream the destination stream; must not be {@code null}
   * @param replacementOffset zero-based index of the byte to replace; if negative or never reached,
   *     no replacement occurs
   * @param replacementValue value to write at {@code replacementOffset}; only the low 8 bits are
   *     used
   * @throws NullPointerException if {@code outputStream} is {@code null}
   */
  public SingleOffsetReplacingOutputStream(
      OutputStream outputStream, int replacementOffset, int replacementValue) {
    super(outputStream);
    this.replacementOffset = replacementOffset;
    this.replacementValue = replacementValue;
  }

  /**
   * Writes one byte, replacing it when the current position equals the configured offset.
   *
   * <p>Postcondition: advances the internal position by one.
   *
   * @param b the byte value to write (low 8 bits used)
   * @throws IOException if the underlying stream throws
   */
  @Override
  public void write(int b) throws IOException {
    if (currentOffset == replacementOffset) {
      out.write(replacementValue);
    } else {
      out.write(b);
    }
    currentOffset++;
  }

  /**
   * Writes a subrange of {@code buffer}. If the replacement position lies within the range, this
   * method forwards the data in three parts: the prefix before the replacement index, the
   * single-byte replacement, and the remaining suffix.
   *
   * <p>Postcondition: advances the internal position by {@code length}.
   *
   * @param buffer the source array; must not be {@code null}
   * @param offset start index in {@code buffer}
   * @param length number of bytes to write
   * @throws IOException if the underlying stream throws
   * @throws NullPointerException if {@code buffer} is {@code null}
   * @throws IndexOutOfBoundsException if {@code offset} or {@code length} is invalid for the array
   */
  @Override
  public void write(byte @NotNull [] buffer, int offset, int length) throws IOException {
    if (offsetToReplaceIsInBufferBeingWritten(length)) {
      // Write prefix before the replacement index.
      out.write(buffer, offset, replacementOffset - currentOffset);
      out.write(replacementValue);
      // Write suffix after the replacement index.
      out.write(
          buffer,
          offset + (replacementOffset - currentOffset) + 1,
          length - (replacementOffset - currentOffset) - 1);
    } else {
      out.write(buffer, offset, length);
    }
    currentOffset += length;
  }

  // True when the single replacement index lies within [currentOffset, currentOffset + length).
  private boolean offsetToReplaceIsInBufferBeingWritten(int length) {
    return (currentOffset <= replacementOffset) && ((currentOffset + length) > replacementOffset);
  }
}

package network.crypta.crypt;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.zip.Checksum;
import network.crypta.support.Fields;
import org.jetbrains.annotations.NotNull;

/**
 * Output stream that maintains a running {@link Checksum} of bytes written.
 *
 * <p>All bytes are forwarded unmodified to the underlying stream. For checksum computation, the
 * first {@code skipPrefix} bytes written through this wrapper are <em>not</em> included; all
 * following bytes contribute to the checksum. Optionally, on {@link #close()}, the current checksum
 * value is appended to the underlying stream as a 4-byte little-endian integer (equivalent to
 * {@link Fields#intToBytes(int)} of the low 32 bits).
 *
 * <p>Ordering note: the checksum is updated before delegating the corresponding writing to the
 * wrapped stream. If the underlying writing throws, the checksum may already reflect the attempted
 * bytes (except those within the prefix).
 *
 * <p>Thread-safety: instances are not thread-safe. Use from a single thread or coordinate
 * externally.
 */
public class ChecksumOutputStream extends FilterOutputStream {

  private final Checksum crc;
  private boolean closed;
  private final boolean writeChecksum;
  // Number of initial bytes to skip when computing the checksum.
  private final int skipPrefix;
  private int bytesInsidePrefix;

  /**
   * Creates a new wrapper that updates {@code crc} as bytes are written.
   *
   * @param out destination stream; must not be {@code null}.
   * @param crc checksum implementation to update; must not be {@code null}.
   * @param writeChecksum when {@code true}, {@link #close()} appends a 4-byte little-endian
   *     representation of the current checksum (low 32 bits) to {@code out} before closing.
   * @param skipPrefix number of initial bytes to forward to {@code out} without contributing to the
   *     checksum; must be {@code >= 0}.
   */
  public ChecksumOutputStream(
      OutputStream out, final Checksum crc, boolean writeChecksum, int skipPrefix) {
    super(out);
    this.crc = crc;
    this.writeChecksum = writeChecksum;
    this.skipPrefix = skipPrefix;
  }

  /**
   * Writes a single byte, updating the checksum only after the skipped prefix has been fully
   * consumed.
   *
   * @param b the byte to write.
   * @throws IOException if the underlying stream fails to write.
   */
  @Override
  public synchronized void write(int b) throws IOException {
    if (bytesInsidePrefix >= skipPrefix) {
      crc.update(b);
    } else bytesInsidePrefix++;
    out.write(b);
  }

  /**
   * Writes a byte array slice, updating the checksum for the portion beyond the remaining prefix.
   *
   * <p>If the slice spans the boundary where the prefix ends, only the bytes after that boundary
   * are included in the checksum. All bytes are still forwarded to the underlying stream.
   *
   * @param buf source array; must not be {@code null}.
   * @param offset start offset in {@code buf}.
   * @param length number of bytes to write.
   * @throws IOException if the underlying stream fails to write.
   * @throws IndexOutOfBoundsException if {@code offset} or {@code length} is invalid.
   */
  @Override
  public synchronized void write(byte @NotNull [] buf, int offset, int length) throws IOException {
    int chop = Math.min(skipPrefix - bytesInsidePrefix, length);
    if (chop <= 0) {
      // Prefix already consumed: count the entire slice.
      crc.update(buf, offset, length);
      out.write(buf, offset, length);
    } else {
      if (length - chop > 0) {
        crc.update(buf, offset + chop, length - chop);
        bytesInsidePrefix = skipPrefix;
      } else {
        bytesInsidePrefix += length;
      }
      out.write(buf, offset, length);
    }
  }

  /**
   * Writes the entire array. Equivalent to {@link #write(byte[], int, int) write(buf, 0,
   * buf.length)} with prefix handling as described there.
   *
   * @param buf source array; must not be {@code null}.
   * @throws IOException if the underlying stream fails to write.
   */
  @Override
  public synchronized void write(byte @NotNull [] buf) throws IOException {
    write(buf, 0, buf.length);
  }

  /**
   * Closes the stream.
   *
   * <p>If configured with {@code writeChecksum = true}, this method first appends a 4-byte
   * little-endian encoding of the current checksum (low 32 bits) to the underlying stream. The
   * trailer is written at most once; subsequent {@code close()} calls are ignored for appending and
   * do not re-close the delegate.
   *
   * @throws IOException if writing the trailer or closing the underlying stream fails.
   */
  @Override
  public synchronized void close() throws IOException {
    if (writeChecksum) {
      if (closed) return; // Idempotent close: avoid duplicate trailer writes
      closed = true;
      out.write(Fields.intToBytes((int) crc.getValue()));
    }
    super.close(); // Always close the underlying stream
  }

  /**
   * Returns the current checksum value.
   *
   * <p>The value reflects all bytes written after the skipped prefix. The exact interpretation is
   * defined by the supplied {@link Checksum} implementation (for {@link java.util.zip.CRC32}, this
   * is an unsigned 32-bit value represented in a {@code long}).
   *
   * @return the running checksum value.
   */
  public synchronized long getValue() {
    return crc.getValue();
  }
}

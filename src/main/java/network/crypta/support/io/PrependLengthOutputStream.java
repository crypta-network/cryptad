package network.crypta.support.io;

import java.io.DataOutputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import org.jetbrains.annotations.NotNull;

/**
 * Output stream that buffers into a temporary {@link network.crypta.support.api.Bucket} and, on
 * close, prepends an 8-byte length header before copying the payload to a caller-provided {@link
 * OutputStream}.
 *
 * <p>Data written to this stream is accumulated in a temporary {@code Bucket}. When {@link
 * #close()} is called:
 *
 * <ol>
 *   <li>If {@link #abort()} was invoked earlier, the stream writes a {@code long} value of {@code
 *       0} to the underlying stream and writes no payload bytes.
 *   <li>Otherwise, it writes a {@code long} header equal to {@code temp.size() - offset} and then
 *       copies the entire buffered payload from the temporary {@code Bucket} to the underlying
 *       stream.
 * </ol>
 *
 * The temporary {@code Bucket} is always freed. The underlying stream is closed only when the
 * {@code closeUnderlying} flag is set at construction time (see {@link #create(OutputStream,
 * BucketFactory, int, boolean)}).
 *
 * <p>Header format: the 8-byte value is written via {@link
 * java.io.DataOutputStream#writeLong(long)} (big-endian). The value is computed as the buffered
 * size minus {@code offset}; if {@code offset} exceeds the buffered size, a negative value is
 * written. Note: confirm with callers whether negative lengths are acceptable before relying on
 * this behavior.
 *
 * <p>Thread-safety: instances are not thread-safe. Callers must serialize access and ensure that
 * {@link #close()} is not invoked concurrently with {@link #write(byte[], int, int)}.
 */
public class PrependLengthOutputStream extends FilterOutputStream {

  private final Bucket temp;
  private final OutputStream origOS;
  private final int offset;
  private final boolean closeUnderlying;
  private boolean aborted;
  private boolean closed;

  /**
   * Creates a stream that buffers to a temporary {@link Bucket} and, on non-aborted close, writes
   * an 8-byte length header followed by the payload to the provided underlying stream.
   *
   * <p>The returned stream writes only to temporary storage until {@link #close()} is called.
   *
   * @param out the underlying stream that receives the header and payload on close; must not be
   *     {@code null}
   * @param bf the factory used to allocate a temporary {@code Bucket}; must not be {@code null}
   * @param offset the value subtracted from the buffered size to compute the length header; may be
   *     negative or greater than the buffered size
   * @param closeUnderlying whether to close {@code out} after writing
   * @return a new {@code PrependLengthOutputStream}
   * @throws IOException if the temporary bucket cannot be created or its output stream cannot be
   *     obtained
   */
  public static PrependLengthOutputStream create(
      OutputStream out, BucketFactory bf, int offset, boolean closeUnderlying) throws IOException {
    Bucket temp = bf.makeBucket(-1);
    OutputStream os = temp.getOutputStream();
    return new PrependLengthOutputStream(os, temp, out, offset, closeUnderlying);
  }

  private PrependLengthOutputStream(
      OutputStream os, Bucket temp, OutputStream origOS, int offset, boolean closeUnderlying) {
    super(os);
    this.temp = temp;
    this.origOS = origOS;
    this.offset = offset;
    this.closeUnderlying = closeUnderlying;
  }

  /**
   * Writes {@code length} bytes from {@code buf}, starting at {@code offset}, to the temporary
   * buffer.
   *
   * <p>This override forwards the bulk operation directly to the wrapped stream to avoid {@link
   * FilterOutputStream}'s default per-byte delegation.
   *
   * @param buf the source buffer; must not be {@code null}
   * @param offset the starting index in {@code buf}
   * @param length the number of bytes to write
   * @throws IOException if an I/O error occurs while writing to the temporary bucket
   */
  @Override
  public void write(byte @NotNull [] buf, int offset, int length) throws IOException {
    // Prefer bulk write over FilterOutputStream's default one-byte-at-a-time path.
    out.write(buf, offset, length);
  }

  /**
   * Writes the entire {@code buf} to the temporary buffer.
   *
   * @param buf the source buffer; must not be {@code null}
   * @throws IOException if an I/O error occurs while writing to the temporary bucket
   */
  @Override
  public void write(byte @NotNull [] buf) throws IOException {
    write(buf, 0, buf.length);
  }

  /**
   * Aborts the stream so that {@link #close()} writes only an eight-byte zero length header and no
   * payload.
   *
   * <p>If already closed, the method does nothing and returns {@code false}; otherwise it marks the
   * stream aborted and returns {@code true}.
   *
   * @return {@code false} if already closed; {@code true} otherwise
   * @throws IOException declared for historical compatibility; this implementation performs no I/O
   *     and does not throw it
   */
  public boolean abort() throws IOException {
    if (closed) return false;
    aborted = true;
    return true;
  }

  /**
   * Flushes the buffered content to the underlying stream with a prepended length header, frees the
   * temporary bucket, and optionally closes the underlying stream.
   *
   * <p>If aborted, writes {@code 0L} as the header and no payload. Otherwise, writes the header
   * {@code temp.size() - offset} and copies all buffered data.
   *
   * <p>This method is idempotent: repeated calls after the first have no effect.
   *
   * @throws IOException if writing the header or payload fails, if freeing resources triggers an
   *     I/O error, or if closing the underlying stream fails when configured to do so
   */
  @Override
  public void close() throws IOException {
    if (closed) return;
    out.close();
    DataOutputStream dos = new DataOutputStream(origOS);
    if (aborted) {
      dos.writeLong(0);
    } else {
      dos.writeLong(temp.size() - offset);
      /* Copy the entire payload. Using Long.MAX_VALUE signals “no explicit limit” to copyTo(). */
      BucketTools.copyTo(temp, dos, Long.MAX_VALUE);
    }
    temp.free();
    closed = true;
    if (closeUnderlying) dos.close();
  }
}

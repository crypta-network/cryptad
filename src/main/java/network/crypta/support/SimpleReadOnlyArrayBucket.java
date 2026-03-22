package network.crypta.support;

import java.io.ByteArrayInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.api.ResumeContext;
import network.crypta.support.io.ByteArrayRandomAccessBuffer;

/**
 * A minimal, read-only {@link Bucket} and {@link RandomAccessBucket} backed by a slice of a {@code
 * byte[]}.
 *
 * <p>This class adapts an existing array with an {@code offset} and {@code length} into the Bucket
 * API without allocating additional buffers. It is intended for small, short-lived data where
 * copying would be wasteful. All write methods throw {@link IOException}; the content and size are
 * fixed at construction time.
 *
 * <h2>Behavior and limitations</h2>
 *
 * <ul>
 *   <li>Streams: {@link #getInputStream()} and {@link #getInputStreamUnbuffered()} always return an
 *       {@link java.io.InputStream} (never {@code null}); for zero length, the stream yields no
 *       bytes.
 *   <li>Read-only: {@link #getOutputStream()} and {@link #getOutputStreamUnbuffered()} always throw
 *       {@link IOException}.
 *   <li>Persistence: Not persistent. {@link #onResume(ResumeContext)} and {@link
 *       #storeTo(DataOutputStream)} throw {@link UnsupportedOperationException}.
 *   <li>Shadows: {@link #createShadow()} returns a new independent bucket that copies this slice
 *       only when the backing array is smaller than 256&nbsp;KiB; otherwise it returns {@code
 *       null}.
 *   <li>Random access buffer: {@link #toRandomAccessBuffer()} returns a read-only {@link
 *       ByteArrayRandomAccessBuffer}. The returned buffer is independent of future changes to the
 *       original backing array.
 *   <li>Threading: This class performs no internal synchronization. It is safe to use concurrently
 *       for reading, provided callers do not mutate the backing array.
 * </ul>
 */
public class SimpleReadOnlyArrayBucket implements Bucket, RandomAccessBucket {

  // Backing array. Only the range [offset, offset + length) is exposed via the Bucket API.
  final byte[] buf;
  // Start index (inclusive) of the visible slice in {@link #buf}.
  final int offset;
  // Length of the visible slice in bytes.
  final int length;

  /**
   * Create a read-only bucket exposing a slice of the provided array.
   *
   * @param buf backing array (must not be {@code null})
   * @param offset start index (inclusive) of the visible range within {@code buf}
   * @param length number of bytes exposed starting at {@code offset}
   */
  public SimpleReadOnlyArrayBucket(byte[] buf, int offset, int length) {
    this.buf = buf;
    this.offset = offset;
    this.length = length;
  }

  /**
   * Create a read-only bucket exposing the entire array.
   *
   * @param buf backing array (must not be {@code null})
   */
  public SimpleReadOnlyArrayBucket(byte[] buf) {
    this(buf, 0, buf.length);
  }

  /**
   * Unsupported write operation.
   *
   * @return never returns normally
   * @throws IOException always thrown with message {@code "Read only"}
   */
  @Override
  public OutputStream getOutputStream() throws IOException {
    throw new IOException("Read only");
  }

  /**
   * Unsupported unbuffered write operation.
   *
   * @return never returns normally
   * @throws IOException always thrown with message {@code "Read only"}
   */
  @Override
  public OutputStream getOutputStreamUnbuffered() throws IOException {
    throw new IOException("Read only");
  }

  /**
   * Return an unbuffered {@link InputStream} over the visible slice.
   *
   * <p>The returned stream reads exactly {@code length} bytes starting at {@code offset}. For
   * zero-length buckets it yields no bytes. This method never returns {@code null}.
   *
   * @return a new {@link ByteArrayInputStream} over the slice
   * @throws IOException never thrown by this implementation
   */
  @Override
  public InputStream getInputStreamUnbuffered() throws IOException {
    return new ByteArrayInputStream(buf, offset, length);
  }

  /**
   * Return a buffered {@link InputStream} over the visible slice.
   *
   * <p>Delegates to {@link #getInputStreamUnbuffered()} since the underlying storage is in memory.
   *
   * @return a new {@link ByteArrayInputStream} over the slice
   * @throws IOException never thrown by this implementation
   */
  @Override
  public InputStream getInputStream() throws IOException {
    return getInputStreamUnbuffered();
  }

  /**
   * Return a human-readable name including the current length and the default {@code toString()} of
   * this instance.
   *
   * <p>The format is implementation-defined and intended for diagnostics only. Example: {@code
   * "SimpleReadOnlyArrayBucket: len=42 network.crypta.support.SimpleReadOnlyArrayBucket@1a2b3c"}.
   *
   * @return a descriptive name string
   */
  @Override
  public String getName() {
    return "SimpleReadOnlyArrayBucket: len=" + length + ' ' + super.toString();
  }

  /**
   * Return the number of readable bytes.
   *
   * @return {@code length}
   */
  @Override
  public long size() {
    return length;
  }

  /**
   * Always returns {@code true}.
   *
   * @return {@code true}
   */
  @Override
  public boolean isReadOnly() {
    return true;
  }

  /** No-op. The bucket is immutable from construction time. */
  @Override
  public void setReadOnly() {
    // Already read-only.
  }

  /** No-op. There are no external resources to release. */
  @Override
  public void free() {
    // Nothing to release.
  }

  /**
   * Create an independent, read-only copy of this slice when the backing array is small.
   *
   * <p>If {@code buf.length < 256 * 1024} (i.e., smaller than 256&nbsp;KiB), this method returns a
   * new {@link SimpleReadOnlyArrayBucket} whose content equals this bucket's slice at the moment of
   * the call. The returned bucket does not reflect future changes to the original array. For larger
   * backing arrays, this method returns {@code null} to avoid copying.
   *
   * @return a new bucket over a copied slice, or {@code null} when the backing array is large
   */
  @Override
  public RandomAccessBucket createShadow() {
    if (buf.length < 256 * 1024) {
      return new SimpleReadOnlyArrayBucket(Arrays.copyOfRange(buf, offset, offset + length));
    }
    return null;
  }

  /**
   * Unsupported because this bucket is not persistent.
   *
   * @param context unused
   * @throws UnsupportedOperationException always
   */
  @Override
  public void onResume(ResumeContext context) {
    // Not persistent.
    throw new UnsupportedOperationException();
  }

  /**
   * Unsupported because this bucket is not persistent.
   *
   * @param dos unused
   * @throws UnsupportedOperationException always
   */
  @Override
  public void storeTo(DataOutputStream dos) {
    // Not persistent.
    throw new UnsupportedOperationException();
  }

  /**
   * Convert this bucket to a read-only {@link LockableRandomAccessBuffer} representing the same
   * content.
   *
   * <p>The returned buffer reflects the data at the time of the call and is independent of any
   * later modification of the original backing array. Writes through the returned buffer fail with
   * {@link IOException}.
   *
   * <p><b>Note:</b> This implementation currently copies the slice into a new {@link
   * ByteArrayRandomAccessBuffer}.
   *
   * @return a read-only random access buffer of size {@code length}
   * @throws IOException never thrown by this implementation
   */
  @Override
  public LockableRandomAccessBuffer toRandomAccessBuffer() throws IOException {
    ByteArrayRandomAccessBuffer raf = new ByteArrayRandomAccessBuffer(buf, offset, length, true);
    raf.setReadOnly();
    return raf;
  }
}

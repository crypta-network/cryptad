package network.crypta.support.io;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import network.crypta.client.async.ClientContext;
import network.crypta.crypt.MasterSecret;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.api.RandomAccessBucket;

/**
 * Read-only {@link Bucket} backed by a {@link LockableRandomAccessBuffer}.
 *
 * <p>This bucket exposes streaming reads over an existing random-access buffer and allows callers
 * to obtain that buffer without copying via {@link #toRandomAccessBuffer()}. It never provides an
 * {@link OutputStream}; attempts to request one will throw {@link IOException} because the bucket
 * is immutable.
 *
 * <p><strong>Size and immutability:</strong> the logical size reported by {@link #size()} is
 * captured at construction time from the underlying buffer. Input streams are created with the
 * underlying buffer size at stream creation time. Callers should treat the buffer length as stable
 * for the lifetime of this bucket.
 *
 * <p><strong>Thread-safety:</strong> this class is a thin wrapper and does not add synchronization
 * beyond what the underlying buffer provides. Multiple readers should create separate input
 * streams. The returned {@link InputStream}s are not thread-safe.
 */
public final class RAFBucket implements Bucket, RandomAccessBucket {

  private final LockableRandomAccessBuffer underlying;
  final long size;

  /**
   * Creates a read-only bucket over an existing random-access buffer.
   *
   * @param underlying the backing {@link LockableRandomAccessBuffer}; must not be {@code null}
   * @throws IOException if obtaining the current size from the buffer fails
   */
  public RAFBucket(LockableRandomAccessBuffer underlying) throws IOException {
    this.underlying = underlying;
    size = underlying.size();
  }

  /**
   * Always throws because this bucket is read-only.
   *
   * @return never returns
   * @throws IOException always thrown to indicate writes are unsupported
   */
  @Override
  public OutputStream getOutputStream() throws IOException {
    throw new IOException("Not supported");
  }

  /**
   * Always throws because this bucket is read-only.
   *
   * @return never returns
   * @throws IOException always thrown to indicate writes are unsupported
   */
  @Override
  public OutputStream getOutputStreamUnbuffered() throws IOException {
    throw new IOException("Not supported");
  }

  /**
   * Returns a buffered {@link InputStream} over the bucket content.
   *
   * <p>The returned stream is a {@link BufferedInputStream} wrapping the unbuffered variant. If the
   * bucket has length 0, the first read will throw {@link java.io.EOFException} (see {@link
   * RAFInputStream}).
   *
   * @return a buffered stream positioned at the start of the bucket
   * @throws IOException if stream creation fails
   */
  @Override
  public InputStream getInputStream() throws IOException {
    return new BufferedInputStream(getInputStreamUnbuffered());
  }

  /**
   * Returns an unbuffered {@link InputStream} over the bucket content.
   *
   * <p>The stream reads from offset {@code 0} up to the current length of the underlying buffer at
   * the time of creation. It throws {@link java.io.EOFException} on reads past the end.
   *
   * @return a non-buffered stream positioned at the start of the bucket
   * @throws IOException if stream creation fails
   */
  @Override
  public InputStream getInputStreamUnbuffered() throws IOException {
    // The RAFInputStream length is taken from the underlying at creation time. The underlying
    // length is expected to be stable while this bucket is in use.
    return new RAFInputStream(underlying, 0, underlying.size());
  }

  /**
   * Returns {@code null} because this bucket does not expose a stable display name.
   *
   * @return always {@code null}
   */
  @Override
  public String getName() {
    return null;
  }

  /**
   * Returns the logical size captured at construction.
   *
   * @return the bucket length in bytes
   */
  @Override
  public long size() {
    return size;
  }

  /**
   * Reports that the bucket is read-only.
   *
   * @return always {@code true}
   */
  @Override
  public boolean isReadOnly() {
    return true;
  }

  /** No-op because the bucket is created read-only. */
  @Override
  public void setReadOnly() {
    // Read-only by construction.
  }

  /**
   * Releases resources by delegating to the underlying buffer.
   *
   * <p>After this call, the underlying buffer is freed and subsequent I/O may fail.
   */
  @Override
  public void free() {
    underlying.free();
  }

  /**
   * Returns {@code null} because this implementation does not provide a cheap shadow copy.
   *
   * @return always {@code null}
   */
  @Override
  public RandomAccessBucket createShadow() {
    return null;
  }

  /**
   * Restores transient state after a process restart by delegating to the underlying buffer.
   *
   * @param context runtime services and registries
   * @throws ResumeFailedException if the underlying buffer cannot resume
   */
  @Override
  public void onResume(ClientContext context) throws ResumeFailedException {
    underlying.onResume(context);
  }

  /** Type discriminator written before the underlying buffer when serializing this bucket. */
  static final int MAGIC = 0x892a708a;

  /**
   * Serializes this bucket to a binary stream.
   *
   * <p>Format: first writes {@link #MAGIC}, then delegates to {@link
   * LockableRandomAccessBuffer#storeTo(DataOutputStream)} of the underlying buffer.
   *
   * @param dos destination stream
   * @throws IOException if writing fails
   */
  @Override
  public void storeTo(DataOutputStream dos) throws IOException {
    dos.writeInt(MAGIC);
    underlying.storeTo(dos);
  }

  /*
   * Package-private restoring constructor used by {@link BucketTools#restoreFrom(DataInputStream,
   * FilenameGenerator, PersistentFileTracker, MasterSecret)}.
   *
   * <p>Reads a {@link LockableRandomAccessBuffer} from {@code dis} via
   * {@link BucketTools#restoreRAFFrom(DataInputStream, FilenameGenerator, PersistentFileTracker,
   * MasterSecret)} and captures its size for {@link #size()}.
   */
  RAFBucket(
      DataInputStream dis,
      FilenameGenerator fg,
      PersistentFileTracker persistentFileTracker,
      MasterSecret masterKey)
      throws IOException, StorageFormatException, ResumeFailedException {
    underlying = BucketTools.restoreRAFFrom(dis, fg, persistentFileTracker, masterKey);
    size = underlying.size();
  }

  /**
   * Returns the backing {@link LockableRandomAccessBuffer} without copying.
   *
   * <p>Per the {@link RandomAccessBucket} contract, callers should treat the returned buffer as
   * read-only when obtained from a read-only bucket.
   *
   * @return the underlying buffer instance
   */
  @Override
  public LockableRandomAccessBuffer toRandomAccessBuffer() {
    return underlying;
  }
}

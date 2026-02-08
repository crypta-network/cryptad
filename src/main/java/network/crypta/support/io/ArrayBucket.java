package network.crypta.support.io;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Serial;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.client.async.ClientContext;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.api.RandomAccessBucket;

/**
 * In‑memory {@link network.crypta.support.api.Bucket} implementation backed by a single byte array.
 *
 * <p>Instances are simple containers intended for short‑lived, local data. This type is not
 * thread‑safe; callers should provide external synchronization if they access a single instance
 * from multiple threads. After {@link #free()} (or {@link #close()} via {@link AutoCloseable}) the
 * instance enters a terminal "freed" state. In that state some methods throw {@link
 * java.io.IOException} (for example {@link #getInputStream()}), while others may fail with {@link
 * NullPointerException} because the internal buffer is cleared.
 *
 * <p>Character conversion in {@link #toString()} uses UTF-8.
 *
 * @author oskar
 */
public class ArrayBucket implements Bucket, Serializable, RandomAccessBucket {
  @Serial private static final long serialVersionUID = 1L;

  /**
   * Current byte buffer published via an atomic reference.
   *
   * <p>Serialization compatibility: The field type was changed from {@code byte[]} to {@code
   * AtomicReference<byte[]>}. We intentionally do not preserve backward compatibility for
   * previously serialized {@code ArrayBucket} objects; older streams will fail to deserialize (for
   * example, with {@code InvalidClassException}). This is by design for this class.
   *
   * @serial Field type intentionally not backward compatible with releases that used {@code
   *     byte[]}.
   */
  // Publishes replaced buffers across threads when the buffer is swapped on close(); improves
  // visibility without implying element-level atomicity.
  private final AtomicReference<byte[]> data;

  private final String name;
  private volatile boolean readOnly;
  private volatile boolean freed;

  /** Create an empty bucket named {@code "ArrayBucket"}. */
  public ArrayBucket() {
    this("ArrayBucket");
  }

  /**
   * Create a bucket whose initial contents are the provided array.
   *
   * <p>This constructor does not defensively copy the array; the reference is stored as‑is until it
   * is replaced by a future writing. Mutations to {@code initdata} performed by the caller after
   * this constructor returns are visible through this instance until the next successful writing
   * via the output stream.
   *
   * @param initdata initial contents; may be {@code null} (later access may throw)
   */
  public ArrayBucket(byte[] initdata) {
    this("ArrayBucket");
    data.set(initdata);
  }

  /**
   * Create an empty bucket with a custom name.
   *
   * @param name human‑readable identifier returned by {@link #getName()}
   */
  public ArrayBucket(String name) {
    this.data = new AtomicReference<>(new byte[0]);
    this.name = name;
  }

  /**
   * Open an {@link OutputStream} for writing new contents from the beginning.
   *
   * <p>The returned stream buffers data in memory. On {@link OutputStream#close() close}, the
   * buffered bytes replace the current contents of this bucket in a single step. If the bucket is
   * marked read‑only before the stream is closed, closing the stream throws an {@link IOException}
   * with message {@code "Read only"}; however, the current implementation commits the buffered data
   * just before throwing.
   *
   * <p>This method throws if the bucket has been freed.
   *
   * @return a stream positioned at the start of the bucket
   * @throws IOException if the bucket is read‑only or already freed
   */
  @Override
  public OutputStream getOutputStream() throws IOException {
    if (readOnly) throw new IOException("Read only");
    if (freed) throw new IOException("Already freed");
    return new ArrayBucketOutputStream();
  }

  /**
   * Open an {@link InputStream} for reading the current contents.
   *
   * <p>Unlike the recommendation on {@link Bucket#getInputStream()}, this implementation always
   * returns a non‑null stream; for an empty bucket it returns an empty stream.
   *
   * @return a stream over the current contents (never {@code null})
   * @throws IOException if the bucket is already freed
   */
  @Override
  public InputStream getInputStream() throws IOException {
    if (freed) throw new IOException("Already freed");
    return new ByteArrayInputStream(data.get());
  }

  /**
   * Convert the entire byte array contents to a {@link String} using the platform default charset.
   *
   * @return a string representation of the current contents
   */
  @Override
  public String toString() {
    return new String(data.get(), StandardCharsets.UTF_8);
  }

  /**
   * Return the number of bytes currently stored.
   *
   * <p>Precondition: the bucket has not been freed.
   *
   * @return current size in bytes
   */
  @Override
  public long size() {
    return data.get().length;
  }

  /**
   * Get the descriptive name provided at construction.
   *
   * @return the human‑readable name
   */
  @Override
  public String getName() {
    return name;
  }

  private class ArrayBucketOutputStream extends ByteArrayOutputStream {
    private boolean hasBeenClosed = false;

    public ArrayBucketOutputStream() {
      super();
    }

    @Override
    public synchronized void close() throws IOException {
      if (hasBeenClosed) return;
      /*
       * Commit the buffered bytes first, then validate read‑only. This ordering
       * mirrors historical behavior: closing after read‑only toggle throws, but
       * the in‑memory contents are already replaced.
       */
      data.set(super.toByteArray());
      if (readOnly) throw new IOException("Read only");
      hasBeenClosed = true;
    }
  }

  /**
   * Check whether the bucket is read‑only.
   *
   * @return {@code true} if further calls to {@link #getOutputStream()} will fail
   */
  @Override
  public boolean isReadOnly() {
    return readOnly;
  }

  /**
   * Make the bucket read‑only. The change is irreversible for this instance.
   *
   * <p>Existing output streams obtained before this call may still commit data on {@link
   * OutputStream#close()}, but the close will then throw an {@link IOException}.
   */
  @Override
  public void setReadOnly() {
    readOnly = true;
  }

  /**
   * Free resources and mark the instance as unusable for further I/O.
   *
   * <p>After this call, {@link #getInputStream()} and {@link #getOutputStream()} throw {@link
   * IOException}. Methods that access the internal array directly (for example {@link #size()} and
   * {@link #toString()}) may fail with {@link NullPointerException}.
   */
  @Override
  public void free() {
    freed = true;
    data.set(null);
    // Nothing else to release – the backing array becomes eligible for GC.
  }

  /**
   * Return a defensive copy of the contents.
   *
   * @return a new array with the current bytes
   * @throws IOException if the bucket is already freed
   */
  public byte[] toByteArray() throws IOException {
    if (freed) throw new IOException("Already freed");
    long sz = size();
    int size = (int) sz;
    return Arrays.copyOf(data.get(), size);
  }

  /**
   * Shadow copy is not supported for this implementation.
   *
   * @return always {@code null}
   */
  @Override
  public RandomAccessBucket createShadow() {
    return null;
  }

  /**
   * No‑op hook for runtime resume.
   *
   * @param context runtime context; ignored
   */
  @Override
  public void onResume(ClientContext context) {
    // Do nothing.
  }

  /**
   * Persist this bucket to a {@link java.io.DataOutputStream}.
   *
   * <p>This implementation does not support persistence and always throws.
   *
   * @throws UnsupportedOperationException always
   */
  @Override
  public void storeTo(DataOutputStream dos) {
    // Not supported for persistent requests.
    throw new UnsupportedOperationException();
  }

  /**
   * Convert to a {@link LockableRandomAccessBuffer} and mark this bucket read‑only.
   *
   * <p>The returned buffer is a read‑only copy of the current contents; later writes to this bucket
   * (if ever allowed again) would not affect the buffer.
   *
   * @return a read‑only random‑access view containing a copy of the data
   */
  @Override
  public LockableRandomAccessBuffer toRandomAccessBuffer() {
    readOnly = true;
    byte[] buf = data.get();
    return new ByteArrayRandomAccessBuffer(buf, 0, buf.length, true);
  }

  /**
   * Unbuffered alias of {@link #getInputStream()}.
   *
   * @return an input stream over the contents
   * @throws IOException if the bucket is already freed
   */
  @Override
  public InputStream getInputStreamUnbuffered() throws IOException {
    return getInputStream();
  }

  /**
   * Unbuffered alias of {@link #getOutputStream()}.
   *
   * @return an output stream positioned at the start of the bucket
   * @throws IOException if the bucket is read‑only or already freed
   */
  @Override
  public OutputStream getOutputStreamUnbuffered() throws IOException {
    return getOutputStream();
  }
}

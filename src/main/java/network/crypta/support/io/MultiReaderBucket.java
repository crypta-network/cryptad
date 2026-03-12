package network.crypta.support.io;

import java.io.*;

import java.util.ArrayList;
import network.crypta.client.async.ClientContext;
import network.crypta.support.ListUtils;
import network.crypta.support.api.Bucket;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Provides multiple read-only views over a single {@link Bucket}.
 *
 * <p>This wrapper lets callers obtain several independent reader buckets (via {@link
 * #getReaderBucket()}) on top of one underlying, read-only {@link Bucket} instance. The underlying
 * data remains allocated until <em>every</em> reader bucket calls {@link Bucket#free()}. After the
 * last reader is freed, the wrapped bucket is freed exactly once and the {@code MultiReaderBucket}
 * becomes closed to further readers.
 *
 * <p>Concurrency and thread-safety:
 *
 * <ul>
 *   <li>Creation and lifecycle changes of reader buckets are synchronized on the {@code
 *       MultiReaderBucket} instance.
 *   <li>The {@link InputStream}s returned by reader buckets perform a liveness check but otherwise
 *       delegate directly to the underlying bucket streams; their I/O is not additionally
 *       synchronized here and follows the semantics of the underlying {@link Bucket}.
 * </ul>
 *
 * <p>Serialization:
 *
 * <ul>
 *   <li>{@code MultiReaderBucket} is {@link Serializable}. During serialization, the underlying
 *       bucket is serialized only if it is itself {@link Serializable}; otherwise a {@link
 *       NotSerializableException} is thrown.
 *   <li>Reader buckets are transient views and must be re-obtained after deserialization by calling
 *       {@link #getReaderBucket()}.
 * </ul>
 *
 * <p>Usage requirements and side effects:
 *
 * <ul>
 *   <li>Always call {@link Bucket#free()} on each reader bucket when finished to avoid leaking the
 *       underlying resource; lifecycle is explicit and there is no background cleanup.
 *   <li>Once closed (i.e., after all readers free themselves), subsequent calls to {@link
 *       #getReaderBucket()} return {@code null}.
 * </ul>
 *
 * <p>Why no {@code Cleaner}:
 *
 * <ul>
 *   <li>{@link java.lang.ref.Cleaner.Cleanable#clean() Cleanable.clean()} both unregisters the
 *       cleanable and executes the cleaning action immediately; there is no "deregister without
 *       running" operation. If a reader were to call {@code clean()} from its {@link Bucket#free()}
 *       implementation, it would execute the shared teardown and close the underlying bucket even
 *       while other readers are still active.
 *   <li>Reader buckets are tracked in a list owned by {@code MultiReaderBucket}. While a reader is
 *       present in that list, it remains strongly reachable and therefore is not eligible for a
 *       GC-triggered cleaner. A cleaner would thus not act as an automatic safety net for abandoned
 *       readers in this design.
 *   <li>Cleaner-triggered teardown is nondeterministic (depends on GC). The lifecycle must be
 *       deterministic here: the underlying is freed only after the last reader releases it.
 * </ul>
 *
 * <p>Consequently, the implementation uses explicit reference tracking (the {@code readers} list)
 * and synchronized updates to ensure the underlying bucket is freed exactly once when the final
 * reader calls {@link Bucket#free()}.
 *
 * @author toad
 */
public class MultiReaderBucket implements Serializable {
  private static final Logger LOG = LoggerFactory.getLogger(MultiReaderBucket.class);

  @Serial private static final long serialVersionUID = 1L;

  // Common log separator used in debug messages.
  private static final String FOR = " for ";

  // No cleaner is used: releasing the underlying bucket must occur only after the last
  // reader frees itself. A per-reader Cleaner would either never run (reader remains strongly
  // referenced by the parent list) or risk closing the parent prematurely if invoked directly.

  // The wrapped bucket may not be java.io.Serializable; keep it transient and handle
  // (de)serialization explicitly (see writeObject/readObject below).
  private transient Bucket bucket;

  // Assume there will be relatively few readers
  private ArrayList<Bucket> readers;

  private boolean closed;

  /**
   * Creates a wrapper over a read-only {@link Bucket} that supports multiple concurrent readers.
   *
   * @param underlying the underlying read-only bucket to expose to multiple readers; must not be
   *     {@code null}.
   */
  public MultiReaderBucket(Bucket underlying) {
    bucket = underlying;
  }

  /**
   * No-arg constructor for Java serialization frameworks.
   *
   * <p>Do not use directly in application code. The field {@code bucket} is initialized by {@link
   * #readObject(ObjectInputStream)}.
   */
  @SuppressWarnings("unused")
  protected MultiReaderBucket() {
    // For serialization.
    bucket = null;
  }

  /**
   * Returns a new read-only reader bucket over the same underlying data.
   *
   * <p>Each returned {@link Bucket} must be released by calling {@link Bucket#free()}. When the
   * last reader bucket is freed, this {@code MultiReaderBucket} closes and frees the underlying
   * resource exactly once. After closure, this method returns {@code null}.
   *
   * @return a new reader {@link Bucket}, or {@code null} if this wrapper has already been closed.
   */
  public Bucket getReaderBucket() {
    synchronized (this) {
      if (closed) return null;
      Bucket d = new ReaderBucket();
      if (readers == null) readers = new ArrayList<>(1);
      readers.add(d);
      if (LOG.isDebugEnabled())
        LOG.debug("getReaderBucket() returning {}" + FOR + "{}" + FOR + "{}", d, this, bucket);
      return d;
    }
  }

  class ReaderBucket implements Bucket, Serializable {

    @Serial private static final long serialVersionUID = 1L;
    private boolean freed;

    ReaderBucket() {
      // No Cleaner registration; lifecycle is explicit via free().
    }

    /**
     * Releases this reader bucket.
     *
     * <p>Idempotent: subsequent calls have no effect. When the last reader bucket is freed, the
     * underlying bucket is freed exactly once. This method does not throw.
     */
    @Override
    public void free() {
      if (LOG.isDebugEnabled())
        LOG.debug(
            "ReaderBucket {}" + FOR + "{} free()ing for {}", this, MultiReaderBucket.this, bucket);
      synchronized (MultiReaderBucket.this) {
        if (freed) return;
        freed = true;
        // Guard against null list before attempting removal.
        if (readers != null) {
          ListUtils.removeBySwapLast(readers, this);
          if (!readers.isEmpty()) {
            // Other readers remain; keep the underlying bucket alive.
            return;
          }
          readers = null;
        }
        if (closed) {
          return;
        }
        closed = true;
      }
      bucket.free();
    }

    /**
     * Opens a buffered {@link InputStream} over the underlying bucket for this reader.
     *
     * @return a buffered stream for reading.
     * @throws IOException if this reader has been freed or the wrapper is closed, or if the
     *     underlying bucket fails to open a stream.
     */
    @Override
    public InputStream getInputStream() throws IOException {
      synchronized (MultiReaderBucket.this) {
        if (freed || closed) {
          throw new IOException("Already freed");
        }
        return new ReaderBucketInputStream(true);
      }
    }

    /**
     * Opens an unbuffered {@link InputStream} over the underlying bucket for this reader.
     *
     * @return an unbuffered stream for reading.
     * @throws IOException if this reader has been freed or the wrapper is closed, or if the
     *     underlying bucket fails to open a stream.
     */
    @Override
    public InputStream getInputStreamUnbuffered() throws IOException {
      synchronized (MultiReaderBucket.this) {
        if (freed || closed) {
          throw new IOException("Already freed");
        }
        return new ReaderBucketInputStream(false);
      }
    }

    private final class ReaderBucketInputStream extends InputStream {

      InputStream is;

      ReaderBucketInputStream(boolean buffer) throws IOException {
        is = buffer ? bucket.getInputStream() : bucket.getInputStreamUnbuffered();
      }

      @Override
      public final int read() throws IOException {
        synchronized (MultiReaderBucket.this) {
          if (freed || closed) throw new IOException("Already closed");
        }
        return is.read();
      }

      @Override
      public final int read(byte @NotNull [] data, int offset, int length) throws IOException {
        synchronized (MultiReaderBucket.this) {
          if (freed || closed) throw new IOException("Already closed");
        }
        return is.read(data, offset, length);
      }

      @Override
      public final int read(byte @NotNull [] data) throws IOException {
        synchronized (MultiReaderBucket.this) {
          if (freed || closed) throw new IOException("Already closed");
        }
        return is.read(data);
      }

      @Override
      public final void close() throws IOException {
        is.close();
      }

      @Override
      public final int available() throws IOException {
        return is.available();
      }
    }

    /**
     * Returns the name of the underlying bucket for diagnostics.
     *
     * @return a name string as provided by the underlying {@link Bucket}.
     */
    @Override
    public String getName() {
      return bucket.getName();
    }

    /**
     * Not supported for reader buckets.
     *
     * @throws IOException always, because reader buckets are read-only.
     */
    @Override
    public OutputStream getOutputStream() throws IOException {
      throw new IOException("Read only");
    }

    /**
     * Not supported for reader buckets.
     *
     * @throws IOException always, because reader buckets are read-only.
     */
    @Override
    public OutputStream getOutputStreamUnbuffered() throws IOException {
      throw new IOException("Read only");
    }

    /**
     * Indicates that this bucket is read-only.
     *
     * @return always {@code true}.
     */
    @Override
    public boolean isReadOnly() {
      return true;
    }

    /** No-op because reader buckets are already read-only. */
    @Override
    public void setReadOnly() {
      // Already read-only.
    }

    /**
     * Returns the size in bytes as reported by the underlying bucket.
     *
     * @return size of the data in bytes.
     */
    @Override
    public long size() {
      return bucket.size();
    }

    /**
     * Reader buckets do not support shadows.
     *
     * @return always {@code null}.
     */
    @Override
    public Bucket createShadow() {
      return null;
    }

    /**
     * Not persistent; resuming is unsupported for reader buckets.
     *
     * @throws UnsupportedOperationException always.
     */
    @Override
    public void onResume(ClientContext context) throws ResumeFailedException {
      throw new UnsupportedOperationException(); // Not persistent.
    }

    /**
     * Not supported for reader buckets.
     *
     * @throws UnsupportedOperationException always.
     */
    @Override
    public void storeTo(DataOutputStream dos) throws IOException {
      throw new UnsupportedOperationException();
    }
  }

  /* ===== Java serialization support (patterned after DelayedFreeBucket) ===== */

  /**
   * Custom serialization that writes the underlying bucket only when it is {@link Serializable}.
   *
   * @param out the destination stream.
   * @throws IOException if the underlying bucket is not {@link Serializable} or an I/O error
   *     occurs.
   */
  @Serial
  private void writeObject(ObjectOutputStream out) throws IOException {
    out.defaultWriteObject();
    if (bucket instanceof Serializable serializable) {
      out.writeObject(serializable);
    } else {
      throw new NotSerializableException(
          bucket == null ? "nullBucket" : bucket.getClass().getName());
    }
  }

  /**
   * Complements {@link #writeObject(ObjectOutputStream)} by restoring the underlying bucket.
   *
   * @param in the source stream.
   * @throws IOException if an I/O error occurs.
   * @throws ClassNotFoundException if the serialized bucket class cannot be found.
   */
  @Serial
  private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    in.defaultReadObject();
    bucket = (Bucket) in.readObject();
  }
}

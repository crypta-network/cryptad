package network.crypta.support.io;

import java.io.*;

import network.crypta.client.async.ClientContext;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.api.RandomAccessBucket;

/**
 * A {@link Bucket} that discards all data written to it and produces no data when read. Intended as
 * a sink or placeholder where an object implementing {@link Bucket} is required but persistence or
 * real I/O is not desired.
 *
 * <p>Behavior summary:
 *
 * <ul>
 *   <li>Writes: {@link #getOutputStream()} and {@link #getOutputStreamUnbuffered()} return a
 *       stateless {@link NullOutputStream} that silently discards all bytes.
 *   <li>Reads: {@link #getInputStream()} and {@link #getInputStreamUnbuffered()} return a stateless
 *       {@link NullInputStream} that always reports end-of-file (EOF). The {@link #length} has no
 *       effect on read semantics.
 *   <li>Size: {@link #size()} returns the fixed {@link #length}. Writes do not change it.
 *   <li>Random access: {@link #toRandomAccessBuffer()} returns a {@link NullRandomAccessBuffer}
 *       whose size equals {@link #length} and whose reads fill zeros.
 *   <li>Lifecycle: {@link #setReadOnly()}, {@link #free()}, and {@link #onResume(ClientContext)}
 *       are no-ops.
 *   <li>Persistence: {@link #storeTo(DataOutputStream)} always throws {@link
 *       UnsupportedOperationException}.
 *   <li>Thread-safety: the singleton streams {@link #nullOut} and {@link #nullIn} are stateless and
 *       safe to share across threads.
 * </ul>
 *
 * <p>Note: While this class is {@link java.io.Serializable Serializable}, it does not support the
 * emergency recovery mechanism via {@link #storeTo(DataOutputStream)}.
 */
public class NullBucket implements Bucket, Serializable, RandomAccessBucket {

  @Serial private static final long serialVersionUID = 1L;

  /**
   * Shared no-op {@link OutputStream}. Writing to this stream discards all bytes. Immutable and
   * safe to reuse across threads.
   */
  public static final OutputStream nullOut = new NullOutputStream();

  /**
   * Shared EOF-only {@link InputStream}. Reading from this stream always returns {@code -1}.
   * Immutable and safe to reuse across threads.
   */
  public static final InputStream nullIn = new NullInputStream();

  /**
   * Fixed logical size in bytes reported by {@link #size()}. Not modified by writes, and does not
   * constrain reads (reads immediately hit EOF).
   */
  public final long length;

  /**
   * Construct a zero-length bucket.
   *
   * @see #NullBucket(long)
   */
  public NullBucket() {
    this(0);
  }

  /**
   * Construct a bucket that reports the given logical size.
   *
   * <p>The {@code length} affects only {@link #size()} and the size of the {@link
   * NullRandomAccessBuffer} returned by {@link #toRandomAccessBuffer()}. It does not change read
   * behavior, and writes are always discarded.
   *
   * @param length logical size in bytes (may be negative)
   */
  public NullBucket(long length) {
    this.length = length;
  }

  /**
   * Return a no-op {@link OutputStream} for writing.
   *
   * <p>All data written to the returned stream is ignored. Operations do not throw and have no side
   * effects.
   *
   * @return the shared {@link #nullOut} stream
   */
  @Override
  public OutputStream getOutputStream() {
    return nullOut;
  }

  /**
   * Return an unbuffered no-op {@link OutputStream}.
   *
   * <p>Semantics are identical to {@link #getOutputStream()} for this implementation.
   *
   * @return the shared {@link #nullOut} stream
   */
  @Override
  public OutputStream getOutputStreamUnbuffered() {
    return nullOut;
  }

  /**
   * Return an EOF-only {@link InputStream} for reading.
   *
   * <p>This implementation always returns the shared {@link #nullIn} and never returns {@code
   * null}. Reads immediately return {@code -1}, regardless of {@link #length}.
   *
   * @return the shared {@link #nullIn} stream
   */
  @Override
  public InputStream getInputStream() {
    return nullIn;
  }

  /**
   * Return an unbuffered EOF-only {@link InputStream}.
   *
   * <p>Semantics are identical to {@link #getInputStream()} for this implementation.
   *
   * @return the shared {@link #nullIn} stream
   */
  @Override
  public InputStream getInputStreamUnbuffered() {
    return nullIn;
  }

  /**
   * Return the fixed logical size in bytes.
   *
   * @return {@link #length}
   */
  @Override
  public long size() {
    return length;
  }

  /**
   * Return a human-readable identifier for this bucket.
   *
   * @return a constant string identifying this type
   */
  @Override
  public String getName() {
    return "President George W. NullBucket";
  }

  @Override
  public boolean isReadOnly() {
    return false;
  }

  /** No-op. There is no mutable read-only state to set. */
  @Override
  public void setReadOnly() {
    /* no-op */
  }

  /** No-op. There are no underlying resources to release. */
  @Override
  public void free() {
    /* no-op */
  }

  /**
   * Create a shallow read-only copy.
   *
   * <p>For this implementation the result is a fresh zero-length {@code NullBucket}.
   *
   * @return a new zero-length {@code NullBucket}
   */
  @Override
  public RandomAccessBucket createShadow() {
    return new NullBucket();
  }

  /**
   * No-op. There is no persisted state to restore after a restart.
   *
   * @param context runtime context; unused
   */
  @Override
  public void onResume(ClientContext context) {
    /* no-op */
  }

  /**
   * Unsupported for this type.
   *
   * <p>This bucket has nothing to persist and therefore cannot be reconstructed via the emergency
   * recovery mechanism.
   *
   * @param dos ignored
   * @throws UnsupportedOperationException always
   * @throws IOException never thrown by this implementation; declared by the interface
   */
  @Override
  public void storeTo(DataOutputStream dos) throws IOException {
    throw new UnsupportedOperationException();
  }

  /**
   * Convert to a zero-filling {@link LockableRandomAccessBuffer} whose size equals {@link #length}.
   *
   * @return a new {@link NullRandomAccessBuffer}
   * @throws IOException never thrown by this implementation; declared by the interface
   */
  @Override
  public LockableRandomAccessBuffer toRandomAccessBuffer() throws IOException {
    return new NullRandomAccessBuffer(length);
  }
}

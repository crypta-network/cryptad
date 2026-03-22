package network.crypta.support.io;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.Serial;
import java.io.Serializable;
import network.crypta.crypt.MasterSecret;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.api.ResumeContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A {@link RandomAccessBucket} wrapper whose {@link #free()} operation is deferred until after the
 * next successful persistence commit.
 *
 * <p>This class collaborates with a {@link PersistentFileTracker}: when {@link #free()} is called,
 * the wrapper is marked to be freed and the tracker is notified via {@link
 * PersistentFileTracker#delayedFree(DelayedFree, long)}. The underlying storage is only released
 * once the transaction that recorded the deletion is durably written. This avoids data loss when
 * the process stops between bookkeeping and checkpointing.
 *
 * <h2>Thread-safety</h2>
 *
 * Lifecycle flags are guarded by synchronization on {@code this}. Stream accessors check the {@code
 * freed} flag and throw {@link IOException} after the wrapper is freed.
 *
 * <h2>Persistence</h2>
 *
 * The wrapper is {@link Serializable}. The wrapped bucket is kept {@code transient} and is
 * serialized explicitly by Java serialization hooks ({@code writeObject}/{@code readObject}) and by
 * the project-specific mechanism {@link #storeTo(DataOutputStream)} / the restoring constructor
 * (identified by {@link #MAGIC} and {@link #VERSION}). The {@code createdCommitID} captured at
 * construction is {@code transient} by design; after Java deserialization it is {@code 0}, which
 * signals “pre-restart” to the tracker.
 *
 * @since 2
 */
public final class DelayedFreeRandomAccessBucket
    implements Bucket, Serializable, RandomAccessBucket, DelayedFree {

  private static final Logger LOG = LoggerFactory.getLogger(DelayedFreeRandomAccessBucket.class);

  @Serial private static final long serialVersionUID = 1L;
  // Set on construction and re-wired on onResume(); set once per lifecycle stage.
  private transient PersistentFileTracker factory;
  // Wrapped bucket may not be java.io.Serializable; handled via writeObject/readObject.
  private transient RandomAccessBucket bucket;
  // True once free() is requested; gates further stream operations and getUnderlying().
  private boolean freed;
  // Commit id captured at construction; 0 after Java deserialization means “pre-restart”.
  private transient long createdCommitID;

  /**
   * Indicates whether this wrapper has been marked for deferred freeing.
   *
   * @return {@code true} if {@link #free()} has been called; {@code false} otherwise
   */
  @Override
  public boolean toFree() {
    return freed;
  }

  /**
   * Creates a wrapper over a random-access bucket that will be freed after a commit.
   *
   * <p>The constructor captures {@link PersistentFileTracker#commitID()} to decide later whether
   * freeing can happen immediately or must be delayed until a subsequent commit.
   *
   * @param factory tracker that schedules and performs the eventual free
   * @param bucket wrapped bucket; must be non-{@code null}
   * @throws NullPointerException if {@code bucket} is {@code null}
   */
  public DelayedFreeRandomAccessBucket(PersistentFileTracker factory, RandomAccessBucket bucket) {
    this.factory = factory;
    this.bucket = bucket;
    this.createdCommitID = factory.commitID();
    if (bucket == null) throw new NullPointerException();
  }

  /**
   * Opens a buffered output stream positioned at offset 0.
   *
   * <p>Delegates to the wrapped bucket.
   *
   * @return buffered {@link OutputStream}
   * @throws IOException if this wrapper has already been freed, or if the underlying bucket fails
   *     to provide a stream
   */
  @Override
  public OutputStream getOutputStream() throws IOException {
    synchronized (this) {
      if (freed) throw new IOException("Already freed");
    }
    return bucket.getOutputStream();
  }

  /**
   * Opens an unbuffered output stream positioned at offset 0.
   *
   * @return unbuffered {@link OutputStream}
   * @throws IOException if this wrapper has already been freed, or if the underlying bucket fails
   *     to provide a stream
   */
  @Override
  public OutputStream getOutputStreamUnbuffered() throws IOException {
    synchronized (this) {
      if (freed) throw new IOException("Already freed");
    }
    return bucket.getOutputStreamUnbuffered();
  }

  /**
   * Opens a buffered input stream to read the bucket contents from the beginning.
   *
   * @return buffered {@link InputStream}
   * @throws IOException if this wrapper has already been freed, or if the underlying bucket fails
   *     to provide a stream
   */
  @Override
  public InputStream getInputStream() throws IOException {
    synchronized (this) {
      if (freed) throw new IOException("Already freed");
    }
    return bucket.getInputStream();
  }

  /**
   * Opens an unbuffered input stream to read the bucket contents from the beginning.
   *
   * @return unbuffered {@link InputStream}
   * @throws IOException if this wrapper has already been freed, or if the underlying bucket fails
   *     to provide a stream
   */
  @Override
  public InputStream getInputStreamUnbuffered() throws IOException {
    synchronized (this) {
      if (freed) throw new IOException("Already freed");
    }
    return bucket.getInputStreamUnbuffered();
  }

  /**
   * Returns the name of the wrapped bucket.
   *
   * @return name reported by the underlying bucket
   */
  @Override
  public String getName() {
    return bucket.getName();
  }

  /**
   * Returns the number of bytes currently stored in the wrapped bucket.
   *
   * @return size in bytes
   */
  @Override
  public long size() {
    return bucket.size();
  }

  /**
   * Indicates whether the wrapped bucket is read-only.
   *
   * @return {@code true} when further writes are disallowed
   */
  @Override
  public boolean isReadOnly() {
    return bucket.isReadOnly();
  }

  /** Makes the wrapped bucket read-only. */
  @Override
  public void setReadOnly() {
    bucket.setReadOnly();
  }

  /**
   * Returns the wrapped bucket if it is still usable.
   *
   * <p>Returns {@code null} if this wrapper has already been freed. The reference is not a stable
   * capability across threads and should be used immediately by the caller.
   *
   * @return the underlying bucket, or {@code null} if freed
   */
  public synchronized Bucket getUnderlying() {
    if (freed) return null;
    return bucket;
  }

  /**
   * Marks this wrapper to be freed after the next successful commit.
   *
   * <p>This method is idempotent. It notifies the {@link PersistentFileTracker}, which will call
   * {@link #realFree()} after the commit.
   */
  @Override
  public void free() {
    synchronized (this) {
      if (freed) return;
      freed = true;
    }
    if (LOG.isDebugEnabled()) LOG.debug("Freeing {} underlying={}", this, bucket);
    this.factory.delayedFree(this, createdCommitID);
  }

  /** Returns a debug-oriented string including the wrapped bucket. */
  @Override
  public String toString() {
    return super.toString() + ":" + bucket;
  }

  /**
   * Creates a read-only shallow copy of the wrapped bucket.
   *
   * <p>Delegates directly to the underlying bucket.
   *
   * @return a shadow bucket, or {@code null} if the underlying implementation cannot provide one
   */
  @Override
  public RandomAccessBucket createShadow() {
    return bucket.createShadow();
  }

  /**
   * Immediately frees the underlying bucket.
   *
   * <p>Called by {@link PersistentFileTracker} after a successful commit. Do not call directly
   * unless you are implementing the tracker.
   */
  @Override
  public void realFree() {
    bucket.free();
  }

  /**
   * Reattaches runtime state after a restart.
   *
   * <p>Wires the tracker from {@link ResumeContext#getPersistentFileTracker()} and delegates {@link
   * Bucket#onResume(ResumeContext)} to the wrapped bucket so it can register itself and avoid
   * premature collection.
   *
   * @param context runtime context providing the persistent file tracker
   * @throws ResumeFailedException if the wrapped bucket cannot be resumed
   */
  @Override
  public void onResume(ResumeContext context) throws ResumeFailedException {
    this.factory = context.getPersistentFileTracker();
    bucket.onResume(context);
  }

  static final int MAGIC = 0xa28f2a2d;
  static final int VERSION = 1;

  /**
   * Writes the minimal state required to reconstruct this wrapper.
   *
   * <p>Format: {@link #MAGIC} (int), {@link #VERSION} (int), followed by the wrapped bucket's
   * serialized form via {@link Bucket#storeTo(DataOutputStream)}.
   *
   * @param dos destination stream
   * @throws IOException if writing fails
   */
  @Override
  public void storeTo(DataOutputStream dos) throws IOException {
    dos.writeInt(MAGIC);
    dos.writeInt(VERSION);
    bucket.storeTo(dos);
  }

  /**
   * Reconstructs an instance from {@link #storeTo(DataOutputStream)} output.
   *
   * <p>The caller must have already consumed {@link #MAGIC}. This constructor validates the stored
   * {@link #VERSION} and restores the wrapped bucket via {@link BucketTools#restoreFrom}.
   *
   * @param dis source positioned at the version field
   * @param fg filename generator for nested bucket reconstruction
   * @param persistentFileTracker tracker used by nested bucket types
   * @param masterKey master secret used by encrypted buckets if present
   * @throws StorageFormatException if the stored format version is unknown or malformed
   * @throws IOException on I/O errors
   * @throws ResumeFailedException if nested buckets cannot be resumed
   */
  DelayedFreeRandomAccessBucket(
      DataInputStream dis,
      FilenameGenerator fg,
      PersistentFileTracker persistentFileTracker,
      MasterSecret masterKey)
      throws StorageFormatException, IOException, ResumeFailedException {
    int version = dis.readInt();
    if (version != VERSION) throw new StorageFormatException("Bad version");
    bucket =
        (RandomAccessBucket) BucketTools.restoreFrom(dis, fg, persistentFileTracker, masterKey);
  }

  /**
   * Converts this bucket to a lockable random-access buffer without copying.
   *
   * <p>This method sets the wrapped bucket read-only before converting. The returned buffer is
   * wrapped in {@link DelayedFreeRandomAccessBuffer} so its {@link
   * DelayedFreeRandomAccessBuffer#free()} is also deferred until the next commit.
   *
   * @return a lockable random-access buffer sharing the same storage
   * @throws IOException if this wrapper has already been freed, or if the underlying conversion
   *     fails
   */
  @Override
  public LockableRandomAccessBuffer toRandomAccessBuffer() throws IOException {
    synchronized (this) {
      if (freed) throw new IOException("Already freed");
    }
    setReadOnly();
    return new DelayedFreeRandomAccessBuffer(bucket.toRandomAccessBuffer(), factory);
  }

  /* ===== Java serialization support ===== */

  @Serial
  private void writeObject(ObjectOutputStream out) throws IOException {
    out.defaultWriteObject();
    if (bucket instanceof Serializable serializable) {
      out.writeObject(serializable);
    } else {
      throw new java.io.NotSerializableException(
          bucket == null ? "nullBucket" : bucket.getClass().getName());
    }
  }

  @Serial
  private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    in.defaultReadObject();
    bucket = (RandomAccessBucket) in.readObject();
  }
}

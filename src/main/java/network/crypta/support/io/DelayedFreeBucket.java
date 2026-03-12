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
import network.crypta.client.async.ClientContext;
import network.crypta.crypt.MasterSecret;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.RandomAccessBucket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A {@link Bucket} wrapper that defers deletion of its underlying resources until the next
 * successful persistence commit.
 *
 * <p>This class marks buckets for deferred freeing via {@link PersistentFileTracker#delayedFree}.
 * The tracker will actually call {@link #realFree()} only after the transaction that recorded the
 * deletion has been written to disk. This avoids data loss when the process stops between marking
 * and checkpointing.
 *
 * <p>Thread-safety: methods that change or read the lifecycle state synchronize on {@code this}.
 * Once {@code freed} is set, stream accessors throw {@link IOException}. After a successful
 * migration to a random-access variant, stream accessors also throw to avoid using the old wrapper
 * concurrently with the new one.
 *
 * <p>Serialization: this class is {@link Serializable}, but the wrapped {@link Bucket} is kept
 * {@code transient} and is persisted through {@link #storeTo(DataOutputStream)} / the matching
 * restoring constructor. The {@code createdCommitID} recorded at construction is transient on
 * purpose; when an instance is restored, it is 0, which signals “created before the last restart”
 * to {@link PersistentFileTracker#delayedFree(DelayedFree, long)}.
 */
public final class DelayedFreeBucket implements Bucket, Serializable, DelayedFree {
  private static final Logger LOG = LoggerFactory.getLogger(DelayedFreeBucket.class);

  @Serial private static final long serialVersionUID = 1L;
  // Set on construction and when resuming; access is guarded by outer synchronization when needed.
  private transient PersistentFileTracker factory;
  // Wrapped bucket may not be java.io.Serializable; persisted via Java serialization hooks.
  private transient Bucket bucket;
  // True once free() is requested; gating flag for stream accessors and getUnderlying().
  private boolean freed;

  /**
   * Set to {@code true} after a successful {@link #toRandomAccessBucket()} migration. When true the
   * old wrapper must no longer expose streams or be freed, because the new {@link
   * DelayedFreeRandomAccessBucket} shares the underlying random-access storage.
   */
  private boolean migrated;

  // Commit id captured at construction. Transient by design: restored instances use 0 which
  // means “pre-restart” for the tracker and allows immediate freeing when appropriate.
  private transient long createdCommitID;

  // No static initialization required.

  /**
   * Indicates whether this wrapper has been marked for deferred freeing.
   *
   * <p>When {@code true}, the {@link PersistentFileTracker} will call {@link #realFree()} after the
   * next successful commit. Until then, the underlying bucket is still present but stream accessors
   * will throw.
   *
   * @return {@code true} if {@link #free()} has been called; {@code false} otherwise
   */
  @Override
  public synchronized boolean toFree() {
    return freed;
  }

  /**
   * Creates a wrapper over a bucket that will be freed after a commit.
   *
   * <p>The constructor captures {@link PersistentFileTracker#commitID()} to decide later whether
   * freeing can happen immediately or must be delayed until a subsequent commit.
   *
   * @param factory tracker that schedules and performs the eventual free
   * @param bucket wrapped bucket; must be non-{@code null}
   * @throws NullPointerException if {@code bucket} is {@code null}
   */
  public DelayedFreeBucket(PersistentFileTracker factory, Bucket bucket) {
    this.factory = factory;
    this.bucket = bucket;
    this.createdCommitID = factory.commitID();
    if (bucket == null) throw new NullPointerException();
  }

  /**
   * Opens a buffered output stream positioned at offset 0.
   *
   * <p>Delegates to the wrapped bucket. Fails if the wrapper was freed or migrated to a
   * random-access variant.
   *
   * @return buffered {@link OutputStream}
   * @throws IOException if the wrapper is freed or migrated, or if the underlying bucket fails to
   *     provide a stream
   */
  @Override
  public OutputStream getOutputStream() throws IOException {
    synchronized (this) {
      if (migrated) throw new IOException("Already migrated to a RandomAccessBucket");
      if (freed) throw new IOException("Already freed");
    }
    return bucket.getOutputStream();
  }

  /**
   * Opens an unbuffered output stream positioned at offset 0.
   *
   * @return unbuffered {@link OutputStream}
   * @throws IOException if the wrapper is freed or migrated, or if the underlying bucket fails to
   *     provide a stream
   */
  @Override
  public OutputStream getOutputStreamUnbuffered() throws IOException {
    synchronized (this) {
      if (migrated) throw new IOException("Already migrated to a RandomAccessBucket");
      if (freed) throw new IOException("Already freed");
    }
    return bucket.getOutputStreamUnbuffered();
  }

  /**
   * Opens a buffered input stream to read the bucket contents from the beginning.
   *
   * @return buffered {@link InputStream}
   * @throws IOException if the wrapper is freed or migrated, or if the underlying bucket fails to
   *     provide a stream
   */
  @Override
  public InputStream getInputStream() throws IOException {
    synchronized (this) {
      if (migrated) throw new IOException("Already migrated to a RandomAccessBucket");
      if (freed) throw new IOException("Already freed");
    }
    return bucket.getInputStream();
  }

  /**
   * Opens an unbuffered input stream to read the bucket contents from the beginning.
   *
   * @return unbuffered {@link InputStream}
   * @throws IOException if the wrapper is freed or migrated, or if the underlying bucket fails to
   *     provide a stream
   */
  @Override
  public InputStream getInputStreamUnbuffered() throws IOException {
    synchronized (this) {
      if (migrated) throw new IOException("Already migrated to a RandomAccessBucket");
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
   * <p>Returns {@code null} if this wrapper has already been freed or migrated to a random-access
   * variant. The reference is not a stable capability across threads and should be used immediately
   * by the caller.
   *
   * @return the underlying bucket, or {@code null} if freed or migrated
   */
  public synchronized Bucket getUnderlying() {
    if (freed) return null;
    if (migrated) return null;
    return bucket;
  }

  /**
   * Marks this wrapper to be freed after the next successful commit.
   *
   * <p>This method is idempotent. If the wrapper has already migrated to a random-access variant,
   * the call is ignored because the new wrapper is responsible for freeing shared resources.
   */
  @Override
  public void free() {
    synchronized (this) {
      if (freed) return;
      if (migrated) return;
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
  public Bucket createShadow() {
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
   * <p>Wires the tracker from {@link ClientContext#persistentBucketFactory} and delegates {@link
   * Bucket#onResume(ClientContext)} to the wrapped bucket so it can register itself and avoid
   * premature collection.
   *
   * @param context runtime context providing the persistent bucket factory
   * @throws ResumeFailedException if the wrapped bucket cannot be resumed
   */
  @Override
  public void onResume(ClientContext context) throws ResumeFailedException {
    this.factory = context.persistentBucketFactory;
    bucket.onResume(context);
  }

  // Persistence marker and on-disk schema version for this wrapper.
  static final int MAGIC = 0x4e9c9a03;
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
  DelayedFreeBucket(
      DataInputStream dis,
      FilenameGenerator fg,
      PersistentFileTracker persistentFileTracker,
      MasterSecret masterKey)
      throws StorageFormatException, IOException, ResumeFailedException {
    int version = dis.readInt();
    if (version != VERSION) throw new StorageFormatException("Bad version");
    bucket = BucketTools.restoreFrom(dis, fg, persistentFileTracker, masterKey);
  }

  /**
   * Attempts to convert the wrapped bucket to a {@link RandomAccessBucket} without copying.
   *
   * <p>If the underlying implementation already is a {@link RandomAccessBucket}, this method marks
   * the wrapper as migrated and returns a {@link DelayedFreeRandomAccessBucket} that shares the
   * same storage. Otherwise, it returns {@code null} to signal that a copy-based conversion is
   * required by callers.
   *
   * @return a delayed-free random-access wrapper, or {@code null} when not directly convertible
   * @throws IOException if this wrapper was already freed
   */
  public synchronized RandomAccessBucket toRandomAccessBucket() throws IOException {
    if (freed) throw new IOException("Already freed");
    if (bucket instanceof RandomAccessBucket accessBucket) {
      migrated = true;
      return new DelayedFreeRandomAccessBucket(factory, accessBucket);
      // Underlying file is already registered.
    }
    return null;
  }

  /* ===== Java serialization support ===== */

  /**
   * Writes default state and the wrapped bucket so that Java serialization can restore it.
   *
   * @param out destination stream
   * @throws IOException on I/O errors
   */
  @Serial
  private void writeObject(ObjectOutputStream out) throws IOException {
    out.defaultWriteObject();
    if (bucket instanceof Serializable serializable) {
      out.writeObject(serializable);
    } else {
      // Do not attempt to serialize non-serializable implementations.
      throw new java.io.NotSerializableException(
          bucket == null ? "nullBucket" : bucket.getClass().getName());
    }
  }

  /**
   * Restores default state and the wrapped bucket written by {@link #writeObject}.
   *
   * @param in source stream
   * @throws IOException on I/O errors
   * @throws ClassNotFoundException if the bucket class is unavailable
   */
  @Serial
  private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    in.defaultReadObject();
    bucket = (Bucket) in.readObject();
  }
}

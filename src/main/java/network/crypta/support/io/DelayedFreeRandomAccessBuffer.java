package network.crypta.support.io;

import java.io.*;
import network.crypta.client.async.ClientContext;
import network.crypta.crypt.MasterSecret;
import network.crypta.support.api.LockableRandomAccessBuffer;

/**
 * A {@link LockableRandomAccessBuffer} wrapper whose {@link #free()} is deferred until after the
 * next successful persistence commit.
 *
 * <p>When {@link #free()} is requested, this wrapper notifies a {@link PersistentFileTracker},
 * which will call {@link #realFree()} only after the transaction recording the deletion has been
 * durably written. This reduces the risk of losing bookkeeping during crashes between mutation and
 * checkpointing.
 *
 * <h2>Thread-safety</h2>
 *
 * Access to the {@code freed} lifecycle flag is synchronized on {@code this}. All I/O methods check
 * the flag and throw {@link IOException} once the wrapper is freed. Otherwise, operations delegate
 * directly to the underlying buffer.
 *
 * <h2>Persistence</h2>
 *
 * This class is {@link Serializable}. It also supports project-level persistence via {@link
 * #storeTo(DataOutputStream)} and the restoring constructor that uses {@link
 * BucketTools#restoreRAFFrom(DataInputStream, FilenameGenerator, PersistentFileTracker,
 * MasterSecret)}. The {@code createdCommitID} captured at construction is transient by design and
 * becomes {@code 0} after Java deserialization, which the tracker interprets as "pre-restart".
 *
 * @since 2
 */
public class DelayedFreeRandomAccessBuffer
    implements LockableRandomAccessBuffer, Serializable, DelayedFree {
  @Serial private static final long serialVersionUID = 1L;
  // Underlying random-access buffer being wrapped and delegated to. Not always Serializable; we
  // handle it via Java serialization hooks below.
  private transient LockableRandomAccessBuffer underlying;
  // Set to true after free() is requested; guards further I/O and query methods.
  private boolean freed;
  // Re-wired on onResume(); not part of the serialized state.
  private transient PersistentFileTracker factory;
  // Commit id captured at construction; transient so restored instances are treated as pre-restart.
  private transient long createdCommitID;

  /**
   * Creates a wrapper around a lockable random-access buffer that will be freed after a commit.
   *
   * <p>The constructor captures {@link PersistentFileTracker#commitID()} to decide later whether
   * the free can happen immediately or must be delayed until a subsequent commit.
   *
   * @param raf underlying buffer; must be non-{@code null}
   * @param factory tracker responsible for deferred freeing
   */
  public DelayedFreeRandomAccessBuffer(
      LockableRandomAccessBuffer raf, PersistentFileTracker factory) {
    underlying = raf;
    this.createdCommitID = factory.commitID();
    this.factory = factory;
  }

  /**
   * Returns the current size of the underlying buffer in bytes.
   *
   * @return size in bytes
   */
  @Override
  public long size() {
    return underlying.size();
  }

  /**
   * Reads {@code length} bytes starting at {@code fileOffset} into {@code buf}.
   *
   * <p>Throws if the wrapper has been freed; otherwise delegates to the underlying buffer.
   *
   * @param fileOffset absolute byte offset within the buffer (0-based)
   * @param buf destination array
   * @param bufOffset offset into {@code buf}
   * @param length number of bytes to read
   * @throws IOException if this wrapper is freed or if the underlying read fails
   */
  @Override
  public void pread(long fileOffset, byte[] buf, int bufOffset, int length) throws IOException {
    synchronized (this) {
      if (freed) throw new IOException("Already freed");
    }
    underlying.pread(fileOffset, buf, bufOffset, length);
  }

  /**
   * Writes {@code length} bytes from {@code buf} at {@code fileOffset}.
   *
   * <p>Throws if the wrapper has been freed; otherwise delegates to the underlying buffer.
   *
   * @param fileOffset absolute byte offset within the buffer (0-based)
   * @param buf source array
   * @param bufOffset offset into {@code buf}
   * @param length number of bytes to write
   * @throws IOException if this wrapper is freed or if the underlying write fails
   */
  @Override
  public void pwrite(long fileOffset, byte[] buf, int bufOffset, int length) throws IOException {
    synchronized (this) {
      if (freed) throw new IOException("Already freed");
    }
    underlying.pwrite(fileOffset, buf, bufOffset, length);
  }

  /**
   * Closes the underlying buffer if not already freed.
   *
   * <p>If {@link #free()} has been called, the close is ignored to avoid racing with deferred
   * freeing.
   */
  @Override
  public void close() {
    synchronized (this) {
      if (freed) return;
    }
    underlying.close();
  }

  /**
   * Marks this wrapper to be freed after the next successful commit.
   *
   * <p>This method is idempotent. It notifies the tracker, which will call {@link #realFree()}
   * after the commit.
   */
  @Override
  public void free() {
    synchronized (this) {
      if (freed) return;
      freed = true;
    }
    this.factory.delayedFree(this, createdCommitID);
  }

  /**
   * Locks the underlying buffer open for a short period.
   *
   * <p>Throws if the wrapper has been freed; otherwise delegates to the underlying buffer.
   *
   * @return a lock handle that must be released by calling {@link RAFLock#unlock()}
   * @throws IOException if this wrapper is freed or if the underlying allocation fails
   */
  @Override
  public RAFLock lockOpen() throws IOException {
    synchronized (this) {
      if (freed) throw new IOException("Already freed");
    }
    return underlying.lockOpen();
  }

  /**
   * Reattaches runtime state after a restart.
   *
   * <p>Wires the tracker from {@link ClientContext#persistentBucketFactory} and delegates to the
   * underlying buffer so it can register itself and avoid premature collection.
   *
   * @param context runtime context providing the persistent bucket factory
   * @throws ResumeFailedException if the underlying buffer cannot be resumed
   */
  @Override
  public void onResume(ClientContext context) throws ResumeFailedException {
    this.factory = context.persistentBucketFactory;
    underlying.onResume(context);
  }

  /** Persistence marker for this wrapper when using {@link #storeTo(DataOutputStream)}. */
  static final int MAGIC = 0x3fb645de;

  /**
   * Writes the minimal state required to reconstruct this wrapper.
   *
   * <p>Format: {@link #MAGIC} (int) followed by the underlying buffer's serialized form via {@link
   * LockableRandomAccessBuffer#storeTo(DataOutputStream)}.
   *
   * @param dos destination stream
   * @throws IOException if writing fails
   */
  @Override
  public void storeTo(DataOutputStream dos) throws IOException {
    dos.writeInt(MAGIC);
    underlying.storeTo(dos);
  }

  /**
   * Reconstructs an instance from the output of {@link #storeTo(DataOutputStream)}.
   *
   * <p>The caller must have already consumed {@link #MAGIC}. The underlying buffer is restored via
   * {@link BucketTools#restoreRAFFrom(DataInputStream, FilenameGenerator, PersistentFileTracker,
   * MasterSecret)} and the tracker is set to the provided {@code persistentFileTracker}.
   *
   * @param dis source stream positioned after {@link #MAGIC}
   * @param fg filename generator for nested reconstruction
   * @param persistentFileTracker tracker passed along to nested types
   * @param masterSecret node's master secret when required by encrypted buffers
   * @throws IOException on I/O errors
   * @throws StorageFormatException if the stored format is unknown or malformed
   * @throws ResumeFailedException if nested buffers cannot be resumed
   */
  public DelayedFreeRandomAccessBuffer(
      DataInputStream dis,
      FilenameGenerator fg,
      PersistentFileTracker persistentFileTracker,
      MasterSecret masterSecret)
      throws IOException, StorageFormatException, ResumeFailedException {
    underlying = BucketTools.restoreRAFFrom(dis, fg, persistentFileTracker, masterSecret);
    factory = persistentFileTracker;
  }

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
   * Returns the wrapped buffer if it is still usable.
   *
   * <p>Returns {@code null} after {@link #free()} has been called. The returned reference is not a
   * stable capability across threads and should be used immediately by the caller.
   *
   * @return the underlying buffer, or {@code null} if freed
   */
  public LockableRandomAccessBuffer getUnderlying() {
    if (freed) return null;
    return underlying;
  }

  /**
   * Immediately frees the underlying buffer.
   *
   * <p>Called by {@link PersistentFileTracker} after a successful commit. Do not call directly
   * unless you are implementing the tracker.
   */
  @Override
  public void realFree() {
    underlying.free();
  }

  /**
   * Returns the hash code of the underlying buffer.
   *
   * @return hash code derived from the wrapped buffer
   */
  @Override
  public int hashCode() {
    return underlying.hashCode();
  }

  /**
   * Compares wrappers by the identity of their underlying buffers.
   *
   * <p>Two delayed-free wrappers may reference the same restored buffer after a resume; they should
   * then compare as equal.
   */
  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (!(obj instanceof DelayedFreeRandomAccessBuffer other)) {
      return false;
    }
    return underlying.equals(other.underlying);
  }

  /* ===== Java serialization support ===== */

  @Serial
  private void writeObject(ObjectOutputStream out) throws IOException {
    out.defaultWriteObject();
    if (underlying instanceof Serializable serializable) {
      out.writeObject(serializable);
    } else {
      throw new NotSerializableException(
          underlying == null ? "nullUnderlying" : underlying.getClass().getName());
    }
  }

  @Serial
  private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    in.defaultReadObject();
    underlying = (LockableRandomAccessBuffer) in.readObject();
  }
}

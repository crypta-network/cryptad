package network.crypta.support.io;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.io.ObjectInputStream;
import java.io.RandomAccessFile;
import java.io.Serial;
import java.io.Serializable;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.Iterator;
import java.util.LinkedHashSet;
import network.crypta.support.WrapperKeepalive;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.api.ResumeContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Random-access file buffer that uses a global pool to cap the number of open file descriptors.
 *
 * <p>Purpose: provides {@link RandomAccessFile}-style, fixed-length pread/pwrite while multiplexing
 * a limited number of OS descriptors across instances. Callers can keep a descriptor open for a
 * short critical section via {@link #lockOpen()}.
 *
 * <p>Concurrency: instances coordinate through a shared {@code FDTracker}. Pool coordination is
 * synchronized on a final monitor ({@code fds.lock}). A lock from {@link #lockOpen()} controls only
 * lifetime in the pool; it does not serialize I/O. Individual I/O calls synchronize on {@code this}
 * around {@link RandomAccessFile#seek(long)} and the further read/write.
 *
 * <p>Resource management: call {@link #close()} when done. If {@code deleteOnFree} is true, {@link
 * #free()} deletes the file (securely when {@link #setSecureDelete(boolean)} is enabled). Closing
 * while holding a pool lock throws {@link IllegalStateException}.
 *
 * <p>Serialization/resume: a compact descriptor can be written with {@link #storeTo} and restored
 * via the {@linkplain #PooledFileRandomAccessBuffer(DataInputStream, PersistentFilenameGenerator,
 * PersistentFileTracker) persistence constructor}. {@link #onResume(ResumeContext)} validates and
 * re-registers persistent-temp files.
 *
 * <p>Shutdown: this type does not rely on a shutdown hook. Descriptors are reclaimed via explicit
 * close/free and by the JVM on process exit.
 */
public final class PooledFileRandomAccessBuffer
    implements LockableRandomAccessBuffer, Serializable {
  private static final Logger LOG = LoggerFactory.getLogger(PooledFileRandomAccessBuffer.class);
  private static final SecureRandom SECURE_DELETE_RANDOM = new SecureRandom();

  @Serial private static final long serialVersionUID = 1L;

  /**
   * Tracks pooled descriptor usage and the set of buffers eligible to be closed to free capacity.
   *
   * <p>Thread-safety: all members are guarded by {@link #lock}. Callers must synchronize on that
   * monitor when accessing or mutating the state.
   */
  static class FDTracker implements Serializable {
    @Serial private static final long serialVersionUID = 1L;

    private int maxOpenFDs;
    private int totalOpenFDs = 0;
    private final LinkedHashSet<PooledFileRandomAccessBuffer> closables = new LinkedHashSet<>();

    /** Monitor used for coordinating access to this tracker; not serialized. */
    transient Object lock = new Object();

    FDTracker(int maxOpenFDs) {
      this.maxOpenFDs = maxOpenFDs;
    }

    /**
     * Custom deserialization to restore the transient monitor.
     *
     * @param in source stream
     * @throws IOException on I/O errors
     * @throws ClassNotFoundException if a serialized type cannot be resolved
     */
    @Serial
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
      in.defaultReadObject();
      // Recreate the monitor because transient fields are not restored by default.
      lock = new Object();
    }

    /** Set the maximum number of file descriptors the pool may hold at once. */
    @SuppressWarnings("unused")
    void setMaxFDs(int max) {
      final Object monitor = lock;
      synchronized (monitor) {
        if (max <= 0) throw new IllegalArgumentException();
        maxOpenFDs = max;
      }
    }

    /** Return the number of file descriptors currently open in this pool. */
    @SuppressWarnings("unused")
    int getOpenFDs() {
      final Object monitor = lock;
      synchronized (monitor) {
        return totalOpenFDs;
      }
    }

    int getClosableFDs() {
      final Object monitor = lock;
      synchronized (monitor) {
        return closables.size();
      }
    }
  }

  // static variables are always transient
  private static final FDTracker DEFAULT_FDTRACKER = new FDTracker(100);
  private transient FDTracker fds;

  /**
   * Path to the backing file. Never {@code null} for regular instances; may be {@code null} only in
   * the serialization constructor.
   */
  public final File file;

  private final boolean readOnly;

  // > 0 means this instance currently holds a pool lock. Guarded by fds.lock.
  private int lockLevel;

  // The current RandomAccessFile, or null when closed or evicted. Guarded by this.
  // Always acquire fds.lock before synchronizing on this to avoid deadlocks.
  private transient RandomAccessFile raf;

  private final long length;
  private boolean closed;

  // -1 when not a persistent-temp file; otherwise an ID to allow relocation across prefix changes.
  private final long persistentTempID;

  private volatile boolean secureDelete;
  private final boolean deleteOnFree;

  /**
   * Construct a pooled random‑access buffer over an existing file with optional preallocation.
   *
   * <p>Behavior:
   *
   * <ul>
   *   <li>If {@code forceLength} is {@code >= 0} and differs from the current file size, the file
   *       is extended or truncated to that size. On supported platforms a native preallocation is
   *       attempted; otherwise a portable fallback is used.
   *   <li>When {@code readOnly} is {@code true}, supplying a conflicting {@code forceLength}
   *       results in an {@link IOException}.
   *   <li>The instance participates in a global pool that limits concurrently open descriptors. The
   *       constructor opens the file, performs any required preallocation, and then releases its
   *       pool lock so the descriptor becomes eligible for reuse/eviction.
   * </ul>
   *
   * <p>Threading: construction may block briefly while acquiring a pool slot. After construction,
   * I/O calls are thread‑safe as described in the class documentation.
   *
   * <p>Postconditions: {@link #size()} equals the on‑disk size after any preallocation/truncation.
   * The descriptor may or may not remain open depending on pool pressure.
   *
   * @param file non‑null path to the target file (must exist and be readable; writable when {@code
   *     readOnly == false})
   * @param readOnly if {@code true}, further calls to {@link #pwrite(long, byte[], int, int)} fail
   *     with {@link IOException}
   * @param forceLength desired size in bytes, or {@code -1} to keep the current size
   * @param persistentTempID persistent‑temp identifier used during resume ({@code -1} for none)
   * @param deleteOnFree if {@code true}, {@link #free()} deletes the backing file (securely when
   *     {@link #setSecureDelete(boolean)} is enabled)
   * @throws IOException if the file cannot be opened, preallocated, resized, or if a conflicting
   *     {@code forceLength} is specified while {@code readOnly == true}
   */
  public PooledFileRandomAccessBuffer(
      File file, boolean readOnly, long forceLength, long persistentTempID, boolean deleteOnFree)
      throws IOException {
    this(file, readOnly, forceLength, persistentTempID, deleteOnFree, DEFAULT_FDTRACKER);
  }

  // For unit testing
  PooledFileRandomAccessBuffer(
      File file,
      boolean readOnly,
      long forceLength,
      long persistentTempID,
      boolean deleteOnFree,
      FDTracker fds)
      throws IOException {
    this.file = file;
    this.readOnly = readOnly;
    this.persistentTempID = persistentTempID;
    this.deleteOnFree = deleteOnFree;
    this.fds = fds;
    lockLevel = 0;
    // Check the parameters and get the length.
    // Also, unlock() adds to the closeable queue, which is essential.
    RAFLock lock = lockOpen();
    try {
      long currentLength = raf.length();
      if (forceLength >= 0 && forceLength != currentLength) {
        if (readOnly) throw new IOException("Read only but wrong length");
        // Preallocate space. We want predictable disk usage, not minimal disk usage, especially for
        // downloads.
        try (WrapperKeepalive wrapperKeepalive = new WrapperKeepalive()) {
          wrapperKeepalive.start();
          // freenet-mobile-changed: Passing a file descriptor to avoid using reflection
          Fallocate.forChannel(raf.getChannel(), raf.getFD(), forceLength)
              .fromOffset(currentLength)
              .execute();
        }
        raf.setLength(forceLength);
        currentLength = forceLength;
      }
      this.length = currentLength;
      lock.unlock();
    } catch (IOException | RuntimeException e) {
      cleanupAfterConstructorFailure(lock, e);
      throw e;
    }
  }

  public PooledFileRandomAccessBuffer(
      File file,
      byte[] initialContents,
      int offset,
      int size,
      long persistentTempID,
      boolean deleteOnFree,
      boolean readOnly)
      throws IOException {
    this.file = file;
    this.readOnly = readOnly;
    this.length = size;
    this.persistentTempID = persistentTempID;
    this.deleteOnFree = deleteOnFree;
    this.fds = DEFAULT_FDTRACKER;
    lockLevel = 0;
    RAFLock lock = lockOpen(true);
    try {
      raf.write(initialContents, offset, size);
      lock.unlock();
    } catch (IOException | RuntimeException e) {
      cleanupAfterConstructorFailure(lock, e);
      throw e;
    }
  }

  /**
   * Best-effort rollback for constructor failures.
   *
   * <p>When construction fails after acquiring a pool lock, the partially initialized instance can
   * otherwise leak an open descriptor and lock state. This helper tries to unlock and close through
   * the normal lifecycle; if that fails, it force-closes the underlying RAF state while preserving
   * the original exception.
   */
  private void cleanupAfterConstructorFailure(RAFLock lock, Throwable failure) {
    try {
      lock.unlock();
    } catch (RuntimeException unlockFailure) {
      failure.addSuppressed(unlockFailure);
    }

    try {
      close();
      return;
    } catch (RuntimeException closeFailure) {
      failure.addSuppressed(closeFailure);
    }

    final Object monitor = fds.lock;
    synchronized (monitor) {
      lockLevel = 0;
      closed = true;
      fds.closables.remove(this);
      closeRAF();
      monitor.notifyAll();
    }
  }

  /**
   * Serialization‑only constructor used by deserialization frameworks.
   *
   * <p>Do not call directly. {@link #readObject(ObjectInputStream)} rebinds transient fields after
   * construction.
   */
  @SuppressWarnings("unused")
  PooledFileRandomAccessBuffer() {
    file = null;
    readOnly = false;
    length = 0;
    persistentTempID = -1;
    deleteOnFree = false;
    fds = null;
  }

  /**
   * Custom deserialization; rebinds the transient pool tracker to the shared default instance.
   *
   * @param in source stream
   * @throws IOException on I/O errors
   * @throws ClassNotFoundException if a serialized type cannot be resolved
   */
  @Serial
  private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    in.defaultReadObject();
    this.fds = DEFAULT_FDTRACKER;
  }

  /**
   * Return the fixed size of the buffer in bytes.
   *
   * @return number of bytes; never negative
   */
  @Override
  public long size() {
    return length;
  }

  /**
   * Read {@code length} bytes starting at {@code fileOffset} into {@code buf}.
   *
   * <p>Blocks until all requested bytes are read or an exception is thrown. {@code buf} must have
   * at least {@code bufOffset + length} bytes available.
   *
   * @param fileOffset absolute position in the file; must be {@code >= 0}
   * @param buf destination array
   * @param bufOffset offset within {@code buf}
   * @param length number of bytes to read
   * @throws IllegalArgumentException if {@code fileOffset < 0}
   * @throws IOException if an I/O error occurs, or EOF is reached before all bytes are read
   */
  @Override
  public void pread(long fileOffset, byte[] buf, int bufOffset, int length) throws IOException {
    if (fileOffset < 0) throw new IllegalArgumentException();
    RAFLock lock = lockOpen();
    try {
      // Use RandomAccessFile for predictable semantics and compatibility.
      synchronized (this) {
        raf.seek(fileOffset);
        raf.readFully(buf, bufOffset, length);
      }
    } finally {
      lock.unlock();
    }
  }

  /**
   * Write {@code length} bytes from {@code buf} at {@code fileOffset}.
   *
   * <p>Writes must remain within the fixed size established at construction time. When {@code
   * readOnly} is {@code true}, all writes fail.
   *
   * @param fileOffset absolute position in the file; must be {@code >= 0}
   * @param buf source array
   * @param bufOffset offset within {@code buf}
   * @param length number of bytes to write
   * @throws IllegalArgumentException if {@code fileOffset < 0}
   * @throws IOException if the buffer is read-only, or if the writing would exceed the fixed length
   */
  @Override
  public void pwrite(long fileOffset, byte[] buf, int bufOffset, int length) throws IOException {
    if (fileOffset < 0) throw new IllegalArgumentException();
    if (readOnly) throw new IOException("Read only");
    RAFLock lock = lockOpen();
    try {
      if (fileOffset + length > this.length) throw new IOException("Length limit exceeded");
      // Use RandomAccessFile for predictable semantics and compatibility.
      synchronized (this) {
        raf.seek(fileOffset);
        raf.write(buf, bufOffset, length);
      }
    } finally {
      lock.unlock();
    }
  }

  /**
   * Close the buffer and return its descriptor to the pool.
   *
   * <p>The instance must not hold a pool lock when closing.
   *
   * @throws IllegalStateException if a lock obtained via {@link #lockOpen()} is still held
   */
  @Override
  public void close() {
    if (LOG.isDebugEnabled()) LOG.debug("Closing {}", this);
    final Object monitor = fds.lock;
    synchronized (monitor) {
      if (lockLevel != 0) throw new IllegalStateException("Must unlock first!");
      closed = true;
      // Remove from the closables set to avoid retention. The set is bounded by the pool size.
      fds.closables.remove(this);
      closeRAF();
    }
  }

  /**
   * Keep the underlying {@link RandomAccessFile} open while the returned lock is held.
   *
   * <p>May block until a pool slot becomes available. The lock controls only lifetime in the pool;
   * it does not serialize I/O.
   *
   * @return a lock that must be {@link RAFLock#unlock() unlocked} exactly once
   * @throws IOException if the buffer has been closed
   */
  @Override
  public RAFLock lockOpen() throws IOException {
    return lockOpen(false);
  }

  private RAFLock lockOpen(boolean forceWrite) throws IOException {
    RAFLock lock =
        new RAFLock() {

          @Override
          protected void innerUnlock() {
            PooledFileRandomAccessBuffer.this.unlock();
          }
        };
    final Object monitor = fds.lock;
    synchronized (monitor) {
      while (true) {
        fds.closables.remove(this);
        if (closed) throw new IOException("Already closed " + this);

        if (isOpenUnsafe()) {
          incrementLockLevel();
          return lock;
        }

        if (hasFDSlotUnsafe()) {
          openRAFUnsafe(forceWrite);
          incrementLockLevel();
          return lock;
        }

        PooledFileRandomAccessBuffer closable = pollFirstClosable();
        if (closable != null) {
          closable.closeRAF();
          continue;
        }
        waitForSlotUnsafe();
      }
    }
  }

  private boolean isOpenUnsafe() {
    return raf != null;
  }

  private void incrementLockLevel() {
    lockLevel++;
  }

  private boolean hasFDSlotUnsafe() {
    return fds.totalOpenFDs < fds.maxOpenFDs;
  }

  private void openRAFUnsafe(boolean forceWrite) throws IOException {
    raf = new RandomAccessFile(file, (readOnly && !forceWrite) ? "r" : "rw");
    fds.totalOpenFDs++;
  }

  /**
   * Wait until a pool slot is available or this instance is already open. Caller holds fds.lock.
   */
  private void waitForSlotUnsafe() throws IOException {
    final Object monitor = fds.lock;
    synchronized (monitor) {
      // Wait only while there is no free slot, this buffer is not yet open/closed, and there
      // are no queued closables we could reap after waking up.
      while (fds.closables.isEmpty() && !hasFDSlotUnsafe() && !isOpenUnsafe() && !closed) {
        try {
          monitor.wait();
        } catch (InterruptedException e) {
          // Propagate interruption to the caller to avoid busy-spinning and allow higher-level
          // code to decide whether to retry or abort.
          Thread.currentThread().interrupt();
          InterruptedIOException ex =
              new InterruptedIOException("Interrupted while waiting for FD slot");
          ex.initCause(e);
          throw ex;
        }
      }
    }
  }

  private PooledFileRandomAccessBuffer pollFirstClosable() {
    final Object monitor = fds.lock;
    synchronized (monitor) {
      Iterator<PooledFileRandomAccessBuffer> it = fds.closables.iterator();
      if (it.hasNext()) {
        PooledFileRandomAccessBuffer first = it.next();
        it.remove();
        return first;
      }
      return null;
    }
  }

  /**
   * Close the live {@link RandomAccessFile} if present.
   *
   * <p>Precondition: {@code lockLevel == 0}. Intended for internal use and tests.
   */
  void closeRAF() {
    final Object monitor = fds.lock;
    synchronized (monitor) {
      if (lockLevel != 0) throw new IllegalStateException();
      if (raf == null) return;
      try {
        raf.close(); // Best effort; failures are logged and the pool counter still decrements.
      } catch (IOException e) {
        LOG.error("Error closing {} : {}", this, e, e);
      }
      raf = null;
      fds.totalOpenFDs--;
    }
  }

  private void unlock() {
    final Object monitor = fds.lock;
    synchronized (monitor) {
      lockLevel--;
      if (lockLevel > 0) return;
      fds.closables.add(this);
      monitor.notifyAll();
    }
  }

  /**
   * Enable or disable secure deletion for {@link #free()}.
   *
   * @param secureDelete when {@code true}, attempts the best‑effort secure deleting
   */
  public void setSecureDelete(boolean secureDelete) {
    this.secureDelete = secureDelete;
  }

  /**
   * Free this buffer. Always calls {@link #close()} and optionally deletes the backing file.
   *
   * <p>When {@code deleteOnFree} is {@code true}, performs the best‑effort delete. If {@link
   * #setSecureDelete(boolean)} was enabled, the file is overwritten with pseudorandom data before
   * removal.
   */
  @Override
  public void free() {
    close();
    if (!deleteOnFree) return;
    if (secureDelete) {
      try {
        secureDelete(file);
      } catch (IOException e) {
        LOG.error("Unable to delete {} : {}", file, e, e);
        LOG.warn("Unable to delete temporary file {}", file);
      }
    } else {
      try {
        Files.delete(file.toPath());
      } catch (IOException e) {
        LOG.error("Unable to delete {} : {}", file, e, e);
      }
    }
  }

  private static void secureDelete(File file) throws IOException {
    if (!file.exists()) return;
    long size = file.length();
    if (size > 0) {
      try (RandomAccessFile raf = new RandomAccessFile(file, "rw")) {
        writeRandomBytes(raf, size);
        raf.getFD().sync();
      }
    }
    try {
      Files.delete(file.toPath());
    } catch (IOException e) {
      if (Files.exists(file.toPath())) {
        throw new IOException("Unable to delete file " + file, e);
      }
    }
  }

  private static void writeRandomBytes(RandomAccessFile raf, long size) throws IOException {
    byte[] buffer = new byte[32 * 1024];
    raf.seek(0);
    long remaining = size;
    while (remaining > 0) {
      SECURE_DELETE_RANDOM.nextBytes(buffer);
      int bytesToWrite = (int) Math.min(remaining, buffer.length);
      raf.write(buffer, 0, bytesToWrite);
      remaining -= bytesToWrite;
    }
  }

  boolean isOpen() {
    final Object monitor = fds.lock;
    synchronized (monitor) {
      return raf != null;
    }
  }

  @SuppressWarnings("unused")
  boolean isLocked() {
    final Object monitor = fds.lock;
    synchronized (monitor) {
      return lockLevel != 0;
    }
  }

  /**
   * Validate the on-disk state and re-register persistent-temp files after deserialization.
   *
   * @param context client context providing the persistent file tracker
   * @throws ResumeFailedException if the file is missing or if the stored length is inconsistent
   */
  @Override
  public void onResume(ResumeContext context) throws ResumeFailedException {
    if (!file.exists()) throw new ResumeFailedException("File does not exist: " + file);
    if (length > file.length()) throw new ResumeFailedException("Bad length");
    if (persistentTempID != -1) context.getPersistentFileTracker().register(file);
  }

  /**
   * Return a debugging-friendly identifier that includes the backing file path.
   *
   * @return a string in the form {@code super.toString():<path>}
   */
  @Override
  public String toString() {
    return super.toString() + ":" + file;
  }

  static final int MAGIC = 0x297c550a;
  static final int VERSION = 1;

  /**
   * Write a compact descriptor sufficient to reconstruct this buffer later.
   *
   * <p>Format: {@link #MAGIC} (int), {@link #VERSION} (int), path (UTF), readOnly (boolean), length
   * (long), persistentTempID (long), deleteOnFree (boolean), and optionally secureDelete (boolean)
   * when {@code deleteOnFree == true}.
   *
   * @param dos destination stream
   * @throws IOException on I/O errors
   */
  @Override
  public void storeTo(DataOutputStream dos) throws IOException {
    dos.writeInt(MAGIC);
    dos.writeInt(VERSION);
    dos.writeUTF(file.toString());
    dos.writeBoolean(readOnly);
    dos.writeLong(length);
    dos.writeLong(persistentTempID);
    dos.writeBoolean(deleteOnFree);
    if (deleteOnFree) dos.writeBoolean(secureDelete);
  }

  /**
   * Reconstruct a buffer from a descriptor written by {@link #storeTo}.
   *
   * <p>Caller must consume {@link #MAGIC} before invoking this constructor; this method validates
   * {@link #VERSION}. For persistent-temp files, the file may be moved by {@link
   * PersistentFilenameGenerator} during resume.
   *
   * @param dis source stream positioned after {@link #MAGIC}
   * @param fg filename contract for persistent-temp resolution
   * @param persistentFileTracker tracker used to (re)register files during resume
   * @throws StorageFormatException if the version or stored values are invalid
   * @throws IOException on I/O errors
   * @throws ResumeFailedException if the file is missing and cannot be recovered
   */
  PooledFileRandomAccessBuffer(
      DataInputStream dis,
      PersistentFilenameGenerator fg,
      PersistentFileTracker persistentFileTracker)
      throws StorageFormatException, IOException, ResumeFailedException {
    int version = dis.readInt();
    if (version != VERSION) throw new StorageFormatException("Bad version");
    File f = new File(dis.readUTF());
    readOnly = dis.readBoolean();
    length = dis.readLong();
    persistentTempID = dis.readLong();
    deleteOnFree = dis.readBoolean();
    if (deleteOnFree) secureDelete = dis.readBoolean();
    else secureDelete = false;
    fds = DEFAULT_FDTRACKER;
    if (length < 0) throw new StorageFormatException("Bad length");
    if (persistentTempID != -1) {
      // File must exist!
      if (!f.exists()) {
        // Maybe moved after the last checkpoint?
        f = fg.getFilename(persistentTempID);
        if (f.exists()) {
          persistentFileTracker.register(f);
          file = f;
          return;
        }
      }
      file = fg.maybeMove(f, persistentTempID);
      if (!f.exists()) throw new ResumeFailedException("Persistent tempfile lost " + f);
    } else {
      file = f;
      if (!f.exists()) throw new ResumeFailedException("Lost file " + f);
    }
  }

  /**
   * Compute a hash based on path, size, and configuration flags.
   *
   * @return a hash consistent with {@link #equals(Object)}
   */
  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + (deleteOnFree ? 1231 : 1237);
    result = prime * result + ((file == null) ? 0 : file.hashCode());
    result = prime * result + Long.hashCode(length);
    result = prime * result + Long.hashCode(persistentTempID);
    result = prime * result + (readOnly ? 1231 : 1237);
    result = prime * result + (secureDelete ? 1231 : 1237);
    return result;
  }

  /**
   * Compare based on the underlying storage object and configuration flags.
   *
   * <p>Two buffers are equal when they reference the same path and have identical size and flags.
   */
  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (!(obj instanceof PooledFileRandomAccessBuffer other)) {
      return false;
    }
    if (deleteOnFree != other.deleteOnFree) {
      return false;
    }
    if (!file.equals(other.file)) {
      return false;
    }
    if (length != other.length) {
      return false;
    }
    if (persistentTempID != other.persistentTempID) {
      return false;
    }
    if (readOnly != other.readOnly) {
      return false;
    }
    return secureDelete == other.secureDelete;
  }
}

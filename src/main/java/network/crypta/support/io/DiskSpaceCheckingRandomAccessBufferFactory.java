package network.crypta.support.io;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Random;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.api.LockableRandomAccessBufferFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Factory that enforces free‑space checks before creating random‑access buffers.
 *
 * <p>This wrapper queries {@link File#getUsableSpace()} on a configured directory and requires that
 * enough space remains after an allocation to meet a caller‑defined reserve. When the check passes,
 * calls delegate to the underlying {@link LockableRandomAccessBufferFactory}. It also implements
 * {@link DiskSpaceChecker} for incremental write checks and {@link FileRandomAccessBufferFactory}
 * for file‑backed buffer creation.
 *
 * <p><strong>Threading:</strong> A single fair {@link java.util.concurrent.locks.ReentrantLock}
 * serializes free‑space checks with allocation to keep observations consistent and reduce
 * fragmentation. The lock does not provide any per‑file concurrency guarantees for returned
 * buffers.
 *
 * <p><strong>Units:</strong> All sizes are bytes.
 */
public class DiskSpaceCheckingRandomAccessBufferFactory
    implements LockableRandomAccessBufferFactory, DiskSpaceChecker, FileRandomAccessBufferFactory {

  private static final Logger LOG =
      LoggerFactory.getLogger(DiskSpaceCheckingRandomAccessBufferFactory.class);

  private final LockableRandomAccessBufferFactory underlying;
  private final File dir;
  private volatile long minDiskSpace;

  /*
   * LOCKING: Serialize space checks and allocations under one fair lock to make the free‑space
   * snapshot representative for the following allocation. Per‑filesystem granularity could be
   * considered in the future if needed.
   */
  private static final Lock lock = new ReentrantLock(true);

  /**
   * Creates a factory that validates free space before delegating to the underlying factory.
   *
   * @param underlying delegate for actual buffer creation when checks pass
   * @param dir directory whose filesystem is queried via {@link File#getUsableSpace()}
   * @param minDiskSpace minimum free bytes that must remain after allocation (reserve)
   */
  public DiskSpaceCheckingRandomAccessBufferFactory(
      LockableRandomAccessBufferFactory underlying, File dir, long minDiskSpace) {
    this.underlying = underlying;
    this.dir = dir;
    this.minDiskSpace = minDiskSpace;
  }

  /**
   * Sets the minimum free‑space reserve (bytes) required to remain after allocations.
   *
   * @param min non‑negative reserve in bytes
   * @throws IllegalArgumentException if {@code min < 0}
   */
  public void setMinDiskSpace(long min) {
    if (min < 0) throw new IllegalArgumentException();
    this.minDiskSpace = min;
  }

  /**
   * Creates a fixed‑size buffer after verifying free space.
   *
   * <p>Requires {@code dir.getUsableSpace() > size + minDiskSpace}. The method holds the internal
   * lock while checking and delegating to avoid races between threads.
   *
   * @param size requested length in bytes
   * @return a new {@link LockableRandomAccessBuffer}
   * @throws InsufficientDiskSpaceException if the free‑space requirement is not met
   * @throws IOException if the delegate fails with an I/O error
   */
  @Override
  public LockableRandomAccessBuffer makeRAF(long size) throws IOException {
    lock.lock();
    try {
      if (dir.getUsableSpace() > size + minDiskSpace) return underlying.makeRAF(size);
      else throw new InsufficientDiskSpaceException();
    } finally {
      lock.unlock();
    }
  }

  /**
   * Creates a buffer initialized from a byte array after verifying free space.
   *
   * <p>Requires {@code dir.getUsableSpace() > size + minDiskSpace}. This method is synchronized and
   * also uses the internal lock for a consistent check‑then‑allocate sequence.
   *
   * @param initialContents source array; data from {@code offset} with length {@code size} is
   *     copied
   * @param offset index of the first byte to copy
   * @param size number of bytes to copy; also the resulting buffer length
   * @param readOnly whether the returned buffer is read‑only if supported by the delegate
   * @return a new {@link LockableRandomAccessBuffer} containing the copied data
   * @throws InsufficientDiskSpaceException if the free‑space requirement is not met
   * @throws IOException if the delegate fails with an I/O error
   */
  @Override
  public synchronized LockableRandomAccessBuffer makeRAF(
      byte[] initialContents, int offset, int size, boolean readOnly) throws IOException {
    lock.lock();
    try {
      if (dir.getUsableSpace() > size + minDiskSpace)
        return underlying.makeRAF(initialContents, offset, size, readOnly);
      else throw new InsufficientDiskSpaceException();
    } finally {
      lock.unlock();
    }
  }

  /**
   * Returns a diagnostic string that includes the delegate factory.
   *
   * @return {@code super.toString() + ":" + underlying.toString()}
   */
  @Override
  public String toString() {
    return super.toString() + ":" + underlying.toString();
  }

  /**
   * Creates a file‑backed buffer for an existing empty file.
   *
   * <p>The file must exist and have length {@code 0}. Requires {@code dir.getUsableSpace() > size +
   * minDiskSpace}. On success, returns a {@link PooledFileRandomAccessBuffer}. If any step fails
   * before returning a buffer, the method deletes the file in the best‑effort manner.
   *
   * <p><strong>Ownership:</strong> The caller owns the returned buffer and must close or free it.
   *
   * @param file target file; must exist and be empty
   * @param size desired length in bytes
   * @param random randomness source used by the buffer implementation when pre‑allocating
   * @return a newly created file‑backed buffer
   * @throws IOException if the file preconditions are not met or another I/O error occurs
   * @throws InsufficientDiskSpaceException if the free‑space requirement is not met
   */
  @Override
  @SuppressWarnings("java:S2093")
  public PooledFileRandomAccessBuffer createNewRAF(File file, long size, Random random)
      throws IOException {
    PooledFileRandomAccessBuffer ret = null;
    lock.lock();
    try {
      if (!file.exists()) throw new IOException("File does not exist");
      if (file.length() != 0) throw new IOException("File is wrong length");
      // Keep check and allocation under the same lock for a consistent space snapshot.
      if (dir.getUsableSpace() > size + minDiskSpace) {
        ret = new PooledFileRandomAccessBuffer(file, false, size, -1, true);
        return ret;
      } else {
        throw new InsufficientDiskSpaceException();
      }
    } finally {
      if (ret == null) { // Best‑effort cleanup when no buffer was returned.
        try {
          Files.delete(file.toPath());
        } catch (IOException e) {
          // Preserve original failure; deletion failure here is non‑fatal.
          LOG.debug("Unable to delete {} after RAF creation failed", file, e);
        }
      }
      lock.unlock();
    }
  }

  /**
   * Checks whether writing more data would violate the configured free‑space reserve.
   *
   * <p>If {@code file} is not a descendant of {@code dir}, the method logs an error and returns
   * {@code true} (i.e., it does not block the writing). Otherwise, it evaluates {@code
   * dir.getUsableSpace() - (toWrite + bufferSize) >= minDiskSpace} under the internal lock.
   *
   * @param file file being extended; used to validate directory relationship
   * @param toWrite number of additional bytes intended to be written
   * @param bufferSize number of bytes written since the last check; callers use this to throttle
   *     check frequency
   * @return {@code true} if the writing is allowed, {@code false} if it would violate the reserve
   */
  @Override
  public boolean checkDiskSpace(File file, int toWrite, int bufferSize) {
    if (!FileUtil.isParent(dir, file)) {
      LOG.error("Not checking disk space because {} is not child of {}", file, dir);
      return true;
    }
    lock.lock();
    try {
      return dir.getUsableSpace() - (toWrite + bufferSize) >= minDiskSpace;
    } finally {
      lock.unlock();
    }
  }
}

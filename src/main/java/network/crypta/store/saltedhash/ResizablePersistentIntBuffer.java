package network.crypta.store.saltedhash;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.util.Arrays;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import network.crypta.support.Fields;
import network.crypta.support.Ticker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A resizable, integer-indexed buffer backed by a flat on-disk file.
 *
 * <p>The buffer persists changes according to a global persistence policy: write immediately on
 * each put, write only on shutdown, or write after a configurable delay. The policy is controlled
 * via {@link #setPersistenceTime(int)} and read via {@link #getPersistenceTime()}.
 *
 * <p>Concurrency and persistence:
 *
 * <ul>
 *   <li>Thread-safe for concurrent {@link #get(int)} and {@link #put(int, int)} calls. Resizes take
 *       a write lock and replace the backing array atomically.
 *   <li>When the policy is {@code -1}, {@link #put(int, int)} writes the single changed integer to
 *       disk synchronously. When {@code 0}, modified values are kept in memory and the whole buffer
 *       is flushed only during {@link #shutdown()}. When {@code > 0}, the first change marks the
 *       buffer dirty and schedules a background write after the given delay in milliseconds using
 *       the provided {@link Ticker}.
 *   <li>{@link #shutdown()} blocks, flushes if dirty, and closes the file while preserving the
 *       thread interrupt status. {@link #abort()} closes the file without flushing in-memory
 *       changes.
 * </ul>
 *
 * <p>Implementation notes: an {@code int[]} stores the contents in memory and is (re)written in
 * fixed-size chunks. A memory-mapped approach is intentionally avoided because standard Java does
 * not provide a supported unmap mechanism, which would complicate resizing.
 *
 * @author toad
 */
public class ResizablePersistentIntBuffer {
  private static final Logger LOG = LoggerFactory.getLogger(ResizablePersistentIntBuffer.class);
  private static final String WRITE_FAILED_MSG = "Write failed during shutdown on {}";

  private final File filename;
  private final RandomAccessFile raf;
  private final FileChannel channel;
  private final boolean isNew;
  private int size;

  /** Backing array; a resize acquires the write lock and replaces this reference. */
  private int[] buffer;

  private final ReadWriteLock lock;
  // Five minutes by default. Periodic disk writes can be noisy; delaying them is a trade‑off.
  // Any value other than -1 risks losing the last in‑memory updates on an unclean shutdown.
  // The store remains consistent: callers recover transparently on restart.
  // A non‑immediate policy may also trigger a Bloom filter rebuild after an unclean shutdown.
  public static final int DEFAULT_PERSISTENCE_TIME = 300000;

  // Using a static for simplicity at present.
  /**
   * Global persistence policy in milliseconds.
   *
   * <p>Semantics:
   *
   * <ul>
   *   <li>{@code -1}: write the changed integer immediately on each successful {@code put}.
   *   <li>{@code 0}: write only during {@link #shutdown()} or explicit {@link #forceWrite()}.
   *   <li>{@code > 0}: debounce writes; schedule a background flush after this delay.
   * </ul>
   */
  private static int globalPersistenceTime = DEFAULT_PERSISTENCE_TIME;

  private Ticker ticker;

  /** True if memory differs from disk; guarded by {@code this}. */
  private boolean dirty;

  /** True if a delayed writer run has been queued; guarded by {@code this}. */
  private boolean scheduled;

  /**
   * True while the writer job is running; guarded by {@code this}. Used to wait for completion
   * during forced writes and shutdown.
   */
  private boolean writing;

  private boolean closed;

  /**
   * Sets the global persistence policy.
   *
   * <p>Values have the following meaning: {@code -1} = immediate per-entry writes, {@code 0} =
   * write only on shutdown, {@code > 0} = schedule a write after the specified delay in
   * milliseconds. The new value affects subsequent updates and scheduling; it does not cancel a run
   * that is already scheduled.
   *
   * @param val policy value in milliseconds; see semantics above
   */
  public static synchronized void setPersistenceTime(int val) {
    globalPersistenceTime = val;
  }

  /**
   * Returns the current global persistence policy value in milliseconds.
   *
   * @return policy value ({@code -1}, {@code 0}, or {@code > 0}) in milliseconds
   */
  public static synchronized int getPersistenceTime() {
    return globalPersistenceTime;
  }

  /**
   * Creates a buffer over {@code f} with the given logical size.
   *
   * <p>If the file does not exist it is created. If it is larger than {@code size * 4} bytes, it is
   * truncated. If smaller, it is extended to exactly {@code size * 4} bytes after reading the
   * existing contents. The in-memory array is initialized from the file up to the available data
   * and zero-filled for any remaining tail.
   *
   * @param f file to back the buffer; one 32-bit integer per 4 bytes
   * @param size number of integers in the buffer (capacity); must be non-negative
   * @throws IOException if the file cannot be opened, read, or resized
   */
  public ResizablePersistentIntBuffer(File f, int size) throws IOException {
    this.filename = f;
    isNew = !f.exists();
    this.raf = new RandomAccessFile(f, "rw");
    this.lock = new ReentrantReadWriteLock();
    this.size = size;
    buffer = new int[size];
    long expectedLength = ((long) size) * 4;
    long realLength = raf.length();
    if (realLength > expectedLength) raf.setLength(expectedLength);
    readBuffer((int) Math.min(size, realLength / 4));
    if (realLength < expectedLength) raf.setLength(expectedLength);
    channel = raf.getChannel();
    // Initialize writer after fields are set so captured members are initialized
    this.writer =
        () -> {
          LOG.info("Writing slot cache {}", ResizablePersistentIntBuffer.this);
          lock.readLock().lock(); // Protect buffer.
          try {
            synchronized (ResizablePersistentIntBuffer.this) {
              if (writing || !dirty || closed) {
                scheduled = false;
                return;
              }
              scheduled = false;
              dirty = false;
              writing = true;
            }
            try {
              writeBuffer();
            } catch (IOException e) {
              LOG.error(WRITE_FAILED_MSG, filename, e);
            }
          } finally {
            synchronized (ResizablePersistentIntBuffer.this) {
              writing = false;
              ResizablePersistentIntBuffer.this.notifyAll();
            }
            lock.readLock().unlock();
          }
          LOG.info("Written slot cache {}", ResizablePersistentIntBuffer.this);
        };
  }

  /**
   * Fills the entire in-memory buffer with {@code value}.
   *
   * <p>Intended for initialization at startup, especially when the buffer is new. This method does
   * not immediately persist the data; persistence follows the active policy or an explicit {@link
   * #forceWrite()}.
   *
   * @param value integer to assign to every slot
   */
  public void fill(int value) {
    Arrays.fill(buffer, value);
  }

  private void readBuffer(int size) throws IOException {
    raf.seek(0);
    byte[] buf = new byte[32768];
    int read = 0;
    while (read < size) {
      int toRead = Math.min(buf.length, (size - read) * 4);
      raf.readFully(buf, 0, toRead);
      int[] data = Fields.bytesToInts(buf, 0, toRead);
      System.arraycopy(data, 0, buffer, read, data.length);
      read += data.length;
    }
  }

  /**
   * Attaches a scheduler used to run delayed writes and schedules one if the buffer is already
   * dirty and the policy is a positive delay.
   *
   * <p>Idempotent: subsequent calls replace the scheduler reference and may schedule a run if none
   * is pending.
   *
   * @param ticker scheduler for timed jobs; must remain live while this buffer is in use
   */
  public void start(Ticker ticker) {
    synchronized (this) {
      this.ticker = ticker;
      if (dirty) {
        int persistenceTime = getPersistenceTime();
        LOG.info("Scheduling write of slot cache {} in {}", this, persistenceTime);
        ticker.queueTimedJob(writer, persistenceTime);
        scheduled = true;
      }
    }
  }

  /**
   * Returns the value at {@code offset}.
   *
   * <p>Thread-safe. Throws {@link IllegalStateException} if the buffer was shut down.
   *
   * @param offset zero-based index in the range {@code [0, size())}
   * @return the stored integer value
   * @throws IllegalStateException if {@link #shutdown()} or {@link #abort()} was called
   * @throws ArrayIndexOutOfBoundsException if {@code offset} is out of bounds
   */
  public int get(int offset) {
    lock.readLock().lock();
    if (closed) throw new IllegalStateException("Already shut down");
    try {
      return buffer[offset];
    } finally {
      lock.readLock().unlock();
    }
  }

  /**
   * Stores {@code value} at {@code offset} honoring the current persistence policy.
   *
   * <p>When the policy is immediate ({@code -1}), the single updated integer is written to disk
   * synchronously. For other policies the buffer is marked dirty and a write may be scheduled.
   *
   * @param offset zero-based index in the range {@code [0, size())}
   * @param value value to store
   * @throws IOException if an immediate write fails
   * @throws IllegalStateException if the buffer is closed
   * @throws ArrayIndexOutOfBoundsException if {@code offset} is out of bounds
   */
  public void put(int offset, int value) throws IOException {
    put(offset, value, false);
  }

  /**
   * Variant of {@link #put(int, int)} that can suppress the immediate write when the policy is
   * {@code -1}.
   *
   * <p>When {@code noWrite} is {@code true} and the policy is immediate, the value is updated only
   * in memory and the buffer is marked dirty; the caller is responsible for ensuring a later flush
   * (e.g., via {@link #forceWrite()} or shutdown). For non-immediate policies {@code noWrite} has
   * no effect beyond the regular scheduling.
   *
   * @param offset zero-based index in the range {@code [0, size())}
   * @param value value to store
   * @param noWrite suppresses the per-entry write when the policy is {@code -1}
   * @throws IOException if an immediate write fails
   * @throws IllegalStateException if the buffer is closed
   * @throws ArrayIndexOutOfBoundsException if {@code offset} is out of bounds
   */
  public void put(int offset, int value, boolean noWrite) throws IOException {
    lock.readLock().lock(); // Only resize needs write lock because it creates a new buffer.
    if (closed) throw new IllegalStateException("Already shut down");
    try {
      int persistenceTime = getPersistenceTime();
      buffer[offset] = value;
      if (persistenceTime == -1 && !noWrite) {
        writeValueImmediate(offset, value);
      } else {
        markDirtyAndMaybeSchedule(persistenceTime);
      }
    } finally {
      lock.readLock().unlock();
    }
  }

  private void writeValueImmediate(int offset, int value) throws IOException {
    final long basePos = ((long) offset) * 4;
    ByteBuffer bb = ByteBuffer.wrap(Fields.intToBytes(value));
    long pos = basePos;
    while (bb.hasRemaining()) {
      int wrote = channel.write(bb, pos);
      if (wrote < 0) {
        throw new IOException("Unexpected EOF while writing to " + filename);
      }
      pos += wrote;
    }
  }

  private void markDirtyAndMaybeSchedule(int persistenceTime) {
    synchronized (this) {
      dirty = true;
      if (persistenceTime > 0) {
        if (ticker != null) {
          if (!scheduled) {
            LOG.info("Scheduling write of slot cache {} in {}", this, persistenceTime);
            ticker.queueTimedJob(writer, persistenceTime);
            scheduled = true;
          }
        } else {
          LOG.info(
              "Will schedule write of slot cache after startup: {} in {}", this, persistenceTime);
        }
      }
    }
  }

  private final Runnable writer;

  /**
   * Flushes pending changes if any and closes the file.
   *
   * <p>Blocks while an in-flight writer completes, then writes the full buffer if dirty. Preserves
   * the thread's interrupt status. After shutdown, further {@link #get(int)} or {@link #put(int,
   * int)} calls throw {@link IllegalStateException}.
   */
  public void shutdown() {
    boolean wasInterrupted = false;
    lock.writeLock().lock();
    try {
      boolean doWrite;
      synchronized (this) {
        if (closed) return;
        closed = true;
        doWrite = dirty;
        if (writing) {
          // Wait for any in-flight write to finish; preserve interrupt status.
          while (writing) {
            try {
              wait();
            } catch (InterruptedException _) {
              wasInterrupted = true; // record and keep waiting so we can flush/close
            }
          }
          // Re-check after the writer completes in case new writes happened while we waited.
          doWrite = dirty;
        }
        if (doWrite) {
          writing = true;
        }
      }
      try {
        if (doWrite) {
          LOG.info("Writing slot cache on shutdown: {}", this);
          writeBuffer();
        }
      } catch (IOException e) {
        LOG.error(WRITE_FAILED_MSG, filename, e);
      }
      synchronized (this) {
        if (writing) {
          writing = false;
          this.notifyAll();
        }
      }
      try {
        raf.close();
      } catch (IOException e) {
        LOG.error("Close failed during shutdown on {}", filename, e);
      }
    } finally {
      lock.writeLock().unlock();
      if (wasInterrupted) Thread.currentThread().interrupt();
    }
  }

  /**
   * Closes the file without flushing in-memory changes.
   *
   * <p>Use when the caller intentionally discards recent updates (e.g., during error recovery).
   */
  public void abort() {
    lock.writeLock().lock();
    try {
      synchronized (this) {
        if (closed) return;
        closed = true;
      }
      try {
        raf.close();
      } catch (IOException e) {
        LOG.error("Close failed during shutdown: {} on {}", e, filename, e);
      }
    } finally {
      lock.writeLock().unlock();
    }
  }

  private void writeBuffer() throws IOException {
    // Writes the entire buffer in chunks.
    raf.seek(0);
    int written = 0;
    while (written < size) {
      int toWrite = Math.min(32768, size - written);
      byte[] buf = Fields.intsToBytes(buffer, written, toWrite);
      raf.write(buf);
      written += toWrite;
    }
  }

  /**
   * Changes the logical size and persists the whole buffer.
   *
   * <p>Preserves existing contents up to the new size, truncating or zero-extending as needed. The
   * underlying file is resized to {@code size * 4} bytes and the full buffer is written immediately
   * under the write lock.
   *
   * @param size new number of integers; must be non-negative
   */
  public void resize(int size) {
    lock.writeLock().lock();
    try {
      if (this.size == size) return;
      LOG.info("Resizing cache from {} slots to {}", this.size, size);
      this.size = size;
      buffer = Arrays.copyOf(buffer, size);
      try {
        raf.setLength(size * 4L);
        writeBuffer();
      } catch (IOException e) {
        LOG.error("Failed to change size or write during resize on {}", filename, e);
      }
    } finally {
      lock.writeLock().unlock();
    }
  }

  /**
   * Forces an immediate write of the entire buffer if dirty.
   *
   * <p>Waits for any in-flight write, clears the scheduled flag to avoid a redundant run, and then
   * writes under the read lock.
   */
  public void forceWrite() {
    LOG.info("Force write slot cache: {}", this);
    boolean wasInterrupted = false;
    lock.readLock().lock();
    try {
      synchronized (this) {
        if (closed) return;
        // Wait for any in-flight write to finish; preserve interrupt status.
        while (writing) {
          try {
            wait();
          } catch (InterruptedException _) {
            wasInterrupted = true; // record and keep waiting
          }
        }
        if (!dirty) return; // Nothing to write.
        // Take ownership of the write, and clear the dirty flag under the write guard.
        writing = true;
        scheduled = false; // avoid a no-op scheduled run after this forced write
        dirty = false;
      }
      try {
        writeBuffer();
      } catch (IOException e) {
        LOG.error(WRITE_FAILED_MSG, filename, e);
      }
    } finally {
      synchronized (this) {
        if (writing) {
          writing = false;
          this.notifyAll();
        }
      }
      lock.readLock().unlock();
      if (wasInterrupted) Thread.currentThread().interrupt();
    }
  }

  /**
   * Returns whether the backing file did not exist at construction time.
   *
   * @return {@code true} if the file was created by the constructor
   */
  public boolean isNew() {
    return isNew;
  }

  /** Returns the backing file path for logging and diagnostics. */
  @Override
  public String toString() {
    return filename.getPath();
  }

  // Testing only: intentionally avoids locking for speed in isolated test scenarios.
  public void replaceAllEntries(int key, int value) {
    for (int i = 0; i < buffer.length; i++) if (buffer[i] == key) buffer[i] = value;
  }

  /**
   * Returns the number of integers in the buffer.
   *
   * @return logical capacity in elements
   */
  public int size() {
    return size;
  }
}

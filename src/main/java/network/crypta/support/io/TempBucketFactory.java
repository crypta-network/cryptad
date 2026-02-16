package network.crypta.support.io;

import static java.util.concurrent.TimeUnit.MINUTES;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.ref.Cleaner;
import java.lang.ref.WeakReference;
import java.security.GeneralSecurityException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.ListIterator;
import java.util.Queue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import network.crypta.client.async.ClientContext;
import network.crypta.crypt.EncryptedRandomAccessBucket;
import network.crypta.crypt.EncryptedRandomAccessBuffer;
import network.crypta.crypt.EncryptedRandomAccessBufferType;
import network.crypta.crypt.MasterSecret;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.SizeUtil;
import network.crypta.support.TimeUtil;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.api.LockableRandomAccessBufferFactory;
import network.crypta.support.api.RandomAccessBucket;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Factory for temporary buckets that prefer RAM and transparently migrate to disk.
 *
 * <p>This factory creates buckets that are initially backed either by memory (an {@link
 * ArrayBucket}) or by a file (a {@link TempFileBucket}), depending on the requested size and
 * current pool usage. RAM-backed buckets may later migrate to disk based on age or size, so the
 * process can continue without running out of the configured memory pool.
 *
 * <p>Selection rules:
 *
 * <ul>
 *   <li>Use an in-memory bucket when {@code size <= maxRAMBucketSize} and the pool ({@link
 *       #bytesInUse}) would remain {@code <= maxRamUsed}.
 *   <li>Otherwise, use a disk-backed bucket (optionally wrapped with padding and encryption when
 *       {@link #reallyEncrypt} is enabled).
 * </ul>
 *
 * <p>Migration rules for RAM buckets:
 *
 * <ul>
 *   <li>Age-based: buckets older than {@link #RAMBUCKET_MAX_AGE} migrate.
 *   <li>Size-based: buckets exceeding {@code RAMBUCKET_CONVERSION_FACTOR * maxRAMBucketSize}
 *       migrate.
 *   <li>Pool-pressure: when total usage rises above {@link #MAX_USAGE_HIGH}, a background cleaner
 *       migrates buckets until usage drops below {@link #MAX_USAGE_LOW}.
 * </ul>
 *
 * <p>Threading and lifecycle:
 *
 * <ul>
 *   <li>Instances are thread-safe for factory operations.
 *   <li>Returned buckets expose synchronized methods where needed; callers must still respect
 *       single-writer constraints described on {@link TempBucket#getOutputStreamUnbuffered()}.
 *   <li>Call {@link Bucket#free()} to release resources deterministically. A JVM cleaner provides a
 *       best-effort safety net when user code forgets to free, but callers should not rely on it.
 * </ul>
 *
 * <p>Disk space: operations may throw {@link InsufficientDiskSpaceException} when migrating or
 * creating disk-backed storage while free space would drop below {@link #minDiskSpace}.
 *
 * @see #makeBucket(long)
 * @see #makeRAF(long)
 */
public class TempBucketFactory implements BucketFactory, LockableRandomAccessBufferFactory {
  private static final Logger LOG = LoggerFactory.getLogger(TempBucketFactory.class);

  // Cleaner for best-effort safety-net resource cleanup.
  private static final Cleaner resourceCleaner = Cleaner.create();

  // Cleaner action that avoids capturing the outer TempBucket instance strongly.
  @SuppressWarnings("ClassCanBeRecord")
  private static class TempBucketCleanup implements Runnable {
    private final RandomAccessBucket currentBucket;

    TempBucketCleanup(RandomAccessBucket bucket) {
      this.currentBucket = bucket;
    }

    @Override
    public void run() {
      // Best-effort cleanup invoked by the Cleaner. This path should be rare because user
      // code is expected to call free() explicitly. We only free the underlying bucket to
      // minimize risk in finalization-like contexts.
      if (currentBucket != null) {
        currentBucket.free();
      }
    }
  }

  // Cleaner action for TempRandomAccessBuffer memory accounting only.
  @SuppressWarnings("ClassCanBeRecord")
  private static class TempRABCleanup implements Runnable {
    private final long rabId;
    private final long size;
    private final TempBucketFactory factory;

    TempRABCleanup(long rabId, long size, TempBucketFactory factory) {
      this.rabId = rabId;
      this.size = size;
      this.factory = factory;
    }

    @Override
    public void run() {
      // Best-effort cleanup. Only adjust memory accounting; do not touch the underlying buffer
      // because it may have a complex state that requires caller-controlled synchronization.
      if (factory != null) {
        factory.cleanerFreedRAM(rabId, size);
      }
    }
  }

  private final FilenameGenerator filenameGenerator;
  private final DiskSpaceCheckingRandomAccessBufferFactory diskRAFFactory;
  private volatile long minDiskSpace;
  private long bytesInUse = 0;
  private final PriorityAwareExecutor executor;
  private volatile boolean reallyEncrypt;
  private final MasterSecret secret;

  // Tracking for a cleanup safety net to prevent double-freeing
  private static volatile long nextRABId = 1;

  private static synchronized long allocateNextRABId() {
    return nextRABId++;
  }

  private final ConcurrentHashMap<Long, Boolean> freedRABIds = new ConcurrentHashMap<>();

  /** Maximum initial size in bytes for which RAM buckets are considered. */
  private long maxRAMBucketSize;

  /** Memory budget for all RAM buckets in bytes. */
  private long maxRamUsed;

  /** Age threshold after which a RAM bucket is considered long-lived and migrates. */
  private static final long RAMBUCKET_MAX_AGE = MINUTES.toMillis(5);

  /** Size multiplier beyond {@link #maxRAMBucketSize} that triggers migration. */
  static final int RAMBUCKET_CONVERSION_FACTOR = 4;

  private interface Migratable {

    long creationTime();

    boolean migrateToDisk() throws IOException;
  }

  /**
   * A bucket that may start in RAM and migrate to disk transparently.
   *
   * <p>Only one output stream can be opened at a time. Reading requires that an output stream has
   * been opened previously to establish the content; see {@link #getInputStreamUnbuffered()} for
   * details.
   *
   * <p>Instances are safe for concurrent use where methods are synchronized; callers should
   * coordinate access patterns when mixing reads, writes, and migration.
   */
  public final class TempBucket implements Bucket, Migratable, RandomAccessBucket {
    /** The current underlying bucket. */
    private RandomAccessBucket currentBucket;

    /** Locally cached size of the underlying bucket for fast access. */
    private long currentSize;

    /** Whether an {@link OutputStream} has been opened at least once. */
    private boolean hasWritten;

    /** The current underlying output stream, reassigned across migrations. */
    private OutputStream os = null;

    /** Open input streams to reset or close on migration or {@link #free()}. */
    private final ArrayList<TempBucketInputStream> tbis;

    /** Monotonic index used to detect and deprecate stale input streams. */
    private short osIndex;

    /** Creation timestamp used for age-based migration. */
    public final long creationTimeMillis;

    private boolean hasBeenFreed = false;

    // Cleaner handle for safety-net resource cleanup.
    private final Cleaner.Cleanable cleanable;

    public TempBucket(long now, RandomAccessBucket cur) {
      if (cur == null) throw new NullPointerException();
      this.currentBucket = cur;
      this.creationTimeMillis = now;
      this.osIndex = 0;
      this.tbis = new ArrayList<>(1);

      // Register best-effort safety-net; explicit free() is still required by callers.
      this.cleanable = resourceCleaner.register(this, new TempBucketCleanup(this.currentBucket));

      if (LOG.isDebugEnabled()) LOG.debug("event=temp_bucket_created bucket={}", this);
    }

    private synchronized void closeInputStreams(boolean forFree) {
      for (ListIterator<TempBucketInputStream> i = tbis.listIterator(); i.hasNext(); ) {
        TempBucketInputStream is = i.next();
        if (forFree) {
          i.remove();
          try {
            is.close();
          } catch (IOException e) {
            LOG.error("Caught {} closing {}", e, is);
          }
        } else {
          try {
            is.maybeResetInputStream();
          } catch (IOException _) {
            i.remove();
            IOUtils.closeQuietly(is);
          }
        }
      }
    }

    /**
     * Migrates the bucket to disk if it is currently RAM-backed.
     *
     * <p>This method blocks until migration completes. Open input streams are reset to the new
     * underlying storage; an open output stream is closed and rebound to the disk-backed bucket.
     *
     * @return {@code true} if migration happened; {@code false} if already disk-backed or freed
     * @throws IOException if migration fails or I/O operations during copy fail
     */
    @Override
    public boolean migrateToDisk() throws IOException {
      Bucket toMigrate;
      long size;
      synchronized (this) {
        if (!isRAMBucket() || hasBeenFreed)
          // Nothing to migrate! We don't want to switch back to ram, do we?
          return false;
        toMigrate = currentBucket;
        RandomAccessBucket tempFB = makeFileBucket();
        size = currentSize;
        if (os != null) {
          os.flush();
          os.close();
          // DO NOT INCREMENT THE osIndex HERE!
          os = tempFB.getOutputStreamUnbuffered();
          if (size > 0) BucketTools.copyTo(toMigrate, os, size);
        } else {
          if (size > 0) {
            try (OutputStream temp = tempFB.getOutputStreamUnbuffered()) {
              BucketTools.copyTo(toMigrate, temp, size);
            }
          }
        }
        if (toMigrate.isReadOnly()) tempFB.setReadOnly();

        closeInputStreams(false);

        currentBucket = tempFB;
        // We need streams to be reset to point to the new bucket
      }
      if (LOG.isDebugEnabled())
        LOG.debug("event=temp_bucket_migrated sourceHash={}", toMigrate.hashCode());

      synchronized (ramBucketQueue) {
        ramBucketQueue.remove(getReference());
      }

      // We can free it on-thread as it's a rambucket
      toMigrate.free();
      // Might have changed already so we can't rely on the currentSize!
      hasFreed(size);
      return true;
    }

    /**
     * Returns whether the current underlying storage is memory-backed.
     *
     * @return {@code true} when backed by {@link ArrayBucket}; {@code false} when disk-backed
     */
    public synchronized boolean isRAMBucket() {
      return (currentBucket instanceof ArrayBucket);
    }

    /**
     * Returns a buffered output stream for writing the bucket contents.
     *
     * <p>Only one output stream may be open at a time. The returned stream may trigger migration to
     * disk as content grows beyond the in-memory thresholds.
     *
     * @return buffered {@link OutputStream}
     * @throws IOException if an output stream is already open or the bucket has been freed
     */
    @Override
    public OutputStream getOutputStream() throws IOException {
      return new BufferedOutputStream(getOutputStreamUnbuffered());
    }

    /**
     * Returns an unbuffered output stream for writing the bucket contents.
     *
     * <p>Preconditions: no other output stream is open. Only a single output stream is supported at
     * a time. After calling this method, {@link #getInputStreamUnbuffered()} becomes available once
     * data has been written.
     *
     * @return unbuffered {@link OutputStream}
     * @throws IOException if another output stream is open or the bucket has been freed
     */
    @Override
    public synchronized OutputStream getOutputStreamUnbuffered() throws IOException {
      if (os != null)
        throw new IOException(
            "Only one OutputStream per bucket on "
                + java.util.Objects.toIdentityString(this)
                + " !");
      if (hasBeenFreed) throw new IOException("Already freed");
      // Hence we don't need to reset currentSize / _hasTaken() if a bucket is reused.
      // Note: consider migrating to disk rather than throwing.
      hasWritten = true;
      osIndex++;
      OutputStream tos = new TempBucketOutputStream();
      if (LOG.isDebugEnabled()) LOG.debug("Opened output stream {} for bucket {}", tos, this);
      return tos;
    }

    private final class TempBucketOutputStream extends OutputStream {
      long lastCheckedSize = 0;
      long checkDiskEvery = 4096;
      boolean closed = false;

      TempBucketOutputStream() throws IOException {
        if (os == null) os = currentBucket.getOutputStreamUnbuffered();
      }

      private boolean shouldMigrateDueToOversize(long futureSize) {
        long maxBucketSize = getMaxRAMBucketSize();
        return futureSize
            >= Math.min(Integer.MAX_VALUE, maxBucketSize * RAMBUCKET_CONVERSION_FACTOR);
      }

      private boolean shouldMigrateDueToPoolLimit(long futureSize) {
        long currentBucketSize;
        synchronized (TempBucket.this) {
          currentBucketSize = currentSize;
        }
        synchronized (TempBucketFactory.this) {
          return (futureSize - currentBucketSize) + bytesInUse >= maxRamUsed;
        }
      }

      private void ensureDiskSpace(long futureSize) throws InsufficientDiskSpaceException {
        long currentBucketSize;
        synchronized (TempBucket.this) {
          currentBucketSize = currentSize;
        }
        if (filenameGenerator.getDir().getUsableSpace() + (futureSize - currentBucketSize)
            < minDiskSpace) throw new InsufficientDiskSpaceException();
      }

      private void logMigration(boolean oversized) {
        if (LOG.isDebugEnabled()) {
          if (oversized)
            LOG.debug(
                "event=ram_bucket_oversize_migrate bucket={} threshold={}",
                TempBucket.this,
                SizeUtil.formatSize(getMaxRAMBucketSize() * RAMBUCKET_CONVERSION_FACTOR));
          else LOG.debug("event=ram_pool_pressure_migrate reason=bucketpool_limit");
        }
      }

      private boolean shouldCheckDisk(long futureSize) {
        return futureSize - lastCheckedSize >= checkDiskEvery;
      }

      private void maybeMigrateRamBucket(long futureSize) throws IOException {
        if (closed) {
          return;
        }
        if (isRAMBucket()) {
          boolean oversized = shouldMigrateDueToOversize(futureSize);
          boolean poolLimit = !oversized && shouldMigrateDueToPoolLimit(futureSize);

          if (oversized || poolLimit) {
            logMigration(oversized);
            migrateToDisk();
          }
        } else {
          // Check for excess disk usage.
          if (shouldCheckDisk(futureSize)) {
            ensureDiskSpace(futureSize);
            lastCheckedSize = futureSize;
          }
        }
      }

      @Override
      public void write(int b) throws IOException {
        synchronized (TempBucket.this) {
          if (hasBeenFreed) throw new IOException("Already freed");
          long futureSize = currentSize + 1;
          maybeMigrateRamBucket(futureSize);
          os.write(b);
          currentSize = futureSize;
          if (isRAMBucket()) { // We need to re-check because it might have changed!
            synchronized (TempBucketFactory.this) {
              bytesInUse += 1;
            }
          }
        }
      }

      @Override
      public void write(byte @NotNull [] b, int off, int len) throws IOException {
        synchronized (TempBucket.this) {
          if (hasBeenFreed) throw new IOException("Already freed");
          long futureSize = currentSize + len;
          maybeMigrateRamBucket(futureSize);
          os.write(b, off, len);
          currentSize = futureSize;
          if (isRAMBucket()) { // We need to re-check because it might have changed!
            synchronized (TempBucketFactory.this) {
              bytesInUse += len;
            }
          }
        }
      }

      @Override
      public void flush() throws IOException {
        synchronized (TempBucket.this) {
          if (hasBeenFreed) return;
          maybeMigrateRamBucket(currentSize);
          if (!closed) os.flush();
        }
      }

      @Override
      public void close() throws IOException {
        synchronized (TempBucket.this) {
          if (closed) return;
          maybeMigrateRamBucket(currentSize);
          os.flush();
          os.close();
          os = null;
          closed = true;
        }
      }
    }

    /**
     * Returns a buffered input stream for reading the bucket contents.
     *
     * <p>Reading requires that an output stream has previously been opened and closed to establish
     * the content to read.
     *
     * @return buffered {@link InputStream}
     * @throws IOException if the bucket has been freed or content has not yet been written
     */
    @Override
    public InputStream getInputStream() throws IOException {
      return new BufferedInputStream(getInputStreamUnbuffered());
    }

    /**
     * Returns an unbuffered input stream for reading the bucket contents.
     *
     * <p>Precondition: an output stream must have been opened earlier to establish content. If not
     * satisfied, this method throws an {@link IOException}.
     *
     * <p>When the bucket migrates while a reader is active, the stream is transparently reset to
     * the new underlying storage and advanced to the previous read position.
     *
     * @return unbuffered {@link InputStream}
     * @throws IOException if no content exists yet or the bucket has been freed
     */
    @Override
    public synchronized InputStream getInputStreamUnbuffered() throws IOException {
      if (!hasWritten)
        throw new IOException(
            "No OutputStream has been opened! Why would you want an InputStream then?");
      if (hasBeenFreed) throw new IOException("Already freed");
      TempBucketInputStream is = new TempBucketInputStream(osIndex);
      tbis.add(is);
      if (LOG.isDebugEnabled()) LOG.debug("Opened input stream {} for bucket {}", is, this);
      return is;
    }

    private final class TempBucketInputStream extends InputStream {
      /** The current input stream from the underlying bucket. */
      private InputStream currentIS;

      /** Current read offset, used to re-seek after migration. */
      private long index = 0;

      /** Snapshot of {@link TempBucket#osIndex} used to detect stream deprecation. */
      private final short idx;

      TempBucketInputStream(short idx) throws IOException {
        this.idx = idx;
        this.currentIS = currentBucket.getInputStreamUnbuffered();
      }

      public void maybeResetInputStream() throws IOException {
        synchronized (TempBucket.this) {
          if (idx != osIndex) {
            close();
          } else {
            IOUtils.closeQuietly(currentIS);
            currentIS = currentBucket.getInputStreamUnbuffered();
            long toSkip = index;
            while (toSkip > 0) {
              toSkip -= currentIS.skip(toSkip);
            }
          }
        }
      }

      @Override
      public int read() throws IOException {
        synchronized (TempBucket.this) {
          if (hasBeenFreed) throw new IOException("Already freed");
          int toReturn = currentIS.read();
          if (toReturn != -1) index++;
          return toReturn;
        }
      }

      @Override
      public int read(byte @NotNull [] b) throws IOException {
        synchronized (TempBucket.this) {
          if (hasBeenFreed) throw new IOException("Already freed");
          return read(b, 0, b.length);
        }
      }

      @Override
      public int read(byte @NotNull [] b, int off, int len) throws IOException {
        synchronized (TempBucket.this) {
          if (hasBeenFreed) throw new IOException("Already freed");
          int toReturn = currentIS.read(b, off, len);
          if (toReturn > 0) index += toReturn;
          return toReturn;
        }
      }

      @Override
      public long skip(long n) throws IOException {
        synchronized (TempBucket.this) {
          if (hasBeenFreed) throw new IOException("Already freed");
          long skipped = currentIS.skip(n);
          index += skipped;
          return skipped;
        }
      }

      @Override
      public int available() throws IOException {
        synchronized (TempBucket.this) {
          if (hasBeenFreed) throw new IOException("Already freed");
          return currentIS.available();
        }
      }

      @Override
      public void close() throws IOException {
        synchronized (TempBucket.this) {
          IOUtils.closeQuietly(currentIS);
          tbis.remove(this);
        }
      }
    }

    /**
     * Returns an implementation-specific, non-stable name for the underlying bucket.
     *
     * @return opaque name intended for diagnostics only
     */
    @Override
    public synchronized String getName() {
      return currentBucket.getName();
    }

    /**
     * Returns the current size in bytes.
     *
     * @return current length in bytes
     */
    @Override
    public synchronized long size() {
      return currentSize;
    }

    /**
     * Returns whether the bucket is read-only.
     *
     * @return {@code true} if writes are disallowed
     */
    @Override
    public synchronized boolean isReadOnly() {
      return currentBucket.isReadOnly();
    }

    /** Marks the bucket read-only. */
    @Override
    public synchronized void setReadOnly() {
      currentBucket.setReadOnly();
    }

    /**
     * Releases all resources associated with this bucket.
     *
     * <p>Closes any open streams, updates memory accounting, and frees the underlying storage. This
     * method is idempotent.
     */
    @Override
    public synchronized void free() {
      Bucket cur;
      synchronized (this) {
        if (hasBeenFreed) return;
        hasBeenFreed = true;

        IOUtils.closeQuietly(os);
        closeInputStreams(true);
        if (isRAMBucket()) {
          // If it's in memory we must free before removing from the queue.
          currentBucket.free();
          hasFreed(currentSize);
          synchronized (ramBucketQueue) {
            ramBucketQueue.remove(getReference());
          }

          // Explicit freeing completed; clear the Cleaner registration.
          if (cleanable != null) {
            cleanable.clean();
          }
          return;
        } else {
          // Better to free outside the lock if it's not in-memory.
          cur = currentBucket;
        }
      }
      cur.free();

      // Explicit freeing completed; clear the Cleaner registration.
      if (cleanable != null) {
        cleanable.clean();
      }
    }

    /** Called only by TempRandomAccessBuffer */
    private synchronized void onFreed() {
      hasBeenFreed = true;
    }

    // Accounting helper inlined at call sites

    @Override
    public synchronized RandomAccessBucket createShadow() {
      return currentBucket.createShadow();
    }

    private final WeakReference<Migratable> weakRef = new WeakReference<>(this);

    private WeakReference<Migratable> getReference() {
      return weakRef;
    }

    @Override
    public long creationTime() {
      return creationTimeMillis;
    }

    /**
     * Not supported. Temporary buckets are not persistent across restarts.
     *
     * @throws IllegalStateException always
     */
    @Override
    public void onResume(ClientContext context) {
      // Not persistent.
      throw new IllegalStateException();
    }

    /**
     * Not supported. Temporary buckets cannot be stored persistently.
     *
     * @throws UnsupportedOperationException always
     */
    @Override
    public void storeTo(DataOutputStream dos) throws IOException {
      throw new UnsupportedOperationException(); // Not persistent.
    }

    /**
     * Converts this bucket into a read-only random-access buffer.
     *
     * <p>Preconditions: no output stream is open and no input stream is currently active. The
     * returned buffer shares the underlying storage; after conversion, this bucket becomes a {@link
     * RAFBucket} wrapping the new buffer.
     *
     * @return a read-only {@link LockableRandomAccessBuffer}
     * @throws IOException if the bucket has been freed or streams are still open
     */
    @Override
    public LockableRandomAccessBuffer toRandomAccessBuffer() throws IOException {
      synchronized (this) {
        if (hasBeenFreed) throw new IOException("Already freed");
        if (os != null) throw new IOException("Can't migrate with open OutputStream's");
        if (!tbis.isEmpty()) throw new IOException("Can't migrate with open InputStream's");
        setReadOnly();
        TempRandomAccessBuffer raf =
            new TempRandomAccessBuffer(
                currentBucket.toRandomAccessBuffer(), creationTimeMillis, !isRAMBucket(), this);
        if (isRAMBucket()) {
          synchronized (ramBucketQueue) {
            // No change in space usage.
            ramBucketQueue.remove(getReference());
            ramBucketQueue.add(raf.getReference());
          }
        }
        currentBucket = new RAFBucket(raf);
        return raf;
      }
    }

    /** Only for tests. */
    synchronized Bucket getUnderlying() {
      return currentBucket;
    }
  }

  /**
   * Creates a new factory.
   *
   * @param executor executor used to run the background migration cleaner
   * @param filenameGenerator generator for temporary file names and base directory
   * @param maxBucketSizeKeptInRam maximum single-bucket size in bytes to keep in RAM
   * @param maxRamUsed total memory budget in bytes for RAM-backed buckets
   * @param reallyEncrypt whether disk-backed storage is wrapped in padding and encryption
   * @param minDiskSpace minimum free space in bytes to preserve on the filesystem
   * @param masterSecret key material used when {@code reallyEncrypt} is {@code true}
   */
  public TempBucketFactory(
      PriorityAwareExecutor executor,
      FilenameGenerator filenameGenerator,
      long maxBucketSizeKeptInRam,
      long maxRamUsed,
      boolean reallyEncrypt,
      long minDiskSpace,
      MasterSecret masterSecret) {
    this.filenameGenerator = filenameGenerator;
    this.maxRamUsed = maxRamUsed;
    this.maxRAMBucketSize = maxBucketSizeKeptInRam;
    this.reallyEncrypt = reallyEncrypt;
    this.executor = executor;
    PooledFileRandomAccessBufferFactory underlyingDiskRAFFactory =
        new PooledFileRandomAccessBufferFactory(filenameGenerator);
    this.minDiskSpace = minDiskSpace;
    this.diskRAFFactory =
        new DiskSpaceCheckingRandomAccessBufferFactory(
            underlyingDiskRAFFactory, filenameGenerator.getDir(), minDiskSpace - maxRamUsed);
    this.secret = masterSecret;
  }

  /**
   * Creates a new temporary bucket with the requested initial size.
   *
   * <p>If {@code size <= maxRAMBucketSize} and the pool budget allows, the bucket is initially
   * memory-backed; otherwise it is disk-backed. RAM buckets may migrate later based on age/size or
   * pool pressure.
   *
   * <p>When {@code size} is known (not {@code -1} or {@link Long#MAX_VALUE}), a preflight check may
   * reject creation if disk space falls below {@link #minDiskSpace}.
   *
   * @param size initial size in bytes, or {@code -1}/{@link Long#MAX_VALUE} when unknown
   * @return a bucket that the caller must {@link Bucket#free()} when finished
   * @throws InsufficientDiskSpaceException if the preflight disk-space check fails
   * @throws IOException on I/O errors while creating a disk-backed bucket
   */
  @Override
  public RandomAccessBucket makeBucket(long size) throws IOException {
    RandomAccessBucket realBucket;
    boolean useRAMBucket = false;
    long now = System.currentTimeMillis();

    synchronized (this) {
      if ((size > 0)
          && (size <= maxRAMBucketSize)
          && (bytesInUse < maxRamUsed)
          && (bytesInUse + size <= maxRamUsed)) {
        useRAMBucket = true;
      }
      if (bytesInUse >= maxRamUsed * MAX_USAGE_HIGH && !runningCleaner) {
        runningCleaner = true;
        executor.execute(cleaner);
      }
    }

    // Do we want a RAMBucket or a FileBucket?
    realBucket = (useRAMBucket ? new ArrayBucket() : makeFileBucket());

    if (useRAMBucket) { // No need to consider them for migration if they can't be migrated
      TempBucket tb = new TempBucket(now, realBucket);
      synchronized (ramBucketQueue) {
        ramBucketQueue.add(tb.getReference());
      }
      return tb;
    } else {
      // If we know the disk space requirement in advance, check it.
      if (size != -1
          && size != Long.MAX_VALUE
          && filenameGenerator.getDir().getUsableSpace() + size < minDiskSpace)
        throw new InsufficientDiskSpaceException();
      return new TempBucket(now, realBucket);
    }
  }

  // Internal predicate for RAM RAB eligibility.
  private boolean canUseRamRAF(long size) {
    return (size > 0)
        && (size <= maxRAMBucketSize)
        && (bytesInUse < maxRamUsed)
        && (bytesInUse + size <= maxRamUsed);
  }

  // Start cleaner when usage crosses the high watermark.
  private void maybeStartCleanerIfHighUsage() {
    if (bytesInUse >= maxRamUsed * MAX_USAGE_HIGH && !runningCleaner) {
      runningCleaner = true;
      executor.execute(cleaner);
    }
  }

  private LockableRandomAccessBuffer createDiskRAF(long size, boolean encrypt) throws IOException {
    long realSize = size;
    long paddedSize = size;
    if (encrypt) {
      realSize += TempBucketFactory.CRYPT_TYPE.headerLen;
      paddedSize =
          PaddedEphemerallyEncryptedBucket.paddedLength(
              realSize, PaddedEphemerallyEncryptedBucket.MIN_PADDED_SIZE);
    }
    LockableRandomAccessBuffer ret = diskRAFFactory.makeRAF(paddedSize);
    if (encrypt) {
      if (realSize != paddedSize) ret = new PaddedRandomAccessBuffer(ret, realSize);
      try {
        ret = new EncryptedRandomAccessBuffer(CRYPT_TYPE, ret, secret, true);
      } catch (GeneralSecurityException e) {
        LOG.error("Cannot create encrypted tempfile: {}", e, e);
      }
    }
    return ret;
  }

  private synchronized void hasFreed(long size) {
    bytesInUse -= size;
  }

  private synchronized void cleanerFreedRAM(long rabId, long size) {
    // Safety net cleanup - only free if we haven't already done so
    if (!freedRABIds.containsKey(rabId)) {
      bytesInUse -= size;
    }
  }

  /**
   * Returns the current total RAM usage in bytes for RAM-backed buckets.
   *
   * @return bytes currently accounted to RAM buckets
   */
  public synchronized long getRamUsed() {
    return bytesInUse;
  }

  /**
   * Sets the total memory budget for RAM-backed buckets.
   *
   * @param size budget in bytes
   */
  public synchronized void setMaxRamUsed(long size) {
    maxRamUsed = size;
  }

  /**
   * Returns the total memory budget for RAM-backed buckets.
   *
   * @return budget in bytes
   */
  public synchronized long getMaxRamUsed() {
    return maxRamUsed;
  }

  /**
   * Sets the maximum single-bucket size eligible for RAM.
   *
   * @param size threshold in bytes
   */
  public synchronized void setMaxRAMBucketSize(long size) {
    maxRAMBucketSize = size;
    diskRAFFactory.setMinDiskSpace(minDiskSpace - maxRamUsed);
  }

  /**
   * Returns the maximum single-bucket size eligible for RAM.
   *
   * @return threshold in bytes
   */
  public synchronized long getMaxRAMBucketSize() {
    return maxRAMBucketSize;
  }

  /**
   * Enables or disables encryption for disk-backed storage.
   *
   * <p>When enabled, disk-backed buckets and random-access buffers are wrapped with padding and an
   * {@link EncryptedRandomAccessBuffer} using {@link #CRYPT_TYPE} and {@link #secret}.
   *
   * @param value {@code true} to enable encryption
   */
  public void setEncryption(boolean value) {
    reallyEncrypt = value;
  }

  /**
   * Sets the minimum free disk space to preserve.
   *
   * <p>Operations that would reduce available space below this threshold fail fast with {@link
   * InsufficientDiskSpaceException}.
   *
   * @param min minimum free space in bytes to maintain
   */
  public synchronized void setMinDiskSpace(long min) {
    minDiskSpace = min;
    diskRAFFactory.setMinDiskSpace(minDiskSpace - maxRamUsed);
  }

  /**
   * Returns whether encryption is enabled for disk-backed storage.
   *
   * @return {@code true} when encryption wrappers are applied
   */
  public boolean isEncrypting() {
    return reallyEncrypt;
  }

  static final double MAX_USAGE_LOW = 0.8;
  static final double MAX_USAGE_HIGH = 0.9;

  /**
   * Cipher configuration used when wrapping disk-backed storage with encryption.
   *
   * <p>Note: This constant affects only temporary disk-backed buffers/buckets produced by this
   * factory and does not alter other cryptographic components.
   */
  public static final EncryptedRandomAccessBufferType CRYPT_TYPE =
      EncryptedRandomAccessBufferType.CHACHA_128;

  boolean runningCleaner = false;

  private final Runnable cleaner =
      new Runnable() {

        @Override
        @SuppressWarnings("BusyWait")
        public void run() {
          boolean saidSo = false;
          try {
            long now = System.currentTimeMillis();
            // First, migrate all the old buckets.
            boolean migratedOldBuckets = false;
            while (!migratedOldBuckets) {
              try {
                cleanBucketQueue(now, false);
                migratedOldBuckets = true;
              } catch (InsufficientDiskSpaceException _) {
                if (!saidSo) {
                  LOG.error("Insufficient disk space while migrating aged RAM buckets to disk!");
                  saidSo = true;
                }
                try {
                  // Intentional backoff: retry migration after a short pause.
                  // There is no portable event to await for "disk space increased",
                  // so we throttle retries to avoid busy-waiting and reduce CPU usage.
                  Thread.sleep(1000);
                } catch (InterruptedException _) {
                  Thread.currentThread().interrupt();
                }
              }
            }
            saidSo = false;
            while (true) {
              // Now migrate buckets until usage is below the lower threshold.
              synchronized (TempBucketFactory.this) {
                if (bytesInUse <= maxRamUsed * MAX_USAGE_LOW) return;
              }
              try {
                if (!cleanBucketQueue(System.currentTimeMillis(), true)) return;
              } catch (InsufficientDiskSpaceException _) {
                if (!saidSo) {
                  LOG.error(
                      "Insufficient disk space while force-migrating RAM buckets to reduce usage!");
                  saidSo = true;
                }
                try {
                  // Intentional backoff: retry migration after a short pause.
                  // There is no portable event to await for "disk space increased",
                  // so we throttle retries to avoid busy-waiting and reduce CPU usage.
                  Thread.sleep(1000);
                } catch (InterruptedException _) {
                  Thread.currentThread().interrupt();
                }
              }
            }
          } finally {
            synchronized (TempBucketFactory.this) {
              runningCleaner = false;
            }
          }
        }

        // Migrate long-lived buckets or force-migrate to free RAM usage.
        private boolean cleanBucketQueue(long now, boolean force)
            throws InsufficientDiskSpaceException {
          boolean shouldContinue = true;
          Queue<Migratable> toMigrate = null;
          if (LOG.isDebugEnabled()) LOG.debug("event=ram_bucket_cleaner_start");
          do {
            synchronized (ramBucketQueue) {
              final WeakReference<Migratable> tmpBucketRef = ramBucketQueue.peek();
              if (tmpBucketRef == null) shouldContinue = false;
              else {
                Migratable tmpBucket = tmpBucketRef.get();
                if (tmpBucket == null) {
                  ramBucketQueue.remove(tmpBucketRef);
                  continue; // ugh. this is freed
                }

                // Don't access the buckets inside the lock, will deadlock.
                if (tmpBucket.creationTime() + RAMBUCKET_MAX_AGE > now && !force)
                  shouldContinue = false;
                else {
                  if (LOG.isDebugEnabled())
                    LOG.debug(
                        "event=ram_bucket_age_migrate bucket={} age={}",
                        tmpBucket,
                        TimeUtil.formatTime(now - tmpBucket.creationTime()));
                  ramBucketQueue.remove(tmpBucketRef);
                  if (toMigrate == null) toMigrate = new ArrayDeque<>();
                  toMigrate.add(tmpBucket);
                  force = false;
                }
              }
            }
          } while (shouldContinue);

          if (toMigrate == null) return false;
          if (!toMigrate.isEmpty()) {
            if (LOG.isDebugEnabled())
              LOG.debug("event=ram_bucket_batch_migrate count={}", toMigrate.size());
            for (Migratable tmpBucket : toMigrate) {
              try {
                tmpBucket.migrateToDisk();
              } catch (InsufficientDiskSpaceException e) {
                throw e;
              } catch (IOException e) {
                LOG.error(
                    "An IOE occurred while migrating long-lived buckets:{}", e.getMessage(), e);
              }
            }
            return true;
          }
          return false;
        }
      };

  private final Queue<WeakReference<Migratable>> ramBucketQueue = new LinkedBlockingQueue<>();

  private RandomAccessBucket makeFileBucket() throws IOException {
    RandomAccessBucket ret =
        new TempFileBucket(filenameGenerator.makeRandomFilename(), filenameGenerator, true);
    // Do we want it to be encrypted?
    if (reallyEncrypt) {
      ret = new PaddedRandomAccessBucket(ret);
      ret = new EncryptedRandomAccessBucket(CRYPT_TYPE, ret, secret);
    }
    return ret;
  }

  /** Unlike {@link TempBucket}, the size is fixed; migration occurs on the cleaner thread only. */
  class TempRandomAccessBuffer extends SwitchableProxyRandomAccessBuffer implements Migratable {

    protected boolean hasMigrated;

    /** If false, there is in-memory storage that needs to be freed. */
    private boolean hasFreedRAM = false;

    private final long creationTimeMillis;

    /**
     * Kept in RAM so that finalizer is called on the TempBucket when *both* the
     * TempRandomAccessBuffer *and* the TempBucket are no longer reachable, in which case we will
     * free from the TempBucket. If this is null, then the TempRAB can free in finalizer.
     */
    private final TempBucket original;

    // Unique ID for tracking cleanup
    private final long rabId;

    // Cleaner for safety net resource cleanup
    private final Cleaner.Cleanable cleanable;

    TempRandomAccessBuffer(int size, long time) {
      super(new ByteArrayRandomAccessBuffer(size), size);
      creationTimeMillis = time;
      hasMigrated = false;
      original = null;
      rabId = allocateNextRABId();

      // Register best-effort safety-net; explicit free() is still required by callers.
      this.cleanable =
          resourceCleaner.register(this, new TempRABCleanup(rabId, size, TempBucketFactory.this));
    }

    public TempRandomAccessBuffer(
        byte[] initialContents, int offset, int size, long time, boolean readOnly) {
      super(new ByteArrayRandomAccessBuffer(initialContents, offset, size, readOnly), size);
      creationTimeMillis = time;
      hasMigrated = false;
      original = null;
      rabId = allocateNextRABId();

      // Register best-effort safety-net; explicit free() is still required by callers.
      this.cleanable =
          resourceCleaner.register(this, new TempRABCleanup(rabId, size, TempBucketFactory.this));
    }

    public TempRandomAccessBuffer(
        LockableRandomAccessBuffer underlying,
        long creationTime,
        boolean migrated,
        TempBucket tempBucket) {
      super(underlying, underlying.size());
      this.creationTimeMillis = creationTime;
      this.hasMigrated = hasFreedRAM = migrated;
      this.original = tempBucket;
      rabId = allocateNextRABId();

      // Register cleaner for a safety net (will be cleaned up when free() is called properly)
      this.cleanable =
          resourceCleaner.register(
              this, new TempRABCleanup(rabId, underlying.size(), TempBucketFactory.this));
    }

    @Override
    protected LockableRandomAccessBuffer innerMigrate(LockableRandomAccessBuffer underlying)
        throws IOException {
      ByteArrayRandomAccessBuffer b = (ByteArrayRandomAccessBuffer) underlying;
      byte[] buf = b.getBuffer();
      return diskRAFFactory.makeRAF(buf, 0, (int) size, b.isReadOnly());
    }

    @Override
    public void free() {
      if (!super.innerFree()) return;
      if (LOG.isDebugEnabled()) LOG.debug("event=temp_random_access_buffer_freed buffer={}", this);
      if (original != null) {
        // Tell the TempBucket to prevent log spam. Don't call free().
        original.onFreed();
      }

      // Mark as freed so cleaner won't double-free
      freedRABIds.put(rabId, true);

      // Explicit freeing completed; clear the Cleaner registration.
      if (cleanable != null) {
        cleanable.clean();
      }
    }

    @Override
    protected void afterFreeUnderlying() {
      // Called when the in-RAM storage has been freed.
      synchronized (this) {
        if (hasFreedRAM) return;
        hasFreedRAM = true;
      }
      hasFreed(size);
      freedRABIds.put(rabId, true);
      synchronized (ramBucketQueue) {
        ramBucketQueue.remove(getReference());
      }

      // Explicit freeing completed; clear the Cleaner registration.
      if (cleanable != null) {
        cleanable.clean();
      }
    }

    private final WeakReference<Migratable> weakRef = new WeakReference<>(this);

    private WeakReference<Migratable> getReference() {
      return weakRef;
    }

    @Override
    public long creationTime() {
      return creationTimeMillis;
    }

    @Override
    public boolean migrateToDisk() throws IOException {
      synchronized (this) {
        if (hasMigrated) return false;
        hasMigrated = true;
      }
      migrate();
      return true;
    }

    public synchronized boolean hasMigrated() {
      return hasMigrated;
    }

    @Override
    public void onResume(ClientContext context) {
      // Not persistent.
      throw new UnsupportedOperationException();
    }

    @Override
    public void storeTo(DataOutputStream dos) throws IOException {
      throw new UnsupportedOperationException();
    }
  }

  /**
   * Creates a lockable random-access buffer with the requested size.
   *
   * <p>For {@code size <= maxRAMBucketSize} and available budget, a RAM-backed buffer is returned;
   * otherwise a disk-backed buffer is created (with optional padding and encryption).
   *
   * @param size required size in bytes; must be {@code >= 0}
   * @return a buffer that the caller must {@link LockableRandomAccessBuffer#free()} when finished
   * @throws IllegalArgumentException if {@code size < 0}
   * @throws IOException on I/O errors while creating disk-backed storage
   */
  @Override
  public LockableRandomAccessBuffer makeRAF(long size) throws IOException {
    if (size < 0) throw new IllegalArgumentException();
    if (size > Integer.MAX_VALUE) return diskRAFFactory.makeRAF(size);

    long now = System.currentTimeMillis();

    TempRandomAccessBuffer raf = null;

    synchronized (this) {
      if (canUseRamRAF(size)) {
        raf = new TempRandomAccessBuffer((int) size, now);
        bytesInUse += size;
      }
      maybeStartCleanerIfHighUsage();
    }

    if (raf != null) {
      synchronized (ramBucketQueue) {
        ramBucketQueue.add(raf.getReference());
      }
      return raf;
    } else {
      return createDiskRAF(size, this.reallyEncrypt);
    }
  }

  /**
   * Creates a lockable random-access buffer initialized with the provided contents.
   *
   * <p>For eligible sizes and available budget, the buffer is RAM-backed; otherwise a disk-backed
   * buffer is used. When encryption is enabled, contents may be written to an encrypted, padded
   * buffer.
   *
   * @param initialContents source array
   * @param offset offset within {@code initialContents}
   * @param size number of bytes to copy; must be {@code >= 0}
   * @param readOnly whether the returned buffer should be read-only
   * @return a buffer that the caller must {@link LockableRandomAccessBuffer#free()} when finished
   * @throws IllegalArgumentException if {@code size < 0}
   * @throws IOException on I/O errors while creating disk-backed storage
   */
  @Override
  public LockableRandomAccessBuffer makeRAF(
      byte[] initialContents, int offset, int size, boolean readOnly) throws IOException {
    if (size < 0) throw new IllegalArgumentException();

    long now = System.currentTimeMillis();

    TempRandomAccessBuffer raf = null;

    synchronized (this) {
      if (canUseRamRAF(size)) {
        raf = new TempRandomAccessBuffer(initialContents, offset, size, now, readOnly);
        bytesInUse += size;
      }
      maybeStartCleanerIfHighUsage();
    }

    if (raf != null) {
      synchronized (ramBucketQueue) {
        ramBucketQueue.add(raf.getReference());
      }
      return raf;
    } else {
      if (reallyEncrypt) {
        // Note: consider encryption in memory if needed; test it before changing.
        LockableRandomAccessBuffer ret = makeRAF(size);
        ret.pwrite(0, initialContents, offset, size);
        if (readOnly) ret = new ReadOnlyRandomAccessBuffer(ret);
        return ret;
      }
      return diskRAFFactory.makeRAF(initialContents, offset, size, readOnly);
    }
  }

  /**
   * Returns the underlying disk-backed buffer factory that performs disk-space checks.
   *
   * @return the underlying factory instance
   */
  public DiskSpaceCheckingRandomAccessBufferFactory getUnderlyingRAFFactory() {
    return diskRAFFactory;
  }
}

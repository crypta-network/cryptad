package network.crypta.store.caching;

import java.util.ArrayList;
import network.crypta.support.Ticker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Tracks approximate memory usage across multiple {@link CachingFreenetStore} instances and
 * triggers background flushes when nearing capacity or after a configured delay.
 *
 * <p>The tracker accepts size deltas (in bytes) via {@link #add(long)} and schedules cache flushes
 * on a {@link Ticker}: immediately when usage crosses a lower threshold (around 90% of the
 * configured maximum) and otherwise after the given period has elapsed since the last writing. The
 * design aims to avoid disk I/O while holding locks; flushes run off-thread by repeatedly calling
 * {@link CachingFreenetStore#pushLeastRecentlyBlock()} on registered stores.
 *
 * <p>Thread-safety: public methods are safe for concurrent use. At most one flush job runs at a
 * time, and at most one delayed job is queued. Internal synchronization ensures that accounting
 * updates and job scheduling are consistent without performing blocking I/O inside synchronized
 * sections.
 *
 * <p>Units: sizes are bytes; delays are milliseconds.
 *
 * @author Simon Vocella <voxsim@gmail.com>
 */
public class CachingFreenetStoreTracker {
  private static final Logger LOG = LoggerFactory.getLogger(CachingFreenetStoreTracker.class);

  /**
   * Maximum number of blocks drained from a single store per pass during a flush. This keeps
   * fairness between stores and prevents a single large cache from monopolizing the flush loop.
   */
  private static final int NUMBER_OF_KEYS_TO_WRITE = 20;

  /**
   * Lower-usage threshold. When the next adding crosses this ratio of {@link #maxSize}, the tracker
   * schedules an immediate background flush but still accepts the data.
   */
  private static final double LOWER_THRESHOLD = 0.9;

  private final long maxSize;
  private final long period;
  private final ArrayList<CachingFreenetStore<?>> cachingStores;
  private final Ticker ticker;

  /**
   * Whether a delayed flush job is currently queued. Only one delayed job is permitted at a time;
   * if capacity is reached before it runs, an immediate job is scheduled instead.
   */
  private boolean queuedJob;

  /**
   * Whether a flush job is currently running. Prevents parallel execution of {@link
   * #pushAllCachingStores()} and limits transient memory pressure during flushes.
   */
  private boolean runningJob;

  private long size;

  /**
   * Creates a tracker with the given capacity and flush period.
   *
   * @param maxSize maximum cached size in bytes across all registered stores
   * @param period maximum delay in milliseconds before a delayed flush is triggered
   * @param ticker scheduler used to run background flush tasks; must not be {@code null}
   * @throws IllegalArgumentException if {@code ticker} is {@code null}
   */
  public CachingFreenetStoreTracker(long maxSize, long period, Ticker ticker) {
    if (ticker == null) throw new IllegalArgumentException();
    this.size = 0;
    this.maxSize = maxSize;
    this.period = period;
    this.queuedJob = false;
    this.cachingStores = new ArrayList<>();
    this.ticker = ticker;
  }

  /**
   * Registers a caching store to participate in background flushes.
   *
   * <p>The tracker will call {@link CachingFreenetStore#pushLeastRecentlyBlock()} during flushes to
   * drain cached entries from the store. Registration is idempotent with respect to the same
   * instance only through collection semantics; duplicates are not automatically filtered.
   *
   * @param fs the store to register; must not be {@code null}
   */
  public void registerCachingFS(CachingFreenetStore<?> fs) {
    synchronized (cachingStores) {
      cachingStores.add(fs);
    }
  }

  /**
   * Unregisters a store and drains its cached entries before removal.
   *
   * <p>This method repeatedly invokes {@link CachingFreenetStore#pushLeastRecentlyBlock()} on the
   * provided store until it reports no more cached data, decrementing the global counter as it
   * proceeds. Depending on the store implementation, draining may perform disk I/O.
   *
   * @param fs the store to unregister; must not be {@code null}
   */
  public void unregisterCachingFS(CachingFreenetStore<?> fs) {
    long sizeBlock;
    while (true) {
      sizeBlock = fs.pushLeastRecentlyBlock();
      synchronized (this) {
        if (sizeBlock == -1) break;
        else size -= sizeBlock;
      }
    }

    synchronized (cachingStores) {
      cachingStores.remove(fs);
    }
  }

  /**
   * Accounts for a new block and schedules flushes as needed.
   *
   * <p>If the new total exceeds the lower threshold (about 90% of {@link #maxSize}), an immediate
   * background flush is scheduled. If the total would exceed {@link #maxSize}, the block is
   * rejected and the caller should write directly to the underlying store. Otherwise, the block is
   * accepted and a delayed flush is scheduled if one is not already pending.
   *
   * @param sizeBlock size of the block in bytes; must be non-negative
   * @return {@code true} if the block is accepted for caching; {@code false} if it should be
   *     written directly by the caller
   */
  public synchronized boolean add(long sizeBlock) {
    // Preemptive flush when crossing ~90% of capacity; still account the block.
    boolean justStartedPush = false;
    if (this.size + sizeBlock > this.maxSize * LOWER_THRESHOLD) {
      pushOffThreadNow();
      justStartedPush = true;
    }
    // Hard cap: refuse to cache beyond the configured maximum.
    if (this.size + sizeBlock > this.maxSize) {
      // Over the limit: signal the caller to write through directly.
      // A delayed job may already be queued, which is acceptable.
      return false;
    } else {
      this.size += sizeBlock;
      if (!justStartedPush) {
        // Ensure a flush runs after the maximum delay unless one is already queued.
        pushOffThreadDelayed();
      } // Else will be written anyway.
      return true;
    }
  }

  private synchronized void pushOffThreadNow() {
    if (runningJob) return;
    runningJob = true;
    this.ticker.queueTimedJob(
        () -> {
          try {
            pushAllCachingStores();
          } finally {
            synchronized (CachingFreenetStoreTracker.this) {
              runningJob = false;
            }
          }
        },
        0);
  }

  private void pushOffThreadDelayed() {
    if (queuedJob) return;
    queuedJob = true;
    this.ticker.queueTimedJob(
        () -> {
          synchronized (CachingFreenetStoreTracker.this) {
            if (runningJob) return;
            runningJob = true;
          }
          try {
            pushAllCachingStores();
          } finally {
            synchronized (CachingFreenetStoreTracker.this) {
              queuedJob = false;
              runningJob = false;
            }
          }
        },
        period);
  }

  // Flushes blocks from registered stores until the global counter reaches zero.
  void pushAllCachingStores() {
    CachingFreenetStore<?>[] cachingStoresSnapshot;

    while (true) {
      // Take a fresh snapshot each pass so newly registered stores are eventually included.
      synchronized (cachingStores) {
        cachingStoresSnapshot =
            this.cachingStores.toArray(new CachingFreenetStore<?>[cachingStores.size()]);
      }
      for (CachingFreenetStore<?> cfs : cachingStoresSnapshot) {
        if (drainStoreOnce(cfs)) return;
      }
    }
  }

  /** Drains up to {@link #NUMBER_OF_KEYS_TO_WRITE} blocks from one store. */
  private boolean drainStoreOnce(CachingFreenetStore<?> cfs) {
    int k = 0;
    while (k < NUMBER_OF_KEYS_TO_WRITE) {
      long sizeBlock = cfs.pushLeastRecentlyBlock();
      if (sizeBlock == -1) break;
      synchronized (this) {
        size -= sizeBlock;
        if (size < 0) {
          LOG.error("Cache broken: Size = {}", size);
          size = 0;
        }
        if (size == 0) return true;
      }
      k++;
    }
    return false;
  }

  /**
   * Returns the current total size of cached data across all registered stores.
   *
   * <p>The value is an instantaneous snapshot taken under synchronization and may change
   * immediately after return.
   *
   * @return total cached size in bytes
   */
  public long getSizeOfCache() {
    long sizeReturned;
    synchronized (this) {
      sizeReturned = size;
    }
    return sizeReturned;
  }
}

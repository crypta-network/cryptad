package network.crypta.store.saltedhash;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Coordinates exclusive access to long-indexed entries.
 *
 * <p>This manager serializes access to entries addressed by a {@code long} offset. At any given
 * time, at most one thread holds the lock for a specific offset. Successful acquisition returns a
 * {@link Condition} that represents the ownership token; the caller must pass that same instance to
 * {@link #unlockEntry(long, Condition)} to release the lock and signal the next waiter.
 *
 * <p>Locks are not reentrant and ownership is not tracked per thread. Do not attempt to acquire
 * more than one offset lock at a time (doing so may deadlock), except for the special Cleaner
 * thread referenced by the original design. Acquisition uses a timed wait to periodically re-check
 * the shutdown flag and to tolerate spurious wakeups.
 *
 * <p>After {@link #shutdown()} is called, no new locks are granted and the method blocks until all
 * outstanding locks are released.
 *
 * <p>Thread safety: all methods are thread-safe. Methods may block.
 *
 * @author sdiz
 */
public class LockManager {
  private static final Logger LOG = LoggerFactory.getLogger(LockManager.class);
  // Set to true to refuse new acquisitions and to allow waiters to exit promptly.
  private volatile boolean shutdown;
  // Single lock guarding access to the map and backing all per-entry Conditions.
  private final Lock entryLock = new ReentrantLock();
  // Presence of a key indicates that the corresponding offset is currently locked. The associated
  // Condition is used to await/signal hand-off to the next waiter.
  private final Map<Long, Condition> lockMap = new HashMap<>();

  LockManager() {}

  /**
   * Acquires exclusive access for the given offset.
   *
   * <p>The returned {@link Condition} is the ownership token. Callers must eventually invoke {@link
   * #unlockEntry(long, Condition)} with the same {@code Condition} instance to release the lock and
   * wake one waiting thread, if any.
   *
   * <p>This lock is <strong>not</strong> reentrant. No threads except the Cleaner should hold more
   * than one offset lock at a time because no global acquisition order is enforced.
   *
   * @param offset entry identifier to lock
   * @return the {@code Condition} representing the acquired lock, or {@code null} if the manager is
   *     shutting down or the thread is interrupted while waiting
   */
  Condition lockEntry(long offset) {
    if (LOG.isTraceEnabled()) LOG.trace("try locking {}", offset);

    Condition condition;
    try {
      entryLock.lock();
      try {
        do {
          if (shutdown) return null;

          Condition lockCond = lockMap.get(offset);
          if (lockCond != null) {
            // Wait in bounded intervals so we periodically re-check the shutdown flag and tolerate
            // spurious/missed signals (loop condition re-validates ownership availability).
            boolean signaled = lockCond.await(10, TimeUnit.SECONDS);
            if (!signaled && shutdown) {
              return null;
            }
          } else break;
        } while (true);
        condition = entryLock.newCondition();
        lockMap.put(offset, condition);
      } finally {
        entryLock.unlock();
      }
    } catch (InterruptedException e) {
      LOG.error("lock interrupted", e);
      // Restore the interrupt status so higher layers can observe it.
      Thread.currentThread().interrupt();
      return null;
    }

    if (LOG.isTraceEnabled()) LOG.trace("locked {}", offset);
    return condition;
  }

  /**
   * Releases the lock for {@code offset} and signals one waiting thread.
   *
   * <p>The {@code condition} argument must be the exact instance returned by the corresponding
   * successful call to {@link #lockEntry(long)}; passing a different instance is a programming
   * error and will trigger the assertion in debug builds.
   *
   * @param offset entry identifier to unlock
   * @param condition the ownership token previously returned by {@code lockEntry}
   */
  void unlockEntry(long offset, Condition condition) {
    if (LOG.isTraceEnabled()) LOG.trace("unlocking {}", offset);

    entryLock.lock();
    try {
      Condition cond = lockMap.remove(offset);
      assert cond == condition;
      // Signal after removal so the next waiter can observe the map state as unlocked.
      cond.signal();
    } finally {
      entryLock.unlock();
    }
  }

  /**
   * Initiates shutdown and waits until all locks are released.
   *
   * <p>After this call sets the shutdown flag, new calls to {@link #lockEntry(long)} return {@code
   * null}. The method then blocks until the {@linkplain #unlockEntry(long, Condition) owners} of
   * all currently held locks release them. If a caller leaks a lock, this method may block
   * indefinitely.
   */
  void shutdown() {
    shutdown = true;
    entryLock.lock();
    try {
      while (!lockMap.isEmpty()) {
        Condition cond = lockMap.values().iterator().next();
        // Wait for a holder to release and signal; uninterruptible to ensure progress to empty.
        cond.awaitUninterruptibly();
      }
    } finally {
      entryLock.unlock();
    }
  }
}

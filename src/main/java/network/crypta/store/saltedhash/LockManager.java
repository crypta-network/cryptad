package network.crypta.store.saltedhash;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import network.crypta.support.Logger;
import network.crypta.support.Logger.LogLevel;

/**
 * Lock Manager
 *
 * <p>Handle locking/unlocking of individual offsets.
 *
 * @author sdiz
 */
public class LockManager {
  private static boolean logDEBUG;
  private volatile boolean shutdown;
  private final Lock entryLock = new ReentrantLock();
  private final Map<Long, Condition> lockMap = new HashMap<>();

  LockManager() {
    logDEBUG = Logger.shouldLog(LogLevel.DEBUG, this);
  }

  /**
   * Lock the entry
   *
   * <p>This lock is <strong>not</strong> re-entrance. No threads except Cleaner should hold more
   * then one lock at a time (or deadlock may occur).
   */
  Condition lockEntry(long offset) {
    if (logDEBUG) Logger.debug(this, "try locking " + offset, new Exception());

    Condition condition;
    try {
      entryLock.lock();
      try {
        do {
          if (shutdown) return null;

          Condition lockCond = lockMap.get(offset);
          if (lockCond != null) lockCond.await(10, TimeUnit.SECONDS); // 10s for checking shutdown
          else break;
        } while (true);
        condition = entryLock.newCondition();
        lockMap.put(offset, condition);
      } finally {
        entryLock.unlock();
      }
    } catch (InterruptedException e) {
      Logger.error(this, "lock interrupted", e);
      return null;
    }

    if (logDEBUG) Logger.debug(this, "locked " + offset, new Exception());
    return condition;
  }

  /** Unlock the entry */
  void unlockEntry(long offset, Condition condition) {
    if (logDEBUG) Logger.debug(this, "unlocking " + offset, new Exception("debug"));

    entryLock.lock();
    try {
      Condition cond = lockMap.remove(offset);
      assert cond == condition;
      cond.signal();
    } finally {
      entryLock.unlock();
    }
  }

  /** Shutdown and wait for all entries unlocked */
  void shutdown() {
    shutdown = true;
    entryLock.lock();
    try {
      while (!lockMap.isEmpty()) {
        Condition cond = lockMap.values().iterator().next();
        cond.awaitUninterruptibly();
      }
    } finally {
      entryLock.unlock();
    }
  }
}

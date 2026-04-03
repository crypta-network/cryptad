package network.crypta.node;

import network.crypta.support.TimeUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Tracks a short-lived routing backoff decision.
 *
 * <p>This class records that routing recently failed and stores an absolute wakeup time
 * (milliseconds since epoch) after which routing may be attempted again. The state is intentionally
 * minimal: a boolean flag and a wakeup timestamp. All public methods are synchronized to provide
 * simple thread-safety when accessed from multiple threads.
 */
public class RecentlyFailedReturn {
  private static final Logger LOG = LoggerFactory.getLogger(RecentlyFailedReturn.class);

  // True while a recent-failure window is active. Overwritten by subsequent calls to fail(...).
  private boolean recentlyFailed;
  // Absolute timestamp (milliseconds since epoch) when the recent-failure window ends.
  private long wakeup;

  /**
   * Creates an inactive recent-failure tracker.
   *
   * <p>New instances start with no active backoff window. Callers typically allocate one tracker
   * per routing decision and then reuse it as failures are observed.
   */
  public RecentlyFailedReturn() {}

  /**
   * Mark this instance as recently failed until the provided wakeup time.
   *
   * <p>The {@code wakeupTime} is an absolute timestamp in milliseconds since the epoch. A later
   * invocation overwrites the previous value.
   *
   * @param wakeupTime absolute timestamp (milliseconds since epoch) when the failure window ends
   */
  public synchronized void fail(long wakeupTime) {
    if (LOG.isDebugEnabled())
      LOG.debug(
          "RecentlyFailed active for {}",
          TimeUtil.formatTime(wakeupTime - System.currentTimeMillis()));
    this.wakeup = wakeupTime;
    this.recentlyFailed = true;
  }

  /**
   * Return the absolute wakeup time if a recent failure is active.
   *
   * @return the absolute wakeup time (milliseconds since epoch) when routing may be retried, or
   *     {@code -1} when no recent failure is active
   */
  public synchronized long recentlyFailed() {
    if (recentlyFailed) return wakeup;
    else return -1;
  }
}

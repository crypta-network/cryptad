package network.crypta.node;

import network.crypta.support.TimeUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Contains information on why we can't route a request. Initially just a flag and a time. */
public class RecentlyFailedReturn {
    private static final Logger LOG = LoggerFactory.getLogger(RecentlyFailedReturn.class);

  static {

  }

  private boolean recentlyFailed;
  private long wakeup;

  public synchronized void fail(int countWaiting, long wakeupTime) {
    if (LOG.isDebugEnabled())
      LOG.debug("RecentlyFailed until " + TimeUtil.formatTime(wakeupTime - System.currentTimeMillis()));
    this.wakeup = wakeupTime;
    this.recentlyFailed = true;
  }

  public synchronized long recentlyFailed() {
    if (recentlyFailed) return wakeup;
    else return -1;
  }
}

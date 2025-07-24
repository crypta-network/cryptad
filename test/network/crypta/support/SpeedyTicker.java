package network.crypta.support;

import network.crypta.support.Executor;
import network.crypta.support.Ticker;

/**
 * A mock Ticker that does ... nothing (avoids sleeping in unit tests)
 */
public class SpeedyTicker implements Ticker {

    public void queueTimedJob(Runnable job, long offset) {
    }

    public void queueTimedJob(
        Runnable job, String name, long offset, boolean runOnTickerAnyway, boolean noDupes) {
    }

    public Executor getExecutor() {
        throw new UnsupportedOperationException();
    }

    public void removeQueuedJob(Runnable job) {
        throw new UnsupportedOperationException();
    }

    public void queueTimedJobAbsolute(
        Runnable runner, String name, long time, boolean runOnTickerAnyway,
        boolean noDupes) {
        throw new UnsupportedOperationException();
    }
}

package network.crypta.node;

import java.util.concurrent.TimeUnit;
import network.crypta.support.math.RunningAverage;
import network.crypta.support.math.SimpleRunningAverage;
import network.crypta.support.math.TimeDecayingRunningAverage;

/**
 * Routing/backoff-related rolling statistics for a {@link PeerNode}.
 *
 * <p>This helper owns the time-decaying averages used for:
 *
 * <ul>
 *   <li>Swap/probe request rate limiting
 *   <li>Ping smoothing
 *   <li>Local rejection (pRejected) tracking
 *   <li>Backoff percent tracking for pruning and UI
 * </ul>
 *
 * <p>Thread-safety: the underlying {@link RunningAverage} implementations are thread-safe; this
 * class synchronizes only when combining samples with {@code lastSampleTime}.
 */
final class PeerNodeRoutingStats {
  private final RunningAverage swapRequestsInterval;
  private final RunningAverage probeRequestsInterval;
  private final RunningAverage backedOffPercent;
  private final RunningAverage backedOffPercentRT;
  private final RunningAverage backedOffPercentBulk;
  private final RunningAverage pingAverage;
  private final TimeDecayingRunningAverage pRejected;

  /** Time of last backoff sample (milliseconds since epoch). */
  private long lastSampleTime = Long.MAX_VALUE;

  PeerNodeRoutingStats(Node node) {
    this.backedOffPercent = new TimeDecayingRunningAverage(0.0, 180000, 0.0, 1.0, node);
    this.backedOffPercentRT = new TimeDecayingRunningAverage(0.0, 180000, 0.0, 1.0, node);
    this.backedOffPercentBulk = new TimeDecayingRunningAverage(0.0, 180000, 0.0, 1.0, node);

    this.swapRequestsInterval =
        new SimpleRunningAverage(50, Node.MIN_INTERVAL_BETWEEN_INCOMING_SWAP_REQUESTS);
    this.probeRequestsInterval =
        new SimpleRunningAverage(50, Node.MIN_INTERVAL_BETWEEN_INCOMING_PROBE_REQUESTS);

    this.pingAverage =
        new TimeDecayingRunningAverage(
            1, TimeUnit.SECONDS.toMillis(30), 0, NodePinger.CRAZY_MAX_PING_TIME, node);
    this.pRejected =
        new TimeDecayingRunningAverage(0, TimeUnit.MINUTES.toMillis(4), 0.0, 1.0, node);
  }

  void reportSwapInterval(long deltaMillis) {
    swapRequestsInterval.report(deltaMillis);
  }

  double averageSwapInterval() {
    return swapRequestsInterval.currentValue();
  }

  void reportProbeInterval(long deltaMillis) {
    probeRequestsInterval.report(deltaMillis);
  }

  double averageProbeInterval() {
    return probeRequestsInterval.currentValue();
  }

  void reportPing(long pingMillis) {
    pingAverage.report(pingMillis);
  }

  double averagePingTime() {
    return pingAverage.currentValue();
  }

  void reportRejectedOverload() {
    pRejected.report(1.0);
  }

  void reportNotRejectedOverload() {
    pRejected.report(0.0);
  }

  double pRejected() {
    return pRejected.currentValue();
  }

  double backedOffPercent() {
    return backedOffPercent.currentValue();
  }

  double backedOffPercentRT() {
    return backedOffPercentRT.currentValue();
  }

  double backedOffPercentBulk() {
    return backedOffPercentBulk.currentValue();
  }

  /**
   * Updates time-decaying averages of the proportion of time spent in routing backoff.
   *
   * @param now current time in milliseconds since epoch
   * @param routingBackedOffUntilRT routing-backoff-until for real-time traffic
   * @param routingBackedOffUntilBulk routing-backoff-until for bulk traffic
   */
  void reportBackoffStatus(long now, long routingBackedOffUntilRT, long routingBackedOffUntilBulk) {
    synchronized (this) {
      if (now > lastSampleTime) { // don't report twice in the same millisecond
        double rt = computeAndReportBackoff(now, routingBackedOffUntilRT, backedOffPercentRT);
        double bulk = computeAndReportBackoff(now, routingBackedOffUntilBulk, backedOffPercentBulk);
        backedOffPercent.report(Math.min(rt, bulk));
      }
      lastSampleTime = now;
    }
  }

  private double computeAndReportBackoff(long now, long backedOffUntil, RunningAverage avg) {
    if (now > backedOffUntil) { // not backed off
      if (lastSampleTime > backedOffUntil) { // last sample after last backoff
        avg.report(0.0);
        return 0.0;
      } else if (backedOffUntil > 0) {
        double fraction =
            (double) (backedOffUntil - lastSampleTime) / (double) (now - lastSampleTime);
        avg.report(fraction);
        return fraction;
      } else {
        return 0.0;
      }
    } else {
      avg.report(1.0);
      return 1.0;
    }
  }
}

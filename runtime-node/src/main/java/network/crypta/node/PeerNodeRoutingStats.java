package network.crypta.node;

import java.util.concurrent.TimeUnit;
import network.crypta.support.math.RunningAverage;
import network.crypta.support.math.RunningAverageBounds;
import network.crypta.support.math.SimpleRunningAverage;
import network.crypta.support.math.TimeDecayingRunningAverage;

/**
 * Maintains rolling routing and backoff statistics for a {@link PeerNode}.
 *
 * <p>This helper owns the time-decaying and simple running averages that track recent routing
 * behavior and load signals. It is used to smooth noisy inputs such as ping latency and to turn
 * event-like signals (for example, overload rejections and backoff windows) into proportions that
 * can be queried by other node components. Typical usage is to record event samples as they occur
 * and then read the current averages when making routing or UI decisions. The values are kept in
 * bounded ranges, most often as milliseconds or fractions in the {@code [0, 1]} interval.
 *
 * <p>Concurrency and lifecycle: the underlying {@link RunningAverage} instances are thread-safe for
 * independent sample reporting. This class synchronizes only when combining samples that are
 * sensitive to {@code lastSampleTime}, ensuring that backoff proportions are derived from a
 * consistent time window. The object is mutable, long-lived, and intended to be shared within the
 * owning {@link PeerNode} without additional external synchronization.
 *
 * <p>Responsibilities include:
 *
 * <ul>
 *   <li>Tracking swap/probe request intervals for rate limiting decisions.
 *   <li>Smoothing ping measurements for routing heuristics.
 *   <li>Estimating overload rejection probability for feedback signals.
 *   <li>Computing backoff proportions for pruning and UI reporting.
 * </ul>
 */
final class PeerNodeRoutingStats {
  /**
   * Running average of the intervals between incoming swap requests, in milliseconds.
   *
   * <p>The value is used to smooth bursty traffic so callers can compare recent request cadence to
   * configured minimums. Samples are reported via {@link #reportSwapInterval(long)} and queried
   * using {@link #averageSwapInterval()}.
   */
  private final RunningAverage swapRequestsInterval;

  /**
   * Running average of the intervals between incoming probe requests, in milliseconds.
   *
   * <p>This average is updated by {@link #reportProbeInterval(long)} and read through {@link
   * #averageProbeInterval()}, providing a smoothed signal for probe rate limiting and diagnostics.
   */
  private final RunningAverage probeRequestsInterval;

  /**
   * Combined backoff proportion for routing, expressed as a fraction in {@code [0, 1]}.
   *
   * <p>The value is derived from the real-time and bulk backoff samples reported in {@link
   * #reportBackoffStatus(long, long, long)} and reflects the minimum of those proportions over the
   * most recent sampling interval.
   */
  private final RunningAverage backedOffPercent;

  /**
   * Backoff proportion for real-time traffic, expressed as a fraction in {@code [0, 1]}.
   *
   * <p>Updated by {@link #reportBackoffStatus(long, long, long)} based on the {@code
   * routingBackedOffUntilRT} input and the time between samples.
   */
  private final RunningAverage backedOffPercentRT;

  /**
   * Backoff proportion for bulk traffic, expressed as a fraction in {@code [0, 1]}.
   *
   * <p>Updated by {@link #reportBackoffStatus(long, long, long)} based on the {@code
   * routingBackedOffUntilBulk} input and the time between samples.
   */
  private final RunningAverage backedOffPercentBulk;

  /**
   * Time-decaying running average of peer ping times in milliseconds.
   *
   * <p>Samples are reported via {@link #reportPing(long)} and smoothed over a short time window to
   * reduce transient noise in latency measurements used by routing heuristics.
   */
  private final RunningAverage pingAverage;

  /**
   * Time-decaying probability of overload rejection, expressed as a fraction in {@code [0, 1]}.
   *
   * <p>Values are updated using {@link #reportRejectedOverload()} and {@link
   * #reportNotRejectedOverload()}, allowing callers to observe the recent rate of overload
   * rejections without storing individual events.
   */
  private final TimeDecayingRunningAverage pRejected;

  /** Time of the last backoff sample (milliseconds since epoch). */
  private long lastSampleTime = Long.MAX_VALUE;

  /**
   * Creates a new statistics tracker for a peer node.
   *
   * <p>The instance initializes a set of time-decaying and fixed-size running averages with bounds
   * and windows tuned to routing behavior. Callers are expected to keep the instance for the
   * lifetime of the owning {@link PeerNode} and to report samples as events occur. No input values
   * are validated here; the underlying averages apply their own bounds and decay behavior as
   * configured.
   *
   * @param node node context used by time-decaying averages for timing and lifecycle integration;
   *     must be non-null and remain valid while this tracker is in use
   */
  PeerNodeRoutingStats(Node node) {
    this.backedOffPercent =
        new TimeDecayingRunningAverage(RunningAverageBounds.of(0.0, 0.0, 1.0), 180000, node);
    this.backedOffPercentRT =
        new TimeDecayingRunningAverage(RunningAverageBounds.of(0.0, 0.0, 1.0), 180000, node);
    this.backedOffPercentBulk =
        new TimeDecayingRunningAverage(RunningAverageBounds.of(0.0, 0.0, 1.0), 180000, node);

    this.swapRequestsInterval =
        new SimpleRunningAverage(50, Node.MIN_INTERVAL_BETWEEN_INCOMING_SWAP_REQUESTS);
    this.probeRequestsInterval =
        new SimpleRunningAverage(50, Node.MIN_INTERVAL_BETWEEN_INCOMING_PROBE_REQUESTS);

    this.pingAverage =
        new TimeDecayingRunningAverage(
            RunningAverageBounds.of(1, 0, NodePinger.CRAZY_MAX_PING_TIME),
            TimeUnit.SECONDS.toMillis(30),
            node);
    this.pRejected =
        new TimeDecayingRunningAverage(
            RunningAverageBounds.of(0, 0.0, 1.0), TimeUnit.MINUTES.toMillis(4), node);
  }

  /**
   * Records the interval between two incoming swap requests.
   *
   * <p>Callers should supply the elapsed time in milliseconds between consecutive swap requests
   * observed for this peer. The sample is added to a fixed-size running average to smooth bursts
   * and to provide a stable rate signal. Supplying large or negative values is permitted but will
   * be reflected in the average as reported.
   *
   * @param deltaMillis elapsed time between swap requests in milliseconds, as measured by the
   *     caller
   */
  void reportSwapInterval(long deltaMillis) {
    swapRequestsInterval.report(deltaMillis);
  }

  /**
   * Returns the smoothed interval between incoming swap requests.
   *
   * <p>The value is the current running-average sample in milliseconds. It is intended for rate
   * limiting and diagnostics and reflects the most recent samples reported via {@link
   * #reportSwapInterval(long)}. A larger value indicates a slower observed swap cadence.
   *
   * @return the current average swap interval in milliseconds, based on recent samples
   */
  double averageSwapInterval() {
    return swapRequestsInterval.currentValue();
  }

  /**
   * Records the interval between two incoming probe requests.
   *
   * <p>This updates the probe interval running average with a caller-supplied elapsed time in
   * milliseconds. The sample sequence is used to smooth variability and to expose a stable signal
   * for rate limiting. The value is accepted as provided and is not validated here.
   *
   * @param deltaMillis elapsed time between probe requests in milliseconds, as measured by the
   *     caller
   */
  void reportProbeInterval(long deltaMillis) {
    probeRequestsInterval.report(deltaMillis);
  }

  /**
   * Returns the smoothed interval between incoming probe requests.
   *
   * <p>The value is the current running average of probe request spacing in milliseconds. It is
   * updated by {@link #reportProbeInterval(long)} and can be used to compare observed probe traffic
   * against expected limits or to surface diagnostics.
   *
   * @return the current average probe interval in milliseconds, based on recent samples
   */
  double averageProbeInterval() {
    return probeRequestsInterval.currentValue();
  }

  /**
   * Records a ping latency sample for this peer.
   *
   * <p>Provide the measured ping time in milliseconds. The value is incorporated into a
   * time-decaying running average, which yields a smoothed latency estimate for routing decisions.
   * If callers report outliers, they will influence the average according to the decay window and
   * bounds configured by the underlying implementation.
   *
   * @param pingMillis measured ping latency in milliseconds for this peer
   */
  void reportPing(long pingMillis) {
    pingAverage.report(pingMillis);
  }

  /**
   * Returns the smoothed ping latency for this peer.
   *
   * <p>The value reflects the current time-decaying average of ping measurements in milliseconds.
   * It is intended for use in routing heuristics and diagnostics and updates as new samples are
   * reported via {@link #reportPing(long)}.
   *
   * @return the current average ping time in milliseconds over the configured decay window
   */
  double averagePingTime() {
    return pingAverage.currentValue();
  }

  /**
   * Records an overload rejection event for this peer.
   *
   * <p>This reports a {@code 1.0} sample into the time-decaying average for overload rejections,
   * increasing the observed probability of rejection over the recent time window. Callers should
   * invoke this when an attempt to route or enqueue work is rejected due to overload.
   */
  void reportRejectedOverload() {
    pRejected.report(1.0);
  }

  /**
   * Records a non-rejection outcome for overload tracking.
   *
   * <p>This reports a {@code 0.0} sample into the time-decaying average, decreasing the observed
   * probability of overload rejection. Callers should invoke this for comparable events where work
   * is accepted, so the rejection probability reflects recent behavior.
   */
  void reportNotRejectedOverload() {
    pRejected.report(0.0);
  }

  /**
   * Returns the current probability of overload rejection.
   *
   * <p>The value is a time-decaying fraction in {@code [0, 1]} derived from the most recent
   * overload acceptance and rejection samples. A value closer to {@code 1} indicates frequent
   * overload rejections over the configured window.
   *
   * @return the current overload rejection probability as a fraction in {@code [0, 1]}
   */
  double pRejected() {
    return pRejected.currentValue();
  }

  /**
   * Returns the combined backoff proportion across real-time and bulk traffic.
   *
   * <p>The returned value is derived from the minimum of the real-time and bulk backoff samples
   * computed in {@link #reportBackoffStatus(long, long, long)}. It is expressed as a fraction in
   * {@code [0, 1]} where {@code 1} indicates fully backed off for the sampling window.
   *
   * @return the current combined backoff fraction in {@code [0, 1]}
   */
  double backedOffPercent() {
    return backedOffPercent.currentValue();
  }

  /**
   * Returns the backoff proportion for real-time traffic.
   *
   * <p>The value is a time-decaying fraction in {@code [0, 1]} that represents the portion of the
   * most recent sampling window during which real-time routing was backed off.
   *
   * @return the current real-time backoff fraction in {@code [0, 1]}
   */
  double backedOffPercentRT() {
    return backedOffPercentRT.currentValue();
  }

  /**
   * Returns the backoff proportion for bulk traffic.
   *
   * <p>The value is a time-decaying fraction in {@code [0, 1]} that represents the portion of the
   * most recent sampling window during which bulk routing was backed off.
   *
   * @return the current bulk backoff fraction in {@code [0, 1]}
   */
  double backedOffPercentBulk() {
    return backedOffPercentBulk.currentValue();
  }

  /**
   * Updates time-decaying averages of the proportion of time spent in routing backoff.
   *
   * <p>This method computes backoff fractions for real-time and bulk routing by comparing the
   * supplied backoff deadlines with the current time and the previous sampling timestamp. It
   * records those fractions into the respective running averages and then records the minimum of
   * the two into the combined backoff average. Calls within the same millisecond are coalesced to
   * avoid double-counting. The method is synchronized to ensure consistent use of {@code
   * lastSampleTime}.
   *
   * @param now current time in milliseconds since epoch, used as the end of the sampling window
   * @param routingBackedOffUntilRT timestamp in milliseconds since epoch until which real-time
   *     routing is backed off; values in the past indicate no backoff
   * @param routingBackedOffUntilBulk timestamp in milliseconds since epoch until which bulk routing
   *     is backed off; values in the past indicate no backoff
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

  /**
   * Computes and reports the backoff fraction for a single routing class.
   *
   * <p>The fraction is derived from the overlap between the time window {@code [lastSampleTime,
   * now]} and the backoff window ending at {@code backedOffUntil}. A return value of {@code 0.0}
   * indicates no backoff during the window, while {@code 1.0} indicates full backoff throughout.
   * The computed value is reported to the provided running average.
   *
   * @param now current time in milliseconds since the epoch that ends the sampling window
   * @param backedOffUntil timestamp in milliseconds since epoch indicating backoff end time
   * @param avg running average to receive the computed backoff fraction
   * @return the backoff fraction in {@code [0, 1]} for the sampled interval
   */
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

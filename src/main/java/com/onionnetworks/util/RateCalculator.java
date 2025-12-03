// (c) Copyright 2000 Justin F. Chapweske
// (c) Copyright 2000 Ry4an C. Brase

package com.onionnetworks.util;

import java.util.Arrays;

/**
 * Computes a smoothed event rate over time using weighted exponential history. The calculator
 * aggregates events into fixed-size intervals, blends recent and historical throughput, and exposes
 * helpers to estimate future progress or remaining time. It is suitable for long-running transfers,
 * background processing loops, and UI displays that need a responsive yet stable rate readout.
 *
 * <p>Intervals are tracked in a circular buffer; each completed interval contributes to the
 * weighted average, while the current interval accumulates live event counts. Callers typically
 * construct an instance, invoke {@link #update(double)} whenever work units complete, and query
 * {@link #getRate} or {@link #getEstimatedTimeRemaining(double)} from the same time base they
 * supply to updates.
 *
 * <p>Concurrency: this class is not thread-safe. External synchronization is required if updates or
 * reads may occur from multiple threads. Mutability is confined to internal counters; configuration
 * is fixed after construction.
 *
 * <ul>
 *   <li>Responsive: recent intervals can dominate by lowering {@link #historyWeight}.
 *   <li>Smooth: larger {@link #historySize} and higher weights damp short-term spikes.
 *   <li>Predictive: estimation methods project totals based on the latest observed rate.
 * </ul>
 *
 * @author Justin F. Chapweske
 */
public class RateCalculator {

  /**
   * Default interval length in milliseconds used to bucket incoming events before weighting them
   * into the historical average. Larger values smooth transient bursts; smaller values respond more
   * quickly to sudden rate shifts.
   */
  public static final int DEFAULT_INTERVAL_LENGTH = 300;

  /**
   * Default number of historical intervals retained in the sliding buffer. The buffer is circular
   * and counts only completed intervals; partially filled intervals are still in-flight and not
   * recorded until they close.
   */
  public static final int DEFAULT_HISTORY_SIZE = 100;

  /**
   * Default multiplicative weight applied as intervals age. Each prior interval is multiplied by
   * this factor relative to the more recent one, shaping the exponential decay used by the moving
   * average.
   */
  public static final float DEFAULT_HISTORY_WEIGHT = .8f;

  /**
   * Interval duration in milliseconds that defines the cadence for finalizing event buckets and
   * contributing them to the historical weighted average used for rate calculations.
   */
  protected int intervalLength; // Number of milliseconds in interval.

  /**
   * Total number of completed intervals tracked in the circular history buffer. Only fully elapsed
   * intervals occupy slots; current work in progress is held separately until the cutoff time is
   * reached.
   */
  protected int historySize; // Number of intervals to keep track of.

  /**
   * Exponential decay factor applied to historical interval rates, where values closer to {@code 1}
   * favor long-term smoothing and smaller values bias the rate toward the newest intervals.
   */
  protected float historyWeight; // Multipler/weight of old intervals.

  /**
   * Circular buffer of historical per-millisecond rates for each completed interval. A value of
   * {@code -1} indicates that the corresponding slot has not yet been populated with observed data.
   */
  protected double[] history; // old intervals.

  /**
   * Current index within the {@link #history} buffer that will be overwritten by the next completed
   * interval, enabling efficient rotation without copying data.
   */
  protected int historyPos; // history is circular, this is index.

  /**
   * Millisecond timestamp marking the start of the current interval; initialized on first update
   * and advanced whenever the interval completes and rolls into the history buffer.
   */
  protected long lastIntervalTime = -1; // last interval cutoff.

  /**
   * Total events accrued within the still-open interval. This value is reset when the interval
   * closes and its rate is persisted into {@link #history}.
   */
  protected double currentIntervalEvents; // Num events this interval.

  /**
   * Running total of all events observed across the lifetime of this calculator, including both
   * closed and in-progress intervals, used for projected counts.
   */
  protected double totalEvents;

  /**
   * Timestamp of the most recent update call that included at least one event. Used when estimating
   * projected totals to avoid extrapolating across long idle periods.
   */
  protected long lastPositiveUpdateTime = -1;

  /**
   * Timestamp recorded when {@link #pause()} is invoked. A value of {@code -1} indicates the
   * calculator is active; non-negative values indicate the paused state and are used to compensate
   * interval timing on resume.
   */
  protected long pauseTime = -1; // for pausing

  /** Construct a new RateCalculator using the default values. */
  public RateCalculator() {
    this(DEFAULT_INTERVAL_LENGTH, DEFAULT_HISTORY_SIZE, DEFAULT_HISTORY_WEIGHT);
  }

  /**
   * Construct a new RateCalculator.
   *
   * <p>All configuration values become immutable after construction to ensure consistent smoothing
   * behavior throughout the life of the instance.
   *
   * @param intervalLength length of each interval in milliseconds, defining when buckets close and
   *     commit to history.
   * @param historySize number of completed intervals retained for weighting; larger sizes smooth
   *     more aggressively.
   * @param historyWeight multiplier applied per step into history; values near {@code 0} emphasize
   *     recent changes, values near {@code 1} prefer stability.
   */
  public RateCalculator(int intervalLength, int historySize, float historyWeight) {

    this.intervalLength = intervalLength;
    this.historySize = historySize;
    this.historyWeight = historyWeight;

    history = new double[historySize];
    Arrays.fill(history, -1);
  }

  /**
   * Pause rate tracking at the current system time. While paused, interval boundaries are logically
   * frozen and incoming updates are discouraged. The calculator must be resumed before more
   * time-aware queries are accurate.
   */
  public void pause() {
    pause(System.currentTimeMillis());
  }

  /**
   * Pauses the RateCalculator at a specific timestamp so interval timing can be compensated
   * precisely when resumed. It is not advised to update events during the paused period.
   *
   * @param time millisecond clock value that marks the moment pausing began; must be monotonic
   *     relative to earlier updates.
   */
  public void pause(long time) {
    if (pauseTime != -1) {
      throw new IllegalStateException("RateCalculator already paused");
    }
    pauseTime = time;
  }

  /**
   * Indicates whether the calculator is currently paused and therefore holding interval progress.
   *
   * @return true if the RateCalculator is paused at the time of invocation.
   */
  public boolean isPaused() {
    return pauseTime != -1;
  }

  /** Resumes the paused RateCalculator. */
  public void resume() {
    resume(System.currentTimeMillis());
  }

  /**
   * Resume a previously paused calculator using an explicit timestamp, adjusting internal interval
   * anchors so elapsed time during the pause does not skew future rate calculations.
   *
   * @param time millisecond clock value representing when activity resumes; must not precede the
   *     pause timestamp.
   */
  public void resume(long time) {
    if (pauseTime == -1) {
      throw new IllegalStateException("RateCalculator not paused");
    }
    update(0, time);
    pauseTime = -1;
  }

  /**
   * Update the calculator with additional events, using the current system time as the event
   * timestamp. This is the common path when events are recorded immediately after they occur.
   *
   * @param numEvents number of events completed since the last update; negative values are not
   *     supported.
   */
  public void update(double numEvents) {
    update(numEvents, System.currentTimeMillis());
  }

  /**
   * Record additional events at a specific moment in time. Callers must supply monotonically
   * increasing timestamps to preserve interval ordering; violating monotonicity will distort rate
   * calculations.
   *
   * @param numEvents number of events that occurred at {@code eventTime}; negative values are not
   *     supported.
   * @param eventTime millisecond clock value when these events were observed; must be greater than
   *     or equal to the previous update time.
   */
  public void update(double numEvents, long eventTime) {
    currentIntervalEvents += numEvents;
    totalEvents += numEvents;

    // paused
    if (pauseTime != -1) {
      if (lastIntervalTime != -1) {
        lastIntervalTime += (eventTime - pauseTime);
      }
      if (lastPositiveUpdateTime != -1) {
        lastPositiveUpdateTime += (eventTime - pauseTime);
      }
      pauseTime = eventTime;
    }

    // first interval.
    if (lastIntervalTime == -1) {
      lastIntervalTime = eventTime;
      lastPositiveUpdateTime = eventTime;
      return;
    }

    if (numEvents > 0) {
      lastPositiveUpdateTime = eventTime;
    }

    long deltaTime = eventTime - lastIntervalTime;

    if (deltaTime >= intervalLength) {
      history[historyPos] = currentIntervalEvents / deltaTime;
      historyPos = (historyPos + 1) % history.length; // circular
      lastIntervalTime = eventTime;
      currentIntervalEvents = 0;
    }
  }

  /**
   * Convenience wrapper for {@link #getRate(long)} that evaluates the rate using the current system
   * time. Suitable when updates are also performed with wall-clock timestamps.
   *
   * @return current weighted event rate in events per millisecond based on {@link
   *     System#currentTimeMillis()}.
   */
  public double getRate() {
    return getRate(System.currentTimeMillis());
  }

  /**
   * Compute the weighted average rate in events per millisecond as of the supplied time. The query
   * time must not precede the most recent update; historical retroactive queries are not supported
   * because incomplete intervals cannot be reconstructed.
   *
   * @param time millisecond clock value representing when the rate should be evaluated; must be
   *     greater than or equal to the last update timestamp.
   * @return smoothed event rate in events per millisecond, incorporating historical weight and the
   *     in-progress interval when applicable.
   */
  public double getRate(long time) {
    update(0, time);
    double rate = 0;
    double total = 0;
    double weight = 1;
    for (int i = history.length - 1; i >= 0; i--) {
      double intervalRate = history[(historyPos + i) % history.length];

      if (intervalRate == -1) {
        continue;
      }

      rate += intervalRate * weight;
      total += weight;
      weight *= historyWeight;
    }

    if (total == 0 && rate == 0) {
      return currentIntervalEvents / (time - lastIntervalTime + 1);
    }

    return rate / total;
  }

  /**
   * Estimate the cumulative number of events that have likely occurred through the present system
   * time, blending observed totals and extrapolated progress since the last positive update.
   *
   * @return projected total event count evaluated at {@link System#currentTimeMillis()}.
   */
  @SuppressWarnings("unused")
  public double getEstimatedEventCount() {
    return getEstimatedEventCount(System.currentTimeMillis());
  }

  /**
   * Estimate the cumulative number of events that have likely occurred by the specified time,
   * projecting forward from the last positive update using the current smoothed rate.
   *
   * @param time millisecond clock value through which event completion should be estimated.
   * @return projected total event count, including observed events and extrapolated progress since
   *     the last positive update.
   */
  public double getEstimatedEventCount(long time) {
    double rate = getRate(time);
    long deltaTime = time - lastPositiveUpdateTime;
    return totalEvents + (deltaTime * rate);
  }

  /**
   * Estimate the remaining duration to reach a target event count, using the current system time as
   * the evaluation point for rate and progress calculations.
   *
   * @param maxEvents total number of events the caller intends to complete; must be greater than
   *     the already observed total.
   * @return remaining time in milliseconds until {@code maxEvents} are projected to be reached,
   *     based on {@link System#currentTimeMillis()} as the reference time.
   */
  @SuppressWarnings("unused")
  public long getEstimatedTimeRemaining(double maxEvents) {
    return getEstimatedTimeRemaining(maxEvents, System.currentTimeMillis());
  }

  /**
   * Estimate how long it will take to reach a target cumulative event count given the current
   * smoothed rate and observed totals.
   *
   * @param maxEvents total number of events the caller intends to complete; must be greater than
   *     the already observed total.
   * @param time millisecond clock value representing when the estimate is requested; must align
   *     with the same time source used for updates.
   * @return remaining time in milliseconds until {@code maxEvents} are projected to be reached,
   *     based on the current weighted rate.
   */
  public long getEstimatedTimeRemaining(double maxEvents, long time) {
    double rate = getRate(time);
    double estimatedEventCount = getEstimatedEventCount(time);
    return (long) ((maxEvents - estimatedEventCount) / rate);
  }
}

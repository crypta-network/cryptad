package network.crypta.support.math;

import java.io.Serial;
import network.crypta.support.SimpleFieldSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Exponential-decay running average with a bootstrapping period.
 *
 * <p>For the first {@code maxReports} valid observations, this behaves as a simple running average.
 * After that, it becomes a decaying running average with decay factor {@code 1 / maxReports}.
 * Formally, on each valid report {@code d} the factor used is {@code 1 / min(reports, maxReports)}
 * where {@code reports} is the number of valid values already accepted. This makes it easy to
 * reason about the decay and avoids excessive influence of the initial default value.
 *
 * <p>Invalid inputs (outside {@code [min, max]} or non-finite) are ignored and do not change the
 * average or the report count.
 *
 * <p>Thread-safety: All public methods that read or mutate state are synchronized. Instances are
 * {@link java.io.Serializable} and can be exported/imported via {@link SimpleFieldSet}.
 */
public final class BootstrappingDecayingRunningAverage implements RunningAverage {
  private static final Logger LOG =
      LoggerFactory.getLogger(BootstrappingDecayingRunningAverage.class);

  @Serial private static final long serialVersionUID = -1;

  /** Copying is provided via the copy constructor. */
  private final double min;

  private final double max;
  private double currentValue;
  private long reports;
  private int maxReports;

  /**
   * Creates a new running average.
   *
   * @param defaultValue initial value returned by {@link #currentValue()} before any valid report
   * @param min minimum acceptable input (inclusive)
   * @param max maximum acceptable input (inclusive)
   * @param maxReports number of valid reports before decay stabilizes at {@code 1/maxReports}
   * @param fs optional {@link SimpleFieldSet} to initialize from; when provided, {@code fs}
   *     overrides {@code defaultValue} and {@code reports} if the stored values are valid. Expected
   *     keys are: {@code CurrentValue} (double) and {@code Reports} (long).
   * @throws IllegalArgumentException if {@code maxReports <= 0}
   */
  public BootstrappingDecayingRunningAverage(
      double defaultValue, double min, double max, int maxReports, SimpleFieldSet fs) {
    this(RunningAverageBounds.of(defaultValue, min, max), maxReports, fs);
  }

  /**
   * Creates a new running average.
   *
   * @param bounds default value and accepted range for observations
   * @param maxReports number of valid reports before decay stabilizes at {@code 1/maxReports}
   * @param fs optional {@link SimpleFieldSet} to initialize from; when provided, {@code fs}
   *     overrides {@code defaultValue} and {@code reports} if the stored values are valid. Expected
   *     keys are: {@code CurrentValue} (double) and {@code Reports} (long).
   * @throws IllegalArgumentException if {@code maxReports <= 0}
   */
  public BootstrappingDecayingRunningAverage(
      RunningAverageBounds bounds, int maxReports, SimpleFieldSet fs) {
    this.min = bounds.min();
    this.max = bounds.max();
    reports = 0;
    currentValue = bounds.defaultValue();
    this.maxReports = maxReports;
    if (maxReports <= 0) {
      throw new IllegalArgumentException("maxReports must be > 0");
    }
    if (fs != null) {
      double d = fs.getDouble("CurrentValue", currentValue);
      if (!(Double.isNaN(d) || Double.isInfinite(d) || d < min || d > max)) {
        currentValue = d;
        reports = fs.getLong("Reports", reports);
      }
    }
  }

  /**
   * Copy constructor.
   *
   * <p>Takes an atomic, thread-safe snapshot of {@code a}'s state at construction time using an
   * internal synchronized snapshot method. This guarantees the copied {@code currentValue}, {@code
   * reports}, and {@code maxReports} come from a consistent moment in time. Subsequent
   * modifications to either instance do not affect the other.
   */
  public BootstrappingDecayingRunningAverage(BootstrappingDecayingRunningAverage a) {
    this.min = a.min;
    this.max = a.max;
    StateSnapshot s = a.snapshot();
    this.currentValue = s.currentValue();
    this.reports = s.reports();
    this.maxReports = s.maxReports();
  }

  /** Immutable snapshot of the mutable fields. */
  private record StateSnapshot(double currentValue, long reports, int maxReports) {}

  /**
   * Returns a consistent snapshot of the mutable state.
   *
   * <p>Synchronized to ensure all fields are read under the same monitor hold.
   */
  private synchronized StateSnapshot snapshot() {
    return new StateSnapshot(currentValue, reports, maxReports);
  }

  /** {@inheritDoc} */
  @Override
  public synchronized double currentValue() {
    return currentValue;
  }

  /**
   * Internal helper: replace the stored {@code currentValue}.
   *
   * <p>Used by {@link DecayingKeyspaceAverage} to normalize stored averages. Calling this method
   * may intentionally invalidate the statistical meaning of the average.
   */
  synchronized void setCurrentValue(double d) {
    currentValue = d;
  }

  /** {@inheritDoc} */
  @Override
  public synchronized void report(double d) {
    // Check for invalid values and return early without updating
    if (isInvalid(d)) {
      traceInvalid(d);
      return; // Don't update the average with invalid values
    }
    reports++;
    double decayFactor = 1.0 / Math.min(reports, maxReports);
    currentValue = (d * decayFactor) + (currentValue * (1 - decayFactor));
  }

  /** {@inheritDoc} */
  @Override
  public void report(long d) {
    report((double) d);
  }

  /** {@inheritDoc} */
  @Override
  public synchronized double valueIfReported(double d) {
    // Return current value for invalid inputs
    if (isInvalid(d)) {
      traceInvalid(d);
      return currentValue; // Return unchanged value for invalid inputs
    }
    double decayFactor = 1.0 / Math.min(reports + 1, maxReports);
    return (d * decayFactor) + (currentValue * (1 - decayFactor));
  }

  private boolean isInvalid(double d) {
    return d < min || d > max || Double.isInfinite(d) || Double.isNaN(d);
  }

  private void traceInvalid(double d) {
    if (!LOG.isTraceEnabled()) return;
    if (d < min) LOG.trace("Too low: {}", d);
    else if (d > max) LOG.trace("Too high: {}", d);
    else if (Double.isInfinite(d)) LOG.trace("Infinite value: {}", d);
    else if (Double.isNaN(d)) LOG.trace("NaN value");
  }

  /**
   * Updates {@code maxReports} for future observations.
   *
   * <p>Only affects later calls to {@link #report(double)}; it does not retroactively recompute the
   * average.
   */
  public synchronized void changeMaxReports(int maxReports) {
    this.maxReports = maxReports;
  }

  /** {@inheritDoc} */
  @Override
  public synchronized long countReports() {
    return reports;
  }

  /**
   * Exports this instance to a {@link SimpleFieldSet}.
   *
   * <p>Fields written:
   *
   * <ul>
   *   <li>{@code Type} — constant {@code "BootstrappingDecayingRunningAverage"}
   *   <li>{@code CurrentValue} — current average (double)
   *   <li>{@code Reports} — number of valid reports (long)
   * </ul>
   *
   * @param shortLived see {@link SimpleFieldSet#SimpleFieldSet(boolean)}
   * @return a new field set containing the serialized state
   */
  public synchronized SimpleFieldSet exportFieldSet(boolean shortLived) {
    SimpleFieldSet fs = new SimpleFieldSet(shortLived);
    fs.putSingle("Type", "BootstrappingDecayingRunningAverage");
    fs.put("CurrentValue", currentValue);
    fs.put("Reports", reports);
    return fs;
  }
}

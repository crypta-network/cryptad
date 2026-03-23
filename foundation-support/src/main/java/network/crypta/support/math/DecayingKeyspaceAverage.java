package network.crypta.support.math;

import java.io.Serial;
import network.crypta.support.SimpleFieldSet;

/**
 * Exponentially decaying running average over a circular {@code [0.0, 1.0)} keyspace.
 *
 * <p>This adapter wraps a {@link BootstrappingDecayingRunningAverage} to correctly average values
 * on a ring (Crypta locations) where {@code 0.0} and {@code 1.0} represent the same point. It
 * performs updates in an "unwrapped" space to cross the wrap boundary smoothly and then
 * re-normalizes back to {@code [0.0, 1.0)}.
 *
 * <p>Inputs to {@link #report(double)} and {@link #valueIfReported(double)} must be normalized
 * locations in {@code [0.0, 1.0]} and finite; invalid inputs cause an {@link
 * IllegalArgumentException}. The underlying average is configured with bounds {@code [-2.0, 2.0]}
 * to accommodate temporary unwrapped values during updates; the stored value is always normalized
 * back to {@code [0.0, 1.0)} after each update.
 *
 * <p>Thread-safety: All public methods are synchronized, so instances are safe for use by multiple
 * threads with external synchronization not required.
 *
 * @author robert
 */
public final class DecayingKeyspaceAverage implements RunningAverage {

  @Serial private static final long serialVersionUID = 5129429614949179428L;

  /**
   * Underlying decaying average used to accumulate observations across the wrap boundary.
   *
   * <p>The backing instance accepts inputs in {@code [-2.0, 2.0]} while this wrapper normalizes the
   * stored value to {@code [0.0, 1.0)}.
   */
  private final BootstrappingDecayingRunningAverage avg;

  /**
   * Creates a new keyspace-aware decaying running average.
   *
   * @param defaultValue initially normalized value returned by {@link #currentValue()} before any
   *     valid report. Expected in {@code [0.0, 1.0]}.
   * @param maxReports number of valid reports before decay stabilizes at {@code 1/maxReports}.
   *     Larger values decay more slowly.
   * @param fs optional persisted state from which to initialize; may be {@code null}. When
   *     provided, valid fields take precedence over {@code defaultValue} and report count.
   * @throws IllegalArgumentException if {@code maxReports <= 0}
   */
  public DecayingKeyspaceAverage(double defaultValue, int maxReports, SimpleFieldSet fs) {
    avg = new BootstrappingDecayingRunningAverage(defaultValue, -2.0, 2.0, maxReports, fs);
  }

  /**
   * Wraps an existing decaying running average.
   *
   * <p>Copies {@code a}'s state and configuration using the backing class's copy constructor.
   * Assumes {@code a} was configured with bounds suitable for use as a circular keyspace average.
   *
   * @param a base average whose configuration/state should be copied
   */
  public DecayingKeyspaceAverage(BootstrappingDecayingRunningAverage a) {
    // Assumes the source instance uses compatible min/max settings.
    avg = new BootstrappingDecayingRunningAverage(a);
  }

  /**
   * Copy constructor.
   *
   * <p>Creates a deep copy of {@code other}. Modifying either instance does not affect the other.
   */
  public DecayingKeyspaceAverage(DecayingKeyspaceAverage other) {
    // Deep copy of the underlying average.
    this.avg = new BootstrappingDecayingRunningAverage(other.avg);
  }

  // Copying is via the copy constructor.

  /**
   * Returns the current average location.
   *
   * <p>The result is normalized to {@code [0.0, 1.0)}; exactly {@code 1.0} is normalized to {@code
   * 0.0}.
   *
   * @return normalized average location in {@code [0.0, 1.0)}
   */
  @Override
  public synchronized double currentValue() {
    return avg.currentValue();
  }

  /**
   * Reports a value in the normalized keyspace range {@code [0.0, 1.0]}.
   *
   * <p>To handle the wrap at {@code 1.0/0.0}, this method computes an unwrapped delta from the
   * current normalized average to {@code d} using {@link KeyspaceMath#change(double, double)} and
   * updates the underlying average in that unwrapped space. After the update it normalizes the
   * stored value back into {@code [0.0, 1.0)}.
   *
   * <p>Side effects: increments the internal report count and mutates the average.
   *
   * @param d normalized keyspace value to report; must be finite and in {@code [0.0, 1.0]}
   * @throws IllegalArgumentException if {@code d} is outside {@code [0.0, 1.0]} or not finite
   */
  @Override
  public synchronized void report(double d) {
    if ((d < 0.0) || (d > 1.0) || Double.isNaN(d) || Double.isInfinite(d))
      // Using an unwrapped representation does not relax the input contract here.
      throw new IllegalArgumentException("Not a valid normalized key: " + d);
    double superValue = avg.currentValue();
    double thisValue = KeyspaceMath.normalize(superValue);
    double diff = KeyspaceMath.change(thisValue, d);
    double toAverage = (superValue + diff);
    avg.report(toAverage);
    // Normalize the stored value back into [0.0, 1.0), so exactly 1.0 becomes 0.0.
    avg.setCurrentValue(KeyspaceMath.normalize(avg.currentValue()));
  }

  /**
   * Returns the hypothetical normalized average if {@code d} were reported next.
   *
   * <p>Does not mutate internal state.
   *
   * @param d candidate normalized value in {@code [0.0, 1.0]}
   * @return the resulting normalized average in {@code [0.0, 1.0)}
   * @throws IllegalArgumentException if {@code d} is outside {@code [0.0, 1.0]} or not finite
   */
  @Override
  public synchronized double valueIfReported(double d) {
    if ((d < 0.0) || (d > 1.0) || Double.isNaN(d) || Double.isInfinite(d))
      throw new IllegalArgumentException("Not a valid normalized key: " + d);
    double superValue = avg.currentValue();
    double thisValue = KeyspaceMath.normalize(superValue);
    double diff = KeyspaceMath.change(thisValue, d);
    return KeyspaceMath.normalize(avg.valueIfReported(superValue + diff));
  }

  /**
   * Returns the number of valid reports accepted so far.
   *
   * <p>This corresponds to the underlying accumulator's notion of accepted values.
   *
   * @return count of valid observations incorporated into the average
   */
  @Override
  public synchronized long countReports() {
    return avg.countReports();
  }

  /**
   * Unsupported: this implementation does not accept long-based reports.
   *
   * @param d ignored
   * @throws IllegalArgumentException always; use {@link #report(double)} instead
   */
  @Override
  public synchronized void report(long d) {
    throw new IllegalArgumentException("KeyspaceAverage does not like longs");
  }

  /**
   * Updates the maximum report window used to compute decay.
   *
   * <p>Only affects subsequent reports; it does not retroactively recompute the average. Callers
   * must provide a positive value.
   *
   * @param maxReports new cap for the bootstrapping/decay window
   */
  public synchronized void changeMaxReports(int maxReports) {
    avg.changeMaxReports(maxReports);
  }

  /**
   * Exports this instance's state into a {@link SimpleFieldSet}.
   *
   * <p>Delegates to the underlying {@link BootstrappingDecayingRunningAverage}. The serialized
   * fields include {@code Type}, {@code CurrentValue}, and {@code Reports}. See {@link
   * BootstrappingDecayingRunningAverage#exportFieldSet(boolean)} for details.
   *
   * @param shortLived see {@link SimpleFieldSet#SimpleFieldSet(boolean)}
   * @return a field set containing the serialized state of the underlying average
   */
  public synchronized SimpleFieldSet exportFieldSet(boolean shortLived) {
    return avg.exportFieldSet(shortLived);
  }
}

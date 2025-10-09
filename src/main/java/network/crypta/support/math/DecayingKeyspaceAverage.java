package network.crypta.support.math;

import java.io.Serial;
import network.crypta.node.Location;
import network.crypta.support.SimpleFieldSet;

/**
 * @author robert
 *     <p>A filter on BootstrappingDecayingRunningAverage which makes it aware of the circular
 *     keyspace.
 */
public final class DecayingKeyspaceAverage implements RunningAverage {

  @Serial private static final long serialVersionUID = 5129429614949179428L;

  /**
   * Underlying decaying running average over a circular keyspace. 'avg' is the normalized average
   * location, note that the reporting bounds are (-2.0, 2.0) however.
   */
  private final BootstrappingDecayingRunningAverage avg;

  /**
   * Creates a new keyspace-aware decaying running average.
   *
   * @param defaultValue initial value returned by {@link #currentValue()} before any valid report
   * @param maxReports number of valid reports before decay stabilizes at {@code 1/maxReports}
   * @param fs optional persisted state from which to initialize; may be {@code null}
   */
  public DecayingKeyspaceAverage(double defaultValue, int maxReports, SimpleFieldSet fs) {
    avg = new BootstrappingDecayingRunningAverage(defaultValue, -2.0, 2.0, maxReports, fs);
  }

  /**
   * Wraps an existing decaying running average.
   *
   * @param a base average whose configuration/state should be copied
   */
  public DecayingKeyspaceAverage(BootstrappingDecayingRunningAverage a) {
    // check the max/min values? ignore them?
    avg = new BootstrappingDecayingRunningAverage(a);
  }

  /** Copy constructor. */
  public DecayingKeyspaceAverage(DecayingKeyspaceAverage other) {
    // Deep copy of the underlying average.
    this.avg = new BootstrappingDecayingRunningAverage(other.avg);
  }

  // Copying is via the copy constructor.

  /** Returns the current (normalized) average value. */
  @Override
  public synchronized double currentValue() {
    return avg.currentValue();
  }

  /**
   * Reports a value in the normalized keyspace range {@code [0.0, 1.0]}.
   *
   * <p>To gracefully handle the circular keyspace at the {@code 1.0/0.0} boundary, this method
   * averages across the wrap using the unwrapped representation and then normalizes the stored
   * value back into {@code [0.0, 1.0]} after updating.
   *
   * @param d normalized keyspace value to report
   * @throws IllegalArgumentException if {@code d} is outside {@code [0.0, 1.0]}
   */
  @Override
  public synchronized void report(double d) {
    if ((d < 0.0) || (d > 1.0))
      // Just because we use non-normalized locations doesn't mean we can accept them.
      throw new IllegalArgumentException("Not a valid normalized key: " + d);
    double superValue = avg.currentValue();
    double thisValue = Location.normalize(superValue);
    double diff = Location.change(thisValue, d);
    double toAverage = (superValue + diff);
    avg.report(toAverage);
    double newValue = avg.currentValue();
    if (newValue < 0.0 || newValue > 1.0) avg.setCurrentValue(Location.normalize(newValue));
  }

  @Override
  public synchronized double valueIfReported(double d) {
    if ((d < 0.0) || (d > 1.0))
      throw new IllegalArgumentException("Not a valid normalized key: " + d);
    double superValue = avg.currentValue();
    double thisValue = Location.normalize(superValue);
    double diff = Location.change(thisValue, d);
    return Location.normalize(avg.valueIfReported(superValue + diff));
  }

  @Override
  public synchronized long countReports() {
    return avg.countReports();
  }

  /** Unsupported: this implementation does not accept long-based reports. */
  @Override
  public synchronized void report(long d) {
    throw new IllegalArgumentException("KeyspaceAverage does not like longs");
  }

  /** Updates the maximum report window used to compute decay. */
  public synchronized void changeMaxReports(int maxReports) {
    avg.changeMaxReports(maxReports);
  }

  /** Exports this instance's state into a {@link SimpleFieldSet}. */
  public synchronized SimpleFieldSet exportFieldSet(boolean shortLived) {
    return avg.exportFieldSet(shortLived);
  }
}

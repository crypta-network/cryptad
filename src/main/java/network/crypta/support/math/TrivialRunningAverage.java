package network.crypta.support.math;

import java.io.Serial;

/**
 * A minimal {@link RunningAverage} that computes the simple arithmetic mean of all reported values.
 *
 * <p>It maintains a running {@code total} and the number of accepted reports ({@code reports}). The
 * current value is computed as {@code total / reports}.
 *
 * <p>Thread-safety: All state access is guarded by this instance's monitor; public methods are
 * synchronized (directly or via delegation), and the copy constructor takes an atomic snapshot of
 * the source instance.
 *
 * <p>Numeric behavior:
 *
 * <ul>
 *   <li>If no values have been reported yet, {@link #currentValue()} returns {@link Double#NaN}
 *       (IEEE 754 semantics for {@code 0.0 / 0}).
 *   <li>No validation is performed on inputs. Passing {@code NaN} or infinities will propagate to
 *       the running total and therefore to the reported average.
 * </ul>
 */
public final class TrivialRunningAverage implements RunningAverage {

  @Serial private static final long serialVersionUID = 1L;
  private long reports;
  private double total;

  /**
   * Creates a new instance by copying the state of the provided running average.
   *
   * <p>The copy is taken atomically with respect to the source instance's monitor and will not
   * reflect subsequent changes to {@code average}.
   *
   * @param average the source to copy from, must not be null
   */
  public TrivialRunningAverage(TrivialRunningAverage average) {
    Snapshot s = average.snapshot();
    this.reports = s.reports;
    this.total = s.total;
  }

  /** Creates a new, empty running average with zero reports and a total of {@code 0.0}. */
  public TrivialRunningAverage() {
    reports = 0;
    total = 0.0;
  }

  @Override
  public synchronized long countReports() {
    return reports;
  }

  /**
   * Returns the accumulated sum of all values reported so far.
   *
   * @return the running total
   */
  public synchronized double totalValue() {
    return total;
  }

  /**
   * Returns the current arithmetic mean, i.e. {@code total / reports}.
   *
   * <p>If no values have been reported, this returns {@link Double#NaN}.
   *
   * @return the current average (may be {@code NaN} when empty)
   */
  @Override
  public synchronized double currentValue() {
    return total / reports;
  }

  /**
   * Reports a single observation.
   *
   * <p>No validation is performed; the value is added to the running total, and the report count is
   * incremented.
   *
   * @param d observation to incorporate
   */
  @Override
  public synchronized void report(double d) {
    total += d;
    reports++;
  }

  /**
   * Convenience overload that reports a {@code long} observation.
   *
   * @param d observation to incorporate
   */
  @Override
  public void report(long d) {
    report((double) d);
  }

  /**
   * Predicts the average if {@code r} were reported next, without modifying state.
   *
   * @param r hypothetical observation
   * @return the value of {@link #currentValue()} after incorporating {@code r}
   */
  @Override
  public synchronized double valueIfReported(double r) {
    return (total + r) / (reports + 1);
  }

  // Copying is via the copy constructor.

  /** Returns an atomic snapshot of this instance's state. */
  private synchronized Snapshot snapshot() {
    Snapshot s = new Snapshot();
    s.reports = this.reports;
    s.total = this.total;
    return s;
  }

  /** Lightweight container for an atomic state snapshot. */
  private static final class Snapshot {
    long reports;
    double total;
  }
}

package network.crypta.support.math;

import java.io.Serial;
import network.crypta.support.LogThresholdCallback;
import network.crypta.support.Logger;
import network.crypta.support.Logger.LogLevel;
import network.crypta.support.SimpleFieldSet;

/**
 * Exponential decay "running average".
 *
 * @author amphibian
 *     <p>For the first <tt>maxReports</tt> reports, this is equivalent to a simple running average.
 *     After that it is a decaying running average with a <tt>decayFactor</tt> of <tt>1 /
 *     maxReports</tt>. We accomplish this by having <tt>decayFactor = 1/(Math.min(#reports,
 *     maxReports))</tt>. We can therefore:
 *     <ul>
 *       <li>Specify <tt>maxReports</tt> more easily than an arbitrary decay factor.
 *       <li>We don't get big problems with influence of the initial value, which is usually not
 *           very reliable.
 *     </ul>
 */
public final class BootstrappingDecayingRunningAverage implements RunningAverage, Cloneable {
  @Serial private static final long serialVersionUID = -1;

  @Override
  public BootstrappingDecayingRunningAverage clone() {
    // Override clone() for locking; BDRAs are self-synchronized.
    // Implement Cloneable to shut up findbugs.
    return new BootstrappingDecayingRunningAverage(this);
  }

  private final double min;
  private final double max;
  private double currentValue;
  private long reports;
  private int maxReports;

  private static volatile boolean logDEBUG;

  static {
    Logger.registerLogThresholdCallback(
        new LogThresholdCallback() {
          @Override
          public void shouldUpdate() {
            logDEBUG = Logger.shouldLog(LogLevel.DEBUG, this);
          }
        });
  }

  /**
   * Constructor
   *
   * @param defaultValue default value
   * @param min minimum value of input data
   * @param max maximum value of input data
   * @param maxReports number of reports before bootstrapping period ends and decay begins
   * @param fs {@link SimpleFieldSet} parameter for this object. Will override other parameters.
   */
  public BootstrappingDecayingRunningAverage(
      double defaultValue, double min, double max, int maxReports, SimpleFieldSet fs) {
    this.min = min;
    this.max = max;
    reports = 0;
    currentValue = defaultValue;
    this.maxReports = maxReports;
    assert (maxReports > 0);
    if (fs != null) {
      double d = fs.getDouble("CurrentValue", currentValue);
      if (!(Double.isNaN(d) || Double.isInfinite(d) || d < min || d > max)) {
        currentValue = d;
        reports = fs.getLong("Reports", reports);
      }
    }
  }

  /**
   * {@inheritDoc}
   *
   * @return
   */
  @Override
  public synchronized double currentValue() {
    return currentValue;
  }

  /**
   * <strong>Not a public method.</strong> Changes the internally stored <code>currentValue</code>
   * and return the old one.
   *
   * <p>Used by {@link DecayingKeyspaceAverage} to normalize the stored averages. Calling this
   * function may (purposefully) destroy the utility of the average being kept.
   *
   * @param d
   * @return
   * @see DecayingKeyspaceAverage
   */
  synchronized double setCurrentValue(double d) {
    double old = currentValue;
    currentValue = d;
    return old;
  }

  /**
   * {@inheritDoc}
   *
   * @param d
   */
  @Override
  public synchronized void report(double d) {
    // Check for invalid values and return early without updating
    if (d < min || d > max || Double.isInfinite(d) || Double.isNaN(d)) {
      if (logDEBUG) {
        if (d < min) Logger.debug(this, "Too low: " + d, new Exception("debug"));
        else if (d > max) Logger.debug(this, "Too high: " + d, new Exception("debug"));
        else if (Double.isInfinite(d))
          Logger.debug(this, "Infinite value: " + d, new Exception("debug"));
        else if (Double.isNaN(d)) Logger.debug(this, "NaN value", new Exception("debug"));
      }
      return; // Don't update the average with invalid values
    }
    reports++;
    double decayFactor = 1.0 / (Math.min(reports, maxReports));
    currentValue = (d * decayFactor) + (currentValue * (1 - decayFactor));
  }

  /**
   * {@inheritDoc}
   *
   * @param d
   */
  @Override
  public void report(long d) {
    report((double) d);
  }

  /**
   * {@inheritDoc}
   *
   * @param d
   */
  @Override
  public synchronized double valueIfReported(double d) {
    // Return current value for invalid inputs
    if (d < min || d > max || Double.isInfinite(d) || Double.isNaN(d)) {
      if (logDEBUG) {
        if (d < min) Logger.debug(this, "Too low: " + d, new Exception("debug"));
        else if (d > max) Logger.debug(this, "Too high: " + d, new Exception("debug"));
        else if (Double.isInfinite(d))
          Logger.debug(this, "Infinite value: " + d, new Exception("debug"));
        else if (Double.isNaN(d)) Logger.debug(this, "NaN value", new Exception("debug"));
      }
      return currentValue; // Return unchanged value for invalid inputs
    }
    double decayFactor = 1.0 / (Math.min(reports + 1, maxReports));
    return (d * decayFactor) + (currentValue * (1 - decayFactor));
  }

  /**
   * Change <code>maxReports</code>.
   *
   * @param maxReports
   */
  public synchronized void changeMaxReports(int maxReports) {
    this.maxReports = maxReports;
  }

  /** Copy constructor. */
  private BootstrappingDecayingRunningAverage(BootstrappingDecayingRunningAverage a) {
    synchronized (a) {
      this.currentValue = a.currentValue;
      this.max = a.max;
      this.maxReports = a.maxReports;
      this.min = a.min;
      this.reports = a.reports;
    }
  }

  /** {@inheritDoc} */
  @Override
  public synchronized long countReports() {
    return reports;
  }

  /**
   * Export this object as {@link SimpleFieldSet}.
   *
   * @param shortLived See {@link SimpleFieldSet#SimpleFieldSet(boolean)}.
   * @return
   */
  public synchronized SimpleFieldSet exportFieldSet(boolean shortLived) {
    SimpleFieldSet fs = new SimpleFieldSet(shortLived);
    fs.putSingle("Type", "BootstrappingDecayingRunningAverage");
    fs.put("CurrentValue", currentValue);
    fs.put("Reports", reports);
    return fs;
  }
}

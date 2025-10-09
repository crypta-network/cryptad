package network.crypta.support.math;

import java.io.Serial;

public final class TrivialRunningAverage implements RunningAverage {

  @Serial private static final long serialVersionUID = 1L;
  private long reports;
  private double total;

  /**
   * @param average
   */
  public TrivialRunningAverage(TrivialRunningAverage average) {
    synchronized (average) {
      this.reports = average.reports;
      this.total = average.total;
    }
  }

  /** */
  public TrivialRunningAverage() {
    reports = 0;
    total = 0.0;
  }

  @Override
  public synchronized long countReports() {
    return reports;
  }

  public synchronized double totalValue() {
    return total;
  }

  /**
   * @return
   */
  @Override
  public synchronized double currentValue() {
    return total / reports;
  }

  /**
   * @param d
   */
  @Override
  public synchronized void report(double d) {
    total += d;
    reports++;
    // TODO Auto-generated method stub
  }

  /**
   * @param d
   */
  @Override
  public void report(long d) {
    report((double) d);
  }

  @Override
  public synchronized double valueIfReported(double r) {
    return (total + r) / (reports + 1);
  }

  // Copying is via the copy constructor.
}

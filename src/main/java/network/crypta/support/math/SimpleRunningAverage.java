package network.crypta.support.math;

import java.io.DataOutputStream;
import java.io.Serial;
import java.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Simple running average: linear mean of the last N reports.
 *
 * @author amphibian
 */
public final class SimpleRunningAverage implements RunningAverage {
  private static final Logger LOG = LoggerFactory.getLogger(SimpleRunningAverage.class);

  @Serial private static final long serialVersionUID = -1;
  final double[] refs;
  int nextSlotPtr = 0;
  int curLen = 0;
  double total = 0;
  int totalReports = 0;
  final double initValue;

  // Copying is via the copy constructor.

  /** Clear the SRA */
  public synchronized void clear() {
    nextSlotPtr = 0;
    curLen = 0;
    totalReports = 0;
    total = 0;
    Arrays.fill(refs, 0.0);
  }

  /**
   * @param length
   * @param initValue
   */
  public SimpleRunningAverage(int length, double initValue) {
    refs = new double[length];
    this.initValue = initValue;
    totalReports = 0;
  }

  /**
   * @param a
   */
  public SimpleRunningAverage(SimpleRunningAverage a) {
    Snapshot s = a.snapshot();
    this.curLen = s.curLen;
    this.initValue = s.initValue;
    this.nextSlotPtr = s.nextSlotPtr;
    this.refs = s.refs;
    this.total = s.total;
    this.totalReports = s.totalReports;
  }

  /** Creates a consistent snapshot of this instance's state. */
  private synchronized Snapshot snapshot() {
    return new Snapshot(curLen, initValue, nextSlotPtr, refs.clone(), total, totalReports);
  }

  private static final class Snapshot {
    final int curLen;
    final double initValue;
    final int nextSlotPtr;
    final double[] refs;
    final double total;
    final int totalReports;

    Snapshot(
        int curLen,
        double initValue,
        int nextSlotPtr,
        double[] refs,
        double total,
        int totalReports) {
      this.curLen = curLen;
      this.initValue = initValue;
      this.nextSlotPtr = nextSlotPtr;
      this.refs = refs;
      this.total = total;
      this.totalReports = totalReports;
    }
  }

  /**
   * @return
   */
  @Override
  public synchronized double currentValue() {
    if (curLen == 0) return initValue;
    return total / curLen;
  }

  @Override
  public synchronized double valueIfReported(double r) {
    if (curLen < refs.length) {
      return (total + r) / (curLen + 1);
    } else {
      // Don't increment curLen because it won't be incremented.
      return (total + r - refs[nextSlotPtr]) / curLen;
    }
  }

  /**
   * @param d
   */
  @Override
  public synchronized void report(double d) {
    totalReports++;
    if (LOG.isTraceEnabled()) LOG.trace("report(" + d + ") on " + this);
    if (curLen < refs.length) curLen++;
    else total -= popValue();
    pushValue(d);
    total += d;
  }

  /**
   * @param value
   */
  private synchronized void pushValue(double value) {
    refs[nextSlotPtr] = value;
    nextSlotPtr++;
    if (nextSlotPtr >= refs.length) nextSlotPtr = 0;
  }

  /**
   * @return
   */
  private synchronized double popValue() {
    return refs[nextSlotPtr];
  }

  @Override
  public synchronized String toString() {
    return super.toString()
        + ": curLen="
        + curLen
        + ", ptr="
        + nextSlotPtr
        + ", total="
        + total
        + ", average="
        + total / curLen;
  }

  /**
   * @param d
   */
  @Override
  public void report(long d) {
    report((double) d);
  }

  /**
   * @param out
   */
  public void writeDataTo(DataOutputStream out) {
    throw new UnsupportedOperationException();
  }

  @Override
  public synchronized long countReports() {
    return totalReports;
  }

  /**
   * @param targetValue
   * @return
   */
  public synchronized double minReportForValue(double targetValue) {
    if (curLen < refs.length) {
      /**
       * Don't need to remove any values before reporting, so is slightly simpler. (total + report)
       * / (curLen + 1) >= targetValue => report / (curLen + 1) >= targetValue - total/(curLen+1) =>
       * report >= (targetValue - total/(curLen + 1)) * (curLen+1) => report >= targetValue *
       * (curLen + 1) - total EXAMPLE: Mean (5, 5, 5, 5, 5, X) = 10 X = 10 * 6 - 25 = 35 => Mean =
       * (25 + 35) / 6 = 60/6 = 10
       */
      return targetValue * (curLen + 1) - total;
    } else {
      /**
       * Essentially the same, but: 1) Length will be curLen, not curLen+1, because is full. 2) Take
       * off the value that will be taken off first.
       */
      return targetValue * curLen - (total - refs[nextSlotPtr]);
    }
  }
}

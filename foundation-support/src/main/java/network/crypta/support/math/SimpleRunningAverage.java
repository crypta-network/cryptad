package network.crypta.support.math;

import java.io.Serial;
import java.util.Arrays;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Fixed-size windowed running average computing the arithmetic mean of the last {@code N}
 * observations.
 *
 * <p>Semantics
 *
 * <ul>
 *   <li><b>Window</b>: keeps at most {@code length} most-recent reports. When full, the oldest
 *       value is evicted when a new one arrives.
 *   <li><b>Initial value</b>: until the first report is accepted, {@link #currentValue()} returns
 *       {@code initValue}. After that, it returns the mean of the values currently in the window.
 *   <li><b>Complexity</b>: {@link #report(double)}, {@link #valueIfReported(double)} and {@link
 *       #currentValue()} are O(1).
 *   <li><b>Thread‑safety</b>: all public methods are synchronized; instances are safe to use from
 *       multiple threads.
 * </ul>
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

  /**
   * Clears all state and forgets any previously reported values.
   *
   * <p>After a call to this method, {@link #currentValue()} will again return the {@code initValue}
   * until a new value is reported.
   */
  public synchronized void clear() {
    nextSlotPtr = 0;
    curLen = 0;
    totalReports = 0;
    total = 0;
    Arrays.fill(refs, 0.0);
  }

  /**
   * Creates a running average with a window that holds up to {@code length} values and an initial
   * value returned before any reports are made.
   *
   * @param length maximum number of recent observations to retain (window size)
   * @param initValue value returned by {@link #currentValue()} until the first report is accepted
   */
  public SimpleRunningAverage(int length, double initValue) {
    refs = new double[length];
    this.initValue = initValue;
    totalReports = 0;
  }

  /**
   * Copy constructor that takes a thread‑safe snapshot of {@code a}.
   *
   * <p>The new instance is independent and will not reflect future changes to {@code a}.
   *
   * @param a source instance to copy
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
    private final int curLen;
    private final double initValue;
    private final int nextSlotPtr;
    private final double[] refs;
    private final double total;
    private final int totalReports;

    private Snapshot(
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

    @Override
    public boolean equals(Object o) {
      if (this == o) return true;
      if (!(o instanceof Snapshot snapshot)) return false;
      return curLen == snapshot.curLen
          && nextSlotPtr == snapshot.nextSlotPtr
          && totalReports == snapshot.totalReports
          && Double.compare(initValue, snapshot.initValue) == 0
          && Double.compare(total, snapshot.total) == 0
          && Arrays.equals(refs, snapshot.refs);
    }

    @Override
    public int hashCode() {
      int result = Integer.hashCode(curLen);
      result = 31 * result + Double.hashCode(initValue);
      result = 31 * result + Integer.hashCode(nextSlotPtr);
      result = 31 * result + Arrays.hashCode(refs);
      result = 31 * result + Double.hashCode(total);
      result = 31 * result + Integer.hashCode(totalReports);
      return result;
    }

    @Override
    public @NotNull String toString() {
      return "Snapshot{"
          + "curLen="
          + curLen
          + ", initValue="
          + initValue
          + ", nextSlotPtr="
          + nextSlotPtr
          + ", refs="
          + Arrays.toString(refs)
          + ", total="
          + total
          + ", totalReports="
          + totalReports
          + '}';
    }
  }

  /**
   * Returns the current average.
   *
   * <p>Until the first report is accepted, this returns {@code initValue}. Once at least one value
   * has been reported, it returns the arithmetic mean of the values currently held in the window.
   */
  @Override
  public synchronized double currentValue() {
    if (curLen == 0) return initValue;
    return total / curLen;
  }

  @Override
  public synchronized double valueIfReported(double r) {
    // Hypothetical next value; does not mutate internal state.
    if (curLen < refs.length) {
      return (total + r) / (curLen + 1);
    } else {
      // Don't increment curLen because it won't be incremented.
      return (total + r - refs[nextSlotPtr]) / curLen;
    }
  }

  /**
   * Reports a single observation.
   *
   * @param d value to incorporate into the running average
   */
  @Override
  public synchronized void report(double d) {
    totalReports++;
    if (LOG.isTraceEnabled()) LOG.trace("report({}) on {}", d, this);
    if (curLen < refs.length) curLen++;
    else total -= popValue();
    pushValue(d);
    total += d;
  }

  /** Adds {@code value} into the circular buffer, advancing the slot pointer. */
  private synchronized void pushValue(double value) {
    refs[nextSlotPtr] = value;
    nextSlotPtr++;
    if (nextSlotPtr >= refs.length) nextSlotPtr = 0;
  }

  /** Returns the value that will be evicted next when the window is full. */
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

  /** Convenience overload that reports a {@code long} value. */
  @Override
  public void report(long d) {
    report((double) d);
  }

  @Override
  public synchronized long countReports() {
    return totalReports;
  }
}

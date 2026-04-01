package network.crypta.support;

import network.crypta.support.math.RunningAverage;
import network.crypta.support.math.TrivialRunningAverage;

/**
 * A lightweight, bucketed aggregator built from independent running averages.
 *
 * <p>This class partitions the key space {@code [0, max)} into a fixed number of equally sized bins
 * ("bars"). Each bar holds a {@link RunningAverage} that is updated when {@link #report} receives a
 * key within that bar's interval. Unlike a conventional histogram that counts occurrences, each bar
 * tracks an average of caller-provided values. A common use case is tracking success rates per
 * location or key range.
 *
 * <p>Thread-safety: The instance performs no explicit synchronization. The bars are created as
 * {@link TrivialRunningAverage}, whose implementation is synchronized. Concurrent calls are safe in
 * practice because the array contents are final after construction and each bar's implementation is
 * thread-safe; however this class itself does not enforce additional memory barriers beyond final
 * field publication.
 */
public class Histogram2 {

  private final double max;
  private final RunningAverage[] bars;

  /**
   * Creates a histogram with {@code numBars} equally sized buckets spanning {@code [0, maxValue)}.
   *
   * <p>Each bar is initialized with a fresh {@link TrivialRunningAverage}. The number of bars and
   * {@code maxValue} are fixed for the lifetime of the instance.
   *
   * <p>Preconditions (not enforced):
   *
   * <ul>
   *   <li>{@code numBars > 0}
   *   <li>{@code maxValue > 0} (avoids division by zero in scaling operations)
   * </ul>
   *
   * @param numBars total number of bars; must be positive
   * @param maxValue exclusive upper bound of the key domain ({@code [0, maxValue)}); must be
   *     positive for meaningful results
   */
  public Histogram2(final int numBars, final double maxValue) {
    this.max = maxValue;
    this.bars = new RunningAverage[numBars];
    for (int i = 0; i < numBars; i++) {
      this.bars[i] = new TrivialRunningAverage();
    }
  }

  /**
   * Reports a value to the bar that corresponds to {@code key}.
   *
   * <p>Behavior:
   *
   * <ul>
   *   <li>Keys outside {@code [0, max)} are ignored.
   *   <li>Valid keys map to a bar via {@code floor(bars.length * key / max)}. This is equivalent to
   *       dividing the key range into equal-width intervals and choosing the corresponding index.
   *   <li>The chosen bar's running average incorporates {@code value}.
   * </ul>
   *
   * <p>Complexity: O(1).
   *
   * <p>Threading: See class-level notes. This method does not synchronize; it delegates to the
   * thread-safe {@link RunningAverage} held by the selected bar.
   *
   * @param key location in {@code [0, max)} that selects the bar
   * @param value observation to feed to that bar's running average; units are caller-defined
   * @throws RuntimeException any exception thrown by the underlying {@link RunningAverage}
   *     implementation is propagated
   */
  public void report(final double key, final double value) {
    if (key < 0.0 || key >= max) return;
    // Compute bar index by scaling key into [0, bars.length) and truncating toward zero (floor for
    // non‑negative inputs). This yields a uniform partition of [0, max) into equal-width bins.
    int n = (int) (bars.length * key / max);
    bars[n].report(value);
  }

  /**
   * Returns a snapshot of per-bar averages scaled to {@code localMax} and truncated to integers.
   *
   * <p>For each bar {@code i}, the returned array contains {@code (int) (bars[i].currentValue() *
   * localMax / max)}. This provides a linear mapping from the bar's average (assumed to be in the
   * range {@code [0, max]} for percentage-like data) into {@code [0, localMax]}.
   *
   * <p>Notes:
   *
   * <ul>
   *   <li>Values are truncated toward zero due to the explicit cast to {@code int}.
   *   <li>If a bar's average is negative, the corresponding entry will be negative.
   *   <li>Precondition (not enforced): {@code max > 0}; otherwise the scale factor is undefined
   *       (division by zero). Callers must supply a positive {@code max}.
   * </ul>
   *
   * <p>Complexity: O(number of bars).
   *
   * @param localMax target scale for the output values; typically a non-negative display height
   * @return an array of length {@code numBars} with the scaled averages (never {@code null})
   */
  public int[] getPercentageArray(int localMax) {
    int[] retval = new int[bars.length];
    for (int i = 0; i < retval.length; i++) {
      // Scale the current average from [0, max] into [0, localMax], then truncate to an int.
      int val = (int) (bars[i].currentValue() * localMax / max);
      retval[i] = val;
    }
    return retval;
  }
}

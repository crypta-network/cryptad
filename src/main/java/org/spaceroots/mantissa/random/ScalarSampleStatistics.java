package org.spaceroots.mantissa.random;

/**
 * Computes basic descriptive statistics for a scalar sample.
 *
 * <p>This class is a small, mutable accumulator for scalar-valued observations. Callers add data
 * points incrementally using one of the {@code add(...)} methods, and then query the aggregated
 * results such as the minimum, maximum, arithmetic mean, and sample standard deviation. The
 * implementation is intended for streaming or iterative use where retaining the full sample would
 * be unnecessary or too expensive.
 *
 * <p>The accumulator maintains simple running totals and extrema, so updates are constant-time and
 * order-independent. When the sample is empty, the instance reports {@code size() == 0}, {@code
 * getMin()} and {@code getMax()} return {@link Double#NaN}, and both {@code getMean()} and {@code
 * getStandardDeviation()} return {@code 0}. The class is not thread-safe; if multiple threads
 * update or read the same instance, external synchronization is required.
 *
 * <ul>
 *   <li><strong>Responsibilities:</strong> track count, extrema, sum, and sum of squares.
 *   <li><strong>Notable behavior:</strong> values are stored as-is with no filtering or
 *       normalization.
 * </ul>
 *
 * @version $Id: ScalarSampleStatistics.java 1666 2005-12-15 16:37:55Z luc $
 * @author L. Maisonobe
 */
public class ScalarSampleStatistics {

  /** Number of sample points. */
  private int n;

  /** Minimal value in the sample. */
  private double min;

  /** Maximal value in the sample. */
  private double max;

  /** Sum of the sample values. */
  private double sum;

  /** Sum of the squares of the sample values. */
  private double sum2;

  /**
   * Creates a new, empty statistics accumulator.
   *
   * <p>The new instance contains no points and is ready to accept observations via {@link
   * #add(double)} or related methods. Until at least one finite point is added, extrema are
   * undefined and reported as {@link Double#NaN}. Mean and sample standard deviation are reported
   * as {@code 0} when the sample size is too small to define them. The instance is mutable and may
   * be reused by adding additional points over time.
   */
  public ScalarSampleStatistics() {
    n = 0;
    min = Double.NaN;
    max = min;
    sum = 0;
    sum2 = 0;
  }

  /**
   * Adds one point to this accumulator.
   *
   * <p>This method updates the running count, extrema, sum, and sum of squares with a single new
   * observation. The update runs in constant time and does not retain historical values. If this is
   * the first point added, it initializes all aggregates from {@code x}. Subsequent points may
   * update the minimum or maximum when they fall outside the current range. Values are incorporated
   * verbatim; in particular, {@code NaN} will propagate to the running sums and therefore to mean
   * and standard deviation, while comparisons against {@code NaN} do not update extrema.
   *
   * @param x value of the sample point to incorporate, in the caller's units
   */
  public void add(double x) {

    if (n++ == 0) {
      min = x;
      max = x;
      sum = x;
      sum2 = x * x;
    } else {

      if (x < min) {
        min = x;
      } else if (x > max) {
        max = x;
      }

      sum += x;
      sum2 += x * x;
    }
  }

  /**
   * Adds all points from an array to this accumulator.
   *
   * <p>The points are processed in iteration order by delegating to {@link #add(double)} for each
   * element. An empty array leaves this instance unchanged. The array itself is not modified. This
   * method is convenient for batch updates and preserves the same numeric behavior as adding points
   * individually, including any propagation of {@code NaN} or infinities.
   *
   * <pre>{@code
   * ScalarSampleStatistics stats = new ScalarSampleStatistics();
   * stats.add(new double[] {1.0, 2.0, 3.0});
   * double mean = stats.getMean();
   * }</pre>
   *
   * @param points array of points to incorporate; must be non-null and may be empty
   */
  public void add(double[] points) {
    for (double point : points) {
      add(point);
    }
  }

  /**
   * Merges all points from another accumulator into this one.
   *
   * <p>This method combines the aggregates of {@code s} with those of this instance without
   * re-scanning individual values. If {@code s} is empty, the call is a no-op. If this instance is
   * empty, it becomes a copy of {@code s}. Otherwise, counts and running sums are added, and
   * extrema are widened to include the other sample's range. Numeric special values are combined
   * according to normal IEEE 754 rules (for example, {@code NaN} in either sum will yield {@code
   * NaN} results for derived statistics).
   *
   * @param s sample statistics to merge; must be non-null
   */
  public void add(ScalarSampleStatistics s) {

    if (s.n == 0) {
      // nothing to add
      return;
    }

    if (n == 0) {
      n = s.n;
      min = s.min;
      max = s.max;
      sum = s.sum;
      sum2 = s.sum2;
    } else {

      n += s.n;

      if (s.min < min) {
        min = s.min;
      } else if (s.max > max) {
        max = s.max;
      }

      sum += s.sum;
      sum2 += s.sum2;
    }
  }

  /**
   * Get the number of points in the sample.
   *
   * <p>The value reflects the total number of observations added so far using any {@code add}
   * overload. The count is monotonic and never decreases for a given instance.
   *
   * @return number of points currently accumulated
   */
  public int size() {
    return n;
  }

  /**
   * Get the minimal value in the sample.
   *
   * <p>This method returns the smallest value observed so far. If no points have been added, the
   * minimum is undefined and {@link Double#NaN} is returned. When {@code NaN} points are added
   * after a finite minimum has been established, the minimum remains unchanged because comparisons
   * with {@code NaN} are unordered.
   *
   * @return smallest observed value, or {@code NaN} when the sample is empty
   */
  public double getMin() {
    return min;
  }

  /**
   * Get the maximal value in the sample.
   *
   * <p>This method returns the largest value observed so far. If no points have been added, the
   * maximum is undefined and {@link Double#NaN} is returned. As with {@link #getMin()}, adding
   * {@code NaN} values does not update the established maximum.
   *
   * @return largest observed value, or {@code NaN} when the sample is empty
   */
  public double getMax() {
    return max;
  }

  /**
   * Get the mean value of the sample.
   *
   * <p>The mean is computed as the running sum divided by the number of points accumulated. If the
   * sample is empty, this method returns {@code 0}. If any {@code NaN} has been added, the running
   * sum becomes {@code NaN} and the mean will be {@code NaN} as well.
   *
   * @return arithmetic mean of accumulated points, or {@code 0} when empty
   */
  public double getMean() {
    return (n == 0) ? 0 : (sum / n);
  }

  /**
   * Get the sample standard deviation of the accumulated points.
   *
   * <p>This method estimates the standard deviation assuming the accumulated values represent a
   * finite sample drawn from a larger population. It uses the unbiased sample variance formula
   * (division by {@code n - 1}). If fewer than two points have been added, there is not enough data
   * to estimate dispersion and this method returns {@code 0}. As with other derived statistics,
   * special values in the sample follow IEEE 754 behavior: if any running sum becomes {@code NaN},
   * the returned standard deviation will be {@code NaN}.
   *
   * @return sample standard deviation, or {@code 0} when {@code size() < 2}
   */
  public double getStandardDeviation() {
    if (n < 2) {
      return 0;
    }
    return Math.sqrt((n * sum2 - sum * sum) / (n * (n - 1)));
  }
}

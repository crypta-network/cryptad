package org.spaceroots.mantissa.random;

import org.spaceroots.mantissa.linalg.SymetricalMatrix;

/**
 * Computes basic descriptive statistics for a sample of fixed‑dimension real vectors.
 *
 * <p>This class incrementally accumulates statistics over a sequence of {@code double[]} sample
 * points that all share the same dimension. After points are added via {@link #add(double[])},
 * callers can query per‑component minima and maxima, their indices of first occurrence, and the
 * arithmetic mean. It also maintains the second‑order sums needed to compute a sample covariance
 * matrix through {@link #getCovarianceMatrix(SymetricalMatrix)}.
 *
 * <p>The instance starts empty. The dimension is inferred from the first point added and is then
 * fixed for the lifetime of the instance. Subsequent points are expected to have exactly the same
 * length; violating this precondition leads to undefined behavior (typically a runtime indexing
 * error) rather than a checked exception. All returned arrays are defensive copies and may be
 * freely modified by the caller.
 *
 * <p>This class is mutable and not thread‑safe. If multiple threads update or read the same
 * instance, external synchronization is required. For read‑only access after construction, it is
 * safe to publish the instance once no further {@code add(...)} calls will occur.
 *
 * <ul>
 *   <li><strong>Responsibilities:</strong> track count, per‑component extrema, mean, and sample
 *       covariance.
 *   <li><strong>Notable behaviors:</strong> extrema indices refer to the zero‑based insertion order
 *       within this instance; copying from another instance preserves its accumulated state.
 * </ul>
 *
 * @version $Id: VectorialSampleStatistics.java 1709 2006-12-03 21:16:50Z luc $
 * @author L. Maisonobe
 */
public class VectorialSampleStatistics {

  /** Dimension of the vectors to handle. */
  private int dimension;

  /** Number of sample points. */
  private int n;

  /** Indices of the minimal values occurrence in the sample. */
  private int[] minIndices;

  /** Minimal value in the sample. */
  private double[] min;

  /** Maximal value in the sample. */
  private double[] max;

  /** Indices of the maximal values occurrence in the sample. */
  private int[] maxIndices;

  /** Sum of the sample values. */
  private double[] sum;

  /** Sum of the squares of the sample values. */
  private double[] sum2;

  /**
   * Creates a new, empty statistics accumulator.
   *
   * <p>The newly created instance has no points and no fixed dimension. The dimension will be
   * established by the first call to {@link #add(double[])}. Until at least one point is added,
   * queries for extrema or covariance are not meaningful and may return {@code null} or empty
   * structures as documented on the individual accessors.
   */
  public VectorialSampleStatistics() {
    dimension = -1;
    n = 0;
    min = null;
    minIndices = null;
    max = null;
    maxIndices = null;
    sum = null;
    sum2 = null;
  }

  /**
   * Adds a single vector sample point to this accumulator.
   *
   * <p>If this is the first point, its length defines the sample dimension and initializes all
   * tracked values. Otherwise, the point contributes to per‑component minima/maxima, the running
   * sum, and the accumulated second‑order sums used for covariance. Points are indexed in the order
   * they are added, starting at zero; the extrema index accessors report these indices.
   *
   * <p>Precondition: {@code x.length} must equal the dimension inferred from the first point. If
   * violated, behavior is undefined and may result in runtime exceptions.
   *
   * @param x sample point to add; must be non‑null and have the established dimension.
   */
  public void add(double[] x) {

    if (n == 0) {

      initializeFromFirstPoint(x);

    } else {
      addNonFirstPoint(x);
    }

    ++n;
  }

  private void initializeFromFirstPoint(double[] x) {

    dimension = x.length;
    minIndices = new int[dimension];
    maxIndices = new int[dimension];
    min = x.clone();
    max = x.clone();
    sum = x.clone();
    sum2 = new double[dimension * (dimension + 1) / 2];

    int k = 0;
    for (int i = 0; i < dimension; ++i) {
      for (int j = 0; j <= i; ++j) {
        sum2[k++] = x[i] * x[j];
      }
    }
  }

  private void addNonFirstPoint(double[] x) {
    int k = 0;
    for (int i = 0; i < dimension; ++i) {

      if (x[i] < min[i]) {
        min[i] = x[i];
        minIndices[i] = n;
      } else if (x[i] > max[i]) {
        max[i] = x[i];
        maxIndices[i] = n;
      }

      sum[i] += x[i];
      for (int j = 0; j <= i; ++j) {
        sum2[k++] += x[i] * x[j];
      }
    }
  }

  /**
   * Adds all points from the given array to this accumulator.
   *
   * <p>The points are processed in iteration order, exactly as if {@link #add(double[])} were
   * called for each element. If the instance is empty, the first point fixes the dimension. Each
   * subsequent point must match that dimension.
   *
   * @param points array of sample points to add; each element must be non‑null and of identical
   *     length to the first point.
   */
  public void add(double[][] points) {
    for (double[] point : points) {
      add(point);
    }
  }

  /**
   * Merges all points from another accumulator into this one.
   *
   * <p>After the call, this instance represents the concatenation of its previous points followed
   * by the points accumulated in {@code s}. When this instance is empty, the other instance's
   * dimension and state are copied. When both instances are non‑empty, their dimensions must match.
   *
   * <p>The extrema indices from {@code s} are not preserved verbatim; when an extrema from {@code
   * s} replaces the current extrema, the stored index records the insertion position of the merged
   * block within this instance.
   *
   * @param s other sample statistics to merge; if {@code s} is empty, this method is a no‑op.
   */
  public void add(VectorialSampleStatistics s) {

    if (s.n == 0) {
      // nothing to add
      return;
    }

    if (n == 0) {

      dimension = s.dimension;
      min = s.min.clone();
      minIndices = s.minIndices.clone();
      max = s.max.clone();
      maxIndices = s.maxIndices.clone();
      sum = s.sum.clone();
      sum2 = s.sum2.clone();

    } else {
      int k = 0;

      for (int i = 0; i < dimension; ++i) {

        if (s.min[i] < min[i]) {
          min[i] = s.min[i];
          minIndices[i] = n;
        } else if (s.max[i] > max[i]) {
          max[i] = s.max[i];
          maxIndices[i] = n;
        }

        sum[i] += s.sum[i];
        for (int j = 0; j <= i; ++j) {
          sum2[k] += s.sum2[k];
          ++k;
        }
      }
    }

    n += s.n;
  }

  /**
   * Returns the number of points accumulated so far.
   *
   * <p>This count increases by one for each call to {@link #add(double[])} and by the number of
   * points in the supplied source for {@link #add(double[][])} and {@link
   * #add(VectorialSampleStatistics)}. The returned value is the basis for all mean and covariance
   * computations.
   *
   * @return current number of points in the sample, starting at zero for an empty instance.
   */
  public int size() {
    return n;
  }

  /**
   * Returns the per‑component minimal values observed in the sample.
   *
   * <p>Each component may attain its minimum at a different sample index. The returned vector
   * therefore aggregates the minima for each component independently. The corresponding indices of
   * first occurrence can be retrieved via {@link #getMinIndices()}.
   *
   * <p>The returned array is a defensive copy and can be mutated by the caller without affecting
   * this instance.
   *
   * @return vector of minimal values for each component in the sample.
   * @see #getMinIndices()
   */
  public double[] getMin() {
    return min.clone();
  }

  /**
   * Returns the indices at which each component reached its minimal value.
   *
   * <p>The indices refer to the zero‑based order in which points were added to this instance. Each
   * component may have a different index. If multiple points share the same minimal value for a
   * component, the first occurrence is recorded.
   *
   * @return vector of indices corresponding to {@link #getMin()}, one per component.
   * @see #getMin()
   */
  public int[] getMinIndices() {
    return minIndices.clone();
  }

  /**
   * Returns the per‑component maximal values observed in the sample.
   *
   * <p>Each component is tracked independently, so the resulting vector aggregates maxima that may
   * have occurred at different points in the sample. The indices of first occurrence for each
   * component can be obtained with {@link #getMaxIndices()}.
   *
   * <p>The returned array is a defensive copy and can be mutated by the caller without affecting
   * this instance.
   *
   * @return vector of maximal values for each component in the sample.
   * @see #getMaxIndices()
   */
  public double[] getMax() {
    return max.clone();
  }

  /**
   * Returns the indices at which each component reached its maximal value.
   *
   * <p>The indices refer to the zero‑based order in which points were added to this instance. Each
   * component may have a different index. If multiple points share the same maximal value for a
   * component, the first occurrence is recorded.
   *
   * @return vector of indices corresponding to {@link #getMax()}, one per component.
   * @see #getMax()
   */
  public int[] getMaxIndices() {
    return maxIndices.clone();
  }

  /**
   * Computes and returns the arithmetic mean of the sample.
   *
   * <p>The mean is computed per component as {@code sum[i] / n}. This method does not mutate the
   * accumulator and may be called repeatedly. If no points have been added yet, an empty array is
   * returned to signal the absence of a defined mean.
   *
   * @return per‑component mean vector, or an empty array if the sample is empty.
   */
  public double[] getMean() {
    if (n == 0) {
      return new double[0];
    }
    double[] mean = new double[dimension];
    for (int i = 0; i < dimension; ++i) {
      mean[i] = sum[i] / n;
    }
    return mean;
  }

  /**
   * Computes the sample covariance matrix of the accumulated vectors.
   *
   * <p>This method returns the unbiased covariance estimate based on the current sample. It treats
   * the accumulated points as a sample from an underlying distribution (as opposed to the full
   * population), and therefore divides by {@code n - 1} in the usual way. The implementation uses
   * pre‑accumulated second‑order sums, so the computation is {@code O(dimension^2)} regardless of
   * sample size.
   *
   * <p>If fewer than two points have been added, the covariance is undefined and {@code null} is
   * returned. Otherwise, the result is written into the provided {@code covariance} matrix when
   * non‑null, or into a newly allocated {@link SymetricalMatrix} when {@code covariance} is {@code
   * null}.
   *
   * @param covariance optional preallocated matrix to store the result; if {@code null}, a new
   *     {@link SymetricalMatrix} of appropriate dimension is created.
   * @return the sample covariance matrix, or {@code null} if the sample has fewer than two points.
   */
  public SymetricalMatrix getCovarianceMatrix(SymetricalMatrix covariance) {

    if (n < 2) {
      return null;
    }

    if (covariance == null) {
      covariance = new SymetricalMatrix(dimension);
    }

    double c = 1.0 / (n * (n - 1));
    int k = 0;
    for (int i = 0; i < dimension; ++i) {
      for (int j = 0; j <= i; ++j) {
        double e = c * (n * sum2[k] - sum[i] * sum[j]);
        covariance.setElementAndSymetricalElement(i, j, e);
        ++k;
      }
    }

    return covariance;
  }
}

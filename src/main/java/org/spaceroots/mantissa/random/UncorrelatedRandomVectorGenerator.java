package org.spaceroots.mantissa.random;

import java.io.Serial;
import java.io.Serializable;

/**
 * Generates random vectors whose components are independent Gaussian‑like samples.
 *
 * <p>This generator wraps a {@link NormalizedRandomGenerator} that produces uncorrelated,
 * normalized scalar samples (typically with mean&nbsp;0 and standard deviation&nbsp;1) and
 * transforms each scalar into a vector component using a per‑dimension affine mapping: {@code
 * mean[i] + standardDeviation[i] * z}. The mean and standard deviation arrays are defensively
 * copied at construction time, so later external mutations do not affect the generator.
 *
 * <p>The class is stateful only through the underlying scalar generator; it does not keep any
 * additional history between calls to {@link #nextVector()}. It is intended for simulations and
 * Monte‑Carlo style sampling when correlations between dimensions are either not present or are
 * handled elsewhere. If you need correlated vectors, see {@link CorrelatedRandomVectorGenerator}.
 *
 * <ul>
 *   <li><strong>Invariants:</strong> the mean and standard deviation vectors have identical length;
 *       each call returns a new array.
 *   <li><strong>Thread safety:</strong> not guaranteed; concurrent use is safe only if the supplied
 *       {@code NormalizedRandomGenerator} is itself thread‑safe.
 * </ul>
 *
 * @version $Id: UncorrelatedRandomVectorGenerator.java 1709 2006-12-03 21:16:50Z luc $
 * @author L. Maisonobe
 * @see NormalizedRandomGenerator
 * @see CorrelatedRandomVectorGenerator
 */
public class UncorrelatedRandomVectorGenerator implements Serializable, RandomVectorGenerator {

  /**
   * Builds an uncorrelated vector generator with explicit per‑dimension mean and standard
   * deviation.
   *
   * <p>Each call to {@link #nextVector()} draws one normalized sample per component from the
   * supplied {@code generator} and scales/shifts it using the matching entries from {@code mean}
   * and {@code standardDeviation}. The two arrays must have the same length; they are cloned so
   * subsequent changes to the input arrays do not affect this instance.
   *
   * @param mean expected mean value for each component, in the same order as generated vectors
   * @param standardDeviation standard deviation for each component, matched by index to {@code
   *     mean}
   * @param generator underlying source of independent normalized scalar samples for each component
   * @throws IllegalArgumentException if {@code mean.length != standardDeviation.length}
   * @throws NullPointerException if any argument is {@code null}
   */
  public UncorrelatedRandomVectorGenerator(
      double[] mean, double[] standardDeviation, NormalizedRandomGenerator generator) {

    if (mean.length != standardDeviation.length) {
      throw new IllegalArgumentException("dimension mismatch");
    }
    this.mean = mean.clone();
    this.standardDeviation = standardDeviation.clone();

    this.generator = generator;
  }

  /**
   * Builds an uncorrelated vector generator with zero mean and unit standard deviation.
   *
   * <p>This convenience constructor initializes all means to {@code 0} and all standard deviations
   * to {@code 1}. The resulting vectors are therefore direct copies of the normalized samples
   * produced by the underlying generator, with one scalar draw per component.
   *
   * @param dimension number of components in each generated vector; must be non‑negative
   * @param generator underlying source of independent normalized scalar samples for each component
   * @throws NegativeArraySizeException if {@code dimension < 0}
   * @throws NullPointerException if {@code generator} is {@code null}
   */
  public UncorrelatedRandomVectorGenerator(int dimension, NormalizedRandomGenerator generator) {

    mean = new double[dimension];
    standardDeviation = new double[dimension];
    for (int i = 0; i < dimension; ++i) {
      mean[i] = 0;
      standardDeviation[i] = 1;
    }

    this.generator = generator;
  }

  /**
   * Returns the underlying normalized scalar generator.
   *
   * <p>The returned instance is the exact generator supplied at construction time and is not
   * wrapped or copied. Mutating its state (if it is mutable) directly affects subsequent vectors
   * produced by this {@code UncorrelatedRandomVectorGenerator}.
   *
   * @return the underlying uncorrelated normalized components generator
   */
  public NormalizedRandomGenerator getGenerator() {
    return generator;
  }

  /**
   * Generates the next uncorrelated random vector.
   *
   * <p>For each component {@code i}, this method draws {@code z = generator.nextDouble()} and
   * returns {@code mean[i] + standardDeviation[i] * z}. The call allocates a fresh array on every
   * invocation; callers may safely mutate the returned array without affecting future results.
   *
   * @return a newly allocated random vector whose components are independent draws from the
   *     underlying normalized generator after scaling and shifting
   * @throws NullPointerException if the underlying generator is {@code null}
   */
  public double[] nextVector() {

    double[] random = new double[mean.length];
    for (int i = 0; i < random.length; ++i) {
      random[i] = mean[i] + standardDeviation[i] * generator.nextDouble();
    }

    return random;
  }

  /** Mean vector. */
  private final double[] mean;

  /** Standard deviation vector. */
  private final double[] standardDeviation;

  /** Underlying scalar generator. */
  NormalizedRandomGenerator generator;

  @Serial private static final long serialVersionUID = -9094322067568302961L;
}

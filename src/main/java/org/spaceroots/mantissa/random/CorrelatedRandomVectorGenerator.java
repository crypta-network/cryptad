package org.spaceroots.mantissa.random;

import java.io.Serial;
import java.io.Serializable;
import org.spaceroots.mantissa.MantissaException;
import org.spaceroots.mantissa.linalg.GeneralMatrix;
import org.spaceroots.mantissa.linalg.Matrix;
import org.spaceroots.mantissa.linalg.SymetricalMatrix;

/**
 * Generates multivariate random vectors whose components follow a prescribed covariance structure.
 *
 * <p>The generator combines an underlying {@link NormalizedRandomGenerator} that emits independent,
 * zero-mean, unit-variance samples with a Cholesky-like factorization of the supplied covariance
 * matrix. Each call to {@link #nextVector()} transforms freshly drawn normalized components by the
 * rectangular root matrix so the returned vector respects both the requested mean and the
 * correlations encoded in the covariance input. The implementation supports strictly positive
 * definite matrices and semi-definite cases by computing a rectangular factor when the matrix rank
 * is lower than its dimension, avoiding failures when small eigenvalues are effectively zero.
 *
 * <p>Instances are mutable and not thread-safe: they retain intermediate buffers and the working
 * permutation from the factorization. Create separate instances per thread or guard access
 * externally if concurrent sampling is required. Typical usage wires a deterministic normalized
 * generator (for reproducibility) and reuses this adapter to produce many correlated samples:
 *
 * <pre>{@code
 * SymetricalMatrix covariance = ...;
 * NormalizedRandomGenerator base = ...; // Gaussian or custom
 * CorrelatedRandomVectorGenerator generator =
 *     new CorrelatedRandomVectorGenerator(covariance, base);
 * double[] sample = generator.nextVector();
 * }</pre>
 *
 * <ul>
 *   <li>Performs rank-revealing factorization to tolerate semi-definite covariance inputs.
 *   <li>Returns fresh arrays on each invocation; callers own and may mutate them.
 *   <li>Exposes the computed root matrix and rank for diagnostic or reuse scenarios.
 * </ul>
 *
 * @version $Id: CorrelatedRandomVectorGenerator.java 1709 2006-12-03 21:16:50Z luc $
 * @author L. Maisonobe
 * @see NormalizedRandomGenerator
 * @see NotPositiveDefiniteMatrixException
 */
public class CorrelatedRandomVectorGenerator implements Serializable, RandomVectorGenerator {

  /**
   * Creates a generator using explicit mean values and a full covariance matrix.
   *
   * <p>The constructor defensively copies the mean vector, factorizes the covariance matrix, and
   * stores the resulting root for reuse across calls to {@link #nextVector()}. The covariance must
   * be positive definite or positive semi-definite; otherwise a checked exception is raised during
   * construction. The supplied {@code generator} should emit independent, normalized components;
   * deterministic seeds can be provided in its implementation to make correlated outputs
   * repeatable.
   *
   * @param mean expected mean value for each component; length must equal covariance order
   * @param covariance square covariance matrix describing target correlations; must not be null
   * @param generator underlying normalized generator producing zero-mean, unit-variance samples
   * @throws IllegalArgumentException if {@code mean.length} differs from covariance dimension
   * @throws NotPositiveDefiniteMatrixException if covariance has a negative diagonal pivot during
   *     factorization
   */
  public CorrelatedRandomVectorGenerator(
      double[] mean, SymetricalMatrix covariance, NormalizedRandomGenerator generator)
      throws NotPositiveDefiniteMatrixException {

    int order = covariance.getRows();
    if (mean.length != order) {
      String message =
          MantissaException.translate(
              "dimension mismatch {0} != {1}",
              new String[] {Integer.toString(mean.length), Integer.toString(order)});
      throw new IllegalArgumentException(message);
    }
    this.mean = mean.clone();

    factorize(covariance);

    this.generator = generator;
    normalized = new double[rank];
  }

  /**
   * Creates a generator that produces zero-mean correlated vectors from a covariance matrix.
   *
   * <p>This overload initializes the mean vector to zeros, computes a rank-revealing factorization
   * of the covariance, and allocates internal buffers sized to the detected rank. It is convenient
   * when callers only need covariance structure and do not require a non-zero mean shift. The
   * {@code generator} supplies normalized components that will be linearly combined by the computed
   * root matrix on each sampling call.
   *
   * @param covariance square covariance matrix defining the desired correlations; must be non-null
   * @param generator normalized component source that outputs independent, unit-variance values
   * @throws NotPositiveDefiniteMatrixException if the matrix contains a significantly negative
   *     diagonal pivot during factorization
   */
  public CorrelatedRandomVectorGenerator(
      SymetricalMatrix covariance, NormalizedRandomGenerator generator)
      throws NotPositiveDefiniteMatrixException {

    int order = covariance.getRows();
    mean = new double[order];
    for (int i = 0; i < order; ++i) {
      mean[i] = 0;
    }

    factorize(covariance);

    this.generator = generator;
    normalized = new double[rank];
  }

  /**
   * Returns the computed root matrix used to correlate normalized samples.
   *
   * <p>The root matrix {@code B} satisfies {@code B.Bt = C} where {@code C} is the user-supplied
   * covariance matrix, possibly after row/column permutation. When the covariance is semi-definite,
   * {@code B} is rectangular with a column count equal to the detected rank. The returned instance
   * is owned by this generator; callers should treat it as read-only to preserve subsequent sample
   * correctness.
   *
   * @return internal root matrix with dimensions {@code order x rank}; not null but mutable
   */
  public Matrix getRootMatrix() {
    return root;
  }

  /**
   * Provides the underlying normalized generator that supplies uncorrelated components.
   *
   * <p>The returned object is the same reference passed to the constructor. It is consulted on each
   * call to {@link #nextVector()}, so replacing it externally will affect subsequent samples.
   * Implementations may or may not be thread-safe; this class does not add synchronization.
   *
   * @return normalized generator reference used during sampling; may be reused by callers
   */
  public NormalizedRandomGenerator getGenerator() {
    return generator;
  }

  /**
   * Reports the detected rank of the covariance matrix after factorization.
   *
   * <p>The rank equals the number of independent rows/columns in the covariance input and matches
   * the column count of the internally stored root matrix. For full-rank, strictly positive
   * definite inputs, this value equals the covariance order; for semi-definite inputs it is lower.
   * The rank determines how many normalized components are requested from the underlying generator
   * during sampling.
   *
   * @return rank value between {@code 1} and the covariance dimension, inclusive
   */
  public int getRank() {
    return rank;
  }

  /**
   * Performs a rank-revealing factorization of the covariance matrix.
   *
   * <p>The routine duplicates the covariance to avoid mutating caller state, selects pivot rows to
   * maximize numerical stability, and builds a rectangular lower-factor such that {@code B.Bt}
   * reproduces the covariance. A negative pivot beyond tolerance triggers {@link
   * NotPositiveDefiniteMatrixException}. This method mutates internal fields ({@code rank}, {@code
   * root}) and should only be invoked during construction.
   *
   * @param covariance symmetric covariance matrix to decompose; must match previously validated
   *     dimensions
   * @throws NotPositiveDefiniteMatrixException if a diagonal pivot is sufficiently negative to
   *     violate positive semi-definiteness
   */
  private void factorize(SymetricalMatrix covariance) throws NotPositiveDefiniteMatrixException {

    int order = covariance.getRows();
    SymetricalMatrix c = (SymetricalMatrix) covariance.duplicate();
    GeneralMatrix b = new GeneralMatrix(order, order);

    int[] swap = new int[order];
    int[] index = initIndex(order);

    rank = 0;
    while (rank < order) {
      swap[rank] = findPivot(c, index, rank, order);
      applySwap(index, rank, swap[rank]);

      double diagonalValue = c.getElement(index[rank], index[rank]);
      if (diagonalValue < 1.0e-12) {
        handleSmallDiagonal(diagonalValue);
        break;
      }

      updateDecomposition(c, b, index, order, diagonalValue);
      ++rank;
    }

    buildRootMatrix(order, b, swap);
  }

  private int[] initIndex(int order) {
    int[] index = new int[order];
    for (int i = 0; i < order; ++i) {
      index[i] = i;
    }
    return index;
  }

  private int findPivot(SymetricalMatrix c, int[] index, int currentRank, int order) {
    int pivot = currentRank;
    double pivotValue = c.getElement(index[currentRank], index[currentRank]);
    for (int i = currentRank + 1; i < order; ++i) {
      double candidate = c.getElement(index[i], index[i]);
      if (candidate > pivotValue) {
        pivot = i;
        pivotValue = candidate;
      }
    }
    return pivot;
  }

  private void applySwap(int[] index, int currentRank, int pivot) {
    if (pivot != currentRank) {
      int tmp = index[currentRank];
      index[currentRank] = index[pivot];
      index[pivot] = tmp;
    }
  }

  private void handleSmallDiagonal(double diagonalValue) throws NotPositiveDefiniteMatrixException {

    if (rank == 0 || diagonalValue < -1.0e-12) {
      throw new NotPositiveDefiniteMatrixException();
    }

    // all remaining diagonal elements are close to zero,
    // we consider we have found the rank of the covariance matrix
    ++rank;
  }

  private void updateDecomposition(
      SymetricalMatrix c, GeneralMatrix b, int[] index, int order, double diagonalValue) {

    double sqrt = Math.sqrt(diagonalValue);
    b.setElement(rank, rank, sqrt);
    double inverse = 1 / sqrt;
    for (int i = rank + 1; i < order; ++i) {
      double e = inverse * c.getElement(index[i], index[rank]);
      b.setElement(i, rank, e);
      c.setElement(index[i], index[i], c.getElement(index[i], index[i]) - e * e);
      for (int j = rank + 1; j < i; ++j) {
        double f = b.getElement(j, rank);
        c.setElementAndSymetricalElement(
            index[i], index[j], c.getElement(index[i], index[j]) - e * f);
      }
    }
  }

  private void buildRootMatrix(int order, GeneralMatrix b, int[] swap) {
    root = new GeneralMatrix(order, rank);
    for (int i = 0; i < order; ++i) {
      for (int j = 0; j < rank; ++j) {
        root.setElement(swap[i], j, b.getElement(i, j));
      }
    }
  }

  /**
   * Generates a single correlated random vector using the precomputed factorization.
   *
   * <p>Each invocation pulls {@link #getRank()} normalized scalars from the underlying generator,
   * multiplies them by the root matrix, and adds the stored mean component-wise. A fresh array is
   * allocated on every call; callers own the returned buffer and may modify it without affecting
   * subsequent samples. The method performs no synchronization and is not thread-safe when sharing
   * an instance across threads.
   *
   * @return newly allocated vector whose length equals the covariance order; values honor mean and
   *     covariance shape
   */
  @Override
  public double[] nextVector() {

    // generate uncorrelated vector
    for (int i = 0; i < rank; ++i) {
      normalized[i] = generator.nextDouble();
    }

    // compute correlated vector
    double[] correlated = new double[mean.length];
    for (int i = 0; i < correlated.length; ++i) {
      correlated[i] = mean[i];
      for (int j = 0; j < rank; ++j) {
        correlated[i] += root.getElement(i, j) * normalized[j];
      }
    }

    return correlated;
  }

  /** Mean vector. */
  private final double[] mean;

  /** Permutated Cholesky root of the covariance matrix. */
  private Matrix root;

  /** Rank of the covariance matrix. */
  private int rank;

  /** Underlying generator. */
  NormalizedRandomGenerator generator;

  /** Storage for the normalized vector. */
  private final double[] normalized;

  @Serial private static final long serialVersionUID = -88563624902398453L;
}

package com.onionnetworks.fec;

import org.jetbrains.annotations.NotNull;

/**
 * Encapsulates the dimensions for multiplying an {@code n x k} matrix by a {@code k x m} matrix.
 *
 * <p>This record is a lightweight carrier for the three integer dimensions that describe a
 * row-major matrix multiplication. It is useful when callers want to pass the dimensions as a
 * single value alongside matrix buffers or slices. The values are stored verbatim, with no
 * validation, normalization, or derived computations performed by this type.
 *
 * <p>The record is immutable and thread-safe as a value object. It carries no lifecycle beyond
 * construction and has no side effects. Consumers should interpret the dimensions consistently with
 * their matrix storage conventions, typically row-major arrays where {@code n} is the number of
 * rows, {@code k} is the shared inner dimension, and {@code m} is the number of columns on the
 * right-hand matrix.
 *
 * <ul>
 *   <li>Groups the three dimensions for a single multiplication operation.
 *   <li>Expresses shape only; it does not validate or allocate storage.
 *   <li>Composes naturally with {@link MatrixMulParams} when building parameter bundles.
 * </ul>
 *
 * @param n number of rows in the left matrix and the resulting output matrix
 * @param k shared inner dimension; columns of the left, rows of the right matrix
 * @param m number of columns in the right matrix and the resulting output matrix
 * @see MatrixMulParams
 */
public record MatrixMulDimensions(int n, int k, int m) {
  /**
   * Returns a compact string representation of the dimensions.
   *
   * <p>The output includes the three integer values labeled by name, in the order {@code n}, {@code
   * k}, and {@code m}. This method is intended for diagnostics and debugging and makes no
   * assumptions about whether the dimensions are valid or consistent with any particular buffers.
   *
   * @return a string describing {@code n}, {@code k}, and {@code m}
   */
  @Override
  public @NotNull String toString() {
    return "MatrixMulDimensions{" + "n=" + n + ", k=" + k + ", m=" + m + '}';
  }
}

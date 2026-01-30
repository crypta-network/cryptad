package org.spaceroots.mantissa.linalg;

import java.io.Serial;

/**
 * Upper triangular square matrix whose elements below the main diagonal are always zero.
 *
 * <p>Instances are mutable containers backed by a contiguous row-major array and are intended for
 * numerical linear algebra where the zero structure can be exploited. Typical uses include
 * back-substitution of right-hand sides produced by Gaussian elimination, incremental updates of
 * decompositions, or inexpensive determinant extraction from triangular factors. Operations in this
 * class alter the current matrix rather than producing copies, so callers should duplicate when the
 * original must be preserved. No internal synchronization is performed; each instance should be
 * confined to a single thread or externally guarded when shared.
 *
 * <ul>
 *   <li>Supports in-place addition and subtraction with structure validation.
 *   <li>Provides determinant computation directly from the diagonal entries.
 *   <li>Solves upper-triangular systems by backward substitution for dense right-hand sides.
 * </ul>
 *
 * @version $Id: UpperTriangularMatrix.java 1709 2006-12-03 21:16:50Z luc $
 * @author L. Maisonobe
 * @see SquareMatrix
 */
public class UpperTriangularMatrix extends SquareMatrix {

  /**
   * Create a zero-filled upper triangular matrix of the requested order.
   *
   * <p>The storage is allocated for the full square layout used by {@link SquareMatrix}, but the
   * entries below the diagonal are considered structurally invalid and should remain zero. Clients
   * typically use this constructor when building a matrix that will be populated explicitly or as a
   * destination for factorization routines that overwrite their inputs.
   *
   * @param order order of the matrix, zero-based indexed rows/columns must be within this bound
   */
  public UpperTriangularMatrix(int order) {
    super(order);
  }

  /**
   * Build an upper triangular matrix initialized from a flat data array.
   *
   * <p>The {@code data} array is interpreted in row-major order consistent with the base
   * implementation, and callers are responsible for supplying values that already satisfy the
   * triangular constraint. Elements corresponding to lower-triangular positions are accepted but
   * should normally be zero to preserve the invariant. The constructor copies the array so later
   * changes to the input will not affect the matrix.
   *
   * @param order order of the matrix, expected to match the square root of the data length
   * @param data table of matrix elements in row-major form; must contain at least {@code order *
   *     order} entries
   */
  public UpperTriangularMatrix(int order, double[] data) {
    super(order, data);
  }

  /**
   * Copy constructor that performs a deep clone of another upper triangular matrix.
   *
   * <p>All numeric entries and structural properties are duplicated so mutations of the new
   * instance leave the original untouched. Use this when a caller needs a writable view of a matrix
   * obtained from a shared context.
   *
   * @param u upper triangular matrix to copy; must not be {@code null}
   */
  public UpperTriangularMatrix(UpperTriangularMatrix u) {
    super(u);
  }

  /**
   * Create an independent duplicate of this matrix.
   *
   * <p>The returned instance contains the same numerical values and dimensions but shares no
   * mutable state, making it safe to modify without affecting the original. This is useful when a
   * caller must preserve the current matrix before applying in-place operations such as {@link
   * #selfAdd(UpperTriangularMatrix)} or {@link #selfSub(UpperTriangularMatrix)}.
   *
   * @return new {@code UpperTriangularMatrix} with identical data and size; caller receives full
   *     ownership of the copy
   */
  @Override
  public Matrix duplicate() {
    return new UpperTriangularMatrix(this);
  }

  /**
   * Set a single element, enforcing the upper-triangular structure.
   *
   * <p>Indices are zero-based and must satisfy {@code i <= j}; attempting to set a lower-triangular
   * position results in an {@link ArrayIndexOutOfBoundsException}. All other elements may be set to
   * arbitrary finite values. This method modifies the matrix in place.
   *
   * @param i row index to update; must be between {@code 0} and {@code rows - 1}
   * @param j column index to update; must be between {@code 0} and {@code columns - 1}
   * @param value numerical value to assign to the specified position
   * @throws ArrayIndexOutOfBoundsException if {@code i > j} or either index is outside valid bounds
   */
  @Override
  public void setElement(int i, int j, double value) {
    if (i > j) {
      throw new ArrayIndexOutOfBoundsException(
          "cannot set elements" + " below diagonal of a" + " upper triangular matrix");
    }
    super.setElement(i, j, value);
  }

  /**
   * Add another upper triangular matrix to this one in place.
   *
   * <p>Both operands must share identical dimensions; otherwise an {@link IllegalArgumentException}
   * is thrown. Only entries on and above the diagonal are touched; the structural zeros remain
   * unchanged. Use this method when accumulating multiple triangular factors without allocating
   * intermediate objects.
   *
   * @param u upper triangular matrix to add; dimensions must equal this instance
   * @throws IllegalArgumentException if {@code u} has a different row or column count
   */
  public void selfAdd(UpperTriangularMatrix u) {

    // validity check
    if ((rows != u.rows) || (columns != u.columns)) {
      throw new IllegalArgumentException(
          "cannot add a "
              + u.rows
              + 'x'
              + u.columns
              + " matrix to a "
              + rows
              + 'x'
              + columns
              + " matrix");
    }

    // addition loop
    for (int i = 0; i < rows; ++i) {
      for (int index = i * (columns + 1); index < (i + 1) * columns; ++index) {
        data[index] += u.data[index];
      }
    }
  }

  /**
   * Subtract another upper triangular matrix from this one in place.
   *
   * <p>Dimensions must match exactly; otherwise an {@link IllegalArgumentException} is raised. Only
   * the upper-triangular portion is affected, mirroring the structure constraint of this class.
   * This is commonly used when updating residual factors or rolling back incremental changes.
   *
   * @param u upper triangular matrix to subtract; must share the same size as this instance
   * @throws IllegalArgumentException if the provided matrix does not match the current dimensions
   */
  public void selfSub(UpperTriangularMatrix u) {

    // validity check
    if ((rows != u.rows) || (columns != u.columns)) {
      throw new IllegalArgumentException(
          "cannot subtract a "
              + u.rows
              + 'x'
              + u.columns
              + " matrix from a "
              + rows
              + 'x'
              + columns
              + " matrix");
    }

    // substraction loop
    for (int i = 0; i < rows; ++i) {
      for (int index = i * (columns + 1); index < (i + 1) * columns; ++index) {
        data[index] -= u.data[index];
      }
    }
  }

  /**
   * Compute the determinant directly from the diagonal entries.
   *
   * <p>The determinant of an upper triangular matrix equals the product of its diagonal elements,
   * so this method multiplies those values without altering the matrix. The {@code epsilon}
   * parameter is accepted for API symmetry with other numeric routines; callers may pass a typical
   * tolerance even though no singularity guard is applied here.
   *
   * @param epsilon tolerated magnitude for near-singular detection; currently unused by this
   *     implementation but retained for compatibility
   * @return product of diagonal entries representing the determinant of this matrix
   */
  @Override
  public double getDeterminant(double epsilon) {
    double determinant = data[0];
    for (int index = columns + 1; index < columns * columns; index += columns + 1) {
      determinant *= data[index];
    }
    return determinant;
  }

  /**
   * Solve the linear system {@code this * X = b} by backward substitution.
   *
   * <p>The right-hand side {@code b} must have the same number of rows as this matrix. The method
   * iterates from the last row upward, dividing by each diagonal pivot and subtracting previously
   * computed terms, producing a dense result matrix with the same shape as {@code b}. A new matrix
   * instance is returned; the inputs remain unchanged. Large pivots near zero trigger a {@link
   * SingularMatrixException} to signal an ill-conditioned or singular system.
   *
   * <pre>{@code
   * // Example: solving Ux = b
   * Matrix x = upperTriangular.solve(b, 1e-12);
   * }</pre>
   *
   * @param b right-hand side matrix whose row count must match this matrix
   * @param epsilon absolute tolerance below which a diagonal pivot is considered singular
   * @return newly allocated matrix containing the solution with the same dimensions as {@code b}
   * @throws IllegalArgumentException if {@code b} has a different number of rows
   * @throws SingularMatrixException if any diagonal element has magnitude smaller than {@code
   *     epsilon}
   */
  @Override
  public Matrix solve(Matrix b, double epsilon) throws SingularMatrixException {
    // validity check
    if (b.getRows() != rows) {
      throw new IllegalArgumentException("dimension mismatch");
    }

    // prepare the data storage
    int bRows = b.getRows();
    int bCols = b.getColumns();

    double[] resultData = new double[bRows * bCols];
    int resultIndex = bRows * bCols - 1;
    int lowerElements = 0;
    int upperElements = 0;
    int minJ = columns;
    int maxJ = 0;

    // solve the linear system
    for (int i = rows - 1; i >= 0; --i) {
      RowResult rowResult = processRow(b, epsilon, resultData, resultIndex, minJ, maxJ, i);
      resultIndex = rowResult.resultIndex();
      lowerElements += rowResult.lowerElementsDelta();
      upperElements += rowResult.upperElementsDelta();
      minJ = rowResult.minJ();
      maxJ = rowResult.maxJ();
    }

    return MatrixFactory.buildMatrix(bRows, bCols, resultData, lowerElements, upperElements);
  }

  private RowResult processRow(
      Matrix b,
      double epsilon,
      double[] resultData,
      int resultIndex,
      int currentMinJ,
      int currentMaxJ,
      int rowIndex)
      throws SingularMatrixException {
    int bRows = b.getRows();
    int bCols = b.getColumns();
    double diag = data[rowIndex * (columns + 1)];
    if (Math.abs(diag) < epsilon) {
      throw new SingularMatrixException();
    }
    double inv = 1.0 / diag;

    NonNullRange range = b.getRangeForRow(rowIndex);
    int minJ = Math.min(currentMinJ, range.begin);
    int maxJ = Math.max(currentMaxJ, range.end);

    int j = bCols - 1;
    int workingResultIndex = resultIndex;
    while (j >= maxJ) {
      resultData[workingResultIndex] = 0.0;
      --workingResultIndex;
      --j;
    }

    int bIndex = rowIndex * bCols + maxJ - 1;
    int lowerElementsDelta = 0;
    int upperElementsDelta = 0;
    while (j >= minJ) {

      // compute the current element
      int index1 = (rowIndex + 1) * columns - 1;
      int index2 = (bRows - 1) * bCols + j;
      double value = b.data[bIndex];
      while (index1 >= rowIndex * (columns + 1)) {
        value -= data[index1] * resultData[index2];
        --index1;
        index2 -= bCols;
      }
      value *= inv;
      resultData[workingResultIndex] = value;

      // count the affected upper and lower elements
      // (in order to deduce the shape of the resulting matrix)
      if (j < rowIndex) {
        ++lowerElementsDelta;
      } else if (rowIndex < j) {
        ++upperElementsDelta;
      }

      --bIndex;
      --workingResultIndex;
      --j;
    }

    while (j >= 0) {
      resultData[workingResultIndex] = 0.0;
      --workingResultIndex;
      --j;
    }

    return new RowResult(workingResultIndex, minJ, maxJ, lowerElementsDelta, upperElementsDelta);
  }

  private record RowResult(
      int resultIndex, int minJ, int maxJ, int lowerElementsDelta, int upperElementsDelta) {}

  /**
   * Describe the contiguous non-null column range for a given row.
   *
   * <p>For an upper triangular matrix, rows start at the main diagonal, so the returned range
   * begins at the row index and extends through the last column. This helps callers reason about
   * sparsity without scanning the data array.
   *
   * @param i zero-based row index whose non-null span is requested
   * @return {@link NonNullRange} representing the inclusive column bounds that can hold non-zero
   *     entries
   */
  @Override
  public NonNullRange getRangeForRow(int i) {
    return new NonNullRange(i, columns);
  }

  /**
   * Describe the contiguous non-null row range for a given column.
   *
   * <p>Columns of an upper triangular matrix can contain non-zero elements from the top row down to
   * the diagonal. This helper reports that span so clients can allocate or iterate efficiently when
   * interacting with external data structures.
   *
   * @param j zero-based column index whose non-null span is requested
   * @return {@link NonNullRange} covering rows that may contain non-zero values in the specified
   *     column
   */
  @Override
  public NonNullRange getRangeForColumn(int j) {
    return new NonNullRange(0, j + 1);
  }

  @Serial private static final long serialVersionUID = -197266611942032237L;
}

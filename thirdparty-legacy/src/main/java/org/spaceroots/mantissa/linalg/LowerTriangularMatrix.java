package org.spaceroots.mantissa.linalg;

import java.io.Serial;

/**
 * Dense implementation of a strictly lower-triangular square matrix.
 *
 * <p>The class specializes {@link SquareMatrix} by enforcing that every element above the main
 * diagonal is treated as a structural zero. Construction fixes the matrix order, but coefficients
 * on and below the diagonal remain mutable through the provided mutators. The implementation stores
 * coefficients in the inherited contiguous row-major buffer, yet range hints ({@link
 * #getRangeForRow(int)} and {@link #getRangeForColumn(int)}) ensure algorithms skip the forced-zero
 * region. Typical usage is forward substitution for triangular solves or incremental construction
 * of factorizations that produce a lower triangular factor. Instances are not thread-safe; callers
 * should synchronize externally when sharing them across threads. Numeric operations assume finite
 * {@code double} values and do not normalize or rescale coefficients automatically.
 *
 * <ul>
 *   <li>Intended for linear systems where the left-hand matrix is already lower triangular.
 *   <li>Determinant is the product of diagonal entries; zeros mark singularity.
 *   <li>Shape invariants: fixed order, zero range above the main diagonal.
 * </ul>
 *
 * @version $Id: LowerTriangularMatrix.java 1709 2006-12-03 21:16:50Z luc $
 * @author L. Maisonobe
 * @see UpperTriangularMatrix
 */
public class LowerTriangularMatrix extends SquareMatrix {

  /**
   * Build an empty lower triangular matrix of the requested order.
   *
   * <p>The instance allocates a dense square buffer with {@code order} rows and columns and fills
   * every position with {@code 0.0}. By contract, callers must only store non-zero values on or
   * below the main diagonal; attempts to write above it will be rejected by {@link #setElement(int,
   * int, double)}. The dimension remains fixed after construction, making the matrix suitable as
   * the left-hand side of forward-substitution solves or as a mutable container for lower factors
   * produced by decomposition routines.
   *
   * @param order strictly positive order defining both row and column counts for the matrix
   */
  public LowerTriangularMatrix(int order) {
    super(order);
  }

  /**
   * Build a matrix with supplied coefficients stored row by row.
   *
   * <p>The {@code data} array must contain exactly {@code order * order} values arranged in
   * row-major order. Values in positions above the diagonal are accepted but conceptually treated
   * as structural zeros by range-aware algorithms; callers should therefore only populate entries
   * on or below the diagonal to preserve semantics. The buffer is copied, so subsequent changes to
   * {@code data} will not affect the matrix. The order is validated upstream to be strictly
   * positive.
   *
   * @param order square order defining both rows and columns; must be greater than zero
   * @param data dense coefficient array in row-major order; expected length {@code order * order}
   */
  public LowerTriangularMatrix(int order, double[] data) {
    super(order, data);
  }

  /**
   * Create a deep copy of another lower triangular matrix.
   *
   * <p>The new instance mirrors the source matrix order and coefficient values, including any
   * explicit zeros stored in the dense buffer. Subsequent modifications to either matrix remain
   * independent, which makes this constructor useful before performing in-place operations such as
   * accumulation or substitution that would otherwise overwrite the source data.
   *
   * @param l source matrix to clone; must not be {@code null} and should already satisfy the
   *     lower-triangular invariant
   */
  public LowerTriangularMatrix(LowerTriangularMatrix l) {
    super(l);
  }

  /**
   * {@inheritDoc}
   *
   * <p>The returned matrix preserves the lower-triangular structure and copies all coefficients,
   * allowing callers to mutate the clone without affecting the original. Structural hints and
   * dimensions are kept identical so downstream algorithms can continue to exploit range
   * information.
   */
  @Override
  public Matrix duplicate() {
    return new LowerTriangularMatrix(this);
  }

  /**
   * Overwrite a single coefficient while preserving the lower-triangular invariant.
   *
   * <p>Indices are validated against the matrix dimensions by the superclass. An attempt to write a
   * non-zero (or zero) value above the main diagonal triggers an {@link
   * ArrayIndexOutOfBoundsException} because the structural constraint would be violated. Writes on
   * or below the diagonal occur in O(1) time and immediately update the dense backing buffer. The
   * method performs no synchronization; coordinate concurrent access externally when necessary.
   *
   * @param i row index in {@code [0, getRows() - 1]} identifying the element to update
   * @param j column index in {@code [0, getColumns() - 1]} that must satisfy {@code i >= j}
   * @param value coefficient to store at the specified position; any finite {@code double} allowed
   * @throws ArrayIndexOutOfBoundsException if {@code j} lies above the diagonal for the given row
   * @throws IllegalArgumentException if either index falls outside the matrix dimensions
   */
  @Override
  public void setElement(int i, int j, double value) {
    if (i < j) {
      throw new ArrayIndexOutOfBoundsException(
          "cannot set elements" + " above diagonal of a" + " lower triangular matrix");
    }
    super.setElement(i, j, value);
  }

  /**
   * Add another lower triangular matrix to this matrix in place.
   *
   * <p>The operation requires both matrices to share identical dimensions. Only the stored
   * lower-triangular region is iterated; the upper region is implicitly zero and therefore ignored.
   * The receiver's coefficients are updated directly, making this a destructive operation that
   * avoids additional allocations. Use {@link #duplicate()} first if the original values must be
   * preserved. Complexity is proportional to the number of coefficients on and below the diagonal
   * ({@code n(n+1)/2} for an {@code n x n} matrix).
   *
   * @param l lower triangular matrix whose coefficients are added element-wise to this instance
   * @throws IllegalArgumentException if the operand does not share the same order as this matrix
   */
  public void selfAdd(LowerTriangularMatrix l) {

    // validity check
    if ((rows != l.rows) || (columns != l.columns)) {
      throw new IllegalArgumentException(
          "cannot add a "
              + l.rows
              + 'x'
              + l.columns
              + " matrix to a "
              + rows
              + 'x'
              + columns
              + " matrix");
    }

    // addition loop
    for (int i = 0; i < rows; ++i) {
      for (int index = i * columns; index < i * (columns + 1) + 1; ++index) {
        data[index] += l.data[index];
      }
    }
  }

  /**
   * Subtract another lower triangular matrix from this matrix in place.
   *
   * <p>Dimensions must match exactly; otherwise an {@link IllegalArgumentException} is thrown. The
   * method iterates only through indices on and below the diagonal, assuming zeros elsewhere. The
   * receiver is mutated, so clone it first when non-destructive behavior is required. This
   * operation runs in O(n²) time for square order {@code n} but touches only the lower half plus
   * diagonal, mirroring the structural constraint.
   *
   * @param l lower triangular matrix whose coefficients are subtracted from this instance
   * @throws IllegalArgumentException if the matrix orders differ between operands
   */
  public void selfSub(LowerTriangularMatrix l) {

    // validity check
    if ((rows != l.rows) || (columns != l.columns)) {
      throw new IllegalArgumentException(
          "cannot subtract a "
              + l.rows
              + 'x'
              + l.columns
              + " matrix from a "
              + rows
              + 'x'
              + columns
              + " matrix");
    }

    // substraction loop
    for (int i = 0; i < rows; ++i) {
      for (int index = i * columns; index < i * (columns + 1) + 1; ++index) {
        data[index] -= l.data[index];
      }
    }
  }

  /**
   * Compute the determinant as the product of diagonal entries.
   *
   * <p>For a lower triangular matrix the determinant equals the multiplication of all diagonal
   * coefficients; off-diagonal elements do not influence the result. No pivoting or scaling is
   * performed, so zeros or near-zeros on the diagonal will directly produce a zero determinant. The
   * {@code epsilon} parameter is retained for API compatibility but is not used in the current
   * computation; callers should pre-validate diagonal values if tolerance-based behavior is
   * desired.
   *
   * @param epsilon unused numerical tolerance maintained for interface consistency
   * @return determinant value equal to the product of diagonal coefficients in this matrix
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
   * Solve {@code L · X = B} where {@code L} is this lower triangular matrix.
   *
   * <p>The solver performs forward substitution row by row. Each diagonal coefficient must have an
   * absolute value greater than or equal to {@code epsilon}; otherwise a {@link
   * SingularMatrixException} is thrown to signal that the system is singular or ill-conditioned
   * under the requested tolerance. The right-hand side matrix {@code B} must share the same row
   * count as {@code L} but may have any column count. A new matrix is produced via {@link
   * MatrixFactory}, carrying range metadata that reflects the lower/upper element counts observed
   * in the solution.
   *
   * @param b right-hand side matrix; must have {@code getRows() == getRows()} for this instance
   * @param epsilon non-negative threshold below which diagonal pivots are considered singular
   * @return newly allocated matrix {@code X} satisfying the triangular system for all columns in
   *     {@code B}
   * @throws IllegalArgumentException if the row dimension of {@code B} differs from this matrix
   * @throws SingularMatrixException if a diagonal entry fails the supplied tolerance check
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
    int resultIndex = 0;
    int lowerElements = 0;
    int upperElements = 0;
    int minJ = columns;
    int maxJ = 0;

    // solve the linear system
    for (int i = 0; i < rows; ++i) {
      double diag = data[i * (columns + 1)];
      if (Math.abs(diag) < epsilon) {
        throw new SingularMatrixException();
      }
      double inv = 1.0 / diag;

      NonNullRange range = b.getRangeForRow(i);
      minJ = Math.min(minJ, range.begin);
      maxJ = Math.max(maxJ, range.end);

      resultIndex = fillZerosUntil(0, minJ, resultData, resultIndex);

      RowPointers pointers = new RowPointers(i * bCols + minJ, resultIndex, bCols);
      ElementCounters counters = new ElementCounters(lowerElements, upperElements);
      computeRowValues(
          i, new NonNullRange(minJ, maxJ), pointers, inv, b.data, resultData, counters);
      resultIndex = pointers.resultIndex;
      lowerElements = counters.lowerElements;
      upperElements = counters.upperElements;

      resultIndex = fillZerosUntil(maxJ, bCols, resultData, resultIndex);
    }

    return MatrixFactory.buildMatrix(bRows, bCols, resultData, lowerElements, upperElements);
  }

  private void computeRowValues(
      int row,
      NonNullRange columnRange,
      RowPointers pointers,
      double inverseDiagonal,
      double[] rhsData,
      double[] resultData,
      ElementCounters counters) {
    for (int j = columnRange.begin; j < columnRange.end; ++j) {
      int index1 = row * columns;
      int index2 = j;
      double value = rhsData[pointers.rhsIndex];
      while (index1 < row * (columns + 1)) {
        value -= data[index1] * resultData[index2];
        ++index1;
        index2 += pointers.rightHandSideColumns;
      }
      value *= inverseDiagonal;
      resultData[pointers.resultIndex] = value;
      if (j < row) {
        ++counters.lowerElements;
      } else if (row < j) {
        ++counters.upperElements;
      }
      ++pointers.rhsIndex;
      ++pointers.resultIndex;
    }
  }

  private int fillZerosUntil(int startColumn, int endColumn, double[] resultData, int resultIndex) {
    for (int j = startColumn; j < endColumn; ++j) {
      resultData[resultIndex] = 0.0;
      ++resultIndex;
    }
    return resultIndex;
  }

  private static final class RowPointers {
    private int rhsIndex;
    private int resultIndex;
    private final int rightHandSideColumns;

    private RowPointers(int rhsIndex, int resultIndex, int rightHandSideColumns) {
      this.rhsIndex = rhsIndex;
      this.resultIndex = resultIndex;
      this.rightHandSideColumns = rightHandSideColumns;
    }
  }

  private static final class ElementCounters {
    private int lowerElements;
    private int upperElements;

    private ElementCounters(int lowerElements, int upperElements) {
      this.lowerElements = lowerElements;
      this.upperElements = upperElements;
    }
  }

  /**
   * Describe the contiguous range of potentially non-zero columns for a row.
   *
   * <p>For a lower triangular matrix, row {@code i} can only contain non-zero values from column
   * {@code 0} through {@code i} inclusive; higher columns are structurally zero. The returned range
   * is half-open, so the {@code end} value equals {@code i + 1}. This information allows generic
   * algorithms in {@link Matrix} to skip zero regions efficiently.
   *
   * @param i zero-based row index for which to compute the active column range
   * @return range object where {@code begin} is 0 and {@code end} is {@code i + 1}
   */
  @Override
  public NonNullRange getRangeForRow(int i) {
    return new NonNullRange(0, i + 1);
  }

  /**
   * Describe the contiguous range of potentially non-zero rows for a column.
   *
   * <p>Column {@code j} of a lower triangular matrix may hold non-zero values from row {@code j}
   * down to the last row; entries above {@code j} are always zero. The returned {@link
   * NonNullRange} is half-open with {@code begin = j} and {@code end = rows}, enabling range-aware
   * algorithms to limit iteration to meaningful coefficients.
   *
   * @param j zero-based column index whose non-null row span is requested
   * @return range object spanning rows {@code j} (inclusive) to {@code rows} (exclusive)
   */
  @Override
  public NonNullRange getRangeForColumn(int j) {
    return new NonNullRange(j, rows);
  }

  @Serial private static final long serialVersionUID = 3592505328858227281L;
}

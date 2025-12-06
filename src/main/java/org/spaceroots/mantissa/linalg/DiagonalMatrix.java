package org.spaceroots.mantissa.linalg;

import java.io.Serial;

/**
 * Diagonal matrix implementation that stores only diagonal coefficients explicitly and assumes all
 * off-diagonal entries are zero.
 *
 * <p>This implementation is geared toward small to medium-sized problems where users want a fast,
 * allocation-friendly representation of a diagonal linear operator. The underlying storage reuses
 * the {@code SquareMatrix} backing array, but only diagonal positions are meaningful, and all
 * accessor methods enforce that invariant. Typical call flows are:
 *
 * <ul>
 *   <li>Build an identity or constant-valued diagonal matrix for scaling vectors.
 *   <li>Compute inverses and determinants quickly by processing only diagonal entries.
 *   <li>Solve linear systems {@code D x = b} by per-row scaling without modifying the right-hand
 *       side structure.
 * </ul>
 *
 * <p>The class is mutable; writes are guarded so that off-diagonal positions cannot be set. No
 * internal synchronization is provided, so instances are not thread-safe for concurrent mutation.
 * Read-only concurrent access is safe after construction if callers avoid interleaved writes. Use
 * {@link #duplicate()} to create defensive copies when sharing across threads. Invariants rely on
 * callers respecting the diagonal-only contract; violating it through reflection or serialization
 * tampering may break algorithmic assumptions.
 *
 * @version $Id: DiagonalMatrix.java 1709 2006-12-03 21:16:50Z luc $
 * @author L. Maisonobe
 * @see SquareMatrix
 * @see Matrix
 */
public class DiagonalMatrix extends SquareMatrix {

  /**
   * Builds an identity-like diagonal matrix of the given order.
   *
   * <p>All diagonal elements are initialized to {@code 1.0} so the resulting matrix acts as an
   * identity for multiplication and solving operations. Off-diagonal positions remain implicitly
   * zero and cannot be assigned. The constructor performs no defensive copy because there is no
   * caller-provided data; it delegates to the value-based constructor for consistent initialization
   * logic and invariant enforcement.
   *
   * @param order order of the matrix; must be positive to describe a valid square shape
   */
  public DiagonalMatrix(int order) {
    this(order, 1.0);
  }

  /**
   * Creates a diagonal matrix and fills every diagonal entry with the same scalar value.
   *
   * <p>Use this constructor for quick creation of scaled identity matrices or to seed iterative
   * algorithms with a uniform diagonal preconditioner. Off-diagonal entries are left at zero and
   * remain inaccessible through {@link #setElement(int, int, double)}. The backing storage uses a
   * dense array sized for a square matrix of the requested order, but only indices {@code i*(n+1)}
   * carry meaningful values. Passing {@code 0.0} creates a singular matrix that will fail inversion
   * or solve operations when the provided tolerance detects the zero diagonal.
   *
   * @param order order of the matrix; must be strictly positive
   * @param value value assigned to every diagonal coefficient; can be zero to model singularity
   */
  public DiagonalMatrix(int order, double value) {
    super(order);
    for (int index = 0; index < order * order; index += order + 1) {
      data[index] = value;
    }
  }

  /**
   * Builds a diagonal matrix by reusing caller-provided storage.
   *
   * <p>The {@code data} array is expected to hold matrix coefficients in row-major order with a
   * length of at least {@code order * order}. Only diagonal slots are interpreted; callers must
   * ensure off-diagonal entries are zero to preserve diagonal semantics. The array is not copied,
   * enabling zero-allocation creation when the caller already owns suitably prepared data. After
   * construction, attempting to change non-diagonal entries through {@link #setElement(int, int,
   * double)} will raise an exception.
   *
   * @param order order of the matrix; must match the square root of the usable array length
   * @param data table of matrix elements stored row by row; not defensively copied
   */
  public DiagonalMatrix(int order, double[] data) {
    super(order, data);
  }

  /**
   * Copy constructor that duplicates the full diagonal state.
   *
   * <p>The new instance owns its own backing array, so subsequent modifications on either matrix do
   * not affect the other. Off-diagonal positions are copied even though they should be zero; this
   * mirrors the layout of the source {@link DiagonalMatrix} exactly. Use this when a deep copy is
   * required before mutating an existing matrix or when sharing data across threads without
   * synchronization.
   *
   * @param d diagonal matrix to copy; must not be {@code null}
   */
  public DiagonalMatrix(DiagonalMatrix d) {
    super(d);
  }

  /**
   * Creates a deep copy of this diagonal matrix.
   *
   * <p>The duplicate contains the same diagonal coefficients and identical implicit zero
   * off-diagonal structure as this instance. Changes to the returned matrix do not propagate back,
   * making it suitable for preserving an original state before performing in-place updates or for
   * passing a snapshot to downstream consumers.
   *
   * @return new {@link DiagonalMatrix} with copied data and identical dimensions
   */
  public Matrix duplicate() {
    return new DiagonalMatrix(this);
  }

  /**
   * Sets a coefficient on the main diagonal.
   *
   * <p>Only positions where {@code i == j} are accepted; attempting to write off-diagonal entries
   * breaks the diagonal invariant and therefore triggers an {@link ArrayIndexOutOfBoundsException}.
   * The value is written directly into the backing array, preserving previously stored diagonal
   * coefficients in other rows and columns.
   *
   * @param i zero-based row index; must equal {@code j} to be valid
   * @param j zero-based column index; must equal {@code i} to be valid
   * @param value coefficient to store at position {@code (i, j)}
   * @throws ArrayIndexOutOfBoundsException if the indices do not reference a diagonal location
   */
  @Override
  public void setElement(int i, int j, double value) {
    if (i != j) {
      throw new ArrayIndexOutOfBoundsException(
          "cannot set elements" + " out of diagonal in a" + " diagonal matrix");
    }
    super.setElement(i, j, value);
  }

  /**
   * Computes the determinant by multiplying all diagonal coefficients.
   *
   * <p>The method ignores the {@code epsilon} argument because a diagonal matrix determinant is the
   * exact product of its diagonal entries. If any entry is zero, the determinant is zero and the
   * matrix is singular. The computation runs in {@code O(n)} time and does not allocate.
   *
   * @param epsilon tolerance parameter accepted for interface consistency; not used in the
   *     computation
   * @return product of all diagonal elements as a {@code double} value
   */
  public double getDeterminant(double epsilon) {
    double determinant = data[0];
    for (int index = columns + 1; index < columns * columns; index += columns + 1) {
      determinant *= data[index];
    }
    return determinant;
  }

  /**
   * Builds the inverse matrix when all diagonal entries are non-zero.
   *
   * <p>Each diagonal coefficient is inverted independently; off-diagonal entries remain zero. A
   * {@link SingularMatrixException} is thrown when any diagonal magnitude is below the supplied
   * tolerance, signalling that inversion would be numerically unstable or impossible. The resulting
   * matrix is a new {@link DiagonalMatrix} instance, leaving the original unchanged.
   *
   * @param epsilon absolute tolerance used to decide whether a diagonal entry is effectively zero
   * @return diagonal matrix containing reciprocal values of the current diagonal
   * @throws SingularMatrixException if a diagonal element is within {@code epsilon} of zero
   */
  @Override
  public SquareMatrix getInverse(double epsilon) throws SingularMatrixException {

    DiagonalMatrix inv = new DiagonalMatrix(columns);

    for (int index = 0; index < columns * columns; index += columns + 1) {
      if (Math.abs(data[index]) < epsilon) {
        throw new SingularMatrixException();
      }
      inv.data[index] = 1.0 / data[index];
    }

    return inv;
  }

  /**
   * Solves the linear system {@code D x = b} where {@code D} is this diagonal matrix.
   *
   * <p>The method duplicates the right-hand side to avoid mutating caller data and scales each row
   * by the reciprocal of the corresponding diagonal element. If any diagonal entry is smaller in
   * magnitude than {@code epsilon}, a {@link SingularMatrixException} is raised because no stable
   * inverse exists. Complexity is proportional to the number of non-null entries reported by the
   * row ranges of {@code b}, making the operation efficient for sparse right-hand sides.
   *
   * @param b right-hand side matrix to solve against; must have matching row dimension
   * @param epsilon absolute tolerance that determines when a diagonal entry is considered singular
   * @return new matrix containing the solution vector or block, leaving {@code b} unchanged
   * @throws SingularMatrixException if any diagonal entry magnitude falls below {@code epsilon}
   */
  public Matrix solve(Matrix b, double epsilon) throws SingularMatrixException {

    Matrix result = b.duplicate();

    for (int i = 0; i < columns; ++i) {
      double diag = data[i * (columns + 1)];
      if (Math.abs(diag) < epsilon) {
        throw new SingularMatrixException();
      }
      double inv = 1.0 / diag;

      NonNullRange range = result.getRangeForRow(i);
      for (int index = i * b.columns + range.begin; index < i * b.columns + range.end; ++index) {
        result.data[index] = inv * b.data[index];
      }
    }

    return result;
  }

  /**
   * Reports the non-null column span for a given row.
   *
   * <p>For diagonal matrices only one element per row is non-zero, so the returned {@link
   * NonNullRange} always covers the single diagonal column. Callers can use this to optimize sparse
   * traversals by skipping known zero regions.
   *
   * @param i zero-based row index queried for its non-null column interval
   * @return range whose {@code begin} is {@code i} and {@code end} is {@code i + 1}
   */
  public NonNullRange getRangeForRow(int i) {
    return new NonNullRange(i, i + 1);
  }

  /**
   * Reports the non-null row span for a given column.
   *
   * <p>Only the diagonal element is potentially non-zero, so the returned {@link NonNullRange}
   * covers exactly one row. Algorithms that iterate column-wise can rely on this to avoid touching
   * zero-only regions when accumulating results.
   *
   * @param j zero-based column index queried for its non-null row interval
   * @return range whose {@code begin} is {@code j} and {@code end} is {@code j + 1}
   */
  public NonNullRange getRangeForColumn(int j) {
    return new NonNullRange(j, j + 1);
  }

  @Serial private static final long serialVersionUID = -2965166085913895323L;
}

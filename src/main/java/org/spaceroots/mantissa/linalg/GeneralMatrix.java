package org.spaceroots.mantissa.linalg;

import java.io.Serial;

/**
 * Dense general-purpose matrix implementation with no structural constraints.
 *
 * <p>{@code GeneralMatrix} stores coefficients in a contiguous row-major array and advertises every
 * row and column as potentially non-null. It is the default choice when no diagonal, triangular, or
 * sparsity structure is known in advance, ensuring algorithms operate over the full {@code rows x
 * columns} surface. Instances are mutable and not thread-safe; callers must synchronize externally
 * if sharing across threads. The matrix shape is fixed at construction time while individual
 * coefficients may be updated through accessor methods or in-place operations.
 *
 * <p>Typical usage constructs a matrix directly or via {@link MatrixFactory}, populates
 * coefficients with {@link #setElement(int, int, double)} or bulk operations, and applies mutating
 * accumulators such as {@link #selfAdd(Matrix)} when avoiding additional allocations. The range
 * hook methods always return full-width spans so that the base {@link Matrix} algorithms iterate
 * across every element. Cloning through {@link #duplicate()} yields independent buffers suitable
 * for branching computations without side effects on the original instance.
 *
 * <ul>
 *   <li>Mutability: elements change freely; shape and dense layout remain constant.
 *   <li>Thread safety: requires external coordination when accessed concurrently.
 *   <li>Structure: no implicit zeros are assumed, so iteration remains predictable.
 * </ul>
 *
 * @version $Id: GeneralMatrix.java 1709 2006-12-03 21:16:50Z luc $
 * @author L. Maisonobe
 * @see Matrix
 * @see MatrixFactory
 */
public class GeneralMatrix extends Matrix {

  /**
   * Construct a dense matrix initialized with zeros for every coefficient.
   *
   * <p>The dimensions are validated as strictly positive before allocating a contiguous row-major
   * buffer sized to {@code rows * columns}. All coefficients start at {@code 0.0}; callers
   * typically populate them through {@link #setElement(int, int, double)} or in-place arithmetic
   * operations. The instance represents the fully general case, so downstream algorithms will visit
   * every position without structural shortcuts. Although coefficients are mutable, the shape stays
   * constant for the lifetime of the matrix, enabling safe bounds checking in client code.
   *
   * @param rows total row count; must be strictly positive for valid indexing
   * @param columns total column count; must be strictly positive for valid indexing
   * @throws IllegalArgumentException if either dimension is zero or negative during construction
   */
  public GeneralMatrix(int rows, int columns) {
    super(rows, columns);
  }

  /**
   * Construct a dense matrix using caller-supplied coefficients stored row after row.
   *
   * <p>Dimensions are checked for positivity, and the provided {@code data} buffer is cloned by the
   * superclass to preserve encapsulation. The array is expected to contain {@code rows * columns}
   * entries laid out in row-major order; {@code null} is accepted and recorded so callers can fill
   * values later. Because the matrix advertises no structural zeros, all coefficients are treated
   * as potentially significant and will be visited by algorithms that rely on non-null ranges. The
   * resulting instance can be mutated freely without affecting the original buffer supplied here.
   *
   * @param rows total row count; must be strictly positive for valid indexing
   * @param columns total column count; must be strictly positive for valid indexing
   * @param data coefficient array in row-major order; may be {@code null} when deferring fills
   * @throws IllegalArgumentException if either dimension is zero or negative during construction
   */
  public GeneralMatrix(int rows, int columns, double[] data) {
    super(rows, columns, data);
  }

  /**
   * Copy constructor producing an independent dense matrix.
   *
   * <p>The new instance mirrors the shape and coefficient values of {@code m} while duplicating the
   * underlying buffer so subsequent mutations remain isolated. Use this overload when a downstream
   * computation needs a baseline snapshot that preserves general-matrix semantics and full non-null
   * ranges. The operation leaves {@code m} unchanged and produces deterministic results regardless
   * of element content.
   *
   * @param m source matrix to duplicate; must not be {@code null} and must expose compatible shape
   */
  public GeneralMatrix(Matrix m) {
    super(m);
  }

  /**
   * Create a deep copy preserving general-matrix semantics.
   *
   * <p>The returned instance owns a fresh buffer sized to the same {@code rows x columns} shape and
   * populated with the current coefficients of this matrix. Use it when branching computations
   * require independent mutation or when providing a snapshot to callers that should not observe
   * later in-place updates. Complexity is linear in the number of stored elements, and no internal
   * synchronization is performed; callers should avoid concurrent writes during duplication to
   * ensure consistent reads.
   *
   * @return new {@code GeneralMatrix} with identical dimensions and coefficient values copied
   */
  public Matrix duplicate() {
    return new GeneralMatrix(this);
  }

  /**
   * Add another matrix to this instance in place.
   *
   * <p>This mutating operation performs element-wise addition after verifying that both operands
   * share identical dimensions. It scans the full dense buffer because general matrices advertise
   * no structural zeros. Use it for accumulations where avoiding a new allocation is desirable;
   * callers remain responsible for coordinating concurrent access. On failure, the method leaves
   * the current state unchanged and throws an {@link IllegalArgumentException}. Passing {@code
   * null} is unsupported and will trigger a {@link NullPointerException} before validation.
   *
   * @param m matrix to add; must match this matrix row and column counts exactly
   * @throws IllegalArgumentException if operand rows or columns differ from this matrix during
   *     addition
   */
  public void selfAdd(Matrix m) {

    // validity check
    if ((rows != m.rows) || (columns != m.columns)) {
      throw new IllegalArgumentException(
          "cannot add a "
              + m.rows
              + 'x'
              + m.columns
              + " matrix to a "
              + rows
              + 'x'
              + columns
              + " matrix");
    }

    // addition loop
    for (int index = 0; index < rows * columns; ++index) {
      data[index] += m.data[index];
    }
  }

  /**
   * Subtract another matrix from this instance in place.
   *
   * <p>The method validates that both matrices share the same shape, then walks the dense buffer to
   * perform element-wise subtraction. It is intended for incremental updates that keep ownership of
   * the existing storage rather than allocating a new result. Because the class represents fully
   * general matrices, no sparsity shortcuts are applied, and every coefficient is visited. The
   * operation is not thread-safe; callers must guard concurrent access. If dimensions mismatch, an
   * {@link IllegalArgumentException} is raised and the matrix remains unchanged.
   *
   * @param m matrix to subtract; must mirror this matrix row and column counts exactly
   * @throws IllegalArgumentException if operand rows or columns differ from this matrix during
   *     subtraction
   */
  public void selfSub(Matrix m) {

    // validity check
    if ((rows != m.rows) || (columns != m.columns)) {
      throw new IllegalArgumentException(
          "cannot subtract a "
              + m.rows
              + 'x'
              + m.columns
              + " matrix from a "
              + rows
              + 'x'
              + columns
              + " matrix");
    }

    // substraction loop
    for (int index = 0; index < rows * columns; ++index) {
      data[index] -= m.data[index];
    }
  }

  /**
   * Get the non-null range for a row in a dense matrix.
   *
   * <p>General matrices treat every column as potentially non-zero, so the returned {@link
   * NonNullRange} always begins at column {@code 0} and ends at {@code columns}, using the
   * exclusive upper bound convention of {@code NonNullRange}. The method communicates structural
   * expectations only; it does not inspect stored values and therefore cannot infer accidental
   * zeros. Base-class algorithms rely on this hook to size inner loops and skip work for structured
   * subclasses, but in this implementation all columns are scanned.
   *
   * @param i zero-based row index whose structural non-null span is requested
   * @return range starting at column 0 and ending at the current column count
   */
  protected NonNullRange getRangeForRow(int i) {
    return new NonNullRange(0, columns);
  }

  /**
   * Get the non-null range for a column in a dense matrix.
   *
   * <p>Because {@code GeneralMatrix} assumes every row may contain data in a given column, the
   * returned {@link NonNullRange} starts at row {@code 0} and ends at {@code rows}, following the
   * exclusive upper bound convention. The method signals to base algorithms that no structural
   * zeros exist along this column, ensuring iteration covers all rows. It does not examine
   * coefficient values and therefore reflects structural expectations rather than actual sparsity.
   *
   * @param j zero-based column index whose structural non-null span is requested
   * @return range starting at row 0 and ending at the current row count
   */
  protected NonNullRange getRangeForColumn(int j) {
    return new NonNullRange(0, rows);
  }

  @Serial private static final long serialVersionUID = 4350328622456299819L;
}

package org.spaceroots.mantissa.linalg;

import java.io.Serial;

/**
 * Dense representation of a square symmetrical matrix.
 *
 * <p>The matrix stores all coefficients in row-major order while enforcing the mathematical
 * symmetry {@code a[i][j] == a[j][i]}. Mutation helpers such as {@link
 * #setElementAndSymetricalElement} keep the upper and lower triangular parts aligned, and direct
 * element writes outside the diagonal are intentionally blocked to protect the invariant. The class
 * is designed for small to medium matrices where a compact dense layout is faster than sparse
 * alternatives, and it is primarily used by least-squares assembly code that repeatedly accumulates
 * {@code w * a * a^T} terms.
 *
 * <p>Instances are mutable and not thread-safe; callers must provide external synchronization when
 * sharing across threads. A newly created matrix defaults to zeros, and helper constructors allow
 * cloning existing data or building directly from a single vector contribution. Typical workflows
 * build the matrix incrementally, then delegate to {@link Matrix} algorithms for solving or further
 * factorization.
 *
 * <ul>
 *   <li>Guarantees square shape and symmetric contents after every public operation.
 *   <li>Provides in-place additive updates to reduce allocations during iterative problems.
 *   <li>Maintains compatibility with {@link GeneralSquareMatrix} APIs for downstream processing.
 * </ul>
 *
 * @version $Id: SymetricalMatrix.java 1709 2006-12-03 21:16:50Z luc $
 * @author L. Maisonobe
 * @see GeneralSquareMatrix
 * @see Matrix
 */
public class SymetricalMatrix extends GeneralSquareMatrix {

  /**
   * Creates a zero-filled symmetrical matrix of the given order.
   *
   * <p>The resulting matrix has {@code order} rows and columns with every coefficient initialized
   * to {@code 0.0}. No validation is performed beyond the superclass constructor, so callers should
   * supply a strictly positive order to obtain a meaningful matrix. After creation, callers may set
   * diagonal entries individually using {@link #setElement(int, int, double)} or populate symmetric
   * pairs via {@link #setElementAndSymetricalElement(int, int, double)} when building numeric
   * systems.
   *
   * @param order order of the square matrix; provide a positive value
   */
  public SymetricalMatrix(int order) {
    super(order);
  }

  /**
   * Creates a symmetrical matrix from an explicit coefficient array.
   *
   * <p>The {@code data} array is interpreted in row-major order and is expected to contain exactly
   * {@code order * order} entries. The superclass constructor handles storage; callers should
   * ensure the provided coefficients are already symmetrical if that property matters to downstream
   * consumers. This constructor is useful when importing matrices from serialized forms or test
   * fixtures where the full dense representation is already available.
   *
   * @param order order of the square matrix; must match the array layout
   * @param data table of matrix elements stored sequentially row after row
   */
  public SymetricalMatrix(int order, double[] data) {
    super(order, data);
  }

  /**
   * Copy constructor that duplicates the full matrix contents.
   *
   * <p>All coefficients of the supplied matrix are copied into a new dense buffer, preserving the
   * source values while allowing independent mutation of the new instance. Use this when a snapshot
   * of an existing symmetrical matrix is required for branching computations or defensive copying
   * in public APIs.
   *
   * @param s square symmetrical matrix to copy in full
   */
  public SymetricalMatrix(SymetricalMatrix s) {
    super(s);
  }

  /**
   * Builds a symmetrical matrix from the rank-one product {@code w * a * a^T}.
   *
   * <p>The resulting matrix has size {@code a.length} and contains the outer product of the
   * supplied vector scaled by {@code w}. Only a single pass over the vector is required, and the
   * constructor mirrors upper-triangular values into the lower triangle to keep symmetry intact.
   * This is the preferred entry point when repeatedly assembling normal matrices in least-squares
   * or covariance calculations.
   *
   * @param w multiplicative factor (weight) applied to every product term
   * @param a base vector used to compute the symmetrical outer-product contribution
   */
  public SymetricalMatrix(double w, double[] a) {
    super(a.length, new double[a.length * a.length]);

    for (int i = 0; i < a.length; ++i) {
      int indexU = i * (columns + 1);
      int indexL = indexU;

      double factor = w * a[i];
      data[indexU] = factor * a[i];

      for (int j = i + 1; j < columns; ++j) {
        ++indexU;
        indexL += columns;
        data[indexU] = factor * a[j];
        data[indexL] = data[indexU];
      }
    }
  }

  /**
   * Creates a deep copy of this symmetrical matrix.
   *
   * <p>The returned instance owns its own dense storage, so subsequent modifications to either
   * matrix do not affect the other. Use this when branching computations require an immutable
   * snapshot of the current state or when providing defensive copies to callers outside the current
   * package. All dimensions and coefficient values are preserved exactly.
   *
   * @return new symmetric matrix with copied dimensions and entries
   */
  @Override
  public Matrix duplicate() {
    return new SymetricalMatrix(this);
  }

  /**
   * Sets a single matrix element on the diagonal.
   *
   * <p>Because the class enforces symmetry, callers may only adjust diagonal entries through this
   * method. Attempting to update an off-diagonal position results in an {@link
   * ArrayIndexOutOfBoundsException}. To modify paired off-diagonal entries in one step, use {@link
   * #setElementAndSymetricalElement(int, int, double)}, which mirrors the change into the
   * transposed position.
   *
   * @param i row index, zero-based, must match the column index
   * @param j column index, zero-based, must match the row index
   * @param value value of the element to store on the diagonal
   * @exception ArrayIndexOutOfBoundsException if the indices are outside matrix bounds
   * @see #setElementAndSymetricalElement
   * @see Matrix#getElement
   */
  @Override
  public void setElement(int i, int j, double value) {
    if (i != j) {
      throw new ArrayIndexOutOfBoundsException(
          "cannot separately set" + " elements out of diagonal" + " in a symmetrical matrix");
    }
    super.setElement(i, j, value);
  }

  /**
   * Sets both a matrix element and its symmetrical counterpart.
   *
   * <p>The supplied {@code value} is written to positions {@code (i, j)} and {@code (j, i)}. When
   * {@code i == j}, the call is equivalent to {@link #setElement(int, int, double)}. Bounds are
   * validated by the superclass, and the method preserves symmetry in a single call, which helps
   * avoid inconsistent states during incremental assembly.
   *
   * @param i row index of first element, zero-based within matrix order
   * @param j column index of first element, zero-based within matrix order
   * @param value value written to both symmetric positions of the matrix
   * @exception ArrayIndexOutOfBoundsException if any index exceeds matrix dimensions
   * @see #setElement
   * @see Matrix#getElement
   */
  public void setElementAndSymetricalElement(int i, int j, double value) {
    super.setElement(i, j, value);
    if (i != j) {
      super.setElement(j, i, value);
    }
  }

  /**
   * Adds another symmetrical matrix to this instance in place.
   *
   * <p>Both operands must share identical dimensions; otherwise an {@link IllegalArgumentException}
   * is thrown. Each coefficient in {@code s} is added to the corresponding position in this matrix,
   * and lower-triangular values are mirrored to preserve symmetry without extra passes. The
   * operation is destructive with respect to this instance but leaves the argument matrix
   * unchanged.
   *
   * @param s symmetrical matrix to add, matching the same order as this instance
   * @exception IllegalArgumentException if the operand order differs from this matrix
   */
  public void selfAdd(SymetricalMatrix s) {

    // validity check
    if ((rows != s.rows) || (columns != s.columns)) {
      throw new IllegalArgumentException(
          "cannot add a "
              + s.rows
              + 'x'
              + s.columns
              + " matrix to a "
              + rows
              + 'x'
              + columns
              + " matrix");
    }

    // addition loop
    for (int i = 0; i < rows; ++i) {
      int indexU = i * (columns + 1);
      int indexL = indexU;

      data[indexU] += s.data[indexU];

      for (int j = i + 1; j < columns; ++j) {
        ++indexU;
        indexL += columns;
        data[indexU] += s.data[indexU];
        data[indexL] = data[indexU];
      }
    }
  }

  /**
   * Subtracts another symmetrical matrix from this instance in place.
   *
   * <p>The operand must have the same order as this matrix; otherwise an {@link
   * IllegalArgumentException} is raised. The method subtracts each coefficient of {@code s} from
   * the corresponding entry here, updating both triangular halves to maintain symmetry. It alters
   * only the receiver, leaving the argument matrix intact for reuse in other computations.
   *
   * @param s symmetrical matrix to subtract, with identical dimensions to this matrix
   * @exception IllegalArgumentException if matrix orders differ between operands
   */
  @SuppressWarnings("unused")
  public void selfSub(SymetricalMatrix s) {

    // validity check
    if ((rows != s.rows) || (columns != s.columns)) {
      throw new IllegalArgumentException(
          "cannot subtract a "
              + s.rows
              + 'x'
              + s.columns
              + " matrix from a "
              + rows
              + 'x'
              + columns
              + " matrix");
    }

    // substraction loop
    for (int i = 0; i < rows; ++i) {
      int indexU = i * (columns + 1);
      int indexL = indexU;

      data[indexU] -= s.data[indexU];

      for (int j = i + 1; j < columns; ++j) {
        ++indexU;
        indexL += columns;
        data[indexU] -= s.data[indexU];
        data[indexL] = data[indexU];
      }
    }
  }

  /**
   * Accumulates {@code w * a * a^T} into this matrix in place.
   *
   * <p>The vector {@code a} must have a length equal to the matrix order; otherwise an {@link
   * IllegalArgumentException} is thrown. The method performs a rank-one update, adding the weighted
   * outer product to both triangular halves to keep the structure symmetrical. It is particularly
   * useful in iterative least-squares assembly and covariance estimation where repeated small
   * updates are cheaper than recomputing full products.
   *
   * @param w multiplicative factor (weight) scaling the outer-product contribution
   * @param a base vector used to compute the symmetrical contribution in one pass
   * @exception IllegalArgumentException if vector length does not match matrix order
   */
  public void selfAddWAAt(double w, double[] a) {
    if (rows != a.length) {
      throw new IllegalArgumentException(
          "cannot add a "
              + a.length
              + 'x'
              + a.length
              + " matrix to a "
              + rows
              + 'x'
              + columns
              + " matrix");
    }

    for (int i = 0; i < rows; ++i) {
      int indexU = i * (columns + 1);
      int indexL = indexU;

      double factor = w * a[i];
      data[indexU] += factor * a[i];

      for (int j = i + 1; j < columns; ++j) {
        ++indexU;
        indexL += columns;
        data[indexU] += factor * a[j];
        data[indexL] = data[indexU];
      }
    }
  }

  @Serial private static final long serialVersionUID = -2083829252075519221L;
}

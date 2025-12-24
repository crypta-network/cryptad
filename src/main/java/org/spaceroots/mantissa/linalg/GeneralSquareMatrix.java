package org.spaceroots.mantissa.linalg;

import java.io.Serial;

/**
 * Dense mutable square matrix with LU factorization and linear solver support.
 *
 * <p>This implementation stores all coefficients in a contiguous row-major array and exposes
 * operations that rely on square-specific properties such as determinants and linear system
 * solving. Instances eagerly validate dimensions at construction time, while numerical computations
 * are performed lazily: the LU decomposition with partial pivoting is built on first use and cached
 * until the matrix content changes. The cached permutation vector tracks row swaps and preserves
 * the parity needed to compute determinants with the correct sign.
 *
 * <p>The class is intended for general-purpose, dense problems where simplicity outweighs the cost
 * of O(n²) storage. It is mutable and not thread-safe; callers must serialize access when sharing
 * an instance. Typical call patterns include constructing a matrix, filling coefficients, then
 * invoking {@link #getDeterminant(double)} or {@link #solve(Matrix, double)} one or more times. Any
 * mutation through {@link #setElement(int, int, double)}, {@link #selfAdd(SquareMatrix)}, or {@link
 * #selfSub(SquareMatrix)} invalidates the cached decomposition so subsequent factorizations reflect
 * the updated data.
 *
 * <ul>
 *   <li>Responsibilities: maintain dense coefficients, perform LU with row pivoting, expose solver
 *       entry points.
 *   <li>Invariants: fixed square order after construction; cached factorization is cleared on
 *       mutation.
 *   <li>Thread safety: none; synchronize externally when sharing across threads.
 * </ul>
 *
 * @version $Id: GeneralSquareMatrix.java 1709 2006-12-03 21:16:50Z luc $
 * @author L. Maisonobe
 * @see SquareMatrix
 * @see LowerTriangularMatrix
 * @see UpperTriangularMatrix
 */
public class GeneralSquareMatrix extends SquareMatrix {

  /**
   * Construct an empty square matrix with all coefficients initialized to zero.
   *
   * <p>The created matrix has identical row and column counts equal to {@code order}. A dense
   * buffer of size {@code order * order} is allocated and filled with {@code 0.0} so callers can
   * immediately populate entries through {@link #setElement(int, int, double)} or higher-level
   * operations. Any previously cached LU factorization fields are reset to {@code null} to reflect
   * the pristine state. Providing a non-positive order is rejected by the superclass constructor,
   * ensuring that downstream algorithms always operate on valid shapes.
   *
   * @param order matrix order (row/column count); must be strictly positive for valid allocation
   */
  public GeneralSquareMatrix(int order) {
    super(order);
    permutations = null;
    evenPermutations = true;
    lower = null;
    upper = null;
  }

  /**
   * Construct a square matrix from a flat row-major coefficient array.
   *
   * <p>Coefficients are read row after row from {@code data}; its length must equal {@code order *
   * order} or the superclass constructor will signal a dimension error. The array is copied, so
   * later modifications to {@code data} do not affect the matrix. Cached LU-related fields are
   * cleared to postpone factorization until a solver or determinant request arrives. This overload
   * is convenient when importing coefficients generated elsewhere while preserving the strict
   * square layout required by the linear algebra routines.
   *
   * @param order matrix order (row and column count); validated to be strictly positive
   * @param data contiguous array of {@code order * order} values in row-major order; not retained
   */
  public GeneralSquareMatrix(int order, double[] data) {
    super(order, data);
    permutations = null;
    evenPermutations = true;
    lower = null;
    upper = null;
  }

  /**
   * Copy constructor creating a deep clone of another {@link GeneralSquareMatrix} instance.
   *
   * <p>The new matrix duplicates coefficient values, dimension, and any previously computed LU
   * factorization state. When the source has already been factorized, the permutation vector and
   * triangular matrices are cloned so the copy can reuse the cached decomposition without
   * recomputing it. Subsequent mutations on either instance invalidate their own caches but do not
   * propagate to the other. Use this constructor when a caller needs an isolated yet fully
   * initialized snapshot before performing destructive updates.
   *
   * @param s square matrix to copy, optionally already factorized; must not be {@code null}
   */
  public GeneralSquareMatrix(GeneralSquareMatrix s) {
    super(s);

    if (s.permutations != null) {
      permutations = s.permutations.clone();
      evenPermutations = s.evenPermutations;
      lower = new LowerTriangularMatrix(s.lower);
      upper = new UpperTriangularMatrix(s.upper);
    } else {
      permutations = null;
      evenPermutations = true;
      lower = null;
      upper = null;
    }
  }

  /**
   * Create an independent copy preserving cached factorization details when available.
   *
   * <p>The returned matrix mirrors this instance, including any LU decomposition state that has
   * already been computed, so repeated solver calls can remain efficient. Later modifications on
   * either matrix clear their own caches independently and do not affect the other instance.
   *
   * @return new {@link GeneralSquareMatrix} containing the same coefficients and cached LU data
   */
  @Override
  public Matrix duplicate() {
    return new GeneralSquareMatrix(this);
  }

  /**
   * Set a single coefficient and invalidate any previously computed LU factorization.
   *
   * <p>Coordinates use 0-based indexing. The call delegates to the superclass setter for bounds
   * checking, then clears cached permutation and triangular matrices so later determinant or solve
   * operations rebuild the decomposition with the updated values. This method mutates the matrix in
   * place and is therefore not thread-safe when the instance is shared.
   *
   * @param i zero-based row index to modify; must be within {@code [0, rows)}
   * @param j zero-based column index to modify; must be within {@code [0, columns)}
   * @param value new coefficient to store at the specified position
   */
  @Override
  public void setElement(int i, int j, double value) {
    super.setElement(i, j, value);
    permutations = null;
    evenPermutations = true;
    lower = null;
    upper = null;
  }

  /**
   * Add another square matrix to this instance in place.
   *
   * <p>Both matrices must share the same order; otherwise an {@link IllegalArgumentException} is
   * thrown. Coefficients from {@code s} are added element by element to this matrix, altering its
   * contents and clearing any cached LU factorization. The argument matrix remains unchanged. Use
   * this to accumulate multiple contributions without allocating intermediate matrices.
   *
   * @param s square matrix whose coefficients are added element-wise to this matrix
   * @exception IllegalArgumentException if the orders differ and addition would be undefined
   */
  public void selfAdd(SquareMatrix s) {

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
    for (int index = 0; index < rows * columns; ++index) {
      data[index] += s.data[index];
    }
  }

  /**
   * Subtract another square matrix from this instance in place.
   *
   * <p>Both matrices must have identical dimensions; otherwise an {@link IllegalArgumentException}
   * is raised. Elements from {@code s} are subtracted coefficient by coefficient, modifying this
   * matrix and invalidating any cached LU decomposition. The supplied matrix is not altered. This
   * method is useful when updating an existing system matrix without reallocating storage.
   *
   * @param s square matrix whose coefficients are removed element-wise from this matrix
   * @exception IllegalArgumentException if the orders differ and subtraction would be invalid
   */
  public void selfSub(SquareMatrix s) {

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
    for (int index = 0; index < rows * columns; ++index) {
      data[index] -= s.data[index];
    }
  }

  /**
   * Compute the determinant using a cached or freshly computed LU factorization.
   *
   * <p>If no factorization exists yet, the method performs LU decomposition with partial pivoting
   * using the supplied {@code epsilon} as the singularity threshold. When a previous computation is
   * available, it is reused unless the matrix has been mutated. A singular matrix triggers a {@link
   * SingularMatrixException} internally, which is converted to a {@code 0.0} determinant value to
   * signal failure while keeping the method signature simple.
   *
   * @param epsilon non-negative pivot threshold; values below it are considered numerically zero
   * @return determinant value; {@code 0.0} when the matrix is detected as singular or
   *     ill-conditioned
   */
  public double getDeterminant(double epsilon) {
    try {
      if (permutations == null) computeLUFactorization(epsilon);
      double d = upper.getDeterminant(epsilon);
      return evenPermutations ? d : -d;
    } catch (SingularMatrixException _) {
      return 0.0;
    }
  }

  /**
   * Solve the linear system {@code A · X = b} using LU decomposition with partial pivoting.
   *
   * <p>The right-hand side {@code b} must have the same number of rows as this matrix; otherwise an
   * {@link IllegalArgumentException} is thrown. The method computes (or reuses) the LU
   * factorization, applies the recorded row permutations to {@code b}, and performs forward then
   * back substitution to obtain the solution. The computation tolerates small pivots down to {@code
   * epsilon}; values below this threshold cause a {@link SingularMatrixException}. The returned
   * matrix has the same dimensions as {@code b}. The input matrix {@code b} remains unmodified.
   *
   * <pre>{@code
   * // Example: solve a 2x2 system
   * var a = MatrixFactory.buildSquareMatrix(2, new double[] {4, 1, 2, 3});
   * var b = MatrixFactory.buildMatrix(2, 1, new double[] {5, 5});
   * Matrix x = a.solve(b, 1.0e-12);
   * }</pre>
   *
   * @param b right-hand side matrix; row count must equal this matrix order
   * @param epsilon pivot threshold; values smaller than this denote singular or unstable systems
   * @return matrix {@code X} with identical row count to {@code b} and solution columns
   * @throws SingularMatrixException if the matrix is singular or ill-conditioned under {@code
   *     epsilon}
   * @throws IllegalArgumentException if {@code b} has a different number of rows
   */
  public Matrix solve(Matrix b, double epsilon) throws SingularMatrixException {
    // validity check
    if (b.getRows() != rows) {
      throw new IllegalArgumentException("dimension mismatch");
    }

    if (permutations == null) {
      computeLUFactorization(epsilon);
    }

    // apply the permutations to the second member
    double[] permData = new double[b.data.length];
    int bCols = b.getColumns();
    for (int i = 0; i < rows; ++i) {
      NonNullRange range = b.getRangeForRow(permutations[i]);
      if (range.end - range.begin >= 0)
        System.arraycopy(
            b.data,
            permutations[i] * bCols + range.begin,
            permData,
            i * bCols + range.begin,
            range.end - range.begin);
    }
    Matrix permB = MatrixFactory.buildMatrix(b.getRows(), bCols, permData);

    // solve the permuted system
    return upper.solve(lower.solve(permB, epsilon), epsilon);
  }

  /**
   * Return the inclusive range of non-zero columns for a given row.
   *
   * <p>The general matrix implementation assumes all columns may contain non-zero values, so the
   * returned range spans the full width of the matrix. Subclasses representing structured matrices
   * override this method to narrow iteration bounds and improve performance in generic algorithms.
   *
   * @param i zero-based row index whose populated column interval is requested
   * @return range object covering {@code [0, columns)} for dense matrices
   */
  protected NonNullRange getRangeForRow(int i) {
    return new NonNullRange(0, columns);
  }

  /**
   * Return the inclusive range of non-zero rows for a given column.
   *
   * <p>Like {@link #getRangeForRow(int)}, this dense implementation reports the entire column as
   * potentially populated. Structured subclasses can override to bound traversal for algorithms
   * that iterate only over non-null regions.
   *
   * @param j zero-based column index for which populated row bounds are requested
   * @return range object covering {@code [0, rows)} for dense matrices
   */
  protected NonNullRange getRangeForColumn(int j) {
    return new NonNullRange(0, rows);
  }

  private void computeLUFactorization(double epsilon) throws SingularMatrixException {
    // build a working copy of the matrix data
    double[] work = copyData();
    initializePermutations();

    for (int k = 0; k < rows; ++k) {
      pivotColumn(work, k, epsilon);
      eliminateBelowPivot(work, k);
    }

    buildTriangularMatrices(work);
  }

  private double[] copyData() {
    double[] work = new double[rows * columns];
    System.arraycopy(data, 0, work, 0, data.length);
    return work;
  }

  private void initializePermutations() {
    permutations = new int[rows];
    for (int i = 0; i < rows; ++i) {
      permutations[i] = i;
    }
    evenPermutations = true;
  }

  private void pivotColumn(double[] work, int k, double epsilon) throws SingularMatrixException {
    double maxElt = Math.abs(work[permutations[k] * columns + k]);
    int jMax = k;
    for (int i = k + 1; i < rows; ++i) {
      double curElt = Math.abs(work[permutations[i] * columns + k]);
      if (curElt > maxElt) {
        maxElt = curElt;
        jMax = i;
      }
    }

    if (maxElt < epsilon) {
      throw new SingularMatrixException();
    }

    if (k != jMax) {
      int tmp = permutations[k];
      permutations[k] = permutations[jMax];
      permutations[jMax] = tmp;
      evenPermutations = !evenPermutations;
    }
  }

  private void eliminateBelowPivot(double[] work, int k) {
    double inv = 1.0 / work[permutations[k] * columns + k];
    for (int i = k + 1; i < rows; ++i) {
      double factor = inv * work[permutations[i] * columns + k];
      work[permutations[i] * columns + k] = factor;

      int index1 = permutations[i] * columns + k;
      int index2 = permutations[k] * columns + k;
      for (int j = k + 1; j < columns; ++j) {
        work[++index1] -= factor * work[++index2];
      }
    }
  }

  private void buildTriangularMatrices(double[] work) {
    double[] lowerData = new double[rows * columns];
    double[] upperData = new double[rows * columns];

    int index = 0;
    for (int i = 0; i < rows; ++i) {
      int workIndex = permutations[i] * columns;
      int j = 0;

      while (j++ < i) {
        lowerData[index] = work[workIndex++];
        upperData[index++] = 0.0;
      }

      lowerData[index] = 1.0;
      upperData[index++] = work[workIndex++];

      while (j++ < columns) {
        lowerData[index] = 0.0;
        upperData[index++] = work[workIndex++];
      }
    }

    lower = new LowerTriangularMatrix(rows, lowerData);
    upper = new UpperTriangularMatrix(rows, upperData);
  }

  /**
   * Permutation vector recording row swaps applied during LU factorization; {@code null} until the
   * first decomposition is computed.
   */
  private int[] permutations;

  /**
   * Flag indicating whether the current permutation count is even, used to adjust determinant sign.
   */
  private boolean evenPermutations;

  /** Cached lower triangular matrix built from the LU factorization, or {@code null} if absent. */
  private LowerTriangularMatrix lower;

  /** Cached upper triangular matrix built from the LU factorization, or {@code null} if absent. */
  private UpperTriangularMatrix upper;

  @Serial private static final long serialVersionUID = -506293526695298279L;
}

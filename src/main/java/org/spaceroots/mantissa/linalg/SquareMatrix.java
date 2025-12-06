package org.spaceroots.mantissa.linalg;

/**
 * Abstract base for all square matrix implementations in the Mantissa linear algebra package.
 *
 * <p>Instances represent matrices that have the same number of rows and columns and therefore
 * support operations such as determinants, inverses, and linear system solving. Concrete subclasses
 * provide the storage strategy and factorization algorithms (for example LU or Cholesky), while
 * this class centralizes size handling and common entry points. Callers typically obtain a specific
 * implementation (dense or specialized) and rely on the square-specific methods defined here rather
 * than re‑implementing these algorithms on {@link Matrix}. Mutability follows the underlying {@code
 * Matrix} contract: construction produces a fully defined matrix whose contents may change through
 * subclass operations but whose order remains constant. Thread safety is not guaranteed;
 * synchronize externally when instances are shared across threads.
 *
 * <ul>
 *   <li>Responsibilities: expose determinant, inversion, and system solving hooks.
 *   <li>Invariants: identical row/column count, non-negative order, fixed dimension after creation.
 *   <li>Usage: create via subclass constructors or factory helpers, then call {@link
 *       #getDeterminant(double)} or {@link #solve(Matrix, double)} as needed.
 * </ul>
 *
 * @version $Id: SquareMatrix.java 1709 2006-12-03 21:16:50Z luc $
 * @author L. Maisonobe
 * @see Matrix
 */
public abstract class SquareMatrix extends Matrix {
  /**
   * Create an empty square matrix initialized with zeros in all positions.
   *
   * <p>The created instance has identical row and column counts equal to {@code order}; all element
   * slots are allocated but contain {@code 0.0}. Subclasses may later fill values or apply
   * factorization data, but the dimension remains fixed. Passing a negative or zero order is
   * rejected by the {@link Matrix} superclass constructor, which enforces the basic size
   * constraints used throughout the linear algebra utilities.
   *
   * @param order number of rows and columns; must be strictly positive to define a valid matrix
   */
  protected SquareMatrix(int order) {
    super(order, order);
  }

  /**
   * Create a square matrix populated from a flat array of elements.
   *
   * <p>Elements are read row by row from {@code data}; the array length must match {@code order *
   * order}. Values are copied into the internal storage defined by the {@link Matrix} superclass,
   * so later changes to {@code data} do not affect the matrix. This constructor is convenient when
   * importing coefficients from external computations while preserving the strict square shape that
   * many algorithms require.
   *
   * @param order number of rows and columns; validated to be positive by {@link Matrix}
   * @param data contiguous array of size {@code order * order} containing row-major coefficients
   */
  protected SquareMatrix(int order, double[] data) {
    super(order, order, data);
  }

  /**
   * Copy constructor cloning the content and dimensions of another square matrix.
   *
   * <p>The new instance mirrors the supplied matrix, including its numeric values and order, but it
   * remains independent thereafter; further modifications to either matrix do not affect the other.
   * Use this when callers need an isolated copy before performing destructive operations such as
   * factorization or row swapping.
   *
   * @param m matrix to copy; must be non-null and already square
   */
  protected SquareMatrix(SquareMatrix m) {
    super(m);
  }

  /**
   * Compute the determinant of this square matrix.
   *
   * <p>Subclasses typically implement this using a factorization (for example LU) that may treat
   * very small pivot values as numerical zeros. The {@code epsilon} parameter defines that cutoff,
   * enabling callers to tune sensitivity to near-singular matrices. Implementations should avoid
   * modifying the matrix unless documented otherwise; callers may prefer to operate on a copy when
   * factorization is destructive.
   *
   * @param epsilon non-negative threshold below which pivots are treated as zero during evaluation
   * @return the determinant value; {@code 0.0} when considered singular under the supplied
   *     threshold
   */
  public abstract double getDeterminant(double epsilon);

  /**
   * Create the inverse of this matrix using its own linear solver.
   *
   * <p>The default implementation delegates to {@link #solve(Matrix, double)} with an identity
   * right-hand side and therefore inherits the numeric stability and side effects of the concrete
   * solver. The call is expected to allocate a new {@link SquareMatrix} instance containing the
   * inverse coefficients; the current matrix remains unchanged unless a subclass documents in-place
   * factorization. Use a sufficiently large {@code epsilon} to avoid inverting matrices that are
   * effectively singular within application tolerances.
   *
   * @param epsilon non-negative tolerance used to detect singular or ill-conditioned matrices
   * @return a new square matrix representing the multiplicative inverse of this instance
   * @throws SingularMatrixException if no stable inverse exists under the supplied threshold
   */
  @SuppressWarnings("unused")
  public SquareMatrix getInverse(double epsilon) throws SingularMatrixException {
    return solve(new DiagonalMatrix(columns), epsilon);
  }

  /**
   * Solve the {@code A · X = B} linear system where {@code A} is this matrix.
   *
   * <p>Implementations typically perform a decomposition of {@code A} and then apply forward/back
   * substitution to compute {@code X}. The {@code epsilon} parameter defines when pivots are deemed
   * too small for a stable solution; failing that test triggers a {@link SingularMatrixException}.
   * The returned matrix has the same number of rows as {@code A} and matches the column count of
   * {@code B}. Callers should ensure that {@code B} has compatible dimensions, and may prefer to
   * supply a preallocated matrix when reuse is important.
   *
   * @param b right-hand side matrix; must have the same row count as this matrix and any column
   *     count
   * @param epsilon non-negative tolerance defining when pivots are treated as zero during solving
   * @return a matrix {@code X} satisfying {@code A · X = B} within the provided tolerance
   * @throws SingularMatrixException if decomposition detects a singular or near-singular matrix
   */
  public abstract Matrix solve(Matrix b, double epsilon) throws SingularMatrixException;

  /**
   * Solve the {@code A · X = B} system with a square right-hand side.
   *
   * <p>This convenience overload enforces that {@code B} is itself square and returns a {@link
   * SquareMatrix} result. It delegates to the general {@link #solve(Matrix, double)} implementation
   * and therefore shares its tolerance semantics and singularity detection behavior. Use this when
   * solving for square transformation matrices or when the caller requires the richer square-matrix
   * API on the result.
   *
   * @param b square right-hand side matrix sharing the same order as this instance
   * @param epsilon non-negative tolerance applied during factorization and singularity checks
   * @return a square matrix {@code X} such that {@code A · X = B} for this instance {@code A}
   * @throws SingularMatrixException if the solver deems the matrix singular within the threshold
   */
  public SquareMatrix solve(SquareMatrix b, double epsilon) throws SingularMatrixException {
    return (SquareMatrix) solve((Matrix) b, epsilon);
  }
}

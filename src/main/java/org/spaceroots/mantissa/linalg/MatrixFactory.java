package org.spaceroots.mantissa.linalg;

/**
 * Central factory that chooses concrete matrix implementations.
 *
 * <p>{@code MatrixFactory} inspects basic shape hints and sparsity counts to return an appropriate
 * {@link Matrix} subtype without forcing callers to know the full class hierarchy. It keeps the
 * decision surface deliberately small—square matrices may become diagonal, triangular, or general
 * depending on the number of reported non-null elements—so client code can remain agnostic to
 * storage details while still benefiting from specialized behaviors. Typical usage wraps raw data
 * loaded from an external source or produced by a computation that already knows how many elements
 * reside in each triangle. The factory never mutates input buffers and delegates all invariant
 * enforcement to the chosen concrete type.
 *
 * <p>The factory is stateless and thread-safe because all methods are pure functions that allocate
 * new matrix instances. It is best suited for boundary code that parses serialized matrices,
 * diagnostic routines that scan sparsity patterns, or algorithms that occasionally produce dense
 * rectangular blocks. Callers should still validate dimensions and sparsity metadata before
 * invoking the factory to ensure the selected subtype matches expectations; inconsistent counts
 * will simply lead to a less specialized type rather than throwing.
 *
 * <ul>
 *   <li>Responsibilities: map dimensions and non-null counts to concrete {@code Matrix} classes.
 *   <li>Notable behavior: prefers specialized square matrices when sparsity hints permit.
 *   <li>Thread safety: safe for concurrent use; no shared mutable state exists.
 * </ul>
 *
 * @version $Id: MatrixFactory.java 1666 2005-12-15 16:37:55Z luc $
 * @author L. Maisonobe
 * @see Matrix
 * @see GeneralMatrix
 * @see GeneralSquareMatrix
 * @see LowerTriangularMatrix
 * @see UpperTriangularMatrix
 * @see DiagonalMatrix
 */
public class MatrixFactory {
  /**
   * Simple constructor. Since the class is a utility class with only static methods, the
   * constructor is made private to prevent creating instances of this class.
   */
  private MatrixFactory() {}

  /**
   * Build a matrix whose concrete type matches supplied sparsity hints.
   *
   * <p>The method inspects the shape and the declared number of non-null coefficients in each
   * triangular portion to pick the most specific square-matrix implementation available. Square
   * inputs with no off-diagonal values become {@link DiagonalMatrix}; square inputs with only one
   * populated triangle become {@link UpperTriangularMatrix} or {@link LowerTriangularMatrix}; all
   * other square inputs become {@link GeneralSquareMatrix}. Rectangular matrices always produce
   * {@link GeneralMatrix}. The input array is not defensively copied; each concrete constructor
   * decides how to handle the provided storage.
   *
   * @param rows total row count; must be strictly positive and match {@code data.length / columns}
   * @param columns total column count; must be strictly positive and align with {@code data} layout
   * @param data coefficients stored row after row; may be shared or copied by the target type
   * @param lowerElements number of non-null entries on or below the main diagonal; zero implies an
   *     empty lower triangle
   * @param upperElements number of non-null entries on or above the main diagonal; zero implies an
   *     empty upper triangle
   * @return new matrix instance owning or referencing {@code data} according to the chosen subtype;
   *     caller retains the original reference
   */
  public static Matrix buildMatrix(
      int rows, int columns, double[] data, int lowerElements, int upperElements) {
    if (rows == columns) {
      if (lowerElements == 0 && upperElements == 0) {
        return new DiagonalMatrix(rows, data);
      } else if (lowerElements == 0) {
        return new UpperTriangularMatrix(rows, data);
      } else if (upperElements == 0) {
        return new LowerTriangularMatrix(rows, data);
      } else {
        return new GeneralSquareMatrix(rows, data);
      }
    }
    return new GeneralMatrix(rows, columns, data);
  }

  /**
   * Build a matrix based solely on its dimensions.
   *
   * <p>This overload disregards sparsity hints and therefore returns a {@link GeneralSquareMatrix}
   * for square shapes and a {@link GeneralMatrix} for rectangular shapes. Use it when no reliable
   * count of non-null coefficients is available or when dense storage is preferred for subsequent
   * operations. The {@code data} array is passed directly to the constructor of the selected class,
   * which may clone it; callers should not rely on shared ownership unless they inspect the
   * concrete implementation.
   *
   * @param rows positive number of rows describing the matrix height in the data layout
   * @param columns positive number of columns describing the matrix width in the data layout
   * @param data coefficients stored row-major; expected length {@code rows * columns} when not null
   * @return new general-purpose matrix whose type matches the shape; contents mirror {@code data}
   */
  public static Matrix buildMatrix(int rows, int columns, double[] data) {
    if (rows == columns) {
      return new GeneralSquareMatrix(rows, data);
    }
    return new GeneralMatrix(rows, columns, data);
  }
}

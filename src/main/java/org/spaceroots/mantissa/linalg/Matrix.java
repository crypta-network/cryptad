package org.spaceroots.mantissa.linalg;

import java.io.Serializable;
import java.util.Arrays;

/**
 * Common base for all matrix implementations, including general and square variants.
 *
 * <p>The class stores matrix coefficients in a single contiguous {@code double[]} buffer, exposes
 * read/write element accessors, and implements core linear-algebra operations such as addition,
 * subtraction, scalar multiplication, matrix multiplication, and transposition. Implementations
 * specializing shapes with structural zeros (for example triangular or diagonal matrices) should
 * override {@link #getRangeForRow(int)} and {@link #getRangeForColumn(int)} so the generic
 * algorithms can skip work outside the non-null ranges. The storage layout is row-major and uses
 * 0-based indices throughout the API.
 *
 * <p>Typical usage starts by constructing a concrete subclass (via {@link MatrixFactory}) and then
 * chaining operations that produce either new matrix instances or in-place updates, depending on
 * the method. Instances are mutable; callers must coordinate access if the same matrix is shared
 * across threads. The class guarantees that dimensions remain constant for the lifetime of an
 * instance and that all arithmetic preserves the matrix shape. Derived classes may enforce stronger
 * invariants but should respect the indexing and mutability expectations established here.
 *
 * <ul>
 *   <li>Responsibility: own the coefficient buffer and provide shape-aware arithmetic.
 *   <li>Performance: algorithms exploit non-null ranges to reduce iterations when structure is
 *       known.
 *   <li>Interoperability: produced instances are built through {@link MatrixFactory} to preserve
 *       structural hints.
 * </ul>
 *
 * @version $Id: Matrix.java 1709 2006-12-03 21:16:50Z luc $
 * @author L. Maisonobe
 * @see SquareMatrix
 * @see MatrixFactory
 */
public abstract class Matrix implements Serializable {
  /**
   * Blocks subclass finalizers so constructor failures cannot be exploited via finalizer attacks.
   *
   * <p>SpotBugs flags constructors that throw on non-final classes because subclasses could
   * otherwise define a finalizer and observe partially initialized state.
   */
  @Override
  @SuppressWarnings({"deprecation", "removal"})
  protected final void finalize() {}

  /**
   * Create a new matrix with all coefficients initialized to zero.
   *
   * <p>The constructor validates that both dimensions are strictly positive and allocates a dense
   * row-major buffer of size {@code rows * columns}. All elements are filled with {@code 0.0};
   * subclasses retain control over structural hints by overriding range methods. The instance is
   * mutable, but its shape is fixed after construction.
   *
   * <p>Because the data buffer is newly allocated for each instance, callers gain exclusive
   * ownership of its contents from the start. The matrix can therefore be safely populated through
   * {@link #setElement(int, int, double)} or other mutating operations without risk of affecting an
   * external buffer supplied at construction time.
   *
   * @param rows number of rows; must be greater than zero and expressed with 0-based indexing
   * @param columns number of columns; must be greater than zero and expressed with 0-based indexing
   * @throws IllegalArgumentException if either dimension is zero or negative
   */
  protected Matrix(int rows, int columns) {
    // sanity check
    if (rows <= 0 || columns <= 0) {
      throw new IllegalArgumentException(
          "cannot build a matrix" + " with negative or null dimension");
    }

    this.rows = rows;
    this.columns = columns;
    data = new double[rows * columns];
    Arrays.fill(data, 0.0);
  }

  /**
   * Create a new matrix with the provided coefficient buffer.
   *
   * <p>The supplied {@code data} array is expected to contain {@code rows * columns} entries laid
   * out row after row. The array is cloned to preserve encapsulation; callers keep ownership of the
   * original buffer. Dimensions must be strictly positive, and subclasses may rely on the stored
   * values to infer structure when exposing ranges.
   *
   * <p>The cloned buffer preserves the caller's values but prevents later external mutation from
   * leaking into the matrix. When {@code data} is {@code null}, the matrix records this fact
   * exactly; callers can later decide how to populate missing coefficients. Use this constructor
   * when importing arrays from interoperability layers where copying defensive data is necessary.
   *
   * @param rows number of rows; must be strictly positive and consistent with {@code data} length
   * @param columns number of columns; must be strictly positive and consistent with {@code data}
   *     length
   * @param data coefficient array in row-major order; {@code null} is accepted and preserved
   * @throws IllegalArgumentException if a dimension is zero or negative
   */
  protected Matrix(int rows, int columns, double[] data) {
    // sanity check
    if (rows <= 0 || columns <= 0) {
      throw new IllegalArgumentException(
          "cannot build a matrix" + " with negative or null dimension");
    }

    this.rows = rows;
    this.columns = columns;
    this.data = (data == null) ? null : data.clone();
  }

  /**
   * Copy constructor creating a deep copy of another matrix.
   *
   * <p>The new instance shares no mutable state with {@code m}; the underlying data buffer is
   * duplicated. Shape information (rows and columns) is preserved exactly, while subclasses remain
   * responsible for honoring their structural semantics when overriding range calculations.
   *
   * <p>Use this constructor inside subclass implementations of {@link #duplicate()} to ensure that
   * the new instance faithfully mirrors the original state. The operation is deterministic and
   * side-effect-free: neither the source nor the copy will be modified during cloning.
   *
   * @param m matrix to copy; must not be {@code null} and must be shape-compatible with this type
   */
  protected Matrix(Matrix m) {
    rows = m.rows;
    columns = m.columns;
    data = new double[rows * columns];
    System.arraycopy(m.data, 0, data, 0, m.data.length);
  }

  /**
   * Create a deep copy preserving the concrete runtime type.
   *
   * <p>Implementations must return a new matrix instance with identical dimensions and coefficient
   * values. The returned object should not share mutable state with the original, allowing callers
   * to perform independent modifications. Unlike {@link Object#clone()}, this method is always
   * public, does not throw checked exceptions, and promises a result typed as {@code Matrix}.
   *
   * <p>Implementations should copy structural hints as well as raw coefficient data so that factory
   * decisions remain consistent across clones. The operation is expected to be O(n) with respect to
   * the number of stored coefficients.
   *
   * @return new matrix instance of the same concrete subclass with identical size and contents
   */
  public abstract Matrix duplicate();

  /**
   * Get the number of rows.
   *
   * <p>The value is fixed at construction time and never decreases or increases. Consumers can rely
   * on this method to plan iteration bounds or to validate input indices before invoking
   * mutating/accessor methods. Because the matrix is mutable, callers should re-query the value
   * only if a different matrix instance could have been substituted, not because the count itself
   * might change.
   *
   * @return immutable row count for this matrix, expressed using 0-based indexing semantics
   * @see #getColumns()
   */
  public int getRows() {
    return rows;
  }

  /**
   * Get the number of columns.
   *
   * <p>The column count is an immutable characteristic of the matrix. It can be used to validate
   * column indices, to pre-size derived buffers, or to determine compatibility with other matrices
   * before performing operations such as multiplication or addition. The value does not change even
   * when elements are mutated.
   *
   * @return immutable column count for this matrix, expressed using 0-based indexing semantics
   * @see #getRows()
   */
  public int getColumns() {
    return columns;
  }

  /**
   * Read a single element from the matrix.
   *
   * <p>Indices are zero-based and validated against the fixed dimensions. No structural assumptions
   * are made about sparsity; the access reads directly from the dense backing buffer.
   *
   * <p>This method is O(1) and thread-safe only if external synchronization guards concurrent
   * writers. It does not normalize values or attempt to enforce structural invariants that a
   * subclass might expect; if the matrix stores guaranteed zeros outside declared ranges, callers
   * must still provide valid indices within bounds.
   *
   * @param i row index in {@code [0, getRows() - 1]}; any other value triggers an exception
   * @param j column index in {@code [0, getColumns() - 1]}; any other value triggers an exception
   * @return stored coefficient at the requested position; always a finite {@code double} value
   * @throws IllegalArgumentException if either index is outside the valid range
   * @see #setElement(int, int, double)
   */
  public double getElement(int i, int j) {
    if (i < 0 || i >= rows || j < 0 || j >= columns) {
      throw new IllegalArgumentException(
          "cannot get element (" + i + ", " + j + ") from a " + rows + 'x' + columns + " matrix");
    }
    return data[i * columns + j];
  }

  /**
   * Overwrite a single element in the matrix.
   *
   * <p>Indices are zero-based and validated; the assignment writes directly into the dense backing
   * buffer. Derived classes may rely on callers to preserve structural invariants when injecting
   * non-zero values outside the advertised ranges.
   *
   * <p>The method executes in O(1) time. No internal synchronization is provided; callers should
   * coordinate access when sharing matrices across threads. Storing values outside a row or column
   * non-null range is permitted but may defeat optimizations that rely on structural sparsity.
   *
   * @param i row index in {@code [0, getRows() - 1]} indicating which row to modify
   * @param j column index in {@code [0, getColumns() - 1]} indicating which column to modify
   * @param value coefficient to store at the specified position; any finite {@code double} accepted
   * @throws IllegalArgumentException if either index is outside the matrix dimensions
   * @see #getElement(int, int)
   */
  public void setElement(int i, int j, double value) {
    if (i < 0 || i >= rows || j < 0 || j >= columns) {
      throw new IllegalArgumentException(
          "cannot set element (" + i + ", " + j + ") in a " + rows + 'x' + columns + " matrix");
    }
    data[i * columns + j] = value;
  }

  /**
   * Add another matrix to this matrix and return the result.
   *
   * <p>Both matrices must share identical dimensions. The operation is purely functional: it leaves
   * the operands unchanged and returns a new instance whose concrete type is chosen by {@link
   * MatrixFactory} based on the resulting structure. The algorithm leverages range hints to skip
   * known-zero regions for efficiency and tracks how many off-diagonal elements are affected.
   *
   * <p>The returned matrix owns its own buffer; modifying it will not alter either operand. Range
   * information is recomputed so structural optimizations remain available to downstream
   * operations. Complexity is proportional to the number of coefficients considered non-zero in the
   * union of operand ranges.
   *
   * @param m matrix to add; must have the same number of rows and columns as this instance
   * @return newly allocated matrix holding the element-wise sum; caller owns the returned instance
   * @throws IllegalArgumentException if the operand dimensions differ from this matrix
   */
  public Matrix add(Matrix m) {

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

    double[] resultData = new double[rows * columns];
    int resultIndex = 0;
    int lowerElements = 0;
    int upperElements = 0;

    // external loop through the rows
    for (int i = 0; i < rows; ++i) {
      // compute the indices of the internal loop
      NonNullRange r = NonNullRange.reunion(getRangeForRow(i), m.getRangeForRow(i));

      // assign the zeros before the non-null range
      int j = 0;
      while (j < r.begin) {
        resultData[resultIndex] = 0.0;
        ++resultIndex;
        ++j;
      }

      // compute the possibly non-null elements
      while (j < r.end) {

        // compute the current element
        resultData[resultIndex] = data[resultIndex] + m.data[resultIndex];

        // count the affected upper and lower elements
        // (in order to deduce the shape of the resulting matrix)
        if (j < i) {
          ++lowerElements;
        } else if (i < j) {
          ++upperElements;
        }

        ++resultIndex;
        ++j;
      }

      // assign the zeros after the non-null range
      while (j < columns) {
        resultData[resultIndex++] = 0.0;
        ++resultIndex;
        ++j;
      }
    }

    return MatrixFactory.buildMatrix(rows, columns, resultData, lowerElements, upperElements);
  }

  /**
   * Subtract another matrix from this matrix and return the result.
   *
   * <p>Dimensions must match exactly. The method produces a new matrix through {@link
   * MatrixFactory} and leaves the operands untouched. Structural range hints guide the inner loops
   * and allow the factory to infer whether the result is, for example, lower or upper triangular by
   * counting affected elements.
   *
   * <p>The result owns its data buffer and is safe to mutate independently. Complexity is driven by
   * the union of the non-null row ranges of both operands; dense matrices will incur a full
   * iteration over all coefficients, whereas structured matrices skip guaranteed zeros.
   *
   * @param m matrix to subtract; must share this matrix's row and column counts
   * @return new matrix containing {@code this - m}; the caller is responsible for subsequent use
   * @throws IllegalArgumentException if the operand dimensions differ from this matrix
   */
  public Matrix sub(Matrix m) {

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

    double[] resultData = new double[rows * columns];
    int resultIndex = 0;
    int lowerElements = 0;
    int upperElements = 0;

    // external loop through the rows
    for (int i = 0; i < rows; ++i) {
      // compute the indices of the internal loop
      NonNullRange r = NonNullRange.reunion(getRangeForRow(i), m.getRangeForRow(i));

      // assign the zeros before the non-null range
      int j = 0;
      while (j < r.begin) {
        resultData[resultIndex] = 0.0;
        ++resultIndex;
        ++j;
      }

      // compute the possibly non-null elements
      while (j < r.end) {

        // compute the current element
        resultData[resultIndex] = data[resultIndex] - m.data[resultIndex];

        // count the affected upper and lower elements
        // (in order to deduce the shape of the resulting matrix)
        if (j < i) {
          ++lowerElements;
        } else if (i < j) {
          ++upperElements;
        }

        ++resultIndex;
        ++j;
      }

      // assign the zeros after the non-null range
      while (j < columns) {
        resultData[resultIndex++] = 0.0;
        ++resultIndex;
        ++j;
      }
    }

    return MatrixFactory.buildMatrix(rows, columns, resultData, lowerElements, upperElements);
  }

  /**
   * Multiply this matrix by another matrix and return the product.
   *
   * <p>The number of columns of this matrix must equal the number of rows of {@code m}. The method
   * allocates a new result through {@link MatrixFactory} and keeps both operands unchanged. It
   * intersects structural ranges to minimize multiplications on known-zero regions and tracks the
   * distribution of non-zero elements above and below the diagonal to preserve structural
   * optimizations in the resulting matrix.
   *
   * @param m right-hand matrix operand; must have {@code m.getRows() == getColumns()}
   * @return newly created matrix containing {@code this * m}; caller receives a dense, mutable copy
   * @throws IllegalArgumentException if the inner dimensions do not match
   */
  public Matrix mul(Matrix m) {

    // validity check
    if (columns != m.rows) {
      throw new IllegalArgumentException(
          "cannot multiply a "
              + rows
              + 'x'
              + columns
              + " matrix by a "
              + m.rows
              + 'x'
              + m.columns
              + " matrix");
    }

    double[] resultData = new double[rows * m.columns];
    int resultIndex = 0;
    int lowerElements = 0;
    int upperElements = 0;

    for (int i = 0; i < rows; ++i) {
      for (int j = 0; j < m.columns; ++j) {
        NonNullRange range = NonNullRange.intersection(getRangeForRow(i), m.getRangeForColumn(j));
        boolean hasValues = range.begin < range.end;
        double value = hasValues ? computeProduct(m, i, j, range) : 0.0;

        if (hasValues) {
          // count the affected upper and lower elements (in order to deduce the shape of the
          // resulting matrix)
          if (j < i) {
            ++lowerElements;
          } else if (i < j) {
            ++upperElements;
          }
        }

        // store the element value
        resultData[resultIndex++] = value;
      }
    }

    return MatrixFactory.buildMatrix(rows, m.columns, resultData, lowerElements, upperElements);
  }

  /**
   * Multiply this matrix by a scalar, producing a new matrix.
   *
   * <p>The operation leaves the current instance unchanged by delegating to {@link
   * #selfMul(double)} on a cloned copy. Structural hints remain intact in the returned matrix.
   * Computation is linear in the number of stored coefficients and suitable for quick scaling of
   * intermediate results without mutating shared state.
   *
   * @param a scalar factor to apply to every element; any finite {@code double} is accepted
   * @return new matrix whose coefficients equal {@code this[i,j] * a}; ownership is transferred to
   *     the caller
   * @see #selfMul(double)
   */
  public Matrix mul(double a) {
    Matrix copy = duplicate();
    copy.selfMul(a);
    return copy;
  }

  /**
   * Multiply this matrix by a scalar in place.
   *
   * <p>The operation scales only the coefficients that lie within the non-null ranges reported for
   * each row, leaving guaranteed structural zeros untouched. Callers should ensure exclusive access
   * if the matrix is shared across threads, as the mutation updates the backing buffer directly.
   *
   * @param a scalar factor applied to all stored coefficients within each row's active range
   * @see #mul(double)
   */
  public void selfMul(double a) {
    for (int i = 0; i < rows; ++i) {
      NonNullRange r = getRangeForRow(i);
      for (int j = r.begin, index = i * columns + r.begin; j < r.end; ++j, ++index) {
        data[index] *= a;
      }
    }
  }

  /**
   * Compute and return the transpose of this matrix.
   *
   * <p>The operation allocates a new matrix of dimensions {@code columns x rows} populated by
   * swapping row and column indices. Structural metadata is recomputed by counting upper and lower
   * elements as the result is built. The original matrix remains unchanged.
   *
   * <p>Computation respects structural hints from {@link #getRangeForColumn(int)} to avoid needless
   * work in zero regions. The resulting matrix type is selected by {@link MatrixFactory} so that
   * structural properties (for example triangularity) are preserved whenever possible.
   *
   * @return freshly allocated transpose of this matrix; size is {@code getColumns() x getRows()}
   */
  @SuppressWarnings("unused")
  public Matrix getTranspose() {

    double[] resultData = new double[columns * rows];
    int resultIndex = 0;
    int upperElements = 0;
    int lowerElements = 0;

    for (int i = 0; i < columns; ++i) {
      // compute the indices of the internal loop
      NonNullRange range = getRangeForColumn(i);

      int j = 0;
      int index = i;

      // assign the zeros before the non-null range
      while (j < range.begin) {
        resultData[resultIndex++] = 0.0;
        index += columns;
        ++j;
      }

      // compute the possibly non-null elements
      while (j < range.end) {
        resultData[resultIndex] = data[index];

        // count the affected upper and lower elements
        // (in order to deduce the shape of the resulting matrix)
        if (j < i) {
          ++lowerElements;
        } else if (i < j) {
          ++upperElements;
        }

        index += columns;
        ++resultIndex;
        ++j;
      }

      // assign the zeros after the non-null range
      while (j < rows) {
        resultData[resultIndex] = 0.0;
        ++resultIndex;
        ++j;
      }
    }

    return MatrixFactory.buildMatrix(columns, rows, resultData, lowerElements, upperElements);
  }

  /**
   * Describe the contiguous non-null range for a given row.
   *
   * <p>Implementations should return a range whose {@code begin} and {@code end} delimit the
   * portion of the row that may contain meaningful coefficients based on structural knowledge (not
   * necessarily on current values). The range is half-open: {@code begin} is inclusive and {@code
   * end} exclusive, and it must satisfy {@code 0 <= begin <= end <= getColumns()}.
   *
   * <p>Implementations should compute this quickly because it is invoked inside tight loops. The
   * method must be side-effect free and should never return {@code null}. Returning minimal ranges
   * improves performance when working with sparse or structured matrices.
   *
   * @param i row index for which to retrieve structural bounds; must be within matrix dimensions
   * @return {@link NonNullRange} describing the inclusive/exclusive bounds of potential non-zero
   *     elements in the row
   * @see #getRangeForColumn(int)
   */
  protected abstract NonNullRange getRangeForRow(int i);

  /**
   * Describe the contiguous non-null range for a given column.
   *
   * <p>Implementations should return bounds that reflect structural expectations for the column,
   * enabling algorithms to skip known-zero regions. The range is half-open and must honor matrix
   * dimensions.
   *
   * <p>Like {@link #getRangeForRow(int)}, this method should be lightweight and deterministic. It
   * is queried frequently by multiplication and transposition routines and should never return
   * {@code null}. The caller treats returned bounds as trusted hints for loop trimming.
   *
   * @param j column index for which to retrieve structural bounds; must satisfy {@code 0 <= j <
   *     getColumns()}
   * @return {@link NonNullRange} identifying the inclusive start and exclusive end of potentially
   *     non-zero elements in the column
   * @see #getRangeForRow(int)
   */
  protected abstract NonNullRange getRangeForColumn(int j);

  /**
   * Render the matrix as a line-separated, space-delimited string.
   *
   * <p>Elements are emitted row by row, with columns separated by single spaces and rows separated
   * by the platform line separator. The representation is intended for debugging and logging rather
   * than for serialization; callers should not rely on it for stable parsing across locales.
   *
   * @return textual view of the matrix coefficients in row-major order
   */
  @Override
  public String toString() {
    String separator = System.lineSeparator();

    StringBuilder buf = new StringBuilder();
    for (int index = 0; index < rows * columns; ++index) {
      if (index > 0) {
        if (index % columns == 0) {
          buf.append(separator);
        } else {
          buf.append(' ');
        }
      }
      buf.append(data[index]);
    }

    return buf.toString();
  }

  /**
   * Compute one entry of a matrix product within the provided range.
   *
   * <p>This helper assumes {@code range} describes the overlapping non-null portion of the row of
   * {@code this} and the column of {@code m}. It multiplies aligned coefficients and accumulates
   * the result without applying structural checks. Callers are responsible for ensuring dimensional
   * compatibility and that {@code range.begin < range.end} when invoking the method.
   *
   * @param m right-hand operand supplying column coefficients; must share the implied inner size
   * @param row row index of the left operand whose coefficients are used for the product
   * @param column column index of the right operand participating in the product
   * @param range intersection bounds identifying valid multiplier positions for this entry
   * @return accumulated dot product over the specified range; equals zero if the range is empty
   */
  private double computeProduct(Matrix m, int row, int column, NonNullRange range) {
    double value = 0.0;
    int k = range.begin;
    int idx = row * columns + k;
    int midx = k * m.columns + column;
    while (k++ < range.end) {
      value += data[idx++] * m.data[midx];
      midx += m.columns;
    }
    return value;
  }

  /**
   * Total number of rows in this matrix; established at construction time and never changes. The
   * value underpins all index validation and is used by range-computation helpers to define legal
   * bounds for callers.
   */
  protected final int rows;

  /**
   * Total number of columns in this matrix; established at construction time and never changes. The
   * value informs multiplication compatibility checks and bounds validation for column-oriented
   * operations.
   */
  protected final int columns;

  /**
   * Dense row-major storage for all matrix coefficients; length is {@code rows * columns} and
   * indices are derived from 0-based row and column positions. The buffer is always allocated by
   * constructors or clone logic and is never shared with external callers.
   */
  protected final double[] data;
}

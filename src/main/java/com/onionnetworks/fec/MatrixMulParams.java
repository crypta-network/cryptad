package com.onionnetworks.fec;

import org.jetbrains.annotations.NotNull;

/**
 * Holds the inputs for a finite-field matrix multiplication over sliced buffers.
 *
 * <p>This class packages three row-major matrix buffers and their starting offsets together with
 * the {@code n x k} by {@code k x m} dimensions that define the multiplication. It is intended for
 * callers that want to pass a single object into matrix multiplication routines instead of a long
 * list of parameters. The instance stores the caller-provided arrays and offsets directly and does
 * not perform any copying or validation.
 *
 * <p>Instances are immutable in terms of reference identity, but the referenced arrays are mutable
 * and are not defensively copied. If the arrays are changed concurrently, all derived behavior (for
 * example, equality, hash codes, and debug output) can change as well. When arrays are treated as
 * stable inputs for the duration of the call, the object is safe to share across threads.
 *
 * <ul>
 *   <li>Groups three matrix slices and their multiplication dimensions.
 *   <li>Represents buffers as-is without bounds checking or normalization.
 *   <li>Compares array contents in {@link #equals(Object)} and {@link #hashCode()}.
 * </ul>
 */
public final class MatrixMulParams {
  private final char[] a;
  private final int aStart;
  private final char[] b;
  private final int bStart;
  private final char[] c;
  private final int cStart;
  private final int n;
  private final int k;
  private final int m;

  /**
   * Creates a parameter bundle for matrix multiplication slices.
   *
   * <p>The provided slices are stored by reference and are assumed to point at row-major blocks of
   * matrices sized according to the supplied dimensions. This constructor does not validate array
   * bounds, nullability, or dimensional consistency. It is the caller's responsibility to ensure
   * that each slice has enough backing capacity for the multiplication and that the dimensions
   * represent the intended {@code n x k} by {@code k x m} operation.
   *
   * @param a slice for the left matrix; must reference a row-major {@code n x k} block
   * @param b slice for the right matrix; must reference a row-major {@code k x m} block
   * @param c slice for the destination; must reference a row-major {@code n x m} block
   * @param dimensions multiplication dimensions describing {@code n}, {@code k}, and {@code m}
   */
  public MatrixMulParams(
      MatrixSlice a, MatrixSlice b, MatrixSlice c, MatrixMulDimensions dimensions) {
    this.a = a.data();
    this.aStart = a.start();
    this.b = b.data();
    this.bStart = b.start();
    this.c = c.data();
    this.cStart = c.start();
    this.n = dimensions.n();
    this.k = dimensions.k();
    this.m = dimensions.m();
  }

  /**
   * Returns the backing array for the left matrix slice.
   *
   * <p>The returned array reference is the same object provided by the caller when this instance
   * was created. It is not copied or wrapped, so further mutations to the array will be observed by
   * any consumer of this object. Treat the returned buffer as read-only for predictable equality
   * and to avoid altering matrix multiplication results in flight.
   *
   * @return the left matrix buffer reference, not copied or normalized
   */
  public char[] a() {
    return a;
  }

  /**
   * Returns the starting offset within {@link #a()} for the left matrix slice.
   *
   * <p>The offset is expressed as a zero-based index into the backing array and is applied to the
   * row-major {@code n x k} block. No bounds checking is performed when using this value, so it is
   * the caller's responsibility to ensure it points at a valid location with sufficient capacity.
   *
   * @return zero-based offset into the left matrix buffer
   */
  public int aStart() {
    return aStart;
  }

  /**
   * Returns the backing array for the right matrix slice.
   *
   * <p>The returned array reference is the same object supplied during construction and is not
   * cloned. Changes to the array contents will be reflected in any computation that uses this
   * instance. For stable behavior, callers should avoid mutating the array while it is in use.
   *
   * @return the right matrix buffer reference, not copied or transformed
   */
  public char[] b() {
    return b;
  }

  /**
   * Returns the starting offset within {@link #b()} for the right matrix slice.
   *
   * <p>The offset is a zero-based index into the buffer representing the {@code k x m} block. It is
   * used by matrix multiplication routines to locate the first element of the slice in row-major
   * order. No validation is performed, so callers must ensure the offset and buffer are valid.
   *
   * @return zero-based offset into the right matrix buffer
   */
  public int bStart() {
    return bStart;
  }

  /**
   * Returns the backing array for the destination matrix slice.
   *
   * <p>The returned array reference is the caller-provided destination buffer where multiplication
   * results are written. The array is not copied or cleared by this class. If the buffer is shared
   * with other operations, ensure appropriate coordination to avoid unintended overwrites.
   *
   * @return the destination matrix buffer reference, not copied or initialized
   */
  public char[] c() {
    return c;
  }

  /**
   * Returns the starting offset within {@link #c()} for the destination matrix slice.
   *
   * <p>The offset is a zero-based index into the destination buffer and points at the first element
   * of the {@code n x m} output block in row-major order. The value is used as-is without bounds
   * checks or normalization, so it must be consistent with the destination buffer's length.
   *
   * @return zero-based offset into the destination matrix buffer
   */
  public int cStart() {
    return cStart;
  }

  /**
   * Returns the number of rows in the left matrix and the output matrix.
   *
   * <p>This dimension corresponds to the {@code n} in the {@code n x k} by {@code k x m}
   * multiplication. The value is stored verbatim without validation and is used to determine the
   * row count for traversal of the left slice and the output slice in row-major order.
   *
   * @return row count for the left matrix and output matrix
   */
  public int n() {
    return n;
  }

  /**
   * Returns the shared inner dimension for the multiplication.
   *
   * <p>This dimension corresponds to the {@code k} in the {@code n x k} by {@code k x m}
   * multiplication and represents the number of columns in the left matrix and the number of rows
   * in the right matrix. The value is stored as provided and is not validated against buffer sizes.
   *
   * @return shared inner dimension of the multiplication
   */
  public int k() {
    return k;
  }

  /**
   * Returns the number of columns in the right matrix and the output matrix.
   *
   * <p>This dimension corresponds to the {@code m} in the {@code n x k} by {@code k x m}
   * multiplication. It controls the column count for the right-hand slice and the output slice in
   * row-major order. The value is used as-is without range checks or normalization.
   *
   * @return column count for the right matrix and output matrix
   */
  public int m() {
    return m;
  }

  /**
   * Compares this parameter bundle to another object for structural equality.
   *
   * <p>Equality is defined by comparing the contents of the three backing arrays, the three start
   * offsets, and the three-dimension values. Because arrays are compared by contents rather than
   * identity, this operation can be relatively expensive for large buffers. If any of the arrays
   * are mutated after construction, the equality relation can change over time.
   *
   * @param obj candidate object to compare against; may be {@code null}
   * @return {@code true} when the other object represents the same parameter set
   */
  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (!(obj instanceof MatrixMulParams other)) {
      return false;
    }
    return java.util.Arrays.equals(a, other.a)
        && aStart == other.aStart
        && java.util.Arrays.equals(b, other.b)
        && bStart == other.bStart
        && java.util.Arrays.equals(c, other.c)
        && cStart == other.cStart
        && n == other.n
        && k == other.k
        && m == other.m;
  }

  /**
   * Computes a hash code consistent with {@link #equals(Object)}.
   *
   * <p>The hash code is derived from the contents of the three backing arrays, the start offsets,
   * and the dimension values. Because array contents participate in the hash, computing the value
   * can be relatively expensive and is sensitive to mutations of the arrays after construction. For
   * predictable hashing behavior, avoid modifying the buffers once shared in hashed collections.
   *
   * @return hash code representing the current parameter values
   */
  @Override
  public int hashCode() {
    int result = java.util.Arrays.hashCode(a);
    result = 31 * result + Integer.hashCode(aStart);
    result = 31 * result + java.util.Arrays.hashCode(b);
    result = 31 * result + Integer.hashCode(bStart);
    result = 31 * result + java.util.Arrays.hashCode(c);
    result = 31 * result + Integer.hashCode(cStart);
    result = 31 * result + Integer.hashCode(n);
    result = 31 * result + Integer.hashCode(k);
    result = 31 * result + Integer.hashCode(m);
    return result;
  }

  /**
   * Returns a debug-oriented string representation of this parameter bundle.
   *
   * <p>The string includes {@link java.util.Arrays#toString(char[])} output for each backing array
   * along with the stored offsets and dimensions. This makes the output potentially large and
   * sensitive to changes if the arrays are mutated after construction. Use this representation for
   * diagnostics rather than for stable identifiers or logging of very large buffers.
   *
   * @return a string describing arrays, offsets, and dimensions
   */
  @Override
  public @NotNull String toString() {
    return "MatrixMulParams{"
        + "a="
        + java.util.Arrays.toString(a)
        + ", aStart="
        + aStart
        + ", b="
        + java.util.Arrays.toString(b)
        + ", bStart="
        + bStart
        + ", c="
        + java.util.Arrays.toString(c)
        + ", cStart="
        + cStart
        + ", n="
        + n
        + ", k="
        + k
        + ", m="
        + m
        + '}';
  }
}

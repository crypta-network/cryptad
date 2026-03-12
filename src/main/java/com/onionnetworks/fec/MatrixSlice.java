package com.onionnetworks.fec;

import java.util.Arrays;
import org.jetbrains.annotations.NotNull;

/**
 * Represents a view into a row-major matrix buffer with a starting offset.
 *
 * <p>This class groups a backing {@code char[]} buffer with a zero-based start index that marks
 * where a matrix block begins. It is typically used to reference submatrices that live inside
 * larger buffers without allocating or copying. The instance stores the array reference as-is and
 * does not validate bounds, dimensions, or content.
 *
 * <p>The slice is immutable with respect to its fields, but the referenced array remains mutable
 * and is not defensively copied. Any concurrent modifications to the buffer can change observable
 * behavior, including equality, hash codes, and string output. When the underlying array is treated
 * as stable for the duration of use, the object is safe to share between threads.
 *
 * <ul>
 *   <li>Packages a backing buffer and a start offset for row-major data.
 *   <li>Avoids allocations by reusing caller-provided arrays.
 *   <li>Defers all bounds and size validation to the caller.
 * </ul>
 *
 * @see MatrixMulParams
 */
@SuppressWarnings({"ClassCanBeRecord", "java:S6206"})
public final class MatrixSlice {
  private final char[] data;
  private final int start;

  /**
   * Creates a slice into a matrix buffer.
   *
   * <p>The provided array is stored by reference, and the start offset is treated as a zero-based
   * index into that array. This constructor does not check for {@code null}, negative offsets, or
   * sufficient remaining capacity for any particular matrix dimensions. Callers are responsible for
   * ensuring the slice is meaningful and consistent with the expected row-major layout.
   *
   * @param data backing array for the matrix buffer; stored by reference and not copied
   * @param start zero-based offset where the matrix block begins in {@code data}
   */
  public MatrixSlice(char[] data, int start) {
    this.data = data;
    this.start = start;
  }

  /**
   * Returns the backing array for this slice.
   *
   * <p>The returned array is the exact reference supplied at construction time. It is not cloned or
   * wrapped, so any modifications are visible to all users of this slice. For predictable behavior
   * in equality and hashing, treat the buffer as read-only while the slice is in use.
   *
   * @return the backing buffer reference for the slice, not copied or normalized
   */
  public char[] data() {
    return data;
  }

  /**
   * Returns the zero-based start offset into {@link #data()}.
   *
   * <p>The offset indicates where the matrix block begins in the row-major buffer. It is
   * interpreted as a simple index and is not validated for bounds or consistency with any implied
   * dimensions. Use the value in combination with the caller's matrix size information to locate
   * elements.
   *
   * @return zero-based offset into the backing buffer
   */
  public int start() {
    return start;
  }

  /**
   * Compares this slice with another object for structural equality.
   *
   * <p>Equality is defined by comparing the contents of the backing array and the start offset.
   * This comparison can be expensive for large arrays because it examines all elements. If the
   * buffer is mutated after construction, the equality relationship may change over time.
   *
   * @param obj candidate object to compare against; may be {@code null}
   * @return {@code true} when the other object represents the same slice contents and offset
   */
  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (!(obj instanceof MatrixSlice other)) {
      return false;
    }
    return Arrays.equals(data, other.data) && start == other.start;
  }

  /**
   * Computes a hash code consistent with {@link #equals(Object)}.
   *
   * <p>The hash code is derived from the contents of the backing array and the start offset.
   * Because array contents are included, this method may be relatively expensive and is sensitive
   * to buffer mutations. For stable hashing, avoid modifying the underlying array while it is used
   * as a key.
   *
   * @return hash code for the current slice contents and offset
   */
  @Override
  public int hashCode() {
    int result = Arrays.hashCode(data);
    result = 31 * result + Integer.hashCode(start);
    return result;
  }

  /**
   * Returns a debug-oriented string representation of this slice.
   *
   * <p>The string includes a {@link Arrays#toString(char[])} representation of the entire backing
   * array and the start offset. This can be large for big buffers and should be used primarily for
   * diagnostics rather than for stable identifiers or high-volume logging.
   *
   * @return a string describing the buffer contents and start offset
   */
  @Override
  public @NotNull String toString() {
    return "MatrixSlice{" + "data=" + Arrays.toString(data) + ", start=" + start + '}';
  }
}

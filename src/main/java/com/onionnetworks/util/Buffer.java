// (c) Copyright 2000 Justin F. Chapweske
// (c) Copyright 2000 Ry4an C. Brase

package com.onionnetworks.util;

/**
 * Represents a lightweight, immutable view over a byte array segment.
 *
 * <p>A {@code Buffer} couples an underlying {@link #b byte array}, an offset, and a length so that
 * callers can pass contiguous byte regions around without copying. The class is intentionally
 * minimal: it exposes the backing array for high-performance code that wants to reuse large
 * buffers, while providing helper utilities such as deep equality, deterministic hashing, and a
 * defensive copy via {@link #getBytes()}. Instances are value objects whose fields never change
 * after construction, which makes them safe to share between threads as long as the backing array
 * is not mutated externally.
 *
 * <p>Typical usage patterns include batching network payloads, slicing reusable scratch buffers, or
 * representing decoded frames before higher-level parsing. The constructor that accepts an existing
 * array avoids allocations, whereas the single-argument constructor allocates a fresh zeroed array
 * of the requested capacity. Offsets and lengths are validated to prevent accidental overreads or
 * overwrites of the provided array segment. Because the backing array is exposed, callers should
 * avoid mutating it once shared unless all consumers agree on those mutations.
 *
 * <ul>
 *   <li>Fields are final, enabling cheap transport and safe publication.
 *   <li>Equality and hashing operate only on the visible slice, not unused capacity.
 *   <li>{@link #getBytes()} returns a defensive copy for APIs that require owned storage.
 * </ul>
 *
 * @author Justin F. Chapweske
 * @see java.nio.ByteBuffer
 */
public class Buffer {

  /**
   * Backing byte array that stores the bytes for this buffer view. The array may contain additional
   * data outside the slice denoted by {@link #off} and {@link #len}; callers that share instances
   * should avoid mutating the referenced array to keep views consistent across threads.
   */
  public final byte[] b;

  /**
   * Zero-based index of the first byte in {@link #b} that belongs to this logical buffer slice.
   * Always non-negative and validated against {@link #b} during construction to prevent overflow
   * when computing {@code off + len}.
   */
  public final int off;

  /**
   * Number of readable bytes in this buffer slice. The value is validated on construction so that
   * {@code off + len} does not exceed {@link #b}'s length. The slice is read-only by convention;
   * mutations to {@link #b} reflect here immediately.
   */
  public final int len;

  /**
   * Constructs a new buffer that owns a freshly allocated byte array of the specified length.
   *
   * <p>The resulting slice spans the full array with offset {@code 0}. The array elements are
   * zero-initialized as per the Java memory model. Use this factory when you need an isolated
   * buffer that will not share storage with other views. Supplying a negative length will cause the
   * array allocation itself to throw {@link NegativeArraySizeException}.
   *
   * @param len desired capacity in bytes for the new backing array; must be non-negative
   */
  public Buffer(int len) {
    this(new byte[len]);
  }

  /**
   * Constructs a buffer view that spans the entire provided byte array without copying it.
   *
   * <p>This overload is allocation-free and preserves any existing contents of {@code b}. The
   * resulting slice starts at offset {@code 0} and uses {@code b.length} bytes. Callers retain
   * ownership of the array and must manage concurrent mutations themselves; changes to the array
   * will be visible through this buffer.
   *
   * @param b backing array to wrap; must be non-null and remains caller-owned after construction
   */
  public Buffer(byte[] b) {
    this(b, 0, b.length);
  }

  /**
   * Constructs a buffer view over a specific contiguous range of the provided array.
   *
   * <p>The constructor validates that {@code off} and {@code len} describe a region fully contained
   * within {@code b}. No data is copied. This is the most flexible entry point for reusing pooled
   * buffers, slicing messages, or exposing subranges to downstream code without allocation. Any
   * mutation to {@code b} inside the defined slice is immediately reflected to readers of this
   * buffer, so coordinate writes carefully in multithreaded scenarios.
   *
   * @param b backing array to wrap; must be non-null and will not be copied
   * @param off starting index within {@code b}; must be zero or positive and within array bounds
   * @param len number of bytes from {@code b} to expose; must be zero or positive and stay in range
   * @throws ArrayIndexOutOfBoundsException if {@code off} or {@code len} describe an invalid slice
   */
  public Buffer(byte[] b, int off, int len) {
    if (len < 0 || off < 0 || off + len > b.length) {
      throw new ArrayIndexOutOfBoundsException(
          "b.length=" + b.length + ",off=" + off + ",len=" + len);
    }

    this.b = b;
    this.off = off;
    this.len = len;
  }

  /**
   * Creates and returns a defensive copy of the visible slice represented by this buffer.
   *
   * <p>The returned array is always of length {@link #len} and starts at offset {@link #off}. This
   * method allocates a new array and copies bytes via {@link System#arraycopy(Object, int, Object,
   * int, int)}, so prefer it only when an owning or immutable view is required by downstream APIs.
   * The backing array of this buffer is never exposed through the returned value.
   *
   * @return newly allocated array containing exactly {@link #len} bytes from offset {@link #off}
   */
  public byte[] getBytes() {
    byte[] retval = new byte[len];
    System.arraycopy(b, off, retval, 0, len);
    return retval;
  }

  /**
   * Compares this buffer to another object for deep, slice-aware equality.
   *
   * <p>The comparison succeeds only when the other object is also a {@code Buffer} with the same
   * {@link #len length} and identical byte values across the visible range starting at each
   * buffer's offset. Backing array identity is ignored; two views into different arrays are equal
   * if their exposed slices contain the same bytes. Comparison runs in {@code O(len)} time.
   *
   * @param o candidate object to compare; equality is considered only for {@code Buffer} instances
   * @return {@code true} when both buffers expose slices of equal length containing identical bytes
   */
  @Override
  public boolean equals(Object o) {
    if (o instanceof Buffer buf) {
      if (buf.len != len) {
        return false;
      }
      for (int i = 0; i < len; i++) {
        if (buf.b[buf.off + i] != b[off + i]) {
          return false;
        }
      }
      return true;
    } else {
      return false;
    }
  }

  /**
   * Computes a hash code based on the bytes within the exposed slice of this buffer.
   *
   * <p>The algorithm mirrors the standard array hash pattern, iterating from {@link #off} for
   * {@link #len} bytes and multiplying by 31 to balance distribution. Only the readable range is
   * considered; unused capacity in {@link #b} does not influence the result. The method is
   * consistent with {@link #equals(Object)} for buffers that view the same byte contents.
   *
   * @return hash code derived solely from bytes in the slice defined by {@link #off} and {@link
   *     #len}
   */
  @Override
  public int hashCode() {
    int result = 1;
    for (int i = 0; i < len; i++) {
      result = 31 * result + b[off + i];
    }
    return result;
  }

  /**
   * Returns a human-readable representation of this buffer including offset, length, and contents.
   *
   * <p>The string lists each byte value in the slice in index order, which is helpful for
   * diagnostics but may be verbose for large buffers. The backing array is not copied; only numeric
   * values are included. This method is intended for debugging and should not be used for parsing
   * or serialization.
   *
   * @return descriptive string showing length, offset, and byte values within the visible range
   */
  @Override
  public String toString() {
    StringBuilder rep =
        new StringBuilder("Buffer{length: ")
            .append(len)
            .append("; offset: ")
            .append(off)
            .append("; ");
    for (int i = off; i < off + len; i++) {
      rep.append(i).append(": ").append(b[i]);
      if (i != off + len - 1) {
        rep.append(", ");
      }
    }
    rep.append("}");
    return rep.toString();
  }
}

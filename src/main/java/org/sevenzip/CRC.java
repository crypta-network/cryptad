// SevenZip/CRC.java

package org.sevenzip;

/**
 * CRC-32 calculator using the standard reversed polynomial {@code 0xEDB88320}.
 *
 * <p>This mutable helper accumulates checksum state over a sequence of bytes and produces the
 * finalized digest on demand. Typical usage creates one instance, invokes {@link #init()} to reset
 * the internal accumulator to the initial inverted value, feeds one or more chunks through {@link
 * #update(byte[], int, int)}, {@link #update(byte[])}, or {@link #updateByte(int)}, and finally
 * calls {@link #getDigest()} to retrieve the 32-bit CRC-32 value in the usual non-inverted form.
 * The instance is reusable across payloads by calling {@link #init()} between runs; doing so is
 * cheaper than creating new objects because the precomputed lookup table is shared.
 *
 * <p>State is not thread-safe: concurrent updates on the same instance will race and corrupt the
 * intermediate accumulator. Multiple threads should either synchronize externally or use distinct
 * {@code CRC} instances. The lookup table is immutable and safe for concurrent reads, so many
 * instances can operate in parallel without contention.
 *
 * <ul>
 *   <li>Computes the same result as {@link java.util.zip.CRC32} for identical input streams.
 *   <li>Supports incremental feeding of arbitrarily sized slices, including zero-length segments,
 *       without resetting.
 *   <li>Exposes only the finalized digest; callers should not rely on the internal {@code value}
 *       field, which remains inverted during accumulation.
 * </ul>
 *
 * @see java.util.zip.CRC32
 */
public class CRC {
  // Lookup table for the CRC-32 calculation.
  private static final int[] table = new int[256];

  static {
    for (int i = 0; i < 256; i++) {
      int r = i;
      for (int j = 0; j < 8; j++)
        if ((r & 1) != 0) r = (r >>> 1) ^ 0xEDB88320;
        else r >>>= 1;
      table[i] = r;
    }
  }

  // Current CRC value (bitwise-inverted working form as per standard implementation).
  int value = -1;

  /**
   * Create a new CRC calculator with the accumulator primed to the initial inverted value.
   *
   * <p>The constructor performs no allocation beyond the instance itself; the shared lookup table
   * is initialized eagerly in the class initializer. Callers may reuse a single instance across
   * multiple payloads by invoking {@link #init()} before starting each new calculation. Instances
   * are lightweight and safe to create per request, yet reusing them in tight loops can avoid
   * repeated garbage creation. The constructor performs no I/O, and it is side effect free aside
   * from allocating the object itself.
   */
  public CRC() {
    // No-op: class initializer sets up the lookup table, and the accumulator starts in a ready
    // state; work is deferred to init() and update* methods to keep construction lightweight.
  }

  /**
   * Reset the CRC to its initial state.
   *
   * <p>This call discards any previously accumulated bytes and reinitializes the internal inverted
   * accumulator to {@code 0xFFFFFFFF}. Invoke it before starting a new logical payload when reusing
   * an instance; omitting it will cause subsequent updates to continue from prior state. The
   * operation is constant time and does not allocate. It is safe to call multiple times in a row,
   * and doing so produces the same effect as a single call.
   */
  public void init() {
    value = -1;
  }

  /**
   * Update the CRC with a slice of the given byte array.
   *
   * <p>Bytes are processed sequentially starting at {@code offset} for {@code size} positions. The
   * method performs no bounds checks beyond the JVM's array access, so callers must ensure that
   * {@code offset} and {@code size} describe a valid region within {@code data}. Passing a
   * zero-length slice leaves the accumulator unchanged. The method is incremental and can be called
   * repeatedly to process streaming data without reallocating buffers.
   *
   * @param data source bytes that contribute to the checksum; must not be {@code null} and must
   *     remain unmodified during this call
   * @param offset start offset in {@code data}; must be non-negative and within array bounds for
   *     {@code size} bytes
   * @param size number of bytes to process; zero is allowed to model empty segments and negative
   *     values will result in the JVM throwing an {@link ArrayIndexOutOfBoundsException}
   */
  public void update(byte[] data, int offset, int size) {
    for (int i = 0; i < size; i++) value = table[(value ^ data[offset + i]) & 0xFF] ^ (value >>> 8);
  }

  /**
   * Update the CRC with the full contents of the given byte array.
   *
   * <p>This overload is convenient for small buffers or when the entire payload already resides in
   * memory. It is equivalent to calling {@link #update(byte[], int, int)} with an offset of zero
   * and a size equal to {@code data.length}. A zero-length array leaves the accumulator unchanged.
   *
   * @param data contiguous bytes to incorporate; must be non-{@code null} and is read sequentially
   *     from index {@code 0} to {@code data.length - 1}
   */
  public void update(byte[] data) {
    for (byte b : data) value = table[(value ^ b) & 0xFF] ^ (value >>> 8);
  }

  /**
   * Update the CRC with a single byte value (low 8 bits are used).
   *
   * <p>Only the least-significant eight bits participate in the calculation; higher bits are
   * ignored. This method is useful when feeding bytes produced from integer arithmetic or when
   * streaming data one byte at a time from an input source.
   *
   * @param b integer whose least-significant 8 bits form the byte to incorporate; higher bits are
   *     ignored but accepted without validation
   */
  public void updateByte(int b) {
    value = table[(value ^ b) & 0xFF] ^ (value >>> 8);
  }

  /**
   * Return the finalized CRC-32 value.
   *
   * <p>The returned value reflects every byte supplied since the most recent {@link #init()} call,
   * or since construction if {@code init()} has not yet been invoked. The accumulator remains
   * inverted internally to match the standard algorithm, and this method applies the final bitwise
   * inversion to expose the conventional CRC-32 output. Repeated calls without further updates are
   * idempotent and return the same integer.
   *
   * @return the non-inverted CRC-32 of all bytes supplied since the last {@link #init()} call; the
   *     value matches {@link java.util.zip.CRC32#getValue()} for identical input and is suitable
   *     for serialization or comparison
   */
  public int getDigest() {
    return ~value;
  }
}

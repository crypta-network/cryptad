package network.crypta.support;

import java.io.DataInput;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.BitSet;
import network.crypta.io.WritableToDataOutputStream;

/**
 * Fixed-size logical bit array backed by {@link BitSet}.
 *
 * <p>This type maintains a logical length ({@code size}) measured in bits. Only the first {@code
 * size} bits participate in string conversion and binary serialization; any bits at or beyond
 * {@code size} are ignored by those operations and may be cleared during resizing.
 *
 * <p>Instances can be created empty for a given length, copied, or deserialized from a {@link
 * DataInput}. Convenience queries exist to find the first/last set or clear bit.
 */
public final class BitArray implements WritableToDataOutputStream {

  private int size;
  private final BitSet bits;

  /**
   * Creates a bit array from a byte array.
   *
   * <p>The logical size is set to {@code data.length * 8}. Bit values are interpreted using {@link
   * BitSet#valueOf(byte[])} semantics.
   *
   * @param data the source bytes (not {@code null})
   */
  @SuppressWarnings("unused")
  public BitArray(byte[] data) {
    this.bits = BitSet.valueOf(data);
    this.size = data.length * 8;
  }

  /**
   * Returns a deep copy of this instance.
   *
   * @return an independent {@code BitArray} with the same size and bit values
   */
  public BitArray copy() {
    return new BitArray(this);
  }

  /**
   * Deserializes from a {@link DataInput} using {@link Integer#MAX_VALUE} as the maximum size.
   *
   * <p>The format is a 4-byte big-endian {@code int} size followed by {@code ceil(size/8)} bytes of
   * bit data. The size must be {@code > 0}; otherwise an {@link IOException} is thrown. Any
   * high-order bits beyond the logical size are cleared.
   *
   * @param dis the input to read from
   * @throws IOException if the size is invalid or the stream does not contain sufficient bytes
   */
  public BitArray(DataInput dis) throws IOException {
    this(dis, Integer.MAX_VALUE);
  }

  /**
   * Deserializes from a {@link DataInput} with an explicit size limit.
   *
   * <p>Reads a 4-byte size, validates {@code 0 < size <= maxSize}, then reads {@code ceil(size/8)}
   * bytes. Bits beyond the logical size in the last byte are cleared.
   *
   * @param dis the input to read from
   * @param maxSize maximum allowed bit length
   * @throws IOException if the size is not in {@code (0, maxSize]} or the stream ends early
   */
  public BitArray(DataInput dis, int maxSize) throws IOException {
    this.size = dis.readInt();
    if (size <= 0 || size > maxSize) {
      throw new IOException("Unacceptable bitarray size: " + size);
    }
    byte[] inputBits = new byte[getByteSize()];
    dis.readFully(inputBits);
    this.bits = BitSet.valueOf(inputBits);
    trimToSize();
  }

  /**
   * Creates an empty bit array with the given logical size.
   *
   * @param size number of logical bits (may be zero or positive)
   */
  public BitArray(int size) {
    this.size = size;
    this.bits = new BitSet(size);
  }

  /**
   * Copy constructor.
   *
   * @param src the instance to copy from
   */
  public BitArray(BitArray src) {
    this.size = src.size;
    this.bits = (BitSet) src.bits.clone();
  }

  /**
   * Sets the bit at {@code pos}.
   *
   * <p>Valid positions are zero-based. This implementation currently permits {@code pos == size},
   * which writes just beyond the logical range; that bit is ignored by {@link #toString()} and
   * serialization and may be cleared by resizing. This behavior is retained for compatibility with
   * historical callers.
   *
   * @param pos bit index (zero-based)
   * @param f value to set
   * @throws ArrayIndexOutOfBoundsException if {@code pos < 0} or {@code pos > size}
   */
  public void setBit(int pos, boolean f) {
    checkPos(pos);
    bits.set(pos, f);
  }

  /**
   * Returns the value of the bit at {@code pos}.
   *
   * @param pos bit index (zero-based)
   * @return {@code true} if set, otherwise {@code false}
   * @throws ArrayIndexOutOfBoundsException if {@code pos < 0} or {@code pos > size}
   */
  public boolean bitAt(int pos) {
    checkPos(pos);
    return bits.get(pos);
  }

  /**
   * Converts a signed byte to an unsigned int in the range {@code [0, 255]}.
   *
   * @param b the input byte
   * @return the unsigned value as an {@code int}
   */
  static int unsignedByteToInt(byte b) {
    return b & 0xFF;
  }

  /**
   * Returns a {@code '0'}/{@code '1'} string for the first {@link #size} bits.
   *
   * <p>Index {@code 0} is rendered first; the returned string length equals {@link #getSize()}.
   *
   * @return string representation of the logical bits
   */
  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder(this.size);
    for (int x = 0; x < size; x++) {
      if (bitAt(x)) {
        sb.append('1');
      } else {
        sb.append('0');
      }
    }
    return sb.toString();
  }

  /**
   * Writes this instance to a {@link DataOutputStream}.
   *
   * <p>Format: 4-byte big-endian size followed by {@code ceil(size/8)} bytes of data. If the
   * backing {@link BitSet} produces fewer bytes than required, the array is right-padded with zeros
   * to the exact length.
   *
   * @param dos destination stream
   * @throws IOException if the stream fails while writing
   */
  @Override
  public void writeToDataOutputStream(DataOutputStream dos) throws IOException {
    dos.writeInt(size);
    byte[] outputBits = bits.toByteArray();
    if (outputBits.length != getByteSize()) {
      outputBits = Arrays.copyOf(outputBits, getByteSize());
    }
    dos.write(outputBits);
  }

  /**
   * Returns the total number of bytes used by the serialized form for a given logical size.
   *
   * <p>The result includes the 4-byte size prefix.
   *
   * @param size logical bit-length
   * @return serialized length in bytes
   */
  public static int serializedLength(int size) {
    return toByteSize(size) + 4;
  }

  /** Returns the logical number of bits. */
  public int getSize() {
    return size;
  }

  /**
   * Compares for value equality.
   *
   * <p>Two instances are equal when they have the same logical size and identical bit values in the
   * logical range. Trailing zeros beyond the logical size do not affect equality.
   *
   * @param o the object to compare with
   * @return {@code true} if equal; {@code false} otherwise
   */
  @Override
  public boolean equals(Object o) {
    if (!(o instanceof BitArray ba)) {
      return false;
    }
    if (ba.getSize() != getSize()) {
      return false;
    }
    return bits.equals(ba.bits);
  }

  /** Returns a hash code consistent with {@link #equals(Object)}. */
  @Override
  public int hashCode() {
    return bits.hashCode() ^ size;
  }

  /** Sets all bits in the range {@code [0, size)} to {@code true}. */
  public void setAllOnes() {
    bits.set(0, size);
  }

  /**
   * Returns the index of the first set bit at or after {@code start} or {@code -1} if none.
   *
   * @param start starting index (inclusive). Negative values will trigger {@link
   *     IndexOutOfBoundsException} from {@link BitSet#nextSetBit(int)}.
   * @return index of next set bit, or {@code -1}
   */
  public int firstOne(int start) {
    return bits.nextSetBit(start);
  }

  /**
   * Returns the index of the first set bit starting from index {@code 0}, or {@code -1}.
   *
   * @return index of first set bit, or {@code -1}
   */
  public int firstOne() {
    return firstOne(0);
  }

  /**
   * Returns the index of the first clear bit at or after {@code start}, or {@code -1} if all bits
   * in the logical range are set.
   *
   * @param start starting index (inclusive). Negative values will trigger {@link
   *     IndexOutOfBoundsException} from {@link BitSet#nextClearBit(int)}.
   * @return index of next clear bit in {@code [start, size)}, or {@code -1}
   */
  public int firstZero(int start) {
    int result = bits.nextClearBit(start);
    if (result >= size) {
      return -1;
    }
    return result;
  }

  /**
   * Sets a new logical size and clears any bits at or beyond that size.
   *
   * <p>Growing preserves existing bits and initializes new ones to {@code false}. Shrinking
   * discards bits in the truncated range; those bits remain cleared if grown again later.
   *
   * @param size new logical bit-length
   */
  public void setSize(int size) {
    this.size = size;
    trimToSize();
  }

  /**
   * Returns the index of the last set bit at or before {@code start}, or {@code -1} if none.
   *
   * @param start starting index (inclusive)
   * @return index of previous set bit, or {@code -1}
   */
  public int lastOne(int start) {
    return bits.previousSetBit(start);
  }

  private void trimToSize() {
    // Keep only bits in [0, size) to ensure stable string/serialization behavior.
    bits.clear(size, Integer.MAX_VALUE);
  }

  private int getByteSize() {
    return toByteSize(size);
  }

  private static int toByteSize(int bitSize) {
    return (bitSize + 7) / 8;
  }

  private void checkPos(int pos) {
    // Note: this intentionally allows pos == size; see setBit/bitAt docs.
    if (pos > size || pos < 0) {
      throw new ArrayIndexOutOfBoundsException();
    }
  }
}

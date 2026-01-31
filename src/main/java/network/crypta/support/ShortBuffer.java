package network.crypta.support;

import java.io.DataInput;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Arrays;
import network.crypta.io.WritableToDataOutputStream;

/**
 * A lightweight view over a byte array whose logical size is limited to 32&nbsp;KiB.
 *
 * <p>The buffer stores a backing array together with a start offset and a {@code short}-sized
 * length. Instances are immutable with respect to their offset and length (all fields are final),
 * but they do not defensively copy the provided array. Mutating the backing array after passing it
 * to the constructor will therefore be reflected by this buffer.
 *
 * <p>Serialization via {@link #writeToDataOutputStream(DataOutputStream)} writes the length as a
 * two-byte signed big-endian value followed by the raw bytes. The constructor that accepts a {@link
 * DataInput} performs the inverse operation and rejects negative lengths.
 */
public class ShortBuffer implements WritableToDataOutputStream {

  /**
   * Historical source control identifier retained for compatibility and debugging only.
   *
   * <p>Not intended for programmatic versioning.
   */
  public static final String VERSION =
      "$Id: ShortBuffer.java,v 1.2 2005/08/25 17:28:19 amphibian Exp $";

  private final byte[] data;
  private final int start;
  private final short length;

  /**
   * Constructs a buffer by reading from a {@link DataInput}.
   *
   * <p>This method consumes exactly two bytes for the length (signed big-endian {@code short})
   * followed by that many payload bytes. Only non-negative lengths are accepted; the maximum length
   * is {@link Short#MAX_VALUE} (32&nbsp;KiB minus one).
   *
   * @param dis the input to read from; not {@code null}.
   * @throws IllegalArgumentException if the encoded length is negative.
   * @throws IOException if an I/O error occurs or there are not enough bytes to satisfy the read.
   */
  public ShortBuffer(DataInput dis) throws IOException {
    length = dis.readShort();
    if (length < 0) throw new IllegalArgumentException("Negative Length: " + length);
    data = new byte[length];
    start = 0;
    dis.readFully(data);
  }

  /** Constructs an empty buffer with zero length. */
  public ShortBuffer() {
    data = new byte[0];
    start = 0;
    length = 0;
  }

  /**
   * Constructs a buffer over the entire provided array.
   *
   * <p>No defensive copy is made. Modifying {@code data} after construction will change the bytes
   * exposed by this buffer.
   *
   * @param data the backing array; not {@code null}.
   * @throws IllegalArgumentException if {@code data.length} exceeds {@link Short#MAX_VALUE}.
   */
  public ShortBuffer(byte[] data) {
    if (data.length > Short.MAX_VALUE)
      throw new IllegalArgumentException("Too big: " + data.length);
    start = 0;
    length = (short) data.length;
    this.data = data;
  }

  /**
   * Constructs a buffer that exposes a contiguous window of the provided array.
   *
   * <p>No defensive copy is made. The window is defined by {@code start} and {@code length}. Both
   * arguments are validated to ensure the window lies inside {@code data} and that {@code length <=
   * Short.MAX_VALUE}.
   *
   * @param data the backing array; not {@code null}.
   * @param start the starting offset in {@code data}, inclusive; must be {@code >= 0}.
   * @param length the number of bytes in the window; must be {@code >= 0} and {@code <=} {@link
   *     Short#MAX_VALUE}.
   * @throws IllegalArgumentException if the window is invalid or exceeds {@link Short#MAX_VALUE}.
   */
  public ShortBuffer(byte[] data, int start, int length) {
    if (length > Short.MAX_VALUE || length < 0 || start < 0 || start + length > data.length)
      throw new IllegalArgumentException("Invalid Length: start=" + start + ", length=" + length);
    this.start = start;
    this.data = data;
    this.length = (short) length;
  }

  /**
   * Returns the logical contents as a byte array.
   *
   * <p>If this buffer already spans the entire backing array, the internal array reference is
   * returned for efficiency; callers must not modify it unless they control all references. When
   * the buffer represents a window into a larger array, a new array containing only the visible
   * bytes is returned.
   *
   * @return a byte array representing the logical contents; either the internal array or a copy.
   */
  public byte[] getData() {
    if ((start == 0) && (length == data.length)) {
      return data;
    } else {
      return Arrays.copyOfRange(data, start, start + length);
    }
  }

  /**
   * Copies the logical contents into the destination array at the specified offset.
   *
   * <p>No bounds checks are performed beyond those of {@link System#arraycopy(Object, int, Object,
   * int, int)}. If {@code array} is too small to hold the bytes starting at {@code position},
   * {@link ArrayIndexOutOfBoundsException} will be thrown by the JVM.
   *
   * @param array the destination array; not {@code null}.
   * @param position the starting index in {@code array} where bytes are written; must be valid.
   */
  public void copyTo(byte[] array, int position) {
    System.arraycopy(data, start, array, position, length);
  }

  /**
   * Returns the byte at the given logical position.
   *
   * @param pos zero-based index into the logical contents; must be {@code 0 <= pos < length}.
   * @return the byte value at {@code pos}.
   * @throws ArrayIndexOutOfBoundsException if {@code pos} is outside the valid range.
   */
  public byte byteAt(int pos) {
    if (pos >= length) {
      throw new ArrayIndexOutOfBoundsException();
    }
    return data[pos + start];
  }

  /**
   * Writes this buffer to a {@link DataOutputStream}.
   *
   * <p>The format is a two-byte signed big-endian length followed by {@code length} raw bytes. This
   * is the inverse of the {@link #ShortBuffer(DataInput)} constructor.
   *
   * @param stream destination stream; not {@code null}.
   * @throws IOException if the stream fails while writing.
   */
  @Override
  public void writeToDataOutputStream(DataOutputStream stream) throws IOException {
    stream.writeShort(length);
    stream.write(data, start, length);
  }

  /**
   * Returns a human-readable representation intended for debugging.
   *
   * <p>For buffers with {@code length > 50}, the result is {@code "Buffer {<length>}"}. Otherwise,
   * the result starts with '{', then the length and a colon, followed by the signed byte values
   * separated by spaces, and ends with a trailing space (historical format).
   *
   * <p>Format stability is not guaranteed. Do not parse this output.
   */
  @Override
  public String toString() {
    if (this.length > 50) {
      return "Buffer {" + this.length + '}';
    } else {
      StringBuilder b = new StringBuilder(this.length * 3);
      b.append('{').append(this.length).append(':');
      for (int x = 0; x < this.length; x++) {
        b.append(byteAt(x));
        b.append(' ');
      }
      return b.toString();
    }
  }

  /**
   * Compares this buffer to another for equality.
   *
   * <p>Equality requires that the logical length and start offset match, and that the entire
   * backing arrays are equal (not just the visible window). This means two buffers exposing the
   * same window over different arrays may be considered unequal if the arrays differ in bytes
   * outside the window.
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof ShortBuffer buffer)) {
      return false;
    }

    if (length != buffer.length) {
      return false;
    }
    if (start != buffer.start) {
      return false;
    }
    // Intentionally compare the entire arrays (not just the visible window).
    return Arrays.equals(data, buffer.data);
  }

  /**
   * Computes a hash code consistent with {@link #equals(Object)}.
   *
   * <p>The result mixes the hash of the full backing array with the start offset and length.
   *
   * @return the hash code.
   */
  @Override
  public int hashCode() {
    return Fields.hashCode(data) ^ start ^ (length << 16);
  }

  /**
   * Returns the logical number of bytes in this buffer.
   *
   * @return the length as a non-negative {@code int} not exceeding {@link Short#MAX_VALUE}.
   */
  public int getLength() {
    return length;
  }
}

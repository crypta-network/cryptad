package network.crypta.support;

import java.io.DataInput;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Arrays;
import network.crypta.io.WritableToDataOutputStream;

/**
 * Immutable view over a byte array with simple serialization support.
 *
 * <p>This class wraps an existing byte array together with a start offset and a length, and
 * provides convenience methods for reading a buffer from a {@link DataInput} and writing it to a
 * {@link DataOutputStream}. When constructed from a {@code DataInput}, the input is expected to be
 * framed as a 4-byte length (signed, big-endian, non-negative, and not exceeding {@link
 * Serializer#MAX_ARRAY_LENGTH}) followed by exactly that many bytes of payload.
 *
 * <p>When the buffer spans the entire backing array (i.e., {@code start == 0} and {@code length ==
 * data.length}), {@link #getData()} returns the backing array directly. In all other cases it
 * returns a copy of the visible window. Callers must not rely on receiving the internal buffer.
 *
 * <p>Thread-safety: instances are effectively immutable in terms of offset/length, however the
 * contents may reflect changes to the original array reference supplied to the constructor. No
 * internal synchronization is performed.
 *
 * @author ian
 */
public class Buffer implements WritableToDataOutputStream {

  /** Historical SCM identifier retained for compatibility/logging. */
  public static final String VERSION = "$Id: Buffer.java,v 1.2 2005/08/25 17:28:19 amphibian Exp $";

  private final byte[] data;
  private final int start;
  private final int length;

  /**
   * Construct a buffer by reading from a {@link DataInput}.
   *
   * <p>The input format is: a 4-byte signed length (written with {@link
   * DataOutputStream#writeInt(int)}) followed by that many bytes of payload. The constructor reads
   * and validates the length and then reads exactly {@code length} bytes.
   *
   * @param dis source to read the framed data from.
   * @throws IllegalArgumentException if the length is negative or greater than {@link
   *     Serializer#MAX_ARRAY_LENGTH}. The historical behavior is to signal invalid length with this
   *     exception type rather than {@link IOException}.
   * @throws IOException if {@code dis} cannot provide the requested bytes.
   */
  public Buffer(DataInput dis) throws IOException {
    length = dis.readInt();
    if (length < 0) throw new IllegalArgumentException("Negative Length: " + length);
    if (length > Serializer.MAX_ARRAY_LENGTH) {
      // Preserve historical behavior: signal invalid length with IllegalArgumentException.
      throw new IllegalArgumentException("Length larger than " + Serializer.MAX_ARRAY_LENGTH);
    }

    data = new byte[length]; // Allocate exactly the announced length.
    start = 0;
    dis.readFully(data);
  }

  /**
   * Construct a buffer that views the entire provided array.
   *
   * <p>No copy is performed. Subsequent external modification of {@code data} will be observable
   * through this instance.
   *
   * @param data backing array; must not be {@code null}.
   */
  public Buffer(byte[] data) {
    start = 0;
    length = data.length;
    this.data = data;
  }

  /**
   * Construct a buffer that views a subrange of the provided array.
   *
   * <p>No copy is performed. The visible window starts at {@code start} and spans {@code length}
   * bytes. The arguments must describe a valid range within {@code data}.
   *
   * @param data backing array; must not be {@code null}.
   * @param start start offset (0-based) into {@code data}.
   * @param length number of bytes visible from {@code start}.
   * @throws IllegalArgumentException if {@code start < 0}, {@code length < 0}, or {@code start +
   *     length > data.length}.
   */
  public Buffer(byte[] data, int start, int length) {
    if (length < 0 || start < 0 || start + length > data.length)
      throw new IllegalArgumentException("Invalid Length: start=" + start + ", length=" + length);
    this.start = start;
    this.data = data;
    this.length = length;
  }

  /**
   * Return the bytes visible through this view.
   *
   * <p>If this view covers the entire backing array the backing array itself is returned (no copy).
   * Otherwise, a new array is allocated and the visible range is copied into it.
   *
   * @return a byte array containing the visible bytes; may be the backing array when the whole
   *     array is visible.
   */
  public byte[] getData() {
    if ((start == 0) && (length == data.length)) {
      return data;
    } else {
      return Arrays.copyOfRange(data, start, start + length);
    }
  }

  /**
   * Copy the visible bytes into the given array starting at {@code position}.
   *
   * @param array destination array.
   * @param position index in {@code array} at which to start writing.
   * @throws ArrayIndexOutOfBoundsException if the copy would write past the end of {@code array}.
   */
  public void copyTo(byte[] array, int position) {
    System.arraycopy(data, start, array, position, length);
  }

  /**
   * Return the byte at the given index within this view.
   *
   * @param pos zero-based index, {@code 0 <= pos < getLength()}.
   * @return the byte value at {@code pos}.
   * @throws ArrayIndexOutOfBoundsException if {@code pos} is outside the visible range.
   */
  public byte byteAt(int pos) {
    if (pos >= length) {
      throw new ArrayIndexOutOfBoundsException();
    }
    return data[pos + start];
  }

  /**
   * Write this buffer to a {@link DataOutputStream} using the standard framing format.
   *
   * <p>The method writes a 4-byte signed length followed by the visible bytes. The length is equal
   * to {@link #getLength()} and must not exceed {@link Serializer#MAX_ARRAY_LENGTH}.
   *
   * @param stream destination stream.
   * @throws IOException if an I/O error occurs while writing to {@code stream}.
   */
  @Override
  public void writeToDataOutputStream(DataOutputStream stream) throws IOException {
    stream.writeInt(length);
    stream.write(data, start, length);
  }

  /**
   * Return a human-readable representation.
   *
   * <p>If the length is greater than 50, returns {@code "Buffer {<length>}"}. Otherwise, returns a
   * string in the form {@code "{[length]:[byte0] [byte1] ... "} with a trailing space after the
   * last value. This method is intended for debugging only; do not parse its output.
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
   * Compare for equality.
   *
   * <p>Two buffers are equal only if they share the same {@code start} and {@code length} and their
   * entire backing arrays are {@linkplain Arrays#equals(byte[], byte[]) equal} (not just the
   * visible window). This preserves historical semantics and is stricter than window-only
   * comparison.
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof Buffer buffer)) {
      return false;
    }

    if (length != buffer.length) {
      return false;
    }
    if (start != buffer.start) {
      return false;
    }
    return Arrays.equals(data, buffer.data);
  }

  /**
   * Compute a hash code consistent with {@link #equals(Object)}.
   *
   * <p>The value combines a hash of the entire backing array with the {@code start} and {@code
   * length} fields.
   */
  @Override
  public int hashCode() {
    return Fields.hashCode(data) ^ start ^ length;
  }

  /**
   * Return the number of visible bytes.
   *
   * @return the length of this view in bytes.
   */
  public int getLength() {
    return length;
  }
}

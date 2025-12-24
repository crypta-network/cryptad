package network.crypta.support.io;

import java.io.Closeable;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteOrder;
import java.util.Objects;

/**
 * Bit-level reader backed by an {@link InputStream}.
 *
 * <p>This class allows reading individual bits and fixed-width unsigned integers from an {@link
 * InputStream} without altering the underlying stream semantics. It maintains an 8-bit buffer and a
 * counter of remaining bits from the most recently fetched byte. Bit order (within each byte) can
 * be either {@link ByteOrder#BIG_ENDIAN} (most significant bit first) or {@link
 * ByteOrder#LITTLE_ENDIAN} (least significant bit first).
 *
 * <p>Fast paths are provided for byte-aligned reads of 8/16/24/32 bits. When the reader is not
 * mid-byte (i.e., no partially consumed bits) these lengths are read directly from the underlying
 * stream in as few calls as possible. For 16/24/32-bit reads, the supplied {@code ByteOrder}
 * controls how bytes are combined.
 *
 * <p>Instances of this class are not thread-safe.
 */
public class BitInputStream implements Closeable {

  private final InputStream in;
  private final ByteOrder streamBitOrder;
  private int bitsBuffer;
  private byte bitsLeft;

  /**
   * Create a new reader with big-endian bit order.
   *
   * @param in the underlying stream; must not be {@code null}.
   * @throws NullPointerException if {@code in} is {@code null}.
   */
  public BitInputStream(InputStream in) {
    this(in, ByteOrder.BIG_ENDIAN);
  }

  /**
   * Create a new reader with a specific bit order.
   *
   * <p>The bit order applies to how bits within a byte are numbered and how multi-bit values are
   * accumulated when using the bit-by-bit path. For 16/24/32-bit byte-aligned fast paths, the
   * provided order controls how bytes are combined to form the result.
   *
   * @param in the underlying stream; must not be {@code null}.
   * @param bitOrder bit order to use for this reader; must not be {@code null}.
   * @throws NullPointerException if {@code in} or {@code bitOrder} is {@code null}.
   */
  public BitInputStream(InputStream in, ByteOrder bitOrder) {
    Objects.requireNonNull(in);
    Objects.requireNonNull(bitOrder);
    this.in = in;
    streamBitOrder = bitOrder;
  }

  /**
   * Close this reader and its underlying stream.
   *
   * <p>Delegates to {@link InputStream#close()} of the wrapped stream.
   *
   * @throws IOException if closing the underlying stream fails.
   */
  @Override
  public void close() throws IOException {
    in.close();
  }

  /**
   * Read the next single bit.
   *
   * <p>When the internal bit buffer is empty, a new byte is fetched from the underlying stream. The
   * returned bit is either the next most-significant bit (big-endian bit order) or the next
   * least-significant bit (little-endian bit order) of the buffered byte.
   *
   * @return the next bit as {@code 0} or {@code 1}.
   * @throws EOFException if the end of the underlying stream is reached before a bit is available.
   * @throws IOException if an I/O error occurs while reading from the underlying stream.
   */
  public int readBit() throws IOException {
    if (bitsLeft == 0) {
      if ((bitsBuffer = in.read()) < 0) {
        throw new EOFException();
      }
      bitsLeft = 8;
    }
    // Compute the index of the next bit within the current buffered byte.
    // Big-endian consumes bits from 7 down to 0; little-endian from 0 up to 7.
    int bitIdx = (streamBitOrder == ByteOrder.BIG_ENDIAN ? --bitsLeft : 8 - bitsLeft--);
    return (bitsBuffer >> bitIdx) & 1;
  }

  /**
   * Read an unsigned integer composed of {@code length} bits using this instance's bit order.
   *
   * <p>When byte-aligned and {@code length} is 8/16/24/32, a fast path is used. Otherwise, the
   * value is assembled bit by bit via repeated {@link #readBit()} calls.
   *
   * @param length number of bits to read; {@code 0} returns {@code 0}.
   * @return the accumulated unsigned value in the low bits of the returned {@code int}.
   * @throws IllegalArgumentException if {@code length} is negative.
   * @throws EOFException if there is not enough data to satisfy the read.
   * @throws IOException if an I/O error occurs while reading from the underlying stream.
   */
  public int readInt(int length) throws IOException {
    return readInt(length, streamBitOrder);
  }

  /**
   * Read an unsigned integer composed of {@code length} bits using the provided bit order.
   *
   * <p>Behavior depends on alignment and length:
   *
   * <ul>
   *   <li>If no bits are currently buffered from a prior byte (i.e., byte-aligned) and {@code
   *       length} is 8/16/24/32, the method reads directly from the underlying stream. For
   *       16/24/32, {@code bitOrder} controls how bytes are combined.
   *   <li>Otherwise, the value is assembled bit by bit. For {@link ByteOrder#BIG_ENDIAN}, bits are
   *       shifted left; for {@link ByteOrder#LITTLE_ENDIAN}, bits are accumulated LSB-first.
   *   <li>For {@link ByteOrder#LITTLE_ENDIAN} with a {@code length} that is an exact multiple of 8
   *       on the bit-by-bit path, this method throws {@link UnsupportedOperationException}. When
   *       byte-aligned, the fast path supports such lengths.
   * </ul>
   *
   * @param length number of bits to read; {@code 0} returns {@code 0}.
   * @param bitOrder bit order to use for this call.
   * @return the accumulated unsigned value in the low bits of the returned {@code int}.
   * @throws IllegalArgumentException if {@code length} is negative.
   * @throws UnsupportedOperationException if little-endian bit-by-bit reading is requested for a
   *     length that is a multiple of 8 (only applicable when not byte-aligned).
   * @throws EOFException if there is not enough data to satisfy the read.
   * @throws IOException if an I/O error occurs while reading from the underlying stream.
   */
  public int readInt(int length, ByteOrder bitOrder) throws IOException {
    if (length == 0) {
      return 0;
    }

    if (length < 0) {
      throw new IllegalArgumentException("Invalid length: " + length + " (must be positive)");
    }

    if (bitsLeft == 0) {
      switch (length) {
        case 8:
          return readByteStrict();
        case 16:
          return readTwoBytes(bitOrder);
        case 24:
          return readThreeBytes(bitOrder);
        case 32:
          return readFourBytes(bitOrder);
        default:
          // fall through to bitwise path below
      }
    }

    return readIntBitwise(length, bitOrder);
  }

  /**
   * Read {@code b.length} bytes into the provided array.
   *
   * <p>If the reader is byte-aligned, this performs a single {@link InputStream#read(byte[])} and
   * throws {@link EOFException} if that call does not return exactly {@code b.length}. When not
   * aligned, this method reads eight bits at a time via {@link #readInt(int)} to fill the array
   * across byte boundaries.
   *
   * @param b destination array; must not be {@code null}.
   * @throws EOFException if there are fewer than {@code b.length} bytes available.
   * @throws IOException if an I/O error occurs while reading from the underlying stream.
   */
  public void readFully(byte[] b) throws IOException {
    if (bitsLeft == 0) {
      if (in.read(b) < b.length) {
        throw new EOFException();
      }
      return;
    }

    for (int i = 0; i < b.length; i++) {
      b[i] = (byte) readInt(8);
    }
  }

  /**
   * Skip up to {@code n} bits.
   *
   * <p>Behavior:
   *
   * <ul>
   *   <li>If the request is satisfied entirely by the currently buffered bits (i.e., {@code
   *       bitsLeft > n}), the method consumes those bits and returns {@code n}.
   *   <li>Otherwise, it consumes any remaining buffered bits, then skips whole bytes followed by
   *       any final bits. If all {@code n} bits are skipped successfully, it returns {@code 0}.
   *   <li>If EOF is reached before skipping {@code n} bits, it returns the number of bits that were
   *       actually skipped.
   * </ul>
   *
   * <p>These return values preserve historical behavior relied on by existing callers.
   *
   * @param n the number of bits to skip; non-positive values result in {@code 0}.
   * @return the value described above (either {@code n}, {@code 0}, or the number of bits actually
   *     skipped on EOF).
   * @throws IOException if an I/O error occurs while reading from the underlying stream.
   */
  public long skip(long n) throws IOException {
    if (n <= 0) {
      return 0;
    }

    long remaining = n;

    if (bitsLeft > 0) {
      if (bitsLeft > remaining) {
        // Fully satisfied within the current buffered byte: consume and return n.
        readInt((int) remaining);
        return remaining;
      } else {
        remaining -= bitsLeft;
        readInt(bitsLeft);
      }
    }

    while (remaining >= 8) {
      if (in.read() == -1) {
        return n - remaining;
      }

      remaining -= 8;
    }

    while (remaining > 0) {
      try {
        readBit();
        remaining--;
      } catch (EOFException _) {
        return n - remaining;
      }
    }

    // When all bits were skipped successfully, {@code remaining} is 0; return 0.
    return remaining;
  }

  private int readByteStrict() throws IOException {
    int b = in.read();
    if (b < 0) {
      throw new EOFException();
    }
    return b;
  }

  private int readTwoBytes(ByteOrder bitOrder) throws IOException {
    int b1 = readByteStrict();
    int b2 = readByteStrict();
    if (bitOrder == ByteOrder.BIG_ENDIAN) {
      return (b1 << 8) | b2;
    } else {
      return b1 | (b2 << 8);
    }
  }

  private int readThreeBytes(ByteOrder bitOrder) throws IOException {
    int b1 = readByteStrict();
    int b2 = readByteStrict();
    int b3 = readByteStrict();
    if (bitOrder == ByteOrder.BIG_ENDIAN) {
      return (b1 << 16) | (b2 << 8) | b3;
    } else {
      return b1 | (b2 << 8) | (b3 << 16);
    }
  }

  private int readFourBytes(ByteOrder bitOrder) throws IOException {
    int b1 = readByteStrict();
    int b2 = readByteStrict();
    int b3 = readByteStrict();
    int b4 = readByteStrict();
    if (bitOrder == ByteOrder.BIG_ENDIAN) {
      return (b1 << 24) | (b2 << 16) | (b3 << 8) | b4;
    } else {
      return b1 | (b2 << 8) | (b3 << 16) | (b4 << 24);
    }
  }

  private int readIntBitwise(int length, ByteOrder bitOrder) throws IOException {
    int value = 0;
    if (bitOrder == ByteOrder.BIG_ENDIAN) {
      for (int i = 0; i < length; i++) {
        value = (value << 1) | readBit();
      }
      return value;
    }

    if (length % 8 == 0) {
      throw new UnsupportedOperationException("Not implemented, yet");
    }

    for (int i = 0; i < length; i++) {
      value |= readBit() << i;
    }
    return value;
  }
}

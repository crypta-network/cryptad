package network.crypta.support;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.BitSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility methods for converting between hexadecimal strings, byte arrays, bit sets, and {@link
 * BigInteger} values.
 *
 * <p>This class centralizes low-level binary/text conversions used by networking and persistence
 * code paths. Methods are intentionally static and allocation-aware: callers can either request new
 * arrays/strings or append into existing buffers. Hex encoding uses lowercase digits and does not
 * include separators or prefixes. Bit conversions map bits in little-endian order within each byte
 * (bit index {@code 0} maps to the least-significant bit of the first output byte), matching legacy
 * expectations in existing serialization helpers.
 *
 * <p>Parsing helpers validate bounds and throw standard Java exceptions for invalid input, allowing
 * callers to handle malformed data explicitly.
 */
public final class HexUtil {
  private static final Logger LOG = LoggerFactory.getLogger("network.crypta.support.HexUtil");

  private HexUtil() {}

  /**
   * Encodes a byte-array slice as lowercase hexadecimal text.
   *
   * @param bs source byte array containing bytes to encode
   * @param off zero-based offset of the first byte to encode
   * @param length number of bytes to encode from {@code bs}
   * @return hexadecimal string containing exactly {@code length * 2} characters
   * @throws IllegalArgumentException if {@code off + length} exceeds {@code bs.length}
   */
  public static String bytesToHex(byte[] bs, int off, int length) {
    if (bs.length < off + length) {
      throw new IllegalArgumentException(
          "Total length: " + bs.length + ", offset: " + off + ", length: " + length);
    }
    StringBuilder sb = new StringBuilder(length * 2);
    bytesToHexAppend(bs, off, length, sb);
    return sb.toString();
  }

  /**
   * Appends a byte-array slice as lowercase hexadecimal text to an existing builder.
   *
   * @param bs source byte array containing bytes to encode
   * @param off zero-based offset of the first byte to encode
   * @param length number of bytes to encode from {@code bs}
   * @param sb destination builder that receives the encoded hex characters
   * @throws IllegalArgumentException if {@code off + length} exceeds {@code bs.length}
   */
  public static void bytesToHexAppend(byte[] bs, int off, int length, StringBuilder sb) {
    if (bs.length < off + length) {
      throw new IllegalArgumentException();
    }
    sb.ensureCapacity(sb.length() + length * 2);
    for (int i = off; i < off + length; i++) {
      int b = bs[i];
      sb.append(Character.forDigit((b >>> 4) & 0xF, 16));
      sb.append(Character.forDigit(b & 0xF, 16));
    }
  }

  /**
   * Encodes an entire byte array as lowercase hexadecimal text.
   *
   * @param bs source byte array to encode
   * @return hexadecimal string containing all bytes from {@code bs}
   */
  public static String bytesToHex(byte[] bs) {
    return bytesToHex(bs, 0, bs.length);
  }

  /**
   * Parses a hexadecimal string into a newly allocated byte array.
   *
   * @param s hexadecimal input string; odd lengths are accepted by prepending a leading {@code 0}
   * @return decoded bytes from {@code s}
   * @throws NumberFormatException if {@code s} contains non-hexadecimal characters
   */
  public static byte[] hexToBytes(String s) {
    return hexToBytes(s, 0);
  }

  /**
   * Parses a hexadecimal string into a new array with a caller-specified leading offset.
   *
   * <p>The first {@code off} bytes in the returned array remain zero-initialized; decoded bytes are
   * written starting at index {@code off}.
   *
   * @param s hexadecimal input string; odd lengths are accepted by prepending a leading {@code 0}
   * @param off number of leading bytes to reserve in the returned array
   * @return new array containing the decoded bytes starting at offset {@code off}
   * @throws NumberFormatException if {@code s} contains non-hexadecimal characters
   */
  public static byte[] hexToBytes(String s, int off) {
    byte[] bs = new byte[off + (1 + s.length()) / 2];
    hexToBytes(s, bs, off);
    return bs;
  }

  /**
   * Parses hexadecimal text into an existing output buffer.
   *
   * <p>If {@code s} has odd length, parsing behaves as though a leading {@code 0} was prepended.
   * Decoded bytes are written into {@code out} beginning at {@code off}.
   *
   * @param s hexadecimal input string to decode
   * @param out destination byte array receiving decoded bytes
   * @param off index in {@code out} where decoded bytes begin
   * @throws NumberFormatException if {@code s} contains non-hexadecimal characters
   * @throws IndexOutOfBoundsException if {@code out} is too small for decoded bytes at {@code off}
   */
  public static void hexToBytes(String s, byte[] out, int off)
      throws NumberFormatException, IndexOutOfBoundsException {
    String str = s;
    int slen = str.length();
    if (slen % 2 != 0) {
      str = "0" + str;
    }
    if (out.length < off + slen / 2) {
      throw new IndexOutOfBoundsException(
          "Output buffer too small for input (" + out.length + "<" + (off + slen / 2) + ")");
    }
    int i = 0;
    while (i < slen) {
      int highNibble = Character.digit(str.charAt(i), 16);
      int lowNibble = Character.digit(str.charAt(i + 1), 16);
      if (highNibble < 0 || lowNibble < 0) {
        throw new NumberFormatException();
      }
      out[off + i / 2] = (byte) ((highNibble << 4) | lowNibble);
      i += 2;
    }
  }

  /**
   * Converts a bit set into a packed byte array.
   *
   * <p>Bit indices increase from least-significant to most-significant bit within each byte. Bits
   * at indices greater than or equal to {@code size} are ignored.
   *
   * @param ba source bit set
   * @param size number of significant bit positions to encode
   * @return packed byte array sized to hold {@code size} bits
   */
  public static byte[] bitsToBytes(BitSet ba, int size) {
    int bytesAlloc = countBytesForBits(size);
    byte[] b = new byte[bytesAlloc];
    StringBuilder debugBuilder = LOG.isDebugEnabled() ? new StringBuilder(8 * bytesAlloc) : null;
    for (int i = 0; i < bytesAlloc; i++) {
      int startBit = i * 8;
      int s = computeByteFromBits(ba, startBit, size, debugBuilder);
      b[i] = (byte) s;
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "bytes: {} returned from bitsToBytes({},{}): {} for {}",
          bytesAlloc,
          ba,
          size,
          bytesToHex(b),
          debugBuilder);
    }
    return b;
  }

  private static int computeByteFromBits(
      BitSet ba, int startBit, int size, StringBuilder debugBuilder) {
    int s = 0;
    for (int j = 0; j < 8; j++) {
      int idx = startBit + j;
      boolean value = idx <= size - 1 && ba.get(idx);
      if (value) {
        s |= 1 << j;
      }
      if (debugBuilder != null) {
        debugBuilder.append(value ? '1' : '0');
      }
    }
    if (s > 255) {
      throw new IllegalStateException("WTF? s = " + s);
    }
    return s;
  }

  /**
   * Converts a bit set to hexadecimal text via packed-byte encoding.
   *
   * @param ba source bit set
   * @param size number of significant bit positions to encode
   * @return lowercase hexadecimal representation of the encoded bytes
   */
  public static String bitsToHexString(BitSet ba, int size) {
    return bytesToHex(bitsToBytes(ba, size));
  }

  /**
   * Encodes a {@link BigInteger} value as hexadecimal text.
   *
   * @param i integer value to encode using its two's-complement byte array form
   * @return lowercase hexadecimal string representing {@code i.toByteArray()}
   */
  public static String toHexString(BigInteger i) {
    return bytesToHex(i.toByteArray());
  }

  /**
   * Computes the number of bytes required to store a given number of bits.
   *
   * @param size number of bits
   * @return minimum number of bytes needed to represent {@code size} bits
   */
  public static int countBytesForBits(int size) {
    return (size + 7) / 8;
  }

  /**
   * Expands packed bytes into individual bits in a destination bit set.
   *
   * <p>Bits are read least-significant first from each byte and written to increasing bit-set
   * indices, stopping once the target index would exceed {@code maxSize}.
   *
   * @param b source bytes containing packed bits
   * @param ba destination bit set that receives decoded bits
   * @param maxSize maximum destination bit index to populate
   */
  public static void bytesToBits(byte[] b, BitSet ba, int maxSize) {
    if (LOG.isDebugEnabled()) {
      LOG.debug("bytesToBits({},ba,{} )", bytesToHex(b), maxSize);
    }
    int x = 0;
    for (byte bi : b) {
      for (int j = 0; j < 8; j++) {
        if (x > maxSize) {
          break;
        }
        int mask = 1 << j;
        boolean value = (mask & bi) != 0;
        ba.set(x, value);
        x++;
      }
    }
  }

  /**
   * Decodes hexadecimal text and writes the corresponding bits into a bit set.
   *
   * @param s hexadecimal input string to decode
   * @param ba destination bit set that receives decoded bits
   * @param length maximum destination bit index used during expansion
   */
  public static void hexToBits(String s, BitSet ba, int length) {
    byte[] b = hexToBytes(s);
    bytesToBits(b, ba, length);
  }

  /**
   * Writes a non-negative {@link BigInteger} with a length prefix.
   *
   * <p>The value is serialized as a signed 16-bit byte-count followed by the raw output of {@link
   * BigInteger#toByteArray()}.
   *
   * @param integer non-negative integer value to serialize
   * @param out destination stream receiving length and value bytes
   * @throws IOException if writing to {@code out} fails
   * @throws IllegalArgumentException if {@code integer} is negative
   * @throws IllegalStateException if the encoded value is longer than {@link Short#MAX_VALUE}
   */
  public static void writeBigInteger(BigInteger integer, DataOutputStream out) throws IOException {
    if (integer.signum() == -1) {
      throw new IllegalArgumentException("Negative BigInteger!");
    }
    byte[] buf = integer.toByteArray();
    if (buf.length > Short.MAX_VALUE) {
      throw new IllegalStateException("Too long: " + buf.length);
    }
    out.writeShort(buf.length);
    out.write(buf);
  }

  /**
   * Reads a length-prefixed, non-negative {@link BigInteger} value.
   *
   * @param dis source stream containing a 16-bit length followed by value bytes
   * @return decoded positive {@link BigInteger} value
   * @throws IOException if input is truncated, invalid, or cannot be read
   */
  public static BigInteger readBigInteger(DataInputStream dis) throws IOException {
    short i = dis.readShort();
    if (i < 0) {
      throw new IOException("Invalid BigInteger length: " + i);
    }
    byte[] buf = new byte[i];
    dis.readFully(buf);
    return new BigInteger(1, buf);
  }

  /**
   * Encodes a {@link BigInteger} as lowercase hexadecimal text.
   *
   * @param bi integer value to encode
   * @return hexadecimal encoding of {@code bi.toByteArray()}
   */
  public static String biToHex(BigInteger bi) {
    return bytesToHex(bi.toByteArray());
  }
}

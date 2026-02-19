package network.crypta.support;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.BitSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Hex/binary conversion helpers for Crypta. */
public final class HexUtil {
  private static final Logger LOG = LoggerFactory.getLogger("network.crypta.support.HexUtil");

  private HexUtil() {}

  public static String bytesToHex(byte[] bs, int off, int length) {
    if (bs.length < off + length) {
      throw new IllegalArgumentException(
          "Total length: " + bs.length + ", offset: " + off + ", length: " + length);
    }
    StringBuilder sb = new StringBuilder(length * 2);
    bytesToHexAppend(bs, off, length, sb);
    return sb.toString();
  }

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

  public static String bytesToHex(byte[] bs) {
    return bytesToHex(bs, 0, bs.length);
  }

  public static byte[] hexToBytes(String s) {
    return hexToBytes(s, 0);
  }

  public static byte[] hexToBytes(String s, int off) {
    byte[] bs = new byte[off + (1 + s.length()) / 2];
    hexToBytes(s, bs, off);
    return bs;
  }

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
      byte b1 = (byte) Character.digit(str.charAt(i), 16);
      byte b2 = (byte) Character.digit(str.charAt(i + 1), 16);
      if (b1 < 0 || b2 < 0) {
        throw new NumberFormatException();
      }
      out[off + i / 2] = (byte) ((b1 << 4) | b2);
      i += 2;
    }
  }

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
          debugBuilder.toString());
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

  public static String bitsToHexString(BitSet ba, int size) {
    return bytesToHex(bitsToBytes(ba, size));
  }

  public static String toHexString(BigInteger i) {
    return bytesToHex(i.toByteArray());
  }

  public static int countBytesForBits(int size) {
    return (size + 7) / 8;
  }

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

  public static void hexToBits(String s, BitSet ba, int length) {
    byte[] b = hexToBytes(s);
    bytesToBits(b, ba, length);
  }

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

  public static BigInteger readBigInteger(DataInputStream dis) throws IOException {
    short i = dis.readShort();
    if (i < 0) {
      throw new IOException("Invalid BigInteger length: " + i);
    }
    byte[] buf = new byte[i];
    dis.readFully(buf);
    return new BigInteger(1, buf);
  }

  public static String biToHex(BigInteger bi) {
    return bytesToHex(bi.toByteArray());
  }
}

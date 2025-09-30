// SevenZip/CRC.java

package SevenZip;

/**
 * CRC-32 calculator (polynomial 0xEDB88320).
 *
 * <p>Mutable instance: call {@link #init()} before feeding data via {@link #update(byte[], int,
 * int)}, {@link #update(byte[])}, or {@link #updateByte(int)}; then read the digest with {@link
 * #getDigest()}.
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

  /** Reset the CRC to its initial state. */
  public void init() {
    value = -1;
  }

  /**
   * Update the CRC with a slice of the given byte array.
   *
   * @param data source bytes
   * @param offset start offset in {@code data}
   * @param size number of bytes to process
   */
  public void update(byte[] data, int offset, int size) {
    for (int i = 0; i < size; i++) value = table[(value ^ data[offset + i]) & 0xFF] ^ (value >>> 8);
  }

  /** Update the CRC with the full contents of the given byte array. */
  public void update(byte[] data) {
    for (byte b : data) value = table[(value ^ b) & 0xFF] ^ (value >>> 8);
  }

  /** Update the CRC with a single byte value (low 8 bits are used). */
  public void updateByte(int b) {
    value = table[(value ^ b) & 0xFF] ^ (value >>> 8);
  }

  /** Return the finalized CRC-32 value. */
  public int getDigest() {
    return ~value;
  }
}

package SevenZip.Compression.RangeCoder;

import java.io.IOException;

/**
 * Decodes integers using a binary tree of range coder bit models.
 *
 * <p>Mechanical refactor of the original 7-Zip BitTreeDecoder to follow Java naming conventions
 * without changing behavior.
 */
public class BitTreeDecoder {
  private final short[] models;
  private final int numBitLevels;

  /**
   * Create a bit-tree decoder with the given number of bit levels.
   *
   * @param numBitLevels number of bits to decode (tree height)
   */
  public BitTreeDecoder(int numBitLevels) {
    this.numBitLevels = numBitLevels;
    this.models = new short[1 << numBitLevels];
  }

  /** Initialize probability models. */
  public void init() {
    Decoder.initBitModels(models);
  }

  /** Decode next symbol MSB-first. */
  public int decode(Decoder rangeDecoder) throws IOException {
    int m = 1;
    for (int bitIndex = numBitLevels; bitIndex != 0; bitIndex--)
      m = (m << 1) + rangeDecoder.decodeBit(models, m);
    return m - (1 << numBitLevels);
  }

  /** Decode next symbol LSB-first. */
  public int reverseDecode(Decoder rangeDecoder) throws IOException {
    int m = 1;
    int symbol = 0;
    for (int bitIndex = 0; bitIndex < numBitLevels; bitIndex++) {
      int bit = rangeDecoder.decodeBit(models, m);
      m <<= 1;
      m += bit;
      symbol |= (bit << bitIndex);
    }
    return symbol;
  }

  /** Static helper for reverse-order decoding using an external model array. */
  public static int reverseDecode(
      short[] models, int startIndex, Decoder rangeDecoder, int numBitLevels) throws IOException {
    int m = 1;
    int symbol = 0;
    for (int bitIndex = 0; bitIndex < numBitLevels; bitIndex++) {
      int bit = rangeDecoder.decodeBit(models, startIndex + m);
      m <<= 1;
      m += bit;
      symbol |= (bit << bitIndex);
    }
    return symbol;
  }
}

package org.sevenzip.compression.rangecoder;

import java.io.IOException;

/**
 * Encodes integers using a binary tree of range coder bit models.
 *
 * <p>This is a direct port of the original 7-Zip BitTreeEncoder with purely mechanical refactors to
 * follow Java naming conventions and basic static analysis rules. No behavior is changed.
 */
public class BitTreeEncoder {
  private final short[] models;
  private final int numBitLevels;

  /**
   * Create a bit-tree encoder with the given number of bit levels.
   *
   * @param numBitLevels number of bits to encode (tree height)
   */
  public BitTreeEncoder(int numBitLevels) {
    this.numBitLevels = numBitLevels;
    this.models = new short[1 << numBitLevels];
  }

  /** Initialize probability models. */
  public void init() {
    Decoder.initBitModels(models);
  }

  /** Encode {@code symbol} most-significant-bit first. */
  public void encode(Encoder rangeEncoder, int symbol) throws IOException {
    int m = 1;
    // Descend from MSB to LSB without mutating the loop counter in the body
    for (int bitIndex = numBitLevels - 1; bitIndex >= 0; bitIndex--) {
      int bit = (symbol >>> bitIndex) & 1;
      rangeEncoder.encode(models, m, bit);
      m = (m << 1) | bit;
    }
  }

  /** Encode {@code symbol} least-significant-bit first. */
  public void reverseEncode(Encoder rangeEncoder, int symbol) throws IOException {
    int m = 1;
    for (int i = 0; i < numBitLevels; i++) {
      int bit = symbol & 1;
      rangeEncoder.encode(models, m, bit);
      m = (m << 1) | bit;
      symbol >>= 1;
    }
  }

  /** Return the price (cost) of encoding {@code symbol} MSB-first. */
  public int getPrice(int symbol) {
    int price = 0;
    int m = 1;
    // Descend from MSB to LSB without mutating the loop counter in the body
    for (int bitIndex = numBitLevels - 1; bitIndex >= 0; bitIndex--) {
      int bit = (symbol >>> bitIndex) & 1;
      price += Encoder.getPrice(models[m], bit);
      m = (m << 1) + bit;
    }
    return price;
  }

  /** Return the price (cost) of encoding {@code symbol} LSB-first. */
  public int reverseGetPrice(int symbol) {
    int price = 0;
    int m = 1;
    for (int i = numBitLevels; i != 0; i--) {
      int bit = symbol & 1;
      symbol >>>= 1;
      price += Encoder.getPrice(models[m], bit);
      m = (m << 1) | bit;
    }
    return price;
  }

  /** Static helper for computing reverse price using an external model array. */
  public static int reverseGetPrice(short[] models, int startIndex, int numBitLevels, int symbol) {
    int price = 0;
    int m = 1;
    for (int i = numBitLevels; i != 0; i--) {
      int bit = symbol & 1;
      symbol >>>= 1;
      price += Encoder.getPrice(models[startIndex + m], bit);
      m = (m << 1) | bit;
    }
    return price;
  }

  /** Static helper for reverse-order encoding using an external model array. */
  public static void reverseEncode(
      short[] models, int startIndex, Encoder rangeEncoder, int numBitLevels, int symbol)
      throws IOException {
    int m = 1;
    for (int i = 0; i < numBitLevels; i++) {
      int bit = symbol & 1;
      rangeEncoder.encode(models, startIndex + m, bit);
      m = (m << 1) | bit;
      symbol >>= 1;
    }
  }
}

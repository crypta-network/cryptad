package org.sevenzip.compression.rangecoder;

import java.io.IOException;

/**
 * Encodes small unsigned integers with a binary tree of adaptive range-coder bit models.
 *
 * <p>This type mirrors the original 7-Zip {@code BitTreeEncoder} while presenting clearer Java
 * documentation. Callers construct the encoder with a fixed bit-width, invoke {@link #init()} to
 * seed per-node probabilities, and then reuse a single instance to emit many symbols into a shared
 * {@link Encoder}. Each internal node tracks its own probability slot that is updated as bits are
 * observed, making the encoder stateful and intentionally mutable across calls.
 *
 * <p>Typical usage pattern:
 *
 * <ul>
 *   <li>Create once with the desired bit depth (for example 3–16 bits depending on table size
 *       tolerance).
 *   <li>Call {@link #init()} before the first symbol or when starting a new independent stream.
 *   <li>Use {@link #encode(Encoder, int)} for most-significant-bit order or {@link
 *       #reverseEncode(Encoder, int)} for least-significant-bit order, depending on downstream
 *       format.
 *   <li>Optionally compute additive costs with {@link #getPrice(int)} or {@link
 *       #reverseGetPrice(int)} to drive encoder decisions without mutating state.
 * </ul>
 *
 * <p>The class is not thread-safe; confine each instance to a single encoding session or guard
 * access externally. Probability arrays are allocated eagerly to {@code 2^numBitLevels} entries and
 * retained for the life of the object. No I/O occurs here beyond delegating to the supplied {@link
 * Encoder}; errors arise only from that delegate.
 *
 * @see BitTreeDecoder
 * @see Encoder
 */
public class BitTreeEncoder {
  private final short[] models;
  private final int numBitLevels;

  /**
   * Creates a bit-tree encoder with a fixed tree height.
   *
   * <p>The constructor allocates the underlying probability table sized to {@code 2^numBitLevels}.
   * Callers must invoke {@link #init()} before encoding so each slot starts at an unbiased
   * probability. Instances are lightweight aside from the model array and are intended to be reused
   * across many symbols to benefit from adaptive probabilities.
   *
   * @param numBitLevels number of bits to encode for each symbol; must be non-negative and is
   *     typically small (for example 3–16) to balance precision against table size.
   */
  public BitTreeEncoder(int numBitLevels) {
    this.numBitLevels = numBitLevels;
    this.models = new short[1 << numBitLevels];
  }

  /**
   * Initializes every probability slot in the internal tree.
   *
   * <p>This method must be called at least once before the first encode operation and should be
   * repeated whenever starting a new unrelated stream. It resets all nodes to an even split between
   * zero and one, matching {@link Decoder#initBitModels(short[])} semantics. The call is idempotent
   * and does not touch any external resources.
   */
  public void init() {
    Decoder.initBitModels(models);
  }

  /**
   * Encodes the supplied symbol in most-significant-bit-first order.
   *
   * <p>The method walks the adaptive tree from the root toward leaves, extracting one bit per level
   * from {@code symbol} starting with the highest-order bit. Each bit is forwarded to the supplied
   * {@link Encoder}, which both writes range-coded data and updates the corresponding probability
   * node. The encoder instance is mutated as probabilities adapt to observed bits.
   *
   * @param rangeEncoder initialized {@link Encoder} that will receive encoded bits; must not be
   *     {@code null}.
   * @param symbol unsigned integer whose upper {@code numBitLevels} bits are emitted; bits beyond
   *     that width are ignored.
   * @throws IOException if the underlying {@link Encoder} fails to flush buffered bytes to its
   *     attached stream.
   */
  public void encode(Encoder rangeEncoder, int symbol) throws IOException {
    int m = 1;
    // Descend from MSB to LSB without mutating the loop counter in the body
    for (int bitIndex = numBitLevels - 1; bitIndex >= 0; bitIndex--) {
      int bit = (symbol >>> bitIndex) & 1;
      rangeEncoder.encode(models, m, bit);
      m = (m << 1) | bit;
    }
  }

  /**
   * Encodes the supplied symbol in least-significant-bit-first order.
   *
   * <p>This variant consumes bits starting from bit zero of {@code symbol}, which is useful for
   * certain offset encodings that expect reversed bit ordering. Traversal still follows the
   * left/right child structure of the adaptive tree, updating each visited node in place to reflect
   * observed outcomes.
   *
   * @param rangeEncoder initialized {@link Encoder} that will receive encoded bits; must not be
   *     {@code null}.
   * @param symbol unsigned integer whose lower {@code numBitLevels} bits are emitted; higher bits
   *     are shifted away as encoding progresses.
   * @throws IOException if the delegate {@link Encoder} encounters an error while writing its
   *     buffered state.
   */
  public void reverseEncode(Encoder rangeEncoder, int symbol) throws IOException {
    int m = 1;
    for (int i = 0; i < numBitLevels; i++) {
      int bit = symbol & 1;
      rangeEncoder.encode(models, m, bit);
      m = (m << 1) | bit;
      symbol >>= 1;
    }
  }

  /**
   * Computes the additive price of encoding {@code symbol} in MSB-first order.
   *
   * <p>The returned cost is expressed in the same scaled units as {@link Encoder#getPrice(int,
   * int)} and is suitable for heuristic comparisons during search without mutating model state. The
   * method walks the same tree path {@link #encode(Encoder, int)} would traverse but only sums
   * prices from the current probability table.
   *
   * @param symbol unsigned integer whose upper {@code numBitLevels} bits are considered; excess
   *     bits are ignored.
   * @return total scaled price for encoding the symbol with the present model probabilities in
   *     MSB-first order.
   */
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

  /**
   * Computes the additive price of encoding {@code symbol} in LSB-first order.
   *
   * <p>This mirrors {@link #reverseEncode(Encoder, int)} but only accumulates prices, leaving
   * probabilities unchanged. It is useful when selecting among candidate encodings while preserving
   * the current model state.
   *
   * @param symbol unsigned integer whose lower {@code numBitLevels} bits are evaluated; higher bits
   *     are discarded.
   * @return total scaled price for encoding the symbol with the present model probabilities in
   *     LSB-first order.
   */
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

  /**
   * Computes the LSB-first price using a caller-supplied model array.
   *
   * <p>This helper enables sharing a probability table across multiple trees by supplying an
   * offset. It does not mutate the models, making it safe for speculative pricing. Prices match the
   * scaling of {@link Encoder#getPrice(int, int)} and can be summed with other model costs.
   *
   * @param models probability table containing the tree slice starting at {@code startIndex}; must
   *     be large enough for {@code startIndex + (1 << numBitLevels)} entries.
   * @param startIndex base offset within {@code models} that represents the root of this tree.
   * @param numBitLevels number of bit levels to traverse; controls both tree height and symbol
   *     width.
   * @param symbol unsigned integer whose lower {@code numBitLevels} bits are priced in LSB-first
   *     order.
   * @return total scaled price of encoding the symbol without altering the provided model array.
   */
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

  /**
   * Encodes a symbol in LSB-first order using an external model array slice.
   *
   * <p>This variant is convenient when multiple trees share one probability table with distinct
   * offsets. It mutates the referenced {@code models} entries in place via the supplied {@link
   * Encoder}, which writes the resulting range-coded bits to its configured output stream.
   *
   * @param models probability table that holds adaptive state; entries at and below {@code
   *     startIndex} are updated.
   * @param startIndex base offset within {@code models} that represents the root of this tree.
   * @param rangeEncoder initialized {@link Encoder} that receives encoded bits and updates
   *     probabilities; must not be {@code null}.
   * @param numBitLevels number of bit levels to encode; determines traversal depth and consumed
   *     bits from {@code symbol}.
   * @param symbol unsigned integer whose lower {@code numBitLevels} bits are emitted; higher bits
   *     are shifted away as encoding progresses.
   * @throws IOException if the delegate {@link Encoder} cannot flush buffered bytes to its attached
   *     stream while emitting the symbol.
   */
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

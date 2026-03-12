package org.sevenzip.compression.rangecoder;

import java.io.IOException;

/**
 * Decodes integer symbols from a range coder using a complete binary tree of adaptive bit models.
 *
 * <p>This helper mirrors the original 7-Zip {@code BitTreeDecoder} while adopting Java naming
 * conventions. Callers construct an instance with the desired tree height (number of bits per
 * symbol), invoke {@link #init()} once to reset probabilities, and then repeatedly call {@link
 * #decode(Decoder)} or {@link #reverseDecode(Decoder)} to consume symbols from a {@link Decoder}.
 * Each internal node of the tree stores a probability slot that is updated in place as bits are
 * observed, so a single instance is intended to be reused across many symbols within a stream.
 *
 * <p>The class is mutable and not thread-safe; confine each instance to a single decoding session
 * or provide external synchronization. Probability arrays are allocated eagerly and retain their
 * state until {@link #init()} is called again, enabling progressive adaptation but requiring an
 * explicit reset between unrelated payloads. Behavior is deterministic for a given bit sequence and
 * model state; no I/O occurs in this class beyond delegating to the supplied {@link Decoder}.
 *
 * <ul>
 *   <li><strong>Responsibilities:</strong> walk the bit-tree, request bits from the range decoder,
 *       and return the assembled symbol.
 *   <li><strong>Notable behaviors:</strong> supports both MSB-first and LSB-first decoding paths,
 *       and offers a static reverse helper that operates on externally managed model arrays.
 * </ul>
 *
 * @see Decoder
 * @see BitTreeEncoder
 */
public class BitTreeDecoder {
  private final short[] models;
  private final int numBitLevels;

  /**
   * Creates a bit-tree decoder with a fixed depth measured in bit levels.
   *
   * <p>The constructor allocates one probability slot for every node in the complete binary tree,
   * totaling {@code 2^numBitLevels} entries. Newly constructed instances must be initialized with
   * {@link #init()} before decoding the first symbol; the constructor does not zero or seed the
   * model array on its own.
   *
   * @param numBitLevels number of bits to decode (tree height); must be non-negative and typically
   *     small (for example 3–16) to balance table size and precision.
   */
  public BitTreeDecoder(int numBitLevels) {
    this.numBitLevels = numBitLevels;
    this.models = new short[1 << numBitLevels];
  }

  /**
   * Initializes every probability slot to an unbiased starting value.
   *
   * <p>This method must be invoked at least once before the first decode call and should be
   * repeated whenever a new independent stream is processed. The operation overwrites all internal
   * probability entries with {@link Decoder#BIT_MODEL_TOTAL} divided by two, matching the SevenZip
   * reference implementation. Calling this method is idempotent and does not interact with any
   * external resources.
   */
  public void init() {
    Decoder.initBitModels(models);
  }

  /**
   * Decodes the next symbol in most-significant-bit-first order.
   *
   * <p>The method walks the internal probability tree from the root to a leaf, requesting one bit
   * from the supplied {@link Decoder} per level. Each observed bit advances the tree index to the
   * left or right child, and the final leaf index is converted into the returned symbol by
   * subtracting {@code 2^numBitLevels}. Probability slots are updated in place by the {@link
   * Decoder}, preserving adaptive state for subsequent calls.
   *
   * @param rangeDecoder initialized {@link Decoder} that supplies range-coded bits; must not be
   *     {@code null} and must already have consumed any necessary preamble bytes.
   * @return decoded symbol in the range {@code 0} to {@code (2^numBitLevels - 1)} inclusive,
   *     assembled with the first decoded bit as the most significant.
   * @throws IOException if the underlying {@link Decoder} needs more input bytes and the stream
   *     read fails or ends prematurely.
   */
  public int decode(Decoder rangeDecoder) throws IOException {
    int m = 1;
    for (int bitIndex = numBitLevels; bitIndex != 0; bitIndex--)
      m = (m << 1) + rangeDecoder.decodeBit(models, m);
    return m - (1 << numBitLevels);
  }

  /**
   * Decodes the next symbol in least-significant-bit-first order.
   *
   * <p>This variant traverses the same internal probability tree as {@link #decode(Decoder)} but
   * places the first bit read into the least significant position of the result. The traversal
   * continues for {@code numBitLevels} steps, updating the adaptive probability models on each
   * access and assembling the returned integer by OR-ing the observed bits at their respective
   * positions.
   *
   * @param rangeDecoder initialized {@link Decoder} to provide adaptive bits; must not be {@code
   *     null} and must already be positioned at the start of the symbol.
   * @return decoded symbol with bits ordered LSB-first, always within {@code 0 <= value <
   *     2^numBitLevels}.
   * @throws IOException if the {@link Decoder} cannot read from its backing stream during
   *     renormalization.
   */
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

  /**
   * Decodes a symbol LSB-first using an externally managed probability table.
   *
   * <p>This static helper mirrors {@link #reverseDecode(Decoder)} but accepts a caller-supplied
   * model array and starting index, enabling shared tables or sliced views across multiple trees.
   * The traversal updates the referenced {@code models} array in place. Callers are responsible for
   * initializing the relevant slice with {@link Decoder#initBitModels(short[])} prior to decoding.
   *
   * @param models mutable probability array that holds adaptive state; must be large enough to
   *     contain entries starting at {@code startIndex + (1 << numBitLevels)}.
   * @param startIndex base offset into {@code models} from which this tree's root node is read;
   *     typically zero when using a dedicated array.
   * @param rangeDecoder initialized {@link Decoder} that provides range-coded bits for this symbol;
   *     must not be {@code null}.
   * @param numBitLevels number of bit levels to traverse; controls both the depth of the tree and
   *     the width of the decoded symbol.
   * @return decoded symbol where the first bit read becomes bit zero of the result and subsequent
   *     bits occupy increasingly significant positions.
   * @throws IOException if the {@link Decoder} encounters an error while reading additional bytes
   *     during renormalization.
   */
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

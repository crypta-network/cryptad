package org.sevenzip.compression.rangecoder;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;

/**
 * Stateful range coder that emits encoded bits to an {@link OutputStream}. The encoder maintains
 * internal {@code low} and {@code range} accumulators that are progressively narrowed as symbols
 * are written, flushing bytes to the output when the high-order portion stabilizes. Callers are
 * expected to create a single instance per logical coding session, initialize it, then feed bits
 * via model-based {@link #encode(short[], int, int)} or direct-bit {@link #encodeDirectBits(int,
 * int)} paths before flushing pending bytes. The instance is not thread-safe and must be confined
 * to one thread while active. Each method mutates internal counters; reuse requires calling {@link
 * #init()} to reset. Typical lifecycle:
 *
 * <ul>
 *   <li>Set an {@link OutputStream} with {@link #setStream(OutputStream)}.
 *   <li>Call {@link #init()} to reset range-coder state.
 *   <li>Encode symbols, optionally updating probability models.
 *   <li>Finish with {@link #flushData()} then {@link #flushStream()} to push buffered bytes.
 * </ul>
 *
 * The encoder writes no framing or length metadata; callers remain responsible for delimiting or
 * sizing encoded payloads and for coordinating model initialization through {@link
 * #initBitModels(short[])} when adaptive probabilities are used.
 */
public class Encoder {
  static final int TOP_MASK = -(1 << 24);

  static final int NUM_BIT_MODEL_TOTAL_BITS = 11;
  static final int BIT_MODEL_TOTAL = (1 << NUM_BIT_MODEL_TOTAL_BITS);
  static final int NUM_MOVE_BITS = 5;

  OutputStream stream;

  long low;
  int range;
  int cacheSize;
  int cache;

  long position;

  /** Creates a new encoder with no attached output stream and uninitialized coder state. */
  public Encoder() {
    // default constructor preserves historical behavior
  }

  /**
   * Assigns the target {@link OutputStream} that will receive encoded bytes.
   *
   * <p>The stream is stored only as a reference and is not reset. Callers must supply an already
   * open stream and remain responsible for closing it after {@link #flushStream()} is invoked. This
   * method does not reset range-coder state; invoke {@link #init()} before starting a new message.
   *
   * @param stream writable, non-null {@link OutputStream} that remains valid for the lifetime of
   *     the encoding session.
   */
  public void setStream(OutputStream stream) {
    this.stream = stream;
  }

  /**
   * Releases the currently assigned stream reference.
   *
   * <p>This method does not flush or close the underlying stream and does not alter any range-coder
   * accumulators. It is typically called after a session completes to allow the encoder instance to
   * be reused with another stream.
   */
  public void releaseStream() {
    stream = null;
  }

  /**
   * Resets the internal range-coder accumulators to their initial values.
   *
   * <p>After calling this method the encoder starts from a clean state: {@code low} is zero, {@code
   * range} is {@code 0xFFFFFFFF}, the cache holds no pending bytes, and the processed byte position
   * is zero. Call this before encoding the first symbol of a new payload. The assigned output
   * stream is not changed.
   */
  public void init() {
    position = 0;
    low = 0;
    range = -1;
    cacheSize = 1;
    cache = 0;
  }

  /**
   * Forces the current coder state to emit five trailing bytes.
   *
   * <p>This aligns with the standard range-coder finalization step used by LZMA: repeatedly call
   * {@link #shiftLow()} five times so that remaining carry bits are flushed to the output. Call
   * this before {@link #flushStream()} when finishing an encoded payload.
   *
   * @throws IOException if writing buffered bytes to the assigned stream fails.
   */
  public void flushData() throws IOException {
    for (int i = 0; i < 5; i++) shiftLow();
  }

  /**
   * Flushes any buffered bytes on the assigned output stream.
   *
   * <p>Invoke this after {@link #flushData()} to ensure all encoded bytes are written downstream.
   * The method does not close the stream.
   *
   * @throws IOException if the delegate stream rejects the flush operation.
   */
  public void flushStream() throws IOException {
    stream.flush();
  }

  /**
   * Moves the high-order byte of {@code low} to the output when stabilization conditions are met.
   *
   * <p>This operation implements the range-coder carry-handling logic: when the upper bits of
   * {@code low} change or drift below {@code 0xFF000000}, the cached bytes are emitted and the
   * cached prefix updated. It adjusts {@code position}, {@code cacheSize}, and {@code cache}
   * accordingly while keeping {@code low} within the lower 24 bits.
   *
   * @throws IOException if writing to the assigned stream fails.
   */
  public void shiftLow() throws IOException {
    int lowHi = (int) (low >>> 32);
    if (lowHi != 0 || low < 0xFF000000L) {
      position += cacheSize;
      int temp = cache;
      do {
        stream.write(temp + lowHi);
        temp = 0xFF;
      } while (--cacheSize != 0);
      cache = (((int) low) >>> 24);
    }
    cacheSize++;
    low = (low & 0xFFFFFF) << 8;
  }

  /**
   * Encodes a fixed-width unsigned integer by writing each bit directly.
   *
   * <p>Bits are taken from {@code v}, starting with the most significant of the {@code
   * numTotalBits} requested, and processed through the range coder without probability adaptation.
   * The caller is responsible for ensuring {@code numTotalBits} does not exceed the meaningful
   * width of {@code v}.
   *
   * @param v value whose high bits are emitted; treated as unsigned.
   * @param numTotalBits number of most significant bits to encode; must be non-negative.
   * @throws IOException if flushing buffered bytes to the underlying stream fails.
   */
  public void encodeDirectBits(int v, int numTotalBits) throws IOException {
    for (int i = numTotalBits - 1; i >= 0; i--) {
      range >>>= 1;
      if (((v >>> i) & 1) == 1) low += range;
      if ((range & Encoder.TOP_MASK) == 0) {
        range <<= 8;
        shiftLow();
      }
    }
  }

  /**
   * Calculates the number of bytes that would be added to the output if pending state were flushed.
   *
   * <p>The value includes cached bytes awaiting emission plus four extra bytes that complete the
   * range-coder footer, matching the behavior of the original LZMA implementation.
   *
   * @return total additional byte count to be written when finalizing the stream state.
   */
  public long getProcessedSizeAdd() {
    return cacheSize + position + 4;
  }

  static final int NUM_MOVE_REDUCING_BITS = 2;

  /**
   * Shift width used when converting bit-model probabilities to price units.
   *
   * <p>The constant defines how many fractional bits are retained when precomputing price tables,
   * effectively scaling logarithmic probabilities into integer costs. Clients computing custom
   * price estimates should apply the same shift so values stay consistent with {@link
   * #getPrice(int, int)} and related helpers.
   */
  public static final int NUM_BIT_PRICE_SHIFT_BITS = 6;

  /**
   * Initializes every probability entry to an even split of {@link #BIT_MODEL_TOTAL}.
   *
   * <p>Callers should run this once before encoding with adaptive models so that each probability
   * starts unbiased at {@code BIT_MODEL_TOTAL / 2}. The method overwrites every element of the
   * supplied array.
   *
   * @param probs array of probability values to initialize; must be non-null and writable.
   */
  public static void initBitModels(short[] probs) {
    Arrays.fill(probs, (short) (BIT_MODEL_TOTAL >>> 1));
  }

  /**
   * Encodes a single binary symbol using the provided probability model.
   *
   * <p>The method splits {@code range} according to the current probability at {@code probs[index]}
   * and updates {@code low}, {@code range}, and the model entry based on whether {@code symbol} is
   * zero or one. When the resulting range falls below {@link #TOP_MASK}, {@link #shiftLow()} is
   * invoked to flush stabilized bytes. This call mutates {@code probs[index]} in-place, gradually
   * adapting it toward observed symbols.
   *
   * @param probs mutable probability table where each entry is in {@code [0, BIT_MODEL_TOTAL]} and
   *     will be updated.
   * @param index position within {@code probs} to use for this symbol; must be a valid array index.
   * @param symbol binary value to encode; expected to be {@code 0} or {@code 1}.
   * @throws IOException if writing buffered bytes to the underlying stream fails.
   */
  public void encode(short[] probs, int index, int symbol) throws IOException {
    int prob = probs[index];
    int newBound = (range >>> NUM_BIT_MODEL_TOTAL_BITS) * prob;
    if (symbol == 0) {
      range = newBound;
      probs[index] = (short) (prob + ((BIT_MODEL_TOTAL - prob) >>> NUM_MOVE_BITS));
    } else {
      low += (newBound & 0xFFFFFFFFL);
      range -= newBound;
      probs[index] = (short) (prob - (prob >>> NUM_MOVE_BITS));
    }
    if ((range & TOP_MASK) == 0) {
      range <<= 8;
      shiftLow();
    }
  }

  private static final int[] probPrices = new int[BIT_MODEL_TOTAL >>> NUM_MOVE_REDUCING_BITS];

  static {
    int kNumBits = (NUM_BIT_MODEL_TOTAL_BITS - NUM_MOVE_REDUCING_BITS);
    for (int i = kNumBits - 1; i >= 0; i--) {
      int start = 1 << (kNumBits - i - 1);
      int end = 1 << (kNumBits - i);
      for (int j = start; j < end; j++)
        probPrices[j] =
            (i << NUM_BIT_PRICE_SHIFT_BITS)
                + (((end - j) << NUM_BIT_PRICE_SHIFT_BITS) >>> (kNumBits - i - 1));
    }
  }

  /**
   * Computes the encoded price for a binary symbol given its probability.
   *
   * <p>The result is looked up in a precomputed table to avoid runtime logarithms. Prices are
   * expressed in scaled integer units using {@link #NUM_BIT_PRICE_SHIFT_BITS} fractional bits.
   *
   * @param prob probability mass for zero, scaled by {@link #BIT_MODEL_TOTAL}; intermediate values
   *     are masked to the valid range.
   * @param symbol symbol to price; expected to be {@code 0} or {@code 1}.
   * @return scaled integer price suitable for additive cost estimation.
   */
  public static int getPrice(int prob, int symbol) {
    return probPrices[
        (((prob - symbol) ^ -symbol) & (BIT_MODEL_TOTAL - 1)) >>> NUM_MOVE_REDUCING_BITS];
  }

  /**
   * Returns the precomputed price of encoding a zero bit with the given probability.
   *
   * @param prob current probability mass for zero, scaled by {@link #BIT_MODEL_TOTAL}; values
   *     outside the range are clipped by lookup.
   * @return integer price scaled by {@link #NUM_BIT_PRICE_SHIFT_BITS}, suitable for additive cost
   *     comparisons.
   */
  public static int getPrice0(int prob) {
    return probPrices[prob >>> NUM_MOVE_REDUCING_BITS];
  }

  /**
   * Returns the precomputed price of encoding a one bit with the given probability.
   *
   * @param prob probability mass for zero, scaled by {@link #BIT_MODEL_TOTAL}; the complement is
   *     used for symbol one.
   * @return integer price scaled by {@link #NUM_BIT_PRICE_SHIFT_BITS}, matching {@link
   *     #getPrice(int, int)} semantics.
   */
  public static int getPrice1(int prob) {
    return probPrices[(BIT_MODEL_TOTAL - prob) >>> NUM_MOVE_REDUCING_BITS];
  }
}

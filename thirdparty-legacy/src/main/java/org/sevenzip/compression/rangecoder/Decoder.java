package org.sevenzip.compression.rangecoder;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

/**
 * Range coder decoder used by the LZMA implementation.
 *
 * <p>This class mirrors the reference SevenZip range-decoder while adopting Java naming
 * conventions. It consumes bytes from an {@link InputStream} and reconstructs either direct-width
 * integers or probability-adapted bits that cooperate with {@link Encoder}. Callers typically
 * create a single instance per decode session, attach an input stream via {@link #setStream}, call
 * {@link #init()} to load the initial state, then repeatedly invoke {@link #decodeBit(short[],
 * int)} or {@link #decodeDirectBits(int)} until the enclosing algorithm completes. Probability
 * tables are mutated in place, so they must be initialized with {@link #initBitModels(short[])}
 * before first use and reused carefully between messages.
 *
 * <p>Instances are mutable and not thread-safe; confine each decoder to one thread at a time. The
 * decoder maintains a 32-bit {@code code} accumulator and {@code range} interval that are narrowed
 * as symbols are read. When the high bits underflow, the implementation pulls more bytes from the
 * stream to restore precision. Behavior is deterministic for a given input stream and probability
 * model state.
 *
 * <ul>
 *   <li><strong>Responsibilities:</strong> manage range intervals, update probability models,
 *       deliver decoded bits and fixed-width integers.
 *   <li><strong>Notable behavior:</strong> automatically renormalizes when {@code range} loses
 *       high-order entropy; leaves stream lifecycle (open/close) to the caller.
 * </ul>
 *
 * @see Encoder
 * @see org.sevenzip.compression.lzma.Decoder
 */
public class Decoder {
  // Constants follow UPPER_SNAKE_CASE per Java conventions.
  static final int TOP_MASK = -(1 << 24);

  static final int NUM_BIT_MODEL_TOTAL_BITS = 11;
  static final int BIT_MODEL_TOTAL = (1 << NUM_BIT_MODEL_TOTAL_BITS);
  static final int NUM_MOVE_BITS = 5;

  int range;
  int code;

  InputStream stream;

  /**
   * Creates a decoder with no attached input stream and zeroed internal state.
   *
   * <p>Call {@link #setStream(InputStream)} followed by {@link #init()} before attempting to decode
   * any symbols. The constructor performs no allocation beyond the instance itself and is safe to
   * invoke repeatedly when pooling decoders.
   */
  public Decoder() {
    // default constructor retains historical behavior
  }

  /**
   * Assigns the input source that provides encoded range-coder bytes.
   *
   * <p>The stream reference is stored without modification; callers remain responsible for opening
   * and closing it. Invoke {@link #init()} after setting the stream to load the initial range-coder
   * state. Passing {@code null} is permitted but will cause {@link #init()} to throw an {@link
   * IOException} when it attempts to read.
   *
   * @param stream readable {@link InputStream} containing the encoded payload; may be reused across
   *     sessions if positioned appropriately.
   */
  public final void setStream(InputStream stream) {
    this.stream = stream;
  }

  /**
   * Releases the current stream reference without closing it.
   *
   * <p>This is a lightweight lifecycle hook used when reusing a decoder instance for multiple
   * payloads. It does not reset internal coder state; call {@link #init()} before decoding another
   * payload after assigning a new stream.
   */
  public final void releaseStream() {
    this.stream = null;
  }

  /**
   * Loads the initial coder state from the assigned stream.
   *
   * <p>This method resets the {@code code} accumulator to the first five bytes of the stream and
   * sets {@code range} to {@code 0xFFFFFFFF}. It must be called exactly once after attaching a
   * stream and before the first decode call. The method performs five blocking reads; partial or
   * exhausted streams propagate as {@link IOException}.
   *
   * @throws IOException if the underlying stream cannot provide five bytes or signals an error.
   */
  public final void init() throws IOException {
    code = 0;
    range = -1;
    for (int i = 0; i < 5; i++) code = (code << 8) | stream.read();
  }

  /**
   * Decodes a fixed-width unsigned integer directly from the range coder.
   *
   * <p>The method reads {@code numTotalBits} bits MSB-first without consulting probability models,
   * mirroring the direct-bit path in the SevenZip specification. Each bit narrows {@code range};
   * when the upper bits underflow, an additional byte is pulled from the stream. The internal
   * {@code code} and {@code range} fields advance accordingly, so callers should not mix direct
   * decoding with model-based decoding unless the encoded stream was written in the same order.
   *
   * @param numTotalBits number of bits to consume; must be non-negative and not exceed 32 in
   *     typical usage.
   * @return reconstructed unsigned value packed into an {@code int}; higher bits are zeroed when
   *     {@code numTotalBits} is less than 32.
   * @throws IOException if an additional byte is required and the stream cannot be read.
   */
  public final int decodeDirectBits(int numTotalBits) throws IOException {
    int result = 0;
    for (int i = numTotalBits; i != 0; i--) {
      range >>>= 1;
      int t = ((code - range) >>> 31);
      code -= range & (t - 1);
      result = (result << 1) | (1 - t);

      if ((range & TOP_MASK) == 0) {
        code = (code << 8) | stream.read();
        range <<= 8;
      }
    }
    return result;
  }

  /**
   * Decodes a single binary symbol using an adaptive probability model.
   *
   * <p>The method splits the current {@code range} according to {@code probs[index]}, returns
   * either zero or one, and updates the model entry toward the observed symbol using the classic
   * SevenZip adaptation rule. Renormalization pulls more bytes from the stream whenever {@code
   * range} loses high-order bits. The supplied probability array is mutated in place and may be
   * shared across multiple calls as long as the same encoding order is followed.
   *
   * @param probs mutable probability table holding scaled masses; all entries should be initialized
   *     with {@link #initBitModels(short[])} before first use.
   * @param index position within {@code probs} to use for this symbol; must be a valid array slot.
   * @return decoded symbol value, either {@code 0} for the low subrange or {@code 1} for the high
   *     subrange after the split.
   * @throws IOException if an additional byte is required from the stream and cannot be read.
   */
  public int decodeBit(short[] probs, int index) throws IOException {
    int prob = probs[index];
    int newBound = (range >>> NUM_BIT_MODEL_TOTAL_BITS) * prob;
    if ((code ^ 0x80000000) < (newBound ^ 0x80000000)) {
      range = newBound;
      probs[index] = (short) (prob + ((BIT_MODEL_TOTAL - prob) >>> NUM_MOVE_BITS));
      if ((range & TOP_MASK) == 0) {
        code = (code << 8) | stream.read();
        range <<= 8;
      }
      return 0;
    } else {
      range -= newBound;
      code -= newBound;
      probs[index] = (short) (prob - (prob >>> NUM_MOVE_BITS));
      if ((range & TOP_MASK) == 0) {
        code = (code << 8) | stream.read();
        range <<= 8;
      }
      return 1;
    }
  }

  /**
   * Initializes every probability slot to an unbiased starting value.
   *
   * <p>This helper fills the provided array with {@code BIT_MODEL_TOTAL / 2}, matching the SevenZip
   * reference. It should be called exactly once for new tables and may be reused between messages
   * when models are intentionally reset. The method performs no bounds checking beyond the array
   * length supplied by the JVM.
   *
   * @param probs array of probability masses to reset; must be non-null and writable for the full
   *     length.
   */
  public static void initBitModels(short[] probs) {
    Arrays.fill(probs, (short) (BIT_MODEL_TOTAL >>> 1));
  }
}

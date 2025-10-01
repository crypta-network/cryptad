package SevenZip.Compression.RangeCoder;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

/**
 * Range coder decoder used by the LZMA implementation.
 *
 * <p>Method and constant names follow Java naming conventions to satisfy static analysis rules. The
 * behavior is unchanged from the original SevenZip reference implementation.
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

  public final void setStream(InputStream stream) {
    this.stream = stream;
  }

  public final void releaseStream() {
    this.stream = null;
  }

  public final void init() throws IOException {
    code = 0;
    range = -1;
    for (int i = 0; i < 5; i++) code = (code << 8) | stream.read();
  }

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

  public static void initBitModels(short[] probs) {
    Arrays.fill(probs, (short) (BIT_MODEL_TOTAL >>> 1));
  }
}

package SevenZip.Compression.RangeCoder;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;

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

  public void setStream(OutputStream stream) {
    this.stream = stream;
  }

  public void releaseStream() {
    stream = null;
  }

  public void init() {
    position = 0;
    low = 0;
    range = -1;
    cacheSize = 1;
    cache = 0;
  }

  public void flushData() throws IOException {
    for (int i = 0; i < 5; i++) shiftLow();
  }

  public void flushStream() throws IOException {
    stream.flush();
  }

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

  public long getProcessedSizeAdd() {
    return cacheSize + position + 4;
  }

  static final int NUM_MOVE_REDUCING_BITS = 2;
  public static final int NUM_BIT_PRICE_SHIFT_BITS = 6;

  public static void initBitModels(short[] probs) {
    Arrays.fill(probs, (short) (BIT_MODEL_TOTAL >>> 1));
  }

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

  public static int getPrice(int prob, int symbol) {
    return probPrices[
        (((prob - symbol) ^ (-symbol)) & (BIT_MODEL_TOTAL - 1)) >>> NUM_MOVE_REDUCING_BITS];
  }

  public static int getPrice0(int prob) {
    return probPrices[prob >>> NUM_MOVE_REDUCING_BITS];
  }

  public static int getPrice1(int prob) {
    return probPrices[(BIT_MODEL_TOTAL - prob) >>> NUM_MOVE_REDUCING_BITS];
  }
}

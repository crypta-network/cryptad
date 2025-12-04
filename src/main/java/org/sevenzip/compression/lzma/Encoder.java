package org.sevenzip.compression.lzma;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import org.sevenzip.ICodeProgress;
import org.sevenzip.compression.lz.BinTree;
import org.sevenzip.compression.rangecoder.BitTreeEncoder;

/**
 * Streaming LZMA encoder responsible for turning an {@link InputStream} into compressed bytes while
 * tracking coder state, repetition distances, and price tables.
 *
 * <p>This implementation mirrors the reference LZMA algorithm and exposes the same tuning knobs
 * used by command-line tools: dictionary size, fast-bytes limit, match-finder choice, and literal
 * context settings. Callers typically configure the encoder, set input/output streams, and invoke
 * {@link #code(InputStream, OutputStream, ICodeProgress)} to perform a full pass; lower-level entry
 * points such as {@link #codeOneBlock(long[], long[], boolean[])} can be used by advanced
 * orchestrators that want tighter progress control. Instances are stateful and not thread-safe; a
 * new encoder should be created per logical compression job. The encoder retains internal buffers
 * sized to the configured dictionary and fast-bytes window and updates probability models as bytes
 * are written. Flushing emits end markers when requested, enabling decoders to detect stream
 * termination reliably.
 *
 * <ul>
 *   <li><strong>Responsibilities:</strong> manage match finding, price tables, range coding, and
 *       repetition tracking during compression.
 *   <li><strong>Mutability:</strong> heavily stateful; reuse only when resetting all tuning
 *       parameters and streams.
 *   <li><strong>Thread safety:</strong> not thread-safe; synchronize externally when sharing.
 * </ul>
 *
 * @see org.sevenzip.compression.lzma.Decoder
 * @see org.sevenzip.compression.rangecoder.Encoder
 */
public class Encoder {
  // Match finder type constants (BT2/BT4) in UPPER_SNAKE_CASE per conventions
  /**
   * Identifier for the binary-tree match finder using two-byte hashing. Use when memory is tight or
   * ultra-fast initialization is preferred over match quality.
   */
  public static final int MATCH_FINDER_TYPE_BT2 = 0;

  /**
   * Identifier for the binary-tree match finder using four-byte hashing. This is the default and
   * offers better match quality at the cost of additional memory and preprocessing time.
   */
  public static final int MATCH_FINDER_TYPE_BT4 = 1;

  static final int INFINITY_PRICE = 0xFFFFFFF;

  static byte[] gFastPos = new byte[1 << 11];

  static {
    int kFastSlots = 22;
    int c = 2;
    gFastPos[0] = 0;
    gFastPos[1] = 1;
    for (int slotFast = 2; slotFast < kFastSlots; slotFast++) {
      int k = (1 << ((slotFast >> 1) - 1));
      for (int j = 0; j < k; j++, c++) gFastPos[c] = (byte) slotFast;
    }
  }

  // Extracted helpers to reduce cognitive complexity in GetOptimum
  private int updateStateForCur(int cur) {
    int posPrev = optimum[cur].posPrev;
    int state =
        (optimum[cur].prev1IsChar) ? stateAfterPrevIsChar(cur, posPrev) : optimum[posPrev].state;
    if (posPrev == cur - 1) {
      return optimum[cur].isShortRep()
          ? Base.stateUpdateShortRep(state)
          : Base.stateUpdateChar(state);
    }
    return stateAfterNonAdjacentPrev(cur, state);
  }

  private int stateAfterPrevIsChar(int cur, int posPrev) {
    posPrev--;
    int state;
    if (optimum[cur].prev2) {
      state = optimum[optimum[cur].posPrev2].state;
      state =
          (optimum[cur].backPrev2 < Base.NUM_REP_DISTANCES)
              ? Base.stateUpdateRep(state)
              : Base.stateUpdateMatch(state);
    } else {
      state = optimum[posPrev].state;
    }
    return Base.stateUpdateChar(state);
  }

  private void loadRepsFromOptimal(Optimal opt, int pos) {
    switch (pos) {
      case 0 -> {
        reps[0] = opt.backs0;
        reps[1] = opt.backs1;
        reps[2] = opt.backs2;
        reps[3] = opt.backs3;
      }
      case 1 -> {
        reps[0] = opt.backs1;
        reps[1] = opt.backs0;
        reps[2] = opt.backs2;
        reps[3] = opt.backs3;
      }
      case 2 -> {
        reps[0] = opt.backs2;
        reps[1] = opt.backs0;
        reps[2] = opt.backs1;
        reps[3] = opt.backs3;
      }
      default -> {
        reps[0] = opt.backs3;
        reps[1] = opt.backs0;
        reps[2] = opt.backs1;
        reps[3] = opt.backs2;
      }
    }
  }

  private int stateAfterNonAdjacentPrev(int cur, int state) {
    int posPrev = optimum[cur].posPrev;
    int pos;
    if (optimum[cur].prev1IsChar && optimum[cur].prev2) {
      posPrev = optimum[cur].posPrev2;
      pos = optimum[cur].backPrev2;
      state = Base.stateUpdateRep(state);
    } else {
      pos = optimum[cur].backPrev;
      state =
          (pos < Base.NUM_REP_DISTANCES)
              ? Base.stateUpdateRep(state)
              : Base.stateUpdateMatch(state);
    }
    Optimal opt = optimum[posPrev];
    if (pos < Base.NUM_REP_DISTANCES) {
      loadRepsFromOptimal(opt, pos);
    } else {
      reps[0] = (pos - Base.NUM_REP_DISTANCES);
      reps[1] = opt.backs0;
      reps[2] = opt.backs1;
      reps[3] = opt.backs2;
    }
    return state;
  }

  private record MatchContext(boolean nextIsChar, byte matchByte, byte currentByte) {}

  private record CurContext(
      int state, int cur, int numAvailableBytesFull, int curAnd1Price, int position) {}

  // Packs common inputs for the rep-candidates processing stage.
  private record RepCandidatesContext(
      int state,
      int position,
      int posState,
      int cur,
      int numAvailableBytesFull,
      int numAvailableBytes,
      int repMatchPrice) {}

  // Packs common inputs for normal (non-rep) matches processing.
  private record NormalMatchesContext(
      int state, int position, int posState, int cur, int numAvailableBytesFull, int matchPrice) {}

  // Packs common inputs for normal match lookahead.
  private record LookaheadContext(int state, int position, int cur, int numAvailableBytesFull) {}

  // Helper object to return two values from rep-candidates processing
  private record RepProcessResult(int lenEnd, int startLen) {}

  // Helper object to return adjusted newLen and numDistancePairs
  private record NewLenAdjustResult(int newLen, int numDistancePairsLocal) {}

  private void handleLiteralPlusRep0(MatchContext mctx, CurContext cctx, int lenEnd) {
    if (!mctx.nextIsChar && mctx.matchByte != mctx.currentByte) {
      int t = Math.min(cctx.numAvailableBytesFull - 1, numFastBytes);
      int lenTest2 = matchFinder.getMatchLen(0, reps[0], t);
      if (lenTest2 >= 2) {
        int state2 = Base.stateUpdateChar(cctx.state);
        int posStateNext = (cctx.position + 1) & posStateMask;
        int nextRepMatchPrice =
            cctx.curAnd1Price
                + org.sevenzip.compression.rangecoder.Encoder.getPrice1(
                    isMatch[(state2 << Base.NUM_POS_STATES_BITS_MAX) + posStateNext])
                + org.sevenzip.compression.rangecoder.Encoder.getPrice1(isRep[state2]);
        int offset = cctx.cur + 1 + lenTest2;
        while (lenEnd < offset) this.optimum[++lenEnd].price = INFINITY_PRICE;
        int curAndLenPrice = nextRepMatchPrice + getRepPrice(0, lenTest2, state2, posStateNext);
        Optimal optEntry = this.optimum[offset];
        if (curAndLenPrice < optEntry.price) {
          optEntry.price = curAndLenPrice;
          optEntry.posPrev = cctx.cur + 1;
          optEntry.backPrev = 0;
          optEntry.prev1IsChar = true;
          optEntry.prev2 = false;
        }
      }
    }
  }

  /**
   * Update the next optimum for the literal and short-rep paths.
   *
   * <p>Side effects: updates {@code optimum[cur + 1]} when a cheaper price is found.
   *
   * @return true when the next step is now a char (literal or short-rep) candidate
   */
  private boolean updateNextOptimumForCharAndShortRep(
      int state,
      int posState,
      int cur,
      int curAnd1Price,
      byte matchByte,
      byte currentByte,
      int repMatchPrice) {
    Optimal nextOptimum = optimum[cur + 1];

    boolean nextIsChar = false;
    if (curAnd1Price < nextOptimum.price) {
      nextOptimum.price = curAnd1Price;
      nextOptimum.posPrev = cur;
      nextOptimum.makeAsChar();
      nextIsChar = true;
    }

    if (matchByte == currentByte && !(nextOptimum.posPrev < cur && nextOptimum.backPrev == 0)) {
      int shortRepPrice = repMatchPrice + getRepLen1Price(state, posState);
      if (shortRepPrice <= nextOptimum.price) {
        nextOptimum.price = shortRepPrice;
        nextOptimum.posPrev = cur;
        nextOptimum.makeAsShortRep();
        nextIsChar = true;
      }
    }
    return nextIsChar;
  }

  /**
   * Handle the main rep-candidates loop inside getOptimum.
   *
   * <p>Side effects: updates {@code optimum[]} table entries; reads from {@code matchFinder}.
   */
  private RepProcessResult processRepCandidates(RepCandidatesContext rctx, int lenEnd) {
    int startLen = 2; // speed optimization
    for (int repIndex = 0; repIndex < Base.NUM_REP_DISTANCES; repIndex++) {
      int lenTest = matchFinder.getMatchLen(-1, reps[repIndex], rctx.numAvailableBytes);
      if (lenTest < 2) continue;

      lenEnd =
          updateRepRangeForIndex(
              repIndex, lenTest, rctx.state, rctx.posState, rctx.cur, lenEnd, rctx.repMatchPrice);
      if (repIndex == 0) startLen = lenTest + 1;
      if (lenTest < rctx.numAvailableBytesFull) {
        lenEnd = handleRepLenTest2(repIndex, lenTest, rctx, lenEnd);
      }
    }
    return new RepProcessResult(lenEnd, startLen);
  }

  private int updateRepRangeForIndex(
      int repIndex, int lenTest, int state, int posState, int cur, int lenEnd, int repMatchPrice) {
    int lt = lenTest;
    do {
      while (lenEnd < cur + lt) this.optimum[++lenEnd].price = INFINITY_PRICE;
      int curAndLenPrice = repMatchPrice + getRepPrice(repIndex, lt, state, posState);
      Optimal optEntry = this.optimum[cur + lt];
      if (curAndLenPrice < optEntry.price) {
        optEntry.price = curAndLenPrice;
        optEntry.posPrev = cur;
        optEntry.backPrev = repIndex;
        optEntry.prev1IsChar = false;
      }
    } while (--lt >= 2);
    return lenEnd;
  }

  private int handleRepLenTest2(int repIndex, int lenTest, RepCandidatesContext rctx, int lenEnd) {
    int t = Math.min(rctx.numAvailableBytesFull - 1 - lenTest, numFastBytes);
    int lenTest2 = matchFinder.getMatchLen(lenTest, reps[repIndex], t);
    if (lenTest2 < 2) return lenEnd;

    int state2 = Base.stateUpdateRep(rctx.state);
    int posStateNext = (rctx.position + lenTest) & posStateMask;
    int curAndLenCharPrice =
        rctx.repMatchPrice
            + getRepPrice(repIndex, lenTest, rctx.state, rctx.posState)
            + org.sevenzip.compression.rangecoder.Encoder.getPrice0(
                isMatch[(state2 << Base.NUM_POS_STATES_BITS_MAX) + posStateNext])
            + literalEncoder
                .getSubCoder(rctx.position + lenTest, matchFinder.getIndexByte(lenTest - 1 - 1))
                .getPrice(
                    true,
                    matchFinder.getIndexByte(lenTest - 1 - (reps[repIndex] + 1)),
                    matchFinder.getIndexByte(lenTest - 1));
    state2 = Base.stateUpdateChar(state2);
    posStateNext = (rctx.position + lenTest + 1) & posStateMask;
    int nextMatchPrice =
        curAndLenCharPrice
            + org.sevenzip.compression.rangecoder.Encoder.getPrice1(
                isMatch[(state2 << Base.NUM_POS_STATES_BITS_MAX) + posStateNext]);
    int nextRepMatchPrice =
        nextMatchPrice + org.sevenzip.compression.rangecoder.Encoder.getPrice1(isRep[state2]);

    int offset = lenTest + 1 + lenTest2;
    while (lenEnd < rctx.cur + offset) this.optimum[++lenEnd].price = INFINITY_PRICE;
    int curAndLenPrice = nextRepMatchPrice + getRepPrice(0, lenTest2, state2, posStateNext);
    Optimal optEntry = this.optimum[rctx.cur + offset];
    if (curAndLenPrice < optEntry.price) {
      optEntry.price = curAndLenPrice;
      optEntry.posPrev = rctx.cur + lenTest + 1;
      optEntry.backPrev = 0;
      optEntry.prev1IsChar = true;
      optEntry.prev2 = true;
      optEntry.posPrev2 = rctx.cur;
      optEntry.backPrev2 = repIndex;
    }
    return lenEnd;
  }

  /** Clamp newLen to availability and update {@code matchDistances} pairs list. */
  private NewLenAdjustResult adjustNewLenAndPairs(int newLen, int numAvailableBytes) {
    int numDistancePairsLocal;
    if (newLen > numAvailableBytes) {
      newLen = numAvailableBytes;
      numDistancePairsLocal = 0;
      while (newLen > matchDistances[numDistancePairsLocal]) {
        // advance to next distance/length pair
        numDistancePairsLocal += 2;
      }
      matchDistances[numDistancePairsLocal] = newLen;
      numDistancePairsLocal += 2;
    } else {
      numDistancePairsLocal = this.numDistancePairs; // unchanged
    }
    return new NewLenAdjustResult(newLen, numDistancePairsLocal);
  }

  /** Process normal match candidates (non-rep) for the current position. */
  private int processNormalMatches(
      NormalMatchesContext nctx, int newLen, int startLen, int lenEnd, int numDistancePairsLocal) {
    if (newLen < startLen) return lenEnd;

    int normalMatchPrice =
        nctx.matchPrice + org.sevenzip.compression.rangecoder.Encoder.getPrice0(isRep[nctx.state]);
    while (lenEnd < nctx.cur + newLen) this.optimum[++lenEnd].price = INFINITY_PRICE;

    int offs = 0;
    while (startLen > matchDistances[offs]) offs += 2;

    for (int lenTest = startLen; ; lenTest++) {
      int curBack = matchDistances[offs + 1];
      int curAndLenPrice = normalMatchPrice + getPosLenPrice(curBack, lenTest, nctx.posState);
      Optimal optEntry = this.optimum[nctx.cur + lenTest];
      if (curAndLenPrice < optEntry.price) {
        optEntry.price = curAndLenPrice;
        optEntry.posPrev = nctx.cur;
        optEntry.backPrev = curBack + Base.NUM_REP_DISTANCES;
        optEntry.prev1IsChar = false;
      }

      if (lenTest == matchDistances[offs]) {
        lenEnd =
            handleNormalMatchLookahead(
                new LookaheadContext(
                    nctx.state, nctx.position, nctx.cur, nctx.numAvailableBytesFull),
                lenTest,
                curBack,
                lenEnd,
                curAndLenPrice);

        offs += 2;
        if (offs == numDistancePairsLocal) break;
      }
    }
    return lenEnd;
  }

  private int handleNormalMatchLookahead(
      LookaheadContext lctx, int lenTest, int curBack, int lenEnd, int curAndLenPrice) {
    if (lenTest >= lctx.numAvailableBytesFull) return lenEnd;
    int t = Math.min(lctx.numAvailableBytesFull - 1 - lenTest, numFastBytes);
    int lenTest2 = matchFinder.getMatchLen(lenTest, curBack, t);
    if (lenTest2 < 2) return lenEnd;

    int state2 = Base.stateUpdateMatch(lctx.state);
    int posStateNext = (lctx.position + lenTest) & posStateMask;
    int curAndLenCharPrice =
        curAndLenPrice
            + org.sevenzip.compression.rangecoder.Encoder.getPrice0(
                isMatch[(state2 << Base.NUM_POS_STATES_BITS_MAX) + posStateNext])
            + literalEncoder
                .getSubCoder(lctx.position + lenTest, matchFinder.getIndexByte(lenTest - 1 - 1))
                .getPrice(
                    true,
                    matchFinder.getIndexByte(lenTest - (curBack + 1) - 1),
                    matchFinder.getIndexByte(lenTest - 1));
    state2 = Base.stateUpdateChar(state2);
    posStateNext = (lctx.position + lenTest + 1) & posStateMask;
    int nextMatchPrice =
        curAndLenCharPrice
            + org.sevenzip.compression.rangecoder.Encoder.getPrice1(
                isMatch[(state2 << Base.NUM_POS_STATES_BITS_MAX) + posStateNext]);
    int nextRepMatchPrice =
        nextMatchPrice + org.sevenzip.compression.rangecoder.Encoder.getPrice1(isRep[state2]);

    int offset = lenTest + 1 + lenTest2;
    while (lenEnd < lctx.cur + offset) this.optimum[++lenEnd].price = INFINITY_PRICE;
    int price = nextRepMatchPrice + getRepPrice(0, lenTest2, state2, posStateNext);
    Optimal optEntry = this.optimum[lctx.cur + offset];
    if (price < optEntry.price) {
      optEntry.price = price;
      optEntry.posPrev = lctx.cur + lenTest + 1;
      optEntry.backPrev = 0;
      optEntry.prev1IsChar = true;
      optEntry.prev2 = true;
      optEntry.posPrev2 = lctx.cur;
      optEntry.backPrev2 = curBack + Base.NUM_REP_DISTANCES;
    }
    return lenEnd;
  }

  static int getPosSlot(int pos) {
    if (pos < (1 << 11)) return gFastPos[pos];
    if (pos < (1 << 21)) return (gFastPos[pos >> 10] + 20);
    return (gFastPos[pos >> 20] + 40);
  }

  static int getPosSlot2(int pos) {
    if (pos < (1 << 17)) return (gFastPos[pos >> 6] + 12);
    if (pos < (1 << 27)) return (gFastPos[pos >> 16] + 32);
    return (gFastPos[pos >> 26] + 52);
  }

  int encoderState = Base.STATE_INIT;
  byte previousByte;
  int[] repDistances = new int[Base.NUM_REP_DISTANCES];

  void baseInit() {
    encoderState = Base.STATE_INIT;
    previousByte = 0;
    Arrays.fill(repDistances, 0);
  }

  static final int DEFAULT_DICTIONARY_LOG_SIZE = 22;
  static final int NUM_FAST_BYTES_DEFAULT = 0x20;

  static class LiteralEncoder {
    static class Encoder2 {
      short[] encoders = new short[0x300];

      public void init() {
        org.sevenzip.compression.rangecoder.Encoder.initBitModels(encoders);
      }

      public void encode(org.sevenzip.compression.rangecoder.Encoder rangeEncoder, byte symbol)
          throws IOException {
        int context = 1;
        for (int i = 7; i >= 0; i--) {
          int bit = ((symbol >> i) & 1);
          rangeEncoder.encode(encoders, context, bit);
          context = (context << 1) | bit;
        }
      }

      public void encodeMatched(
          org.sevenzip.compression.rangecoder.Encoder rangeEncoder, byte matchByte, byte symbol)
          throws IOException {
        int context = 1;
        boolean same = true;
        for (int i = 7; i >= 0; i--) {
          int bit = ((symbol >> i) & 1);
          int state = context;
          if (same) {
            int matchBit = ((matchByte >> i) & 1);
            state += ((1 + matchBit) << 8);
            same = (matchBit == bit);
          }
          rangeEncoder.encode(encoders, state, bit);
          context = (context << 1) | bit;
        }
      }

      public int getPrice(boolean matchMode, byte matchByte, byte symbol) {
        int price = 0;
        int context = 1;
        int i = 7;
        if (matchMode) {
          for (; i >= 0; i--) {
            int matchBit = (matchByte >> i) & 1;
            int bit = (symbol >> i) & 1;
            price +=
                org.sevenzip.compression.rangecoder.Encoder.getPrice(
                    encoders[((1 + matchBit) << 8) + context], bit);
            context = (context << 1) | bit;
            if (matchBit != bit) {
              i--;
              break;
            }
          }
        }
        for (; i >= 0; i--) {
          int bit = (symbol >> i) & 1;
          price += org.sevenzip.compression.rangecoder.Encoder.getPrice(encoders[context], bit);
          context = (context << 1) | bit;
        }
        return price;
      }
    }

    Encoder2[] coders;
    int numPrevBits;
    int numPosBits;
    int posMask;

    public void create(int numPosBits, int numPrevBits) {
      if (coders != null && this.numPrevBits == numPrevBits && this.numPosBits == numPosBits)
        return;
      this.numPosBits = numPosBits;
      posMask = (1 << numPosBits) - 1;
      this.numPrevBits = numPrevBits;
      int numStates = 1 << (this.numPrevBits + this.numPosBits);
      coders = new Encoder2[numStates];
      for (int i = 0; i < numStates; i++) coders[i] = new Encoder2();
    }

    public void init() {
      int numStates = 1 << (numPrevBits + numPosBits);
      for (int i = 0; i < numStates; i++) coders[i].init();
    }

    public Encoder2 getSubCoder(int pos, byte prevByte) {
      return coders[((pos & posMask) << numPrevBits) + ((prevByte & 0xFF) >>> (8 - numPrevBits))];
    }
  }

  static class LenEncoder {
    short[] choice = new short[2];
    BitTreeEncoder[] lowCoder = new BitTreeEncoder[Base.NUM_POS_STATES_ENCODING_MAX];
    BitTreeEncoder[] midCoder = new BitTreeEncoder[Base.NUM_POS_STATES_ENCODING_MAX];
    BitTreeEncoder highCoder = new BitTreeEncoder(Base.NUM_HIGH_LEN_BITS);

    public LenEncoder() {
      for (int posState = 0; posState < Base.NUM_POS_STATES_ENCODING_MAX; posState++) {
        lowCoder[posState] = new BitTreeEncoder(Base.NUM_LOW_LEN_BITS);
        midCoder[posState] = new BitTreeEncoder(Base.NUM_MID_LEN_BITS);
      }
    }

    public void init(int numPosStates) {
      org.sevenzip.compression.rangecoder.Encoder.initBitModels(choice);

      for (int posState = 0; posState < numPosStates; posState++) {
        lowCoder[posState].init();
        midCoder[posState].init();
      }
      highCoder.init();
    }

    public void encode(
        org.sevenzip.compression.rangecoder.Encoder rangeEncoder, int symbol, int posState)
        throws IOException {
      if (symbol < Base.NUM_LOW_LEN_SYMBOLS) {
        rangeEncoder.encode(choice, 0, 0);
        lowCoder[posState].encode(rangeEncoder, symbol);
      } else {
        symbol -= Base.NUM_LOW_LEN_SYMBOLS;
        rangeEncoder.encode(choice, 0, 1);
        if (symbol < Base.NUM_MID_LEN_SYMBOLS) {
          rangeEncoder.encode(choice, 1, 0);
          midCoder[posState].encode(rangeEncoder, symbol);
        } else {
          rangeEncoder.encode(choice, 1, 1);
          highCoder.encode(rangeEncoder, symbol - Base.NUM_MID_LEN_SYMBOLS);
        }
      }
    }

    public void setPrices(int posState, int numSymbols, int[] prices, int st) {
      int a0 = org.sevenzip.compression.rangecoder.Encoder.getPrice0(choice[0]);
      int a1 = org.sevenzip.compression.rangecoder.Encoder.getPrice1(choice[0]);
      int b0 = a1 + org.sevenzip.compression.rangecoder.Encoder.getPrice0(choice[1]);
      int b1 = a1 + org.sevenzip.compression.rangecoder.Encoder.getPrice1(choice[1]);
      int i;
      for (i = 0; i < Base.NUM_LOW_LEN_SYMBOLS; i++) {
        if (i >= numSymbols) return;
        prices[st + i] = a0 + lowCoder[posState].getPrice(i);
      }
      for (; i < Base.NUM_LOW_LEN_SYMBOLS + Base.NUM_MID_LEN_SYMBOLS; i++) {
        if (i >= numSymbols) return;
        prices[st + i] = b0 + midCoder[posState].getPrice(i - Base.NUM_LOW_LEN_SYMBOLS);
      }
      for (; i < numSymbols; i++)
        prices[st + i] =
            b1 + highCoder.getPrice(i - Base.NUM_LOW_LEN_SYMBOLS - Base.NUM_MID_LEN_SYMBOLS);
    }
  }

  static class LenPriceTableEncoder extends LenEncoder {
    int[] prices = new int[Base.NUM_LEN_SYMBOLS << Base.NUM_POS_STATES_BITS_ENCODING_MAX];
    int tableSize;
    int[] counters = new int[Base.NUM_POS_STATES_ENCODING_MAX];

    public void setTableSize(int tableSize) {
      this.tableSize = tableSize;
    }

    public int getPrice(int symbol, int posState) {
      return prices[posState * Base.NUM_LEN_SYMBOLS + symbol];
    }

    void updateTable(int posState) {
      setPrices(posState, tableSize, prices, posState * Base.NUM_LEN_SYMBOLS);
      counters[posState] = tableSize;
    }

    public void updateTables(int numPosStates) {
      for (int posState = 0; posState < numPosStates; posState++) updateTable(posState);
    }

    @Override
    public void encode(
        org.sevenzip.compression.rangecoder.Encoder rangeEncoder, int symbol, int posState)
        throws IOException {
      super.encode(rangeEncoder, symbol, posState);
      if (--counters[posState] == 0) updateTable(posState);
    }
  }

  static final int NUM_OPTS = 1 << 12;

  static class Optimal {
    int state;

    boolean prev1IsChar;
    boolean prev2;

    int posPrev2;
    int backPrev2;

    int price;
    int posPrev;
    int backPrev;

    int backs0;
    int backs1;
    int backs2;
    int backs3;

    public void makeAsChar() {
      backPrev = -1;
      prev1IsChar = false;
    }

    public void makeAsShortRep() {
      backPrev = 0;
      prev1IsChar = false;
    }

    public boolean isShortRep() {
      return (backPrev == 0);
    }
  }

  Optimal[] optimum = new Optimal[NUM_OPTS];
  BinTree matchFinder = null;
  org.sevenzip.compression.rangecoder.Encoder rangeEncoder =
      new org.sevenzip.compression.rangecoder.Encoder();

  short[] isMatch = new short[Base.NUM_STATES << Base.NUM_POS_STATES_BITS_MAX];
  short[] isRep = new short[Base.NUM_STATES];
  short[] isRepG0 = new short[Base.NUM_STATES];
  short[] isRepG1 = new short[Base.NUM_STATES];
  short[] isRepG2 = new short[Base.NUM_STATES];
  short[] isRep0Long = new short[Base.NUM_STATES << Base.NUM_POS_STATES_BITS_MAX];

  BitTreeEncoder[] posSlotEncoder =
      new BitTreeEncoder[Base.NUM_LEN_TO_POS_STATES]; // NUM_POS_SLOT_BITS

  short[] posEncoders = new short[Base.NUM_FULL_DISTANCES - Base.END_POS_MODEL_INDEX];
  BitTreeEncoder posAlignEncoder = new BitTreeEncoder(Base.NUM_ALIGN_BITS);

  LenPriceTableEncoder lenEncoder = new LenPriceTableEncoder();
  LenPriceTableEncoder repMatchLenEncoder = new LenPriceTableEncoder();

  LiteralEncoder literalEncoder = new LiteralEncoder();

  int[] matchDistances = new int[Base.MATCH_MAX_LEN * 2 + 2];

  int numFastBytes = NUM_FAST_BYTES_DEFAULT;
  int longestMatchLength;
  int numDistancePairs;

  int additionalOffset;

  int optimumEndIndex;
  int optimumCurrentIndex;

  boolean longestMatchWasFound;

  int[] posSlotPrices = new int[1 << (Base.NUM_POS_SLOT_BITS + Base.NUM_LEN_TO_POS_STATES_BITS)];
  int[] distancesPrices = new int[Base.NUM_FULL_DISTANCES << Base.NUM_LEN_TO_POS_STATES_BITS];
  int[] alignPrices = new int[Base.ALIGN_TABLE_SIZE];
  int alignPriceCount;

  int distTableSize = (DEFAULT_DICTIONARY_LOG_SIZE * 2);

  int posStateBits = 2;
  int posStateMask = (4 - 1);
  int numLiteralPosStateBits = 0;
  int numLiteralContextBits = 3;

  int dictionarySize = (1 << DEFAULT_DICTIONARY_LOG_SIZE);
  int dictionarySizePrev = -1;
  int numFastBytesPrev = -1;

  long nowPos64;
  boolean isFinished;
  InputStream inStream;

  int matchFinderType = MATCH_FINDER_TYPE_BT4;
  boolean writeEndMark = false;

  boolean needReleaseMFStream = false;

  void create() {
    if (matchFinder == null) {
      BinTree bt = new BinTree();
      int numHashBytes = 4;
      if (matchFinderType == MATCH_FINDER_TYPE_BT2) numHashBytes = 2;
      bt.setType(numHashBytes);
      matchFinder = bt;
    }
    literalEncoder.create(numLiteralPosStateBits, numLiteralContextBits);

    if (dictionarySize == dictionarySizePrev && numFastBytesPrev == numFastBytes) return;
    matchFinder.createMatchFinder(dictionarySize, NUM_OPTS, numFastBytes, Base.MATCH_MAX_LEN + 1);
    dictionarySizePrev = dictionarySize;
    numFastBytesPrev = numFastBytes;
  }

  /**
   * Constructs a new encoder instance with default dictionary size, fast-bytes setting, and BT4
   * match finder. Internal probability models and buffers are allocated lazily; {@link #create()}
   * and {@link #setStreams(InputStream, OutputStream)} must be invoked before compression.
   */
  public Encoder() {
    for (int i = 0; i < NUM_OPTS; i++) optimum[i] = new Optimal();
    for (int i = 0; i < Base.NUM_LEN_TO_POS_STATES; i++)
      posSlotEncoder[i] = new BitTreeEncoder(Base.NUM_POS_SLOT_BITS);
  }

  void init() {
    baseInit();
    rangeEncoder.init();

    org.sevenzip.compression.rangecoder.Encoder.initBitModels(isMatch);
    org.sevenzip.compression.rangecoder.Encoder.initBitModels(isRep0Long);
    org.sevenzip.compression.rangecoder.Encoder.initBitModels(isRep);
    org.sevenzip.compression.rangecoder.Encoder.initBitModels(isRepG0);
    org.sevenzip.compression.rangecoder.Encoder.initBitModels(isRepG1);
    org.sevenzip.compression.rangecoder.Encoder.initBitModels(isRepG2);
    org.sevenzip.compression.rangecoder.Encoder.initBitModels(posEncoders);

    literalEncoder.init();
    for (int i = 0; i < Base.NUM_LEN_TO_POS_STATES; i++) posSlotEncoder[i].init();

    lenEncoder.init(1 << posStateBits);
    repMatchLenEncoder.init(1 << posStateBits);

    posAlignEncoder.init();

    longestMatchWasFound = false;
    optimumEndIndex = 0;
    optimumCurrentIndex = 0;
    additionalOffset = 0;
  }

  int readMatchDistances() throws IOException {
    int lenRes = 0;
    numDistancePairs = matchFinder.getMatches(matchDistances);
    if (numDistancePairs > 0) {
      lenRes = matchDistances[numDistancePairs - 2];
      if (lenRes == numFastBytes)
        lenRes +=
            matchFinder.getMatchLen(
                lenRes - 1, matchDistances[numDistancePairs - 1], Base.MATCH_MAX_LEN - lenRes);
    }
    additionalOffset++;
    return lenRes;
  }

  void movePos(int num) throws IOException {
    if (num > 0) {
      matchFinder.skip(num);
      additionalOffset += num;
    }
  }

  int getRepLen1Price(int state, int posState) {
    return org.sevenzip.compression.rangecoder.Encoder.getPrice0(isRepG0[state])
        + org.sevenzip.compression.rangecoder.Encoder.getPrice0(
            isRep0Long[(state << Base.NUM_POS_STATES_BITS_MAX) + posState]);
  }

  int getPureRepPrice(int repIndex, int state, int posState) {
    int price;
    if (repIndex == 0) {
      price = org.sevenzip.compression.rangecoder.Encoder.getPrice0(isRepG0[state]);
      price +=
          org.sevenzip.compression.rangecoder.Encoder.getPrice1(
              isRep0Long[(state << Base.NUM_POS_STATES_BITS_MAX) + posState]);
    } else {
      price = org.sevenzip.compression.rangecoder.Encoder.getPrice1(isRepG0[state]);
      if (repIndex == 1)
        price += org.sevenzip.compression.rangecoder.Encoder.getPrice0(isRepG1[state]);
      else {
        price += org.sevenzip.compression.rangecoder.Encoder.getPrice1(isRepG1[state]);
        price += org.sevenzip.compression.rangecoder.Encoder.getPrice(isRepG2[state], repIndex - 2);
      }
    }
    return price;
  }

  int getRepPrice(int repIndex, int len, int state, int posState) {
    int price = repMatchLenEncoder.getPrice(len - Base.MATCH_MIN_LEN, posState);
    return price + getPureRepPrice(repIndex, state, posState);
  }

  int getPosLenPrice(int pos, int len, int posState) {
    int price;
    int lenToPosState = Base.getLenToPosState(len);
    if (pos < Base.NUM_FULL_DISTANCES)
      price = distancesPrices[(lenToPosState * Base.NUM_FULL_DISTANCES) + pos];
    else
      price =
          posSlotPrices[(lenToPosState << Base.NUM_POS_SLOT_BITS) + getPosSlot2(pos)]
              + alignPrices[pos & Base.ALIGN_MASK];
    return price + lenEncoder.getPrice(len - Base.MATCH_MIN_LEN, posState);
  }

  int backward(int cur) {
    optimumEndIndex = cur;
    int posMem = optimum[cur].posPrev;
    int backMem = optimum[cur].backPrev;
    do {
      if (optimum[cur].prev1IsChar) {
        optimum[posMem].makeAsChar();
        optimum[posMem].posPrev = posMem - 1;
        if (optimum[cur].prev2) {
          optimum[posMem - 1].prev1IsChar = false;
          optimum[posMem - 1].posPrev = optimum[cur].posPrev2;
          optimum[posMem - 1].backPrev = optimum[cur].backPrev2;
        }
      }
      int posPrev = posMem;
      int backCur = backMem;

      backMem = optimum[posPrev].backPrev;
      posMem = optimum[posPrev].posPrev;

      optimum[posPrev].backPrev = backCur;
      optimum[posPrev].posPrev = cur;
      cur = posPrev;
    } while (cur > 0);
    backRes = optimum[0].backPrev;
    optimumCurrentIndex = optimum[0].posPrev;
    return optimumCurrentIndex;
  }

  int[] reps = new int[Base.NUM_REP_DISTANCES];
  int[] repLens = new int[Base.NUM_REP_DISTANCES];
  int backRes;

  int getOptimum(int position) throws IOException {
    if (optimumEndIndex != optimumCurrentIndex) {
      int lenRes = optimum[optimumCurrentIndex].posPrev - optimumCurrentIndex;
      backRes = optimum[optimumCurrentIndex].backPrev;
      optimumCurrentIndex = optimum[optimumCurrentIndex].posPrev;
      return lenRes;
    }
    optimumCurrentIndex = optimumEndIndex = 0;

    int lenMain;
    int numDistancePairsLocal;
    if (!longestMatchWasFound) {
      lenMain = readMatchDistances();
    } else {
      lenMain = longestMatchLength;
      longestMatchWasFound = false;
    }
    numDistancePairsLocal = this.numDistancePairs;

    int numAvailableBytes = matchFinder.getNumAvailableBytes() + 1;
    if (numAvailableBytes < 2) {
      backRes = -1;
      return 1;
    }
    // No need to clamp here since this local value is not used afterward.

    int repMaxIndex = 0;
    int i;
    for (i = 0; i < Base.NUM_REP_DISTANCES; i++) {
      reps[i] = repDistances[i];
      repLens[i] = matchFinder.getMatchLen(-1, reps[i], Base.MATCH_MAX_LEN);
      if (repLens[i] > repLens[repMaxIndex]) repMaxIndex = i;
    }
    if (repLens[repMaxIndex] >= numFastBytes) {
      backRes = repMaxIndex;
      int lenRes = repLens[repMaxIndex];
      movePos(lenRes - 1);
      return lenRes;
    }

    if (lenMain >= numFastBytes) {
      backRes = matchDistances[numDistancePairsLocal - 1] + Base.NUM_REP_DISTANCES;
      movePos(lenMain - 1);
      return lenMain;
    }

    int lenEnd = initializePreludeAndReturnLenEnd(position, lenMain, repMaxIndex);
    if (lenEnd == 1) return 1;
    return runMainOptimumLoop(position, lenEnd);
  }

  private int initializePreludeAndReturnLenEnd(int position, int lenMain, int repMaxIndex) {
    byte currentByte = matchFinder.getIndexByte(-1);
    byte matchByte = matchFinder.getIndexByte(-repDistances[0] - 1 - 1);

    if (lenMain < 2 && currentByte != matchByte && repLens[repMaxIndex] < 2) {
      backRes = -1;
      return 1;
    }

    optimum[0].state = encoderState;
    int posState = (position & posStateMask);

    optimum[1].price =
        org.sevenzip.compression.rangecoder.Encoder.getPrice0(
                isMatch[(encoderState << Base.NUM_POS_STATES_BITS_MAX) + posState])
            + literalEncoder
                .getSubCoder(position, previousByte)
                // Use matchByte price model only when in a match state (not a literal state).
                .getPrice(!Base.isCharState(encoderState), matchByte, currentByte);
    optimum[1].makeAsChar();

    int matchPrice =
        org.sevenzip.compression.rangecoder.Encoder.getPrice1(
            isMatch[(encoderState << Base.NUM_POS_STATES_BITS_MAX) + posState]);
    int repMatchPrice =
        matchPrice + org.sevenzip.compression.rangecoder.Encoder.getPrice1(isRep[encoderState]);

    if (matchByte == currentByte) {
      int shortRepPrice = repMatchPrice + getRepLen1Price(encoderState, posState);
      if (shortRepPrice < optimum[1].price) {
        optimum[1].price = shortRepPrice;
        optimum[1].makeAsShortRep();
      }
    }

    int lenEnd = Math.max(lenMain, repLens[repMaxIndex]);

    if (lenEnd < 2) {
      backRes = optimum[1].backPrev;
      return 1;
    }

    optimum[1].posPrev = 0;
    optimum[0].backs0 = reps[0];
    optimum[0].backs1 = reps[1];
    optimum[0].backs2 = reps[2];
    optimum[0].backs3 = reps[3];

    fillInfinityFromLenEnd(lenEnd);
    initRepLenEntries(posState, repMatchPrice);

    int normalMatchPrice =
        matchPrice + org.sevenzip.compression.rangecoder.Encoder.getPrice0(isRep[encoderState]);
    int lenStart = ((repLens[0] >= 2) ? repLens[0] + 1 : 2);
    initNormalMatchEntries(lenMain, posState, normalMatchPrice, lenStart);

    return lenEnd;
  }

  private void fillInfinityFromLenEnd(int lenEnd) {
    int len = lenEnd;
    do {
      optimum[len--].price = INFINITY_PRICE;
    } while (len >= 2);
  }

  private void initRepLenEntries(int posState, int repMatchPrice) {
    for (int i = 0; i < Base.NUM_REP_DISTANCES; i++) {
      int repLen = repLens[i];
      if (repLen < 2) continue;
      int price = repMatchPrice + getPureRepPrice(i, encoderState, posState);
      do {
        int curAndLenPrice = price + repMatchLenEncoder.getPrice(repLen - 2, posState);
        Optimal optEntry = this.optimum[repLen];
        if (curAndLenPrice < optEntry.price) {
          optEntry.price = curAndLenPrice;
          optEntry.posPrev = 0;
          optEntry.backPrev = i;
          optEntry.prev1IsChar = false;
        }
      } while (--repLen >= 2);
    }
  }

  private void initNormalMatchEntries(
      int lenMain, int posState, int normalMatchPrice, int lenStart) {
    int len = lenStart;
    if (len > lenMain) return;
    int offs = 0;
    while (len > matchDistances[offs]) offs += 2;
    for (; ; len++) {
      int distance = matchDistances[offs + 1];
      int curAndLenPrice = normalMatchPrice + getPosLenPrice(distance, len, posState);
      Optimal optEntry = this.optimum[len];
      if (curAndLenPrice < optEntry.price) {
        optEntry.price = curAndLenPrice;
        optEntry.posPrev = 0;
        optEntry.backPrev = distance + Base.NUM_REP_DISTANCES;
        optEntry.prev1IsChar = false;
      }
      if (len == matchDistances[offs]) {
        offs += 2;
        if (offs == numDistancePairs) break;
      }
    }
  }

  private int runMainOptimumLoop(int position, int lenEnd) throws IOException {
    int cur = 0;
    while (true) {
      cur++;
      if (cur == lenEnd) return backward(cur);
      int newLen = readMatchDistances();
      if (newLen >= numFastBytes) {
        longestMatchLength = newLen;
        longestMatchWasFound = true;
        return backward(cur);
      }
      position++;
      int state = updateStateForCur(cur);
      optimum[cur].state = state;
      optimum[cur].backs0 = reps[0];
      optimum[cur].backs1 = reps[1];
      optimum[cur].backs2 = reps[2];
      optimum[cur].backs3 = reps[3];
      int curPrice = optimum[cur].price;

      byte currentByte = matchFinder.getIndexByte(-1);
      byte matchByte = matchFinder.getIndexByte(-reps[0] - 1 - 1);

      int posState = (position & posStateMask);

      int curAnd1Price =
          curPrice
              + org.sevenzip.compression.rangecoder.Encoder.getPrice0(
                  isMatch[(state << Base.NUM_POS_STATES_BITS_MAX) + posState])
              + literalEncoder
                  .getSubCoder(position, matchFinder.getIndexByte(-2))
                  // Use matchByte price model only when in a match state
                  .getPrice(!Base.isCharState(state), matchByte, currentByte);

      int matchPrice =
          curPrice
              + org.sevenzip.compression.rangecoder.Encoder.getPrice1(
                  isMatch[(state << Base.NUM_POS_STATES_BITS_MAX) + posState]);
      int repMatchPrice =
          matchPrice + org.sevenzip.compression.rangecoder.Encoder.getPrice1(isRep[state]);
      boolean nextIsChar =
          updateNextOptimumForCharAndShortRep(
              state, posState, cur, curAnd1Price, matchByte, currentByte, repMatchPrice);

      int numAvailableBytesFull = matchFinder.getNumAvailableBytes() + 1;
      numAvailableBytesFull = Math.min(NUM_OPTS - 1 - cur, numAvailableBytesFull);
      int numAvailableBytes = numAvailableBytesFull;

      if (numAvailableBytes < 2) continue;
      if (numAvailableBytes > numFastBytes) numAvailableBytes = numFastBytes;
      handleLiteralPlusRep0(
          new MatchContext(nextIsChar, matchByte, currentByte),
          new CurContext(state, cur, numAvailableBytesFull, curAnd1Price, position),
          lenEnd);

      RepProcessResult repResult =
          processRepCandidates(
              new RepCandidatesContext(
                  state,
                  position,
                  posState,
                  cur,
                  numAvailableBytesFull,
                  numAvailableBytes,
                  repMatchPrice),
              lenEnd);
      lenEnd = repResult.lenEnd;
      int startLen = repResult.startLen;

      NewLenAdjustResult adj = adjustNewLenAndPairs(newLen, numAvailableBytes);
      newLen = adj.newLen;
      lenEnd =
          processNormalMatches(
              new NormalMatchesContext(
                  state, position, posState, cur, numAvailableBytesFull, matchPrice),
              newLen,
              startLen,
              lenEnd,
              adj.numDistancePairsLocal);
    }
  }

  void writeEndMarker(int posState) throws IOException {
    if (!writeEndMark) return;

    rangeEncoder.encode(isMatch, (encoderState << Base.NUM_POS_STATES_BITS_MAX) + posState, 1);
    rangeEncoder.encode(isRep, encoderState, 0);
    encoderState = Base.stateUpdateMatch(encoderState);
    int len = Base.MATCH_MIN_LEN;
    lenEncoder.encode(rangeEncoder, 0, posState);
    int posSlot = (1 << Base.NUM_POS_SLOT_BITS) - 1;
    int lenToPosState = Base.getLenToPosState(len);
    posSlotEncoder[lenToPosState].encode(rangeEncoder, posSlot);
    int footerBits = 30;
    int posReduced = (1 << footerBits) - 1;
    rangeEncoder.encodeDirectBits(
        posReduced >> Base.NUM_ALIGN_BITS, footerBits - Base.NUM_ALIGN_BITS);
    posAlignEncoder.reverseEncode(rangeEncoder, posReduced & Base.ALIGN_MASK);
  }

  void flush(int nowPos) throws IOException {
    releaseMFStream();
    writeEndMarker(nowPos & posStateMask);
    rangeEncoder.flushData();
    rangeEncoder.flushStream();
  }

  private boolean handleStartOfStream() throws IOException {
    if (nowPos64 != 0) return false;
    if (matchFinder.getNumAvailableBytes() == 0) {
      flush((int) nowPos64);
      return true;
    }

    readMatchDistances();
    int posState = (int) (nowPos64) & posStateMask;
    rangeEncoder.encode(isMatch, (encoderState << Base.NUM_POS_STATES_BITS_MAX) + posState, 0);
    encoderState = Base.stateUpdateChar(encoderState);
    byte curByte = matchFinder.getIndexByte(-additionalOffset);
    literalEncoder.getSubCoder((int) (nowPos64), previousByte).encode(rangeEncoder, curByte);
    previousByte = curByte;
    additionalOffset--;
    nowPos64++;
    return false;
  }

  private void encodeMatchOrLiteral(int len, int pos, int posState, int complexState)
      throws IOException {
    if (len == 1 && pos == -1) {
      encodeLiteralBranch(complexState);
      return;
    }

    rangeEncoder.encode(isMatch, complexState, 1);
    if (pos < Base.NUM_REP_DISTANCES) {
      encodeRepBranch(len, pos, posState, complexState);
    } else {
      encodeMatchBranch(len, pos, posState);
    }
    previousByte = matchFinder.getIndexByte(len - 1 - additionalOffset);
  }

  private void encodeLiteralBranch(int complexState) throws IOException {
    rangeEncoder.encode(isMatch, complexState, 0);
    byte curByte = matchFinder.getIndexByte(-additionalOffset);
    LiteralEncoder.Encoder2 subCoder = literalEncoder.getSubCoder((int) nowPos64, previousByte);
    if (Base.isCharState(encoderState)) {
      // Literal state: encode without match context
      subCoder.encode(rangeEncoder, curByte);
    } else {
      // Match/repetition state: use match context
      byte matchByte = matchFinder.getIndexByte(-repDistances[0] - 1 - additionalOffset);
      subCoder.encodeMatched(rangeEncoder, matchByte, curByte);
    }
    previousByte = curByte;
    encoderState = Base.stateUpdateChar(encoderState);
  }

  private void encodeRepBranch(int len, int pos, int posState, int complexState)
      throws IOException {
    rangeEncoder.encode(isRep, encoderState, 1);
    if (pos == 0) {
      rangeEncoder.encode(isRepG0, encoderState, 0);
      if (len == 1) rangeEncoder.encode(isRep0Long, complexState, 0);
      else rangeEncoder.encode(isRep0Long, complexState, 1);
    } else {
      rangeEncoder.encode(isRepG0, encoderState, 1);
      if (pos == 1) rangeEncoder.encode(isRepG1, encoderState, 0);
      else {
        rangeEncoder.encode(isRepG1, encoderState, 1);
        rangeEncoder.encode(isRepG2, encoderState, pos - 2);
      }
    }
    if (len == 1) encoderState = Base.stateUpdateShortRep(encoderState);
    else {
      repMatchLenEncoder.encode(rangeEncoder, len - Base.MATCH_MIN_LEN, posState);
      encoderState = Base.stateUpdateRep(encoderState);
    }
    int distance = repDistances[pos];
    if (pos != 0) {
      for (int i = pos; i >= 1; i--) repDistances[i] = repDistances[i - 1];
      repDistances[0] = distance;
    }
  }

  private void encodeMatchBranch(int len, int pos, int posState) throws IOException {
    rangeEncoder.encode(isRep, encoderState, 0);
    encoderState = Base.stateUpdateMatch(encoderState);
    lenEncoder.encode(rangeEncoder, len - Base.MATCH_MIN_LEN, posState);
    pos -= Base.NUM_REP_DISTANCES;
    int posSlot = getPosSlot(pos);
    int lenToPosState = Base.getLenToPosState(len);
    posSlotEncoder[lenToPosState].encode(rangeEncoder, posSlot);

    if (posSlot >= Base.START_POS_MODEL_INDEX) {
      int footerBits = ((posSlot >> 1) - 1);
      int baseVal = ((2 | (posSlot & 1)) << footerBits);
      int posReduced = pos - baseVal;

      if (posSlot < Base.END_POS_MODEL_INDEX)
        BitTreeEncoder.reverseEncode(
            posEncoders, baseVal - posSlot - 1, rangeEncoder, footerBits, posReduced);
      else {
        rangeEncoder.encodeDirectBits(
            posReduced >> Base.NUM_ALIGN_BITS, footerBits - Base.NUM_ALIGN_BITS);
        posAlignEncoder.reverseEncode(rangeEncoder, posReduced & Base.ALIGN_MASK);
        alignPriceCount++;
      }
    }
    int distance = pos;
    for (int i = Base.NUM_REP_DISTANCES - 1; i >= 1; i--) repDistances[i] = repDistances[i - 1];
    repDistances[0] = distance;
    matchPriceCount++;
  }

  private boolean updateAndMaybeFlush(
      long progressPosValuePrev, long[] inSize, long[] outSize, boolean[] finished)
      throws IOException {
    if (matchPriceCount >= (1 << 7)) fillDistancesPrices();
    if (alignPriceCount >= Base.ALIGN_TABLE_SIZE) fillAlignPrices();
    inSize[0] = nowPos64;
    outSize[0] = rangeEncoder.getProcessedSizeAdd();
    if (matchFinder.getNumAvailableBytes() == 0) {
      flush((int) nowPos64);
      return true;
    }

    if (nowPos64 - progressPosValuePrev >= (1 << 12)) {
      isFinished = false;
      finished[0] = false;
      return true;
    }
    return false;
  }

  /**
   * Compresses a single logical block using the currently configured streams and updates progress
   * arrays in place.
   *
   * <p>This call advances internal position counters, emits literals or matches as needed, and
   * stops when the encoder determines a flush point or detects the end of input. Callers typically
   * loop on this method until {@code finished[0]} becomes {@code true}. The method expects the
   * input and output arrays to be at least length one and will overwrite index {@code 0} on each
   * invocation.
   *
   * @param inSize single-element array updated with total bytes consumed from the input stream in
   *     this invocation; must be non-null and length ≥ 1.
   * @param outSize single-element array receiving the encoded byte count written by the range
   *     encoder; must be non-null and length ≥ 1.
   * @param finished single-element boolean array set to {@code true} when the encoder finishes the
   *     entire stream or reaches a flush condition; must be non-null and length ≥ 1.
   * @throws IOException if reading from the input stream or writing encoded bytes fails at any
   *     point during processing.
   */
  public void codeOneBlock(long[] inSize, long[] outSize, boolean[] finished) throws IOException {
    inSize[0] = 0;
    outSize[0] = 0;
    finished[0] = true;

    if (inStream != null) {
      matchFinder.setStream(inStream);
      matchFinder.init();
      needReleaseMFStream = true;
      inStream = null;
    }

    if (isFinished) return;
    isFinished = true;

    long progressPosValuePrev = nowPos64;
    if (handleStartOfStream()) return;
    if (matchFinder.getNumAvailableBytes() == 0) {
      flush((int) nowPos64);
      return;
    }
    while (true) {
      int len = getOptimum((int) nowPos64);
      int pos = backRes;
      int posState = ((int) nowPos64) & posStateMask;
      int complexState = (encoderState << Base.NUM_POS_STATES_BITS_MAX) + posState;
      encodeMatchOrLiteral(len, pos, posState, complexState);
      additionalOffset -= len;
      nowPos64 += len;
      if (additionalOffset == 0
          && updateAndMaybeFlush(progressPosValuePrev, inSize, outSize, finished)) return;
    }
  }

  void releaseMFStream() {
    if (matchFinder != null && needReleaseMFStream) {
      matchFinder.releaseStream();
      needReleaseMFStream = false;
    }
  }

  void setOutStream(OutputStream outStream) {
    rangeEncoder.setStream(outStream);
  }

  void releaseOutStream() {
    rangeEncoder.releaseStream();
  }

  void releaseStreams() {
    releaseMFStream();
    releaseOutStream();
  }

  void setStreams(InputStream inStream, OutputStream outStream) {
    this.inStream = inStream;
    isFinished = false;
    create();
    setOutStream(outStream);
    init();

    fillDistancesPrices();
    fillAlignPrices();

    lenEncoder.setTableSize(numFastBytes + 1 - Base.MATCH_MIN_LEN);
    lenEncoder.updateTables(1 << posStateBits);
    repMatchLenEncoder.setTableSize(numFastBytes + 1 - Base.MATCH_MIN_LEN);
    repMatchLenEncoder.updateTables(1 << posStateBits);

    nowPos64 = 0;
  }

  long[] processedInSize = new long[1];
  long[] processedOutSize = new long[1];
  boolean[] finished = new boolean[1];

  /**
   * Compresses the entire {@link InputStream} to the provided {@link OutputStream}, reporting
   * progress through an optional callback.
   *
   * <p>The method initializes internal match finders, iteratively calls {@link
   * #codeOneBlock(long[], long[], boolean[])}, and guarantees that resources are released even when
   * exceptions occur. Compression stops when the input is exhausted or the encoder emits an
   * explicit end marker. The method is blocking and not thread-safe; invoke it from a dedicated
   * worker thread when used in asynchronous systems.
   *
   * @param inStream source of uncompressed bytes; must remain readable for the duration of the
   *     call; not closed by this method.
   * @param outStream destination for encoded bytes; must accept streaming writes; flushed and
   *     released when encoding completes.
   * @param progress optional progress reporter notified with cumulative in/out sizes after each
   *     block; may be {@code null} to disable callbacks.
   * @throws IOException if the encoder cannot read from the input or write to the output stream at
   *     any step of the compression loop.
   */
  public void code(InputStream inStream, OutputStream outStream, ICodeProgress progress)
      throws IOException {
    needReleaseMFStream = false;
    try {
      setStreams(inStream, outStream);
      while (true) {

        codeOneBlock(processedInSize, processedOutSize, finished);
        if (finished[0]) return;
        if (progress != null) {
          progress.setProgress(processedInSize[0], processedOutSize[0]);
        }
      }
    } finally {
      releaseStreams();
    }
  }

  /**
   * Byte length of the serialized LZMA property header emitted by {@link #writeCoderProperties}.
   */
  public static final int PROP_SIZE = 5;

  byte[] properties = new byte[PROP_SIZE];

  /**
   * Writes the five-byte LZMA property header describing literal and dictionary configuration to
   * the supplied stream.
   *
   * <p>The header encodes position state bits, literal position bits, literal context bits, and the
   * dictionary size in little-endian order, matching the canonical 7-Zip LZMA header layout.
   * Callers should invoke this before writing compressed data so decoders can reconstruct the same
   * settings.
   *
   * @param outStream destination stream that receives the property bytes; must remain writable
   *     throughout the call.
   * @throws IOException if the property bytes cannot be written to the provided stream.
   */
  public void writeCoderProperties(OutputStream outStream) throws IOException {
    properties[0] =
        (byte) ((posStateBits * 5 + numLiteralPosStateBits) * 9 + numLiteralContextBits);
    for (int i = 0; i < 4; i++) properties[1 + i] = (byte) (dictionarySize >> (8 * i));
    outStream.write(properties, 0, PROP_SIZE);
  }

  int[] tempPrices = new int[Base.NUM_FULL_DISTANCES];
  int matchPriceCount;

  void fillDistancesPrices() {
    for (int i = Base.START_POS_MODEL_INDEX; i < Base.NUM_FULL_DISTANCES; i++) {
      int posSlot = getPosSlot(i);
      int footerBits = ((posSlot >> 1) - 1);
      int baseVal = ((2 | (posSlot & 1)) << footerBits);
      tempPrices[i] =
          BitTreeEncoder.reverseGetPrice(
              posEncoders, baseVal - posSlot - 1, footerBits, i - baseVal);
    }

    for (int lenToPosState = 0; lenToPosState < Base.NUM_LEN_TO_POS_STATES; lenToPosState++) {
      int posSlot;
      BitTreeEncoder encoder = posSlotEncoder[lenToPosState];

      int st = (lenToPosState << Base.NUM_POS_SLOT_BITS);
      for (posSlot = 0; posSlot < distTableSize; posSlot++)
        posSlotPrices[st + posSlot] = encoder.getPrice(posSlot);
      for (posSlot = Base.END_POS_MODEL_INDEX; posSlot < distTableSize; posSlot++)
        posSlotPrices[st + posSlot] +=
            ((((posSlot >> 1) - 1) - Base.NUM_ALIGN_BITS)
                << org.sevenzip.compression.rangecoder.Encoder.NUM_BIT_PRICE_SHIFT_BITS);

      int st2 = lenToPosState * Base.NUM_FULL_DISTANCES;
      int i;
      for (i = 0; i < Base.START_POS_MODEL_INDEX; i++)
        distancesPrices[st2 + i] = posSlotPrices[st + i];
      for (; i < Base.NUM_FULL_DISTANCES; i++)
        distancesPrices[st2 + i] = posSlotPrices[st + getPosSlot(i)] + tempPrices[i];
    }
    matchPriceCount = 0;
  }

  void fillAlignPrices() {
    for (int i = 0; i < Base.ALIGN_TABLE_SIZE; i++)
      alignPrices[i] = posAlignEncoder.reverseGetPrice(i);
    alignPriceCount = 0;
  }

  /**
   * Sets the encoder algorithm profile, trading speed for compression ratio.
   *
   * <p>Valid values are {@code 0} (fast), {@code 1} (normal), and {@code 2} (maximum). Values
   * outside this range are ignored and the previous setting remains in effect. The choice affects
   * internal heuristics only; stream format compatibility is unchanged.
   *
   * @param algorithm profile selector in the inclusive range {@code 0..2}; other values are
   *     rejected without side effects.
   * @return {@code true} when the value is accepted and recorded; {@code false} when rejected.
   */
  public boolean setAlgorithm(int algorithm) {
    // Accept historical values 0..2 (0=fast, 1=normal, 2=max). Values outside this
    // range are rejected to match typical LZMA command-line expectations.
    return algorithm >= 0 && algorithm <= 2;
  }

  /**
   * Configures the dictionary size used by the match finder and probability models.
   *
   * <p>The supplied size must be between {@code 1 << Base.DIC_LOG_SIZE_MIN} and {@code 1 << 29}
   * inclusive. Larger dictionaries generally improve compression for long inputs but consume more
   * memory and initialization time. On success, the internal distance table size is recalculated to
   * maintain pricing consistency.
   *
   * @param dictionarySize desired dictionary in bytes; must fall within the supported range or the
   *     request is ignored.
   * @return {@code true} when the size is accepted and internal tables are updated; {@code false}
   *     when the value falls outside allowed bounds.
   */
  public boolean setDictionarySize(int dictionarySize) {
    int kDicLogSizeMaxCompress = 29;
    if (dictionarySize < (1 << Base.DIC_LOG_SIZE_MIN)
        || dictionarySize > (1 << kDicLogSizeMaxCompress)) return false;
    this.dictionarySize = dictionarySize;
    int dicLogSize = 0;
    while (dictionarySize > (1 << dicLogSize)) {
      dicLogSize++;
    }
    distTableSize = dicLogSize * 2;
    return true;
  }

  /**
   * Sets the fast-bytes threshold that bounds greedy match extension before falling back to the
   * optimal parser.
   *
   * <p>Valid values are between {@code 5} and {@code Base.MATCH_MAX_LEN} inclusive. Lower values
   * favor speed while higher values allow longer matches to be accepted eagerly. When the input is
   * out of range, the prior configuration is preserved.
   *
   * @param numFastBytes maximum number of bytes for quick match processing; must be within the
   *     allowed range to take effect.
   * @return {@code true} if the value is recorded; {@code false} when rejected as invalid.
   */
  public boolean setNumFastBytes(int numFastBytes) {
    if (numFastBytes < 5 || numFastBytes > Base.MATCH_MAX_LEN) return false;
    this.numFastBytes = numFastBytes;
    return true;
  }

  /**
   * Selects the match finder implementation used during compression.
   *
   * <p>Accepts {@link #MATCH_FINDER_TYPE_BT2} or {@link #MATCH_FINDER_TYPE_BT4}; values outside
   * {@code 0..2} are rejected. Changing the match finder after creation discards any cached match
   * finder state to ensure the new type is applied on the next {@link #create()} call.
   *
   * @param matchFinderIndex numeric identifier for the desired match finder; see constants for
   *     supported values.
   * @return {@code true} when the identifier is recognized and stored; {@code false} otherwise.
   */
  public boolean setMatchFinder(int matchFinderIndex) {
    if (matchFinderIndex < 0 || matchFinderIndex > 2) return false;
    int matchFinderIndexPrev = matchFinderType;
    matchFinderType = matchFinderIndex;
    if (matchFinder != null && matchFinderIndexPrev != matchFinderType) {
      dictionarySizePrev = -1;
      matchFinder = null;
    }
    return true;
  }

  /**
   * Configures literal context bits (lc), literal position bits (lp), and position state bits (pb)
   * that influence probability model selection.
   *
   * <p>Each value must be within the bounds defined by {@link Base#NUM_LIT_CONTEXT_BITS_MAX},
   * {@link Base#NUM_LIT_POS_STATES_BITS_ENCODING_MAX}, and {@link
   * Base#NUM_POS_STATES_BITS_ENCODING_MAX}. Accepted values update the corresponding masks used
   * during encoding; invalid inputs are rejected without altering existing state.
   *
   * @param lc literal context bits in the inclusive range {@code 0..8}; higher values improve
   *     textual compression at the cost of model size.
   * @param lp literal position bits in the inclusive range {@code 0..4}; useful for data with
   *     fixed-byte structures.
   * @param pb position state bits in the inclusive range {@code 0..4}; affects match/literal
   *     decision granularity.
   * @return {@code true} when all values are valid and applied; {@code false} when any argument is
   *     outside its supported range.
   */
  public boolean setLcLpPb(int lc, int lp, int pb) {
    if (lp < 0
        || lp > Base.NUM_LIT_POS_STATES_BITS_ENCODING_MAX
        || lc < 0
        || lc > Base.NUM_LIT_CONTEXT_BITS_MAX
        || pb < 0
        || pb > Base.NUM_POS_STATES_BITS_ENCODING_MAX) return false;
    numLiteralPosStateBits = lp;
    numLiteralContextBits = lc;
    posStateBits = pb;
    posStateMask = ((1) << posStateBits) - 1;
    return true;
  }

  /**
   * Enables or disables writing an explicit end-of-stream marker after the final encoded symbol.
   *
   * <p>When enabled, decoders can reliably detect the end of the compressed stream even if the
   * uncompressed size is unknown. Disabling the marker can be useful in container formats that
   * convey length separately.
   *
   * @param endMarkerMode {@code true} to append the end marker; {@code false} to omit it.
   */
  public void setEndMarkerMode(boolean endMarkerMode) {
    writeEndMark = endMarkerMode;
  }
}

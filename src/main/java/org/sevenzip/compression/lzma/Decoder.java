package org.sevenzip.compression.lzma;

import static org.sevenzip.compression.rangecoder.Decoder.initBitModels;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import org.sevenzip.compression.lz.OutWindow;
import org.sevenzip.compression.rangecoder.BitTreeDecoder;

/**
 * Streaming LZMA decoder that materializes compressed input into an {@link OutWindow} backed output
 * buffer.
 *
 * <p>The decoder drives the reference range-coder implementation and LZ-style repetition tracking
 * to reconstruct bytes in order. Callers typically configure the instance once with {@link
 * #setDecoderProperties(byte[])} and reuse it across streams by providing fresh input and output
 * streams to {@link #code(InputStream, OutputStream, long)}. Internally the type manages
 * probability models for literals, match lengths, and distances, along with a sliding window to
 * satisfy back-references. The class is stateful and <strong>not</strong> thread-safe; confine each
 * instance to a single decoding pipeline or provide external synchronization if shared.
 *
 * <p>Lifecycle expectations:
 *
 * <ul>
 *   <li>Create an instance and configure properties (dictionary size and lc/lp/pb parameters).
 *   <li>Invoke {@code code(...)} with an input stream positioned at the start of an LZMA payload
 *       and an output stream ready to receive plain bytes.
 *   <li>Repeat with new streams as needed; the decoder reinitializes internal models per call.
 * </ul>
 *
 * <p>Performance considerations: buffer sizes follow the encoded dictionary; decoding proceeds
 * byte-by-byte with frequent small range-coder updates. Avoid sharing the same {@link
 * java.io.InputStream} or {@link java.io.OutputStream} across concurrent decodes. Errors surfaced
 * as {@link IOException} indicate malformed input or I/O failures and leave the instance in an
 * undefined state until reinitialized via a new {@link #code(InputStream, OutputStream, long)}
 * call.
 */
public class Decoder {
  static class LenDecoder {
    short[] choice = new short[2];
    BitTreeDecoder[] lowCoder = new BitTreeDecoder[Base.NUM_POS_STATES_MAX];
    BitTreeDecoder[] midCoder = new BitTreeDecoder[Base.NUM_POS_STATES_MAX];
    BitTreeDecoder highCoder = new BitTreeDecoder(Base.NUM_HIGH_LEN_BITS);
    int numPosStates = 0;

    public void create(int numPosStates) {
      for (; this.numPosStates < numPosStates; this.numPosStates++) {
        lowCoder[this.numPosStates] = new BitTreeDecoder(Base.NUM_LOW_LEN_BITS);
        midCoder[this.numPosStates] = new BitTreeDecoder(Base.NUM_MID_LEN_BITS);
      }
    }

    public void init() {
      initBitModels(choice);
      for (int posState = 0; posState < numPosStates; posState++) {
        lowCoder[posState].init();
        midCoder[posState].init();
      }
      highCoder.init();
    }

    public int decode(org.sevenzip.compression.rangecoder.Decoder rangeDecoder, int posState)
        throws IOException {
      if (rangeDecoder.decodeBit(choice, 0) == 0) return lowCoder[posState].decode(rangeDecoder);
      int symbol = Base.NUM_LOW_LEN_SYMBOLS;
      if (rangeDecoder.decodeBit(choice, 1) == 0) symbol += midCoder[posState].decode(rangeDecoder);
      else symbol += Base.NUM_MID_LEN_SYMBOLS + highCoder.decode(rangeDecoder);
      return symbol;
    }
  }

  static class LiteralDecoder {
    static class Decoder2 {
      short[] decoders = new short[0x300];

      public void init() {
        initBitModels(decoders);
      }

      public byte decodeNormal(org.sevenzip.compression.rangecoder.Decoder rangeDecoder)
          throws IOException {
        int symbol = 1;
        do symbol = (symbol << 1) | rangeDecoder.decodeBit(decoders, symbol);
        while (symbol < 0x100);
        return (byte) symbol;
      }

      public byte decodeWithMatchByte(
          org.sevenzip.compression.rangecoder.Decoder rangeDecoder, byte matchByte)
          throws IOException {
        int symbol = 1;
        do {
          int matchBit = (matchByte >> 7) & 1;
          matchByte = (byte) (matchByte << 1);
          int bit = rangeDecoder.decodeBit(decoders, ((1 + matchBit) << 8) + symbol);
          symbol = (symbol << 1) | bit;
          if (matchBit != bit) {
            while (symbol < 0x100)
              symbol = (symbol << 1) | rangeDecoder.decodeBit(decoders, symbol);
            break;
          }
        } while (symbol < 0x100);
        return (byte) symbol;
      }
    }

    Decoder2[] coders;
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
      coders = new Decoder2[numStates];
      for (int i = 0; i < numStates; i++) coders[i] = new Decoder2();
    }

    public void init() {
      int numStates = 1 << (numPrevBits + numPosBits);
      for (int i = 0; i < numStates; i++) coders[i].init();
    }

    Decoder2 getDecoder(int pos, byte prevByte) {
      return coders[((pos & posMask) << numPrevBits) + ((prevByte & 0xFF) >>> (8 - numPrevBits))];
    }
  }

  OutWindow outWindow = new OutWindow();
  org.sevenzip.compression.rangecoder.Decoder rangeDecoder =
      new org.sevenzip.compression.rangecoder.Decoder();

  short[] isMatchDecoders = new short[Base.NUM_STATES << Base.NUM_POS_STATES_BITS_MAX];
  short[] isRepDecoders = new short[Base.NUM_STATES];
  short[] isRepG0Decoders = new short[Base.NUM_STATES];
  short[] isRepG1Decoders = new short[Base.NUM_STATES];
  short[] isRepG2Decoders = new short[Base.NUM_STATES];
  short[] isRep0LongDecoders = new short[Base.NUM_STATES << Base.NUM_POS_STATES_BITS_MAX];

  BitTreeDecoder[] posSlotDecoder = new BitTreeDecoder[Base.NUM_LEN_TO_POS_STATES];
  short[] posDecoders = new short[Base.NUM_FULL_DISTANCES - Base.END_POS_MODEL_INDEX];

  BitTreeDecoder posAlignDecoder = new BitTreeDecoder(Base.NUM_ALIGN_BITS);

  LenDecoder lenDecoder = new LenDecoder();
  LenDecoder repLenDecoder = new LenDecoder();

  LiteralDecoder literalDecoder = new LiteralDecoder();

  int dictionarySize = -1;
  int dictionarySizeCheck = -1;

  int posStateMask;

  /**
   * Creates a decoder with uninitialized models and window buffers sized on first configuration.
   *
   * <p>The constructor performs no I/O and allocates only constant-size probability structures; the
   * dictionary buffer is deferred to the first successful {@link #setDecoderProperties(byte[])} or
   * {@link #setDictionarySize(int)} call. Instances are mutable and should be configured before
   * decoding to avoid validation failures.
   */
  public Decoder() {
    for (int i = 0; i < Base.NUM_LEN_TO_POS_STATES; i++)
      posSlotDecoder[i] = new BitTreeDecoder(Base.NUM_POS_SLOT_BITS);
  }

  boolean setDictionarySize(int dictionarySize) {
    if (dictionarySize < 0) return false;
    if (this.dictionarySize != dictionarySize) {
      this.dictionarySize = dictionarySize;
      dictionarySizeCheck = Math.max(this.dictionarySize, 1);
      outWindow.create(Math.max(dictionarySizeCheck, (1 << 12)));
    }
    return true;
  }

  boolean setLcLpPb(int lc, int lp, int pb) {
    if (lc > Base.NUM_LIT_CONTEXT_BITS_MAX || lp > 4 || pb > Base.NUM_POS_STATES_BITS_MAX)
      return false;
    literalDecoder.create(lp, lc);
    int numPosStates = 1 << pb;
    lenDecoder.create(numPosStates);
    repLenDecoder.create(numPosStates);
    posStateMask = numPosStates - 1;
    return true;
  }

  void init() throws IOException {
    outWindow.init(false);

    initBitModels(isMatchDecoders);
    initBitModels(isRep0LongDecoders);
    initBitModels(isRepDecoders);
    initBitModels(isRepG0Decoders);
    initBitModels(isRepG1Decoders);
    initBitModels(isRepG2Decoders);
    initBitModels(posDecoders);

    literalDecoder.init();
    int i;
    for (i = 0; i < Base.NUM_LEN_TO_POS_STATES; i++) posSlotDecoder[i].init();
    lenDecoder.init();
    repLenDecoder.init();
    posAlignDecoder.init();
    rangeDecoder.init();
  }

  /**
   * Decodes a single LZMA stream from {@code inStream} into {@code outStream} until {@code outSize}
   * bytes are produced or the stream signals end-of-data.
   *
   * <p>This method resets internal probability models, attaches the provided streams, and then
   * iteratively emits literals or back-references according to the encoded payload. The operation
   * is blocking and must not be called concurrently on the same instance. A negative {@code
   * outSize} requests decoding until the end marker; non-negative values cap output length and
   * allow early termination when the requested byte count is reached.
   *
   * <p>Example usage:
   *
   * <pre>{@code
   * Decoder decoder = new Decoder();
   * decoder.setDecoderProperties(props);
   * boolean ok = decoder.code(in, out, -1);
   * }</pre>
   *
   * @param inStream source of compressed bytes; must be positioned at the beginning of the LZMA
   *     stream and remain readable for the duration of decoding.
   * @param outStream destination for decompressed bytes; must accept writes and remain open until
   *     decoding completes, though it is not closed by this method.
   * @param outSize number of bytes to decode, or a negative value to continue until the encoded end
   *     marker; values are interpreted as a 64-bit signed length.
   * @return {@code true} when decoding finishes without validation errors; {@code false} if the
   *     input violates format invariants before reaching the requested length.
   * @throws IOException if reading from {@code inStream} or writing to {@code outStream} fails, or
   *     if model initialization cannot proceed due to upstream I/O errors.
   */
  public boolean code(InputStream inStream, OutputStream outStream, long outSize)
      throws IOException {
    rangeDecoder.setStream(inStream);
    outWindow.setStream(outStream);
    init();

    int state = Base.STATE_INIT;
    Reps reps = new Reps();

    long nowPos64 = 0;
    byte prevByte = 0;
    while (outSize < 0 || nowPos64 < outSize) {
      int posState = (int) nowPos64 & posStateMask;
      if (isLiteralState(state, posState)) {
        prevByte = decodeLiteral(nowPos64, prevByte, state, reps.rep0);
        outWindow.putByte(prevByte);
        state = Base.stateUpdateChar(state);
        nowPos64++;
      } else {
        LenState step = nextLenAndState(state, posState, reps);
        state = step.state;
        int len = step.len;
        int v = validateRep0(nowPos64, reps.rep0);
        if (v != 0) {
          if (v > 0) break; // end marker
          return false;
        }
        outWindow.copyBlock(reps.rep0, len);
        nowPos64 += len;
        prevByte = outWindow.getByte(0);
      }
    }
    outWindow.flush();
    outWindow.releaseStream();
    rangeDecoder.releaseStream();
    return true;
  }

  private boolean isLiteralState(int state, int posState) throws IOException {
    return rangeDecoder.decodeBit(
            isMatchDecoders, (state << Base.NUM_POS_STATES_BITS_MAX) + posState)
        == 0;
  }

  private boolean isRep(int state) throws IOException {
    return rangeDecoder.decodeBit(isRepDecoders, state) == 1;
  }

  private byte decodeLiteral(long nowPos64, byte prevByte, int state, int rep0) throws IOException {
    LiteralDecoder.Decoder2 decoder2 = literalDecoder.getDecoder((int) nowPos64, prevByte);
    // In literal (non-match) states, decode without match context; otherwise use match-byte path.
    if (Base.isCharState(state)) return decoder2.decodeNormal(rangeDecoder);
    return decoder2.decodeWithMatchByte(rangeDecoder, outWindow.getByte(rep0));
  }

  private static final class Reps {
    int rep0 = 0;
    int rep1 = 0;
    int rep2 = 0;
    int rep3 = 0;
  }

  private record RepResult(int len, int state) {}

  private RepResult decodeRep(int state, int posState, Reps r) throws IOException {
    int len = 0;
    if (rangeDecoder.decodeBit(isRepG0Decoders, state) == 0) {
      if (rangeDecoder.decodeBit(
              isRep0LongDecoders, (state << Base.NUM_POS_STATES_BITS_MAX) + posState)
          == 0) {
        state = Base.stateUpdateShortRep(state);
        len = 1;
      }
    } else {
      int distance;
      if (rangeDecoder.decodeBit(isRepG1Decoders, state) == 0) distance = r.rep1;
      else {
        if (rangeDecoder.decodeBit(isRepG2Decoders, state) == 0) distance = r.rep2;
        else {
          distance = r.rep3;
          r.rep3 = r.rep2;
        }
        r.rep2 = r.rep1;
      }
      r.rep1 = r.rep0;
      r.rep0 = distance;
    }
    if (len == 0) {
      len = repLenDecoder.decode(rangeDecoder, posState) + Base.MATCH_MIN_LEN;
      state = Base.stateUpdateRep(state);
    }
    return new RepResult(len, state);
  }

  private record MatchResult(int len, int state) {}

  private MatchResult decodeMatch(int state, int posState, Reps r) throws IOException {
    r.rep3 = r.rep2;
    r.rep2 = r.rep1;
    r.rep1 = r.rep0;
    int len = Base.MATCH_MIN_LEN + lenDecoder.decode(rangeDecoder, posState);
    state = Base.stateUpdateMatch(state);
    int posSlot = posSlotDecoder[Base.getLenToPosState(len)].decode(rangeDecoder);
    if (posSlot >= Base.START_POS_MODEL_INDEX) {
      int numDirectBits = (posSlot >> 1) - 1;
      r.rep0 = ((2 | (posSlot & 1)) << numDirectBits);
      if (posSlot < Base.END_POS_MODEL_INDEX)
        r.rep0 +=
            BitTreeDecoder.reverseDecode(
                posDecoders, r.rep0 - posSlot - 1, rangeDecoder, numDirectBits);
      else {
        r.rep0 +=
            (rangeDecoder.decodeDirectBits(numDirectBits - Base.NUM_ALIGN_BITS)
                << Base.NUM_ALIGN_BITS);
        r.rep0 += posAlignDecoder.reverseDecode(rangeDecoder);
      }
    } else r.rep0 = posSlot;
    return new MatchResult(len, state);
  }

  private int validateRep0(long nowPos64, int rep0) {
    if (rep0 < 0) return (rep0 == -1) ? 1 : -1;
    if (rep0 >= nowPos64 || rep0 >= dictionarySizeCheck) return -1;
    return 0;
  }

  private record LenState(int len, int state) {}

  private LenState nextLenAndState(int state, int posState, Reps reps) throws IOException {
    if (isRep(state)) {
      RepResult rep = decodeRep(state, posState, reps);
      return new LenState(rep.len, rep.state);
    } else {
      MatchResult match = decodeMatch(state, posState, reps);
      return new LenState(match.len, match.state);
    }
  }

  /**
   * Applies the lc/lp/pb parameters and dictionary size encoded in a five-byte LZMA properties
   * header.
   *
   * <p>The method interprets the first byte as packed literal-context, literal-position, and
   * position-state bits, then reads a little-endian 32-bit dictionary size from the remaining
   * bytes. It initializes probability models and buffers accordingly. Callers should invoke this
   * once per decoder configuration; repeated calls update the state and may reallocate the output
   * window when dictionary sizes change.
   *
   * @param properties five-byte property block from the start of an LZMA stream; must contain
   *     packed lc/lp/pb in the first byte followed by a 32-bit little-endian dictionary size.
   * @return {@code true} when parameters are valid and internal structures are updated; {@code
   *     false} when validation fails due to length or out-of-range values.
   */
  public boolean setDecoderProperties(byte[] properties) {
    if (properties.length < 5) return false;
    int val = properties[0] & 0xFF;
    int lc = val % 9;
    int remainder = val / 9;
    int lp = remainder % 5;
    int pb = remainder / 5;
    int dictSize = 0;
    for (int i = 0; i < 4; i++) dictSize += (properties[1 + i] & 0xFF) << (i * 8);
    if (!setLcLpPb(lc, lp, pb)) return false;
    return setDictionarySize(dictSize);
  }
}

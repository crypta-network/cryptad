// Base.java

package org.sevenzip.compression.lzma;

public class Base {
  public static final int NUM_REP_DISTANCES = 4;
  public static final int NUM_STATES = 12;
  public static final int STATE_INIT = 0;

  /** Transition state for a literal (char) emission. */
  public static int stateUpdateChar(int index) {
    if (index < 4) return 0;
    if (index < 10) return index - 3;
    return index - 6;
  }

  /** Transition state for a match. */
  public static int stateUpdateMatch(int index) {
    return (index < 7 ? 7 : 10);
  }

  /** Transition state for a repeated match. */
  public static int stateUpdateRep(int index) {
    return (index < 7 ? 8 : 11);
  }

  /** Transition state for a short repeated match. */
  public static int stateUpdateShortRep(int index) {
    return (index < 7 ? 9 : 11);
  }

  /**
   * True when the given state is a "non-match" (literal) state. Kept to align with existing callers
   * (semantics: index >= 7).
   */
  public static boolean isCharState(int index) {
    return index >= 7;
  }

  public static final int NUM_POS_SLOT_BITS = 6;
  public static final int DIC_LOG_SIZE_MIN = 0;
  /*
   * Note: historical constants (kDicLogSizeMax, kDistTableSizeMax) were intentionally removed
   * as they are unused in this codebase.
   */

  public static final int NUM_LEN_TO_POS_STATES_BITS = 2; // it's for speed optimization
  public static final int NUM_LEN_TO_POS_STATES = 1 << NUM_LEN_TO_POS_STATES_BITS;

  public static final int MATCH_MIN_LEN = 2;

  /** Computes the length-to-position state bucket. */
  public static int getLenToPosState(int len) {
    len -= MATCH_MIN_LEN;
    if (len < NUM_LEN_TO_POS_STATES) return len;
    return NUM_LEN_TO_POS_STATES - 1;
  }

  public static final int NUM_ALIGN_BITS = 4;
  public static final int ALIGN_TABLE_SIZE = 1 << NUM_ALIGN_BITS;
  public static final int ALIGN_MASK = (ALIGN_TABLE_SIZE - 1);

  public static final int START_POS_MODEL_INDEX = 4;
  public static final int END_POS_MODEL_INDEX = 14;

  public static final int NUM_FULL_DISTANCES = 1 << (END_POS_MODEL_INDEX / 2);

  public static final int NUM_LIT_POS_STATES_BITS_ENCODING_MAX = 4;
  public static final int NUM_LIT_CONTEXT_BITS_MAX = 8;

  public static final int NUM_POS_STATES_BITS_MAX = 4;
  public static final int NUM_POS_STATES_MAX = (1 << NUM_POS_STATES_BITS_MAX);
  public static final int NUM_POS_STATES_BITS_ENCODING_MAX = 4;
  public static final int NUM_POS_STATES_ENCODING_MAX = (1 << NUM_POS_STATES_BITS_ENCODING_MAX);

  public static final int NUM_LOW_LEN_BITS = 3;
  public static final int NUM_MID_LEN_BITS = 3;
  public static final int NUM_HIGH_LEN_BITS = 8;
  public static final int NUM_LOW_LEN_SYMBOLS = 1 << NUM_LOW_LEN_BITS;
  public static final int NUM_MID_LEN_SYMBOLS = 1 << NUM_MID_LEN_BITS;
  public static final int NUM_LEN_SYMBOLS =
      NUM_LOW_LEN_SYMBOLS + NUM_MID_LEN_SYMBOLS + (1 << NUM_HIGH_LEN_BITS);
  public static final int MATCH_MAX_LEN = MATCH_MIN_LEN + NUM_LEN_SYMBOLS - 1;

  private Base() {}
}

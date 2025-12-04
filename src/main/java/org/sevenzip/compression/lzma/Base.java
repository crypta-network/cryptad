// Base.java

package org.sevenzip.compression.lzma;

/**
 * Provides shared constants and finite-state helper routines for the LZMA encoder/decoder state
 * machine.
 *
 * <p>This type centralizes the numeric configuration for the reference implementation, including
 * literal/match state encodings, distance slot geometry, and length bucket thresholds. Consumers
 * typically read these values rather than copy literals so that encoder and decoder branches remain
 * synchronized when tuning or upgrading the algorithm. The class is intentionally stateless and
 * thread-safe; all members are {@code static} constants or pure functions. Typical usage patterns
 * include selecting the next state after emitting a literal or match, determining whether a state
 * is considered a literal state, and mapping a match length to the correct position-model bucket to
 * drive probability model selection. Because the values mirror the original LZMA specification,
 * they preserve binary compatibility with existing compressed streams while keeping the
 * implementation straightforward to reason about across platforms.
 *
 * <ul>
 *   <li>Responsibilities: expose canonical constants and state transition helpers.
 *   <li>Mutability: immutable; safe to share across threads without coordination.
 *   <li>Performance: helpers avoid branching depth and do not allocate.
 * </ul>
 */
public class Base {
  /**
   * Count of remembered repetition distances used by the encoder/decoder; keeps track of the last
   * four distances to accelerate repeated match detection. The value is fixed at four to mirror the
   * reference LZMA design and should match associated probability models.
   */
  public static final int NUM_REP_DISTANCES = 4;

  /**
   * Total number of possible finite states within the simplified LZMA state machine. States 0–6
   * represent literal-emission contexts; states 7–11 represent various match/repetition contexts.
   * Algorithms rely on this size to bound arrays and normalize state transitions.
   */
  public static final int NUM_STATES = 12;

  /**
   * Initial state identifier assigned when a coder starts or is reset. Using zero guarantees entry
   * into the literal branch until matches are observed, matching historical implementations and
   * test vectors.
   */
  public static final int STATE_INIT = 0;

  /**
   * Transition state for a literal (char) emission.
   *
   * <p>Determines the next finite-state index after emitting a literal. For low-index states (0–3)
   * the machine returns to the initial literal state. For mid-range states (4–9) it advances toward
   * match-oriented states to reflect observed patterns. For higher states it shifts toward the
   * repetition branch. The function is pure and side effect free.
   *
   * @param index current state index, expected to be within {@code 0..NUM_STATES-1}; values outside
   *     the range are accepted but mapped using the same arithmetic without validation.
   * @return next state index after processing a literal; callers should reuse the result
   *     immediately to maintain encoder/decoder alignment.
   */
  public static int stateUpdateChar(int index) {
    if (index < 4) return 0;
    if (index < 10) return index - 3;
    return index - 6;
  }

  /**
   * Transition state for a match.
   *
   * <p>Advances the finite-state machine when a full match (non-repetition) token is emitted.
   * States below seven move into the primary match state, while higher states move into an
   * alternate match cluster, preserving legacy probability distributions.
   *
   * @param index current state index before emitting a match token; typically the previous state of
   *     the LZMA coder.
   * @return match state index {@code 7} for literal-dominated states or {@code 10} for
   *     match-oriented states, preserving the original split.
   */
  public static int stateUpdateMatch(int index) {
    return (index < 7 ? 7 : 10);
  }

  /**
   * Transition state for a repeated match.
   *
   * <p>Used when reusing one of the recent distances tracked by the coder. States below seven move
   * into repetition state {@code 8}; others move into repetition state {@code 11}. The logic
   * mirrors the classic implementation and keeps repetition probabilities isolated from first-time
   * matches.
   *
   * @param index state index prior to handling a repeated distance; expected within {@code
   *     0..NUM_STATES-1} but not strictly validated.
   * @return next repetition state index ({@code 8} or {@code 11}) suitable for immediate reuse by
   *     the caller.
   */
  public static int stateUpdateRep(int index) {
    return (index < 7 ? 8 : 11);
  }

  /**
   * Transition state for a short repeated match.
   *
   * <p>Short repetitions represent single-byte matches to a recent distance. Literal-weighted
   * states transition to index {@code 9}; existing match-weighted states transition to index {@code
   * 11}. This distinction helps maintain accurate probability models for very short repeats versus
   * longer repetitions.
   *
   * @param index current state index prior to processing a short repetition token; typically
   *     derived from the previous coding step.
   * @return next state index ({@code 9} or {@code 11}) for continued coding after the short repeat.
   */
  public static int stateUpdateShortRep(int index) {
    return (index < 7 ? 9 : 11);
  }

  /**
   * Returns true when the given state is a literal (non-match) state.
   *
   * <p>Legacy LZMA semantics: states {@code 0..6} represent literal states and {@code 7..11}
   * represent match/repetition states. Some encoder/decoder branches depend on this exact split. Do
   * not invert this condition.
   *
   * @param index state index under evaluation; values under seven are considered literal, values
   *     seven or above are treated as match-capable.
   * @return {@code true} when the index denotes a literal state, otherwise {@code false}; callers
   *     can branch encoder/decoder logic accordingly.
   */
  public static boolean isCharState(int index) {
    return index < 7;
  }

  /**
   * Number of bits used to encode the position slot for distance modeling. Six bits provide 64
   * distinct slots, balancing precision and table size for typical LZMA distance coding.
   */
  public static final int NUM_POS_SLOT_BITS = 6;

  /**
   * Minimum dictionary log size supported by the implementation. A value of zero represents a
   * single-byte dictionary and serves mainly as a theoretical lower bound for validation paths.
   */
  public static final int DIC_LOG_SIZE_MIN = 0;

  /*
   * Note: historical constants (kDicLogSizeMax, kDistTableSizeMax) were intentionally removed
   * as they are unused in this codebase.
   */

  /**
   * Number of bits dedicated to mapping match lengths to position-state buckets, primarily chosen
   * for speed. Two bits create four buckets and keep lookup tables compact.
   */
  public static final int NUM_LEN_TO_POS_STATES_BITS = 2; // it's for speed optimization

  /**
   * Total count of length-to-position states derived from {@link #NUM_LEN_TO_POS_STATES_BITS}. With
   * two bits, four buckets are available for grouping match lengths when selecting probability
   * models.
   */
  public static final int NUM_LEN_TO_POS_STATES = 1 << NUM_LEN_TO_POS_STATES_BITS;

  /**
   * Minimum match length recognized by the coder. The LZMA format treats length values below two as
   * literals; matches start at two bytes to maintain format compatibility.
   */
  public static final int MATCH_MIN_LEN = 2;

  /**
   * Computes the length-to-position state bucket.
   *
   * <p>Maps a raw match length to one of the small number of position-state buckets used by
   * distance models. Lengths shorter than {@link #MATCH_MIN_LEN} are normalized to zero after
   * subtraction. Values exceeding the available buckets clamp to the last bucket to avoid array
   * overflows.
   *
   * @param len match length expressed in bytes; should be at least {@link #MATCH_MIN_LEN} for
   *     typical callers, though smaller values are accepted and treated as zero-length after
   *     normalization.
   * @return bucket index within {@link #NUM_LEN_TO_POS_STATES}; the maximum value is the last
   *     bucket when the length exceeds the available range.
   */
  public static int getLenToPosState(int len) {
    len -= MATCH_MIN_LEN;
    if (len < NUM_LEN_TO_POS_STATES) return len;
    return NUM_LEN_TO_POS_STATES - 1;
  }

  /**
   * Number of bits dedicated to the alignment portion of distance coding. Four bits allow sixteen
   * alignment values, controlling fine-grained distance reconstruction during decoding.
   */
  public static final int NUM_ALIGN_BITS = 4;

  /**
   * Size of the alignment lookup table, computed from {@link #NUM_ALIGN_BITS}. With four bits, the
   * table contains sixteen entries and remains cache-friendly.
   */
  public static final int ALIGN_TABLE_SIZE = 1 << NUM_ALIGN_BITS;

  /**
   * Bitmask used to extract the alignment portion from a coded distance value. It equals the
   * alignment table size minus one, making it suitable for efficient bitwise masking operations.
   */
  public static final int ALIGN_MASK = (ALIGN_TABLE_SIZE - 1);

  /**
   * Start index (inclusive) for position models that receive specialized treatment. Distances with
   * slot indices below this value use simpler probability trees; larger distances rely on extended
   * slot encoding.
   */
  public static final int START_POS_MODEL_INDEX = 4;

  /**
   * End index (inclusive) for the base position models. Distances at or above this index transition
   * to the full-distance modeling path, enabling broader range representation.
   */
  public static final int END_POS_MODEL_INDEX = 14;

  /**
   * Total number of explicit distance values represented without additional bit trees, derived from
   * the end position model index. Distances beyond this count require extra bits during coding.
   */
  public static final int NUM_FULL_DISTANCES = 1 << (END_POS_MODEL_INDEX / 2);

  /**
   * Maximum bits allowed for literal position state selection during encoding, limiting how finely
   * position-dependent literal contexts are partitioned.
   */
  public static final int NUM_LIT_POS_STATES_BITS_ENCODING_MAX = 4;

  /**
   * Maximum number of bits used to derive literal contexts from preceding bytes. Eight bits support
   * up to 256 distinct literal contexts, enabling nuanced probability modeling when memory permits.
   */
  public static final int NUM_LIT_CONTEXT_BITS_MAX = 8;

  /**
   * Maximum bits for position states used by decoders, constraining table sizes and probability
   * model allocations during runtime.
   */
  public static final int NUM_POS_STATES_BITS_MAX = 4;

  /**
   * Maximum count of position states derived from {@link #NUM_POS_STATES_BITS_MAX}. With four bits
   * the encoder/decoder can differentiate up to sixteen positions for context modeling.
   */
  public static final int NUM_POS_STATES_MAX = (1 << NUM_POS_STATES_BITS_MAX);

  /**
   * Maximum bits for position states specifically during encoding, mirroring decoder constraints to
   * keep model sizes consistent across the pipeline.
   */
  public static final int NUM_POS_STATES_BITS_ENCODING_MAX = 4;

  /**
   * Maximum number of position states available to the encoder, computed from the encoding bit
   * limit. Ensures symmetry with decoder expectations and bounds memory usage.
   */
  public static final int NUM_POS_STATES_ENCODING_MAX = (1 << NUM_POS_STATES_BITS_ENCODING_MAX);

  /**
   * Number of bits allocated to the low-length probability subrange. Three bits yield eight symbols
   * for short matches, enabling fast lookups for common short lengths.
   */
  public static final int NUM_LOW_LEN_BITS = 3;

  /**
   * Number of bits allocated to the mid-length probability subrange. Also, three bits, providing
   * eight symbols that fill the space between low and high length ranges.
   */
  public static final int NUM_MID_LEN_BITS = 3;

  /**
   * Number of bits allocated to the high-length probability subrange. Eight bits allow 256 symbols
   * to represent the remaining long match lengths beyond the low and mid-ranges.
   */
  public static final int NUM_HIGH_LEN_BITS = 8;

  /**
   * Count of symbols in the low-length range, computed from {@link #NUM_LOW_LEN_BITS}. Provides a
   * quick reference for allocating probability arrays for short matches.
   */
  public static final int NUM_LOW_LEN_SYMBOLS = 1 << NUM_LOW_LEN_BITS;

  /**
   * Count of symbols in the mid-length range, computed from {@link #NUM_MID_LEN_BITS}. Mirrors the
   * low-length calculation to keep middle ranges consistent in sizing and access patterns.
   */
  public static final int NUM_MID_LEN_SYMBOLS = 1 << NUM_MID_LEN_BITS;

  /**
   * Total number of length symbols across low, mid, and high ranges. This figure drives allocation
   * sizes for length probability models and defines the upper bound of decodable match lengths.
   */
  public static final int NUM_LEN_SYMBOLS =
      NUM_LOW_LEN_SYMBOLS + NUM_MID_LEN_SYMBOLS + (1 << NUM_HIGH_LEN_BITS);

  /**
   * Maximum representable match length, derived from the minimum match length and total symbol
   * count. Defines the highest length value the coder can emit without additional extensions.
   */
  public static final int MATCH_MAX_LEN = MATCH_MIN_LEN + NUM_LEN_SYMBOLS - 1;

  private Base() {}
}

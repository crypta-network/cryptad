package network.crypta.clients.fcp;

/**
 * Defines the priority-class values used by ordinary FCP message and request classes.
 *
 * <p>The constants in this helper mirror the daemon-owned request-starter priorities that have
 * historically been referenced directly from parser and message code. Keeping the values local to
 * {@code clients.fcp} reduces compile-time coupling while preserving the existing wire-level
 * behavior and scheduler semantics. A dedicated parity test verifies that the numeric values here
 * stay aligned with the daemon layer, so this cleanup does not silently change default request
 * ordering.
 *
 * <p>The class is package-private, immutable, and safe for concurrent use. It exists only to
 * support FCP message parsing, defaulting, serialization, and validation in classes such as {@code
 * ClientGetMessage}, {@code ClientPutMessage}, and {@code ModifyPersistentRequest}.
 */
final class FcpPriorityClasses {
  /**
   * Priority used for latency-sensitive splitfile work that should begin immediately.
   *
   * <p>FCP request parsers use this as the default for direct fetches and inserts where the legacy
   * daemon behavior favored prompt processing over background batching.
   */
  static final short IMMEDIATE_SPLITFILE = 2;

  /**
   * Priority used for background fetch activity that should avoid competing with direct user work.
   *
   * <p>This value is typically chosen for requests such as {@code ReturnType=none}, where the
   * caller wants the node to warm data in the background rather than stream it back immediately.
   */
  static final short PREFETCH = 5;

  /**
   * Priority used for bulk splitfile work that is expected to run behind interactive traffic.
   *
   * <p>Directory inserts and disk-oriented fetch flows commonly default to this value, so large
   * background transfers do not take precedence over more urgent requests.
   */
  static final short BULK_SPLITFILE = 4;

  /**
   * Lowest numeric priority value accepted by the FCP layer.
   *
   * <p>Priority validation treats this constant as the inclusive lower bound when checking whether
   * a parsed {@code PriorityClass} value can be handed to the scheduler.
   */
  static final short MAXIMUM = 0;

  /**
   * Highest numeric priority value accepted by the FCP layer.
   *
   * <p>Priority validation treats this constant as the inclusive upper bound. Values above this
   * threshold are rejected during message parsing before any request is queued.
   */
  static final short PAUSED = 6;

  /** Prevents instantiation of this constants-only helper type. */
  private FcpPriorityClasses() {}

  /**
   * Determines whether a parsed FCP priority class lies within the accepted inclusive range.
   *
   * <p>This helper centralizes the boundary check used by multiple request and message parsers. It
   * does not normalize or remap values; callers remain responsible for producing protocol errors
   * when this method returns {@code false}.
   *
   * @param priorityClass priority value parsed from an inbound FCP field set
   * @return {@code true} when {@code priorityClass} is between {@link #MAXIMUM} and {@link
   *     #PAUSED}, inclusive; {@code false} otherwise
   */
  static boolean isValid(short priorityClass) {
    return priorityClass >= MAXIMUM && priorityClass <= PAUSED;
  }
}

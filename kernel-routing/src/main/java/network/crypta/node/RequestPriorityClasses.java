package network.crypta.node;

/**
 * Leaf-safe request-priority constants shared by detached browse and routing code.
 *
 * <p>This class preserves the stable numeric request-priority contract that legacy runtime code has
 * historically exposed through {@code RequestStarter}, but it does so without importing the
 * runtime-owned scheduling implementation. Detached leaves such as browse, bridge, and kernel-side
 * helpers use these constants when they need to express relative urgency for fetch, insert,
 * prefetch, or update work while remaining independent of the daemon execution body.
 *
 * <p>Lower numeric values represent higher urgency. The range runs from {@link
 * #MAXIMUM_PRIORITY_CLASS} through {@link #PAUSED_PRIORITY_CLASS}, and callers should treat the
 * specific numbers as part of a compatibility contract rather than as arbitrary implementation
 * detail. If the runtime changes its scheduling semantics in the future, this class must stay in
 * lockstep so detached modules and root/runtime code continue to agree on the same priority scale.
 *
 * <ul>
 *   <li>Interactive browse and FProxy work uses {@link #INTERACTIVE_PRIORITY_CLASS}.
 *   <li>USK update polling and similar background refresh flows use {@link #UPDATE_PRIORITY_CLASS}.
 *   <li>Best-effort warming uses {@link #PREFETCH_PRIORITY_CLASS}, the lowest fetchable class.
 * </ul>
 */
public final class RequestPriorityClasses {
  /**
   * Prevents instantiation of this constants-only utility class.
   *
   * <p>The type exists solely as a namespace for the detached priority contract.
   */
  private RequestPriorityClasses() {}

  /**
   * Highest-priority class, reserved for work that must outrank interactive browse requests.
   *
   * <p>Lower numbers mean higher urgency, so this constant anchors the top of the supported range.
   */
  public static final short MAXIMUM_PRIORITY_CLASS = 0;

  /**
   * Interactive browse work such as FProxy requests.
   *
   * <p>This is the normal class for latency-sensitive user-driven fetches where prompt response is
   * more important than bulk throughput.
   */
  public static final short INTERACTIVE_PRIORITY_CLASS = 1;

  /**
   * Immediate splitfile fetches spawned from interactive work.
   *
   * <p>This priority is used for follow-up splitfile activity that should stay close to the
   * initiating interactive request.
   */
  public static final short IMMEDIATE_SPLITFILE_PRIORITY_CLASS = 2;

  /**
   * Background update work such as USK polling.
   *
   * <p>Work at this level is important for freshness, but it does not normally preempt direct
   * interactive browsing.
   */
  public static final short UPDATE_PRIORITY_CLASS = 3;

  /**
   * Bulk splitfile fetches.
   *
   * <p>This class is intended for larger throughput-oriented work that can yield to interactive and
   * update traffic.
   */
  public static final short BULK_SPLITFILE_PRIORITY_CLASS = 4;

  /**
   * Prefetch work.
   *
   * <p>This class represents best-effort warm-up activity and is intentionally lower priority than
   * explicitly requested fetches.
   */
  public static final short PREFETCH_PRIORITY_CLASS = 5;

  /**
   * Paused or lowest-priority work.
   *
   * <p>This marks the bottom of the supported priority range and is typically used for work that
   * should remain deferred unless the scheduler explicitly resumes it.
   */
  public static final short PAUSED_PRIORITY_CLASS = 6;

  /**
   * Total number of priority classes, inclusive of the maximum and paused classes.
   *
   * <p>The value is derived from the numeric endpoints of the supported range rather than being
   * hand-maintained independently.
   */
  public static final short NUMBER_OF_PRIORITY_CLASSES =
      PAUSED_PRIORITY_CLASS - MAXIMUM_PRIORITY_CLASS + 1;

  /**
   * Lowest priority class that still represents fetchable work.
   *
   * <p>Classes below this threshold are considered effectively paused rather than merely low
   * priority.
   */
  public static final short MINIMUM_FETCHABLE_PRIORITY_CLASS = PREFETCH_PRIORITY_CLASS;

  /**
   * Returns whether the supplied priority class falls within the historical supported range.
   *
   * <p>Callers can use this as a defensive check when parsing user input, protocol messages, or
   * compatibility data that may contain out-of-range values. The method performs only a numeric
   * range test; it does not validate whether a given subsystem should use a particular priority for
   * a specific request type.
   *
   * @param priorityClass candidate priority value to validate against the detached supported range
   * @return {@code true} if the supplied value is within the inclusive supported priority range
   */
  public static boolean isValidPriorityClass(int priorityClass) {
    return !((priorityClass < MAXIMUM_PRIORITY_CLASS) || (priorityClass > PAUSED_PRIORITY_CLASS));
  }
}

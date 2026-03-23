package network.crypta.support.math;

/**
 * Performs wrap-aware arithmetic on Cryptad's normalized unit keyspace.
 *
 * <p>This helper centralizes the circular math shared by support-side averages and node-side
 * location utilities such as {@code network.crypta.node.Location}. Callers use it when they already
 * enforce their own validity checks and need the historical wrap behavior at the {@code 0.0}/{@code
 * 1.0} boundary. The methods are pure, allocate no state, and keep the long-standing convention
 * that diametrically opposite points produce a positive half-turn.
 *
 * <p>The class is intentionally narrow:
 *
 * <ul>
 *   <li>{@link #normalize(double)} maps arbitrary doubles into the canonical storage range.
 *   <li>{@link #change(double, double)} returns the signed shortest path across the ring.
 *   <li>{@link #distance(double, double)} derives the absolute arc length from the same rule set.
 * </ul>
 *
 * <p>By keeping these semantics in one place, support-layer code such as {@code
 * DecayingKeyspaceAverage} can use the same behavior as node-layer location code without depending
 * on node-specific APIs.
 */
public final class KeyspaceMath {

  /** Prevents instantiation of this stateless helper class. */
  private KeyspaceMath() {}

  /**
   * Returns the shortest signed delta from one normalized position to another.
   *
   * <p>Use this when a caller needs to move from a current keyspace position toward a target, and
   * the shortest route may cross the wrap boundary. The result matches Cryptad's historical
   * location semantics: values greater than {@code 0.5} wrap backward by {@code 1.0}, values at or
   * below {@code -0.5} wrap forward by {@code 1.0}, and exactly opposite points produce {@code
   * +0.5}. The method does not validate inputs, so callers should normalize or validate first when
   * range guarantees matter.
   *
   * @param from normalized starting position supplied by the caller.
   * @param to normalized destination position supplied by the caller.
   * @return a signed shortest-path delta on the unit keyspace ring.
   */
  public static double change(double from, double to) {
    double change = to - from;
    if (change > 0.5) {
      return change - 1.0;
    }
    if (change <= -0.5) {
      return change + 1.0;
    }
    return change;
  }

  /**
   * Returns the shortest absolute arc length between two normalized positions.
   *
   * <p>This is a convenience wrapper around {@link #change(double, double)} for callers that need
   * only the scale of the shortest route. The computation remains symmetric for any ordered pair
   * because it derives from the same signed wrap rules. Like the other helpers in this class, it
   * assumes the caller has already decided whether the inputs are valid keyspace coordinates.
   *
   * @param a first normalized keyspace position to compare.
   * @param b second normalized keyspace position to compare.
   * @return shortest absolute distance measured on the unit ring.
   */
  public static double distance(double a, double b) {
    return Math.abs(change(a, b));
  }

  /**
   * Maps an arbitrary double into Cryptad's canonical keyspace range.
   *
   * <p>The returned value is always in {@code [0.0, 1.0)}, which makes it suitable for storage,
   * comparison, and further calls to {@link #change(double, double)} or {@link #distance(double,
   * double)}. Multiples of {@code 1.0} collapse onto the same position, so {@code 1.0} becomes
   * {@code 0.0}. The implementation intentionally follows Java remainder rules and then adjusts
   * negative results, preserving the behavior historically exposed through the node-side {@code
   * Location.normalize(double)} helper.
   *
   * @param rough arbitrary keyspace value that may need wrapping.
   * @return equivalent normalized position in the canonical unit range.
   */
  public static double normalize(double rough) {
    double normal = rough % 1.0;
    if (normal < 0) {
      return 1.0 + normal;
    }
    return normal;
  }
}

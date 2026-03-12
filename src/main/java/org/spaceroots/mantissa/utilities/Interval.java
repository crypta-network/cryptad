package org.spaceroots.mantissa.utilities;

/**
 * Represents a numeric interval on the real line.
 *
 * <p>An {@code Interval} stores two bounds and provides a small set of operations that are useful
 * when reasoning about ranges of real-valued quantities. Typical usage is to construct an interval
 * from two endpoints, query its bounds or length, and test containment or overlap with points or
 * other intervals. The class is deliberately lightweight and does not depend on any external
 * infrastructure.
 *
 * <p>The bounds are normalized at construction time so that {@code inf <= sup} holds as an
 * invariant. Both endpoints are treated as inclusive; there is no explicit distinction between open
 * and closed intervals, as real numbers are represented approximately in {@code double} form.
 * Operations that combine intervals (addition and intersection) follow this inclusive model and
 * preserve the ordering invariant.
 *
 * <p>This type is mutable: methods such as {@link #addToSelf(Interval)} and {@link
 * #intersectSelf(Interval)} modify the receiver. Instances are not thread-safe; if shared between
 * threads, callers should provide external synchronization or use separate instances.
 *
 * <ul>
 *   <li><strong>Responsibilities:</strong> store bounds, normalize ordering, and provide basic
 *       range operations.
 *   <li><strong>Notable behavior:</strong> adding disjoint intervals fills the gap between them,
 *       and intersecting disjoint intervals collapses the result to a point.
 * </ul>
 *
 * @author Luc Maisonobe
 * @version $Id: Interval.java 1539 2003-12-13 19:31:14Z luc $
 */
public class Interval {

  /**
   * Creates the degenerate interval {@code [0, 0]}.
   *
   * <p>This no-argument constructor initializes both bounds to zero, yielding an interval of length
   * {@code 0.0}. It is primarily useful as a neutral starting point when bounds are accumulated
   * later via {@link #addToSelf(Interval)} or {@link #intersectSelf(Interval)}.
   */
  public Interval() {
    inf = 0;
    sup = 0;
  }

  /**
   * Creates an interval with the specified bounds.
   *
   * <p>The constructor accepts two endpoints which may be provided in either order. The bounds are
   * normalized so that the internal lower bound {@code inf} is the smaller of {@code a} and {@code
   * b}, and the upper bound {@code sup} is the larger. This normalization establishes the invariant
   * {@code getInf() <= getSup()} for all instances created through this constructor.
   *
   * <p>Both endpoints are treated as inclusive. If you need a "point interval", pass equal values.
   *
   * @param a first endpoint; may be less than, equal to, or greater than {@code b}
   * @param b second endpoint; may be less than, equal to, or greater than {@code a}
   */
  public Interval(double a, double b) {
    if (a <= b) {
      inf = a;
      sup = b;
    } else {
      inf = b;
      sup = a;
    }
  }

  /**
   * Copy-constructor.
   *
   * <p>Creates a new interval with the same bounds as the supplied interval. The new instance is
   * independent of {@code i}; later mutations to either interval do not affect the other.
   *
   * @param i interval to copy; must be non-null and already normalized
   */
  public Interval(Interval i) {
    inf = i.inf;
    sup = i.sup;
  }

  /**
   * Returns the lower bound of the interval.
   *
   * <p>The returned value is the smallest endpoint after normalization. It is inclusive for all
   * containment and intersection tests. This value is stable unless the interval is mutated.
   *
   * @return inclusive lower endpoint of this interval
   */
  public double getInf() {
    return inf;
  }

  /**
   * Returns the upper bound of the interval.
   *
   * <p>The returned value is the largest endpoint after normalization. It is inclusive for all
   * containment and intersection tests. This value is stable unless the interval is mutated.
   *
   * @return inclusive upper endpoint of this interval
   */
  public double getSup() {
    return sup;
  }

  /**
   * Returns the length of the interval.
   *
   * <p>The length is computed as {@code getSup() - getInf()}. For a degenerate interval, this
   * method returns {@code 0.0}. The length can be infinite if either bound is infinite.
   *
   * @return non-negative interval length, possibly {@code +Infinity}
   */
  public double getLength() {
    return sup - inf;
  }

  /**
   * Tests whether this interval contains the given point.
   *
   * <p>Containment is inclusive on both ends: a point equal to {@code getInf()} or {@code getSup()}
   * is considered contained. If {@code x} is {@code NaN}, the comparison rules of {@code double}
   * make this method return {@code false}.
   *
   * @param x point to test against the interval bounds, in the same numeric space
   * @return {@code true} when {@code getInf() <= x <= getSup()}, otherwise {@code false}
   */
  public boolean contains(double x) {
    return (inf <= x) && (x <= sup);
  }

  /**
   * Tests whether this interval fully contains another interval.
   *
   * <p>The argument is considered contained when its lower bound is not below this interval's lower
   * bound and its upper bound is not above this interval's upper bound. Endpoints that touch are
   * treated as contained due to inclusive bounds.
   *
   * @param i interval to test for full inclusion; must be non-null and normalized
   * @return {@code true} if {@code i} lies entirely within this interval, otherwise {@code false}
   */
  public boolean contains(Interval i) {
    return (inf <= i.inf) && (i.sup <= sup);
  }

  /**
   * Tests whether another interval intersects this interval.
   *
   * <p>Two intervals are considered intersecting when they share at least one point under the
   * inclusive endpoint model. In particular, intervals that touch at a single endpoint intersect.
   * If either bound of {@code i} is {@code NaN}, the comparisons evaluate to {@code false}.
   *
   * @param i interval to test for overlap; must be non-null and normalized
   * @return {@code true} if the intervals overlap or touch, otherwise {@code false}
   */
  public boolean intersects(Interval i) {
    return (inf <= i.sup) && (i.inf <= sup);
  }

  /**
   * Expands this interval to include another interval.
   *
   * <p>This method mutates the receiver by replacing its bounds with the minimum lower bound and
   * maximum upper bound across the two intervals. The resulting interval therefore contains both
   * the original interval and {@code i}.
   *
   * <p>This operation is <strong>not</strong> a set union on potentially disjoint intervals. If the
   * intervals are disjoint (meaning {@link #intersects(Interval)} would return {@code false}), the
   * gap between them is filled in and becomes part of the expanded interval.
   *
   * <pre>{@code
   * Interval a = new Interval(0.0, 1.0);
   * a.addToSelf(new Interval(3.0, 4.0));
   * // a is now [0.0, 4.0]
   * }</pre>
   *
   * @param i interval to include in this interval; must be non-null and normalized
   */
  public void addToSelf(Interval i) {
    inf = Math.min(inf, i.inf);
    sup = Math.max(sup, i.sup);
  }

  /**
   * Returns a new interval that covers both input intervals.
   *
   * <p>This is a convenience method that does not mutate its arguments. It creates a copy of {@code
   * i1} and expands it with {@code i2} using {@link #addToSelf(Interval)}. As with {@code
   * addToSelf}, this operation is <strong>not</strong> a union: if {@code i1} and {@code i2} are
   * disjoint, the returned interval fills the gap between them.
   *
   * @param i1 first interval providing an initial set of bounds; must be non-null and normalized
   * @param i2 second interval to be included in the result; must be non-null and normalized
   * @return new interval spanning both inputs, independent of the arguments
   */
  public static Interval add(Interval i1, Interval i2) {
    Interval copy = new Interval(i1);
    copy.addToSelf(i2);
    return copy;
  }

  /**
   * Reduces this interval to its intersection with another interval.
   *
   * <p>This method mutates the receiver by clamping its bounds to the overlap with {@code i}. The
   * new lower bound becomes {@code max(this.inf, i.inf)}. The new upper bound is the smaller of the
   * two upper bounds, but never below the new lower bound.
   *
   * <p>If the intervals are disjoint, the intersection is treated as empty and represented as a
   * degenerate interval where {@code getInf() == getSup()} at the nearest boundary. Under the
   * inclusive model, intervals touching at a point intersect at that point.
   *
   * @param i interval to intersect with this instance; must be non-null and normalized
   */
  public void intersectSelf(Interval i) {
    inf = Math.max(inf, i.inf);
    sup = Math.clamp(Math.min(sup, i.sup), inf, Double.POSITIVE_INFINITY);
  }

  /**
   * Returns a new interval that is the intersection of two intervals.
   *
   * <p>This method does not mutate either argument. It copies {@code i1} and applies {@link
   * #intersectSelf(Interval)} with {@code i2}. The result follows the same inclusive intersection
   * rules as {@code intersectSelf}, including the degenerate representation for disjoint intervals.
   *
   * @param i1 first interval to intersect; must be non-null and normalized
   * @param i2 second interval to intersect; must be non-null and normalized
   * @return new interval representing the overlap of {@code i1} and {@code i2}
   */
  public static Interval intersection(Interval i1, Interval i2) {
    Interval copy = new Interval(i1);
    copy.intersectSelf(i2);
    return copy;
  }

  /** Lower bound of the interval. */
  private double inf;

  /** Upper bound of the interval. */
  private double sup;
}

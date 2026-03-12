package org.spaceroots.mantissa.utilities;

import java.util.ArrayList;
import java.util.List;

/**
 * Represents a mutable set of real-valued intervals.
 *
 * <p>An {@code IntervalsList} stores a collection of {@link Interval} instances that together form
 * a set of points on the real line. The intervals are maintained in ascending order and are
 * intended to be pairwise disjoint; most mutating operations in this class (for example {@link
 * #addToSelf(Interval)} and {@link #subtractFromSelf(Interval)}) preserve this normalized
 * representation by merging or splitting intervals as required.
 *
 * <p>This type is useful when you need a compact representation of a union of ranges, and you want
 * to apply basic set operations (union, intersection, and subtraction) incrementally. Typical usage
 * is to construct an instance, add and remove intervals as a computation progresses, and query
 * membership with {@link #contains(double)} or bounds with {@link #getInf()} and {@link #getSup()}.
 *
 * <pre>{@code
 * IntervalsList allowed = new IntervalsList();
 * allowed.addToSelf(new Interval(0.0, 10.0));
 * allowed.subtractFromSelf(new Interval(4.0, 6.0));
 * boolean ok = allowed.contains(5.0); // false
 * }</pre>
 *
 * <p>Instances are mutable and are not thread-safe. The {@link #getIntervals()} accessor returns
 * the internal backing list directly; callers are expected to treat it as read-only to avoid
 * violating ordering and disjointness invariants.
 *
 * <ul>
 *   <li>Union operations: {@link #addToSelf(Interval)} and {@link #addToSelf(IntervalsList)}
 *   <li>Intersection operations: {@link #intersectSelf(Interval)} and {@link
 *       #intersectSelf(IntervalsList)}
 *   <li>Subtraction operations: {@link #subtractFromSelf(Interval)} and {@link
 *       #subtractFromSelf(IntervalsList)}
 * </ul>
 *
 * @see Interval
 * @author Luc Maisonobe
 * @version $Id: IntervalsList.java 1694 2006-09-03 19:53:48Z luc $
 */
@SuppressWarnings("unused")
public class IntervalsList {

  /**
   * Build an empty intervals list.
   *
   * <p>The created instance contains no intervals and therefore represents the empty set of points.
   * It can be incrementally built up with {@link #addToSelf(Interval)} or {@link
   * #addToSelf(IntervalsList)}. In the empty state, {@link #isEmpty()} returns {@code true}, {@link
   * #getSize()} returns {@code 0}, and {@link #getInf()} / {@link #getSup()} return {@link
   * Double#NaN}.
   */
  public IntervalsList() {
    intervals = new ArrayList<>();
  }

  /**
   * Build an intervals list containing a single interval defined by two bounds.
   *
   * <p>The created instance initially contains exactly one {@link Interval}. The interpretation of
   * the bounds (ordering, inclusiveness, and degeneracy) is delegated to {@link Interval}; if the
   * bounds are provided out of order, the behavior follows the {@code Interval} constructor. The
   * resulting list is connected (see {@link #isConnex()}) until further updates are applied.
   *
   * @param a first bound of the interval, in the same units as all future operations
   * @param b second bound of the interval, in the same units as {@code a}
   */
  public IntervalsList(double a, double b) {
    intervals = new ArrayList<>();
    intervals.add(new Interval(a, b));
  }

  /**
   * Build an intervals list containing a single existing interval.
   *
   * <p>The provided {@link Interval} instance is stored as-is; it is not copied. This constructor
   * is therefore a convenience for adopting an interval object as the initial state of the list. If
   * the caller subsequently mutates {@code i} (if it is mutable), the list will observe those
   * changes as well.
   *
   * @param i interval to store as the sole element of this list
   */
  public IntervalsList(Interval i) {
    intervals = new ArrayList<>();
    intervals.add(i);
  }

  /**
   * Build an intervals list from two intervals, normalizing order and overlap.
   *
   * <p>If the provided intervals intersect, they are merged into a single interval that spans from
   * the minimum lower bound to the maximum upper bound. If they do not intersect, they are stored
   * in ascending order by lower bound.
   *
   * @param i1 first interval to include in the new list, possibly overlapping {@code i2}
   * @param i2 second interval to include in the new list, possibly overlapping {@code i1}
   */
  public IntervalsList(Interval i1, Interval i2) {
    intervals = new ArrayList<>();
    if (i1.intersects(i2)) {
      intervals.add(
          new Interval(Math.min(i1.getInf(), i2.getInf()), Math.max(i1.getSup(), i2.getSup())));
    } else if (i1.getSup() < i2.getInf()) {
      intervals.add(i1);
      intervals.add(i2);
    } else {
      intervals.add(i2);
      intervals.add(i1);
    }
  }

  /**
   * Copy constructor.
   *
   * <p>The copy operation is a deep copy: newly created {@link Interval} instances are stored in
   * the new list, so subsequent modifications to the source list's intervals do not affect the
   * copy.
   *
   * @param list intervals list to copy; must not be {@code null}
   */
  public IntervalsList(IntervalsList list) {
    intervals = new ArrayList<>(list.intervals.size());
    for (Interval interval : list.intervals) {
      intervals.add(new Interval(interval));
    }
  }

  /**
   * Check whether this list currently contains no intervals.
   *
   * <p>This is a pure query and does not modify the instance. An empty list represents the empty
   * set of points; in this state, {@link #getInf()} and {@link #getSup()} return {@link
   * Double#NaN}.
   *
   * @return {@code true} if the instance contains zero intervals, {@code false} otherwise
   */
  public boolean isEmpty() {
    return intervals.isEmpty();
  }

  /**
   * Check whether this list represents a connected set.
   *
   * <p>An {@code IntervalsList} is considered connected when it contains exactly one interval. In
   * particular, an empty list is not connected. This method does not attempt to infer connectivity
   * from adjacency; it relies solely on the current normalized representation.
   *
   * @return {@code true} if the list contains exactly one interval, {@code false} otherwise
   */
  public boolean isConnex() {
    return intervals.size() == 1;
  }

  /**
   * Get the lower bound of the whole list.
   *
   * <p>The value returned is the infimum of all points contained by this list, which corresponds to
   * the lower bound of the first stored interval. For an empty list, the method returns {@link
   * Double#NaN}.
   *
   * @return lower bound of the list, or {@link Double#NaN} when the list is empty
   */
  public double getInf() {
    return intervals.isEmpty() ? Double.NaN : intervals.getFirst().getInf();
  }

  /**
   * Get the upper bound of the whole list.
   *
   * <p>The value returned is the supremum of all points contained by this list, which corresponds
   * to the upper bound of the last stored interval. For an empty list, the method returns {@link
   * Double#NaN}.
   *
   * @return upper bound of the list, or {@link Double#NaN} when the list is empty
   */
  public double getSup() {
    return intervals.isEmpty() ? Double.NaN : intervals.getLast().getSup();
  }

  /**
   * Get the number of stored intervals.
   *
   * <p>The returned value is the size of the internal normalized representation, not a measure of
   * length or measure on the real line. Many operations (like union and subtraction) can increase
   * or decrease this count by merging or splitting intervals.
   *
   * @return number of {@link Interval} instances currently stored in this list
   */
  public int getSize() {
    return intervals.size();
  }

  /**
   * Get an interval from the list by index.
   *
   * <p>The index is in ascending order (the same order as returned by {@link #getIntervals()}). The
   * returned object is the stored {@link Interval} instance; it is not copied. If the underlying
   * {@code Interval} objects are mutable, callers should avoid modifying them as doing so may break
   * ordering and disjointness assumptions used by this class.
   *
   * @param i index of the interval to return, in the range {@code [0, getSize())}
   * @return the interval stored at the specified index, in ascending order
   * @throws IndexOutOfBoundsException if {@code i} is not a valid interval index
   */
  public Interval getInterval(int i) {
    return intervals.get(i);
  }

  /**
   * Get the ordered list of disjoint intervals backing this instance.
   *
   * <p>This method returns the internal list directly (no defensive copy is performed). The list is
   * ordered in ascending order and is expected to contain disjoint intervals. For correctness, the
   * returned list should be treated as read-only by callers; external modification may violate the
   * invariants assumed by mutating operations.
   *
   * @return the internal list of disjoint intervals, ordered by increasing lower bound
   */
  public List<Interval> getIntervals() {
    return intervals;
  }

  /**
   * Check whether this list contains a point.
   *
   * <p>The membership test is performed by scanning the stored intervals and delegating point
   * containment to {@link Interval#contains(double)}. For a normalized list, this is an {@code
   * O(n)} operation in the number of stored intervals.
   *
   * @param x point to test for membership in this interval set
   * @return {@code true} if {@code x} belongs to at least one stored interval, {@code false}
   *     otherwise
   */
  public boolean contains(double x) {
    for (Interval interval : intervals) {
      if (interval.contains(x)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Check whether this list fully contains an interval.
   *
   * <p>The interval is considered contained if there exists a stored {@link Interval} that
   * completely contains {@code i} according to {@link Interval#contains(Interval)}. Because this
   * list stores disjoint intervals, partial coverage across multiple intervals does not count as
   * containment.
   *
   * @param i interval to test for full containment within this list
   * @return {@code true} if any stored interval contains {@code i} in full, {@code false} otherwise
   */
  public boolean contains(Interval i) {
    for (Interval interval : intervals) {
      if (interval.contains(i)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Check whether an interval intersects this list.
   *
   * <p>The intersection test is performed by scanning stored intervals and delegating to {@link
   * Interval#intersects(Interval)}. The method returns as soon as an intersecting interval is
   * found, making the best-case runtime constant and the worst-case runtime linear in the number of
   * stored intervals.
   *
   * @param i interval to test for intersection with this interval set
   * @return {@code true} if {@code i} intersects any stored interval, {@code false} otherwise
   */
  public boolean intersects(Interval i) {
    for (Interval interval : intervals) {
      if (interval.intersects(i)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Add an interval to this list (in-place union).
   *
   * <p>This method modifies the instance to represent the union of its current set and the points
   * contained by {@code i}. If {@code i} overlaps existing intervals, they are merged so the result
   * remains normalized (sorted and disjoint). If {@code i} lies entirely in a gap, it is inserted
   * at the appropriate position.
   *
   * <p>The number of stored intervals may decrease when {@code i} connects two previously disjoint
   * intervals. The operation scans the current intervals once and therefore runs in {@code O(n)}
   * time for {@code n = getSize()}.
   *
   * @param i interval to add to the instance; must use the same coordinate system as existing data
   */
  public void addToSelf(Interval i) {

    List<Interval> newIntervals = new ArrayList<>(intervals.size() + 1);
    double inf = Double.NaN;
    double sup = Double.NaN;
    boolean pending = false;
    boolean processed = false;
    for (Interval local : intervals) {

      if (local.getSup() < i.getInf()) {
        newIntervals.add(local);
      } else if (local.getInf() < i.getSup()) {
        if (!pending) {
          inf = Math.min(local.getInf(), i.getInf());
          pending = true;
          processed = true;
        }
        sup = Math.max(local.getSup(), i.getSup());
      } else {
        if (pending) {
          newIntervals.add(new Interval(inf, sup));
          pending = false;
        } else if (!processed) {
          newIntervals.add(i);
        }
        processed = true;
        newIntervals.add(local);
      }
    }

    if (pending) {
      newIntervals.add(new Interval(inf, sup));
    } else if (!processed) {
      newIntervals.add(i);
    }

    intervals = newIntervals;
  }

  /**
   * Return the union of an intervals list and a single interval.
   *
   * <p>This is a pure helper that leaves the input list unchanged by working on a deep copy (see
   * {@link #IntervalsList(IntervalsList)}). The semantics match {@link #addToSelf(Interval)}
   * applied to the copied list.
   *
   * @param list base intervals list to union with {@code i}; must not be {@code null}
   * @param i interval to add to the returned list; must not be {@code null}
   * @return a new intervals list representing {@code list ∪ i}, normalized and independent of
   *     {@code list}
   */
  public static IntervalsList add(IntervalsList list, Interval i) {
    IntervalsList copy = new IntervalsList(list);
    copy.addToSelf(i);
    return copy;
  }

  /**
   * Remove an interval from this list (in-place subtraction).
   *
   * <p>This method modifies the instance to represent the set difference between its current set
   * and the points contained by {@code i}. If {@code i} is disjoint from the list, the operation is
   * effectively a no-op. If {@code i} overlaps stored intervals, it may shrink them or split one
   * interval into two disjoint intervals.
   *
   * <p>The implementation derives the result by intersecting the current list with a list
   * representing the complement of {@code i} over a temporary finite outer range. That outer range
   * is chosen as {@code [a - 1, b + 1]} where {@code a} and {@code b} are the minimum and maximum
   * bounds of the current list and {@code i}. Extreme input values may cause the temporary bounds
   * to overflow to infinities.
   *
   * @param i interval to remove from the instance; must not be {@code null}
   */
  public void subtractFromSelf(Interval i) {
    double a = Math.min(getInf(), i.getInf());
    double b = Math.max(getSup(), i.getSup());
    intersectSelf(
        new IntervalsList(new Interval(a - 1.0, i.getInf()), new Interval(i.getSup(), b + 1.0)));
  }

  /**
   * Return the difference of an intervals list and a single interval.
   *
   * <p>This is a pure helper that leaves the input list unchanged by working on a deep copy (see
   * {@link #IntervalsList(IntervalsList)}). The semantics match {@link #subtractFromSelf(Interval)}
   * applied to the copied list.
   *
   * @param list base intervals list from which {@code i} is removed; must not be {@code null}
   * @param i interval to remove from the returned list; must not be {@code null}
   * @return a new intervals list representing {@code list \\ i}, normalized and independent of
   *     {@code list}
   */
  public static IntervalsList subtract(IntervalsList list, Interval i) {
    IntervalsList copy = new IntervalsList(list);
    copy.subtractFromSelf(i);
    return copy;
  }

  /**
   * Intersect this list with a single interval (in-place intersection).
   *
   * <p>This method modifies the instance to contain only the points that are present both in the
   * current list and in {@code i}. Any stored interval that does not intersect {@code i} is
   * removed; intersecting intervals are replaced by their pairwise intersection computed via {@link
   * Interval#intersection(Interval, Interval)}.
   *
   * <p>The operation scans the current intervals once and therefore runs in {@code O(n)} time for
   * {@code n = getSize()}.
   *
   * @param i interval to intersect with the current instance; must not be {@code null}
   */
  public void intersectSelf(Interval i) {
    List<Interval> newIntervals = new ArrayList<>(intervals.size());
    for (Interval local : intervals) {
      if (local.intersects(i)) {
        newIntervals.add(Interval.intersection(local, i));
      }
    }
    intervals = newIntervals;
  }

  /**
   * Return the intersection of an intervals list and a single interval.
   *
   * <p>This is a pure helper that leaves the input list unchanged by working on a deep copy (see
   * {@link #IntervalsList(IntervalsList)}). The semantics match {@link #intersectSelf(Interval)}
   * applied to the copied list.
   *
   * @param list base intervals list to intersect with {@code i}; must not be {@code null}
   * @param i interval to intersect with {@code list}; must not be {@code null}
   * @return a new intervals list representing {@code list ∩ i}, normalized and independent of
   *     {@code list}
   */
  public static IntervalsList intersection(IntervalsList list, Interval i) {
    IntervalsList copy = new IntervalsList(list);
    copy.intersectSelf(i);
    return copy;
  }

  /**
   * Add another intervals list to this instance (in-place union).
   *
   * <p>This method modifies this instance to represent the union of its current set and all
   * intervals contained in {@code list}. The operation iterates over the other list's internal
   * intervals and applies {@link #addToSelf(Interval)} for each.
   *
   * <p>Because each individual addition may scan the current list, the overall runtime is roughly
   * {@code O(n * m)} for {@code n = getSize()} and {@code m = list.getSize()} in the worst case.
   * The result remains normalized (sorted and disjoint).
   *
   * @param list intervals list to union into this instance; must not be {@code null}
   */
  public void addToSelf(IntervalsList list) {
    for (Interval interval : list.intervals) {
      addToSelf(interval);
    }
  }

  /**
   * Return the union of two intervals lists.
   *
   * <p>This is a pure helper that leaves the input lists unchanged by working on a deep copy of
   * {@code list1} (see {@link #IntervalsList(IntervalsList)}). The semantics match calling {@link
   * #addToSelf(IntervalsList)} on the copied list.
   *
   * @param list1 first intervals list providing the base content; must not be {@code null}
   * @param list2 second intervals list to union into the result; must not be {@code null}
   * @return a new intervals list representing {@code list1 ∪ list2}, normalized and independent of
   *     the inputs
   */
  public static IntervalsList add(IntervalsList list1, IntervalsList list2) {
    IntervalsList copy = new IntervalsList(list1);
    copy.addToSelf(list2);
    return copy;
  }

  /**
   * Remove all intervals from another list from this instance (in-place subtraction).
   *
   * <p>This method iterates over the other list's internal intervals and applies {@link
   * #subtractFromSelf(Interval)} for each. Each subtraction may split existing intervals, and the
   * number of stored intervals can increase or decrease accordingly.
   *
   * <p>The operation is order-dependent only with respect to intermediate representations; the
   * final result corresponds to subtracting the union of all intervals in {@code list}.
   *
   * @param list intervals list whose points are removed from this instance; must not be {@code
   *     null}
   */
  public void subtractFromSelf(IntervalsList list) {
    for (Interval interval : list.intervals) {
      subtractFromSelf(interval);
    }
  }

  /**
   * Return the difference of two intervals lists.
   *
   * <p>This is a pure helper that leaves the input lists unchanged by working on a deep copy of
   * {@code list1} (see {@link #IntervalsList(IntervalsList)}). The semantics match calling {@link
   * #subtractFromSelf(IntervalsList)} on the copied list.
   *
   * @param list1 base intervals list from which {@code list2} is removed; must not be {@code null}
   * @param list2 intervals list to remove from the result; must not be {@code null}
   * @return a new intervals list representing {@code list1 \\ list2}, normalized and independent of
   *     the inputs
   */
  public static IntervalsList subtract(IntervalsList list1, IntervalsList list2) {
    IntervalsList copy = new IntervalsList(list1);
    copy.subtractFromSelf(list2);
    return copy;
  }

  /**
   * Intersect this list with another intervals list (in-place intersection).
   *
   * <p>This method modifies the instance to contain only points that belong to both lists. The
   * computation is performed via {@link #intersection(IntervalsList, IntervalsList)}, and the
   * internal interval list is replaced with the result's internal representation.
   *
   * <p>Because this method replaces the backing list, any external references obtained earlier via
   * {@link #getIntervals()} will not observe the updated contents.
   *
   * @param list list to intersect with this instance; must not be {@code null}
   */
  public void intersectSelf(IntervalsList list) {
    intervals = intersection(this, list).intervals;
  }

  /**
   * Return the intersection of two intervals lists.
   *
   * <p>This method builds a new list containing only the points present in both inputs. The
   * computation iterates over the second list's intervals and unions their individual intersections
   * with {@code list1}. This approach keeps the intermediate and final results normalized.
   *
   * <p>The runtime depends on the sizes and shapes of the input lists; in the worst case it may be
   * quadratic in the number of stored intervals.
   *
   * @param list1 first intervals list participating in the intersection; must not be {@code null}
   * @param list2 second intervals list participating in the intersection; must not be {@code null}
   * @return a new intervals list representing {@code list1 ∩ list2}, normalized and independent of
   *     the inputs
   */
  public static IntervalsList intersection(IntervalsList list1, IntervalsList list2) {
    IntervalsList list = new IntervalsList();
    for (Interval interval : list2.intervals) {
      list.addToSelf(intersection(list1, interval));
    }
    return list;
  }

  /** The list of intervals. */
  private List<Interval> intervals;
}

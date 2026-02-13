package network.crypta.support;

import java.io.Serial;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.NavigableSet;
import java.util.TreeSet;
import org.jetbrains.annotations.NotNull;

/**
 * Sparse set of integer slots represented as disjoint, closed intervals.
 *
 * <p>This structure stores ranges of {@code int} indices as non-overlapping and non-adjacent
 * intervals {@code [start, end]} (both inclusive). Adjacent or overlapping ranges are merged on
 * insertion; removals may split an existing range. Typical use cases include tracking received
 * sequence numbers, completed chunks, or any presence bitmap that benefits from interval
 * compression.
 *
 * <p>Iteration yields the current intervals in ascending order of {@code start}. Each element is a
 * newly created {@code int[2]} array where {@code [0]} is {@code start} and {@code [1]} is {@code
 * end}. Mutating the returned arrays does not affect this bitmap. The iterator supports {@link
 * Iterator#remove()} to delete the last returned interval from the bitmap.
 *
 * <p>Thread-safety: not thread-safe. Synchronize externally if accessed from multiple threads.
 *
 * <p>Complexity (let {@code n} be the number of stored intervals and {@code m} the number touched
 * by an operation): - {@link #add(int, int)} and {@link #remove(int, int)} run in {@code O(log n +
 * m)}. - {@link #contains(int, int)} runs in {@code O(log n)}. - Iteration is {@code O(n)} and
 * yields intervals in order.
 */
public final class SparseBitmap implements Iterable<int[]> {
  // Intervals are ordered by start. Invariant: they are disjoint and non-adjacent.
  private final TreeSet<Range> ranges;

  /** Creates an empty bitmap with no intervals present. */
  public SparseBitmap() {
    ranges = new TreeSet<>(new RangeComparator());
  }

  /**
   * Creates a deep copy of another bitmap.
   *
   * <p>All intervals from {@code original} are added to this instance preserving the representation
   * invariants.
   *
   * @param original source bitmap to copy; must not be {@code null}
   */
  public SparseBitmap(SparseBitmap original) {
    ranges = new TreeSet<>(new RangeComparator());

    for (int[] range : original) {
      add(range[0], range[1]);
    }
  }

  /**
   * Marks all slots in {@code [start, end]} (inclusive) as present.
   *
   * <p>Overlapping or adjacent intervals are merged into a single interval.
   *
   * @param start lower bound, inclusive
   * @param end upper bound, inclusive
   * @throws IllegalArgumentException if {@code start > end}
   */
  public void add(int start, int end) {
    if (start > end) {
      throw new IllegalArgumentException(
          "Tried adding bad range. Start: " + start + ", end: " + end);
    }
    NavigableSet<Range> toReplace = overlaps(start, end, true);
    if (!toReplace.isEmpty()) {
      Range first = toReplace.getFirst();
      if (first.start < start) {
        start = first.start;
      }
      Range last = toReplace.getLast();
      if (last.end > end) {
        end = last.end;
      }
      toReplace.clear();
    }
    ranges.add(new Range(start, end));
  }

  /**
   * Removes all intervals from the bitmap.
   *
   * <p>After this call {@link #isEmpty()} returns {@code true}.
   */
  public void clear() {
    ranges.clear();
  }

  /**
   * Returns whether every slot in {@code [start, end]} is present.
   *
   * <p>The check is inclusive of both bounds and succeeds only if a single stored interval fully
   * covers the query range.
   *
   * @param start lower bound, inclusive
   * @param end upper bound, inclusive
   * @return {@code true} if the entire range is present, otherwise {@code false}
   * @throws IllegalArgumentException if {@code start > end}
   */
  public boolean contains(int start, int end) {
    if (start > end) {
      throw new IllegalArgumentException(
          "Tried checking bad range. Start: " + start + ", end: " + end);
    }

    // Find the latest interval whose start is <= start, if any exists.
    Range floor = ranges.floor(new Range(start, end));
    // By definition of floor(), floor.start <= start.
    return floor != null && floor.end >= end;
  }

  /**
   * Marks all slots in {@code [start, end]} (inclusive) as not present.
   *
   * <p>Existing intervals that intersect the removal range are trimmed or split as needed; any
   * non-intersecting intervals remain unchanged.
   *
   * @param start lower bound, inclusive
   * @param end upper bound, inclusive
   * @throws IllegalArgumentException if {@code start > end}
   */
  public void remove(int start, int end) {
    if (start > end) {
      throw new IllegalArgumentException("Removing bad range. Start: " + start + ", end: " + end);
    }

    List<Range> toAdd = new ArrayList<>();

    Iterator<Range> it = overlaps(start, end, false).iterator();
    while (it.hasNext()) {
      Range range = it.next();

      if (range.start < start) {
        if (range.end <= end) {
          // Overlaps the left side: keep the left fragment.
          toAdd.add(new Range(range.start, start - 1));
        } else {
          // Strictly contains [start, end]: split into left and right fragments.
          toAdd.add(new Range(range.start, start - 1));
          toAdd.add(new Range(end + 1, range.end));
        }
      } else {
        if (range.end > end) {
          // Overlaps the right side: keep the right fragment.
          toAdd.add(new Range(end + 1, range.end));
        }
        // Else: fully removed (equal or entirely inside [start, end]).
      }
      it.remove();
    }

    ranges.addAll(toAdd);
  }

  /**
   * Returns an iterator over the stored intervals.
   *
   * <p>The iterator yields {@code int[2]} arrays representing {@code [start, end]} for each stored
   * interval in ascending order. Calling {@link Iterator#remove()} removes the last returned
   * interval from this bitmap.
   *
   * @return an iterator over {@code [start, end]} arrays; never {@code null}
   */
  @Override
  public @NotNull Iterator<int[]> iterator() {
    return new SparseBitmapIterator(this);
  }

  /**
   * Returns whether the bitmap contains no intervals.
   *
   * @return {@code true} if empty; {@code false} otherwise
   */
  public boolean isEmpty() {
    return ranges.isEmpty();
  }

  /**
   * Returns a human-readable representation of the stored intervals.
   *
   * <p>The format is {@code "start->end"} pairs separated by comma and space, in ascending order by
   * {@code start} (e.g., {@code "1->3, 10->12"}).
   */
  @Override
  public String toString() {
    StringBuilder s = new StringBuilder();
    for (int[] range : this) {
      if (!s.isEmpty()) s.append(", ");
      s.append(range[0]).append("->").append(range[1]);
    }
    return s.toString();
  }

  /**
   * Finds the view of intervals that overlap or (optionally) touch the given query.
   *
   * <p>When {@code includeTouching} is {@code true}, intervals that share a boundary with the query
   * (i.e., {@code end + 1 == start} or {@code start - 1 == end}) are included. The returned set is
   * a live {@link NavigableSet} view backed by the internal {@link TreeSet} and supports bulk
   * operations such as {@link NavigableSet#clear()}.
   */
  private NavigableSet<Range> overlaps(int start, int end, boolean includeTouching) {
    // Establish bounds on starts to select intervals that would overlap or touch.
    Range startRange = new Range(start, 0);
    Range lower = ranges.lower(startRange);
    // Guard against integer underflow when computing (start - 1).
    int touchStart;
    if (includeTouching) {
      touchStart = (start == Integer.MIN_VALUE) ? Integer.MIN_VALUE : start - 1;
    } else {
      touchStart = start;
    }
    if (lower != null && lower.end >= touchStart) {
      // The previous interval overlaps or touches; widen the lower bound.
      startRange = new Range(lower.start, 0);
    }
    // Compute the exclusive upper bound as (end + 1). When end == MAX_VALUE, saturate and switch
    // to an inclusive bound to preserve semantics and avoid overflow.
    boolean upperInclusive = includeTouching || end == Integer.MAX_VALUE;
    int upperStart = (end == Integer.MAX_VALUE) ? Integer.MAX_VALUE : end + 1;
    Range endRange = new Range(upperStart, 0);
    // Any interval with start within [startRange, endRange) (or inclusive upper bound) touches or
    // overlaps the query.
    return ranges.subSet(startRange, true, endRange, upperInclusive);
  }

  @SuppressWarnings("ClassCanBeRecord")
  private static class SparseBitmapIterator implements Iterator<int[]> {
    private final Iterator<Range> it;

    public SparseBitmapIterator(SparseBitmap map) {
      it = map.ranges.iterator();
    }

    @Override
    public boolean hasNext() {
      return it.hasNext();
    }

    @Override
    public int[] next() {
      Range r = it.next();
      return new int[] {r.start, r.end};
    }

    @Override
    public void remove() {
      it.remove();
    }
  }

  /*
   * Closed interval used as the internal representation. Kept package-private to minimize
   * surface; fields are read via record accessors where needed.
   */
  private record Range(int start, int end) {

    @Override
    public @NotNull String toString() {
      return "Range:" + start + "->" + end;
    }
  }

  private static class RangeComparator implements Comparator<Range>, Serializable {

    @Serial private static final long serialVersionUID = 1L;

    @Override
    public int compare(Range r1, Range r2) {
      return Integer.compare(r1.start, r2.start);
    }
  }

  /**
   * Counts the number of slots in {@code [start, end]} that are not present.
   *
   * <p>This is an equivalent to {@code (end - start + 1) - covered}, where {@code covered} is the
   * total size of intersections between the query range and the stored intervals.
   *
   * <p>Precondition: {@code start <= end}.
   *
   * @param start lower bound, inclusive
   * @param end upper bound, inclusive
   * @return the number of missing slots in the range
   * @throws IllegalStateException if an internal invariant is violated
   */
  public int notOverlapping(int start, int end) {
    int count = end - start + 1;
    for (Range range : overlaps(start, end, false)) {
      if (range.end < start || range.start > end) {
        throw new IllegalStateException();
      }
      int overlap = range.end - range.start + 1;
      if (range.start < start) {
        overlap -= start - range.start;
      }
      if (range.end > end) {
        overlap -= range.end - end;
      }
      count -= overlap;
    }
    return count;
  }
}

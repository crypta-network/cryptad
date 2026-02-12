package com.onionnetworks.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.StringTokenizer;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Represents a mutable set of {@code long} integers stored as inclusive ranges.
 *
 * <p>RangeSet is a compact alternative to bitmap- or hash-based sets when the data contains long
 * contiguous runs of values, including unbounded runs that stretch to negative or positive
 * infinity. It stores paired endpoints in ascending order and collapses adjacent or overlapping
 * input automatically. Core operations such as {@link #union(RangeSet)}, {@link
 * #intersect(RangeSet)}, and {@link #complement()} create derived sets without mutating the source
 * instance. Membership checks use binary search over endpoints, so the performance profile favors a
 * modest number of ranges rather than extremely fragmented input.
 *
 * <p>Typical usage is to construct an empty instance, add individual values or {@link Range}
 * objects, and then iterate over normalized ranges via {@link #iterator()}. Instances are mutable
 * but not thread-safe; callers must serialize access when sharing across threads. Infinite lower
 * and upper bounds are tracked explicitly rather than via sentinel values, preventing overflow
 * while still allowing correct set algebra with unbounded domains.
 *
 * <ul>
 *   <li>Stores ranges inclusively using paired {@code long} endpoints.
 *   <li>Supports infinite bounds without exposing artificial minimum/maximum sentinels.
 *   <li>Provides iterators that materialize ranges with the appropriate infinity markers.
 * </ul>
 *
 * @see Range
 */
public class RangeSet {

  /**
   * Default number of endpoint pairs allocated for a new {@code RangeSet}. The backing array grows
   * automatically when ranges are added beyond this capacity, so callers rarely need to tune this
   * value directly.
   */
  public static final int DEFAULT_CAPACITY = 16;

  private static final Logger LOG = Logger.getLogger(RangeSet.class.getName());

  boolean posInf;
  boolean negInf;
  int rangeCount;
  long[] ranges;

  /**
   * Creates an empty {@code RangeSet} with capacity for {@link #DEFAULT_CAPACITY} range pairs.
   *
   * <p>No ranges are present after construction, and both infinity flags are clear. Callers
   * typically add values or ranges immediately using {@link #add(long)} or {@link #add(Range)}. The
   * instance is mutable and may expand its internal storage automatically as additional ranges are
   * merged.
   */
  public RangeSet() {
    ranges = new long[DEFAULT_CAPACITY * 2];
  }

  /**
   * Creates a {@code RangeSet} containing the provided range as its initial content.
   *
   * <p>The new instance starts empty and then folds the supplied {@link Range} into its internal
   * representation, preserving any infinite bounds carried by the range. Subsequent mutations on
   * the returned set do not affect the original {@code Range} object.
   *
   * @param r the range to add during construction; must not be {@code null}.
   */
  public RangeSet(Range r) {
    this();
    add(r);
  }

  /**
   * Copy constructor that duplicates another {@code RangeSet} including infinity markers.
   *
   * <p>All endpoints are copied into a fresh backing array, and the source set remains unchanged.
   * The resulting instance is a shallow structural clone: later modifications to either set do not
   * affect the other, but {@link Range} objects returned by iterators are newly allocated each
   * time.
   *
   * @param source the {@code RangeSet} to replicate, including its current ranges and flags.
   */
  public RangeSet(RangeSet source) {
    this.ranges = Arrays.copyOf(source.ranges, source.ranges.length);
    this.rangeCount = source.rangeCount;
    this.posInf = source.posInf;
    this.negInf = source.negInf;
  }

  /**
   * Computes the union of this set and the provided set without modifying either input.
   *
   * <p>All ranges from both operands are merged into a new {@code RangeSet}, collapsing overlaps
   * and adjacent segments so the result remains normalized. Infinity flags propagate if either
   * operand spans negative or positive infinity. The operation is idempotent and safe to invoke
   * repeatedly with identical inputs.
   *
   * @param rs the non-{@code null} set to combine with this instance.
   * @return a new {@code RangeSet} containing every value present in either operand.
   * @throws NullPointerException if {@code rs} is {@code null}.
   */
  public RangeSet union(RangeSet rs) {
    // This should be rewritten to interleave the additions so that there
    // are fewer midlist insertions.
    RangeSet result = new RangeSet();
    result.add(this);
    result.add(rs);
    return result;
  }

  /**
   * Produces the intersection of this set and the provided set.
   *
   * <p>The returned {@code RangeSet} contains only values present in both operands. Internally, the
   * method leverages complement logic, so infinite bounds are handled consistently with other set
   * operations. Neither input set is modified. When the operands do not overlap, an empty set is
   * returned.
   *
   * @param rs the non-{@code null} set to intersect with this instance.
   * @return a new {@code RangeSet} representing the overlap between the two sets.
   * @throws NullPointerException if {@code rs} is {@code null}.
   */
  public RangeSet intersect(RangeSet rs) {
    RangeSet result = complement();
    result.add(rs.complement());
    return result.complement();
  }

  /**
   * Computes the complement of this set across the entire {@code long} domain.
   *
   * <p>The complement contains every value not present in this set, respecting explicit negative
   * and positive infinity markers. The current instance is not mutated. Callers should inspect the
   * returned set's infinity flags to understand whether the complement is unbounded in either
   * direction.
   *
   * @return a new {@code RangeSet} containing all values not included in this set.
   */
  public RangeSet complement() {
    RangeSet rs = new RangeSet();
    if (isEmpty()) {
      rs.add(new Range(true, true));
    } else {
      if (!negInf) {
        rs.add(new Range(true, ranges[0] - 1));
      }
      for (int i = 0; i < rangeCount - 1; i++) {
        rs.add(ranges[i * 2 + 1] + 1, ranges[i * 2 + 2] - 1);
      }
      if (!posInf) {
        rs.add(new Range(ranges[(rangeCount - 1) * 2 + 1] + 1, true));
      }
    }
    return rs;
  }

  /**
   * Determines whether the specified value is a member of this set.
   *
   * <p>The lookup uses a binary search across stored endpoints and completes in O(log n) time when
   * {@code n} is the number of disjoint ranges. Negative and positive infinity markers are honored,
   * so values beyond the finite endpoints are considered present when the corresponding flag is
   * set.
   *
   * @param i the value to test for membership within this set.
   * @return {@code true} when {@code i} lies inside any stored range; otherwise {@code false}.
   */
  public boolean contains(long i) {
    int pos = binarySearch(i);
    if (pos > 0) {
      return true;
    }
    pos = -(pos + 1);
    return pos % 2 != 0;
  }

  /**
   * Checks whether every element of the provided range appears in this set.
   *
   * <p>The method constructs a temporary {@code RangeSet} from the supplied {@link Range} and
   * compares the intersection result, ensuring that both finite and infinite endpoints are treated
   * consistently. The current set remains unchanged.
   *
   * @param r the range whose membership should be verified; must not be {@code null}.
   * @return {@code true} when all values within {@code r} are contained in this set.
   */
  public boolean contains(Range r) {
    RangeSet rs = new RangeSet();
    rs.add(r);
    return intersect(rs).equals(rs);
  }

  /**
   * Adds every range from the provided set into this set, merging overlaps as needed.
   *
   * <p>Ranges are iterated in the source order and folded into the current instance. Overlapping or
   * adjacent segments are collapsed automatically. This operation mutates the receiver while
   * leaving the source set untouched. Callers must supply a non-{@code null} argument.
   *
   * @param rs the set whose ranges should be inserted into this instance.
   * @throws NullPointerException if {@code rs} is {@code null}.
   */
  public void add(RangeSet rs) {
    for (Iterator<Range> it = rs.iterator(); it.hasNext(); ) {
      add(it.next());
    }
  }

  /**
   * Adds a single {@link Range} to this set, respecting infinite endpoints.
   *
   * <p>The range's bounds are merged into existing ranges and may expand the tracked infinity flags
   * when the range is unbounded. Overlapping regions are normalized to prevent duplicate segments.
   *
   * @param r the range to add to this set; must not be {@code null}.
   */
  public void add(Range r) {
    if (r.isMinNegInf()) {
      negInf = true;
    }
    if (r.isMaxPosInf()) {
      posInf = true;
    }
    add(r.getMin(), r.getMax());
  }

  /**
   * Adds a single value to this set as a one-element range.
   *
   * <p>The call is equivalent to {@link #add(long, long)} with identical bounds. Existing adjacent
   * ranges are merged so the internal representation remains normalized.
   *
   * @param i the value to insert into the set.
   */
  public void add(long i) {
    add(i, i);
  }

  /**
   * Adds an inclusive range of values to this set.
   *
   * <p>The method validates that {@code min <= max}, merges the provided bounds with any
   * overlapping or adjacent stored ranges, and expands the backing array when necessary. Infinity
   * flags are set when callers supply unbounded endpoints via {@link Range} wrappers; this overload
   * expects finite {@code long} values.
   *
   * @param min the inclusive lower bound of the range to add.
   * @param max the inclusive upper bound of the range to add.
   * @throws IllegalArgumentException if {@code min} is greater than {@code max}.
   */
  public void add(long min, long max) {

    if (min > max) {
      throw new IllegalArgumentException("min cannot be greater than max");
    }

    if (rangeCount == 0) { // first value.
      insert(min, max, 0);
      return;
    }

    // This case should be the most common (insert at the end), so we will
    // specifically check for it.  It's +1 so that we make sure it's not
    // adjacent.  Do the MIN_VALUE check to make sure we don't overflow
    // the long.
    if (min != Long.MIN_VALUE && min - 1 > ranges[(rangeCount - 1) * 2 + 1]) {
      insert(min, max, rangeCount);
      return;
    }

    // minPos and maxPos represent inclusive brackets around the various
    // ranges that this new range encompasses.  Anything within these
    // brackets should be folded into the new range.
    int minPos = getMinPos(min);
    int maxPos = getMaxPos(max);

    // minPos and maxPos will switch order if we are either completely
    // within another range or completely outside any ranges.
    if (minPos > maxPos) {
      if (minPos % 2 == 0) {
        // outside any ranges, insert.
        insert(min, max, minPos / 2);
      } // else completely inside a range, nop
    } else {
      combine(min, max, minPos / 2, maxPos / 2);
    }
  }

  /**
   * Removes all values contained in the provided set from this set.
   *
   * <p>The method iterates over the ranges in the supplied {@code RangeSet} and delegates to {@link
   * #remove(Range)} for each. The receiver is mutated, while the argument remains unchanged.
   * Callers must provide a non-{@code null} instance.
   *
   * @param r the set whose contents should be subtracted from this instance.
   * @throws NullPointerException if {@code r} is {@code null}.
   */
  public void remove(RangeSet r) {
    for (Iterator<Range> it = r.iterator(); it.hasNext(); ) {
      remove(it.next());
    }
  }

  /**
   * Removes the specified range of values from this set.
   *
   * <p>A temporary complement-based approach is used to produce the new state, which is then copied
   * back into this instance. Infinite endpoints within the supplied range are honored. The method
   * mutates the receiver but does not alter the input {@link Range}.
   *
   * @param r the range of values to exclude from this set.
   */
  public void remove(Range r) {
    // FIX absolutely horrible implementation.
    RangeSet rs = new RangeSet();
    rs.add(r);
    rs = intersect(rs.complement());
    ranges = rs.ranges;
    rangeCount = rs.rangeCount;
    posInf = rs.posInf;
    negInf = rs.negInf;
  }

  /**
   * Removes a single value from this set when present.
   *
   * <p>The value is treated as a one-element range for removal purposes. No action is taken when
   * the value is already absent. This method mutates the current set.
   *
   * @param i the value to remove from the set.
   */
  public void remove(long i) {
    remove(new Range(i, i));
  }

  /**
   * Removes an inclusive range of values from this set.
   *
   * <p>The call delegates to {@link #remove(Range)} by wrapping the supplied bounds in a {@link
   * Range}. Infinite bounds are not inferred; callers should supply a {@link Range} instance
   * directly when removing unbounded segments.
   *
   * @param min the inclusive lower bound of the range to remove.
   * @param max the inclusive upper bound of the range to remove.
   */
  public void remove(long min, long max) {
    remove(new Range(min, max));
  }

  /**
   * Returns an iterator over normalized {@link Range} instances contained in this set.
   *
   * <p>The iterator produces ranges in ascending order and expands infinity markers into explicit
   * {@link Range} objects. The returned iterator is fail-safe with respect to later mutations of
   * this set because it iterates over a snapshot list created at invocation time.
   *
   * @return an iterator that traverses each stored range exactly once in ascending order.
   */
  public Iterator<Range> iterator() {
    List<Range> rangeList = new ArrayList<>(rangeCount);
    for (int i = 0; i < rangeCount; i++) {
      if (rangeCount == 1 && negInf && posInf) {
        rangeList.add(new Range(true, true));
      } else if (i == 0 && negInf) {
        rangeList.add(new Range(true, ranges[1]));
      } else if (i == rangeCount - 1 && posInf) {
        rangeList.add(new Range(ranges[i * 2], true));
      } else {
        rangeList.add(new Range(ranges[i * 2], ranges[i * 2 + 1]));
      }
    }
    return rangeList.iterator();
  }

  /**
   * Computes the total number of distinct values represented by this set.
   *
   * <p>When either infinite bound is present, the size is reported as {@code -1} to denote an
   * unbounded cardinality. Otherwise, the method sums the sizes of each range. The computation uses
   * a snapshot iterator, so concurrent modifications after invocation are not reflected in the
   * result.
   *
   * @return the count of contained values, or {@code -1} when unbounded because of infinity flags.
   */
  public long size() {
    if (negInf || posInf) {
      return -1;
    }
    long result = 0;
    for (Iterator<Range> it = iterator(); it.hasNext(); ) {
      result += it.next().size();
    }
    return result;
  }

  /**
   * Indicates whether this set currently contains any values.
   *
   * <p>The method inspects the number of stored ranges; infinity flags are irrelevant because they
   * are always accompanied by at least one range entry. No mutation occurs.
   *
   * @return {@code true} when no ranges are present; otherwise {@code false}.
   */
  public boolean isEmpty() {
    return rangeCount == 0;
  }

  /**
   * Parses a comma-separated list of ranges into a {@code RangeSet}.
   *
   * <p>Each token is interpreted via {@link Range#parse(String)} and merged into the result.
   * Whitespace is not trimmed, so callers should provide clean input. Invalid tokens trigger a
   * {@link ParseException}. The returned set is mutable and may be further modified by callers.
   *
   * @param s the string containing one or more ranges separated by commas.
   * @return a {@code RangeSet} representing the parsed ranges in normalized form.
   * @throws ParseException if any token cannot be parsed as a valid {@link Range}.
   * @throws NullPointerException if {@code s} is {@code null}.
   */
  public static RangeSet parse(String s) throws ParseException {
    RangeSet rs = new RangeSet();
    for (StringTokenizer st = new StringTokenizer(s, ","); st.hasMoreTokens(); ) {
      rs.add(Range.parse(st.nextToken()));
    }
    return rs;
  }

  /**
   * Computes a hash code based on stored endpoints and infinity flags.
   *
   * <p>The calculation iterates over all endpoint values in order and incorporates them into the
   * result using a simple multiplicative scheme. The hash is stable across JVM invocations provided
   * the set contents do not change.
   *
   * @return a hash code suitable for use in hashed collections.
   */
  @Override
  public int hashCode() {
    int result = 0;
    for (int i = 0; i < rangeCount * 2; i++) {
      result = (int) (91L * result + ranges[i]);
    }
    return result;
  }

  /**
   * Compares this set to another object for value equality.
   *
   * <p>Two {@code RangeSet} instances are equal when they share identical infinity flags, contain
   * the same number of ranges, and have equal endpoint pairs in the same order. Non-{@code
   * RangeSet} instances are considered unequal. This comparison is deterministic and insensitive to
   * the source of the ranges.
   *
   * @param obj the object to compare against this set.
   * @return {@code true} when the provided object represents the same ranges and flags.
   */
  @Override
  public boolean equals(Object obj) {
    if (!(obj instanceof RangeSet rs)) {
      return false;
    }
    return negInf == rs.negInf
        && posInf == rs.posInf
        && rangeCount == rs.rangeCount
        && Util.arraysEqual(ranges, 0, rs.ranges, 0, rangeCount * 2);
  }

  /**
   * Returns a parsable string representation of this set.
   *
   * <p>The output matches the format expected by {@link #parse(String)}: ranges are comma-separated
   * and expressed using {@link Range#toString()}. Infinite bounds are encoded according to the
   * {@link Range} contract. The method does not modify the set.
   *
   * @return a comma-separated string describing all ranges contained in this set.
   */
  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    for (Iterator<Range> it = iterator(); it.hasNext(); ) {
      sb.append(it.next().toString());
      if (it.hasNext()) {
        sb.append(",");
      }
    }
    return sb.toString();
  }

  /**
   * Creates a shallow copy of this {@code RangeSet}.
   *
   * <p>The returned instance contains identical endpoints and infinity flags but can be mutated
   * independently of the original. Ranges are stored as primitive values, so no deep copy of
   * objects is required.
   *
   * @return a new {@code RangeSet} holding the same ranges and infinity markers.
   */
  public RangeSet copy() {
    return new RangeSet(this);
  }

  /**
   * Demonstrates interactive manipulation of a {@code RangeSet} via standard input.
   *
   * <p>The program seeds an initial set of ranges, prints the set to {@link Logger#info(String)}
   * when enabled, and then processes user commands to add ranges, intersect with another set, or
   * invert the current set. Input of {@code q} ends the loop. This method is intended as a quick
   * manual exploration aid rather than a production interface.
   */
  static void main() throws IOException, ParseException {
    RangeSet rs = RangeSet.parse("5-10,15-20,25-30");
    try (BufferedReader br =
        new BufferedReader(new InputStreamReader(System.in, Charset.defaultCharset()))) {
      boolean exit = false;
      while (!exit) {
        logCurrentSet(rs);
        String input = br.readLine();
        if (input == null) {
          break;
        }
        LoopResult result = processInput(br, rs, input);
        rs = result.rangeSet();
        exit = result.exit();
      }
    }
  }

  private static void logCurrentSet(RangeSet rs) {
    if (LOG.isLoggable(Level.INFO)) {
      LOG.info(rs.toString());
    }
  }

  private static LoopResult processInput(BufferedReader br, RangeSet current, String input)
      throws IOException, ParseException {
    if (input.isEmpty()) {
      return new LoopResult(current, false);
    }
    char command = input.charAt(0);
    return switch (command) {
      case '~' -> new LoopResult(current.complement(), false);
      case 'i' -> {
        String intersectWith = br.readLine();
        if (intersectWith == null) {
          yield new LoopResult(current, true);
        }
        yield new LoopResult(current.intersect(RangeSet.parse(intersectWith)), false);
      }
      case 'q' -> new LoopResult(current, true);
      default -> {
        current.add(RangeSet.parse(input));
        yield new LoopResult(current, false);
      }
    };
  }

  private record LoopResult(RangeSet rangeSet, boolean exit) {}

  private void combine(long min, long max, int minRange, int maxRange) {
    // Fill in the new values into the "leftmost" range.
    ranges[minRange * 2] = Math.min(min, ranges[minRange * 2]);
    ranges[minRange * 2 + 1] = Math.max(max, ranges[maxRange * 2 + 1]);

    // shrink if necessary.
    if (minRange != maxRange && maxRange != rangeCount - 1) {
      System.arraycopy(
          ranges, (maxRange + 1) * 2, ranges, (minRange + 1) * 2, (rangeCount - 1 - maxRange) * 2);
    }

    rangeCount -= maxRange - minRange;
  }

  /**
   * @return the position of the min element within the ranges.
   */
  private int getMinPos(long min) {
    // Search for min-1 so that adjacent ranges are included.
    int pos = binarySearch(min == Long.MIN_VALUE ? min : min - 1);
    return pos >= 0 ? pos : -(pos + 1);
  }

  /**
   * @return the position of the max element within the ranges.
   */
  private int getMaxPos(long max) {
    // Search for max+1 so that adjacent ranges are included.
    int pos = binarySearch(max == Long.MAX_VALUE ? max : max + 1);
    // Return pos-1 if there isn't a direct hit because the max
    // pos is inclusive.
    return pos >= 0 ? pos : -(pos + 1) - 1;
  }

  /**
   * @see Arrays#binarySearch
   */
  private int binarySearch(long key) {
    int low = 0;
    int high = (rangeCount * 2) - 1;

    while (low <= high) {
      int mid = low + ((high - low) >>> 1);
      long midVal = ranges[mid];

      if (midVal < key) {
        low = mid + 1;
      } else if (midVal > key) {
        high = mid - 1;
      } else {
        return mid; // key found
      }
    }
    return -(low + 1); // key not found.
  }

  private void insert(long min, long max, int rangeNum) {

    // grow the array if necessary.
    if (ranges.length == rangeCount * 2) {
      long[] newRanges = new long[ranges.length * 2];
      System.arraycopy(ranges, 0, newRanges, 0, ranges.length);
      ranges = newRanges;
    }

    if (rangeNum != rangeCount) {
      System.arraycopy(
          ranges, rangeNum * 2, ranges, (rangeNum + 1) * 2, (rangeCount - rangeNum) * 2);
    }
    ranges[rangeNum * 2] = min;
    ranges[rangeNum * 2 + 1] = max;
    rangeCount++;
  }
}

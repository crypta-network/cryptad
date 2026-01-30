package com.onionnetworks.util;

import java.text.ParseException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Represents an immutable, inclusive range of long values that can be unbounded on either side.
 *
 * <p>A range may describe a single point, a finite closed interval, or an open-ended span using
 * negative or positive infinity. Instances are normalized at construction time and keep their
 * endpoints unchanged for the lifetime of the object. Because all fields are {@code final} and no
 * mutators are exposed, the type is thread-safe by construction and can be freely shared between
 * threads without coordination. Typical usage includes guarding argument bounds, slicing files or
 * network offsets, or modeling user-configurable limits such as rate caps.
 *
 * <p>Notable behaviors include:
 *
 * <ul>
 *   <li>Endpoints are inclusive; {@link #size()} returns {@code -1} for any infinite boundary.
 *   <li>{@link #toString()} renders negative infinity with {@code (} and positive infinity with
 *       {@code )}, mirroring the accepted {@link #parse(String)} syntax.
 *   <li>Construction guards against {@code min > max} and inconsistent infinity flags to keep
 *       invariants intact.
 * </ul>
 *
 * @see #parse(String)
 */
public class Range {

  private static final Logger LOGGER = Logger.getLogger(Range.class.getName());

  private final boolean negInf;
  private final boolean posInf;
  private final long min;
  private final long max;

  /**
   * Creates a range that represents exactly one numeric value.
   *
   * <p>The resulting instance has identical minimum and maximum bounds and no infinite endpoints.
   * It is useful for callers that want to reuse API contracts expecting a range while passing a
   * single probe value. Because the class is immutable, repeated calls can safely share the same
   * instance without additional synchronization or copying.
   *
   * @param num inclusive value captured by both endpoints; any 64-bit signed long is accepted
   */
  public Range(long num) {
    this(num, num, false, false);
  }

  /**
   * Creates a finite inclusive range bounded by the supplied minimum and maximum values.
   *
   * <p>The constructor enforces {@code min <= max} and stores both bounds verbatim. Use this
   * variant when you want explicit closed intervals that will later be compared or combined with
   * other ranges. Because validation happens eagerly, invalid input fails fast instead of producing
   * a partially defined object.
   *
   * @param min inclusive lower endpoint; must be less than or equal to {@code max}
   * @param max inclusive upper endpoint; must be greater than or equal to {@code min}
   * @throws IllegalArgumentException if {@code min} exceeds {@code max}
   */
  public Range(long min, long max) {
    this(min, max, false, false);
  }

  /**
   * Creates an inclusive range from a concrete lower bound to positive infinity.
   *
   * <p>The upper endpoint is treated as unbounded, so operations such as {@link #size()} report
   * {@code -1}. The {@code posInf} flag must explicitly confirm the caller intends an infinite
   * upper bound, preventing accidental construction when a boolean is misordered or misread. The
   * created object remains immutable and safe for concurrent sharing.
   *
   * @param min inclusive lower endpoint that anchors the range on the left side
   * @param posInf must be {@code true} to request an unbounded upper endpoint; otherwise rejected
   * @throws IllegalArgumentException if {@code posInf} is {@code false}
   */
  public Range(long min, boolean posInf) {
    this(min, Long.MAX_VALUE, false, posInf);
    if (!posInf) {
      throw new IllegalArgumentException("posInf must be true");
    }
  }

  /**
   * Creates an inclusive range from negative infinity up to a concrete upper bound.
   *
   * <p>The lower endpoint is unbounded, yielding a {@link #size()} of {@code -1}. The explicit
   * {@code negInf} confirmation prevents mistaken calls that would otherwise mask argument order
   * issues. Use this constructor when modeling ceilings, quotas, or any situation where only the
   * maximum meaningful value is known.
   *
   * @param negInf must be {@code true} to request an unbounded lower endpoint; otherwise rejected
   * @param max inclusive upper endpoint that caps the allowable values in this range
   * @throws IllegalArgumentException if {@code negInf} is {@code false}
   */
  public Range(boolean negInf, long max) {
    this(Long.MIN_VALUE, max, negInf, false);
    if (!negInf) {
      throw new IllegalArgumentException("negInf must be true");
    }
  }

  /**
   * Creates an inclusive range that spans negative infinity through positive infinity.
   *
   * <p>This form represents an unbounded interval where any {@code long} is considered contained.
   * It is useful as a default sentinel or placeholder when no constraints are known. Both boolean
   * arguments must be {@code true}; otherwise the constructor rejects the request to avoid silently
   * producing partially infinite intervals.
   *
   * @param negInf must be {@code true} to enable an unbounded lower endpoint
   * @param posInf must be {@code true} to enable an unbounded upper endpoint
   * @throws IllegalArgumentException if either flag is {@code false}
   */
  public Range(boolean negInf, boolean posInf) {
    this(Long.MIN_VALUE, Long.MAX_VALUE, negInf, posInf);
    if (!negInf || !posInf) {
      throw new IllegalArgumentException("negInf && posInf must be true");
    }
  }

  private Range(long min, long max, boolean negInf, boolean posInf) {
    if (min > max) {
      throw new IllegalArgumentException("min cannot be greater than max");
    }
    // very common bug, its worth reporting for now.
    if (min == 0 && max == 0) {
      LOGGER.log(
          Level.WARNING,
          "Range.debug: 0-0 range detected. Did you intend to do this?",
          new Exception());
    }
    this.min = min;
    this.max = max;
    this.negInf = negInf;
    this.posInf = posInf;
  }

  /**
   * Reports whether the lower endpoint is negative infinity.
   *
   * <p>The value is determined at construction time and never changes, making it safe to cache in
   * calling code. A {@code true} result indicates any value less than or equal to the upper bound
   * is considered contained, regardless of how small it is. Use this to branch logic between
   * bounded and unbounded intervals without inspecting the raw endpoints.
   *
   * @return {@code true} when this range has an unbounded lower endpoint, otherwise {@code false}
   */
  public boolean isMinNegInf() {
    return negInf;
  }

  /**
   * Reports whether the upper endpoint is positive infinity.
   *
   * <p>The value is fixed for the lifetime of the instance. A {@code true} result means containment
   * checks treat any value greater than or equal to the lower bound as within the range. This is
   * helpful when choosing algorithms that should avoid subtracting or adding offsets that might
   * overflow when the upper bound is unbounded.
   *
   * @return {@code true} when this range has an unbounded upper endpoint, otherwise {@code false}
   */
  public boolean isMaxPosInf() {
    return posInf;
  }

  /**
   * Returns the inclusive lower endpoint for this range.
   *
   * <p>For ranges with a negative-infinite lower bound, the returned value is {@link
   * Long#MIN_VALUE} and should be interpreted as a sentinel rather than an actual boundary. Because
   * the class is immutable, callers can reuse the result without concern for later updates or
   * synchronization concerns.
   *
   * @return inclusive minimum endpoint, or {@link Long#MIN_VALUE} when lower bound is infinite
   */
  public long getMin() {
    return min;
  }

  /**
   * Returns the inclusive upper endpoint for this range.
   *
   * <p>For ranges with a positive-infinite upper bound, the returned value is {@link
   * Long#MAX_VALUE} and represents an unbounded sentinel rather than a strict cap. The value
   * remains stable for the lifetime of the instance and can be safely cached alongside other
   * derived calculations.
   *
   * @return inclusive maximum endpoint, or {@link Long#MAX_VALUE} when upper bound is infinite
   */
  public long getMax() {
    return max;
  }

  /**
   * Computes the number of distinct {@code long} values contained in this range.
   *
   * <p>Finite ranges return {@code max - min + 1}, while any range with an infinite endpoint
   * returns {@code -1} to signal unbounded length. Callers should check for {@code -1} before
   * relying on the value in arithmetic to avoid overflow or inappropriate allocations. The
   * operation runs in constant time without side effects.
   *
   * @return count of values for finite ranges, or {@code -1} when either endpoint is infinite
   */
  public long size() {
    if (negInf || posInf) {
      return -1;
    }
    return max - min + 1;
  }

  /**
   * Tests whether the provided value lies within this inclusive range.
   *
   * <p>The check compares the argument to the stored endpoints without side effects. For ranges
   * with infinite bounds, containment collapses to a single-sided comparison because the infinite
   * side always satisfies the inequality. The method is deterministic and can be used in tight
   * loops or validation paths without additional caching.
   *
   * @param i candidate value to test against the range boundaries; any 64-bit signed long
   * @return {@code true} when {@code i} falls between the endpoints, inclusive; otherwise {@code
   *     false}
   */
  public boolean contains(long i) {
    return i >= min && i <= max;
  }

  /**
   * Determines whether this range fully contains another range.
   *
   * <p>The comparison uses the stored endpoints and does not consider object identity. A {@code
   * true} result means both the other range's minimum and maximum fall within this range's bounds.
   * For infinite endpoints the sentinel values {@link Long#MIN_VALUE} and {@link Long#MAX_VALUE}
   * are used, which aligns with how the class models unbounded sides. The method is symmetric only
   * when both ranges share identical endpoints.
   *
   * @param r candidate range whose bounds will be compared against this instance; must not be
   *     {@code null}
   * @return {@code true} if {@code r} is wholly contained within this range; otherwise {@code
   *     false}
   */
  public boolean contains(Range r) {
    return r.min >= min && r.max <= max;
  }

  /**
   * Produces a hash code derived from the stored endpoints and infinity markers.
   *
   * <p>The implementation combines the numeric bounds in a simple linear expression, which favors
   * speed over distribution quality. Because the class is immutable, the hash code is stable for
   * the lifetime of the instance and is safe to cache within hashed data structures such as {@link
   * java.util.HashMap}. Different ranges may still collide, so callers should not rely on
   * uniqueness.
   *
   * @return deterministic hash value suitable for use in hash-based collections
   */
  @Override
  public int hashCode() {
    return (int) (min + 23 * max);
  }

  /**
   * Compares this range to another object for structural equality.
   *
   * <p>The comparison succeeds only when the other object is also a {@code Range} with identical
   * endpoints and matching infinity flags. The method performs no tolerance or overlap checks; two
   * ranges that represent equivalent mathematical intervals but were constructed differently will
   * only compare equal if their stored values match exactly. The method is reflexive, symmetric,
   * and transitive as required by the {@link Object#equals(Object)} contract.
   *
   * @param obj object to compare against this instance; non-{@code Range} values yield {@code
   *     false}
   * @return {@code true} when all endpoints and infinity markers are identical; otherwise {@code
   *     false}
   */
  @Override
  public boolean equals(Object obj) {
    if (obj instanceof Range other) {
      return other.min == min
          && other.max == max
          && other.negInf == negInf
          && other.posInf == posInf;
    }
    return false;
  }

  /**
   * Renders this range as a compact string representation.
   *
   * <p>Single-point ranges are printed as the lone numeric value. Finite intervals use the format
   * {@code "<min>-<max>"}. An unbounded lower endpoint is rendered with a leading parenthesis
   * {@code (}, while an unbounded upper endpoint is rendered with a trailing parenthesis {@code )},
   * matching the syntax accepted by {@link #parse(String)}. The method allocates only short-lived
   * strings and performs no logging or side effects.
   *
   * @return human-readable representation of this range that can be fed back into {@link
   *     #parse(String)}
   */
  @Override
  public String toString() {
    if (!negInf && !posInf && min == max) {
      return Long.toString(min);
    } else {
      return (negInf ? "(" : "" + min) + "-" + (posInf ? ")" : "" + max);
    }
  }

  /**
   * This method creates a new range from a String. Allowable characters are all integer values,
   * "-", ")", and "(". The open and closed parens indicate positive and negative infinity.
   *
   * <pre>
   * Example strings would be:
   * "11" is the range that only includes 11
   * "-6" is the range that only includes -6
   * "10-20" is the range 10 through 20 (inclusive)
   * "-10--5" is the range -10 through -5
   * "(-20" is the range negative infinity through 20
   * "30-)" is the range 30 through positive infinity.
   * </pre>
   *
   * @param s The String to parse
   * @return The resulting range
   * @throws ParseException if the string is empty, malformed, or contains non-numeric endpoints
   */
  public static Range parse(String s) throws ParseException {
    try {
      long min = 0;
      long max = 0;
      boolean negInf = false;
      boolean posInf = false;
      // search from the 1 pos because it may be a negative number.
      int dashPos = s.indexOf("-", 1);
      if (dashPos == -1) { // no dash, one value.
        min = max = Long.parseLong(s);
      } else {
        if (s.contains("(")) {
          negInf = true;
        } else {
          min = Long.parseLong(s.substring(0, dashPos));
        }
        if (s.contains(")")) {
          posInf = true;
        } else {
          max = Long.parseLong(s.substring(dashPos + 1));
        }
      }
      if (negInf) {
        if (posInf) {
          return new Range(true, true);
        } else {
          return new Range(true, max);
        }
      } else if (posInf) {
        return new Range(min, true);
      } else {
        return new Range(min, max);
      }
    } catch (RuntimeException e) {
      throw new ParseException(e.getMessage(), -1);
    }
  }
}

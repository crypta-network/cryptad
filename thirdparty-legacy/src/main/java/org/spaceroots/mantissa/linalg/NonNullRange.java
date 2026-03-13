package org.spaceroots.mantissa.linalg;

import java.io.Serial;
import java.io.Serializable;

/**
 * Immutable description of the contiguous indexes that may contain non-null entries in a matrix row
 * or column.
 *
 * <p>This helper encapsulates structural sparsity knowledge so loops can skip leading and trailing
 * zeros without probing actual values. A {@code NonNullRange} instance is a half-open interval
 * {@code [begin, end)} expressed in row/column coordinates where {@code begin} is inclusive and
 * {@code end} is exclusive. The class is deliberately minimal: it stores only the bounds, is fully
 * thread-safe because it is immutable, and can be freely copied or passed between computation
 * stages.
 *
 * <p>Typical use cases include precomputing ranges for common matrix shapes. For example, a dense
 * row has {@code begin = 0} and {@code end = order}, a diagonal row has {@code begin = i} and
 * {@code end = i + 1}, and a lower triangular row has {@code begin = 0} with {@code end} depending
 * on the row index. Consumers can build intersections to refine sparsity for chained operations or
 * reunions to cover combined support when adding matrices.
 *
 * <ul>
 *   <li>Contiguous: represents one continuous block only; gaps require separate ranges.
 *   <li>Structure-driven: bounds reflect matrix shape expectations, not inspected values.
 *   <li>Lightweight: no allocation beyond two integers; safe to construct per iteration.
 * </ul>
 *
 * @version $Id: NonNullRange.java 1709 2006-12-03 21:16:50Z luc $
 * @author L. Maisonobe
 */
public class NonNullRange implements Serializable {

  /**
   * Index in row or column coordinates of the first structurally non-null element. The value is
   * inclusive and is expected to be greater than or equal to zero for valid matrix indices.
   */
  public final int begin;

  /**
   * Index immediately after the last structurally non-null element in the row or column. This upper
   * bound is exclusive and typically does not exceed the matrix order for well-formed input.
   */
  public final int end;

  /**
   * Creates a range with the provided inclusive start and exclusive end bounds.
   *
   * <p>The constructor does not enforce ordering or matrix size constraints; callers must ensure
   * {@code begin <= end} and that both indices fall inside the intended matrix dimension. Because
   * the class is immutable, the created instance can be reused across threads without additional
   * synchronization.
   *
   * @param begin index in row or column coordinates marking the first possible non-null entry; must
   *     align with the structural sparsity definition used by the caller
   * @param end index immediately after the last possible non-null entry, using the same coordinate
   *     system; should be greater than or equal to {@code begin}
   */
  public NonNullRange(int begin, int end) {
    this.begin = begin;
    this.end = end;
  }

  /**
   * Creates a new instance that duplicates the bounds of an existing range.
   *
   * <p>The source instance is not retained, so modifications to external references cannot affect
   * the newly created object. This is mostly a convenience to emphasize intent when forwarding or
   * caching range values across API layers.
   *
   * @param range source range whose {@code begin} and {@code end} values are replicated; must not
   *     be {@code null}
   */
  public NonNullRange(NonNullRange range) {
    begin = range.begin;
    end = range.end;
  }

  /**
   * Builds a new range representing the intersection of two half-open intervals.
   *
   * <p>The resulting bounds are computed by taking the maximum of the starts and the minimum of the
   * ends. If the intervals do not overlap, the returned range may have {@code begin > end}, which
   * callers can treat as an empty structural region. The method never mutates its inputs and always
   * returns a fresh {@link NonNullRange} instance.
   *
   * @param first first range whose bounds contribute to the intersection; must not be {@code null}
   * @param second second range whose bounds contribute to the intersection; must not be {@code
   *     null}
   * @return new range describing the shared structural support, possibly empty when inputs are
   *     disjoint
   */
  public static NonNullRange intersection(NonNullRange first, NonNullRange second) {
    return new NonNullRange(Math.max(first.begin, second.begin), Math.min(first.end, second.end));
  }

  /**
   * Builds a range that spans every index covered by either of the provided ranges.
   *
   * <p>Also known as the union, this operation chooses the smallest {@code begin} and the largest
   * {@code end} of the inputs to ensure all potentially non-null elements are included. The method
   * performs no validation on ordering; if inputs are malformed, the returned bounds mirror that
   * state. A new {@link NonNullRange} is always created, leaving the arguments unchanged.
   *
   * @param first first range whose bounds contribute to the union; must not be {@code null}
   * @param second second range whose bounds contribute to the union; must not be {@code null}
   * @return new range that fully encloses both inputs, preserving half-open semantics
   */
  public static NonNullRange reunion(NonNullRange first, NonNullRange second) {
    return new NonNullRange(Math.min(first.begin, second.begin), Math.max(first.end, second.end));
  }

  @Serial private static final long serialVersionUID = 8175301560126132666L;
}

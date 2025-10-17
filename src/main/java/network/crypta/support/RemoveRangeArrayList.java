package network.crypta.support;

import java.io.Serial;
import java.util.ArrayList;

/**
 * An {@link ArrayList} variant that exposes {@code removeRange(int, int)} as a public API.
 *
 * <p>This class behaves exactly like {@link ArrayList} with the only difference being that the
 * normally {@code protected} {@code removeRange} method is made {@code public}. This is useful in
 * code paths that need to efficiently delete a contiguous slice of elements without constructing a
 * {@link java.util.List#subList(int, int) subList} or performing multiple single-element removes.
 *
 * <p>Null elements are permitted; iteration order and all other semantics are identical to {@link
 * ArrayList}. This type is not thread-safe.
 *
 * @param <T> the element type stored in the list
 */
public class RemoveRangeArrayList<T> extends ArrayList<T> {

  // Serial version for interoperability of serialized forms across compatible versions.
  @Serial private static final long serialVersionUID = -1L;

  /**
   * Creates a list with the specified initial capacity.
   *
   * <p>The list grows as needed; the capacity argument is only a performance hint for internal
   * array sizing.
   *
   * @param capacity the initial capacity of the list (non-negative)
   * @throws IllegalArgumentException if {@code capacity} is negative
   */
  public RemoveRangeArrayList(int capacity) {
    super(capacity);
  }

  /**
   * Removes elements in the half-open interval {@code [fromIndex, toIndex)} from this list.
   *
   * <p>All elements with indices {@code fromIndex} through {@code toIndex - 1} are deleted. Any
   * subsequent elements are shifted left to fill the gap, and the size decreases by {@code (toIndex
   * - fromIndex)}. This is a structural modification and invalidates any active iterators.
   *
   * <p>Time complexity is linear in the number of elements moved (proportional to the remainder of
   * the list after {@code toIndex}).
   *
   * @param fromIndex the start index, inclusive
   * @param toIndex the end index, exclusive
   * @throws IndexOutOfBoundsException if an index is out of range ({@code fromIndex < 0}, {@code
   *     toIndex > size()}, or {@code fromIndex > toIndex})
   */
  @Override
  public void removeRange(int fromIndex, int toIndex) {
    super.removeRange(fromIndex, toIndex);
  }
}

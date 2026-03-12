package network.crypta.support;

import java.util.List;
import java.util.Random;

/**
 * Utilities for destructive removals from {@link java.util.List} without preserving element order.
 *
 * <p>The helpers here remove an element by swapping it with the list's last element and then
 * truncating the list. This yields O(1) data movement on typical array-backed lists (for example,
 * {@link java.util.ArrayList}), at the cost of changing the relative order of elements. These
 * operations are not synchronized and make no attempt to be thread-safe.
 *
 * <p>Performance characteristics assume a list with:
 *
 * <ul>
 *   <li>O(1) random access and {@code set(int, E)}
 *   <li>O(1) removal of the last element
 * </ul>
 *
 * Using a linked-list implementation will typically degrade performance to O(n).
 */
public class ListUtils {
  private ListUtils() {}

  /**
   * Removes the first occurrence of {@code o} by swapping it with the last element and truncating
   * the list.
   *
   * <p>Complexity: O(n) to locate the element (via {@link List#indexOf(Object)}), then O(1) data
   * movement on array-backed lists. Order is not preserved.
   *
   * @param <E> element type
   * @param a list to mutate; must support {@code get(int)}, {@code set(int, E)}, and removal of the
   *     last element in O(1)
   * @param o element to remove; {@code null} is permitted
   * @return {@code true} if an element equal to {@code o} was found and removed; {@code false}
   *     otherwise
   */
  @SuppressWarnings("SuspiciousMethodCalls")
  public static <E> boolean removeBySwapLast(List<E> a, Object o) {
    int idx = a.indexOf(o);
    if (idx == -1) return false;
    removeBySwapLast(a, idx);
    return true;
  }

  /**
   * Removes the element at {@code idx} by swapping it with the last element and truncating the
   * list.
   *
   * <p>Complexity: O(1) data movement on array-backed lists. Order is not preserved.
   *
   * <p>Return value note: Unlike {@link List#remove(int)}, this method returns the element that was
   * moved into position {@code idx}. When {@code idx} points to the last element, the removed
   * element is returned (nothing is moved).
   *
   * @param <E> element type
   * @param a list to mutate; must support {@code get(int)}, {@code set(int, E)}, and removal of the
   *     last element in O(1)
   * @param idx index of the element to remove; valid range is {@code [0, a.size())}
   * @return the element moved into position {@code idx}, or the removed element when {@code idx}
   *     was the last index
   * @throws IndexOutOfBoundsException if {@code idx} is negative or not less than {@code a.size()}
   */
  public static <E> E removeBySwapLast(List<E> a, int idx) {
    int size = a.size();
    if (idx < 0 || idx >= size)
      throw new IndexOutOfBoundsException(idx + " out of range [0;" + size + ")");
    E moved = a.remove(size - 1);
    if (idx != size - 1) a.set(idx, moved);
    return moved;
  }

  /**
   * Result tuple for random removal operations.
   *
   * @param <E> element type
   * @param removed the element removed from the list; never {@code null} if the list contained a
   *     non-{@code null} element at the chosen index
   * @param moved the element that was moved to fill the vacated slot; equals {@code removed} when
   *     the removed element was the last element or when the list size was 1
   */
  public record RandomRemoveResult<E>(E removed, E moved) {}

  /**
   * Removes a uniformly random element by swapping it with the last element and truncating the
   * list.
   *
   * <p>The index is selected with {@link Random#nextInt(int)}. When the list has size 1, the random
   * source is not consulted; the sole element is removed and returned as both the {@code removed}
   * and {@code moved} components. Order is not preserved.
   *
   * <p>The amount of random data consumed depends on the {@link Random} implementation.
   *
   * @param <E> element type
   * @param random source of randomness; must not be {@code null} when {@code a.size() > 1}
   * @param a list to mutate; must support {@code get(int)}, {@code set(int, E)}, and removal of the
   *     last element in O(1)
   * @return {@code null} if the list is empty; otherwise a {@link RandomRemoveResult} whose {@code
   *     removed} component is no longer present in the list and whose {@code moved} component
   *     either equals {@code removed} or is still present in the list
   */
  public static <E> RandomRemoveResult<E> removeRandomBySwapLast(Random random, List<E> a) {
    int size = a.size();
    if (size == 0) return null;
    if (size == 1) {
      // Short-circuit: avoid invoking the random source for a single-element list.
      E removed = a.removeFirst();
      return new RandomRemoveResult<>(removed, removed);
    }
    int idx = random.nextInt(size);
    E removed = a.get(idx);
    return new RandomRemoveResult<>(removed, removeBySwapLast(a, idx));
  }

  /**
   * Removes a uniformly random element by swapping it with the last element and truncating the
   * list, returning only the removed element.
   *
   * <p>Semantics are identical to {@link #removeRandomBySwapLast(Random, List)} except that only
   * the removed element is returned. When the list has size 1, the random source is not consulted.
   * Order is not preserved.
   *
   * @param <E> element type
   * @param random source of randomness; must not be {@code null} when {@code a.size() > 1}
   * @param a list to mutate; must support {@code get(int)}, {@code set(int, E)}, and removal of the
   *     last element in O(1)
   * @return {@code null} if the list is empty; otherwise the removed element
   */
  public static <E> E removeRandomBySwapLastSimple(Random random, List<E> a) {
    int size = a.size();
    if (size == 0) return null;
    if (size == 1) {
      // Short-circuit: avoid invoking the random source for a single-element list.
      return a.removeFirst();
    }
    int idx = random.nextInt(size);
    E removed = a.get(idx);
    removeBySwapLast(a, idx);
    return removed;
  }
}

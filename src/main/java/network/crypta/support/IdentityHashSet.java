package network.crypta.support;

import java.util.Collection;
import java.util.IdentityHashMap;
import java.util.Iterator;
import java.util.Set;
import org.jetbrains.annotations.NotNull;

/**
 * A {@link Set} whose membership and uniqueness are based on reference identity (the {@code ==}
 * operator) rather than {@link Object#equals(Object)}.
 *
 * <p>This implementation is a thin wrapper around an {@link IdentityHashMap} where each element is
 * stored as a key and the value is an unused sentinel. It permits {@code null} elements.
 *
 * <p>Concurrency and performance:
 *
 * <ul>
 *   <li>Not thread-safe. Use external synchronization when accessed from multiple threads.
 *   <li>Iteration order is unspecified and may change when the set is modified.
 *   <li>Typical operations ({@code add}, {@code contains}, {@code remove}) run in expected constant
 *       time on average.
 * </ul>
 *
 * @param <T> element type stored in the set
 */
public class IdentityHashSet<T> implements Set<T> {

  // Keys are the elements (compared by identity). Values are an unused, non-null sentinel.
  private final IdentityHashMap<T, Object> map = new IdentityHashMap<>();

  /**
   * Adds the specified element if it is not already present (by reference identity).
   *
   * @param e element to add; may be {@code null}.
   * @return {@code true} if this set changed as a result of the call.
   */
  @Override
  public boolean add(T e) {
    return map.put(e, this) == null;
  }

  /**
   * Adds all the elements in the specified collection to this set (subject to identity semantics).
   *
   * <p>Per the {@link Collection#addAll(Collection) Collection} contract, returns {@code true} if
   * and only if the set changed as a result of the call.
   *
   * @param c collection whose elements are to be added; must not be {@code null}.
   * @return {@code true} if this set changed as a result of the call.
   * @throws NullPointerException if {@code c} is {@code null}.
   */
  @Override
  public boolean addAll(Collection<? extends T> c) {
    boolean changed = false;
    for (T item : c) {
      if (add(item)) changed = true;
    }
    return changed;
  }

  /**
   * Removes all elements from this set.
   *
   * <p>After this call, {@link #size()} returns {@code 0} and {@link #isEmpty()} returns {@code
   * true}.
   */
  @Override
  public void clear() {
    map.clear();
  }

  /**
   * Returns {@code true} if this set contains the specified element, comparing by reference
   * identity.
   *
   * @param o element whose presence is to be tested; may be {@code null}.
   * @return {@code true} if an element {@code e} exists such that {@code e == o}.
   */
  @Override
  @SuppressWarnings("SuspiciousMethodCalls")
  public boolean contains(Object o) {
    return map.containsKey(o);
  }

  /**
   * Returns {@code true} if this set contains all the elements in the specified collection,
   * comparing by reference identity.
   *
   * @param c collection whose elements are to be checked for containment; must not be {@code null}.
   * @return {@code true} if for every element {@code x} in {@code c} there exists {@code e} in this
   *     set such that {@code e == x}.
   * @throws NullPointerException if {@code c} is {@code null}.
   */
  @Override
  public boolean containsAll(@NotNull Collection<?> c) {
    return map.keySet().containsAll(c);
  }

  /** Returns {@code true} if this set contains no elements. */
  @Override
  public boolean isEmpty() {
    return map.isEmpty();
  }

  /**
   * Returns an iterator over the elements in this set.
   *
   * <p>The iterator traverses elements in an unspecified order. It is typically fail-fast with
   * respect to concurrent structural modifications (as provided by the backing {@link
   * IdentityHashMap}) and may throw {@link java.util.ConcurrentModificationException} if the set is
   * modified after the iterator is created, except through the iterator's own {@link
   * Iterator#remove()} method.
   *
   * @return a non-null iterator over the elements of this set.
   */
  @Override
  public @NotNull Iterator<T> iterator() {
    return map.keySet().iterator();
  }

  /**
   * Removes the specified element from this set if it is present (matching by identity).
   *
   * @param o element to remove; may be {@code null}.
   * @return {@code true} if an element was removed as a result of this call.
   */
  @Override
  public boolean remove(Object o) {
    return map.remove(o) != null;
  }

  /**
   * Removes from this set all of its elements that are contained in the specified collection
   * (matching by identity).
   *
   * @param c collection containing elements to be removed; must not be {@code null}.
   * @return {@code true} if this set changed as a result of the call.
   * @throws NullPointerException if {@code c} is {@code null}.
   */
  @Override
  public boolean removeAll(Collection<?> c) {
    boolean changed = false;
    for (Object o : c) {
      if (remove(o)) changed = true;
    }
    return changed;
  }

  /**
   * Retains only the elements in this set that are contained in the specified collection.
   *
   * <p>This operation is not supported by this implementation and always throws {@link
   * UnsupportedOperationException}.
   *
   * @param c collection whose elements are to be retained.
   * @return never returns normally.
   * @throws UnsupportedOperationException always.
   */
  @Override
  public boolean retainAll(@NotNull Collection<?> c) {
    throw new UnsupportedOperationException();
  }

  /** Returns the number of elements in this set. */
  @Override
  public int size() {
    return map.size();
  }

  /**
   * Returns an array containing all the elements in this set.
   *
   * <p>The returned array reference is never {@code null}, but its elements may be {@code null}
   * when this set contains {@code null}.
   *
   * @return a non-null array containing the elements of this set in unspecified order. The elements
   *     may include {@code null}.
   */
  @Override
  @SuppressWarnings("NullableProblems")
  public @NotNull Object[] toArray() {
    return map.keySet().toArray();
  }

  /**
   * Returns an array containing all the elements in this set; the runtime type of the returned
   * array is that of the specified array. If the set fits in the specified array, it is returned
   * therein. Otherwise, a new array is allocated with the runtime type of the specified array and
   * the size of this set.
   *
   * <p>Per the {@link java.util.Collection#toArray(Object[])} contract, if the set fits in the
   * specified array with room to spare (that is, the array has more elements than the set), the
   * element in the array immediately following the end of the set is set to {@code null}. As a
   * result, the returned array's elements may include {@code null} even if the array instance is
   * non-null.
   *
   * @param <U> runtime component type of the destination array.
   * @param a destination array; must not be {@code null}.
   * @return the array containing the elements; either {@code a} if it was large enough, or a new
   *     array of the same runtime type.
   * @throws NullPointerException if {@code a} is {@code null}.
   * @throws ArrayStoreException if the runtime type of {@code a} is not a supertype of the elements
   *     contained in this set.
   */
  @Override
  @SuppressWarnings("NullableProblems")
  public <U> @NotNull U[] toArray(@NotNull U[] a) {
    return map.keySet().toArray(a);
  }
}

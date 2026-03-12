package network.crypta.support;

import java.util.AbstractSet;
import java.util.Collection;
import java.util.Iterator;
import java.util.WeakHashMap;
import org.jetbrains.annotations.NotNull;

public class WeakHashSet<E> extends AbstractSet<E> {

  private final WeakHashMap<E, Object> map;
  private static final Object PLACEHOLDER = new Object();

  public WeakHashSet() {
    map = new WeakHashMap<>();
  }

  @Override
  public boolean add(E key) {
    return map.put(key, PLACEHOLDER) == null;
  }

  @Override
  public void clear() {
    map.clear();
  }

  @Override
  @SuppressWarnings("SuspiciousMethodCalls")
  public boolean contains(Object key) {
    return map.containsKey(key);
  }

  @Override
  public boolean containsAll(@NotNull Collection<?> collection) {
    return map.keySet().containsAll(collection);
  }

  @Override
  public boolean isEmpty() {
    return map.isEmpty();
  }

  @Override
  public @NotNull Iterator<E> iterator() {
    return map.keySet().iterator();
  }

  @Override
  public boolean remove(Object key) {
    return map.remove(key) != null;
  }

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
   * @param <T> runtime component type of the destination array.
   * @param array destination array; must not be {@code null}.
   * @return the array containing the elements; either {@code array} if it was large enough, or a
   *     new array of the same runtime type.
   * @throws NullPointerException if {@code array} is {@code null}.
   * @throws ArrayStoreException if the runtime type of {@code array} is not a supertype of the
   *     elements contained in this set.
   */
  @Override
  @SuppressWarnings("NullableProblems")
  public <T> @NotNull T[] toArray(@NotNull T[] array) {
    return map.keySet().toArray(array);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;
    // Delegate to AbstractSet's equals to preserve Set semantics.
    return super.equals(obj);
  }

  @Override
  public int hashCode() {
    // Delegate to AbstractSet's hashCode to preserve Set semantics.
    return super.hashCode();
  }
}

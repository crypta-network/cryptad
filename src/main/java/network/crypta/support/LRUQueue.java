package network.crypta.support;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Objects;

/**
 * A hash-indexed least-recently-used (LRU) queue with {@code O(1)} updates.
 *
 * <p>This queue stores each element at most once. Calling {@link #push(Object)} with an element
 * that is already present moves it to the most recently used position (the head) rather than
 * inserting a duplicate. {@link #pushLeast(Object)} inserts or moves an element to the least
 * recently used position (the tail). {@link #pop()} removes and returns the least recently used
 * element.
 *
 * <p>Implementation notes: the queue maintains order in an intrusive {@link DoublyLinkedListImpl}
 * and a {@link java.util.HashMap} from element to list node to avoid duplicates and to provide
 * constant-time membership checks and removals.
 *
 * <p>Concurrency: Most operations synchronize on {@code this}. Mutations and the majority of read
 * operations (e.g., {@link #contains(Object)}, {@link #toArray()}, {@link #toArrayOrdered()},
 * {@link #clear()}, {@link #get(Object)}, and {@link #elements()}) are synchronized. The {@link
 * #size()} method is not synchronized and may observe transient states if other threads mutate the
 * queue concurrently. The iterator returned by {@link #elements()} is built from a snapshot
 * captured while holding the monitor; it does not reflect later mutations.
 *
 * <p>Nullability: {@link #push(Object)}, {@link #pushLeast(Object)}, and {@link #remove(Object)}
 * reject {@code null} and throw {@link NullPointerException}. Other lookups using {@code null}
 * simply return {@code null} or {@code false}.
 *
 * <p>Complexity: {@code push}, {@code pushLeast}, {@code pop}, {@code remove}, and {@code contains}
 * are {@code O(1)}; array conversions and enumerations are {@code O(n)}.
 *
 * @param <T> element type stored in the queue; must provide stable {@link Object#equals(Object)}
 *     and {@link Object#hashCode()} while enqueued
 */
public class LRUQueue<T> {

  /*
   * Data structure overview:
   * - 'list' preserves LRU order: head = most recently used; tail = least recently used.
   * - 'hash' maps each element to its intrusive list node for O(1) lookup/removal.
   * Invariants: every node in 'list' is referenced by exactly one entry in 'hash' and vice versa.
   */
  private final DoublyLinkedListImpl<QItem<T>> list = new DoublyLinkedListImpl<>();
  private final Map<T, QItem<T>> hash = new HashMap<>();

  // Default constructor intentionally implicit; no additional initialization required.

  /**
   * Inserts an element at the most recently used position (head).
   *
   * <p>If the element is already present, it is moved to the head and the queue does not contain a
   * duplicate.
   *
   * @param obj element to record as most recently used; must not be {@code null}
   * @throws NullPointerException if {@code obj} is {@code null}
   */
  public final synchronized void push(T obj) {
    if (obj == null) throw new NullPointerException();

    QItem<T> insert = hash.get(obj);
    if (insert == null) {
      insert = new QItem<>(obj);
      hash.put(obj, insert);
    } else {
      list.remove(insert);
    }

    list.unshift(insert);
  }

  /**
   * Inserts an element at the least recently used position (tail).
   *
   * <p>If the element is already present, it is moved to the tail and the queue does not contain a
   * duplicate.
   *
   * @param obj element to record as least recently used; must not be {@code null}
   * @throws NullPointerException if {@code obj} is {@code null}
   */
  public synchronized void pushLeast(T obj) {
    if (obj == null) throw new NullPointerException();

    QItem<T> insert = hash.get(obj);
    if (insert == null) {
      insert = new QItem<>(obj);
      hash.put(obj, insert);
    } else {
      list.remove(insert);
    }

    list.push(insert);
  }

  /**
   * Removes and returns the least recently used element.
   *
   * @return the LRU element, or {@code null} if the queue is empty
   */
  public final synchronized T pop() {
    if (!list.isEmpty()) {
      QItem<T> popped = list.pop();
      QItem<T> notNull =
          Objects.requireNonNull(popped, "List.pop() returned null despite non-empty");
      return hash.remove(notNull.obj).obj;
    } else {
      return null;
    }
  }

  /**
   * Returns the current number of elements.
   *
   * <p>Concurrency: This method is not synchronized and may return a stale value if other threads
   * mutate the queue concurrently. For a consistent view in multithreaded code, call it while
   * holding the same lock used by the synchronized methods on this class.
   *
   * @return element count (non-negative)
   */
  public final int size() {
    return list.size();
  }

  @SuppressWarnings("SuspiciousMethodCalls")
  public final synchronized boolean remove(Object obj) {
    if (obj == null) throw new NullPointerException();

    QItem<T> i = hash.remove(obj);
    if (i != null) {
      list.remove(i);
      return true;
    } else {
      return false;
    }
  }

  /**
   * Returns whether the queue currently contains an element equal to {@code obj}.
   *
   * @param obj element to test; may be any type
   * @return {@code true} if present; {@code false} otherwise
   */
  @SuppressWarnings("SuspiciousMethodCalls")
  public final synchronized boolean contains(Object obj) {
    return hash.containsKey(obj);
  }

  /**
   * Returns an {@link Iterator} over the elements from least recently used to most recently used.
   *
   * <p>The iterator is backed by a snapshot constructed at the time of the call. It does not
   * reflect later mutations and is not fail-fast.
   *
   * @return iterator from LRU to MRU
   */
  public synchronized Iterator<T> elements() {
    // Build snapshot under lock because DoublyLinkedListImpl is not thread-safe.
    ArrayList<T> snapshot = new ArrayList<>(list.size());
    for (Iterator<QItem<T>> e = list.reverseElements(); e.hasNext(); ) {
      snapshot.add(e.next().obj);
    }
    return snapshot.iterator();
  }

  private static class QItem<T> extends DoublyLinkedListImpl.Item<QItem<T>> {
    public final T obj;

    public QItem(T obj) {
      this.obj = obj;
    }
  }

  /**
   * Returns the elements as an array in an unspecified order.
   *
   * <p>The order is the internal hash iteration order and has no relation to recency.
   *
   * @return new array containing all elements in arbitrary order
   */
  public synchronized Object[] toArray() {
    return hash.keySet().toArray();
  }

  /**
   * Returns the elements as a typed array in an unspecified order.
   *
   * <p>The order is the internal hash iteration order and has no relation to recency.
   *
   * @param <E> array component type
   * @param array destination array; if too small, a new array of the same runtime type is returned
   * @return the provided array if large enough, otherwise a new array of the same type
   */
  public synchronized <E> E[] toArray(E[] array) {
    return hash.keySet().toArray(array);
  }

  /**
   * Returns the elements ordered from least to most recently used.
   *
   * <p>The element at index {@code 0} is the LRU; the last element is the MRU.
   *
   * @return new array ordered from LRU to MRU
   */
  public synchronized Object[] toArrayOrdered() {
    Object[] array = new Object[list.size()];
    int x = 0;
    for (Iterator<QItem<T>> e = list.reverseElements(); e.hasNext(); ) {
      array[x++] = e.next().obj;
    }
    return array;
  }

  /**
   * Returns the elements ordered from least to most recently used, into a typed array.
   *
   * <p>The element at index {@code 0} is the LRU; the last element is the MRU.
   *
   * @param <E> array component type
   * @param array destination array; if too small, a new array of the same runtime type is returned
   * @return the provided array if large enough, otherwise a new array of the same type, filled from
   *     LRU to MRU
   * @throws IllegalStateException if an internal size invariant is violated while materializing the
   *     snapshot (should not occur under normal use)
   */
  public synchronized <E> E[] toArrayOrdered(E[] array) {
    array = toArray(array);
    int listSize = list.size();
    if (array.length != listSize)
      throw new IllegalStateException(
          "array.length=" + array.length + " but list.size=" + listSize);
    int x = 0;
    for (Iterator<QItem<T>> e = list.reverseElements(); e.hasNext(); ) {
      array[x++] = castElementForArray(array, e.next().obj);
    }
    return array;
  }

  private static <E> E castElementForArray(E[] array, Object value) {
    Class<?> component = array.getClass().getComponentType();
    if (!component.isInstance(value)) {
      throw new ArrayStoreException(
          "Attempted to store "
              + (value == null ? "null" : value.getClass().getName())
              + " into array of "
              + component.getName());
    }
    @SuppressWarnings("unchecked")
    E cast = (E) value;
    return cast;
  }

  /**
   * Returns whether the queue contains no elements.
   *
   * @return {@code true} if empty; {@code false} otherwise
   */
  public synchronized boolean isEmpty() {
    return hash.isEmpty();
  }

  /** Removes all elements and resets recency order. */
  public synchronized void clear() {
    list.clear();
    hash.clear();
  }

  /**
   * Returns the stored instance equal to {@code obj} without changing recency.
   *
   * <p>When elements with custom equality semantics are used as keys, this method can return the
   * canonical instance maintained by the queue.
   *
   * @param obj lookup key; may be {@code null}
   * @return the equal element stored in the queue, or {@code null} if none
   */
  public synchronized T get(T obj) {
    QItem<T> val = hash.get(obj);
    if (val == null) return null;
    return val.obj;
  }
}

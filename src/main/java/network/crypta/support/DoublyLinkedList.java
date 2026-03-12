package network.crypta.support;

import java.util.Iterator;

/**
 * Intrusive doubly linked list interface.
 *
 * <p>This interface defines a lightweight, allocation-free ("intrusive") doubly linked list in
 * which each element stores links to its neighbors and remembers which list it belongs to. Compared
 * to {@link java.util.LinkedList}, this enables constant-time ({@code O(1)}) removal when the
 * element to remove is already known, because no search is required. For general-purpose use cases
 * where intrusive storage is not needed, prefer standard JDK collections.
 *
 * <p>Concurrency: implementations are not required to be thread-safe.
 *
 * @param <T> the concrete {@link Item} type stored in this list
 * @author tavin
 */
public interface DoublyLinkedList<T extends DoublyLinkedList.Item<?>> extends Iterable<T> {

  /**
   * Node stored in a {@link DoublyLinkedList}. Implementations maintain neighbor links and a
   * reference to the parent list.
   *
   * <p>Nullability: for the first element, {@link #getPrev()} may return {@code null}; for the last
   * element, {@link #getNext()} may return {@code null}.
   *
   * @param <T> the concrete, self-referential item type (typically {@code T extends Item<T>})
   */
  interface Item<T extends DoublyLinkedList.Item<?>> {
    /**
     * Returns the next item in the list, or {@code null} if this is the last item.
     *
     * @return the next item, or {@code null} if none
     * @see DoublyLinkedList#hasNext
     */
    T getNext();

    /**
     * Sets the next item reference.
     *
     * <p>Preconditions: {@code i} is {@code null} or an item compatible with this list's generic
     * type. Implementations may perform sanity checks; behavior on incompatible items is
     * implementation-defined.
     *
     * @param i the next item, or {@code null}
     * @return the previously linked next item, or {@code null} if none
     */
    T setNext(Item<?> i);

    /**
     * Returns the previous item in the list, or {@code null} if this is the first item.
     *
     * @return the previous item, or {@code null} if none
     * @see DoublyLinkedList#hasPrev
     */
    T getPrev();

    /**
     * Sets the previous item reference.
     *
     * <p>Preconditions: {@code i} is {@code null} or an item compatible with this list's generic
     * type. Implementations may perform sanity checks; behavior on incompatible items is
     * implementation-defined.
     *
     * @param i the previous item, or {@code null}
     * @return the previously linked previous item, or {@code null} if none
     */
    T setPrev(Item<?> i);

    /**
     * Returns the parent list that currently contains this item.
     *
     * @return the parent list, or {@code null} if not in any list
     */
    DoublyLinkedList<T> getParent();

    /**
     * Sets the parent list reference. Intended for use by list implementations for sanity checking.
     * Calling this does not by itself add or remove the item from a list.
     *
     * @param l the new parent list, or {@code null} to mark the item as detached
     * @return the previous parent list, or {@code null} if none
     */
    DoublyLinkedList<T> setParent(DoublyLinkedList<T> l);
  }

  /**
   * Removes all items from this list and detaches their neighbor links.
   *
   * <p>Postconditions: {@link #size()} returns 0; {@link #head()} and {@link #tail()} return {@code
   * null}. Complexity: {@code O(n)}.
   */
  void clear();

  /**
   * Returns the number of items in this list.
   *
   * @return the item count, never negative
   */
  int size();

  /**
   * Returns whether this list is empty.
   *
   * @return {@code true} if empty; {@code false} otherwise
   */
  boolean isEmpty();

  /**
   * Returns an {@link Iterator} over items from head to tail.
   *
   * <p>Iteration semantics during concurrent modification are implementation-defined and may vary
   * by implementation.
   *
   * @return an iterator of items in forward order
   */
  Iterator<T> elements(); // Provided for consistency with typical Java APIs.

  /**
   * Returns whether the list contains an item equal to {@code item}.
   *
   * <p>Equality is determined by {@link Object#equals(Object)}.
   *
   * @param item the item to compare against existing elements (may be {@code null})
   * @return {@code true} if an equal item exists; {@code false} otherwise
   */
  boolean contains(T item);

  /**
   * Returns the first item.
   *
   * @return the item at the head, or {@code null} if empty
   */
  T head();

  /**
   * Returns the last item.
   *
   * @return the item at the tail, or {@code null} if empty
   */
  T tail();

  /**
   * Inserts {@code i} as the new head (before the current first item).
   *
   * <p>Preconditions: {@code i} is not already linked into a list. Implementations may validate
   * this and throw a runtime exception if violated.
   *
   * @param i the item to insert
   */
  void unshift(T i);

  /**
   * Removes and returns the first item.
   *
   * @return the removed head, or {@code null} if empty
   */
  T shift();

  /**
   * Removes up to {@code n} items from the head and returns them as a new list.
   *
   * <p>If {@code n} is greater than the current size, all items are removed. If {@code n} is less
   * than 1, an empty list is returned. Complexity: {@code O(n)} in the number of removed items.
   *
   * @param n number of items to remove from the head
   * @return a new list containing the removed items in their original order
   */
  DoublyLinkedList<T> shift(int n);

  /**
   * Inserts {@code i} as the new tail (after the current last item).
   *
   * <p>Preconditions: {@code i} is not already linked into a list. Implementations may validate
   * this and throw a runtime exception if violated.
   *
   * @param i the item to insert
   */
  void push(T i);

  /**
   * Removes and returns the last item.
   *
   * @return the removed tail, or {@code null} if empty
   */
  T pop();

  /**
   * Removes up to {@code n} items from the tail and returns them as a new list.
   *
   * <p>If {@code n} is greater than the current size, all items are removed. If {@code n} is less
   * than 1, an empty list is returned. Complexity: {@code O(n)} in the number of removed items.
   *
   * @param n number of items to remove from the tail
   * @return a new list containing the removed items in their original order
   */
  DoublyLinkedList<T> pop(int n);

  /**
   * Returns whether {@code i} has a successor.
   *
   * @param i the item to inspect
   * @return {@code true} if {@code i} is not the last item; {@code false} otherwise
   */
  boolean hasNext(T i);

  /**
   * Returns whether {@code i} has a predecessor.
   *
   * @param i the item to inspect
   * @return {@code true} if {@code i} is not the first item; {@code false} otherwise
   */
  boolean hasPrev(T i);

  /**
   * Returns the successor of {@code i}.
   *
   * @param i the item to inspect
   * @return the next item, or {@code null} if {@code i} is last
   */
  T next(T i);

  /**
   * Returns the predecessor of {@code i}.
   *
   * @param i the item to inspect
   * @return the previous item, or {@code null} if {@code i} is first
   */
  T prev(T i);

  /**
   * Removes {@code i} from this list.
   *
   * <p>If {@code i} is not in any list, this method returns {@code null}. If {@code i} belongs to a
   * different {@link DoublyLinkedList}, a runtime exception is thrown.
   *
   * @param i the item to remove
   * @return the same item, or {@code null} if it was not contained
   * @throws network.crypta.support.PromiscuousItemException if {@code i} belongs to another list
   */
  T remove(T i);

  /**
   * Inserts item {@code j} immediately before item {@code i}.
   *
   * <p>If {@code i} is {@code null}, {@code j} is inserted as the new tail. The item {@code j} must
   * not already be linked into any list.
   *
   * @param i the anchor item before which to insert, or {@code null} for tail insertion
   * @param j the item to insert
   * @throws network.crypta.support.PromiscuousItemException if {@code j} is already linked or if
   *     {@code i} belongs to another list
   * @throws network.crypta.support.VirginItemException if internal invariants indicate that {@code
   *     i} is not positioned as expected (diagnostic guard)
   */
  void insertPrev(T i, T j);

  /**
   * Inserts item {@code j} immediately after item {@code i}.
   *
   * <p>If {@code i} is {@code null}, {@code j} is inserted as the new head. The item {@code j} must
   * not already be linked into any list.
   *
   * @param i the anchor item after which to insert, or {@code null} for head insertion
   * @param j the item to insert
   * @throws network.crypta.support.PromiscuousItemException if {@code j} is already linked or if
   *     {@code i} belongs to another list
   * @throws network.crypta.support.VirginItemException if internal invariants indicate that {@code
   *     i} is not positioned as expected (diagnostic guard)
   */
  void insertNext(T i, T j);
}

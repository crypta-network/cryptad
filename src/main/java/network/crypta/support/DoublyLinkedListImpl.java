package network.crypta.support;

import java.util.Enumeration;
import java.util.Iterator;
import java.util.NoSuchElementException;
import org.jetbrains.annotations.NotNull;

/**
 * Intrusive doubly linked list implementation.
 *
 * <p>This class provides a lightweight, allocation-free list in which each element stores
 * references to its neighbors and to the parent list (see {@link DoublyLinkedList.Item}). It is
 * designed for constant-time ({@code O(1)}) insertions and removals when the target node is already
 * known. It does not allocate wrapper nodes and therefore avoids GC pressure compared to
 * non-intrusive structures.
 *
 * <p>Concurrency: Instances are not thread-safe. External synchronization is required for
 * concurrent use.
 *
 * <p>Nullability: Methods such as {@link #head()} and {@link #tail()} return {@code null} for an
 * empty list. Accessors on {@link Item} may also return {@code null} at the boundaries.
 *
 * <p>Iteration: {@link #elements()} and {@link #reverseElements()} return simple enumerations over
 * the current structure. They are not fail-fast and have unspecified behavior if the list is
 * structurally modified during iteration.
 *
 * @param <T> concrete intrusive item type stored in this list
 * @author tavin
 */
public class DoublyLinkedListImpl<T extends DoublyLinkedList.Item<T>>
    implements DoublyLinkedList<T> {

  /** Current number of items in the list. Never negative. */
  protected int size;

  /** Reference to the first item (head) or {@code null} when empty. */
  protected T firstItem;

  /** Reference to the last item (tail) or {@code null} when empty. */
  protected T lastItem;

  /** Creates an empty list with no items. */
  public DoublyLinkedListImpl() {
    clear();
  }

  /**
   * Creates a list that adopts an existing intrusive chain.
   *
   * <p>The items from {@code head} through {@code tail} (via {@link Item#getNext()}) are assumed to
   * form a valid chain. This constructor sets their parent to this list and records the provided
   * size without validation.
   *
   * @param head first item in the chain; may be {@code null} when {@code size} is 0
   * @param tail last item in the chain; may be {@code null} when {@code size} is 0
   * @param size number of items contained in the chain
   */
  protected DoublyLinkedListImpl(T head, T tail, int size) {
    firstItem = head;
    lastItem = tail;

    T i = firstItem;
    while (i != null) {
      i.setParent(this);
      i = i.getNext();
    }

    this.size = size;
  }

  // === DoublyLinkedList implementation ======================================

  /** {@inheritDoc} */
  @Override
  public void clear() {
    // Help detect later misuse: detach and null all neighbor links and clear parent pointers.
    // Note: {@link #remove(Object)} separately guards against removing after clear; we keep
    // this full unlinking pass to avoid accidental retention.
    if (firstItem == null) return;

    T pos = firstItem;
    T opos;

    while (pos != null) {
      pos.setParent(null);
      pos.setPrev(null);
      opos = pos;
      pos = pos.getNext();
      opos.setNext(null);
    }

    firstItem = lastItem = null;
    size = 0;
  }

  /** {@inheritDoc} */
  @Override
  public final int size() {
    assert size != 0 || (firstItem == null && lastItem == null);
    return size;
  }

  /** {@inheritDoc} */
  @Override
  public final boolean isEmpty() {
    assert size != 0 || (firstItem == null && lastItem == null);
    return size == 0;
  }

  /** Returns a forward {@link Enumeration} over list items. See {@link #forwardElements()}. */
  @Override
  public final Enumeration<T> elements() {
    return forwardElements();
  }

  /**
   * Returns whether an equal item is present.
   *
   * <p>Equality uses {@link Object#equals(Object)} on elements already in the list.
   *
   * @param item item to search for; may be {@code null}
   * @return {@code true} if an equal item exists; {@code false} otherwise
   */
  @Override
  public boolean contains(T item) {
    for (T i : this) {
      if (i.equals(item)) return true;
    }
    return false;
  }

  /** Returns the first item or {@code null} when empty. */
  @Override
  public final T head() {
    return size == 0 ? null : firstItem;
  }

  /** Returns the last item or {@code null} when empty. */
  @Override
  public final T tail() {
    return size == 0 ? null : lastItem;
  }

  // === methods that add/remove items at the head of the list ================
  /** Inserts {@code i} at the head in {@code O(1)} time. */
  @Override
  public final void unshift(T i) {
    insertNext(null, i);
  }

  /** Removes and returns the head in {@code O(1)} time, or {@code null} if empty. */
  @Override
  public final T shift() {
    return size == 0 ? null : remove(firstItem);
  }

  /**
   * Removes up to {@code n} items from the head and returns them as a new list.
   *
   * <p>If {@code n} exceeds the current size, all items are removed. If {@code n} is less than 1,
   * this returns an empty list and does not modify this list.
   *
   * @param n number of items to remove; non-positive values yield an empty result
   * @return a list containing the removed prefix, preserving original order
   */
  @Override
  public DoublyLinkedList<T> shift(int n) {
    if (n > size) n = size;
    if (n < 1) return new DoublyLinkedListImpl<>();

    T i = firstItem;
    for (int m = 0; m < n - 1; ++m) i = i.getNext();

    T newTailItem = i;
    T newFirstItem = newTailItem.getNext();
    newTailItem.setNext(null);

    DoublyLinkedList<T> newlist = new DoublyLinkedListImpl<>(firstItem, newTailItem, n);

    if (newFirstItem != null) {
      newFirstItem.setPrev(null);
      firstItem = newFirstItem;
    } else {
      firstItem = lastItem = null;
    }
    size -= n;

    return newlist;
  }

  // === methods that add/remove items at the tail of the list ================
  /** Appends {@code i} at the tail in {@code O(1)} time. */
  @Override
  public final void push(T i) {
    insertPrev(null, i);
  }

  /** Removes and returns the tail in {@code O(1)} time, or {@code null} if empty. */
  @Override
  public final T pop() {
    return size == 0 ? null : remove(lastItem);
  }

  /**
   * Removes up to {@code n} items from the tail and returns them as a new list.
   *
   * <p>If {@code n} exceeds the current size, all items are removed. If {@code n} is less than 1,
   * this returns an empty list and does not modify this list.
   *
   * @param n number of items to remove; non-positive values yield an empty result
   * @return a list containing the removed suffix, preserving original order
   */
  @Override
  public DoublyLinkedList<T> pop(int n) {
    if (n > size) n = size;
    if (n < 1) return new DoublyLinkedListImpl<>();

    T i = lastItem;
    for (int m = 0; m < n - 1; ++m) i = i.getPrev();

    T newFirstItem = i;
    T newLastItem = newFirstItem.getPrev();
    newFirstItem.setPrev(null);

    DoublyLinkedList<T> newlist = new DoublyLinkedListImpl<>(newFirstItem, lastItem, n);

    if (newLastItem != null) {
      newLastItem.setNext(null);
      lastItem = newLastItem;
    } else firstItem = lastItem = null;
    size -= n;

    return newlist;
  }

  // === testing/looking at neighbor items ====================================
  /** Returns whether {@code i} has a successor (not the tail). */
  @Override
  public final boolean hasNext(T i) {
    T next = i.getNext();
    return next != null;
  }

  /** Returns whether {@code i} has a predecessor (not the head). */
  @Override
  public final boolean hasPrev(T i) {
    T prev = i.getPrev();
    return prev != null;
  }

  /** Returns the successor of {@code i}, or {@code null} if {@code i} is the tail. */
  @Override
  public final T next(T i) {
    return i.getNext();
  }

  /** Returns the predecessor of {@code i}, or {@code null} if {@code i} is the head. */
  @Override
  public final T prev(T i) {
    return i.getPrev();
  }

  // === insertion and removal of items =======================================

  /**
   * Removes {@code i} from this list.
   *
   * <p>Returns {@code null} if {@code i} is not in any list. If {@code i} belongs to a different
   * list, a {@link PromiscuousItemException} is thrown. Internal invariants are validated and may
   * raise {@link IllegalStateException} if corrupted links are detected.
   *
   * @param i item to remove
   * @return the same item, or {@code null} if not contained
   * @throws PromiscuousItemException if {@code i} belongs to another list
   * @throws IllegalStateException if neighbor links do not match expected invariants
   */
  @Override
  public T remove(T i) {
    if (i.getParent() == null || isEmpty()) return null; // not in list
    if (i.getParent() != this) throw new PromiscuousItemException(i, i.getParent());

    T next = i.getNext();
    T prev = i.getPrev();

    ensureLinkedOrSingle(next, prev);
    unlinkNextSide(i, next, prev);
    unlinkPrevSide(i, next, prev);

    i.setNext(null);
    i.setPrev(null);
    --size;
    i.setParent(null);
    return i;
  }

  private void ensureLinkedOrSingle(T next, T prev) {
    if (!((next != null) || (prev != null) || size == 1)) {
      throw new IllegalStateException("Corrupted list: isolated node");
    }
  }

  private void unlinkNextSide(T i, T next, T prev) {
    if (next == null) { // last item
      if (lastItem != i) {
        throw new IllegalStateException("Corrupted list: tail mismatch");
      }
      lastItem = prev;
    } else {
      if (next.getPrev() != i) {
        throw new IllegalStateException("Corrupted list: next.prev mismatch");
      }
      next.setPrev(prev);
    }
  }

  private void unlinkPrevSide(T i, T next, T prev) {
    if (prev == null) { // first item
      if (firstItem != i) {
        throw new IllegalStateException("Corrupted list: head mismatch");
      }
      firstItem = next;
    } else {
      if (prev.getNext() != i) {
        throw new IllegalStateException("Corrupted list: prev.next mismatch");
      }
      prev.setNext(next);
    }
  }

  /**
   * Inserts {@code j} immediately before {@code i}.
   *
   * <p>When {@code i} is {@code null}, {@code j} is appended as the new tail. The item {@code j}
   * must not already be linked into any list.
   *
   * @param i anchor item to insert before, or {@code null} for tail insertion
   * @param j item to insert (must be unlinked)
   * @throws PromiscuousItemException if {@code j} is already linked or {@code i} belongs to another
   *     list
   * @throws VirginItemException if invariants indicate {@code i} is not positioned as expected
   */
  @Override
  public void insertPrev(T i, T j) {
    if (j.getParent() != null) throw new PromiscuousItemException(j, j.getParent());
    if ((j.getNext() != null) || (j.getPrev() != null)) throw new PromiscuousItemException(j);

    if (i == null) {
      insertAsTail(j);
    } else {
      insertBefore(i, j);
    }
  }

  /** Inserts {@code j} as the new tail. Precondition: {@code j} is not linked. */
  private void insertAsTail(T j) {
    j.setPrev(lastItem);
    j.setNext(null);
    j.setParent(this);
    if (lastItem != null) {
      lastItem.setNext(j);
      lastItem = j;
    } else {
      firstItem = lastItem = j;
    }
    ++size;
  }

  /** Inserts {@code j} before {@code i}. Precondition: {@code i} belongs to this list. */
  private void insertBefore(T i, T j) {
    if (i.getParent() == null)
      throw new PromiscuousItemException(
          i, i.getParent()); // different trace to make easier debugging
    if (i.getParent() != this) throw new PromiscuousItemException(i, i.getParent());
    T prev = i.getPrev();
    if (prev == null) {
      if (i != firstItem) throw new VirginItemException(i);
      firstItem = j;
    } else {
      prev.setNext(j);
    }
    j.setPrev(prev);
    i.setPrev(j);
    j.setNext(i);
    j.setParent(this);
    ++size;
  }

  /**
   * Inserts {@code j} immediately after {@code i}.
   *
   * <p>When {@code i} is {@code null}, {@code j} becomes the new head. The item {@code j} must not
   * already be linked into any list.
   *
   * @param i anchor item to insert after, or {@code null} for head insertion
   * @param j item to insert (must be unlinked)
   * @throws PromiscuousItemException if {@code j} is already linked or {@code i} belongs to another
   *     list
   * @throws VirginItemException if invariants indicate {@code i} is not positioned as expected
   */
  @Override
  public void insertNext(T i, T j) {
    if (j.getParent() != null) throw new PromiscuousItemException(j, j.getParent());
    if ((j.getNext() != null) || (j.getPrev() != null)) throw new PromiscuousItemException(j);

    if (i == null) {
      insertAsHead(j);
    } else {
      insertAfter(i, j);
    }
  }

  /** Inserts {@code j} as the new head. Precondition: {@code j} is not linked. */
  private void insertAsHead(T j) {
    j.setPrev(null);
    j.setNext(firstItem);
    j.setParent(this);

    if (firstItem != null) {
      firstItem.setPrev(j);
      firstItem = j;
    } else {
      firstItem = lastItem = j;
    }

    ++size;
  }

  /** Inserts {@code j} after {@code i}. Precondition: {@code i} belongs to this list. */
  private void insertAfter(T i, T j) {
    if (i.getParent() != this) throw new PromiscuousItemException(i, i.getParent());
    T next = i.getNext();
    if (next == null) {
      if (i != lastItem) throw new VirginItemException(i);
      lastItem = j;
    } else {
      next.setPrev(j);
    }
    j.setNext(next);
    i.setNext(j);
    j.setPrev(i);
    j.setParent(this);

    ++size;
  }

  // === Walkable implementation ==============================================

  /** Returns an {@link Enumeration} over items from head to tail. */
  private Enumeration<T> forwardElements() {
    return new Enumeration<>() {
      private T next = firstItem;

      @Override
      public boolean hasMoreElements() {
        return next != null;
      }

      @Override
      public T nextElement() {
        if (next == null) throw new NoSuchElementException();
        T result = next;
        next = next.getNext();
        return result;
      }
    };
  }

  /** Returns an {@link Enumeration} over items from tail to head. */
  public Enumeration<T> reverseElements() {
    return new Enumeration<>() {
      private T next = lastItem;

      @Override
      public boolean hasMoreElements() {
        return next != null;
      }

      @Override
      public T nextElement() {
        if (next == null) throw new NoSuchElementException();
        T result = next;
        next = next.getPrev();
        return result;
      }
    };
  }

  // === list element ====================================================

  /**
   * Base implementation of an intrusive list item.
   *
   * <p>Implementations typically extend this class to inherit neighbor link management and a
   * reference to the parent list.
   *
   * @param <T> the concrete self-referential item type (e.g., {@code T extends Item<T>})
   */
  public static class Item<T extends DoublyLinkedListImpl.Item<?>>
      implements DoublyLinkedList.Item<T> {
    private T prev;
    private T next;
    private DoublyLinkedList<T> list;

    /** Returns the next item, or {@code null} if this is the tail. */
    @Override
    public final T getNext() {
      return next;
    }

    /**
     * Sets the next link.
     *
     * @param i next item or {@code null}
     * @return the previously linked next item (may be {@code null})
     */
    @Override
    public final T setNext(DoublyLinkedList.Item<?> i) {
      return nextAndSet(castItem(i));
    }

    /** Returns the previous item, or {@code null} if this is the head. */
    @Override
    public final T getPrev() {
      return prev;
    }

    /**
     * Sets the previous link.
     *
     * @param i previous item or {@code null}
     * @return the previously linked previous item (may be {@code null})
     */
    @Override
    public final T setPrev(DoublyLinkedList.Item<?> i) {
      return prevAndSet(castItem(i));
    }

    /** Returns the parent list, or {@code null} if not linked. */
    @Override
    public DoublyLinkedList<T> getParent() {
      return list;
    }

    /**
     * Sets the parent list reference.
     *
     * <p>Intended for use by list implementations to support sanity checks. Changing this value
     * does not by itself insert or remove the item.
     *
     * @param l new parent list or {@code null}
     * @return the previous parent list
     */
    @Override
    public DoublyLinkedList<T> setParent(DoublyLinkedList<T> l) {
      return parentAndSet(l);
    }

    private T nextAndSet(T newNext) {
      try {
        return next;
      } finally {
        next = newNext;
      }
    }

    private T prevAndSet(T newPrev) {
      try {
        return prev;
      } finally {
        prev = newPrev;
      }
    }

    private DoublyLinkedList<T> parentAndSet(DoublyLinkedList<T> newList) {
      try {
        return list;
      } finally {
        list = newList;
      }
    }

    /**
     * Casts an {@link Item} to the concrete type {@code T}.
     *
     * <p>Safe by construction: items in a {@code DoublyLinkedList<T>} are always of type {@code T}.
     */
    @SuppressWarnings("unchecked")
    private T castItem(DoublyLinkedList.Item<?> i) {
      return (T) i;
    }
  }

  /** Returns an {@link Iterator} that traverses from head to tail. */
  @Override
  public @NotNull Iterator<T> iterator() {
    final Enumeration<T> e = forwardElements();
    return new Iterator<>() {
      @Override
      public boolean hasNext() {
        return e.hasMoreElements();
      }

      @Override
      public T next() {
        if (!hasNext()) {
          throw new NoSuchElementException();
        }
        return e.nextElement();
      }

      @Override
      public void remove() {
        throw new UnsupportedOperationException();
      }
    };
  }
}

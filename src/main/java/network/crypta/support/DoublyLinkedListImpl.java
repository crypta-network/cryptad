package network.crypta.support;

import java.util.Enumeration;
import java.util.Iterator;
import java.util.NoSuchElementException;
import org.jetbrains.annotations.NotNull;

/**
 * DoublyLinkedList implementation. See DoublyLinkedList for an explanation when to use this.
 *
 * <p>Note: Some methods remain unimplemented; they may not be needed.
 *
 * @author tavin
 */
public class DoublyLinkedListImpl<T extends DoublyLinkedList.Item<T>>
    implements DoublyLinkedList<T> {

  protected int size;
  protected T firstItem;
  protected T lastItem;

  /** A new list with no items. */
  public DoublyLinkedListImpl() {
    clear();
  }

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
    // Help to detect removal after clear().
    // The check in remove() is enough, strictly,
    // as long as people don't add elements afterward.
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

  /**
   * {@inheritDoc}
   *
   * @see #forwardElements()
   */
  @Override
  public final Enumeration<T> elements() {
    return forwardElements();
  }

  @Override
  public boolean contains(T item) {
    for (T i : this) {
      if (i.equals(item)) return true;
    }
    return false;
  }

  /** {@inheritDoc} */
  @Override
  public final T head() {
    return size == 0 ? null : firstItem;
  }

  /** {@inheritDoc} */
  @Override
  public final T tail() {
    return size == 0 ? null : lastItem;
  }

  // === methods that add/remove items at the head of the list ================
  /** {@inheritDoc} */
  @Override
  public final void unshift(T i) {
    insertNext(null, i);
  }

  /** {@inheritDoc} */
  @Override
  public final T shift() {
    return size == 0 ? null : remove(firstItem);
  }

  /** {@inheritDoc} */
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
  /** {@inheritDoc} */
  @Override
  public final void push(T i) {
    insertPrev(null, i);
  }

  /** {@inheritDoc} */
  @Override
  public final T pop() {
    return size == 0 ? null : remove(lastItem);
  }

  /** {@inheritDoc} */
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
  /** {@inheritDoc} */
  @Override
  public final boolean hasNext(T i) {
    T next = i.getNext();
    return next != null;
  }

  /** {@inheritDoc} */
  @Override
  public final boolean hasPrev(T i) {
    T prev = i.getPrev();
    return prev != null;
  }

  /** {@inheritDoc} */
  @Override
  public final T next(T i) {
    return i.getNext();
  }

  /** {@inheritDoc} */
  @Override
  public final T prev(T i) {
    return i.getPrev();
  }

  // === insertion and removal of items =======================================

  /** {@inheritDoc} */
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

  /** {@inheritDoc} */
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

  private void insertAsTail(T j) {
    // insert as tail
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

  private void insertBefore(T i, T j) {
    // insert in middle (before 'i')
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

  /** {@inheritDoc} */
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

  private void insertAsHead(T j) {
    // insert as head
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

  /**
   * @return an Enumeration of list elements from head to tail
   */
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

  /**
   * @return an Enumeration of list elements from tail to head
   */
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

  public static class Item<T extends DoublyLinkedListImpl.Item<?>>
      implements DoublyLinkedList.Item<T> {
    private T prev;
    private T next;
    private DoublyLinkedList<T> list;

    @Override
    public final T getNext() {
      return next;
    }

    @Override
    public final T setNext(DoublyLinkedList.Item<?> i) {
      return nextAndSet(castItem(i));
    }

    @Override
    public final T getPrev() {
      return prev;
    }

    @Override
    public final T setPrev(DoublyLinkedList.Item<?> i) {
      return prevAndSet(castItem(i));
    }

    @Override
    public DoublyLinkedList<T> getParent() {
      return list;
    }

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

    @SuppressWarnings("unchecked")
    private T castItem(DoublyLinkedList.Item<?> i) {
      // Safe by construction: this Item<T> only participates in lists of T, and callers
      // use the same T throughout DoublyLinkedList<T>. We localize the unchecked cast here.
      return (T) i;
    }
  }

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

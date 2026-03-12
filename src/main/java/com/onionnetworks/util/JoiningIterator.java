package com.onionnetworks.util;

import java.util.Iterator;

/**
 * Iterator that traverses all elements from a primary iterator and then continues with a secondary
 * iterator, presenting them as one continuous sequence.
 *
 * <p>JoiningIterator stitches two ordered sources together so callers can treat them as a single
 * stream without copying or buffering. It advances the supplied iterators lazily, preserving any
 * side effects or mutation semantics they expose. Use it when concatenation semantics are desired
 * and the second source should remain untouched until the first is fully consumed. Instances are
 * not thread-safe; concurrent access requires external synchronization. Removal is intentionally
 * unsupported to avoid ambiguous mutation of the underlying sources, so callers should supply
 * iterators that already reflect the desired contents.
 *
 * <ul>
 *   <li>Progresses through {@code first} completely before consulting {@code second}.
 *   <li>Delegates element retrieval directly to the underlying iterators without buffering.
 *   <li>Propagates {@link java.util.NoSuchElementException} and other runtime exceptions thrown by
 *       the sources.
 * </ul>
 *
 * @param <T> type of elements produced sequentially by the joined iterators
 * @see java.util.Iterator
 */
public class JoiningIterator<T> implements Iterator<T> {
  private final Iterator<? extends T> first;
  private final Iterator<? extends T> second;

  /**
   * Creates an iterator that yields elements from the first iterator and then from the second.
   *
   * <p>The iterators are stored by reference and are not inspected at construction time. Emitted
   * results reflect the current state of each iterator when {@link #next()} is called. The first
   * iterator is exhausted before the second is consulted, providing deterministic ordering without
   * additional buffering. Neither argument may be {@code null}; callers retain ownership and
   * responsibility for any thread-safety guarantees.
   *
   * @param f iterator whose elements are delivered first in sequence; must be non-null
   * @param s iterator read only after {@code f} is exhausted; must be non-null
   */
  public JoiningIterator(Iterator<? extends T> f, Iterator<? extends T> s) {
    first = f;
    second = s;
  }

  /**
   * Reports whether either underlying iterator still has elements available.
   *
   * <p>The check first consults {@code first}; if it reports additional elements, the combined
   * iterator is considered non-empty regardless of {@code second}. Only when {@code first} is
   * exhausted does the method query {@code second}. The operation does not advance iteration state
   * or buffer values, so repeated calls are safe but may reflect concurrent modifications to the
   * underlying iterators.
   *
   * @return {@code true} if {@code first} or {@code second} advertises remaining elements
   */
  @Override
  public boolean hasNext() {
    return first.hasNext() || second.hasNext();
  }

  /**
   * Returns the next element from the first iterator until it is exhausted, then from the second.
   *
   * <p>The call advances only one underlying iterator per invocation. If {@code first} still has
   * elements, its next value is returned; otherwise the method delegates to {@code second}. No
   * buffering occurs, so results mirror the real-time state of the underlying iterators. Callers
   * should invoke {@link #hasNext()} first to avoid exceptions when both sources are exhausted.
   *
   * @return next element yielded by {@code first} or, once exhausted, by {@code second}
   * @throws java.util.NoSuchElementException if both iterators are exhausted at call time
   */
  @Override
  public T next() {
    return first.hasNext() ? first.next() : second.next(); // throws NSEEx
  }

  /**
   * Unsupported operation because mutating the joined iterators would be ambiguous for callers.
   *
   * <p>Removing elements through this wrapper could desynchronize the two sources or hide state
   * changes, so the method unconditionally throws {@link UnsupportedOperationException}. Clients
   * that require mutation should operate directly on the underlying iterators or use a different
   * abstraction that defines clear removal semantics for concatenated sequences.
   *
   * @throws UnsupportedOperationException always thrown to signal that removal is not supported
   */
  @Override
  public void remove() {
    throw new UnsupportedOperationException();
  }
}

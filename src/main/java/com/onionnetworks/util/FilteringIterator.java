package com.onionnetworks.util;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Iterator that exposes only the elements from a wrapped iterator that satisfy {@link
 * #accept(Object)}, leaving the underlying iteration order intact.
 *
 * <p>The iterator keeps at most one buffered element, reading ahead only when needed to satisfy the
 * contract, so memory use stays bounded even for large sources. Exceptions thrown by the parent
 * iterator, including {@link java.util.ConcurrentModificationException}, are propagated unchanged.
 * Synchronization is left to callers; guard externally if multiple threads share an instance.
 * Removal is unsupported to avoid coupling the filter to optional mutation behavior in the parent.
 *
 * <p>Typical usage patterns:
 *
 * <ul>
 *   <li>Exclude nulls or sentinel values while consuming an existing iterator.
 *   <li>Compose pipelines when stream APIs are unavailable.
 *   <li>Subclass with a concise {@link #accept(Object)} predicate for ad-hoc adapters.
 * </ul>
 *
 * <p>Example:
 *
 * <pre>{@code
 * Iterator<String> source =
 *     Arrays.asList("a", null, "was", null).iterator();
 * Iterator<String> filtered = new FilteringIterator<>(source) {
 *   public boolean accept(String o) { return o != null; }
 *   // If cross-thread access is expected, override hasNext/next as synchronized.
 * };
 * while (filtered.hasNext()) {
 *   System.out.println(filtered.next());
 * }
 * }</pre>
 *
 * @param <T> element type yielded by the iterator and evaluated by {@link #accept(Object)}
 * @author Ry4an
 */
public abstract class FilteringIterator<T> implements Iterator<T> {

  private static final Logger LOGGER = Logger.getLogger(FilteringIterator.class.getName());
  private static final String ITEM_MESSAGE_PATTERN = "Item: {0}";

  private final Iterator<T> parent;
  private T next;

  /**
   * Creates a filtering iterator that delegates to the supplied parent iterator.
   *
   * <p>The constructor does not advance or otherwise inspect the parent; elements are pulled lazily
   * during {@link #hasNext()} and {@link #next()} so callers can control iteration timing. The
   * parent iterator must remain valid for the lifetime of this wrapper; it is not defensively
   * copied. Callers should ensure the parent is not concurrently modified unless the iterator
   * explicitly allows it.
   *
   * @param p parent iterator providing the raw sequence; must not be {@code null} and should remain
   *     consistent for the duration of iteration
   */
  protected FilteringIterator(Iterator<T> p) {
    parent = p;
  }

  /** Unsupported. */
  @Override
  public void remove() {
    throw new UnsupportedOperationException();
  }

  /**
   * Determines whether another element that satisfies {@link #accept(Object)} is available.
   *
   * <p>The method may advance the parent iterator to find the next acceptable element, buffering
   * only a single candidate. It is safe to call repeatedly; once an acceptable element is buffered,
   * further calls are O(1) until {@link #next()} consumes it. If the parent throws an exception
   * while advancing, that exception is propagated so callers receive the same failure surface as
   * the source iterator.
   *
   * @return {@code true} when a matching element is buffered and ready to be returned, or {@code
   *     false} when the parent is exhausted without further matches
   */
  @Override
  public boolean hasNext() {
    while ((next == null) && (parent.hasNext())) {
      T o = parent.next();
      if (accept(o)) {
        next = o;
        return true;
      }
    }
    return (next != null);
  }

  /**
   * Evaluates whether a candidate element should be exposed to callers.
   *
   * <p>Subclasses implement this method with a deterministic predicate. Implementations should be
   * free of side effects because it may be invoked during look-ahead inside {@link #hasNext()}.
   * Returning {@code true} retains the element; {@code false} skips it and continues scanning the
   * parent iterator. Avoid long-running work here to preserve predictable iteration latency.
   *
   * @param o element read from the parent iterator; may be {@code null} if the parent produces
   *     nulls
   * @return {@code true} when the element should be yielded by {@link #next()}, otherwise {@code
   *     false}
   */
  protected abstract boolean accept(T o);

  /**
   * Retrieves and consumes the next element that satisfies {@link #accept(Object)}.
   *
   * <p>If no such element exists, the method throws {@link NoSuchElementException} in accordance
   * with the iterator contract. When a buffered element is present from a prior {@link #hasNext()}
   * call, it is returned immediately; otherwise the method advances the parent until it finds a
   * match or exhausts the source. Each successful call clears the buffer, so the next invocation
   * will re-evaluate availability.
   *
   * @return the next acceptable element; never {@code null} unless the parent produces nulls and
   *     {@link #accept(Object)} permits them
   * @throws NoSuchElementException if the parent iterator contains no further acceptable elements
   */
  @Override
  public T next() {
    if (!hasNext()) {
      throw new NoSuchElementException();
    }
    T retval = next;
    next = null;
    return retval;
  }

  /**
   * Demonstrates basic filtering by removing null entries from a short list.
   *
   * <p>The example logs both the unfiltered list and the filtered output to illustrate iteration
   * order preservation. It intentionally uses explicit {@link #hasNext()} / {@link #next()} calls
   * to mirror typical consumer code. Any unexpected state during the walk triggers a logged
   * warning, so the example remains simple to debug.
   */
  static void main() {
    List<String> l = new ArrayList<>(Arrays.asList("a", null, "was", null));
    Iterator<String> i = l.iterator();
    FilteringIterator<String> f =
        new FilteringIterator<>(i) {
          public boolean accept(String o) {
            return (o != null);
          }
        };
    LOGGER.info("--[ Unfiltered list: ]--");
    for (String item : l) {
      LOGGER.log(Level.INFO, ITEM_MESSAGE_PATTERN, item);
    }
    LOGGER.info("--[ List with null filter: ]--");
    try { // note: this test code is dependent on the test array
      String firstItem = f.hasNext() ? f.next() : null;
      if (firstItem == null) {
        throw new IllegalStateException();
      }
      LOGGER.log(Level.INFO, ITEM_MESSAGE_PATTERN, firstItem);

      String secondItem = f.hasNext() ? f.next() : null;
      if (!"was".equals(secondItem)) {
        throw new IllegalStateException();
      }
      LOGGER.log(Level.INFO, ITEM_MESSAGE_PATTERN, secondItem);

      if (f.hasNext()) {
        throw new IllegalStateException();
      }
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Something unexpected happened", e);
    }
  }
}

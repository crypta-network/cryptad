package com.onionnetworks.util;

/**
 * Iterates over primitive {@code int} values without boxing overhead.
 *
 * <p>This interface mirrors the behavior of {@link java.util.Iterator} but specializes it for
 * primitive integers, allowing implementers and callers to avoid allocating {@link Integer}
 * wrappers on every element. Typical usage follows the same control flow as an iterator: callers
 * repeatedly query {@link #hasNextInt()} and retrieve the next value with {@link #nextInt()} until
 * exhaustion, optionally removing elements along the way via {@link #removeInt()} when supported.
 *
 * <p>Instances are generally stateful and advance on each successful call to {@link #nextInt()}.
 * Unless otherwise documented by an implementation, iterators are not thread-safe; concurrent use
 * should be externally synchronized or confined to a single thread. Implementations may represent
 * views over mutable collections or streaming sources, so element availability and removal
 * semantics depend on the underlying data structure.
 *
 * <ul>
 *   <li>Provides primitive accessors to reduce GC pressure.
 *   <li>Supports optional element removal consistent with {@link java.util.Iterator#remove()}.
 *   <li>Intended for single-pass traversal; do not assume rewind or random access.
 * </ul>
 *
 * @author Justin F. Chapweske
 */
public interface IntIterator {

  /**
   * Indicates whether an additional {@code int} value can be retrieved.
   *
   * <p>Callers should invoke this method before each call to {@link #nextInt()} to avoid
   * encountering iteration errors. The result may change after each advancement of the iterator and
   * reflects the current traversal state. Implementations are expected to be side effect free; the
   * iterator position should not advance when this method is called repeatedly.
   *
   * @return {@code true} when another {@code int} is available from this iterator; {@code false}
   *     when iteration is complete and {@link #nextInt()} would fail.
   */
  @SuppressWarnings("unused")
  boolean hasNextInt();

  /**
   * Returns the next {@code int} in the iteration sequence.
   *
   * <p>This method advances the iterator position by one element. It should only be called after
   * verifying availability with {@link #hasNextInt()}; calling when no elements remain typically
   * results in an {@link java.util.NoSuchElementException} (implementations may differ but should
   * follow iterator conventions). Retrieved values are returned by value, not by reference, and
   * callers assume ownership of the primitive copy.
   *
   * <pre>{@code
   * while (it.hasNextInt()) {
   *   int value = it.nextInt();
   *   // process value
   * }
   * }</pre>
   *
   * @return the next available {@code int} from the underlying data source; never boxed and valid
   *     only for the current iteration step.
   */
  int nextInt();

  /**
   * Removes the last value returned by {@link #nextInt()} from the underlying collection.
   *
   * <p>Support for removal is implementation dependent; iterators that do not allow structural
   * modification should throw {@link UnsupportedOperationException}. When supported, this method
   * must be invoked only once per successful {@link #nextInt()} call and only if no intervening
   * call to {@link #nextInt()} has occurred. Concurrent structural modification rules mirror those
   * of {@link java.util.Iterator#remove()}, so implementations should document any additional
   * constraints or fail-fast behavior.
   *
   * @throws IllegalStateException if invoked before any value has been retrieved or more than once
   *     for the same returned element.
   * @throws UnsupportedOperationException if the underlying iterator does not support removal.
   */
  @SuppressWarnings("unused")
  void removeInt();
}

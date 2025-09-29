package com.onionnetworks.util;

import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.NoSuchElementException;

/**
 * FilteredIterators wrap Iterators and return only elements that pass a provided test. No more than
 * one value is buffered up. ConcurrentModificationExceptions and other exceptions filter up
 * correctly. remove() is not supported. This implemention isn't synchronized. The easiest way to
 * synchronize is shown in the example.
 *
 * <p>Example:
 *
 * <pre>
 * Iterator i = Arrays.asList(new String[] {"a",null,"was",null}).iterator();
 * Iterator f = new FilteringIterator(i) {
 * public boolean accept(Object o) {
 * return (o != null);
 * }
 * // uncomment the next to lines if you want it synchronized
 * // public synchronized Object next() { return super.next(); }
 * // public synchronized boolean hasNext() { return super.hasNext(); }
 * });
 * for (; f.hasNext(); ) {
 * Sytem.out.println("non-null: " + f.next());
 * }
 * </pre>
 *
 * @author Ry4an
 */
public abstract class FilteringIterator<T> implements Iterator<T> {

  private final Iterator<T> parent;
  private T next;
  private boolean removeOkay = true;

  /**
   * Create a FilteringIterator and provide the parent Iterator
   *
   * @param Iterator the iterator to wrap w/ the filter
   */
  public FilteringIterator(Iterator<T> p) {
    parent = p;
  }

  /** Unsupported. */
  public void remove() {
    throw new UnsupportedOperationException();
  }

  /**
   * Checks if the parent iterator has another element that will pass the filter defined in <code>
   * accept</code>.
   *
   * @return true = another passing object available, false otherwise
   * @see accept
   */
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
   * Fill in this method with a test that will be applied to each object which is a candidate for
   * passing through the filter.
   *
   * @param o the object which may be passed through the filter
   * @return true indciated the object should be returned. else false.
   */
  protected abstract boolean accept(T o);

  /**
   * Returns the next object from the parent iterator which passes the filter defined by <code>
   * accept</code>.
   *
   * @return Object an object which passes <code>accept</code>
   * @see accept
   */
  public T next() {
    if (!hasNext()) {
      throw new NoSuchElementException();
    }
    T retval = next;
    next = null;
    return retval;
  }

  /** Test and example. */
  public static void main(String[] args) {
    List<String> l = new LinkedList<>(Arrays.asList(new String[] {"a", null, "was", null}));
    Iterator<String> i = l.iterator();
    FilteringIterator<String> f =
        new FilteringIterator<String>(i) {
          public boolean accept(String o) {
            return (o != null);
          }
        };
    System.out.println("--[ Unfiltered list: ]--");
    for (String item : l) {
      System.out.println("Item: " + item);
    }
    System.out.println("--[ List with null filter: ]--");
    try { // note: this test code is dependent on the test array
      String o;
      if (!f.hasNext()) {
        throw new Exception();
      }
      if (!(o = f.next()).equals("a")) {
        throw new Exception();
      }
      System.out.println("Item: " + o);
      if (!(o = f.next()).equals("was")) {
        throw new Exception();
      }
      System.out.println("Item: " + o);
      if (f.hasNext()) {
        throw new Exception();
      }
    } catch (Throwable t) {
      System.err.println("Something unexpected happened:");
      t.printStackTrace();
    }
  }
}

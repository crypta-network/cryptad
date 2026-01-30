package network.crypta.support;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

/**
 * Time-indexed set-like structure that maintains values ordered by an associated timestamp.
 *
 * <p>Entries are ordered by their timestamp in ascending order. When timestamps are equal, ordering
 * falls back to the natural ordering of {@code T}. The class treats timestamps as caller-provided,
 * opaque numeric values; it does not interpret units or clock source.
 *
 * <p>Concurrency: All mutating methods and most queries are {@code synchronized} on this instance.
 * The {@link #size()} method is not synchronized and therefore may observe a transient size if
 * called concurrently with updates. Callers that require a consistent view should perform their own
 * synchronization.
 *
 * <p>Complexity (typical): {@code O(log n)} per insert/update via the underlying {@link TreeSet},
 * plus {@code O(1)} expected for the index lookup via {@link HashMap}. Range queries create {@link
 * java.util.NavigableSet} views and may iterate over matching elements.
 *
 * @param <T> value type, which must be {@link Comparable} for tie-breaking order
 */
public class TimeSortedHashtable<T extends Comparable<T>> {
  /** Creates an empty table. */
  public TimeSortedHashtable() {
    this.elements = new TreeSet<>();
    this.valueToElement = new HashMap<>();
  }

  private static class Element<T extends Comparable<T>> implements Comparable<Element<T>> {
    Element(long t, T v) {
      time = t;
      value = v;
    }

    long time;
    final T value;

    @Override
    public int compareTo(Element<T> o) {
      if (time > o.time) return 1;
      if (time < o.time) return -1;
      if (value == null && o.value == null) return 0;
      if (value == null) return 1; // o.value is non-null here
      if (o.value == null) return -1; // value is non-null here
      return value.compareTo(o.value);
    }

    @Override
    public boolean equals(Object obj) {
      if (this == obj) return true;
      if (!(obj instanceof Element<?> other)) return false;
      return time == other.time && Objects.equals(value, other.value);
    }

    @Override
    public int hashCode() {
      return Objects.hash(time, value);
    }
  }

  private final TreeSet<Element<T>> elements;
  private final HashMap<T, Element<T>> valueToElement;

  /**
   * Adds or updates a value with the given timestamp and moves it to the most recent position.
   *
   * <p>If the value already exists, its timestamp is updated to {@code now} and its ordering is
   * adjusted accordingly; no duplicate entry is inserted.
   *
   * <p>Timestamp semantics are defined by the caller; the structure only preserves ordering.
   *
   * @param value non-null value to insert or update
   * @param now caller-provided timestamp used for ordering
   * @throws NullPointerException if {@code value} is {@code null}
   */
  public final synchronized void push(T value, long now) {
    assert (elements.size() == valueToElement.size());
    if (value == null) throw new NullPointerException();

    Element<T> e = valueToElement.get(value);

    if (e == null) {
      e = new Element<>(now, value);
      elements.add(e);
      valueToElement.put(value, e);
    } else {
      elements.remove(e);
      e.time = now;
      elements.add(e);
    }

    assert (elements.size() == valueToElement.size());
  }

  /**
   * Returns the number of stored values.
   *
   * <p>Thread-safety: This method is not synchronized. If invoked concurrently with mutations, it
   * may observe a transient size. Callers requiring a consistent view should synchronize on this
   * instance.
   *
   * @return element count
   */
  public final int size() {
    return elements.size();
  }

  /**
   * Removes a value if present.
   *
   * @param value value to remove (may be {@code null}; {@code null} is treated as absent)
   * @return {@code true} if the value was present and removed; {@code false} otherwise
   */
  public final synchronized boolean removeValue(T value) {
    assert (elements.size() == valueToElement.size());
    Element<T> e = valueToElement.remove(value);
    if (e == null) return false;
    elements.remove(e);
    assert (elements.size() == valueToElement.size());
    return true;
  }

  /**
   * Returns whether the value is currently present.
   *
   * @param key value to test for membership
   * @return {@code true} if present; {@code false} otherwise
   */
  public final synchronized boolean containsValue(T key) {
    return valueToElement.containsKey(key);
  }

  /**
   * Returns the timestamp associated with {@code value}, or {@code -1} if absent.
   *
   * <p>Side effects: This method removes the value from the internal index that maps values to
   * elements but does not remove it from the time-ordered set. It does not promote or otherwise
   * update recency; use {@link #push} to update ordering.
   *
   * @param value value whose timestamp is requested
   * @return the associated timestamp, or {@code -1} if the value is not present
   */
  public final synchronized long getTime(T value) {
    Element<T> e = valueToElement.remove(value);
    if (e == null) return -1;
    return e.time;
  }

  /**
   * Counts the number of values strictly after the given timestamp.
   *
   * <p>Entries with exactly the provided timestamp are not included. This is implemented by
   * constructing a sentinel element and taking a tail view that begins strictly after {@code t}.
   *
   * @param t timestamp lower bound (exclusive)
   * @return number of values with timestamp greater than {@code t}
   */
  public synchronized int countValuesAfter(long t) {
    // Use a sentinel with {@code null} value so entries at exactly {@code t} compare smaller and
    // are excluded from the tail view (strictly greater than {@code t}).
    Set<Element<T>> s = elements.tailSet(new Element<>(t, null));

    return s.size();
  }

  /**
   * Removes all entries whose timestamp is less than or equal to the given time.
   *
   * <p>Internally, a head view up to a sentinel at {@code t} is iterated and removed. The operation
   * maintains the internal index and set in lockstep.
   *
   * @param t timestamp upper bound (inclusive)
   */
  public final synchronized void removeBefore(long t) {
    assert (elements.size() == valueToElement.size());
    // Head view includes entries at exactly {@code t} because the sentinel sorts after them.
    Set<Element<T>> s = elements.headSet(new Element<>(t, null));

    for (Iterator<Element<T>> i = s.iterator(); i.hasNext(); ) {
      Element<T> e = i.next();
      valueToElement.remove(e.value);
      i.remove();
    }

    assert (elements.size() == valueToElement.size());
  }

  /**
   * Returns the values and timestamps strictly after the given timestamp.
   *
   * <p>The result is a two-element array: index {@code 0} contains the populated {@code
   * valuesArray} (in ascending timestamp order), and index {@code 1} contains a newly allocated
   * {@code Long[]} with the corresponding timestamps.
   *
   * <p>Preconditions: {@code valuesArray.length} must be at least the number of matching entries;
   * otherwise, an {@link ArrayIndexOutOfBoundsException} is thrown while populating it.
   *
   * @param timestamp lower bound (exclusive)
   * @param valuesArray destination array for values; must be large enough
   * @return an {@code Object[]} containing {@code valuesArray} at index {@code 0} and the
   *     corresponding {@code Long[]} timestamps at index {@code 1}
   */
  public final synchronized Object[] pairsAfter(long timestamp, T[] valuesArray) {
    // Tail view starts strictly after {@code timestamp}; see comparison rules in Element.
    Set<Element<T>> s = elements.tailSet(new Element<>(timestamp, null));
    Long[] timeArray = new Long[s.size()];

    int i = 0;
    for (Element<T> e : s) {
      timeArray[i] = e.time;
      valuesArray[i] = e.value;
      i++;
    }

    return new Object[] {valuesArray, timeArray};
  }
}

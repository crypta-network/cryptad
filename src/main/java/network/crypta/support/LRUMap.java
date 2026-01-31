package network.crypta.support;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Least-recently-used (LRU) map from keys to values.
 *
 * <p>When a mapping is {@linkplain #push(Object, Object) pushed}, the entry becomes the most
 * recently used, even if the key already exists. Removal and peeking operations work from the
 * least-recently-used side (i.e., the entry that was pushed furthest in the past). The caller is
 * responsible for enforcing any size limits or eviction policies on top of this primitive.
 *
 * <p>In many cases, a {@link java.util.LinkedHashMap} configured for access order can offer similar
 * behavior, but this implementation avoids rehashing and uses an intrusive list for predictable
 * constant-time operations.
 *
 * <h3>Threading</h3>
 *
 * Most mutating and order-sensitive methods are {@code synchronized}. Methods such as {@link
 * #size()} and {@link #isEmpty()} are not synchronized and may reflect a momentarily stale view
 * under concurrent access.
 *
 * <h3>Nullability</h3>
 *
 * Null keys are not permitted and cause a {@link NullPointerException}. Null values are allowed.
 *
 * <h3>Iteration</h3>
 *
 * {@link #keys()} and {@link #values()} return snapshot enumerations in LRU→MRU order. The snapshot
 * is created under synchronization and is not affected by later modifications.
 *
 * @param <K> the key type (non-null)
 * @param <V> the value type (may be null)
 */
public class LRUMap<K, V> {
  private static final Logger LOG = LoggerFactory.getLogger(LRUMap.class);
  private static final String NULL_KEY_IN_QITEM = "LRUMap invariant violated: null key in QItem";

  /**
   * Intrusive list of entries, ordered MRU→LRU (head is MRU, tail is LRU). We use an intrusive
   * structure to store neighbor links in the nodes themselves for {@code O(1)} moves and removals.
   */
  private final DoublyLinkedListImpl<QItem<K, V>> list = new DoublyLinkedListImpl<>();

  private final Map<K, QItem<K, V>> hash;

  /**
   * Creates an instance backed by a {@link HashMap}. This variant is fast but not resilient to
   * adversarial hash collisions; prefer {@link #createSafeMap()} when keys may be
   * attacker-controlled.
   */
  public LRUMap() {
    hash = new HashMap<>();
  }

  /**
   * Creates an instance reusing the provided backing map.
   *
   * <p>Implementation detail: used by safe factory methods to switch map type.
   */
  private LRUMap(Map<K, QItem<K, V>> map) {
    hash = map;
  }

  /**
   * Creates a variant that is safer for attacker-controlled keys.
   *
   * <p>Backed by a {@link TreeMap} to avoid pathological {@link HashMap} collision attacks.
   *
   * @param <K> comparable key type
   * @param <V> value type
   * @return a new map using {@link TreeMap} as the backing map
   */
  public static <K extends Comparable<K>, V> LRUMap<K, V> createSafeMap() {
    return new LRUMap<>(new TreeMap<>());
  }

  /**
   * Creates a variant that is safer for attacker-controlled keys using a custom comparator.
   *
   * <p>Backed by a {@link TreeMap} with the supplied {@link Comparator}.
   *
   * @param comparator comparator for ordering keys; must impose a total order
   * @param <K> key type
   * @param <V> value type
   * @return a new map using {@link TreeMap} as the backing map
   */
  public static <K, V> LRUMap<K, V> createSafeMap(Comparator<K> comparator) {
    return new LRUMap<>(new TreeMap<>(comparator));
  }

  /**
   * Inserts or updates a mapping and promotes it to most-recently-used (MRU).
   *
   * <p>If the key already exists, its value is replaced and the entry is moved to the MRU position.
   * No duplicate entry is inserted.
   *
   * @param key non-null key
   * @param value value (may be null)
   * @return the previous value associated with {@code key}, or {@code null} if none
   * @throws NullPointerException if {@code key} is {@code null}
   * @implNote Runs in {@code O(1)} time.
   */
  public final synchronized V push(K key, V value) {
    if (key == null) throw new NullPointerException();
    V old = null;
    QItem<K, V> insert = hash.get(key);
    if (insert == null) {
      insert = new QItem<>(key, value);
      hash.put(key, insert);
    } else {
      old = insert.getValue();
      insert.setValue(value);
      list.remove(insert);
    }
    LOG.debug("Pushed {} ( {} {} )", insert, key, value);

    list.unshift(insert);
    return old;
  }

  /**
   * Removes and returns the least-recently-used key.
   *
   * <p>Also removes the corresponding mapping.
   *
   * @return the LRU key, or {@code null} if empty
   * @implNote Runs in {@code O(1)} time.
   */
  public final synchronized K popKey() {
    if (!list.isEmpty()) {
      QItem<K, V> popped = list.pop();
      if (popped == null) return null; // defensive: static analysis may not infer non-null here
      K k = Objects.requireNonNull(popped.getObj(), NULL_KEY_IN_QITEM);
      QItem<K, V> removed =
          Objects.requireNonNull(
              hash.remove(k), "LRUMap invariant violated: hash missing popped key");
      return removed.getObj();
    } else {
      return null;
    }
  }

  /**
   * Removes and returns the least-recently-used value.
   *
   * <p>Also removes the corresponding mapping.
   *
   * @return the LRU value, or {@code null} if empty
   * @implNote Runs in {@code O(1)} time.
   */
  public final synchronized V popValue() {
    if (!list.isEmpty()) {
      QItem<K, V> popped = list.pop();
      if (popped == null) return null; // defensive: static analysis may not infer non-null here
      K k = Objects.requireNonNull(popped.getObj(), NULL_KEY_IN_QITEM);
      QItem<K, V> removed =
          Objects.requireNonNull(
              hash.remove(k), "LRUMap invariant violated: hash missing popped key");
      return removed.getValue();
    } else {
      return null;
    }
  }

  /**
   * Returns the least-recently-used value without removing it.
   *
   * @return the LRU value, or {@code null} if empty
   */
  public final synchronized V peekValue() {
    if (!list.isEmpty()) {
      QItem<K, V> tail = list.tail();
      if (tail == null) return null; // defensive
      K k = Objects.requireNonNull(tail.getObj(), NULL_KEY_IN_QITEM);
      QItem<K, V> q =
          Objects.requireNonNull(hash.get(k), "LRUMap invariant violated: hash missing tail key");
      return q.getValue();
    } else {
      return null;
    }
  }

  /**
   * Returns the least-recently-used key without removing it.
   *
   * @return the LRU key, or {@code null} if empty
   */
  public final synchronized K peekKey() {
    if (!list.isEmpty()) {
      QItem<K, V> tail = list.tail();
      if (tail == null) return null; // defensive
      K k = Objects.requireNonNull(tail.getObj(), NULL_KEY_IN_QITEM);
      QItem<K, V> q =
          Objects.requireNonNull(hash.get(k), "LRUMap invariant violated: hash missing tail key");
      return q.getObj();
    } else {
      return null;
    }
  }

  /**
   * Returns the number of mappings currently stored.
   *
   * <p>Not synchronized; may reflect a slightly stale value under concurrent access.
   *
   * @return current entry count (never negative)
   */
  public final int size() {
    return list.size();
  }

  /**
   * Removes a mapping by key.
   *
   * @param key non-null key
   * @return {@code true} if a mapping was removed; {@code false} if the key was absent
   * @throws NullPointerException if {@code key} is {@code null}
   * @implNote Runs in {@code O(1)} time.
   */
  public final synchronized boolean removeKey(K key) {
    if (key == null) throw new NullPointerException();
    QItem<K, V> i = hash.remove(key);
    if (i != null) {
      list.remove(i);
      return true;
    } else {
      return false;
    }
  }

  /**
   * Returns whether a mapping for the key exists.
   *
   * @param key non-null key
   * @return {@code true} if present; {@code false} otherwise
   * @throws NullPointerException if {@code key} is {@code null}
   */
  public final synchronized boolean containsKey(K key) {
    if (key == null) throw new NullPointerException();
    return hash.containsKey(key);
  }

  /**
   * Returns the value for the key without promotion.
   *
   * <p>This does not change LRU order. To promote, call {@link #push(Object, Object)} with the same
   * key and value.
   *
   * @param key non-null key
   * @return the value, or {@code null} if absent
   * @throws NullPointerException if {@code key} is {@code null}
   */
  public final synchronized V get(K key) {
    if (key == null) throw new NullPointerException();
    QItem<K, V> q = hash.get(key);
    if (q == null) return null;
    return q.getValue();
  }

  /**
   * Returns a snapshot {@link Enumeration} of keys in LRU→MRU order.
   *
   * <p>The snapshot is built under synchronization and is not affected by subsequent changes.
   *
   * @return enumeration of keys from least- to most-recently-used
   */
  public Enumeration<K> keys() {
    synchronized (this) {
      ArrayList<K> out = new ArrayList<>(list.size());
      Enumeration<QItem<K, V>> e = list.reverseElements();
      while (e.hasMoreElements()) {
        out.add(e.nextElement().getObj());
      }
      return Collections.enumeration(out);
    }
  }

  /**
   * Returns a snapshot {@link Enumeration} of values in LRU→MRU order.
   *
   * <p>The snapshot is built under synchronization and is not affected by subsequent changes.
   *
   * @return enumeration of values from least- to most-recently-used
   */
  public Enumeration<V> values() {
    synchronized (this) {
      ArrayList<V> out = new ArrayList<>(list.size());
      Enumeration<QItem<K, V>> e = list.reverseElements();
      while (e.hasMoreElements()) {
        out.add(e.nextElement().getValue());
      }
      return Collections.enumeration(out);
    }
  }

  /**
   * Node stored in the intrusive list.
   *
   * <p>Public for historical reasons; intended for internal use. Holds a key/value pair and the
   * neighbor links required by {@link DoublyLinkedListImpl}.
   *
   * @param <K> key type
   * @param <V> value type
   */
  public static class QItem<K, V> extends DoublyLinkedListImpl.Item<QItem<K, V>> {
    private K obj;
    private V value;

    /**
     * Creates a node.
     *
     * @param key key (may be null only for internal/defensive states)
     * @param val value (may be null)
     */
    public QItem(K key, V val) {
      this.obj = key;
      this.value = val;
    }

    /** Returns the key. */
    public K getObj() {
      return obj;
    }

    /** Sets the key. */
    public void setObj(K obj) {
      this.obj = obj;
    }

    /** Returns the value. */
    public V getValue() {
      return value;
    }

    /** Sets the value. */
    public void setValue(V value) {
      this.value = value;
    }

    @Override
    public String toString() {
      return super.toString() + ": " + obj + ' ' + value;
    }
  }

  /**
   * Returns whether the map is empty.
   *
   * <p>Not synchronized; may reflect a slightly stale value under concurrent access.
   *
   * @return {@code true} if size is 0, otherwise {@code false}
   */
  public boolean isEmpty() {
    return list.isEmpty();
  }

  /**
   * Copies values into the provided array in LRU→MRU order.
   *
   * <p>Unlike many {@code java.util} methods, this method never reallocates and therefore does not
   * return the filled array. Ensure {@code entries.length >= size()} before calling.
   *
   * @param entries destination array in which values are written from index 0 upward
   */
  public synchronized void valuesToArray(V[] entries) {
    Enumeration<V> values = values();
    int i = 0;
    while (values.hasMoreElements()) entries[i++] = values.nextElement();
  }

  /**
   * Removes all entries.
   *
   * <p>Clears both the intrusive list and the backing map.
   */
  public synchronized void clear() {
    list.clear();
    hash.clear();
  }
}

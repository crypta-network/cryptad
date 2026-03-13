/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *          http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

package com.jthemedetecor.util;

import java.util.Collection;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.jetbrains.annotations.NotNull;

/**
 * A mutable {@link Set} implementation backed by a {@link ConcurrentHashMap}.
 *
 * <p>This type provides a small concurrent set for callers that need lock-free membership checks,
 * additions, and removals without introducing an additional dependency. Each element is stored as a
 * key in the backing map, while a single shared marker object acts as the constant placeholder
 * value. The class is useful when multiple threads may add or remove listeners or other
 * membership-style entries concurrently.
 *
 * <p>The set is thread-safe for the operations delegated to {@link ConcurrentHashMap}, but it
 * remains a mutable collection with the same practical trade-offs as the backing map. In
 * particular, iteration reflects the weakly consistent view provided by the concurrent key set, and
 * {@code null} elements are not supported because the underlying map rejects {@code null} keys.
 * Bulk retention and bulk removal are intentionally unsupported by this minimal wrapper.
 *
 * @param <E> the element type stored as concurrent map keys
 */
public class ConcurrentHashSet<E> implements Set<E> {

  private static final Object OBJ = new Object();

  private final Map<E, Object> map;

  /**
   * Creates an empty concurrent set backed by a new {@link ConcurrentHashMap} instance.
   *
   * <p>The resulting set is ready for concurrent reads and writes immediately after construction.
   * No initial capacity or concurrency tuning is exposed here because this wrapper is intended to
   * stay small and behave like a straightforward membership container over the default map
   * configuration.
   */
  public ConcurrentHashSet() {
    map = new ConcurrentHashMap<>();
  }

  @Override
  public int size() {
    return map.size();
  }

  @Override
  public boolean isEmpty() {
    return map.isEmpty();
  }

  @Override
  public boolean contains(Object o) {
    return containsKey(map, o);
  }

  @Override
  public @NotNull Iterator<E> iterator() {
    return map.keySet().iterator();
  }

  @Override
  public Object @NotNull [] toArray() {
    return map.keySet().toArray();
  }

  @Override
  public <T> T @NotNull [] toArray(T @NotNull [] a) {
    return map.keySet().toArray(a);
  }

  @Override
  public boolean add(E e) {
    return map.put(e, OBJ) == null;
  }

  @Override
  public boolean remove(Object o) {
    return map.remove(o) != null;
  }

  @Override
  public boolean containsAll(@NotNull Collection<?> c) {
    return map.keySet().containsAll(c);
  }

  @Override
  public boolean addAll(Collection<? extends E> c) {
    boolean changed = false;
    for (E e : c) {
      if (map.put(e, OBJ) == null) {
        changed = true;
      }
    }
    return changed;
  }

  @Override
  public boolean retainAll(@NotNull Collection<?> c) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean removeAll(@NotNull Collection<?> c) {
    throw new UnsupportedOperationException();
  }

  @Override
  public void clear() {
    map.clear();
  }

  private static boolean containsKey(Map<?, ?> map, Object key) {
    return map.containsKey(key);
  }
}

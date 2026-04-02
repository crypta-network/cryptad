package network.crypta.support;

/**
 * Extension of {@link RemoveRandom} that associates a contextual object with the container.
 *
 * <p>The extra object (of type {@code T}) typically identifies the group or owner whose requests
 * are contained in this node. For example, {@link RandomGrabArrayWithObject} stores a per-client
 * {@code RandomGrabArray}, and {@link SectoredRandomGrabArray} organizes children by such objects
 * to provide fair selection among groups.
 *
 * <p>Thread-safety: Implementations are usually accessed while the request selector's root lock is
 * held (see {@code ClientRequestSelector}). Getters/setters should be fast and avoid blocking.
 *
 * @param <T> the type of the associated context object (e.g., a client handle or grouping key)
 */
public interface RemoveRandomWithObject<T> extends RemoveRandom {

  /**
   * Returns the contextual object associated with this container.
   *
   * @return the associated object, possibly {@code null} depending on the implementation
   */
  T getObject();

  /**
   * Returns whether the container currently holds no items.
   *
   * <p>Used by parents (e.g., {@link RemoveRandomParent}) to decide whether to detach and prune
   * empty nodes from the selection tree.
   *
   * @return {@code true} if the logical size is zero; otherwise {@code false}
   */
  boolean isEmpty();

  /**
   * Sets or replaces the contextual object associated with this container.
   *
   * <p>Intended for maintenance operations such as reattachment under a different group. This does
   * not move or modify contained items by itself.
   *
   * @param client the new associated object
   */
  void setObject(T client);
}

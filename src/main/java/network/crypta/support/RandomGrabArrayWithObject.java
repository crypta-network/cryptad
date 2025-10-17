package network.crypta.support;

import network.crypta.client.async.ClientRequestSelector;

/**
 * Random-grab array that carries an associated context object.
 *
 * <p>This thin wrapper around {@link RandomGrabArray} stores and exposes a caller-provided
 * contextual object (for example, a client handle or grouping key) while retaining the base class's
 * storage and selection behavior. Parents use this to organize children by an object and still have
 * access to the underlying array of {@link RandomGrabArrayItem}s.
 *
 * <p><strong>Thread-safety:</strong> Like its superclass, this class uses the shared selection-root
 * object (a {@link ClientRequestSelector} instance) as a monitor. All public methods synchronize on
 * that monitor to remain consistent with operations on sibling nodes in the request-selection tree.
 * Callers should hold no other locks when entering these methods to avoid deadlocks and should use
 * the same root monitor when accessing related structures.
 *
 * @param <T> type of the associated context object
 */
public class RandomGrabArrayWithObject<T> extends RandomGrabArray
    implements RemoveRandomWithObject<T> {

  // Guarded by 'root' (the shared {@link ClientRequestSelector} monitor used throughout the tree).
  private T client;

  /**
   * Constructs a new instance with an associated object and selection-tree wiring.
   *
   * <p>The provided {@code root} is used as the synchronization monitor for this node. All public
   * methods synchronize on it so that reads/writes of the associated object and the underlying
   * storage remain consistent with operations on the rest of the tree.
   *
   * @param client the associated object; may be {@code null}
   * @param parent the parent in the selection tree; may be {@code null}
   * @param root the shared selection root used for synchronization; must be the same object used by
   *     sibling nodes
   */
  public RandomGrabArrayWithObject(
      T client, RemoveRandomParent parent, ClientRequestSelector root) {
    super(parent, root);
    this.client = client;
  }

  /**
   * Returns the associated context object.
   *
   * <p><strong>Threading:</strong> Synchronizes on {@code root}. The call blocks briefly if another
   * thread is currently operating on the selection tree using the same monitor.
   *
   * @return the object previously supplied (which may be {@code null})
   */
  @Override
  public final T getObject() {
    synchronized (root) {
      return client;
    }
  }

  /**
   * Sets or replaces the associated context object.
   *
   * <p>This does not modify the contained items or their scheduling state. It merely updates the
   * reference to the context object used by parents when grouping or identifying this node.
   *
   * <p><strong>Threading:</strong> Synchronizes on {@code root} to remain consistent with other
   * tree operations.
   *
   * @param client the new associated object; may be {@code null}
   */
  @Override
  public void setObject(T client) {
    synchronized (root) {
      this.client = client;
    }
  }
}

package network.crypta.support;

import network.crypta.client.async.ClientRequestSelector;

/**
 * Sectorized selector that also carries an associated context object.
 *
 * <p>This class augments {@link SectoredRandomGrabArray} by implementing {@link
 * RemoveRandomWithObject} for the current node itself. It keeps a caller-supplied object of type
 * {@code T} while the children remain containers that associate their own objects of type {@code
 * C}. This is useful for building deeper selection trees where an SRGA node needs to be treated as
 * a child that also has an identity/context at the next level up.
 *
 * <p><strong>Thread-safety:</strong> All public methods synchronize on the shared {@link
 * ClientRequestSelector} instance referenced by {@code root}. Callers should hold no other locks
 * when entering these methods to avoid deadlocks and must use the same {@code root} monitor across
 * the selection tree.
 *
 * @param <T> the type of the context object associated with this node (returned by {@link
 *     #getObject()})
 * @param <C> the type of the context object associated with each child container
 * @param <G> the child container type; must implement {@link RemoveRandomWithObject} for {@code C}
 */
public class SectoredRandomGrabArrayWithObject<T, C, G extends RemoveRandomWithObject<C>>
    extends SectoredRandomGrabArray<C, G> implements RemoveRandomWithObject<T> {

  // Guarded by 'root' (the shared ClientRequestSelector monitor used throughout the tree).
  private T object;

  /**
   * Creates a sectorized selector that stores an associated object for this node.
   *
   * <p>The provided {@code root} is the synchronization monitor shared with peers in the request
   * selection tree. All public methods synchronize on it to keep internal state consistent.
   *
   * @param object the object to associate with this node; may be {@code null}
   * @param parent the parent used for wakeup propagation and pruning; may be {@code null}
   * @param root the shared selector root used as the synchronization monitor; must not be {@code
   *     null}
   */
  public SectoredRandomGrabArrayWithObject(
      T object, RemoveRandomParent parent, ClientRequestSelector root) {
    super(parent, root);
    this.object = object;
  }

  /**
   * Returns the context object associated with this node.
   *
   * <p><strong>Threading:</strong> Synchronizes on {@code root}. The call may briefly block if
   * another thread is operating on the same selection tree.
   *
   * @return the associated object, possibly {@code null}
   */
  @Override
  public T getObject() {
    synchronized (root) {
      return object;
    }
  }

  /**
   * Returns a concise string representation including this node's associated object.
   *
   * <p>The format is the superclass representation followed by a colon and the associated object,
   * i.e., {@code super.toString() + ":" + object}.
   *
   * @return human-readable representation for diagnostics and logging
   */
  @Override
  public String toString() {
    return super.toString() + ":" + object;
  }

  /**
   * Sets or replaces the context object associated with this node.
   *
   * <p>This does not modify child containers or their contents; it only updates this node's
   * metadata. Synchronizes on {@code root} for consistency with other tree operations.
   *
   * @param client the new associated object; may be {@code null}
   */
  @Override
  public void setObject(T client) {
    synchronized (root) {
      object = client;
    }
  }
}

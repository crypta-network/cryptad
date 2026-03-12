package network.crypta.support;

import network.crypta.client.async.ClientContext;
import network.crypta.client.async.RequestSelectionTreeNode;

/**
 * Parent contract for nodes that contain {@link RemoveRandom} children in the selection tree.
 *
 * <p>Implementations manage one or more child containers (for example, {@link RandomGrabArray} or
 * sectorized variants) and are responsible for removing empty children and propagating structural
 * changes upward. The interface extends {@link RequestSelectionTreeNode} so parents can participate
 * in wakeup-time propagation and overall scheduling decisions.
 *
 * <p>Thread-safety: Callers typically hold the request selector's root lock (see {@code
 * ClientRequestSelector}) when invoking methods on this interface. Implementations should avoid
 * long-running work and external blocking inside these callbacks.
 */
public interface RemoveRandomParent extends RequestSelectionTreeNode {

  /**
   * Removes the given child if it has become empty and propagates removal if the parent empties.
   *
   * <p>Callers invoke this after a child {@link RemoveRandom} container reports emptiness (for
   * example, following compaction that deleted the last item). The parent should detach the child
   * from its internal structures. If that makes the parent itself empty, it should notify its own
   * parent (if any) so that the tree can be further pruned.
   *
   * <p>Side effects may include clearing or reducing cached wakeup times on ancestors via the usual
   * {@link RequestSelectionTreeNode} methods.
   *
   * @param r the child container that may need removal; must not be {@code null}
   * @param context client execution context used for notifications; must not be {@code null}
   */
  void maybeRemove(RemoveRandom r, ClientContext context);
}

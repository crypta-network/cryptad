package network.crypta.support;

import network.crypta.client.async.ClientContext;
import network.crypta.client.async.RequestSelectionTreeNode;

public interface RemoveRandomParent extends RequestSelectionTreeNode {

  /**
   * Remove the specified RemoveRandom, and propagate upwards if the parent is now empty.
   *
   * @param context
   */
  void maybeRemove(RemoveRandom r, ClientContext context);
}

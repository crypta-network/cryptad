package network.crypta.node;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Gates admission of peers based on opennet policy for the current node.
 *
 * <p>This helper provides a single, focused entry point for deciding whether a newly discovered
 * peer should be retained when opennet logic is in play. Callers supply the candidate peer and a
 * flag that can bypass opennet checks; the gate then applies opennet-specific rules only when the
 * peer is an {@link OpennetPeerNode} and opennet support is available. The class hides the direct
 * {@link OpennetManager} dependency so other components do not need to reference opennet types to
 * make basic admission decisions.
 *
 * <p>Lifecycle and state are intentionally simple: the instance is bound to a {@link Node} and
 * remains valid as long as that node reference is valid. It has no internal mutable state beyond
 * the node reference and performs no caching; each call evaluates the current opennet manager
 * availability. Concurrency is limited to the thread-safety of the supplied {@link Node} and its
 * opennet manager; this class itself is stateless and safe to share between threads when the node
 * is safe.
 *
 * <p>Responsibilities include:
 *
 * <ul>
 *   <li>Applying opt-in opennet admission rules for {@link OpennetPeerNode} instances.
 *   <li>Delegating to {@link OpennetManager} when opennet is enabled.
 *   <li>Rejecting opennet peers when opennet support is absent or disabled.
 * </ul>
 *
 * @see OpennetManager
 * @see OpennetPeerNode
 */
public class PeerOpennetGate {
  private static final Logger LOG = LoggerFactory.getLogger(PeerOpennetGate.class);

  private final Node node;

  /**
   * Creates a gate that evaluates opennet admission against the given node.
   *
   * <p>The provided {@link Node} supplies the opennet manager reference used to validate opennet
   * peers. The gate does not take ownership of the node and performs no defensive copying; callers
   * should pass the same node instance used by their peer-management workflow. This constructor is
   * side-effect free and does not perform any opennet checks by itself.
   *
   * @param node node instance that supplies opennet configuration and manager access.
   */
  public PeerOpennetGate(Node node) {
    this.node = node;
  }

  /**
   * Validates opennet peers when opennet handling is enabled.
   *
   * <p>This method returns {@code true} for non-opennet peers or when opennet checks are explicitly
   * bypassed. For opennet peers, it consults the current {@link OpennetManager} from the associated
   * {@link Node} and, when available, delegates admission to the manager. If opennet is disabled or
   * unavailable, the peer is rejected and an error is logged. The method is deterministic and
   * idempotent with respect to non-opennet peers; it may have side effects when delegating to the
   * manager for opennet peers.
   *
   * @param peer candidate peer to evaluate for opennet admission; non-opennet peers are accepted.
   * @param ignoreOpennet if true, bypass all opennet checks and accept the peer immediately.
   * @return {@code true} if the peer may remain, or {@code false} if it must be removed.
   */
  public boolean allowPeer(PeerNode peer, boolean ignoreOpennet) {
    if (ignoreOpennet) return true;
    if (!(peer instanceof OpennetPeerNode)) return true;

    OpennetManager opennet = node.getOpennet();
    if (opennet != null) {
      opennet.forceAddPeer((OpennetPeerNode) peer, true);
      return true;
    }

    LOG.error("Adding opennet peer when opennet is disabled: {} - removing", peer);
    return false;
  }
}

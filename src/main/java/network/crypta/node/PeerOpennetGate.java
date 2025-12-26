package network.crypta.node;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Handles opennet admission checks for peers that are being added.
 *
 * <p>Encapsulates the dependency on {@link OpennetManager} so callers do not need to reference
 * opennet-specific types when deciding whether a peer may be accepted.
 */
public class PeerOpennetGate {
  private static final Logger LOG = LoggerFactory.getLogger(PeerOpennetGate.class);

  private final Node node;

  public PeerOpennetGate(Node node) {
    this.node = node;
  }

  /**
   * Validates opennet peers when opennet handling is enabled.
   *
   * @param peer candidate peer.
   * @param ignoreOpennet if true, skip opennet checks entirely.
   * @return true if the peer may remain, false if it must be removed.
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

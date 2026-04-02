package network.crypta.node;

/**
 * Opennet-specific peer status snapshot.
 *
 * <p>This type augments {@link PeerNodeStatus} with the timestamp of the last successful
 * interaction as reported by the associated {@link OpennetPeerNode}. Instances represent a snapshot
 * taken at construction time and do not update afterward.
 *
 * <p>Immutability note: the fields declared in this class are {@code final}. The overall snapshot
 * semantics and identity behavior are inherited from {@link PeerNodeStatus}.
 */
public class OpennetPeerNodeStatus extends PeerNodeStatus {

  /**
   * Creates a new snapshot for an opennet peer.
   *
   * <p>The {@code peerNode} must be an instance of {@link OpennetPeerNode}. The {@code noHeavy}
   * flag is forwarded to the superclass; see {@link PeerNodeStatus#PeerNodeStatus(PeerNode,
   * boolean)} for details about how it affects snapshot contents.
   *
   * @param peerNode the peer whose status is captured; must be an {@link OpennetPeerNode}
   * @param noHeavy forwarded to the superclass; consult {@link PeerNodeStatus}
   * @throws ClassCastException if {@code peerNode} is not an {@link OpennetPeerNode}
   */
  OpennetPeerNodeStatus(PeerNode peerNode, boolean noHeavy) {
    super(peerNode, noHeavy);
    timeLastSuccess = ((OpennetPeerNode) peerNode).timeLastSuccess();
  }

  /**
   * Timestamp of the most recent successful interaction with this opennet peer, as returned by
   * {@link OpennetPeerNode#timeLastSuccess()} when this snapshot was created.
   *
   * <p>Units and clock source are defined by the provider method; this field is an immutable
   * capture of that value.
   */
  public final long timeLastSuccess;

  /**
   * Compares by peer identity as defined in {@link PeerNodeStatus}.
   *
   * <p>Two snapshots are equal if they refer to the same peer identity. This method intentionally
   * does not include {@link #timeLastSuccess} in the comparison to maintain the equality contract
   * across the class hierarchy (e.g., when comparing with a {@link PeerNodeStatus}).
   */
  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;
    if (!(obj instanceof PeerNodeStatus)) return false;
    return super.equals(obj);
  }

  /**
   * Returns a hash code consistent with {@link #equals(Object)} by delegating to the base class.
   */
  @Override
  public int hashCode() {
    return super.hashCode();
  }
}

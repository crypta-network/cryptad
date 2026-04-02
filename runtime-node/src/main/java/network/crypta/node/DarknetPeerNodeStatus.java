package network.crypta.node;

import network.crypta.node.DarknetPeerNode.FRIEND_TRUST;
import network.crypta.node.DarknetPeerNode.FRIEND_VISIBILITY;

/**
 * Immutable snapshot of darknet‑specific peer state.
 *
 * <p>Extends {@link PeerNodeStatus} with values that apply only to darknet friends: display name,
 * connection policy flags (burst/listen/disabled), a private note, friend trust, and visibility
 * preferences. Values are copied from a live {@link DarknetPeerNode} during construction so UI and
 * diagnostics do not read mutable node state directly.
 *
 * <p>Threading: instances are read‑only after construction and therefore thread‑safe.
 */
public class DarknetPeerNodeStatus extends PeerNodeStatus {

  private final String name;

  private final boolean burstOnly;

  private final boolean listening;

  private final boolean disabled;

  private final String privateDarknetCommentNote;

  private final FRIEND_TRUST trustLevel;

  private final FRIEND_VISIBILITY ourVisibility;
  private final FRIEND_VISIBILITY theirVisibility;
  private final FRIEND_VISIBILITY overallVisibility;

  /**
   * Builds a snapshot from a live darknet peer.
   *
   * <p>Heavy statistics (message counters, load summaries) are handled by the {@link
   * PeerNodeStatus} constructor; this subclass only reads darknet‑specific values.
   *
   * @param peerNode source peer (must be a {@link DarknetPeerNode})
   * @param noHeavy forwarded to the parent constructor to optionally omit heavy statistics
   */
  public DarknetPeerNodeStatus(DarknetPeerNode peerNode, boolean noHeavy) {
    super(peerNode, noHeavy);
    this.name = peerNode.getName();
    this.burstOnly = peerNode.isBurstOnly();
    this.listening = peerNode.isListenOnly();
    this.disabled = peerNode.isDisabled();
    this.privateDarknetCommentNote = peerNode.getPrivateDarknetCommentNote();
    this.trustLevel = peerNode.getTrustLevel();
    this.ourVisibility = peerNode.getOurVisibility();
    this.theirVisibility = peerNode.getTheirVisibility();
    // Effective visibility is the stricter of ours and theirs. If theirs is null, the helper
    // treats it as less strict, so ourVisibility becomes the effective value.
    if (ourVisibility.isStricterThan(theirVisibility)) this.overallVisibility = ourVisibility;
    else this.overallVisibility = theirVisibility;
  }

  /**
   * Returns the configured friend trust.
   *
   * @return trust level used by friend‑related heuristics
   */
  public FRIEND_TRUST getTrustLevel() {
    return trustLevel;
  }

  /**
   * Returns the peer's display name.
   *
   * @return non‑null user‑provided name
   */
  public String getName() {
    return name;
  }

  /**
   * Indicates that handshake attempts are sent only in infrequent bursts.
   *
   * @return {@code true} when burst‑only is enabled
   */
  public boolean isBurstOnly() {
    return burstOnly;
  }

  /**
   * Indicates that the friend is locally disabled.
   *
   * @return {@code true} when disabled and not considered for new connections
   */
  public boolean isDisabled() {
    return disabled;
  }

  /**
   * Indicates that we accept inbound handshakes but do not initiate them.
   *
   * @return {@code true} when in listen‑only mode
   */
  public boolean isListening() {
    return listening;
  }

  /**
   * Returns the private note shown on the friends page.
   *
   * @return note text; may be empty
   */
  public String getPrivateDarknetCommentNote() {
    return privateDarknetCommentNote;
  }

  /**
   * Returns a concise, human‑readable description including the name and {@link PeerNodeStatus}
   * summary.
   */
  @Override
  public String toString() {
    return name + ' ' + super.toString();
  }

  /**
   * Equality is identical to {@link PeerNodeStatus#equals(Object)}.
   *
   * <p>This subclass does not add identity beyond the underlying peer. We therefore delegate to the
   * parent implementation to preserve symmetry and transitivity with {@code PeerNodeStatus}
   * instances.
   */
  @Override
  public boolean equals(Object obj) {
    return super.equals(obj);
  }

  /**
   * Hash code consistent with {@link #equals(Object)}.
   *
   * <p>Delegates to the parent implementation so that instances of this subclass remain
   * interchangeable with {@link PeerNodeStatus} for hashing based on the same peer identity.
   */
  @Override
  public int hashCode() {
    return super.hashCode();
  }

  /**
   * Returns our visibility preference for this friend.
   *
   * @return enum describing what other friends may learn about this link
   */
  public FRIEND_VISIBILITY getOurVisibility() {
    return ourVisibility;
  }

  /**
   * Returns the peer‑reported visibility preference.
   *
   * <p>If the peer has not sent a preference yet, returns {@link FRIEND_VISIBILITY#NO} to avoid
   * null checks in callers.
   *
   * @return their preference, or {@code NO} when unknown
   */
  public FRIEND_VISIBILITY getTheirVisibility() {
    if (theirVisibility == null) return FRIEND_VISIBILITY.NO;
    return theirVisibility;
  }

  /**
   * Returns the effective visibility, defined as the stricter of ours and theirs.
   *
   * @return stricter of {@link #getOurVisibility()} and {@link #getTheirVisibility()}
   */
  public FRIEND_VISIBILITY getOverallVisibility() {
    return overallVisibility;
  }
}

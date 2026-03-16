package network.crypta.runtime.spi;

/**
 * UI-level delivery categories for legacy node-to-node message sends.
 *
 * <p>The N2NTM compose/send page does not expose the daemon's full peer-state matrix. It collapses
 * the underlying sending result into three buckets that are stable enough for HTTP rendering and
 * localization: sent now, delayed because the peer is backed off, or queued for later delivery.
 * This enum is that detached contract.
 *
 * <p>Keeping the contract at this level lets the HTTP layer render the existing page without
 * depending on {@code PeerManager} status constants or live daemon objects. Callers should treat
 * these values as presentation categories, not as a complete audit trail of low-level transport
 * behavior.
 */
public enum DarknetMessageSendStatus {
  /**
   * The daemon reported a currently connected peer, so the UI renders the message as sent
   * immediately.
   */
  SENT,

  /**
   * The daemon reported routing backoff for the selected peer, so the UI keeps the existing delayed
   * bucket wording.
   */
  DELAYED,

  /**
   * Any legacy outcome outside the sent and delayed buckets is rendered in the existing queued UI
   * category.
   */
  QUEUED
}

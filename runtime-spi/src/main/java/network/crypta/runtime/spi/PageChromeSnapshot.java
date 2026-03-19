package network.crypta.runtime.spi;

import java.util.Objects;

/**
 * Captures the detached read-only runtime state needed by the shared admin page chrome.
 *
 * <p>The legacy HTTP shell still shows two security-level labels and one peer-progress bar in its
 * shared status area. This record carries only the values required to reproduce that existing UI:
 * detached threat-level enums, current connected-peer counts, the enabled-darknet total used when
 * opennet is disabled, and the opennet target count used when it is enabled.
 *
 * <p>The snapshot is intentionally narrow and does not model alerts, menus, mode-switch state, or
 * other request-context concerns that remain owned by the HTTP layer. It is designed to be created
 * once per request and then passed through rendering code as a stable, immutable view of the
 * daemon's shell-related status.
 *
 * @param networkThreatLevel current detached network threat level shown in the status bar
 * @param physicalThreatLevel current detached physical threat level shown in the status bar
 * @param connectedPeerCount current total number of connected peers across all transport modes
 * @param connectedDarknetPeerCount current number of connected darknet peers in the live roster
 * @param connectedOpennetPeerCount current number of connected opennet peers in the live roster
 * @param enabledDarknetPeerCount current number of enabled darknet peers used for darknet targets
 * @param opennetEnabled whether opennet is currently enabled for the node
 * @param opennetTargetIncludingDarknetPeerCount current opennet-connected-peers target, including
 *     darknet peers, or {@code 0} when opennet is disabled
 */
public record PageChromeSnapshot(
    SecurityNetworkThreatLevel networkThreatLevel,
    SecurityPhysicalThreatLevel physicalThreatLevel,
    int connectedPeerCount,
    int connectedDarknetPeerCount,
    int connectedOpennetPeerCount,
    int enabledDarknetPeerCount,
    boolean opennetEnabled,
    int opennetTargetIncludingDarknetPeerCount) {
  /**
   * Creates an immutable page-chrome snapshot.
   *
   * <p>The constructor enforces only the presence of the detached threat-level values. Peer counts
   * are stored exactly as supplied by the adapter, so the HTTP shell can preserve its current
   * rendering behavior without adding extra normalization in the shared SPI layer.
   *
   * @throws NullPointerException if either detached threat-level enum is {@code null}
   */
  public PageChromeSnapshot {
    Objects.requireNonNull(networkThreatLevel, "networkThreatLevel");
    Objects.requireNonNull(physicalThreatLevel, "physicalThreatLevel");
  }
}

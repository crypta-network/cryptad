package network.crypta.runtime.spi;

import java.util.List;
import java.util.Objects;

/**
 * Detached snapshot of one UDP socket handler's connectivity status.
 *
 * <p>Each UDP socket displayed by the connectivity page gets one of these records. The snapshot
 * contains the localized title used by the page, the current port-forwarding classification, and
 * optional advanced tracker-table rows for peer and IP history. The advanced data is intentionally
 * nested here, so callers can skip expensive tracker export work when rendering the summary view.
 *
 * <p>The record is immutable and copies its collections defensively, which makes it safe to pass
 * between adapter, UI, and test layers without retaining the live tracker state.
 *
 * @param title human-readable handler title shown on the connectivity page
 * @param portForwardStatus detached connectivity status for this handler
 * @param longestSendReceiveGapMillis longest observed send-to-receive gap in milliseconds, or
 *     {@code -1} when the advanced tracker export was not requested
 * @param peerEntries detached per-peer tracker rows in display order; empty when advanced details
 *     were omitted
 * @param ipEntries detached per-IP tracker rows in display order; empty when advanced details were
 *     omitted
 */
public record ConnectivitySocketSnapshot(
    String title,
    ConnectivityPortForwardStatus portForwardStatus,
    long longestSendReceiveGapMillis,
    List<ConnectivityTrafficEntrySnapshot> peerEntries,
    List<ConnectivityTrafficEntrySnapshot> ipEntries) {
  /**
   * Creates an immutable socket snapshot.
   *
   * <p>The constructor copies both tracker-entry lists defensively, so the snapshot remains stable
   * for the lifetime of an HTTP response.
   *
   * @throws NullPointerException if any required component is {@code null}
   */
  public ConnectivitySocketSnapshot {
    Objects.requireNonNull(title, "title");
    Objects.requireNonNull(portForwardStatus, "portForwardStatus");
    Objects.requireNonNull(peerEntries, "peerEntries");
    Objects.requireNonNull(ipEntries, "ipEntries");
    peerEntries = List.copyOf(peerEntries);
    ipEntries = List.copyOf(ipEntries);
  }
}

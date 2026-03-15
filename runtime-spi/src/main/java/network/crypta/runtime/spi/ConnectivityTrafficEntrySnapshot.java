package network.crypta.runtime.spi;

import java.util.List;
import java.util.Objects;

/**
 * Detached snapshot of one advanced connectivity tracker table row.
 *
 * <p>This record models a single peer or IP row in the advanced connectivity tables. It includes
 * the rendered address label, basic send and receive counters, a coarse initiator classification,
 * and lead-time values that describe when traffic first appeared after the node startup. Recent gap
 * history is exported separately, so the HTTP layer can render the existing table layout without
 * holding references to daemon tracker items.
 *
 * <p>All timing values use milliseconds. Negative lead times indicate that the relevant event has
 * not been observed for this row.
 *
 * @param address rendered peer or IP address label exactly as the page should display it
 * @param packetsSent total packets sent to this address since the tracker started collecting data
 * @param packetsReceived total packets received from this address since the tracker started
 *     collecting data
 * @param initiator whether traffic appears locally initiated, remotely initiated, or unanswered
 * @param firstSendLeadTimeMillis delay in milliseconds from startup to the first sent packet, or
 *     {@code -1} if none has been observed
 * @param firstReceiveLeadTimeMillis delay in milliseconds from startup to the first received
 *     packet, or {@code -1} if none has been observed
 * @param gaps detached recent gap history in newest-first order
 */
public record ConnectivityTrafficEntrySnapshot(
    String address,
    long packetsSent,
    long packetsReceived,
    ConnectivityTrafficInitiator initiator,
    long firstSendLeadTimeMillis,
    long firstReceiveLeadTimeMillis,
    List<ConnectivityGapSnapshot> gaps) {
  /**
   * Creates an immutable tracker-row snapshot.
   *
   * <p>The constructor copies the gap list defensively so later tracker updates do not affect an
   * already-created snapshot.
   *
   * @throws NullPointerException if any required component is {@code null}
   */
  public ConnectivityTrafficEntrySnapshot {
    Objects.requireNonNull(address, "address");
    Objects.requireNonNull(initiator, "initiator");
    Objects.requireNonNull(gaps, "gaps");
    gaps = List.copyOf(gaps);
  }
}

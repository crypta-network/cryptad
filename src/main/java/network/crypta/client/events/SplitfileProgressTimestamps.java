package network.crypta.client.events;

import java.util.Date;

/**
 * Captures the latest success and failure timestamps for a splitfile operation snapshot.
 *
 * <p>This record holds the most recent success and failure {@link Date} values associated with a
 * splitfile fetch or insert. It is typically created alongside the splitfile progress counters and
 * passed to the corresponding progress event so consumers can display timing hints without
 * maintaining direct references to mutable timestamps. The record is immutable and therefore safe
 * to share across threads as a read-only snapshot.
 *
 * <p>The canonical constructor defensively copies the incoming {@link Date} instances. Callers may
 * pass {@code null} for either timestamp to indicate that no success or failure has occurred yet. A
 * {@code null} value remains {@code null} in the stored snapshot, while non-null dates are copied
 * to prevent external mutation after construction.
 *
 * <ul>
 *   <li>Represents timestamps only; it does not contain counters or totals.
 *   <li>Uses {@link Date} values in milliseconds since the epoch.
 *   <li>Provides a stable, read-only view of the latest known activity.
 * </ul>
 *
 * @param latestSuccess time of the most recent successful block, or {@code null} if none yet
 * @param latestFailure time of the most recent failure, or {@code null} if none yet
 */
@SuppressWarnings("JavaUtilDate")
public record SplitfileProgressTimestamps(Date latestSuccess, Date latestFailure) {
  /**
   * Creates a snapshot of the latest success and failure timestamps.
   *
   * <p>This constructor copies the supplied {@link Date} instances to preserve immutability. It
   * performs no validation beyond null handling and is idempotent with respect to already-copied
   * values. Passing {@code null} for either argument leaves that component unset in the snapshot,
   * which callers can interpret as “no event yet.”
   *
   * @param latestSuccess time of the most recent successful block, or {@code null} if absent
   * @param latestFailure time of the most recent failure, or {@code null} if absent
   */
  public SplitfileProgressTimestamps {
    latestSuccess = latestSuccess != null ? new Date(latestSuccess.getTime()) : null;
    latestFailure = latestFailure != null ? new Date(latestFailure.getTime()) : null;
  }
}

package network.crypta.client.events;

import java.time.Instant;

/**
 * Captures the latest success and failure timestamps for a splitfile operation snapshot.
 *
 * <p>This record holds the most recent success and failure {@link Instant} values associated with a
 * splitfile fetch or insert. It is typically created alongside the splitfile progress counters and
 * passed to the corresponding progress event so consumers can display timing hints without
 * maintaining direct references to mutable timestamps. The record is immutable and therefore safe
 * to share across threads as a read-only snapshot.
 *
 * <p>The canonical constructor stores the incoming {@link Instant} instances. Callers may pass
 * {@code null} for either timestamp to indicate that no success or failure has occurred yet. A
 * {@code null} value remains {@code null} in the stored snapshot, while non-null dates are copied
 * to prevent external mutation after construction.
 *
 * <ul>
 *   <li>Represents timestamps only; it does not contain counters or totals.
 *   <li>Uses {@link Instant} values in milliseconds since the epoch.
 *   <li>Provides a stable, read-only view of the latest known activity.
 * </ul>
 *
 * @param latestSuccess time of the most recent successful block, or {@code null} if none yet
 * @param latestFailure time of the most recent failure, or {@code null} if none yet
 */
public record SplitfileProgressTimestamps(Instant latestSuccess, Instant latestFailure) {}

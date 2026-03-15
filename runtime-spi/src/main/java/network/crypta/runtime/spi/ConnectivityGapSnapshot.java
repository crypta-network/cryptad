package network.crypta.runtime.spi;

/**
 * Detached snapshot of one recorded connectivity gap.
 *
 * <p>A connectivity gap represents a span with no matching traffic for one tracker entry, followed
 * by the packet that ended that quiet period. The connectivity page uses these values only in
 * advanced mode, where operators compare recent packet history for peers and IP addresses without
 * touching daemon-side tracker objects directly.
 *
 * <p>This record is immutable and uses epoch-based millisecond values, so callers can format times
 * or compute relative durations in their own layer.
 *
 * @param gapLengthMillis duration, in milliseconds, between the derived interval start and the
 *     packet that ended the gap
 * @param receivedPacketAtMillis absolute wall-clock time, in milliseconds since the epoch, when the
 *     packet ending the gap was received
 */
public record ConnectivityGapSnapshot(long gapLengthMillis, long receivedPacketAtMillis) {}

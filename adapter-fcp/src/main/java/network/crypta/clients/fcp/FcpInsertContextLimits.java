package network.crypta.clients.fcp;

/**
 * Bundles the detached insert-context limits that are not already captured by {@link
 * FcpInsertOptions}.
 *
 * <p>This record carries the low-level limits that shape how the adapter-owned insert-context
 * handle maps onto the daemon's mutable insert context. The values are preserved exactly as
 * supplied, so the bridge can round-trip the persistent insert policy without exposing the live
 * runtime type to adapter-owned code.
 *
 * <p>Unlike the mutable knobs grouped under {@link FcpInsertOptions}, these limits are effectively
 * structural defaults captured from the runtime baseline. Keeping them in a dedicated immutable
 * record makes it clear which insert-context values the adapter may treat as read-only while still
 * serializing and replaying them accurately.
 *
 * @param consecutiveRnfsCountAsSuccess number of consecutive RNFs that should count as success
 * @param splitfileSegmentDataBlocks maximum number of data blocks per splitfile segment
 * @param splitfileSegmentCheckBlocks maximum number of check blocks per splitfile segment
 */
public record FcpInsertContextLimits(
    int consecutiveRnfsCountAsSuccess,
    int splitfileSegmentDataBlocks,
    int splitfileSegmentCheckBlocks) {}

package network.crypta.clients.http;

/**
 * Captures block-level progress counters for an FProxy fetch snapshot.
 *
 * <p>The counts describe how many blocks have been discovered, fetched, or failed at the moment the
 * snapshot is created. The {@code finalizedBlocks} flag indicates whether the total block count is
 * final or still subject to discovery.
 *
 * @param totalBlocks total number of blocks known at snapshot time
 * @param requiredBlocks minimum blocks required to finish successfully
 * @param fetchedBlocks blocks fetched successfully at snapshot time
 * @param failedBlocks retryable failures at snapshot time
 * @param fatallyFailedBlocks permanent failures at snapshot time
 * @param finalizedBlocks whether the total block count is final
 */
public record FProxyFetchProgressCounts(
    int totalBlocks,
    int requiredBlocks,
    int fetchedBlocks,
    int failedBlocks,
    int fatallyFailedBlocks,
    boolean finalizedBlocks) {}

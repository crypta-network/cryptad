package network.crypta.store;

/**
 * Options controlling store fetch behavior.
 *
 * <p>This record bundles cache permission flags and metadata collectors used during reads.
 *
 * @param dontPromote when {@code true}, do not promote the entry in any recency structure
 * @param canReadClientCache whether lookups may consult the client cache (e.g., to get SSK keys)
 * @param canReadSlashdotCache whether lookups may consult the slashdot cache for prerequisites
 * @param ignoreOldBlocks when {@code true}, suppress returning blocks flagged as old
 * @param meta optional metadata sink populated during the fetch
 */
public record FetchOptions(
    boolean dontPromote,
    boolean canReadClientCache,
    boolean canReadSlashdotCache,
    boolean ignoreOldBlocks,
    BlockMetadata meta) {}

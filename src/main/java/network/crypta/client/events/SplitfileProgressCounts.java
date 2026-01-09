package network.crypta.client.events;

/**
 * Collects the numeric progress counters for a splitfile operation snapshot.
 *
 * <p>This record carries the integer counters that summarize progress at a single point in time for
 * splitfile fetches and inserts. It is intended to be paired with a timestamp snapshot and passed
 * to the surrounding splitfile progress event as a compact, immutable bundle. The values are
 * read-only and thread-safe after construction because records are immutable and contain only
 * primitives.
 *
 * <p>The counters express totals, successes, and failures as absolute block counts, plus a success
 * threshold that indicates when the overall operation can be considered complete. The {@code
 * finalizedTotal} flag distinguishes provisional totals from final ones, which helps callers avoid
 * presenting misleading percentages while discovery is still in progress.
 *
 * <ul>
 *   <li>Represents a point-in-time snapshot rather than live, mutable counters.
 *   <li>Uses block counts only; no time-based or size-based units are embedded.
 *   <li>Separates total discovery from completion thresholds via {@code minSuccessfulBlocks}.
 * </ul>
 *
 * @param totalBlocks total known blocks in the splitfile at this snapshot, non-negative count
 * @param succeedBlocks blocks completed successfully at this instant, non-negative count
 * @param failedBlocks retryable failures recorded so far, non-negative count
 * @param fatallyFailedBlocks permanent failures that will not retry, non-negative count
 * @param minSuccessfulBlocks minimum success threshold required for completion, non-negative count
 * @param minSuccessFetchBlocks minimum fetchable blocks needed to proceed, non-negative count
 * @param finalizedTotal whether {@code totalBlocks} is final and no longer growing
 */
public record SplitfileProgressCounts(
    int totalBlocks,
    int succeedBlocks,
    int failedBlocks,
    int fatallyFailedBlocks,
    int minSuccessfulBlocks,
    int minSuccessFetchBlocks,
    boolean finalizedTotal) {}

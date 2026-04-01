package network.crypta.client.async;

import network.crypta.node.KeysFetchingLocally;

/**
 * Bundles the segment-specific inputs for {@link SplitFileFetcherSegmentBlockChooser}.
 *
 * <p>This parameter object keeps the chooser constructor focused on the shared cooldown and retry
 * settings while grouping the segment context that determines fetch eligibility.
 *
 * @param segment backing segment storage that provides key material and segment context; must not
 *     be {@code null}.
 * @param keysFetching coordinator tracking keys currently fetched locally to avoid duplicate
 *     fetches.
 * @param ignoreLastBlock zero-based block index to exclude from selection, or {@code -1} to disable
 *     the exclusion and consider all indices.
 */
public record SplitFileFetcherSegmentBlockChooserParams(
    SplitFileFetcherSegmentStorage segment,
    KeysFetchingLocally keysFetching,
    int ignoreLastBlock) {}

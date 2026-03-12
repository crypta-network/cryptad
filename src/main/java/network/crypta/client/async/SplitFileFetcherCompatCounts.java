package network.crypta.client.async;

import network.crypta.client.InsertContext.CompatibilityMode;

/**
 * Groups compatibility mode and block count totals parsed from splitfile settings.
 *
 * <p>This record is a lightweight carrier used when decoding the fixed header of the splitfile
 * fetcher storage footer. The settings codec extracts the compatibility mode, segment count, and
 * aggregated block totals from the persisted header and bundles them into this value object before
 * assembling a {@link ParsedBasicSettings}. The record does not validate ranges or enforce
 * invariants; callers are expected to construct it only after the parser has verified basic
 * constraints, such as non-negative totals and a valid compatibility code.
 *
 * <p>Instances are immutable and safe to share, but the record reflects the raw persisted values
 * rather than recomputed counts. This helps keep resume-time parsing deterministic and avoids
 * expensive recalculation before segment metadata is read.
 *
 * <ul>
 *   <li>Captures the minimum compatibility mode stored in the header.
 *   <li>Records the persisted segment count for later validation.
 *   <li>Aggregates data, check, and cross-check block totals across all segments.
 * </ul>
 *
 * @param finalMinCompatMode compatibility mode value stored in the header; not validated here.
 * @param segmentCount segment count value stored in the header; expected to be positive.
 * @param totalDataBlocks total data block count across segments; non-negative in valid headers.
 * @param totalCheckBlocks total check block count across segments; non-negative in valid headers.
 * @param totalCrossCheckBlocks total cross-check block count across segments; non-negative in valid
 *     headers.
 * @see SplitFileFetcherStorageSettingsCodec
 * @see ParsedBasicSettings
 */
record SplitFileFetcherCompatCounts(
    CompatibilityMode finalMinCompatMode,
    int segmentCount,
    int totalDataBlocks,
    int totalCheckBlocks,
    int totalCrossCheckBlocks) {}

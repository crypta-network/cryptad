package network.crypta.client.async;

/**
 * Groups byte offsets for sections within the splitfile fetcher storage layout.
 *
 * <p>This record captures the offsets that point to each fixed section in the persisted storage
 * footer. It is typically created by the settings codec when parsing the basic settings block and
 * then passed into {@link ParsedBasicSettings}, which exposes the values to resume-time builders.
 * The offsets are expressed in bytes relative to the start of the storage file and are expected to
 * refer to positions within the backing buffer. This record does not validate or normalize the
 * values; it relies on the parser to enforce invariants before construction.
 *
 * <p>Instances are immutable and safe to share. The record represents the persisted layout as-is
 * and does not recompute offsets from other metadata, which keeps parsing deterministic and avoids
 * extra dependencies during recovery.
 *
 * <ul>
 *   <li>Captures offsets for key lists, segment status, and progress tracking sections.
 *   <li>Records bloom filter locations and original metadata/detail boundaries.
 *   <li>Preserves the basic settings offset used to validate layout integrity.
 * </ul>
 *
 * @param offsetKeyList byte offset of the persisted key list section in the storage file.
 * @param offsetSegmentStatus byte offset of the persisted segment status section.
 * @param offsetGeneralProgress byte offset of the general progress section, in bytes.
 * @param offsetMainBloomFilter byte offset of the main bloom filter section, in bytes.
 * @param offsetSegmentBloomFilters byte offset of the segment bloom filters section, in bytes.
 * @param offsetOriginalMetadata byte offset of the original metadata section, in bytes.
 * @param offsetOriginalDetails byte offset of the original details section, in bytes.
 * @param offsetBasicSettings byte offset of the basic settings block, in bytes.
 * @see SplitFileFetcherStorageSettingsCodec
 * @see ParsedBasicSettings
 */
record SplitFileFetcherStorageOffsets(
    long offsetKeyList,
    long offsetSegmentStatus,
    long offsetGeneralProgress,
    long offsetMainBloomFilter,
    long offsetSegmentBloomFilters,
    long offsetOriginalMetadata,
    long offsetOriginalDetails,
    long offsetBasicSettings) {}

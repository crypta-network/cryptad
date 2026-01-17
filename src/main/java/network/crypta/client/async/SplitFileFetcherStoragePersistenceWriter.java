package network.crypta.client.async;

import java.io.IOException;

/**
 * Writes the initial persistent layout for splitfile fetcher storage.
 *
 * <p>This helper centralizes creation-time disk writes and footer serialization so the storage
 * orchestrator can focus on lifecycle and scheduling. It assumes the caller has already assembled
 * segment keys, precomputed metadata, and encoded the settings payload. The implementation performs
 * direct random-access writes and metadata serialization, so it must run before any fetch work that
 * depends on the persistent structure.
 *
 * <p>The class is a pure utility: it holds no state and is intended for one-time initialization of
 * on-disk files. Calls are safe to repeat only when the caller manages file replacement or a clean
 * initialization path. Concurrency control is delegated to the caller and the storage lock, so
 * callers should avoid invoking it from multiple threads without external coordination.
 *
 * <ul>
 *   <li>Writes segment key material and per-segment metadata.
 *   <li>Persists general progress and Bloom filters for later resume.
 *   <li>Serializes the original metadata block and footer layout.
 * </ul>
 */
final class SplitFileFetcherStoragePersistenceWriter {
  /** Prevents instantiation; this type exists only to host static write helpers. */
  private SplitFileFetcherStoragePersistenceWriter() {}

  /**
   * Writes the initial persistent records and metadata for a splitfile fetcher.
   *
   * <p>The method acquires the storage lock and then writes per-segment key material to the RAF. If
   * the storage is persistent, it proceeds to flush segment metadata, general progress, Bloom
   * filters, and the serialized metadata footer. The method assumes the arrays are aligned by
   * segment index and does not perform validation beyond what called helpers enforce.
   *
   * <pre>{@code
   * SplitFileFetcherStoragePersistenceWriter.writeToRaf(
   *     storage, keys, prepared, encodedSettings, progress, totalLength);
   * }</pre>
   *
   * @param storage initialized fetcher storage providing RAF offsets and locking
   * @param segmentKeys segment key array aligned to {@code storage.segments} ordering
   * @param prepared precomputed persistent metadata to write into the footer
   * @param encodedBasicSettings encoded basic settings payload, already checksummed
   * @param generalProgress encoded progress bytes for general fetch state
   * @param totalLength total splitfile length in bytes, used for metadata integrity
   * @throws IOException when random-access writes or serialization to the RAF fail
   */
  static void writeToRaf(
      SplitFileFetcherStorage storage,
      SplitFileSegmentKeys[] segmentKeys,
      SplitFileFetcherStoragePersistence.PreparedMetadata prepared,
      byte[] encodedBasicSettings,
      byte[] generalProgress,
      long totalLength)
      throws IOException {
    try (var _ = storage.autoLockOpen()) {
      for (int i = 0; i < storage.segments.length; i++) {
        SplitFileFetcherSegmentStorage segment = storage.segments[i];
        segment.writeKeysWithChecksum(segmentKeys[i]);
      }
      if (storage.persistent) {
        for (SplitFileFetcherSegmentStorage segment : storage.segments) segment.writeMetadata();
        storage
            .getRAF()
            .pwrite(storage.offsetGeneralProgress, generalProgress, 0, generalProgress.length);
        storage.keyListener.innerWriteMainBloomFilter(storage.offsetMainBloomFilter);
        storage.keyListener.initialWriteSegmentBloomFilters(storage.offsetSegmentBloomFilters);
        SplitFileFetcherStoragePersistence.writePersistentMetadata(
            storage.getRAF(),
            storage.offsetOriginalMetadata,
            prepared,
            encodedBasicSettings,
            storage.checksumChecker,
            totalLength);
      }
    }
  }
}

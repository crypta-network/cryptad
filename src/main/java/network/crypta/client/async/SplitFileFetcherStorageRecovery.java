package network.crypta.client.async;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import network.crypta.client.FailureCodeTracker;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.FetchException;
import network.crypta.crypt.ChecksumFailedException;
import network.crypta.support.io.StorageFormatException;
import org.slf4j.Logger;

/**
 * Coordinates resume-time recovery steps for splitfile fetcher storage.
 *
 * <p>This helper encapsulates the validation and regeneration work needed when reopening a
 * persistent splitfile fetcher. It reads per-segment metadata, rebuilds in-memory progress state,
 * and schedules background work for decoding or Bloom filter regeneration. The class is tightly
 * coupled to {@link SplitFileFetcherStorage} and expects the storage to be initialized with valid
 * offsets and segment arrays before any recovery method is invoked.
 *
 * <p>The methods are not inherently thread-safe; callers should ensure serialized access using the
 * storage's locking discipline. Recovery is designed to be idempotent as long as the underlying
 * persistent data are stable, but the caller is responsible for avoiding concurrent mutation of the
 * same storage.
 *
 * <ul>
 *   <li>Reads and validates persisted progress records.
 *   <li>Queues decode attempts for segments with corrupt metadata.
 *   <li>Rebuilds Bloom filters and key indices when needed.
 * </ul>
 */
final class SplitFileFetcherStorageRecovery {
  /**
   * Backing storage whose metadata and progress state are being recovered.
   *
   * <p>The reference is immutable and shared across recovery steps. Callers must ensure the storage
   * remains valid for the duration of recovery because methods access RAF offsets, segment arrays,
   * and listener hooks without additional null checks.
   */
  private final SplitFileFetcherStorage storage;

  /**
   * Creates a recovery helper for the provided storage instance.
   *
   * <p>The storage is assumed to be initialized but not yet recovered; callers should construct the
   * helper after the storage structure and offsets are ready and before any fetch work resumes. The
   * helper retains the storage reference for all later recovery operations.
   *
   * @param storage initialized storage instance whose state will be recovered
   */
  SplitFileFetcherStorageRecovery(SplitFileFetcherStorage storage) {
    this.storage = storage;
  }

  /**
   * Reads per-segment metadata and enqueues segments that need decode attempts.
   *
   * <p>This method walks every segment, reads its metadata, records decode requirements, then reads
   * all segment keys, and verifies cross-segment blocks. It is intended to run once after opening
   * persistent storage, before any decoding tasks are started. The method may close and free the
   * RAF if a segment is marked failed, propagating a {@link FetchException} in that case.
   *
   * @throws FetchException when the stored metadata indicates a splitfile failure
   * @throws IOException when reading segment metadata or keys fails
   * @throws StorageFormatException when persisted, segment data is corrupt or inconsistent
   */
  void postInitReadSegmentState() throws FetchException, IOException, StorageFormatException {
    for (SplitFileFetcherSegmentStorage segment : storage.segments) {
      boolean needsDecode = determineIfSegmentNeedsDecode(segment);
      if (needsDecode) queueSegmentForDecode(segment);
    }
    readAllSegmentKeys();
    checkCrossSegmentsIfAny();
  }

  /**
   * Reads the persisted general progress block and applies it to the storage state.
   *
   * <p>The method fetches the check-summed progress payload, decodes flags and failure codes, and
   * updates the in-memory state of the storage. If the payload is corrupted or fails checksum
   * validation, the method logs an error and resets the progress fields to safe defaults so the
   * fetcher can proceed without relying on the corrupted state.
   *
   * @throws IOException when the progress block cannot be read from storage
   */
  void readGeneralProgress() throws IOException {
    try {
      byte[] buf = storage.preadChecksummedWithLength(storage.offsetGeneralProgress);
      ByteArrayInputStream bais = new ByteArrayInputStream(buf);
      DataInputStream dis = new DataInputStream(bais);
      long flags = dis.readLong();
      if ((flags & SplitFileFetcherStorage.HAS_CHECKED_DATASTORE_FLAG) != 0)
        storage.hasCheckedDatastore = true;
      storage.errors = new FailureCodeTracker(false, dis);
      dis.close();
    } catch (ChecksumFailedException | StorageFormatException e) {
      SplitFileFetcherStorage.LOG.error("Failed to read general progress: {}", String.valueOf(e));
      // Reset general progress
      storage.hasCheckedDatastore = false;
      storage.errors = new FailureCodeTracker(false);
    }
  }

  /**
   * Queues an asynchronous Bloom filter regeneration job when persistence is enabled.
   *
   * <p>The job rebuilds key indices by scanning segment keys and then writes regenerated Bloom
   * filters to disk. If persistence is disabled, the queue operation is ignored and the method
   * returns {@code false}. This method does not wait for completion and always returns {@code
   * false}, matching the job-runner callback signature used by the caller.
   *
   * @return always {@code false}; the regeneration work is scheduled asynchronously
   */
  boolean regenerateKeysAsync() {
    try {
      storage.jobRunner.queue(
          _ -> {
            regenerateKeysJob();
            return false;
          },
          SplitFileFetcherStorage.REGENERATE_KEYS_PRIORITY);
    } catch (PersistenceDisabledException _) {
      // Ignore.
    }
    return false;
  }

  /**
   * Restarts any cross-segment storage blocks that are present.
   *
   * <p>The method is a no-op when the storage does not include cross-segments. When present, each
   * cross-segment is restarted in sequence to rebuild any transient state needed for recovery.
   */
  void restartCrossSegments() {
    if (storage.crossSegments == null) return;
    for (SplitFileFetcherCrossSegmentStorage segment : storage.crossSegments) {
      segment.restart();
    }
  }

  /**
   * Schedules decode attempts for any segments marked as broken during recovery.
   *
   * <p>The list is captured under the storage lock and then cleared, so each segment is only queued
   * once. The method is safe to call even when no broken segments were recorded.
   */
  void scheduleTryDecodeForBrokenSegments() {
    List<SplitFileFetcherSegmentStorage> brokenSegments;
    synchronized (storage) {
      brokenSegments = storage.segmentsToTryDecode;
      storage.segmentsToTryDecode = null;
    }
    if (brokenSegments == null) return;
    for (SplitFileFetcherSegmentStorage segment : brokenSegments) {
      segment.tryStartDecode();
    }
  }

  /**
   * Determines whether a segment needs to be queued for decoding based on its metadata.
   *
   * <p>The method reads the segment metadata, reports splitfile failure as a {@link
   * FetchException}, and treats checksum errors as corruption that requires a decoding attempt. It
   * also checks the segment's own decode flag after metadata is read. The method does not mutate
   * the decoding queue; callers decide how to record the result.
   *
   * @param segment segment whose metadata should be inspected for decoding requirements
   * @return {@code true} when the segment should be scheduled for decoding attempts
   * @throws FetchException when the segment reports a failed splitfile state
   * @throws IOException when reading segment metadata fails due to I/O errors
   * @throws StorageFormatException when persisted, metadata cannot be parsed
   */
  private boolean determineIfSegmentNeedsDecode(SplitFileFetcherSegmentStorage segment)
      throws FetchException, IOException, StorageFormatException {
    boolean needsDecode = false;
    try {
      segment.readMetadata();
      if (segment.hasFailed()) {
        storage.getRAF().close();
        storage.getRAF().free(); // Failed, so free it.
        throw new FetchException(FetchExceptionMode.SPLITFILE_ERROR, storage.errors);
      }
    } catch (ChecksumFailedException _) {
      SplitFileFetcherStorage.LOG.error(
          "Progress for segment {} on {} corrupted.", segment.segNo, storage);
      needsDecode = true;
    }
    if (segment.needsDecode()) needsDecode = true;
    return needsDecode;
  }

  /**
   * Appends a segment to the decoding queue, initializing the queue if necessary.
   *
   * <p>The queue is stored in {@link SplitFileFetcherStorage#segmentsToTryDecode} and may be null
   * until the first decoding candidate is found. This method performs minimal work and does not
   * synchronize; callers should coordinate access via the storage lock where required.
   *
   * @param segment segment that should be decoded when recovery completes
   */
  private void queueSegmentForDecode(SplitFileFetcherSegmentStorage segment) {
    if (storage.segmentsToTryDecode == null) storage.segmentsToTryDecode = new ArrayList<>();
    storage.segmentsToTryDecode.add(segment);
  }

  /**
   * Reads and validates all segment keys for the storage.
   *
   * <p>The method iterates through each segment and loads its key list. If a checksum error occurs,
   * the method fails fast with a {@link StorageFormatException} so the caller can treat the storage
   * as corrupt and avoid using partial key data.
   *
   * @throws StorageFormatException when any segment keys fail checksum validation
   * @throws IOException when key reads fail due to underlying I/O errors
   */
  private void readAllSegmentKeys() throws StorageFormatException, IOException {
    for (SplitFileFetcherSegmentStorage segment : storage.segments) {
      try {
        segment.readSegmentKeys();
      } catch (ChecksumFailedException _) {
        throw new StorageFormatException("Keys corrupted");
      }
    }
  }

  /**
   * Checks cross-segment blocks after segment metadata has been read.
   *
   * <p>The method is a no-op when the storage has no cross-segment structures. The ordering matters
   * because cross-segment validation depends on metadata from the plain segments.
   */
  private void checkCrossSegmentsIfAny() {
    if (storage.crossSegments == null) return;
    for (SplitFileFetcherCrossSegmentStorage crossSegment : storage.crossSegments)
      // Must be after reading the metadata for the plain segments.
      crossSegment.checkBlocks();
  }

  /**
   * Rebuilds Bloom filters by scanning all segment keys and writing them to storage.
   *
   * <p>The job is executed by the storage job runner and logs its progress. It adds every key to
   * the key listener, writes regenerated Bloom filters, and informs the fetcher that recovery
   * completed after corruption. If key scanning fails, the job terminates early after reporting the
   * disk error.
   */
  private void regenerateKeysJob() {
    Logger log = SplitFileFetcherStorage.LOG;
    // Regenerating filters for this storage
    log.error("Regenerating filters for {}", storage);
    KeySalter salt = storage.fetcher.getSalter();
    if (!addAllKeysFromSegments(salt)) return;
    storage.keyListener.addedAllKeys();
    writeBloomFiltersSafely();
    storage.fetcher.restartedAfterDataCorruption();
    log.warn("Finished regenerating filters for {}", storage);
  }

  /**
   * Adds all segment keys to the key listener, returning {@code false} on failure.
   *
   * <p>Each segment's key list is read and converted to node keys before being forwarded to the key
   * listener. I/O or checksum errors cause the storage to be marked failed and stop further
   * processing so that callers do not rely on a partial key set.
   *
   * @param salt salter used to derive node keys during listener updates
   * @return {@code true} when all segments are processed without I/O or checksum failures
   */
  private boolean addAllKeysFromSegments(KeySalter salt) {
    for (int i = 0; i < storage.segments.length; i++) {
      SplitFileFetcherSegmentStorage segment = storage.segments[i];
      try {
        SplitFileSegmentKeys keys = segment.readSegmentKeys();
        for (int j = 0; j < keys.totalKeys(); j++) {
          storage.keyListener.addKey(keys.getKey(j, null, false).getNodeKey(false), i, salt);
        }
      } catch (IOException | ChecksumFailedException e) {
        if (e instanceof IOException io) {
          storage.failOnDiskError(io);
        } else {
          storage.failOnDiskError((ChecksumFailedException) e);
        }
        return false;
      }
    }
    return true;
  }

  /**
   * Writes regenerated Bloom filters and handles I/O errors for persistent storage.
   *
   * <p>The method writes segment and main Bloom filters. When persistence is enabled, I/O failures
   * are reported to the storage failure handler; otherwise they are ignored because the storage is
   * not durable.
   */
  private void writeBloomFiltersSafely() {
    try {
      storage.keyListener.initialWriteSegmentBloomFilters(storage.offsetSegmentBloomFilters);
      storage.keyListener.innerWriteMainBloomFilter(storage.offsetMainBloomFilter);
    } catch (IOException e) {
      if (storage.persistent) storage.failOnDiskError(e);
    }
  }
}

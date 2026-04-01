package network.crypta.client;

import network.crypta.client.ArchiveManager.ARCHIVE_TYPE;
import network.crypta.keys.FreenetURI;
import network.crypta.support.api.Bucket;
import network.crypta.support.compress.Compressor.COMPRESSOR_TYPE;

/**
 * Bundles the archive source inputs needed to extract a container into the cache.
 *
 * <p>This parameter object captures the archive key, format metadata, raw data bucket, and
 * per-request archive context along with the manager's store context. It performs no validation and
 * stores references as-is; callers should treat the supplied objects as immutable for the duration
 * of extraction.
 */
final class ArchiveExtractionInput {
  final FreenetURI key;
  final ARCHIVE_TYPE archiveType;
  final COMPRESSOR_TYPE compressorType;
  final Bucket data;
  final ArchiveContext archiveContext;
  final ArchiveStoreContext storeContext;

  /**
   * Creates a new extraction input bundle.
   *
   * @param key key of the archive being extracted
   * @param archiveType container format used to enumerate entries
   * @param compressorType optional outer compression type; may be {@code null}
   * @param data bucket holding the raw archive bytes
   * @param archiveContext per-request archive context and limits
   * @param storeContext manager-maintained store context for the archive key
   */
  ArchiveExtractionInput(
      FreenetURI key,
      ARCHIVE_TYPE archiveType,
      COMPRESSOR_TYPE compressorType,
      Bucket data,
      ArchiveContext archiveContext,
      ArchiveStoreContext storeContext) {
    this.key = key;
    this.archiveType = archiveType;
    this.compressorType = compressorType;
    this.data = data;
    this.archiveContext = archiveContext;
    this.storeContext = storeContext;
  }
}

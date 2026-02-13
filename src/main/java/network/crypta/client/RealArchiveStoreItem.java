package network.crypta.client;

import network.crypta.keys.FreenetURI;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.MultiReaderBucket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Concrete cache entry that holds the extracted bytes of a single member from an archive.
 *
 * <p>This implementation wraps the original {@link Bucket} in a {@link MultiReaderBucket} so
 * callers can obtain independent, read-only reader buckets on demand. The underlying data is kept
 * immutable from the perspective of consumers; the instance measures the size at construction time
 * and exposes it via {@link #spaceUsed()} for cache accounting. The lifetime of the stored data is
 * tied to the surrounding cache: {@link #innerClose()} releases resources when the item is evicted
 * by the {@link ArchiveManager}.
 *
 * <p>Typical usage is internal to the archive extraction flow: when an entry is successfully
 * unpacked, an instance is created and registered in the {@link ArchiveStoreContext}. Subsequent
 * requests for that member retrieve a reader via {@link #getReaderBucket()} or the plain read-only
 * view via {@link #dataAsBucket()}, then copy or stream the bytes to the client. Callers must
 * invoke {@link Bucket#free()} on any reader bucket they obtain once the data has been fully
 * consumed.
 *
 * <ul>
 *   <li>Read-only data model; no mutation after construction.
 *   <li>Provides multiple readers over the same stored content.
 *   <li>Tracks precise space usage for eviction decisions.
 * </ul>
 *
 * @see ArchiveStoreItem
 * @see ArchiveStoreContext
 * @see ArchiveManager
 */
final class RealArchiveStoreItem extends ArchiveStoreItem {
  /** Logger for diagnostic messages related to this store item. */
  private static final Logger LOG = LoggerFactory.getLogger(RealArchiveStoreItem.class);

  /**
   * Multiplexer that creates independent, read-only reader buckets backed by a single source
   * bucket. This enables multiple consumers to read the same stored data safely.
   */
  private final MultiReaderBucket mb;

  /**
   * Primary read-only view of the stored data returned by {@link #dataAsBucket()}. The instance is
   * obtained from {@link #mb} and is guaranteed to be non-null for the lifetime of this object.
   */
  private final Bucket bucket;

  /**
   * Cached size of the stored data in bytes. Captured at construction time and used for cache
   * accounting and eviction; does not change afterward.
   */
  private final long spaceUsed;

  // No static initialization required.

  /**
   * Creates a new cache item for an extracted archive member.
   *
   * <p>The provided {@code bucket} is wrapped in a {@link MultiReaderBucket} to permit multiple
   * independent readers. The stored view is set read-only immediately, and the exact size is
   * recorded for later reporting via {@link #spaceUsed()}. The constructor throws {@link
   * NullPointerException} if the supplied bucket or the derived reader bucket is {@code null}.
   *
   * @param ctx context that indexes items for the enclosing {@link FreenetURI}; used for lifecycle
   *     management by the archive cache
   * @param key2 the archive key from which this member originated; used as part of the cache key
   * @param realName archive-relative name of the member represented by this item; must be the
   *     normalized name used by callers when looking it up
   * @param bucket non-null bucket containing the extracted bytes for this member; ownership remains
   *     with the cache and the bucket is set read-only by this constructor
   */
  RealArchiveStoreItem(ArchiveStoreContext ctx, FreenetURI key2, String realName, Bucket bucket) {
    super(new ArchiveKey(key2, realName), ctx);
    if (bucket == null) throw new NullPointerException();
    mb = new MultiReaderBucket(bucket);
    this.bucket = mb.getReaderBucket();
    if (this.bucket == null) throw new NullPointerException();
    this.bucket.setReadOnly();
    spaceUsed = this.bucket.size();
  }

  /**
   * Returns the stored data as a read-only {@link Bucket}.
   *
   * <p>The returned bucket is owned by this cache item and remains valid until either the caller
   * frees it explicitly or the item is evicted and closed. Callers should avoid retaining it longer
   * than necessary; use {@link #getReaderBucket()} when an independent reader is preferred.
   *
   * @return a non-null, read-only {@link Bucket} view of the stored content suitable for direct
   *     reading
   */
  Bucket dataAsBucket() {
    return bucket;
  }

  /**
   * Returns the byte length of the stored data.
   *
   * <p>The value is captured at construction time and does not change. It represents the precise
   * size of the underlying content and may be used by callers for progress reporting or capacity
   * planning.
   *
   * @return exact number of bytes contained in this item’s data
   */
  long dataSize() {
    return bucket.size();
  }

  /**
   * {@inheritDoc}
   *
   * <p>For this implementation the reported value equals the exact data size measured at
   * construction time.
   */
  @Override
  long spaceUsed() {
    return spaceUsed;
  }

  /**
   * {@inheritDoc}
   *
   * <p>This implementation logs the close operation for diagnostics and frees the underlying bucket
   * if present. It tolerates a defensive {@code null} check even though the constructor guarantees
   * non-nullity, to remain robust under historical edge cases.
   */
  @Override
  void innerClose() {
    if (LOG.isDebugEnabled()) LOG.debug("innerClose(): {} : {}", this, bucket);
    if (bucket == null) {
      // This still happens. It is clearly impossible as we check in the constructor and throw if it
      // is null.
      // Nonetheless, there is little we can do here ...
      LOG.error("IMPOSSIBLE: BUCKET IS NULL!");
      return;
    }
    bucket.free();
  }

  /**
   * Returns the stored data, or throws if unavailable.
   *
   * <p>For a successful extraction the data is always available and this method returns the same
   * read-only bucket as {@link #dataAsBucket()}. It does not create a new reader; callers that need
   * an independent handle should use {@link #getReaderBucket()} instead.
   *
   * @return a non-null, read-only {@link Bucket} over the stored content
   */
  @Override
  Bucket getDataOrThrow() {
    return dataAsBucket();
  }

  /**
   * Returns a fresh read-only reader bucket over the stored data.
   *
   * <p>Each call obtains a new reader from the internal {@link MultiReaderBucket}, enabling
   * multiple concurrent reads without sharing state between consumers. Callers must release the
   * returned bucket via {@link Bucket#free()} when finished to avoid resource leaks.
   *
   * @return a new read-only {@link Bucket} suitable for independent consumption by callers
   */
  @Override
  Bucket getReaderBucket() {
    return mb.getReaderBucket();
  }
}

package network.crypta.client;

import java.io.Serial;
import java.io.Serializable;
import network.crypta.client.ArchiveManager.ARCHIVE_TYPE;
import network.crypta.client.async.ClientContext;
import network.crypta.keys.FreenetURI;
import network.crypta.support.api.Bucket;
import network.crypta.support.compress.Compressor.COMPRESSOR_TYPE;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Package-private implementation of {@link ArchiveHandler} that serves content from the {@link
 * ArchiveManager} cache and coordinates extraction of newly fetched archives into an {@link
 * ArchiveStoreContext} owned by the manager.
 *
 * <p>Instances are lightweight wrappers around a single {@link FreenetURI} and keep track of a
 * small piece of state indicating whether the next lookup should skip the cache ({@code
 * forceRefetchArchive}). This class does not perform any network I/O and does not parse container
 * formats by itself; it merely looks up previously extracted items and delegates extraction to
 * {@link ArchiveManager#extractToCache(ArchiveExtractionInput, ArchiveElementRequest)}.
 *
 * <p>Typical usage is:
 *
 * <ul>
 *   <li>Create a handler through {@link ArchiveManager#makeHandler(FreenetURI, ARCHIVE_TYPE,
 *       network.crypta.support.compress.Compressor.COMPRESSOR_TYPE, boolean, boolean)}.
 *   <li>Attempt a cache-only read via {@link #get(String, ArchiveContext, ArchiveManager)}.
 *   <li>After fetching the outer archive data elsewhere, call {@link #extractToCache(Bucket,
 *       ArchiveContext, String, ArchiveExtractCallback, ArchiveManager, ClientContext)} to populate
 *       the cache and optionally stream a specific element to the callback.
 * </ul>
 *
 * <p>Thread-safety: instances carry a mutable flag and are not designed for concurrent mutation
 * without external synchronization. In practice, they are created, used on a single thread, and
 * then discarded. The heavy lifting (caching, extraction, size/hash validation) is handled by
 * {@link ArchiveManager}, which provides its own concurrency guarantees.
 *
 * @see ArchiveHandler
 * @see ArchiveManager
 * @see ArchiveStoreContext
 */
class ArchiveHandlerImpl implements ArchiveHandler, Serializable {
  private static final Logger LOG = LoggerFactory.getLogger(ArchiveHandlerImpl.class);

  @Serial private static final long serialVersionUID = 1L;

  private final FreenetURI key;
  private boolean forceRefetchArchive;

  /**
   * The archive container format to decode (for example, {@link ARCHIVE_TYPE#TAR} or {@link
   * ARCHIVE_TYPE#ZIP}). The value is selected by the creator and used when delegating extraction to
   * the {@link ArchiveManager}.
   */
  ARCHIVE_TYPE archiveType;

  /**
   * Compression applied around the archive stream, such as {@code GZIP}, {@code BZIP2} or LZMA
   * variants as defined by {@link COMPRESSOR_TYPE}. This does not affect the internal container
   * format; it is only the outer transport encoding for the archive bytes.
   */
  COMPRESSOR_TYPE compressorType;

  /**
   * Create a new handler bound to the given key and archive characteristics.
   *
   * @param key The base {@link FreenetURI} identifying the archive or its manifest; the handler
   *     never mutates it and returns the same instance from {@link #getKey()}.
   * @param archiveType The container type (ZIP or TAR) used to enumerate entries during extraction;
   *     determines metadata generation and element naming rules.
   * @param ctype The outer compression applied to the archive bytes as stored or fetched; accepted
   *     values include {@code GZIP}, {@code BZIP2}, and LZMA variants as supported by the system.
   * @param forceRefetchArchive When {@code true}, the next {@link #get(String, ArchiveContext,
   *     ArchiveManager)} call bypasses the cache and returns {@code null}. The flag is cleared by
   *     {@link #extractToCache(Bucket, ArchiveContext, String, ArchiveExtractCallback,
   *     ArchiveManager, ClientContext)} after a successful extraction.
   */
  ArchiveHandlerImpl(
      FreenetURI key,
      ARCHIVE_TYPE archiveType,
      COMPRESSOR_TYPE ctype,
      boolean forceRefetchArchive) {
    this.key = key;
    this.archiveType = archiveType;
    this.compressorType = ctype;
    this.forceRefetchArchive = forceRefetchArchive;
  }

  /**
   * Return a cached element from this archive, if available.
   *
   * <p>This implementation performs a cache-only lookup and never triggers a fetch or on-the-fly
   * extraction. If {@code forceRefetchArchive} is set, the method immediately returns {@code null}.
   * Otherwise, it queries {@link ArchiveManager#getCached(FreenetURI, String)} for the requested
   * name. The returned bucket is non-persistent and must be consumed before it is evicted by the
   * cache.
   *
   * @param internalName The exact archive-internal path of the desired element using {@code /}
   *     separators. Special value {@code ".metadata"} refers to the container metadata entry.
   * @param archiveContext The high-level archive fetch context; present for symmetry and future
   *     uses. This implementation does not consult it when serving from cache.
   * @param manager The archive manager that maintains per-key contexts and the on-disk cache to
   *     query for a previously extracted element.
   * @return The non-persistent {@link Bucket} when a cache hit occurs; otherwise {@code null}. The
   *     caller owns the stream and should close any obtained resources promptly.
   * @throws ArchiveFailureException If the cache cannot be accessed or an I/O error occurs while
   *     materializing the element from storage.
   * @throws ArchiveRestartException If a restart is required by the broader flow; typically not
   *     raised by this cache-only implementation.
   * @throws MetadataParseException If intermediary metadata must be parsed and an error occurs; not
   *     expected for pure cache hits but allowed by the API contract.
   * @throws FetchException If underlying fetch state causes an error to surface through the cache
   *     layer during lookup.
   */
  @Override
  public Bucket get(String internalName, ArchiveContext archiveContext, ArchiveManager manager)
      throws ArchiveFailureException,
          ArchiveRestartException,
          MetadataParseException,
          FetchException {

    if (forceRefetchArchive) return null;

    Bucket data;

    // Fetch from cache
    if (LOG.isDebugEnabled()) LOG.debug("Checking cache: {} {}", key, internalName);
    if ((data = manager.getCached(key, internalName)) != null) {
      return data;
    }

    return null;
  }

  /**
   * {@inheritDoc}
   *
   * <p>This implementation requests the conventional metadata entry by delegating to {@link
   * #get(String, ArchiveContext, ArchiveManager)} with {@code ".metadata"}.
   */
  @Override
  public Bucket getMetadata(ArchiveContext archiveContext, ArchiveManager manager)
      throws ArchiveFailureException,
          ArchiveRestartException,
          MetadataParseException,
          FetchException {
    return get(".metadata", archiveContext, manager);
  }

  /**
   * Unpack a freshly fetched archive into the manager-maintained cache and optionally stream a
   * specific element to a callback.
   *
   * <p>The {@code forceRefetchArchive} flag is cleared before extraction, allowing subsequent cache
   * lookups to proceed. The method constructs an {@link ArchiveStoreContext} for the key via {@link
   * ArchiveManager#makeContext(FreenetURI, ARCHIVE_TYPE,
   * network.crypta.support.compress.Compressor.COMPRESSOR_TYPE, boolean)} and delegates the heavy
   * lifting to {@link ArchiveManager#extractToCache(ArchiveExtractionInput,
   * ArchiveElementRequest)}.
   *
   * @param bucket The raw bytes of the outer archive to unpack; must provide readable content for
   *     the duration of the call.
   * @param actx The archive-level context (limits, hashing, and behavior) used by the manager while
   *     decoding and validating the container.
   * @param element The single element of special interest, or {@code null} when not applicable. The
   *     callback is notified if the element is encountered.
   * @param callback Receiver for the element or for absence notifications; invoked by the manager
   *     during extraction progress.
   * @param manager The archive manager responsible for caching and integrity tracking.
   * @param context Client execution context used for background tasks and stream management.
   * @throws ArchiveFailureException If the archive cannot be decoded or violates size/hash limits.
   * @throws ArchiveRestartException If extraction determines that the archive changed and the
   *     request must be restarted.
   */
  @Override
  public void extractToCache(
      Bucket bucket,
      ArchiveContext actx,
      String element,
      ArchiveExtractCallback callback,
      ArchiveManager manager,
      ClientContext context)
      throws ArchiveFailureException, ArchiveRestartException {
    forceRefetchArchive = false; // now we don't need to force refetch anymore
    ArchiveStoreContext ctx = manager.makeContext(key, archiveType, compressorType, false);
    ArchiveExtractionInput input =
        new ArchiveExtractionInput(key, archiveType, compressorType, bucket, actx, ctx);
    ArchiveElementRequest elementRequest = new ArchiveElementRequest(element, callback, context);
    manager.extractToCache(input, elementRequest);
  }

  /**
   * Return the archive container type that will be used for decoding.
   *
   * @return The container format associated with this handler, as supplied at construction time.
   */
  @Override
  public ARCHIVE_TYPE getArchiveType() {
    return archiveType;
  }

  /**
   * Return the compression scheme surrounding the archive bytes.
   *
   * <p>The compressor type reflects the outer encoding of the archive stream (for example, {@code
   * GZIP}). It does not describe the internal container format; see {@link #getArchiveType()} for
   * that. Callers typically use this together with the archive type when staging an extraction
   * through the manager.
   *
   * @return The selected outer compression ({@link COMPRESSOR_TYPE}) for this handler.
   */
  public COMPRESSOR_TYPE getCompressorType() {
    return compressorType;
  }

  /**
   * Return the immutable {@link FreenetURI} associated with this handler.
   *
   * @return The key instance that identifies the archive or manifest; stable for the lifetime of
   *     the handler.
   */
  @Override
  public FreenetURI getKey() {
    return key;
  }

  /**
   * Create a new handler that references the same key and archive characteristics.
   *
   * <p>The clone captures the current {@code forceRefetchArchive} flag value. Subsequent calls that
   * mutate the flag on either instance do not affect the other one.
   *
   * @return A new {@link ArchiveHandler} instance with identical configuration, suitable for reuse
   *     in independent flows.
   */
  @Override
  public ArchiveHandler cloneHandler() {
    return new ArchiveHandlerImpl(key, archiveType, compressorType, forceRefetchArchive);
  }
}

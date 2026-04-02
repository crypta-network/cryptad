package network.crypta.client;

import network.crypta.client.ArchiveManager.ARCHIVE_TYPE;
import network.crypta.client.async.ClientContext;
import network.crypta.keys.FreenetURI;
import network.crypta.support.api.Bucket;

/**
 * Handles client archive operations such as reading metadata, retrieving entries, and extracting
 * content into a cache.
 *
 * <p>This interface is the public face of the archive subsystem used by fetchers and other client
 * components. Typical call patterns are:
 *
 * <ul>
 *   <li>Call {@link #getMetadata(ArchiveContext, ArchiveManager)} to obtain the container metadata
 *       (manifest) as a non-persistent {@link Bucket}.
 *   <li>Call {@link #get(String, ArchiveContext, ArchiveManager)} to retrieve the content of a
 *       single entry by its internal name, reusing any available cache when possible.
 *   <li>After the raw archive has been fetched, call {@link #extractToCache(Bucket, ArchiveContext,
 *       String, ArchiveExtractCallback, ArchiveManager, ClientContext)} to unpack it and notify a
 *       callback.
 * </ul>
 *
 * <p>Implementations may be stateful (e.g., holding short-lived references to decoded manifests)
 * but are expected to be safe to call from multiple threads if shared by higher-level components.
 * The returned {@code Bucket} instances are always non-persistent; callers should copy data to a
 * persistent store when longer retention is required. Because {@link ArchiveManager} instances are
 * not persistent, a manager is passed into each operation to mediate caching and extraction.
 *
 * @author toad
 */
public interface ArchiveHandler {

  /**
   * Returns the archive metadata (manifest) as a non-persistent {@link Bucket}.
   *
   * <p>The metadata typically contains structural information about the archive entries and may be
   * used to render directory listings or resolve an entry’s existence before attempting content
   * retrieval. The returned bucket is ephemeral; if the data must outlive the current operation,
   * copy it to a persistent destination.
   *
   * @param archiveContext context used to scope and coordinate archive operations; includes
   *     request-specific configuration and must be non-null.
   * @param manager non-persistent archive manager that provides cache and extraction helpers; must
   *     be supplied by the caller for each operation.
   * @return a non-persistent bucket containing the metadata, or {@code null} if unavailable or not
   *     applicable to this archive.
   * @throws ArchiveFailureException if the archive cannot be processed due to a terminal condition
   *     such as corruption or unsupported structure.
   * @throws ArchiveRestartException if the operation should be retried, typically after upstream
   *     state changes or cache refresh.
   * @throws MetadataParseException if intermediary metadata was fetched but failed to parse
   *     correctly.
   * @throws FetchException if an upstream fetch required to obtain metadata fails or is aborted by
   *     the client.
   */
  Bucket getMetadata(ArchiveContext archiveContext, ArchiveManager manager)
      throws ArchiveFailureException,
          ArchiveRestartException,
          MetadataParseException,
          FetchException;

  /**
   * Retrieves a single entry from the archive as a non-persistent {@link Bucket}.
   *
   * <p>Implementations should prefer cached data when available and only fetch or extract the
   * underlying content when necessary. When the requested entry is not present, or cannot be
   * determined to exist, this method returns {@code null}. The returned bucket is ephemeral and
   * should be copied by callers that require persistence.
   *
   * @param internalName the entry’s internal name within the archive; typically a path-like string
   *     relative to the root of the container.
   * @param archiveContext context used to scope and coordinate archive operations for this request;
   *     must be non-null.
   * @param manager non-persistent archive manager mediating cache and extraction behaviors; the
   *     caller provides it.
   * @return a non-persistent bucket containing the entry’s content, or {@code null} if the entry is
   *     not found or not retrievable under current conditions.
   * @throws ArchiveFailureException if the archive or entry cannot be processed due to a terminal
   *     condition (for example, corruption or an unsupported format).
   * @throws ArchiveRestartException if the operation should be retried later, typically after cache
   *     changes or additional data becomes available.
   * @throws MetadataParseException if intermediary metadata used to locate the entry could not be
   *     parsed successfully.
   * @throws FetchException if an upstream fetch required to obtain the entry or metadata fails.
   */
  Bucket get(String internalName, ArchiveContext archiveContext, ArchiveManager manager)
      throws ArchiveFailureException,
          ArchiveRestartException,
          MetadataParseException,
          FetchException;

  /**
   * Returns the archive type handled by this instance.
   *
   * @return the concrete archive type (for example, TAR or ZIP) used by the handler.
   */
  ARCHIVE_TYPE getArchiveType();

  /**
   * Returns the key that identifies the root archive for this handler.
   *
   * @return the non-null key associated with the archive represented by this handler.
   */
  FreenetURI getKey();

  /**
   * Extracts a fetched archive into the cache and notifies an optional callback.
   *
   * <p>The supplied {@code bucket} contains the raw downloaded archive data. Implementations unpack
   * its contents into a cache coordinated by the provided {@link ArchiveManager} and then notify
   * the {@code callback} about availability. The {@code element} parameter may indicate a specific
   * entry of interest so implementations can prioritize extraction.
   *
   * @param bucket non-persistent bucket holding the raw archive bytes to be extracted; must be
   *     readable for the duration of the operation.
   * @param actx archive context carrying per-request configuration and state needed during
   *     extraction; must be non-null.
   * @param element an optional internal name for a specific entry to prioritize; may be {@code
   *     null} to indicate no single preferred entry.
   * @param callback callback to receive notifications about availability and to consume extracted
   *     data when ready; may be {@code null} if the caller does not require notifications.
   * @param manager non-persistent archive manager mediating cache writes and bookkeeping; supplied
   *     by the caller.
   * @param context client execution context used to schedule or coordinate work with the broader
   *     client subsystem; must be non-null.
   * @throws ArchiveFailureException if extraction fails due to terminal conditions such as
   *     corruption or unsupported structures.
   * @throws ArchiveRestartException if the extraction should be retried, for example due to
   *     upstream state changes or interrupted inputs.
   */
  void extractToCache(
      Bucket bucket,
      ArchiveContext actx,
      String element,
      ArchiveExtractCallback callback,
      ArchiveManager manager,
      ClientContext context)
      throws ArchiveFailureException, ArchiveRestartException;

  /**
   * Creates a new handler instance with equivalent configuration and key.
   *
   * <p>The returned handler can be used independently of the original, which is useful when client
   * components wish to perform operations concurrently without sharing transient state. The clone
   * does not copy caches held by {@link ArchiveManager}; callers should pass their own manager per
   * operation.
   *
   * @return a new handler instance functionally equivalent to this one.
   */
  ArchiveHandler cloneHandler();
}

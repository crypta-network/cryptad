package network.crypta.clients.fcp;

import network.crypta.client.async.CacheFetchResult;
import network.crypta.client.async.persistence.PersistentRequestRuntimeContext;
import network.crypta.keys.FreenetURI;
import network.crypta.support.api.Bucket;

/**
 * Adapter-owned cache seam for FCP-local completed-request lookups.
 *
 * <p>This interface represents the narrow cache behavior that the FCP adapter still needs after the
 * server/runtime detachment work. Implementations answer only from already-completed local FCP
 * requests; they do not schedule new fetches, consult wider node caches, or expose the full
 * runtime-owned {@code DownloadCache} contract. The bridge layer is responsible for adapting this
 * seam back to runtime-facing callers that still expect the older cache interface.
 *
 * <p>Typical callers are server-owned helper paths such as persistent-request replay and
 * get-completed-request lookups. Those call sites need immediate access to previously downloaded
 * data, but they should not depend directly on runtime-owned cache abstractions or on a live {@code
 * ClientContext}. The interface therefore stays intentionally small and keeps the copy, filtering,
 * and detached-runtime-context decisions explicit at the call site.
 *
 * <ul>
 *   <li>Never starts network work or waits for an in-flight request to finish.
 *   <li>Exposes only the lookup variants currently required by FCP server infrastructure.
 *   <li>Keeps runtime-specific cache adaptation in {@code :bridge-fcp-runtime}.
 * </ul>
 */
public interface FcpDownloadCache {

  /**
   * Performs a non-blocking cache lookup without scheduling additional work.
   *
   * <p>Use this variant when the caller already knows that no runtime context is needed for the
   * lookup. Implementations must limit themselves to data that is already available locally and
   * should return quickly even on a miss. When {@code mustCopy} is {@code false}, the returned
   * bucket may share underlying storage with the cached request and should therefore be treated as
   * short-lived and effectively read-only by callers.
   *
   * @param key exact Freenet key used to identify the cached payload
   * @param noFilter whether the caller requires raw bytes instead of filtered content
   * @param mustCopy whether the result must be copied into dedicated caller-owned storage
   * @param preferred optional destination bucket to reuse when copying is required
   * @return cached result when a matching completed request exists, or {@code null} on a miss
   */
  CacheFetchResult lookupInstant(
      FreenetURI key, boolean noFilter, boolean mustCopy, Bucket preferred);

  /**
   * Performs a cache lookup using the supplied detached runtime context when needed.
   *
   * <p>This overload exists for server-owned call paths that still carry a detached persistent
   * runtime context while remaining independent of live runtime-owned infrastructure types. The
   * current FCP implementations may ignore the context for purely local lookups, but callers should
   * still pass the appropriate detached token so future implementations can use it without widening
   * the adapter boundary again. As with {@link #lookupInstant(FreenetURI, boolean, boolean,
   * Bucket)}, the lookup is local-only and must not trigger new network activity.
   *
   * @param key exact Freenet key used to identify the cached payload
   * @param noFilter whether the caller requires raw bytes instead of filtered content
   * @param context detached runtime context associated with the surrounding persistent operation
   * @param mustCopy whether the result must be copied into dedicated caller-owned storage
   * @param preferred optional destination bucket to reuse when copying is required
   * @return cached result when a matching completed request exists, or {@code null} on a miss
   */
  CacheFetchResult lookup(
      FreenetURI key,
      boolean noFilter,
      PersistentRequestRuntimeContext context,
      boolean mustCopy,
      Bucket preferred);
}

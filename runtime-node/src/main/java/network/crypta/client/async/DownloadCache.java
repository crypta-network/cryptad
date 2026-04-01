package network.crypta.client.async;

import network.crypta.keys.FreenetURI;
import network.crypta.support.api.Bucket;

/**
 * Lookup facility for returning recently downloaded content from a local cache.
 *
 * <p>Implementations consult locally available, already-completed downloads (for example, in-memory
 * or on-disk request caches) and return the data immediately when a hit is found. The interface is
 * intentionally narrow and non-blocking with respect to network activity: methods never initiate a
 * new fetch and simply return {@code null} when the requested key is not present. This makes the
 * cache suitable for fast-path checks in user interfaces and HTTP serving paths where a small
 * memory/disk lookup is preferred over scheduling work.
 *
 * <p>Callers control two important behaviors: whether unfiltered/raw data is required, and whether
 * the result must be copied into a caller-supplied or newly allocated {@link Bucket}. When copying
 * is not required, implementations may return a view that shares the underlying storage; such views
 * should be treated as read-only and short‑lived. When copying is requested, an implementation may
 * write into a provided {@code preferred} bucket when size and type allow, otherwise it allocates a
 * new one.
 *
 * <p>Thread-safety: unless stated otherwise by a concrete implementation, instances are safe to use
 * from multiple threads concurrently. Returned buckets follow their own concurrency and lifecycle
 * rules; consult {@link Bucket} for details.
 *
 * <ul>
 *   <li>Non-blocking: never triggers network fetches; returns {@code null} on a miss.
 *   <li>Filtering-aware: can require raw bytes or accept pre-filtered content.
 *   <li>Copy policy: may return a shared view unless an explicit copy is requested.
 * </ul>
 *
 * @see ClientContext
 * @see CacheFetchResult
 * @see Bucket
 */
public interface DownloadCache {

  /**
   * Attempts to return a cached payload for the given key without performing any slow work.
   *
   * <p>This method is intended for fast-path checks that must not block on I/O beyond a local cache
   * lookup. When a cache hit exists, the result may either share underlying storage (when {@code
   * mustCopy} is {@code false}) or be copied into the supplied {@code preferred} bucket (or a newly
   * allocated one). The {@code noFilter} flag indicates whether only raw/unfiltered bytes are
   * acceptable, or whether pre-filtered content from the cache is an acceptable substitute.
   *
   * <pre>{@code
   * CacheFetchResult hit = cache.lookupInstant(uri, false, false, null);
   * if (hit != null) {
   *   // Serve directly from the cached bucket
   * }
   * }</pre>
   *
   * @param key the exact {@link FreenetURI} that identifies the desired object; must not be {@code
   *     null}; the lookup does not normalize or rewrite the key.
   * @param noFilter {@code true} to require raw/unfiltered content bytes; {@code false} to accept a
   *     cache entry whose bytes were already filtered by higher-level logic.
   * @param mustCopy {@code true} to force copying the payload into a dedicated bucket; {@code
   *     false} to allow a shared, read-only view that may reference underlying cached storage.
   * @param preferred optional destination bucket to use when copying is required; may be {@code
   *     null}; implementations may ignore it if size or type are unsuitable.
   * @return a {@link CacheFetchResult} describing the hit, or {@code null} when no suitable entry
   *     exists; when {@code mustCopy} is {@code false}, the returned bucket may share storage and
   *     should be treated as read-only and short‑lived.
   */
  CacheFetchResult lookupInstant(
      FreenetURI key, boolean noFilter, boolean mustCopy, Bucket preferred);

  /**
   * Looks up a cached payload for the given key, using the provided context where relevant.
   *
   * <p>Semantics mirror {@link #lookupInstant(FreenetURI, boolean, boolean, Bucket)} but allow an
   * implementation to consult caches that are associated with, or require services from, the
   * supplied {@link ClientContext}. The method still does not initiate network activity; it returns
   * {@code null} if the key is not present locally. Copying and filtering behavior are controlled
   * via {@code mustCopy} and {@code noFilter} respectively, and a caller-supplied bucket may be
   * used as the copy target when appropriate.
   *
   * <pre>{@code
   * CacheFetchResult hit = cache.lookup(uri, true, context, true, dest);
   * if (hit != null) {
   *   // 'dest' now contains a stable copy of the payload
   * }
   * }</pre>
   *
   * @param key the {@link FreenetURI} to resolve from a local cache; must not be {@code null} and
   *     is matched exactly.
   * @param noFilter {@code true} to require raw, unfiltered bytes; {@code false} to accept
   *     previously filtered content from the cache.
   * @param context runtime services and configuration that an implementation may consult while
   *     performing the lookup; never used to start new network fetches.
   * @param mustCopy {@code true} to copy the data into a dedicated bucket; {@code false} to allow a
   *     shared, read-only view when safe.
   * @param preferred optional destination bucket to receive a copy when copying; may be {@code
   *     null}; ignored when not copying.
   * @return a {@link CacheFetchResult} when a suitable cache entry exists; otherwise {@code null};
   *     when copying is disabled, the returned bucket may share storage and should be treated as a
   *     short‑lived, read-only view.
   */
  CacheFetchResult lookup(
      FreenetURI key, boolean noFilter, ClientContext context, boolean mustCopy, Bucket preferred);
}

package network.crypta.client.async;

import network.crypta.keys.USK;

/**
 * Callback interface used by the asynchronous USK fetch machinery.
 *
 * <p>This interface is notified by a fetcher created for a specific Updateable Subspace Key (USK)
 * request when progress reaches a terminal state for that one-off fetch operation. Typical usage is
 * to obtain a fetcher from a manager, register an instance of this callback, and then react to one
 * of the lifecycle events defined here. Unlike long-lived USK subscriptions that continue to
 * receive updates, a {@code USKFetcherCallback} is expected to be invoked at most once per fetch
 * attempt and then considered complete by the caller.
 *
 * <p>Implementations should be lightweight and non-blocking. Callbacks are generally invoked from
 * the client framework’s worker threads; heavy work should be dispatched elsewhere to avoid
 * starving the scheduler. Implementations must also tolerate re-entrancy and cancellation, because
 * fetches may be abandoned due to shut down or superseded by newer attempts when higher editions
 * are discovered.
 *
 * <ul>
 *   <li>Failure: no suitable edition found at or above a given hint.
 *   <li>Cancelled: fetch aborted before a definitive result could be produced.
 *   <li>Found: the latest known-good edition has been retrieved for this fetch.
 * </ul>
 */
public interface USKFetcherCallback extends USKCallback {

  /**
   * Reports that the fetch failed to locate any valid edition.
   *
   * <p>This outcome indicates that no edition at or above the requested hint could be retrieved or
   * validated during this attempt. Implementations may record the failure, adjust scheduling
   * policies, or trigger retries using separate logic. This method is terminal for the associated
   * fetch operation and will not be followed by {@code onFoundEdition} for the same attempt.
   *
   * @param context the client execution context supplying shared services and state; never {@code
   *     null} when the callback is invoked
   */
  void onFailure(ClientContext context);

  /**
   * Signals that the fetch was cancelled before it completed.
   *
   * <p>Cancellation can be explicit (requested by the caller) or implicit (triggered by shutdown,
   * superseding operations, or time budgeting). No guarantees are made about partial progress: the
   * implementation should treat this as a non-result and clean up any resources associated solely
   * with this attempt. This method is terminal for the attempt and is not followed by other
   * terminal callbacks.
   *
   * @param context the client execution context associated with the attempt; provided to enable any
   *     necessary cleanup or logging within the broader client subsystem
   */
  void onCancelled(ClientContext context);

  /**
   * Reports that the latest applicable edition for the requested USK has been found.
   *
   * <p>This is terminal for a {@code USKFetcherCallback} (a single-shot fetch) but not for a
   * long-lived {@code USKCallback} subscription. The provided data represents the content for the
   * resolved edition along with metadata flags describing the payload. Implementations typically
   * persist or forward the result, update any local caches, and record the "known good" status for
   * subsequent resolution and validation decisions.
   *
   * <pre>{@code
   * // Example: record the resolved edition then hand off for processing
   * callback.onFoundEdition(edition, usk, ctx, false, codec, bytes, true, false);
   * }</pre>
   *
   * @param l the resolved edition number for the USK; non-negative and monotonically increasing
   *     across successful updates for the same key within the network
   * @param key the USK identifying the namespace and site; the reference is owned by the caller and
   *     should not be mutated by the callback implementation
   * @param context the client execution context that initiated the fetch; provides access to
   *     environment services useful for post-processing and logging
   * @param metadata whether the {@code data} buffer represents metadata rather than primary
   *     content; consumers should branch appropriately when this flag is {@code true}
   * @param codec a short identifier for the data’s encoding or transport codec; value ranges and
   *     semantics are defined by the surrounding client protocol version
   * @param data the raw bytes of the fetched object or its metadata; the array may be reused by the
   *     caller and should not be retained or modified by the callee without copying
   * @param newKnownGood whether this edition advanced the known-good marker for the key within the
   *     local client; {@code true} implies subsequent fetches may use this as a baseline
   * @param newSlotToo whether a new slot was also discovered alongside the edition; used by the
   *     caller to convey additional progress that might influence scheduling heuristics
   */
  @Override
  void onFoundEdition(
      long l,
      USK key,
      ClientContext context,
      boolean metadata,
      short codec,
      byte[] data,
      boolean newKnownGood,
      boolean newSlotToo);
}

package network.crypta.client.async;

import network.crypta.keys.USK;

/**
 * Callback interface notified about updates to a USK subscription.
 *
 * <p>This interface is implemented by components that wish to be informed when a USK subscription
 * discovers a newer edition or finishes determining the latest available edition. It is used by the
 * asynchronous client layer: callers typically subscribe through a manager component which
 * maintains background fetchers, and receive callbacks on internal worker threads whenever the
 * observed state changes. The same implementation may be shared across multiple subscriptions.
 *
 * <p>Typical usage is to subscribe, react to {@link #onFoundEdition(long, USK, ClientContext,
 * boolean, short, byte[], boolean, boolean)} events, and decide whether to request further work or
 * update downstream state. Implementations should keep callbacks short and avoid blocking: heavy
 * processing should be dispatched to application executors to prevent head-of-line blocking of
 * internal polling. Callers can influence background polling by returning priority values from the
 * {@link #getPollingPriorityNormal()} and {@link #getPollingPriorityProgress()} methods.
 *
 * <ul>
 *   <li>State model: callbacks may be invoked repeatedly as the latest known edition advances.
 *   <li>Threading: callbacks are invoked by internal threads; implementations must be thread-safe
 *       if they share mutable state.
 *   <li>Error handling: this interface communicates successful discoveries; failures are managed by
 *       the subscription machinery and not reported here.
 * </ul>
 */
public interface USKCallback {

  /**
   * Called when the latest known edition has been found or advanced.
   *
   * <p>This method is invoked by the subscription/fetcher once it has located what it currently
   * believes to be the newest available edition for the subscribed key. It may be invoked multiple
   * times over the life of a subscription as newer editions become visible. The {@code metadata}
   * flag indicates whether the provided bytes represent metadata-only information or complete
   * content for the edition. The {@code codec} value identifies an implementation-specific content
   * codec associated with the returned bytes.
   *
   * <p>The {@code newKnownGood} and {@code newSlotToo} flags provide additional progress signals:
   * the first indicates that the highest edition known to fetch successfully has increased; the
   * second indicates that the highest examined SSK slot has advanced as well.
   *
   * @param l The discovered logical edition number. Higher values represent newer editions.
   * @param key A copy of the key with the discovered edition set for this notification.
   * @param context Execution context with client-layer services and schedulers for follow-up work.
   * @param metadata True when the bytes correspond to metadata for the edition rather than content.
   * @param codec Short identifier of the content codec associated with the returned byte payload.
   * @param data Raw byte payload for the discovered edition or its metadata, as provided by
   *     fetcher.
   * @param newKnownGood True when the highest known-good, successfully fetched edition has
   *     advanced.
   * @param newSlotToo True when the highest known SSK slot has also advanced alongside known-good.
   */
  void onFoundEdition(
      long l,
      USK key,
      ClientContext context,
      boolean metadata,
      short codec,
      byte[] data,
      boolean newKnownGood,
      boolean newSlotToo);

  /**
   * Returns the steady-state priority used for background polling.
   *
   * <p>This value controls the scheduler priority applied when the subscription is idle or not
   * making immediate progress. It should reflect the desired background importance relative to
   * other client activity. Use a value consistent with the request scheduler’s documented
   * constants.
   *
   * @return A scheduler priority constant used for steady-state USK polling operations.
   */
  short getPollingPriorityNormal();

  /**
   * Returns the priority to use when starting or immediately after progress is made.
   *
   * <p>This value is typically higher (i.e., more urgent) than the normal background level and is
   * applied to reduce end-to-end latency around events such as first subscription or discovery of a
   * new edition. Implementations may return the same value as the normal priority when no boost is
   * desired.
   *
   * @return A scheduler priority constant used to boost polling during startup or after progress.
   */
  short getPollingPriorityProgress();
}

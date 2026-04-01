package network.crypta.client.async;

import network.crypta.client.FetchResult;
import network.crypta.keys.USK;
import network.crypta.node.RequestStarter;

/**
 * Callback contract for clients that consume results from a USK retriever.
 *
 * <p>Implementations receive notifications when the retriever discovers and downloads a newer
 * edition for a given {@link USK}. This interface is intentionally small and synchronous so it can
 * be implemented by UI controllers, logging/reporting components, or higher-level coordinators.
 * Typical usage is to register an instance with a retriever or subscription manager, update the
 * application state on {@link #onFound(USK, long, FetchResult)}, and influence background polling
 * aggressiveness by returning priorities through {@link #getPollingPriorityNormal()} and {@link
 * #getPollingPriorityProgress()}.
 *
 * <p>Concurrency and ordering: callbacks may be invoked on internal worker threads. Implementations
 * should be thread-safe if shared and must avoid blocking operations; heavy work should be
 * dispatched to application executors. Notifications can repeat over time as newer editions become
 * available. The interface does not guarantee delivery for every intermediate edition if multiple
 * updates occur quickly.
 *
 * <ul>
 *   <li>Keep implementations fast and idempotent to avoid head-of-line blocking.
 *   <li>Persist only data the application actually needs; payloads may be large.
 *   <li>Use {@link RequestStarter} constants when returning polling priorities.
 * </ul>
 *
 * @see USKCallback
 * @see RequestStarter
 */
public interface USKRetrieverCallback {

  /**
   * Notifies that a new USK edition has been found and its content retrieved.
   *
   * <p>The retriever supplies the original key used to subscribe, the discovered logical edition
   * number, and the corresponding fetch result. Implementations commonly persist the payload,
   * update a cache, or trigger downstream processing. This method should return quickly; lengthy
   * work should be scheduled elsewhere to keep polling responsive. The same method may be invoked
   * multiple times over the lifetime of a subscription as newer editions are published.
   *
   * @param origUSK The original key for the subscription or request; never {@code null}. It may be
   *     reused across callbacks and identifies the logical update stream rather than a specific
   *     edition.
   * @param edition The discovered edition number associated with this callback. Higher values
   *     represent newer content; callers must handle out-of-order delivery when processing quickly
   *     advancing streams.
   * @param data The retrieved content wrapper for the edition, including any metadata provided by
   *     the client layer. Callers should treat the contained buffers as owned by the callee after
   *     this method returns.
   */
  void onFound(USK origUSK, long edition, FetchResult data);

  /**
   * Returns the scheduler priority used for steady-state background polling.
   *
   * <p>This value applies when no immediate progress is expected. It should reflect the desired
   * background importance relative to other client activity and be one of the documented constants
   * in {@link RequestStarter}. Returning a lower urgency may reduce bandwidth usage at the cost of
   * update latency.
   *
   * @return A {@link RequestStarter} priority constant representing normal background polling
   *     urgency; callers must not return arbitrary values outside the supported constant set.
   */
  short getPollingPriorityNormal();

  /**
   * Returns the scheduler priority to use at startup or immediately after progress.
   *
   * <p>This value is typically higher than the normal background level and is applied to reduce
   * end-to-end latency around initial subscription and recent discoveries. It must match a constant
   * from {@link RequestStarter}. Implementations may return the same value as normal when no boost
   * is desired.
   *
   * @return A {@link RequestStarter} priority constant indicating boosted urgency during startup or
   *     right after progress; must correspond to a supported scheduler priority level.
   */
  short getPollingPriorityProgress();
}

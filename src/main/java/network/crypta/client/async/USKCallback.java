package network.crypta.client.async;

import network.crypta.keys.USK;

/**
 * Callback interface for USK-related subscriptions and fetch operations.
 *
 * <p>Implementations receive notifications when a new or latest edition of a USK has been found and
 * can influence how background polling proceeds by reporting preferred polling priorities. Typical
 * usage is to implement this interface and pass the instance to the {@code USKManager}-based
 * subscription APIs or to the {@code USKFetcher} when initiating a direct fetch. The {@link
 * #onFoundEdition(long, network.crypta.keys.USK, ClientContext, boolean, short, byte[], boolean,
 * boolean)} method is invoked once the fetcher completes its search, at which point it will not
 * look for later editions during that cycle.
 *
 * <p>Callbacks may be invoked on threads managed by the client layer or its executors. Implementers
 * should therefore avoid blocking for long periods and treat the provided arguments as read-only.
 * State updates that affect subsequent polling can be performed in the callback, but heavy work is
 * best delegated to application executors. No assumptions should be made about reentrancy beyond
 * what the calling code guarantees.
 *
 * <ul>
 *   <li>Edition discovery notifications with contextual data.
 *   <li>Control over normal and "progress" polling priorities.
 *   <li>Neutral about persistence; subscription owners decide durability.
 * </ul>
 *
 * @see network.crypta.client.async.USKManager
 * @see network.crypta.client.async.USKFetcher
 */
public interface USKCallback {

  /**
   * Reports that the latest edition has been found for the specified USK.
   *
   * <p>Called when the fetcher completes its search cycle and will not look for later editions in
   * that pass. Implementers can persist the result, update application state, and choose future
   * polling priorities via the other methods of this interface. The supplied context exposes
   * schedulers and supporting services should further work need to be scheduled.
   *
   * @param l the discovered edition number for the key; higher values represent newer editions
   * @param key a key instance with the discovered edition applied; treated as read-only by callees
   * @param context operational client context used for scheduling and services; never {@code null}
   * @param metadata {@code true} when the accompanying bytes represent metadata rather than
   *     content; exact meaning is defined by the caller
   * @param codec opaque short identifying how to interpret {@code data}; semantics depend on caller
   * @param data raw byte content or metadata bytes associated with this edition; treat as read-only
   * @param newKnownGood whether the highest known good edition (successfully fetched and verified)
   *     has increased; otherwise only the highest known slot has advanced for future searches
   * @param newSlotToo when {@code newKnownGood} is {@code true}, indicates it is also a new highest
   *     known slot; when {@code newKnownGood} is {@code false}, the highest known slot is always
   *     considered new
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
   * Returns the polling priority used during normal, steady-state monitoring.
   *
   * <p>The value should correspond to a valid priority class constant used by the client request
   * system (for example, the constants defined in {@link network.crypta.node.RequestStarter}). Call
   * sites may map this to an appropriate scheduler or queue.
   *
   * @return a priority class value to use for regular polling cycles
   */
  short getPollingPriorityNormal();

  /**
   * Returns the polling priority to apply when starting or right after progress is observed.
   *
   * <p>This value is typically more aggressive than the normal priority to accelerate discovery
   * after activity is detected. Use a valid priority class value (e.g., from {@link
   * network.crypta.node.RequestStarter}).
   *
   * @return a priority class value for initial or post-progress polling phases
   */
  short getPollingPriorityProgress();
}

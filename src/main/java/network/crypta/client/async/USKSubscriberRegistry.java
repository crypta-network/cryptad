package network.crypta.client.async;

import java.util.HashMap;
import java.util.HashSet;
import network.crypta.keys.USK;

/**
 * Tracks USK subscribers, edition hints, and polling priority preferences.
 *
 * <p>The registry maintains a set of {@link USKCallback} subscribers and their associated edition
 * hints. It updates the {@link USKKeyWatchSet} with subscriber hints, recalculates polling
 * priorities through {@link USKPriorityPolicy}, and exposes snapshot views of registered
 * subscribers. Callers generally use it when adding or removing subscribers from a {@link
 * USKFetcher} so that the polling attempts remain aligned with the most recent subscriber state.
 *
 * <p>The registry is mutable and synchronizes around the subscriber state. It does not synchronize
 * accesses to the {@link USKKeyWatchSet} or {@link USKManager}; those collaborators are expected to
 * be thread-safe or externally synchronized. Hint updates and priority changes are applied in a
 * predictable sequence: update the registry, refresh priorities, and then update watching keys with
 * the latest hint snapshot.
 *
 * <ul>
 *   <li>Stores subscriber hints used to bias edition probing.
 *   <li>Maintains polling priority preferences for normal and progress modes.
 *   <li>Provides snapshot arrays for use by scheduling and notification paths.
 * </ul>
 */
final class USKSubscriberRegistry {
  /** Live subscriber set used for callback updates and snapshots. */
  private final HashSet<USKCallback> subscribers = new HashSet<>();

  /** Edition hint values supplied by subscribers, keyed by callback. */
  private final HashMap<USKCallback, Long> subscriberHints = new HashMap<>();

  /** Watched the key set that consumes subscriber hints. */
  private final USKKeyWatchSet watchingKeys;

  /** USK manager used to look up the latest known slot. */
  private final USKManager uskManager;

  /** Priority policy that aggregates polling preferences. */
  private final USKPriorityPolicy priorityPolicy;

  /** Base USK used for lookup and hint interpretation. */
  private final USK origUSK;

  /**
   * Creates a subscriber registry bound to a specific USK fetcher.
   *
   * <p>The registry holds the dependencies needed to update watch keys and compute polling
   * priorities. It assumes the {@code attempts} manager and {@code uskManager} remain valid for the
   * lifetime of the owning fetcher.
   *
   * @param watchingKeys watch set updated with subscriber hints; must be non-null
   * @param uskManager manager used to query latest slot values; must be non-null
   * @param attempts attempt manager used by the priority policy; must be non-null
   * @param origUSK base USK that anchors hint and lookup calculations; must be non-null
   */
  USKSubscriberRegistry(
      USKKeyWatchSet watchingKeys, USKManager uskManager, USKAttemptManager attempts, USK origUSK) {
    this.watchingKeys = watchingKeys;
    this.uskManager = uskManager;
    this.priorityPolicy = new USKPriorityPolicy(attempts);
    this.origUSK = origUSK;
  }

  /**
   * Adds a subscriber and updates polling priorities and watch hints.
   *
   * <p>The subscriber and its hint are stored, then the priority policy is refreshed using the
   * provided fetcher callbacks. Finally, the updated hint set is pushed to the watch set so that
   * future polling attempts can incorporate the new hint values.
   *
   * @param cb subscriber callback to register; must be non-null
   * @param hint edition hint provided by the subscriber
   * @param fetcherCallbacks fetcher callbacks that influence polling priorities; must not be null
   * @param fetcherName human-readable fetcher identifier used for debug logging
   */
  void addSubscriber(
      USKCallback cb, long hint, USKFetcherCallback[] fetcherCallbacks, String fetcherName) {
    Long[] hints;
    synchronized (this) {
      subscribers.add(cb);
      subscriberHints.put(cb, hint);
      hints = subscriberHints.values().toArray(new Long[0]);
    }
    updatePriorities(fetcherCallbacks, fetcherName);
    watchingKeys.updateSubscriberHints(hints, uskManager.lookupLatestSlot(origUSK));
  }

  /**
   * Removes a subscriber and updates polling priorities and watch hints.
   *
   * <p>The subscriber and its hint are removed, priorities are refreshed using the provided fetcher
   * callbacks, and the remaining hint set is propagated to the watch set. The method is safe to
   * call even if the subscriber was not registered.
   *
   * @param cb subscriber callback to remove; must be non-null
   * @param fetcherCallbacks fetcher callbacks that influence polling priorities; must not be null
   * @param fetcherName human-readable fetcher identifier used for debug logging
   */
  void removeSubscriber(USKCallback cb, USKFetcherCallback[] fetcherCallbacks, String fetcherName) {
    Long[] hints;
    synchronized (this) {
      subscribers.remove(cb);
      subscriberHints.remove(cb);
      hints = subscriberHints.values().toArray(new Long[0]);
    }
    updatePriorities(fetcherCallbacks, fetcherName);
    watchingKeys.updateSubscriberHints(hints, uskManager.lookupLatestSlot(origUSK));
  }

  /**
   * Removes a subscriber without updating polling priorities.
   *
   * <p>This is used when the caller is already managing priority changes elsewhere. The method
   * still updates the watch set with the remaining hint values.
   *
   * @param cb subscriber callback to remove; must be non-null
   */
  void removeCallback(USKCallback cb) {
    Long[] hints;
    synchronized (this) {
      subscribers.remove(cb);
      subscriberHints.remove(cb);
      hints = subscriberHints.values().toArray(new Long[0]);
    }
    watchingKeys.updateSubscriberHints(hints, uskManager.lookupLatestSlot(origUSK));
  }

  /**
   * Returns whether any subscribers are registered.
   *
   * @return {@code true} if at least one subscriber is present
   */
  boolean hasSubscribers() {
    synchronized (this) {
      return !subscribers.isEmpty();
    }
  }

  /**
   * Returns whether any fetcher callbacks are present.
   *
   * @param fetcherCallbacks fetcher callbacks to evaluate; must not be null
   * @return {@code true} when the array contains at least one callback
   */
  boolean hasCallbacks(USKFetcherCallback[] fetcherCallbacks) {
    return fetcherCallbacks.length != 0;
  }

  /**
   * Refreshes priorities and returns the current progress polling priority.
   *
   * <p>The method recalculates polling priorities using the provided fetcher callbacks and then
   * returns the progress priority, allowing callers to use the updated value immediately.
   *
   * @param fetcherCallbacks fetcher callbacks that influence polling priorities; must not be null
   * @param fetcherName human-readable fetcher identifier used for debug logging
   * @return the updated progress polling priority class
   */
  short refreshAndGetProgressPollPriority(
      USKFetcherCallback[] fetcherCallbacks, String fetcherName) {
    updatePriorities(fetcherCallbacks, fetcherName);
    return progressPriority();
  }

  /**
   * Returns the current progress polling priority class.
   *
   * @return progress polling priority derived from subscriber preferences
   */
  short progressPriority() {
    return priorityPolicy.progressPriority();
  }

  /**
   * Returns the current normal polling priority class.
   *
   * @return normal polling priority derived from subscriber preferences
   */
  short normalPriority() {
    return priorityPolicy.normalPriority();
  }

  /**
   * Returns a snapshot of registered subscribers.
   *
   * @return an array snapshot of subscribers; may be empty but never null
   */
  USKCallback[] snapshotSubscribers() {
    synchronized (this) {
      return subscribers.toArray(new USKCallback[0]);
    }
  }

  /**
   * Updates polling priorities using the current subscriber snapshot.
   *
   * @param fetcherCallbacks fetcher callbacks that influence polling priorities; must not be null
   * @param fetcherName human-readable fetcher identifier used for debug logging
   */
  void updatePriorities(USKFetcherCallback[] fetcherCallbacks, String fetcherName) {
    USKCallback[] localCallbacks;
    synchronized (this) {
      localCallbacks = subscribers.toArray(new USKCallback[0]);
    }
    priorityPolicy.updatePriorities(localCallbacks, fetcherCallbacks, fetcherName);
  }
}

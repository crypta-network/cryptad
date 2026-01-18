package network.crypta.client.async;

import java.util.HashMap;
import java.util.HashSet;
import network.crypta.keys.USK;

/** Tracks subscribers, hint editions, and polling priorities for a USK fetcher. */
final class USKSubscriberRegistry {
  private final HashSet<USKCallback> subscribers = new HashSet<>();
  private final HashMap<USKCallback, Long> subscriberHints = new HashMap<>();
  private final USKKeyWatchSet watchingKeys;
  private final USKManager uskManager;
  private final USKPriorityPolicy priorityPolicy;
  private final USK origUSK;

  USKSubscriberRegistry(
      USKKeyWatchSet watchingKeys, USKManager uskManager, USKAttemptManager attempts, USK origUSK) {
    this.watchingKeys = watchingKeys;
    this.uskManager = uskManager;
    this.priorityPolicy = new USKPriorityPolicy(attempts);
    this.origUSK = origUSK;
  }

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

  void removeCallback(USKCallback cb) {
    Long[] hints;
    synchronized (this) {
      subscribers.remove(cb);
      subscriberHints.remove(cb);
      hints = subscriberHints.values().toArray(new Long[0]);
    }
    watchingKeys.updateSubscriberHints(hints, uskManager.lookupLatestSlot(origUSK));
  }

  boolean hasSubscribers() {
    synchronized (this) {
      return !subscribers.isEmpty();
    }
  }

  boolean hasCallbacks(USKFetcherCallback[] fetcherCallbacks) {
    return fetcherCallbacks.length != 0;
  }

  short refreshAndGetProgressPollPriority(
      USKFetcherCallback[] fetcherCallbacks, String fetcherName) {
    updatePriorities(fetcherCallbacks, fetcherName);
    return progressPriority();
  }

  short progressPriority() {
    return priorityPolicy.progressPriority();
  }

  short normalPriority() {
    return priorityPolicy.normalPriority();
  }

  USKCallback[] snapshotSubscribers() {
    synchronized (this) {
      return subscribers.toArray(new USKCallback[0]);
    }
  }

  void updatePriorities(USKFetcherCallback[] fetcherCallbacks, String fetcherName) {
    USKCallback[] localCallbacks;
    synchronized (this) {
      localCallbacks = subscribers.toArray(new USKCallback[0]);
    }
    priorityPolicy.updatePriorities(localCallbacks, fetcherCallbacks, fetcherName);
  }
}

package network.crypta.platform.api.content.subscriptions;

import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import network.crypta.platform.apphost.manifest.AppManifest;

/**
 * In-memory content subscription store for tests and embedded routers.
 *
 * <p>The implementation keeps the same app/id scoping as the file-backed store without touching the
 * filesystem. All methods are synchronized so API requests and a background scheduler see a
 * coherent snapshot. It is useful for router tests, release smoke checks, and embedded runtimes
 * that need subscription behavior without durable state.
 *
 * <p>The store deliberately mirrors the path-safety rules of {@link FileContentSubscriptionStore}:
 * app ids are normalized, subscription ids are validated as safe path segments, and source URIs are
 * stored only inside {@link ContentSubscription} records. It does not simulate corrupt files or
 * partial writes, so tests for recovery behavior should use the file-backed implementation.
 */
public final class InMemoryContentSubscriptionStore implements ContentSubscriptionStore {
  private final Map<String, Map<String, ContentSubscription>> subscriptions = new LinkedHashMap<>();

  /**
   * Creates an empty in-memory subscription store.
   *
   * <p>The store starts with no app partitions and no durable records. All state is process-local
   * and is discarded when the instance is dropped.
   */
  public InMemoryContentSubscriptionStore() {
    // State is initialized by the field initializer; no external resources need setup.
  }

  @Override
  public synchronized List<ContentSubscription> listForApp(String appId) {
    String normalizedAppId = AppManifest.normalizeAppId(appId);
    Map<String, ContentSubscription> appSubscriptions = subscriptions.get(normalizedAppId);
    if (appSubscriptions == null) {
      return List.of();
    }
    return appSubscriptions.values().stream()
        .sorted(Comparator.comparing(ContentSubscription::subscriptionId))
        .toList();
  }

  @Override
  public synchronized List<ContentSubscription> listAll() {
    return subscriptions.values().stream()
        .flatMap(appSubscriptions -> appSubscriptions.values().stream())
        .sorted(
            Comparator.comparing(ContentSubscription::appId)
                .thenComparing(ContentSubscription::subscriptionId))
        .toList();
  }

  @Override
  public synchronized Optional<ContentSubscription> read(String appId, String subscriptionId) {
    String normalizedAppId = AppManifest.normalizeAppId(appId);
    String normalizedSubscriptionId = ContentSubscription.requireSubscriptionId(subscriptionId);
    Map<String, ContentSubscription> appSubscriptions = subscriptions.get(normalizedAppId);
    return appSubscriptions == null
        ? Optional.empty()
        : Optional.ofNullable(appSubscriptions.get(normalizedSubscriptionId));
  }

  @Override
  public synchronized void write(ContentSubscription subscription) {
    subscriptions
        .computeIfAbsent(subscription.appId(), _ -> new LinkedHashMap<>())
        .put(subscription.subscriptionId(), subscription);
  }

  @Override
  public synchronized boolean delete(String appId, String subscriptionId) {
    String normalizedAppId = AppManifest.normalizeAppId(appId);
    String normalizedSubscriptionId = ContentSubscription.requireSubscriptionId(subscriptionId);
    Map<String, ContentSubscription> appSubscriptions = subscriptions.get(normalizedAppId);
    if (appSubscriptions == null) {
      return false;
    }
    boolean removed = appSubscriptions.remove(normalizedSubscriptionId) != null;
    if (appSubscriptions.isEmpty()) {
      subscriptions.remove(normalizedAppId);
    }
    return removed;
  }

  @Override
  public synchronized void deleteAllForApp(String appId) {
    subscriptions.remove(AppManifest.normalizeAppId(appId));
  }
}

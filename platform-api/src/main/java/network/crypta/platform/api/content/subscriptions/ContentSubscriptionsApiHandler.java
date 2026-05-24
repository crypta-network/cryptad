package network.crypta.platform.api.content.subscriptions;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Thin Platform API handler for app-owned content subscription routes.
 *
 * <p>The router supplies the already-authenticated app principal id. This handler never accepts an
 * app id from query parameters, which keeps list/read/mutate/delete operations scoped to the
 * calling app. It also keeps route handling separate from subscription policy, persistence, and
 * fetch behavior, all of which live in {@link ContentSubscriptionService}.
 *
 * <p>Each method returns a deterministic envelope map so the router can serialize a stable JSON
 * shape. The handler does not catch service exceptions or rewrite error bodies; service and router
 * layers already convert validation, authorization, and store failures into platform API errors
 * without exposing raw content, tokens, paths, or daemon exception text.
 */
public final class ContentSubscriptionsApiHandler {
  private static final String ENVELOPE_SUBSCRIPTION = "subscription";
  private static final String ENVELOPE_SUBSCRIPTIONS = "subscriptions";

  private final ContentSubscriptionService service;

  /**
   * Creates a handler around the shared content subscription service.
   *
   * <p>The service should be the app-platform-scoped instance wired by the runtime. If subscription
   * support is unavailable, the router should reject the route before constructing this handler.
   *
   * @param service shared content subscription service used for all route operations
   * @throws NullPointerException if the service is {@code null}
   */
  public ContentSubscriptionsApiHandler(ContentSubscriptionService service) {
    this.service = Objects.requireNonNull(service, "service");
  }

  /**
   * Lists subscriptions for the calling app.
   *
   * <p>The response envelope contains a {@code subscriptions} array with safe summaries only. The
   * app id comes from the authenticated principal and is never supplied by the app request body.
   *
   * @param appId app principal id supplied by the router
   * @return response envelope containing the app's subscription summaries
   */
  public Map<String, Object> list(String appId) {
    return envelope(ENVELOPE_SUBSCRIPTIONS, service.list(appId));
  }

  /**
   * Creates one subscription for the calling app.
   *
   * <p>The service validates that the request describes a bounded USK subscription and enforces
   * local limits before storing metadata. This handler only wraps the resulting summary under the
   * stable {@code subscription} key.
   *
   * @param appId app principal id supplied by the router
   * @param parameters decoded form parameters from the request body
   * @return response envelope containing the created subscription summary
   */
  public Map<String, Object> create(String appId, Map<String, List<String>> parameters) {
    return envelope(ENVELOPE_SUBSCRIPTION, service.create(appId, parameters));
  }

  /**
   * Reads one subscription for the calling app.
   *
   * <p>Subscriptions owned by other apps are not visible through this route because the service
   * scopes the read by both app id and subscription id.
   *
   * @param appId app principal id supplied by the router
   * @param subscriptionId subscription id path segment from the route
   * @return response envelope containing the subscription summary
   */
  public Map<String, Object> get(String appId, String subscriptionId) {
    return envelope(ENVELOPE_SUBSCRIPTION, service.get(appId, subscriptionId));
  }

  /**
   * Refreshes one subscription for the calling app.
   *
   * <p>Manual refresh uses the same service path as scheduler polling and returns the resulting
   * safe metadata summary, whether the fetch succeeds, dedupes as unchanged, or records a bounded
   * failure.
   *
   * @param appId app principal id supplied by the router
   * @param subscriptionId subscription id path segment from the route
   * @return response envelope containing the refreshed subscription summary
   */
  public Map<String, Object> refresh(String appId, String subscriptionId) {
    return envelope(ENVELOPE_SUBSCRIPTION, service.refresh(appId, subscriptionId));
  }

  /**
   * Pauses one subscription for the calling app.
   *
   * <p>Pausing is persisted by the service and prevents later scheduler ticks from polling the
   * record until the app resumes it.
   *
   * @param appId app principal id supplied by the router
   * @param subscriptionId subscription id path segment from the route
   * @return response envelope containing the paused subscription summary
   */
  public Map<String, Object> pause(String appId, String subscriptionId) {
    return envelope(ENVELOPE_SUBSCRIPTION, service.pause(appId, subscriptionId));
  }

  /**
   * Resumes one subscription for the calling app.
   *
   * <p>Resuming marks the subscription enabled and immediately due according to the service clock.
   * The scheduler may still defer the next fetch because of configured limits or pressure signals.
   *
   * @param appId app principal id supplied by the router
   * @param subscriptionId subscription id path segment from the route
   * @return response envelope containing the resumed subscription summary
   */
  public Map<String, Object> resume(String appId, String subscriptionId) {
    return envelope(ENVELOPE_SUBSCRIPTION, service.resume(appId, subscriptionId));
  }

  /**
   * Deletes one subscription for the calling app.
   *
   * <p>Deletion removes the durable record and returns a final safe summary in the same envelope
   * shape used by the other single-subscription operations.
   *
   * @param appId app principal id supplied by the router
   * @param subscriptionId subscription id path segment from the route
   * @return response envelope containing the deleted subscription summary
   */
  public Map<String, Object> delete(String appId, String subscriptionId) {
    return envelope(ENVELOPE_SUBSCRIPTION, service.delete(appId, subscriptionId));
  }

  private static Map<String, Object> envelope(String key, Object value) {
    LinkedHashMap<String, Object> envelope = LinkedHashMap.newLinkedHashMap(1);
    envelope.put(key, value);
    return envelope;
  }
}

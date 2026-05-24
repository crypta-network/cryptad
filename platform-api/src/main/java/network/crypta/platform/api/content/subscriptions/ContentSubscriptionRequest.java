package network.crypta.platform.api.content.subscriptions;

/**
 * Parsed request for creating one content subscription.
 *
 * <p>The API handler builds this record after it has read form parameters and applied scheduler
 * configuration bounds. It carries only normalized creation input: the short label that the owning
 * app wants to see in summaries, the public USK source accepted for background polling, and the
 * bounded policy that will be copied onto the durable subscription. The record does not represent a
 * stored subscription and contains no generated id, timestamps, fetch result metadata, raw content,
 * or app-host paths.
 *
 * <p>Constructing the request validates the same app-visible fields that will later be stored. That
 * keeps bad labels or missing components from reaching the service layer and makes request parsing
 * tests independent of the file-backed store.
 *
 * @param label short app-facing display label for the new subscription
 * @param source normalized app-owned USK source metadata accepted for polling
 * @param policy bounded scheduler and detached-fetch policy for the subscription
 */
public record ContentSubscriptionRequest(
    String label, ContentSubscriptionSource source, ContentSubscriptionPolicy policy) {
  /**
   * Creates a validated request.
   *
   * <p>The label is trimmed and checked for the same single-line length bound used by durable
   * records. Source and policy values must already have been parsed by their dedicated factories so
   * this constructor only enforces their presence.
   *
   * @throws NullPointerException if the source or policy component is {@code null}
   * @throws network.crypta.platform.api.PlatformApiException if the label is blank or unsafe
   */
  public ContentSubscriptionRequest {
    label = ContentSubscription.requireLabel(label);
    java.util.Objects.requireNonNull(source, "source");
    java.util.Objects.requireNonNull(policy, "policy");
  }
}

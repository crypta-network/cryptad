package network.crypta.platform.api.content.subscriptions;

import java.util.Map;

/**
 * App-facing subscription summary wrapper.
 *
 * <p>The wrapper exists so API handlers can clearly distinguish safe subscription metadata from the
 * durable record that also includes runtime-only fields such as the normalized fetch URI. It is a
 * small type boundary around the map returned to apps, not a separate persistence model. Callers
 * can pass the values directly into the platform JSON response builders without exposing store
 * paths, raw fetched bytes, private insert material, queue HTML, tokens, or daemon exception text.
 *
 * <p>The map is copied into insertion order on construction. That keeps responses deterministic for
 * tests and release evidence even when a caller builds the input from another map implementation.
 *
 * @param values deterministic JSON-compatible summary values safe for the owning app
 */
public record ContentSubscriptionSummary(Map<String, Object> values) {
  /**
   * Creates a detached immutable summary.
   *
   * <p>The input map is copied immediately so later modifications by the caller cannot change an
   * API response that has already been assembled. Values are not deep-copied because subscription
   * summaries contain only strings, numbers, booleans, and {@code null}.
   *
   * @throws NullPointerException if the supplied map is {@code null}
   */
  public ContentSubscriptionSummary {
    values = java.util.Collections.unmodifiableMap(new java.util.LinkedHashMap<>(values));
  }

  /**
   * Creates a safe summary from durable metadata.
   *
   * <p>This is the preferred conversion path for API handlers. The durable record owns the exact
   * summary shape and field ordering, while this wrapper documents that the resulting object is
   * already safe to serialize for the app that owns the subscription.
   *
   * @param subscription subscription metadata to summarize for its owning app
   * @return detached safe summary with deterministic field ordering
   */
  public static ContentSubscriptionSummary from(ContentSubscription subscription) {
    return new ContentSubscriptionSummary(subscription.toSummary());
  }
}

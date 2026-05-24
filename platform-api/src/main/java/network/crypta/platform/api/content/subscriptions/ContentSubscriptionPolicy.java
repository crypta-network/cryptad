package network.crypta.platform.api.content.subscriptions;

import java.time.Duration;
import java.util.Objects;

/**
 * Bounded fetch policy attached to one content subscription.
 *
 * <p>The policy is intentionally narrow: it controls how often the scheduler may poll, how much
 * content a single detached fetch may materialize, and how long that fetch may wait. Values stored
 * here have already been clamped by {@link ContentSubscriptionSchedulerConfig}, so scheduler code
 * can apply them without reinterpreting API request parameters. A policy belongs to one durable
 * subscription and should be treated as immutable after creation.
 *
 * <p>This is not a general crawler policy, queue priority override, or persistent app data store.
 * The scheduler may still delay a due poll because of app capability changes, queue pressure, a
 * prior failure backoff, startup jitter, or per-tick fetch limits.
 *
 * @param pollInterval positive interval between successful scheduler polls
 * @param maxBytes positive maximum bytes a single poll may materialize
 * @param timeout positive maximum wait for one detached fetch attempt
 */
public record ContentSubscriptionPolicy(Duration pollInterval, long maxBytes, Duration timeout) {
  /**
   * Creates a validated bounded policy.
   *
   * <p>The constructor checks only the invariant that every limit is positive. API parsing and
   * scheduler configuration decide the minimum and maximum acceptable ranges before the record is
   * created. Keeping the record validation small makes it safe to reconstruct policies from durable
   * files while still rejecting nonsensical persisted values.
   *
   * @throws NullPointerException if either duration is {@code null}
   * @throws IllegalArgumentException if any configured limit is zero or negative
   */
  public ContentSubscriptionPolicy {
    Objects.requireNonNull(pollInterval, "pollInterval");
    Objects.requireNonNull(timeout, "timeout");
    if (pollInterval.isZero() || pollInterval.isNegative()) {
      throw new IllegalArgumentException("pollInterval must be positive");
    }
    if (maxBytes <= 0L) {
      throw new IllegalArgumentException("maxBytes must be positive");
    }
    if (timeout.isZero() || timeout.isNegative()) {
      throw new IllegalArgumentException("timeout must be positive");
    }
  }

  /**
   * Returns the poll interval as whole seconds.
   *
   * <p>Platform API summaries expose seconds because subscription intervals are intentionally
   * coarse. Sub-second durations should not be produced by API parsing, but this method still uses
   * {@link Duration#toSeconds()} so JSON serialization remains stable if a test constructs a
   * smaller duration directly.
   *
   * @return positive poll interval expressed as whole seconds
   */
  public long pollIntervalSeconds() {
    return pollInterval.toSeconds();
  }

  /**
   * Returns the timeout as whole milliseconds.
   *
   * <p>Detached fetch calls consume a {@link Duration}, while app-facing summaries expose timeout
   * values in milliseconds to match the foreground content fetch API. The returned value is derived
   * directly from the stored timeout and does not apply any additional clamping.
   *
   * @return positive timeout expressed as whole milliseconds
   */
  public long timeoutMillis() {
    return timeout.toMillis();
  }
}

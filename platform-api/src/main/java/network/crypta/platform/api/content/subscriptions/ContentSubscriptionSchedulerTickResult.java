package network.crypta.platform.api.content.subscriptions;

import java.time.Instant;
import java.util.Objects;

/**
 * Deterministic result from one content subscription scheduler pass.
 *
 * <p>The scheduler returns this record from both foreground test ticks and background executor
 * passes. It summarizes scheduler work without exposing subscription sources, fetched content,
 * queue internals, store paths, or raw exception messages. Tests use it to verify deterministic
 * behavior such as per-tick limits, disabled scheduler handling, and no-overlap protection.
 *
 * <p>Counters are aggregate values for the pass. A skipped subscription may be paused, not due,
 * delayed by pressure handling, missing required app capabilities, or beyond the configured
 * per-tick fetch limit. Individual subscription records carry their own safe status and backoff
 * metadata.
 *
 * @param ranAt time supplied to the deterministic scheduler tick
 * @param status aggregate scheduler status for the completed pass
 * @param pollsAttempted number of due subscriptions that started detached fetches
 * @param pollFailures number of attempted polls that recorded fetch failures
 * @param skippedSubscriptions number of subscriptions skipped because not due, paused, limited, or
 *     pressure-gated
 * @param nextRunAt earliest known next due time across visible subscriptions
 * @param message safe path-free summary of the scheduler pass
 */
public record ContentSubscriptionSchedulerTickResult(
    Instant ranAt,
    ContentSubscriptionStatus status,
    int pollsAttempted,
    int pollFailures,
    int skippedSubscriptions,
    Instant nextRunAt,
    String message) {
  /**
   * Creates a validated tick result.
   *
   * <p>The constructor enforces non-negative counters and trims empty messages to {@code null}.
   * Message text should be suitable for release evidence and app-facing diagnostics; it must not
   * contain raw content, absolute paths, queue HTML, request bodies, or daemon exception text.
   *
   * @throws NullPointerException if the tick time or aggregate status is {@code null}
   * @throws IllegalArgumentException if any scheduler counter is negative
   */
  public ContentSubscriptionSchedulerTickResult {
    Objects.requireNonNull(ranAt, "ranAt");
    Objects.requireNonNull(status, "status");
    if (pollsAttempted < 0 || pollFailures < 0 || skippedSubscriptions < 0) {
      throw new IllegalArgumentException("scheduler counters must be >= 0");
    }
    message = message == null || message.isBlank() ? null : message.trim();
  }

  static ContentSubscriptionSchedulerTickResult disabled(Instant now) {
    return new ContentSubscriptionSchedulerTickResult(
        now,
        ContentSubscriptionStatus.DISABLED,
        0,
        0,
        0,
        null,
        "Content subscription scheduler is disabled.");
  }

  static ContentSubscriptionSchedulerTickResult alreadyRunning(Instant now) {
    return new ContentSubscriptionSchedulerTickResult(
        now,
        ContentSubscriptionStatus.RUNNING,
        0,
        0,
        0,
        null,
        "Previous content subscription scheduler pass is still running.");
  }
}

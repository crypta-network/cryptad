package network.crypta.platform.api.networkbudget;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

/**
 * Durable fixed-window counter for one app-network budget key.
 *
 * <p>Usage records contain safe counters and decision metadata only. The app id and operation are
 * normalized path-safe labels, while all request-specific material stays outside the store.
 *
 * <p>The counter is immutable. Budget evaluation reads a record, rolls it into the current window
 * when needed, and creates a new record for the allowed or denied decision. Allowed decisions
 * increment {@code count}; denied decisions update only decision metadata so an already exhausted
 * counter does not continue consuming quota.
 *
 * @param appId normalized app id or reserved internal budget scope id
 * @param operation budget operation represented by this counter
 * @param windowStart inclusive fixed-window start time for this counter
 * @param window positive fixed-window duration used for this budget family
 * @param count number of consumed allowed decisions inside the window
 * @param lastDecisionAt time of the last recorded decision, or {@code null} before first use
 * @param lastDecision safe decision label, or {@code null} when no accepted label is present
 * @param nextAvailableAt optional retry time for the most recent rate denial
 */
public record AppNetworkBudgetUsage(
    String appId,
    AppNetworkBudgetOperation operation,
    Instant windowStart,
    Duration window,
    int count,
    Instant lastDecisionAt,
    String lastDecision,
    Instant nextAvailableAt) {
  /**
   * Creates a validated fixed-window usage record.
   *
   * <p>The constructor normalizes the app id or reserved scope and discards unknown decision labels
   * instead of persisting arbitrary text. That keeps file-backed records stable and prevents raw
   * daemon errors, source strings, or request bodies from becoming durable budget metadata.
   */
  public AppNetworkBudgetUsage {
    appId = AppNetworkBudgetScope.normalize(appId);
    Objects.requireNonNull(operation, "operation");
    Objects.requireNonNull(windowStart, "windowStart");
    Objects.requireNonNull(window, "window");
    if (window.isZero() || window.isNegative()) {
      throw new IllegalArgumentException("window must be positive");
    }
    if (count < 0) {
      throw new IllegalArgumentException("count must be non-negative");
    }
    lastDecision = optionalDecision(lastDecision);
  }

  static AppNetworkBudgetUsage empty(
      String appId, AppNetworkBudgetOperation operation, Instant windowStart, Duration window) {
    return new AppNetworkBudgetUsage(appId, operation, windowStart, window, 0, null, null, null);
  }

  AppNetworkBudgetUsage inWindow(Instant newWindowStart, Duration newWindow) {
    if (windowStart.equals(newWindowStart) && window.equals(newWindow)) {
      return this;
    }
    return empty(appId, operation, newWindowStart, newWindow);
  }

  AppNetworkBudgetUsage allowedAt(Instant now) {
    return new AppNetworkBudgetUsage(
        appId, operation, windowStart, window, count + 1, now, "allowed", null);
  }

  AppNetworkBudgetUsage deniedAt(Instant now, String decision, Instant nextAvailableAt) {
    return new AppNetworkBudgetUsage(
        appId, operation, windowStart, window, count, now, decision, nextAvailableAt);
  }

  private static String optionalDecision(String value) {
    if (value == null || value.isBlank()) {
      return null;
    }
    return switch (value.trim()) {
      case "allowed", "rate_limited", "concurrency_limited", "store_unavailable" -> value.trim();
      default -> null;
    };
  }
}

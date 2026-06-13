package network.crypta.platform.api.networkbudget;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Safe budget snapshot suitable for tests, diagnostics, and future operator status views.
 *
 * <p>The snapshot includes only app id, operation, window metadata, counts, limits, and stable
 * decision labels. It intentionally has no place for raw request text or fetched content.
 *
 * <p>Snapshots are read models derived from durable usage records. They are safe to serialize into
 * release-certification evidence or an operator-only status route because they do not expose
 * content keys, source strings, queue output, exception text, tokens, raw signatures, or local
 * paths. The values describe one normalized budget key for one fixed window; they are not a
 * complete history.
 *
 * @param appId normalized app id or reserved internal budget scope id
 * @param operation budget operation represented by this counter
 * @param windowStart fixed-window start time for the represented counter
 * @param windowSeconds fixed-window size in seconds for this budget family
 * @param count consumed allowed decisions in the represented window
 * @param limit configured rate limit for the represented key
 * @param lastDecisionAt time of the last recorded decision, or {@code null} when none exists
 * @param lastDecision safe last-decision label such as {@code allowed} or {@code rate_limited}
 * @param nextAvailableAt optional retry time for rate-limited counters
 */
public record AppNetworkBudgetSnapshot(
    String appId,
    AppNetworkBudgetOperation operation,
    Instant windowStart,
    long windowSeconds,
    int count,
    int limit,
    Instant lastDecisionAt,
    String lastDecision,
    Instant nextAvailableAt) {
  /**
   * Creates a validated safe snapshot.
   *
   * <p>The constructor checks structural invariants only. It does not re-read the budget
   * configuration or store because snapshots are detached reporting values. A snapshot with a
   * {@code null} last decision time is valid when no decision has been recorded for the key.
   */
  public AppNetworkBudgetSnapshot {
    Objects.requireNonNull(appId, "appId");
    Objects.requireNonNull(operation, "operation");
    Objects.requireNonNull(windowStart, "windowStart");
    if (windowSeconds <= 0L || count < 0 || limit <= 0) {
      throw new IllegalArgumentException(
          "snapshot limits must be positive and counts non-negative");
    }
  }

  /**
   * Returns a deterministic JSON-compatible representation.
   *
   * <p>The map insertion order is stable so certification fixtures and operator diagnostics can
   * compare output without sorting object fields. Timestamps are rendered as ISO-8601 strings, and
   * optional values remain explicit {@code null} values rather than being omitted.
   *
   * @return safe ordered snapshot values ready for JSON serialization
   */
  public Map<String, Object> toJson() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(9);
    json.put("appId", appId);
    json.put("operation", operation.jsonValue());
    json.put("windowStart", windowStart.toString());
    json.put("windowSeconds", windowSeconds);
    json.put("count", count);
    json.put("limit", limit);
    json.put("lastDecisionAt", lastDecisionAt == null ? null : lastDecisionAt.toString());
    json.put("lastDecision", lastDecision);
    json.put("nextAvailableAt", nextAvailableAt == null ? null : nextAvailableAt.toString());
    return json;
  }
}

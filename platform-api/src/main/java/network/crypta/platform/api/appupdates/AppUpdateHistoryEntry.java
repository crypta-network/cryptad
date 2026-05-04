package network.crypta.platform.api.appupdates;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * One bounded app update lifecycle event safe for Platform API display.
 *
 * <p>The update service records these entries for check, stage, apply, and rollback actions. They
 * are intentionally compact because they are kept in process memory and returned in update
 * summaries. Each entry uses stable action, status, and error-code strings so operators can
 * reconstruct what happened without reading server logs, while avoiding request bodies, catalog
 * scratch paths, staged bundle paths, app tokens, browser-session tokens, and private URI material.
 *
 * <p>History entries are not a durable audit log. They provide recent lifecycle context for the Web
 * Shell and Platform API clients, and the service bounds the number retained per app.
 *
 * @param timestamp time when the lifecycle event was recorded
 * @param action stable action label such as {@code check}, {@code stage}, {@code apply}, or {@code
 *     rollback}
 * @param status stable result label, typically {@code success} or {@code failed}
 * @param catalogId catalog id involved in the event, or {@code null} when not relevant
 * @param targetVersion candidate or restored version involved in the event, or {@code null}
 * @param errorCode stable error code for failed events, or {@code null} for successful events
 * @param message short operator-facing explanation with no private paths or secrets
 * @see AppUpdateService
 */
public record AppUpdateHistoryEntry(
    Instant timestamp,
    String action,
    String status,
    String catalogId,
    String targetVersion,
    String errorCode,
    String message) {
  /**
   * Creates a validated history entry.
   *
   * <p>Required labels are trimmed and must remain non-blank. Optional strings are also trimmed,
   * and blank optional values are normalized to {@code null}. The constructor does not redact
   * arbitrary input; callers are responsible for passing only safe identifiers and short messages.
   *
   * @param timestamp event timestamp recorded by the update service
   * @param action stable action label used by clients and tests
   * @param status stable status label used by clients and tests
   * @param catalogId catalog id when relevant, or {@code null}
   * @param targetVersion target version when relevant, or {@code null}
   * @param errorCode stable error code when the event failed, or {@code null}
   * @param message short operator-facing message, or {@code null}
   */
  public AppUpdateHistoryEntry {
    Objects.requireNonNull(timestamp, "timestamp");
    action = requireText(action, "action");
    status = requireText(status, "status");
    catalogId = optionalText(catalogId);
    targetVersion = optionalText(targetVersion);
    errorCode = optionalText(errorCode);
    message = optionalText(message);
  }

  /**
   * Converts the entry to a JSON-compatible map.
   *
   * <p>The returned map preserves the response field order used by update summaries. Timestamps are
   * serialized with {@link Instant#toString()} so clients receive a timezone-explicit ISO-8601
   * instant without additional formatting assumptions.
   *
   * @return path-free history entry suitable for Platform API responses
   */
  public Map<String, Object> toJsonValue() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(7);
    json.put("timestamp", timestamp.toString());
    json.put("action", action);
    json.put("status", status);
    json.put("catalogId", catalogId);
    json.put("targetVersion", targetVersion);
    json.put("errorCode", errorCode);
    json.put("message", message);
    return json;
  }

  private static String requireText(String value, String fieldName) {
    String text = Objects.requireNonNull(value, fieldName).trim();
    if (text.isEmpty()) {
      throw new IllegalArgumentException(fieldName + " must not be blank");
    }
    return text;
  }

  private static String optionalText(String value) {
    if (value == null) {
      return null;
    }
    String text = value.trim();
    return text.isEmpty() ? null : text;
  }
}

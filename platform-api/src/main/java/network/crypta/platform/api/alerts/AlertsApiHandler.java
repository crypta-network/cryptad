package network.crypta.platform.api.alerts;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.runtime.spi.AlertFeedPort;
import network.crypta.runtime.spi.AlertListSnapshot;
import network.crypta.runtime.spi.AlertMutationPort;
import network.crypta.runtime.spi.AlertSeverity;
import network.crypta.runtime.spi.AlertSnapshot;

/**
 * Alert endpoint family for Platform API v1.
 *
 * <p>This handler turns the detached runtime alert SPI into stable, shell-facing JSON. It keeps the
 * contract intentionally small: callers can fetch the current alert list, inspect a few precomputed
 * summary counts, and request dismissal by the detached identifier already used by the legacy HTTP
 * flow. That keeps alert transport details out of the bridge layer while still giving the Web Shell
 * enough structure to render badges, cards, and per-alert actions without additional server-side
 * shaping.
 *
 * <p>The class is transport-neutral. It validates path-derived alert identifiers and packages the
 * response body, but it does not interpret HTTP authentication, form-password policy, or redirect
 * behavior. Those concerns stay in the bridge and router layers. Runtime-owned alert ordering,
 * dismissal side effects, and localized dismiss labels continue to come from the runtime ports.
 *
 * <ul>
 *   <li>{@link #list()} exposes one ordered snapshot plus summary fields.
 *   <li>{@link #dismiss(String)} preserves the best-effort legacy dismissal semantics.
 * </ul>
 */
public final class AlertsApiHandler {
  /** Detached runtime alert read port. */
  private final AlertFeedPort alertFeedPort;

  /** Detached runtime alert mutation port. */
  private final AlertMutationPort alertMutationPort;

  /**
   * Creates an alert API handler backed by the supplied detached runtime ports.
   *
   * <p>Typical callers create one handler while assembling the router and then reuse it for every
   * request. The feed and mutation ports may share a backing adapter, but the handler does not rely
   * on that detail. It only requires that both ports refer to the same live alert domain so list
   * and dismiss operations observe the same node state.
   *
   * @param alertFeedPort detached runtime port used to read the current alert snapshot
   * @param alertMutationPort detached runtime port used to dismiss alerts by stable identifier
   * @throws NullPointerException if either port is {@code null}
   */
  public AlertsApiHandler(AlertFeedPort alertFeedPort, AlertMutationPort alertMutationPort) {
    this.alertFeedPort = Objects.requireNonNull(alertFeedPort, "alertFeedPort");
    this.alertMutationPort = Objects.requireNonNull(alertMutationPort, "alertMutationPort");
  }

  /**
   * Returns the current detached alert list as a JSON-compatible object.
   *
   * <p>The returned map is stable in both field names and encounter order so browser clients can
   * render directly from the payload. Summary values are derived from the same snapshot used to
   * build the alert array, which avoids count mismatches caused by multiple runtime reads during a
   * single request. When no alerts are present, the method returns an empty list, zero counts, and
   * a {@code null} highest-severity field rather than inventing a placeholder severity.
   *
   * @return JSON-compatible alert list snapshot in encounter order, including summary counts and
   *     per-alert entries
   */
  public Map<String, Object> list() {
    AlertListSnapshot snapshot = alertFeedPort.snapshot();
    List<Map<String, Object>> alerts =
        snapshot.alerts().stream().map(AlertsApiHandler::toJson).toList();

    long dismissibleCount = snapshot.alerts().stream().filter(AlertSnapshot::dismissible).count();
    long eventNotificationCount =
        snapshot.alerts().stream().filter(AlertSnapshot::eventNotification).count();

    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(5);
    json.put("alertCount", alerts.size());
    json.put("dismissibleCount", dismissibleCount);
    json.put("eventNotificationCount", eventNotificationCount);
    json.put("highestSeverity", highestSeverity(snapshot.alerts()));
    json.put("alerts", alerts);
    return json;
  }

  /**
   * Dismisses one alert identified by a path-derived alert id.
   *
   * <p>This method performs only syntactic validation on the supplied route segment. Once the
   * segment parses as an integer, the request is forwarded to the detached mutation port and the
   * response echoes the requested identifier. Missing alerts, already-cleared alerts, and
   * non-dismissible alerts remain a runtime concern and continue to follow the legacy best-effort
   * behavior rather than producing a separate not-found response. That keeps the Platform API
   * aligned with the existing operator-facing dismissal semantics.
   *
   * @param alertIdSegment route segment identifying the alert to dismiss
   * @return JSON-compatible mutation summary echoing the requested alert identifier after the
   *     dismissal request is forwarded
   * @throws PlatformApiException if the route segment is absent or not a valid integer
   */
  public Map<String, Object> dismiss(String alertIdSegment) {
    int alertId = parseAlertId(alertIdSegment);
    alertMutationPort.dismiss(alertId);

    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(2);
    json.put("operation", "dismiss");
    json.put("alertId", alertId);
    return json;
  }

  private static Map<String, Object> toJson(AlertSnapshot alert) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(9);
    json.put("id", alert.id());
    json.put("title", alert.title());
    json.put("shortText", alert.shortText());
    json.put("text", alert.text());
    json.put("severity", alert.severity());
    json.put("dismissible", alert.dismissible());
    json.put("dismissLabel", alert.dismissLabel());
    json.put("eventNotification", alert.eventNotification());
    json.put("updatedTimeMillis", alert.updatedTimeMillis());
    return json;
  }

  private static AlertSeverity highestSeverity(List<AlertSnapshot> alerts) {
    AlertSeverity highest = null;
    int highestRank = Integer.MAX_VALUE;
    for (AlertSnapshot alert : alerts) {
      int rank = severityRank(alert.severity());
      if (rank < highestRank) {
        highestRank = rank;
        highest = alert.severity();
      }
    }
    return highest;
  }

  private static int severityRank(AlertSeverity severity) {
    if (severity == null) {
      return Integer.MAX_VALUE;
    }
    return switch (severity) {
      case CRITICAL_ERROR -> 0;
      case ERROR -> 1;
      case WARNING -> 2;
      case MINOR -> 3;
    };
  }

  private static int parseAlertId(String alertIdSegment) {
    try {
      return Integer.parseInt(Objects.requireNonNull(alertIdSegment, "alertIdSegment"));
    } catch (IllegalArgumentException _) {
      throw new PlatformApiException(
          400,
          "invalid_path_parameter",
          "Alert route parameter 'alertId' must be a valid integer.");
    }
  }
}

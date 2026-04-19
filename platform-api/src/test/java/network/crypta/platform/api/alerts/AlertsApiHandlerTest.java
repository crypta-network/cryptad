package network.crypta.platform.api.alerts;

import java.util.List;
import java.util.Map;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.runtime.spi.AlertFeedPort;
import network.crypta.runtime.spi.AlertListSnapshot;
import network.crypta.runtime.spi.AlertMutationPort;
import network.crypta.runtime.spi.AlertSeverity;
import network.crypta.runtime.spi.AlertSnapshot;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class AlertsApiHandlerTest {
  @Test
  void list_whenSnapshotEmpty_expectZeroCountsAndNullHighestSeverity() {
    Map<String, Object> response = listResponse(new AlertListSnapshot(List.of()));

    assertEquals(0, response.get("alertCount"));
    assertEquals(0L, response.get("dismissibleCount"));
    assertEquals(0L, response.get("eventNotificationCount"));
    assertNull(response.get("highestSeverity"));
    assertEquals(List.of(), response.get("alerts"));
  }

  @Test
  void list_whenSnapshotReturned_expectSummaryCountsAndStructuredAlerts() {
    AlertListSnapshot snapshot =
        new AlertListSnapshot(
            List.of(
                new AlertSnapshot(
                    42,
                    "Update available",
                    "Updater",
                    "A new core package is ready.",
                    AlertSeverity.WARNING,
                    true,
                    "Delete",
                    false,
                    123L)));

    Map<String, Object> response = listResponse(snapshot);

    assertEquals(1, response.get("alertCount"));
    assertEquals(1L, response.get("dismissibleCount"));
    assertEquals(0L, response.get("eventNotificationCount"));
    assertEquals(AlertSeverity.WARNING, response.get("highestSeverity"));
    assertEquals(
        List.of(
            Map.of(
                "id",
                42,
                "title",
                "Update available",
                "shortText",
                "Updater",
                "text",
                "A new core package is ready.",
                "severity",
                AlertSeverity.WARNING,
                "dismissible",
                true,
                "dismissLabel",
                "Delete",
                "eventNotification",
                false,
                "updatedTimeMillis",
                123L)),
        response.get("alerts"));
  }

  @Test
  void list_whenAlertsSpanSeveritiesAndFlags_expectHighestSeverityAndSummaryCounts() {
    AlertListSnapshot snapshot =
        new AlertListSnapshot(
            List.of(
                new AlertSnapshot(
                    1,
                    "Minor event",
                    "Event",
                    "Minor event body.",
                    AlertSeverity.MINOR,
                    false,
                    null,
                    true,
                    100L),
                new AlertSnapshot(
                    2,
                    "Critical issue",
                    "Critical",
                    "Critical issue body.",
                    AlertSeverity.CRITICAL_ERROR,
                    true,
                    "Acknowledge",
                    false,
                    200L),
                new AlertSnapshot(
                    3,
                    "Warning",
                    "Warning",
                    "Warning body.",
                    AlertSeverity.WARNING,
                    true,
                    "Dismiss",
                    false,
                    300L)));

    Map<String, Object> response = listResponse(snapshot);

    assertEquals(3, response.get("alertCount"));
    assertEquals(2L, response.get("dismissibleCount"));
    assertEquals(1L, response.get("eventNotificationCount"));
    assertEquals(AlertSeverity.CRITICAL_ERROR, response.get("highestSeverity"));
  }

  @Test
  void dismiss_whenNumericAlertIdProvided_expectDelegatesAndReturnsSummary() {
    RecordingAlertMutationPort mutationPort = new RecordingAlertMutationPort();
    AlertsApiHandler handler = new AlertsApiHandler(emptyFeed(), mutationPort);

    Map<String, Object> response = handler.dismiss("-17");

    assertEquals(-17, mutationPort.lastDismissedAlertId);
    assertEquals("dismiss", response.get("operation"));
    assertEquals(-17, response.get("alertId"));
  }

  @Test
  void dismiss_whenAlertIdMalformed_expectBadRequest() {
    AlertsApiHandler handler = new AlertsApiHandler(emptyFeed(), ignored -> {});

    PlatformApiException error =
        assertThrows(PlatformApiException.class, () -> handler.dismiss("not-a-number"));

    assertEquals(400, error.statusCode());
    assertEquals("invalid_path_parameter", error.errorCode());
    assertEquals("Alert route parameter 'alertId' must be a valid integer.", error.getMessage());
  }

  private static AlertFeedPort emptyFeed() {
    return () -> new AlertListSnapshot(List.of());
  }

  private static Map<String, Object> listResponse(AlertListSnapshot snapshot) {
    return new AlertsApiHandler(() -> snapshot, ignored -> {}).list();
  }

  private static final class RecordingAlertMutationPort implements AlertMutationPort {
    private Integer lastDismissedAlertId;

    @Override
    public void dismiss(int alertId) {
      lastDismissedAlertId = alertId;
    }
  }
}

package network.crypta.platform.api.diagnostics;

import java.util.List;
import java.util.Map;
import network.crypta.runtime.spi.DiagnosticReportSnapshot;
import network.crypta.runtime.spi.DiagnosticSectionSnapshot;
import network.crypta.runtime.spi.LegacyAdminSurfaceUsage;
import network.crypta.runtime.spi.LegacyAdminUsageSnapshot;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

@SuppressWarnings("java:S100")
class DiagnosticsApiHandlerTest {
  private static final String TITLE_FIELD = "title";

  @Test
  void snapshot_whenReportEmpty_expectEmptySectionsAndBlankPlainTextExport() {
    DiagnosticsApiHandler handler =
        new DiagnosticsApiHandler(() -> new DiagnosticReportSnapshot(List.of()));

    Map<String, Object> response = handler.snapshot();

    assertEquals(0, response.get("sectionCount"));
    assertEquals(List.of(), response.get("sections"));
    assertEquals("", response.get("plainTextExport"));
  }

  @Test
  void snapshot_whenReportReturned_expectStructuredSectionsAndPlainTextExport() {
    DiagnosticsApiHandler handler =
        new DiagnosticsApiHandler(
            () ->
                new DiagnosticReportSnapshot(
                    List.of(
                        new DiagnosticSectionSnapshot(
                            "System Information:", List.of("alpha", "", "beta")),
                        new DiagnosticSectionSnapshot(
                            "Queue:", List.of("Downloads Queued: 1", "")))));

    Map<String, Object> response = handler.snapshot();

    assertEquals(2, response.get("sectionCount"));
    assertEquals(
        List.of(
            Map.of(TITLE_FIELD, "System Information:", "lines", List.of("alpha", "", "beta")),
            Map.of(TITLE_FIELD, "Queue:", "lines", List.of("Downloads Queued: 1", ""))),
        response.get("sections"));
    assertEquals(
        "System Information:\nalpha\n\nbeta\nQueue:\nDownloads Queued: 1\n\n",
        response.get("plainTextExport"));
  }

  @Test
  void snapshot_whenLegacyAdminUsagePortProvided_expectLegacyAdminUsageSection() {
    Map<String, Object> response = legacyAdminUsageResponse();

    @SuppressWarnings("unchecked")
    List<Map<String, Object>> surfaces =
        (List<Map<String, Object>>) legacyAdmin(response).get("surfaces");
    assertEquals(
        Map.ofEntries(
            Map.entry("id", "queue-downloads"),
            Map.entry(TITLE_FIELD, "Download queue"),
            Map.entry("path", "/downloads/"),
            Map.entry("state", "PRIMARY_REPLACED"),
            Map.entry("replacementUrl", "/apps/queue-manager/"),
            Map.entry("removalMode", "REDIRECT_TO_REPLACEMENT"),
            Map.entry("removalWave", 1),
            Map.entry("removedByDefaultSince", "phase-6-pr-8"),
            Map.entry("fallbackPolicy", "none"),
            Map.entry("count", 12L),
            Map.entry("replacementResponseCount", 4L),
            Map.entry("blockedMutatingRequestCount", 1L),
            Map.entry("fallbackRenderCount", 0L),
            Map.entry("retainedOrPendingRenderCount", 0L),
            Map.entry("lastSeenEpochMillis", 1_770_000_000_000L)),
        surfaces.getFirst());
  }

  private static Map<String, Object> legacyAdminUsageResponse() {
    DiagnosticsApiHandler handler =
        new DiagnosticsApiHandler(
            () -> new DiagnosticReportSnapshot(List.of()),
            () ->
                new LegacyAdminUsageSnapshot(
                    List.of(
                        new LegacyAdminSurfaceUsage(
                            "queue-downloads",
                            "Download queue",
                            "/downloads/",
                            "PRIMARY_REPLACED",
                            "/apps/queue-manager/",
                            "REDIRECT_TO_REPLACEMENT",
                            1,
                            "phase-6-pr-8",
                            "none",
                            12L,
                            4L,
                            1L,
                            0L,
                            0L,
                            1_770_000_000_000L))));
    return handler.snapshot();
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> legacyAdmin(Map<String, Object> response) {
    return (Map<String, Object>) assertInstanceOf(Map.class, response.get("legacyAdmin"));
  }
}

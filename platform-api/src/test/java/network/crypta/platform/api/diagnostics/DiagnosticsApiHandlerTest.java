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
        Map.of(
            "id",
            "queue-downloads",
            TITLE_FIELD,
            "Download queue",
            "path",
            "/downloads/",
            "state",
            "PRIMARY_REPLACED",
            "replacementUrl",
            "/apps/queue-manager/",
            "count",
            12L,
            "lastSeenEpochMillis",
            1_770_000_000_000L),
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
                            12L,
                            1_770_000_000_000L))));
    return handler.snapshot();
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> legacyAdmin(Map<String, Object> response) {
    return (Map<String, Object>) assertInstanceOf(Map.class, response.get("legacyAdmin"));
  }
}

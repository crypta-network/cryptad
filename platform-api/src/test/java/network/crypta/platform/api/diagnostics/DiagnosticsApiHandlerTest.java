package network.crypta.platform.api.diagnostics;

import java.util.List;
import java.util.Map;
import network.crypta.runtime.spi.DiagnosticReportSnapshot;
import network.crypta.runtime.spi.DiagnosticSectionSnapshot;
import network.crypta.runtime.spi.LegacyAdminSurfaceUsage;
import network.crypta.runtime.spi.LegacyAdminUsageSnapshot;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
            Map.entry("removalScope", "CANONICAL_AND_SLASHLESS_ALIAS"),
            Map.entry("scopeExpandedInWave", 0),
            Map.entry("count", 12L),
            Map.entry("replacementResponseCount", 4L),
            Map.entry("blockedMutatingRequestCount", 1L),
            Map.entry("fallbackRenderCount", 0L),
            Map.entry("retainedOrPendingRenderCount", 0L),
            Map.entry("lastSeenEpochMillis", 1_770_000_000_000L)),
        surfaces.getFirst());
  }

  @Test
  void supportSummary_whenReportContainsSensitiveLines_expectSummaryOnlyAndRedactedDigest() {
    Map<String, Object> response = sensitiveSupportSummaryResponse();

    assertEquals(true, response.get("available"));
    assertEquals(1, response.get("sectionCount"));
    assertEquals(true, response.get("plainTextExportAvailable"));
    assertEquals(true, response.get("legacyFallbackAvailable"));
    assertFalse(response.containsKey("plainTextExport"));
    Map<String, Object> section = firstSection(response);
    assertFalse(section.containsKey("lines"));
    assertEquals("sensitive", section.get("id"));
    assertEquals("error", section.get("status"));
    assertEquals(4, section.get("lineCount"));
    assertEquals(3L, section.get("redactedLineCount"));
    assertEquals(1L, section.get("warningCount"));
    assertEquals(1L, section.get("errorCount"));
    assertTrue(section.get("digest") instanceof String digest && digest.matches("[a-f0-9]{64}"));
    String rendered = response.toString();
    assertFalse(rendered.contains("/work/private/catalog"));
    assertFalse(rendered.contains("USK@example/private/0"));
    assertFalse(rendered.contains("token=secret"));
  }

  @Test
  void supportSummary_whenZeroErrorSummaryLinesPresent_expectAvailableSection() {
    DiagnosticsApiHandler handler =
        new DiagnosticsApiHandler(
            () ->
                new DiagnosticReportSnapshot(
                    List.of(
                        new DiagnosticSectionSnapshot(
                            "Health:",
                            List.of(
                                "Errors: 0",
                                "Errors: none",
                                "Errors: no failures",
                                "Error: none",
                                "Error: no errors",
                                "No failures",
                                "Exceptions: none",
                                "Exception: none",
                                "Exceptions: 0",
                                "0 failed",
                                "Failure count: 0",
                                "Failure count: none")))));

    Map<String, Object> response = handler.supportSummary();

    Map<String, Object> section = firstSection(response);
    assertEquals("available", section.get("status"));
    assertEquals(0L, section.get("errorCount"));
  }

  @Test
  void supportSummary_whenNonZeroErrorSummaryLinesPresent_expectErrorSection() {
    DiagnosticsApiHandler handler =
        new DiagnosticsApiHandler(
            () ->
                new DiagnosticReportSnapshot(
                    List.of(
                        new DiagnosticSectionSnapshot(
                            "Health:",
                            List.of(
                                "Errors: 2",
                                "1 failure",
                                "Exception count: 3",
                                "Error: no route to peer")))));

    Map<String, Object> response = handler.supportSummary();

    Map<String, Object> section = firstSection(response);
    assertEquals("error", section.get("status"));
    assertEquals(4L, section.get("errorCount"));
  }

  @Test
  void supportSummary_whenZeroWarningSummaryLinesPresent_expectAvailableSection() {
    DiagnosticsApiHandler handler =
        new DiagnosticsApiHandler(
            () ->
                new DiagnosticReportSnapshot(
                    List.of(
                        new DiagnosticSectionSnapshot(
                            "Health:",
                            List.of(
                                "Warnings: 0",
                                "Warnings: none",
                                "Warnings: no warnings",
                                "Warning: none",
                                "Warning: no warnings",
                                "No warnings",
                                "Warn count: 0",
                                "Warn count: none",
                                "0 warns",
                                "zero warning")))));

    Map<String, Object> response = handler.supportSummary();

    Map<String, Object> section = firstSection(response);
    assertEquals("available", section.get("status"));
    assertEquals(0L, section.get("warningCount"));
  }

  @Test
  void supportSummary_whenNonZeroWarningSummaryLinesPresent_expectWarningSection() {
    DiagnosticsApiHandler handler =
        new DiagnosticsApiHandler(
            () ->
                new DiagnosticReportSnapshot(
                    List.of(
                        new DiagnosticSectionSnapshot(
                            "Health:",
                            List.of(
                                "Warnings: 2",
                                "1 warning",
                                "Warn count: 3",
                                "Warning: no route to peer")))));

    Map<String, Object> response = handler.supportSummary();

    Map<String, Object> section = firstSection(response);
    assertEquals("warning", section.get("status"));
    assertEquals(4L, section.get("warningCount"));
  }

  private static Map<String, Object> sensitiveSupportSummaryResponse() {
    DiagnosticsApiHandler handler =
        new DiagnosticsApiHandler(
            () ->
                new DiagnosticReportSnapshot(
                    List.of(
                        new DiagnosticSectionSnapshot(
                            "!!! Sensitive:",
                            List.of(
                                "path /work/private/catalog",
                                "uri USK@example/private/0",
                                "warn token=secret",
                                "error failed")))));
    return handler.supportSummary();
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
                            "CANONICAL_AND_SLASHLESS_ALIAS",
                            0,
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

  @SuppressWarnings("unchecked")
  private static Map<String, Object> firstSection(Map<String, Object> response) {
    List<Map<String, Object>> sections = (List<Map<String, Object>>) response.get("sections");
    return sections.getFirst();
  }
}

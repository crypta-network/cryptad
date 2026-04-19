package network.crypta.platform.api.diagnostics;

import java.util.List;
import java.util.Map;
import network.crypta.runtime.spi.DiagnosticReportSnapshot;
import network.crypta.runtime.spi.DiagnosticSectionSnapshot;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SuppressWarnings("java:S100")
class DiagnosticsApiHandlerTest {
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
            Map.of("title", "System Information:", "lines", List.of("alpha", "", "beta")),
            Map.of("title", "Queue:", "lines", List.of("Downloads Queued: 1", ""))),
        response.get("sections"));
    assertEquals(
        "System Information:\nalpha\n\nbeta\nQueue:\nDownloads Queued: 1\n\n",
        response.get("plainTextExport"));
  }
}

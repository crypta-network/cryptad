package network.crypta.platform.api.diagnostics;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import network.crypta.runtime.spi.DiagnosticPort;
import network.crypta.runtime.spi.DiagnosticReportSnapshot;
import network.crypta.runtime.spi.DiagnosticSectionSnapshot;

/**
 * Diagnostics endpoint family for Platform API v1.
 *
 * <p>This handler exposes the detached diagnostic report as a stable read-only JSON payload. It
 * keeps the runtime-provided section ordering intact so shell clients can render the same logical
 * report structure the legacy diagnostics page exposes, while avoiding any dependency on page
 * toadlets or legacy plain-text assembly code in higher layers. The result is suitable for
 * shell-native panels, lightweight export actions, and future local tooling that needs a
 * transport-neutral diagnostic snapshot.
 *
 * <p>The handler also emits one plain-text export string alongside the structured section list.
 * That avoids forcing browser clients to reverse-engineer the exact legacy line layout when they
 * need a copy-friendly representation. Section content still comes from the runtime SPI; this class
 * only packages it into JSON and mirrors the established text concatenation order.
 */
public final class DiagnosticsApiHandler {
  /** Detached runtime diagnostic-report port. */
  private final DiagnosticPort diagnosticPort;

  /**
   * Creates a diagnostics API handler backed by the supplied detached runtime port.
   *
   * <p>Routers typically create one instance during startup and reuse it for every diagnostics
   * request. The supplied port remains the single authority for report content and section order;
   * this handler does not cache or merge reports across requests.
   *
   * @param diagnosticPort detached runtime port used to read the current diagnostic report
   * @throws NullPointerException if {@code diagnosticPort} is {@code null}
   */
  public DiagnosticsApiHandler(DiagnosticPort diagnosticPort) {
    this.diagnosticPort = Objects.requireNonNull(diagnosticPort, "diagnosticPort");
  }

  /**
   * Returns the current detached diagnostic report as a JSON-compatible object.
   *
   * <p>The response always includes the ordered section array and a pre-rendered plain-text export.
   * When the runtime reports no sections, the handler returns an empty list, a zero section count,
   * and an empty export string. Callers therefore do not need special-case parsing for missing
   * fields or optional export content.
   *
   * @return JSON-compatible diagnostic report containing ordered sections and a plain-text export
   *     that mirrors the same snapshot
   */
  public Map<String, Object> snapshot() {
    DiagnosticReportSnapshot snapshot = diagnosticPort.snapshot();
    List<Map<String, Object>> sections =
        snapshot.sections().stream().map(DiagnosticsApiHandler::toJson).toList();

    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(3);
    json.put("sectionCount", sections.size());
    json.put("sections", sections);
    json.put("plainTextExport", render(snapshot));
    return json;
  }

  private static Map<String, Object> toJson(DiagnosticSectionSnapshot section) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(2);
    json.put("title", section.title());
    json.put("lines", section.lines());
    return json;
  }

  private static String render(DiagnosticReportSnapshot snapshot) {
    StringBuilder builder = new StringBuilder();
    for (DiagnosticSectionSnapshot section : snapshot.sections()) {
      builder.append(section.title()).append('\n');
      for (String line : section.lines()) {
        builder.append(line).append('\n');
      }
    }
    return builder.toString();
  }
}

package network.crypta.platform.api.diagnostics;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import network.crypta.runtime.spi.DiagnosticPort;
import network.crypta.runtime.spi.DiagnosticReportSnapshot;
import network.crypta.runtime.spi.DiagnosticSectionSnapshot;
import network.crypta.runtime.spi.LegacyAdminSurfaceUsage;
import network.crypta.runtime.spi.LegacyAdminUsagePort;
import network.crypta.runtime.spi.LegacyAdminUsageSnapshot;

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

  /** Optional process-local legacy admin usage source. */
  private final LegacyAdminUsagePort legacyAdminUsagePort;

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
    this(diagnosticPort, null);
  }

  /**
   * Creates a diagnostics API handler backed by the supplied detached runtime port and optional
   * legacy-admin usage source.
   *
   * @param diagnosticPort detached runtime port used to read the current diagnostic report
   * @param legacyAdminUsagePort optional process-local legacy admin usage source
   * @throws NullPointerException if {@code diagnosticPort} is {@code null}
   */
  public DiagnosticsApiHandler(
      DiagnosticPort diagnosticPort, LegacyAdminUsagePort legacyAdminUsagePort) {
    this.diagnosticPort = Objects.requireNonNull(diagnosticPort, "diagnosticPort");
    this.legacyAdminUsagePort = legacyAdminUsagePort;
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

    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(4);
    json.put("sectionCount", sections.size());
    json.put("sections", sections);
    json.put("plainTextExport", render(snapshot));
    if (legacyAdminUsagePort != null) {
      json.put("legacyAdmin", legacyAdminUsageToJson(legacyAdminUsagePort.snapshot()));
    }
    return json;
  }

  private static Map<String, Object> legacyAdminUsageToJson(LegacyAdminUsageSnapshot snapshot) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(1);
    json.put(
        "surfaces",
        snapshot.surfaces().stream().map(DiagnosticsApiHandler::legacySurfaceUsageToJson).toList());
    return json;
  }

  private static Map<String, Object> legacySurfaceUsageToJson(LegacyAdminSurfaceUsage surface) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(14);
    json.put("id", surface.surfaceId());
    json.put("title", surface.title());
    json.put("path", surface.legacyPath());
    json.put("state", surface.state());
    json.put("replacementUrl", surface.replacementUrl());
    json.put("removalMode", surface.removalMode());
    json.put("removalWave", surface.removalWave());
    json.put("removedByDefaultSince", surface.removedByDefaultSince());
    json.put("fallbackPolicy", surface.fallbackPolicy());
    json.put("count", surface.count());
    json.put("replacementResponseCount", surface.replacementResponseCount());
    json.put("blockedMutatingRequestCount", surface.blockedMutatingRequestCount());
    json.put("fallbackRenderCount", surface.fallbackRenderCount());
    json.put("retainedOrPendingRenderCount", surface.retainedOrPendingRenderCount());
    json.put("lastSeenEpochMillis", surface.lastSeenEpochMillis());
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

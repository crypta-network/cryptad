package network.crypta.platform.api.diagnostics;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;
import network.crypta.platform.api.operator.OperatorSupportRedactor;
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
  private static final HexFormat HEX = HexFormat.of();
  private static final Pattern DIAGNOSTIC_TOKEN_SEPARATOR_PATTERN = Pattern.compile("[^a-z0-9]+");
  private static final Set<String> ERROR_WORDS =
      Set.of("error", "errors", "failed", "failure", "failures", "exception", "exceptions");
  private static final Set<String> WARNING_WORDS = Set.of("warn", "warns", "warning", "warnings");
  private static final Set<String> TEXTUAL_ZERO_COUNT_WORDS = Set.of("no", "none", "zero");
  private static final Set<String> COUNT_VALUE_QUALIFIER_WORDS =
      Set.of("code", "reason", "status", "message", "messages", "value", "values");

  private enum CountSignal {
    NONE,
    ZERO,
    NON_ZERO
  }

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

  /**
   * Returns a support-bundle-safe diagnostics summary.
   *
   * <p>The normal diagnostics endpoint deliberately keeps the local operator's structured lines and
   * legacy plain-text export available. Support bundles need a narrower shape: section names,
   * counts, warning/error totals, and digests computed over redacted lines. This method never
   * returns raw diagnostic lines or the plain-text export.
   *
   * @return JSON-compatible diagnostics summary for redacted support bundles
   */
  public Map<String, Object> supportSummary() {
    DiagnosticReportSnapshot snapshot = diagnosticPort.snapshot();
    List<Map<String, Object>> sections =
        snapshot.sections().stream().map(DiagnosticsApiHandler::supportSectionSummary).toList();
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(5);
    json.put("available", true);
    json.put("sectionCount", sections.size());
    json.put("sections", sections);
    json.put("plainTextExportAvailable", !render(snapshot).isBlank());
    json.put("legacyFallbackAvailable", true);
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
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(16);
    json.put("id", surface.surfaceId());
    json.put("title", surface.title());
    json.put("path", surface.legacyPath());
    json.put("state", surface.state());
    json.put("replacementUrl", surface.replacementUrl());
    json.put("removalMode", surface.removalMode());
    json.put("removalWave", surface.removalWave());
    json.put("removedByDefaultSince", surface.removedByDefaultSince());
    json.put("fallbackPolicy", surface.fallbackPolicy());
    json.put("removalScope", surface.removalScope());
    json.put("scopeExpandedInWave", surface.scopeExpandedInWave());
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

  private static Map<String, Object> supportSectionSummary(DiagnosticSectionSnapshot section) {
    List<String> rawLines = section.lines();
    @SuppressWarnings("unchecked")
    List<Object> redactedLines = (List<Object>) OperatorSupportRedactor.redact(rawLines).value();
    long changedLineCount = changedLineCount(rawLines, redactedLines);
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(8);
    json.put("id", sectionId(section.title()));
    json.put("name", safeSectionName(section.title()));
    json.put("status", sectionStatus(rawLines));
    json.put("lineCount", rawLines.size());
    json.put("redactedLineCount", changedLineCount);
    json.put("warningCount", boundedWarningCount(rawLines));
    json.put("errorCount", boundedErrorCount(rawLines));
    json.put("digest", digest(section.title(), redactedLines));
    return json;
  }

  private static long changedLineCount(List<String> rawLines, List<Object> redactedLines) {
    long changed = 0L;
    int limit = Math.min(rawLines.size(), redactedLines.size());
    for (int index = 0; index < limit; index++) {
      Object redacted = redactedLines.get(index);
      if (redacted instanceof String text && !Objects.equals(rawLines.get(index), text)) {
        changed++;
      }
    }
    return changed + Math.max(0, rawLines.size() - redactedLines.size());
  }

  private static String safeSectionName(String title) {
    Object redacted = OperatorSupportRedactor.redact(title).value();
    return redacted instanceof String text && !text.isBlank() ? text : "diagnostic-section";
  }

  private static String sectionId(String title) {
    String normalized =
        safeSectionName(title)
            .toLowerCase(Locale.ROOT)
            .replaceAll("[^a-z0-9]+", "-")
            .replaceAll("^-", "")
            .replaceAll("-$", "");
    return normalized.isBlank() ? "diagnostic-section" : normalized;
  }

  private static String sectionStatus(List<String> lines) {
    long errors = boundedErrorCount(lines);
    if (errors > 0L) {
      return "error";
    }
    if (boundedWarningCount(lines) > 0L) {
      return "warning";
    }
    return "available";
  }

  private static long boundedErrorCount(List<String> lines) {
    return lines.stream()
        .map(line -> line.toLowerCase(Locale.ROOT))
        .filter(DiagnosticsApiHandler::hasErrorSignal)
        .limit(1_000L)
        .count();
  }

  private static boolean hasErrorSignal(String line) {
    return hasDiagnosticSignal(line, ERROR_WORDS);
  }

  private static boolean hasWarningSignal(String line) {
    return hasDiagnosticSignal(line, WARNING_WORDS);
  }

  private static boolean hasDiagnosticSignal(String line, Set<String> signalWords) {
    List<String> tokens = diagnosticTokens(line);
    boolean hasUnqualifiedSignalWord = false;
    for (int index = 0; index < tokens.size(); index++) {
      if (!signalWords.contains(tokens.get(index))) {
        continue;
      }
      CountSignal countSignal = countSignal(tokens, index, signalWords);
      if (countSignal == CountSignal.NON_ZERO) {
        return true;
      }
      if (countSignal != CountSignal.ZERO && !isNegatedSignalWord(tokens, index)) {
        hasUnqualifiedSignalWord = true;
      }
    }
    return hasUnqualifiedSignalWord;
  }

  private static List<String> diagnosticTokens(String line) {
    return DIAGNOSTIC_TOKEN_SEPARATOR_PATTERN
        .splitAsStream(line)
        .filter(token -> !token.isBlank())
        .toList();
  }

  private static boolean isNegatedSignalWord(List<String> tokens, int signalWordIndex) {
    if (signalWordIndex == 0) {
      return false;
    }
    String previous = tokens.get(signalWordIndex - 1);
    return "no".equals(previous) || "zero".equals(previous);
  }

  private static CountSignal countSignal(
      List<String> tokens, int signalWordIndex, Set<String> signalWords) {
    int nextIndex = signalWordIndex + 1;
    boolean explicitCount = false;
    if (nextIndex < tokens.size() && "count".equals(tokens.get(nextIndex))) {
      explicitCount = true;
      nextIndex++;
    }
    while (nextIndex < tokens.size()
        && COUNT_VALUE_QUALIFIER_WORDS.contains(tokens.get(nextIndex))) {
      nextIndex++;
    }
    CountSignal next =
        countValueSignal(
            tokens,
            nextIndex,
            explicitCount || isPluralCountSummaryWord(tokens.get(signalWordIndex)),
            signalWords);
    if (next != CountSignal.NONE) {
      return next;
    }
    return numericCountSignal(tokens, signalWordIndex - 1);
  }

  private static CountSignal numericCountSignal(List<String> tokens, int index) {
    return countValueSignal(tokens, index, false, Set.of());
  }

  private static CountSignal countValueSignal(
      List<String> tokens, int index, boolean allowCountProse, Set<String> signalWords) {
    if (index < 0 || index >= tokens.size()) {
      return CountSignal.NONE;
    }
    if (isTextualZeroCountValue(tokens, index, allowCountProse, signalWords)) {
      return CountSignal.ZERO;
    }
    try {
      return Long.parseLong(tokens.get(index)) == 0L ? CountSignal.ZERO : CountSignal.NON_ZERO;
    } catch (NumberFormatException _) {
      return CountSignal.NONE;
    }
  }

  private static boolean isTextualZeroCountValue(
      List<String> tokens, int index, boolean allowCountProse, Set<String> signalWords) {
    String token = tokens.get(index);
    if (!TEXTUAL_ZERO_COUNT_WORDS.contains(token)) {
      return false;
    }
    if ("none".equals(token)) {
      return true;
    }
    return allowCountProse
        || index + 1 == tokens.size()
        || signalWords.contains(tokens.get(index + 1));
  }

  private static boolean isPluralCountSummaryWord(String signalWord) {
    return signalWord.endsWith("s");
  }

  private static long boundedWarningCount(List<String> lines) {
    return lines.stream()
        .map(line -> line.toLowerCase(Locale.ROOT))
        .filter(DiagnosticsApiHandler::hasWarningSignal)
        .limit(1_000L)
        .count();
  }

  private static String digest(String title, List<Object> redactedLines) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      digest.update(safeSectionName(title).getBytes(StandardCharsets.UTF_8));
      for (Object line : redactedLines) {
        if (line instanceof String text) {
          digest.update((byte) '\n');
          digest.update(text.getBytes(StandardCharsets.UTF_8));
        }
      }
      return HEX.formatHex(digest.digest());
    } catch (NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable", exception);
    }
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

package network.crypta.platform.devtools;

import java.util.List;
import java.util.Locale;

/**
 * Result of one app-owned UI lint run.
 *
 * <p>The result keeps static UI lint output deterministic for both human CLI output and JSON
 * evidence. It records whether the lint rules applied to the bundle, preserves finding order, and
 * exposes severity counts without forcing callers to duplicate stream logic. The model is small on
 * purpose: it carries parsed manifest identity, effective UI mode, applicability, and
 * presentation-safe findings only. It does not include absolute bundle paths, file contents,
 * request bodies, query strings, tokens, or other runtime data that could leak through reports.
 *
 * <p>JSON serialization is implemented locally to avoid adding a dependency to the standalone
 * developer tooling path. The output shape is stable and intended for offline certification
 * fixtures, so changes to field names or ordering should be treated as developer-facing behavior.
 * The result object is therefore both a command model and an evidence model: validation reads the
 * severity counts, while release tooling can archive the same sanitized findings without needing
 * access to the staged bundle.
 *
 * @param appId parsed app id, or an empty string if manifest parsing failed before an id was known
 * @param uiMode parsed manifest UI mode, such as {@code static}, {@code none}, or {@code
 *     shell-panel}
 * @param applicable whether static UI lint checks apply to this bundle and mode
 * @param findings deterministic finding list, copied defensively during construction and preserved
 *     in reporting order
 */
record AppUiLintResult(
    String appId, String uiMode, boolean applicable, List<AppUiLintFinding> findings) {
  /**
   * Creates an immutable lint result from parsed bundle identity and findings.
   *
   * <p>The compact constructor copies the finding list so later caller-side mutations cannot change
   * command output, JSON evidence, or validation decisions. Individual findings are immutable
   * records, so no deeper copy is needed. A {@code null} list or {@code null} element is rejected
   * by the standard collection copy contract, which keeps invalid results from reaching CLI output.
   *
   * @param appId parsed app id, or an empty string if parsing failed before an id was available
   * @param uiMode manifest UI mode value reported by the bundle
   * @param applicable whether static UI lint rules were applicable to the bundle
   * @param findings non-null finding list in deterministic reporting order
   */
  AppUiLintResult {
    findings = List.copyOf(findings);
  }

  /**
   * Reports whether any finding is fatal in the current lint mode.
   *
   * <p>Normal and strict runs can produce different effective severities for the same rule id. This
   * method deliberately checks the already-effective severity stored on each finding rather than
   * recalculating strict-mode behavior.
   *
   * @return {@code true} when at least one finding has {@link AppUiLintSeverity#ERROR} severity
   */
  boolean hasErrors() {
    return findings.stream().anyMatch(finding -> finding.severity() == AppUiLintSeverity.ERROR);
  }

  /**
   * Counts fatal findings in the current result.
   *
   * <p>The value is used for command status and for the JSON summary. It counts only effective
   * severities already present on findings; callers should not reinterpret warning rules here.
   *
   * @return number of findings whose effective severity is {@link AppUiLintSeverity#ERROR}
   */
  long errorCount() {
    return count(AppUiLintSeverity.ERROR);
  }

  /**
   * Counts advisory findings in the current result.
   *
   * <p>Warnings remain non-fatal in normal lint output. Strict lint should promote a rule before a
   * finding reaches this result when that rule must block validation.
   *
   * @return number of findings whose effective severity is {@link AppUiLintSeverity#WARNING}
   */
  long warningCount() {
    return count(AppUiLintSeverity.WARNING);
  }

  /**
   * Counts informational findings in the current result.
   *
   * <p>Notes explain not-applicable or evidence-only outcomes. They are included in reports so
   * callers can distinguish a skipped static UI lint run from a silent empty result.
   *
   * @return number of findings whose effective severity is {@link AppUiLintSeverity#NOTE}
   */
  long noteCount() {
    return count(AppUiLintSeverity.NOTE);
  }

  /**
   * Serializes the lint result to deterministic JSON.
   *
   * <p>The serializer emits fields in a fixed order and escapes every string value directly. It is
   * intentionally limited to the small data model used by UI lint reports, which keeps the
   * standalone CLI dependency-light and avoids pulling a general JSON library into this leaf. The
   * method does not pretty-print file contents or command-line arguments; every path and message
   * has already been reduced to the sanitized finding model.
   *
   * @return JSON document ending with a newline, suitable for {@code crypta-app ui lint --json}
   */
  String toJson() {
    StringBuilder builder = new StringBuilder();
    builder.append("{\n");
    appendJsonField(builder, "appId", appId, true, 1);
    appendJsonField(builder, "uiMode", uiMode, true, 1);
    indent(builder, 1).append("\"applicable\": ").append(applicable).append(",\n");
    indent(builder, 1).append("\"summary\": {\n");
    indent(builder, 2).append("\"errors\": ").append(errorCount()).append(",\n");
    indent(builder, 2).append("\"warnings\": ").append(warningCount()).append(",\n");
    indent(builder, 2).append("\"notes\": ").append(noteCount()).append('\n');
    indent(builder, 1).append("},\n");
    indent(builder, 1).append("\"findings\": [");
    if (!findings.isEmpty()) {
      builder.append('\n');
    }
    for (int index = 0; index < findings.size(); index++) {
      AppUiLintFinding finding = findings.get(index);
      indent(builder, 2).append("{\n");
      appendJsonField(builder, "id", finding.id(), true, 3);
      appendJsonField(builder, "category", finding.category(), true, 3);
      appendJsonField(
          builder, "severity", finding.severity().name().toLowerCase(Locale.ROOT), true, 3);
      appendJsonField(builder, "path", finding.path(), true, 3);
      appendJsonField(builder, "message", finding.message(), false, 3);
      indent(builder, 2).append("}");
      if (index + 1 < findings.size()) {
        builder.append(',');
      }
      builder.append('\n');
    }
    if (!findings.isEmpty()) {
      indent(builder, 1);
    }
    builder.append("]\n");
    builder.append("}\n");
    return builder.toString();
  }

  /**
   * Counts findings by effective severity.
   *
   * @param severity severity bucket to count in the immutable finding list
   * @return number of findings whose severity matches the requested bucket
   */
  private long count(AppUiLintSeverity severity) {
    return findings.stream().filter(finding -> finding.severity() == severity).count();
  }

  /**
   * Appends one quoted string field to a JSON object.
   *
   * @param builder destination builder for the current JSON document
   * @param name object field name to escape and write
   * @param value field value to escape and write
   * @param comma whether the field should be followed by a comma
   * @param depth indentation depth measured in two-space units
   */
  private static void appendJsonField(
      StringBuilder builder, String name, String value, boolean comma, int depth) {
    indent(builder, depth)
        .append('"')
        .append(escapeJson(name))
        .append("\": \"")
        .append(escapeJson(value))
        .append('"');
    if (comma) {
      builder.append(',');
    }
    builder.append('\n');
  }

  /**
   * Appends deterministic two-space indentation.
   *
   * @param builder destination builder for the current JSON document
   * @param depth indentation depth measured in two-space units
   * @return the same builder after indentation has been appended
   */
  private static StringBuilder indent(StringBuilder builder, int depth) {
    return builder.repeat("  ", depth);
  }

  /**
   * Escapes a Java string as JSON string content.
   *
   * <p>The returned text does not include surrounding quotes. Control characters use short JSON
   * escapes where available and lowercase Unicode escapes otherwise, which keeps report output
   * deterministic and readable.
   *
   * @param value unescaped string value from lint result data
   * @return escaped JSON string content without surrounding quotes
   */
  private static String escapeJson(String value) {
    StringBuilder escaped = new StringBuilder(value.length());
    for (int index = 0; index < value.length(); index++) {
      char character = value.charAt(index);
      switch (character) {
        case '"' -> escaped.append("\\\"");
        case '\\' -> escaped.append("\\\\");
        case '\b' -> escaped.append("\\b");
        case '\f' -> escaped.append("\\f");
        case '\n' -> escaped.append("\\n");
        case '\r' -> escaped.append("\\r");
        case '\t' -> escaped.append("\\t");
        default -> appendJsonCharacter(escaped, character);
      }
    }
    return escaped.toString();
  }

  /**
   * Appends one JSON-safe character representation.
   *
   * @param escaped destination builder that receives the escaped character text
   * @param character character that does not use one of the short escape branches
   */
  private static void appendJsonCharacter(StringBuilder escaped, char character) {
    if (character < 0x20) {
      escaped.append("\\u");
      String hex = Integer.toHexString(character);
      escaped.repeat("0", 4 - hex.length()).append(hex);
    } else {
      escaped.append(character);
    }
  }
}

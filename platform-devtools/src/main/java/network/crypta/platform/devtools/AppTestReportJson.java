package network.crypta.platform.devtools;

/**
 * Dependency-light JSON serializer for {@link AppTestReport}.
 *
 * <p>The developer CLI needs stable JSON reports without adding a JSON library to the devtools
 * runtime. This serializer writes the fixed schema used by {@code crypta-app test}: top-level app
 * metadata, aggregate status, and an ordered array of check objects. It assumes values have already
 * passed through the report model's redaction boundary, then performs the JSON string escaping
 * needed for control characters, quotes, and backslashes.
 *
 * <p>The output format is deliberately plain and deterministic. Indentation, field order, and
 * trailing newlines are part of the snapshot-friendly contract used by tests and release evidence.
 * Extend this class only when the report schema changes; do not use it as a general JSON writer.
 */
final class AppTestReportJson {
  /** Prevents construction of this stateless serializer. */
  private AppTestReportJson() {}

  /**
   * Serializes one app test report using schema version {@code 1}.
   *
   * @param report sanitized immutable report produced by {@link AppTestSuite}
   * @return deterministic UTF-8-safe JSON text with a trailing newline
   */
  static String write(AppTestReport report) {
    StringBuilder builder = new StringBuilder();
    builder.append("{\n");
    field(builder, 1, "schemaVersion", Integer.toString(report.schemaVersion()), false, true);
    field(builder, 1, "appId", report.appId(), true, true);
    field(builder, 1, "version", report.version(), true, true);
    field(builder, 1, "status", report.status().jsonValue(), true, true);
    indent(builder, 1).append("\"checks\": [");
    if (!report.checks().isEmpty()) {
      builder.append('\n');
    }
    for (int index = 0; index < report.checks().size(); index++) {
      AppTestCheck check = report.checks().get(index);
      indent(builder, 2).append("{\n");
      field(builder, 3, "id", check.id(), true, true);
      field(builder, 3, "status", check.status().jsonValue(), true, true);
      field(builder, 3, "summary", check.summary(), true, false);
      indent(builder, 2).append("}");
      if (index + 1 < report.checks().size()) {
        builder.append(',');
      }
      builder.append('\n');
    }
    if (!report.checks().isEmpty()) {
      indent(builder, 1);
    }
    builder.append("]\n");
    builder.append("}\n");
    return builder.toString();
  }

  /**
   * Appends one scalar JSON field at the requested indentation depth.
   *
   * @param builder destination builder for the report document
   * @param depth indentation depth measured in two-space units
   * @param name JSON field name to escape and write
   * @param value scalar JSON value, escaped when {@code quote} is true
   * @param quote whether the value should be emitted as a JSON string
   * @param comma whether to append a trailing comma after the value
   */
  private static void field(
      StringBuilder builder, int depth, String name, String value, boolean quote, boolean comma) {
    indent(builder, depth).append('"').append(escape(name)).append("\": ");
    if (quote) {
      builder.append('"').append(escape(value)).append('"');
    } else {
      builder.append(value);
    }
    if (comma) {
      builder.append(',');
    }
    builder.append('\n');
  }

  /**
   * Appends deterministic two-space indentation.
   *
   * @param builder destination builder for the report document
   * @param depth indentation depth measured in two-space units
   * @return the same builder for fluent appends
   */
  private static StringBuilder indent(StringBuilder builder, int depth) {
    return builder.repeat("  ", depth);
  }

  /**
   * Escapes one Java string for inclusion as a JSON string value.
   *
   * @param value non-null scalar value to escape
   * @return escaped value without surrounding quote characters
   */
  private static String escape(String value) {
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
        default -> {
          if (character < 0x20) {
            escaped.append(String.format("\\u%04x", (int) character));
          } else {
            escaped.append(character);
          }
        }
      }
    }
    return escaped.toString();
  }
}

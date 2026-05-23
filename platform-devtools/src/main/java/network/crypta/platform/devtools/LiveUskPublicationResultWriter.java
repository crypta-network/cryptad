package network.crypta.platform.devtools;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;

/**
 * Writes sanitized live USK publication summaries.
 *
 * <p>The writer renders the result model without consulting any secret-bearing request object. JSON
 * output is intended for release jobs and certification evidence, while Markdown output is a
 * compact operator summary. Both formats intentionally omit local absolute paths, private insert
 * URIs, form passwords, raw node bodies, and key material beyond the public signing key id.
 *
 * <p>The output format is selected by the destination filename: paths ending in {@code .json}
 * receive stable machine-readable evidence, and all other paths receive Markdown. Callers are
 * expected to pass an already sanitized {@link LiveUskPublicationResult}; this class does not
 * inspect live-node requests or local staging directories. It creates the output parent directory
 * when needed and overwrites the target file without following the target as a symlink.
 */
final class LiveUskPublicationResultWriter {
  /** Utility class; all rendering operations are static. */
  private LiveUskPublicationResultWriter() {}

  /**
   * Writes one publication result.
   *
   * @param result report-safe live publication result
   * @throws IOException if the output path cannot be created or written
   */
  static void write(LiveUskPublicationResult result) throws IOException {
    Path parent = result.output().getParent();
    if (parent != null) {
      Files.createDirectories(parent);
    }
    String content = result.output().toString().endsWith(".json") ? json(result) : markdown(result);
    Files.writeString(
        result.output(),
        content,
        StandardCharsets.UTF_8,
        StandardOpenOption.CREATE,
        StandardOpenOption.TRUNCATE_EXISTING,
        StandardOpenOption.WRITE,
        LinkOption.NOFOLLOW_LINKS);
  }

  /**
   * Renders a compact Markdown summary for an operator or release note attachment.
   *
   * <p>The Markdown form favors direct scanability over full machine schema stability. It includes
   * the same report-safe fields as the JSON form, emits optional resolved-source and edition fields
   * only when present, and places warnings in a separate section so release operators can see
   * retained-staging or verification notes without parsing JSON.
   *
   * @param result sanitized publication result to render without reading secret-bearing inputs
   * @return Markdown text suitable for a local operator summary file
   */
  private static String markdown(LiveUskPublicationResult result) {
    StringBuilder builder = new StringBuilder();
    builder
        .append("# Crypta Catalog Live USK Publication Summary\n\n")
        .append("- Catalog id: `")
        .append(result.catalogId())
        .append("`\n")
        .append("- Entries: `")
        .append(result.entryCount())
        .append("`\n")
        .append("- Catalog: `")
        .append(result.catalogFileName())
        .append("`\n")
        .append("- Signature sidecar: `")
        .append(result.catalogSignatureFileName())
        .append("`\n")
        .append("- Public catalog source: `")
        .append(result.publicCatalogSource())
        .append("`\n")
        .append("- Public signature source: `")
        .append(result.publicSignatureSource())
        .append("`\n")
        .append("- Catalog SHA-256: `")
        .append(result.catalogSha256())
        .append("`\n")
        .append("- Signature SHA-256: `")
        .append(result.signatureSha256())
        .append("`\n")
        .append("- Catalog signing key id: `")
        .append(result.catalogSigningKeyId())
        .append("`\n")
        .append("- Catalog insert status: `")
        .append(result.catalogInsertStatus())
        .append("`\n")
        .append("- Signature insert status: `")
        .append(result.signatureInsertStatus())
        .append("`\n")
        .append("- Post-publish verification: `")
        .append(result.postPublishVerificationStatus())
        .append("`\n")
        .append("- Scheduler refresh verification: `")
        .append(result.schedulerRefreshVerificationStatus())
        .append("`\n");
    result
        .resolvedCatalogSource()
        .ifPresent(value -> appendMarkdownField(builder, "Resolved catalog source", value));
    result.edition().ifPresent(value -> appendMarkdownField(builder, "Edition", value));
    if (!result.warnings().isEmpty()) {
      builder.append("\n## Warnings\n\n");
      for (String warning : result.warnings()) {
        builder.append("- ").append(warning).append('\n');
      }
    }
    return builder.toString();
  }

  /**
   * Appends one optional Markdown scalar field when the caller has a value to report.
   *
   * <p>The helper keeps the optional fields visually consistent with the required fields. Values
   * are wrapped as code spans because catalog sources and editions are literal operator-facing
   * values, not prose.
   *
   * @param builder destination Markdown builder for the current summary
   * @param name human-readable field label shown to operators
   * @param value sanitized literal field value to render in a code span
   */
  private static void appendMarkdownField(StringBuilder builder, String name, String value) {
    builder.append("- ").append(name).append(": `").append(value).append("`\n");
  }

  /**
   * Renders deterministic JSON evidence for release automation.
   *
   * <p>The JSON form keeps a fixed field order so certification diffs stay readable. Optional
   * source and edition fields are emitted as {@code null} when absent instead of being omitted, and
   * warnings are always emitted as an array. Numeric fields that are part of the schema, such as
   * the schema version and entry count, are written without quotes.
   *
   * @param result sanitized publication result to serialize as JSON
   * @return JSON object text with a trailing newline
   */
  private static String json(LiveUskPublicationResult result) {
    StringBuilder builder = new StringBuilder();
    builder.append("{\n");
    stringField(builder, "schemaVersion", "1", false);
    stringField(builder, "mode", "live", true);
    stringField(builder, "catalogId", result.catalogId(), true);
    stringField(builder, "catalogFile", result.catalogFileName(), true);
    stringField(builder, "catalogSignatureFile", result.catalogSignatureFileName(), true);
    stringField(builder, "publicCatalogSource", result.publicCatalogSource(), true);
    stringField(builder, "publicSignatureSource", result.publicSignatureSource(), true);
    optionalStringField(
        builder, "resolvedCatalogSource", result.resolvedCatalogSource().orElse(null));
    optionalStringField(builder, "edition", result.edition().orElse(null));
    stringField(builder, "catalogSha256", result.catalogSha256(), true);
    stringField(builder, "signatureSha256", result.signatureSha256(), true);
    stringField(builder, "catalogSigningKeyId", result.catalogSigningKeyId(), true);
    stringField(builder, "entryCount", Integer.toString(result.entryCount()), false);
    stringField(builder, "catalogInsertStatus", result.catalogInsertStatus(), true);
    stringField(builder, "signatureInsertStatus", result.signatureInsertStatus(), true);
    stringField(
        builder, "postPublishVerificationStatus", result.postPublishVerificationStatus(), true);
    stringField(
        builder,
        "schedulerRefreshVerificationStatus",
        result.schedulerRefreshVerificationStatus(),
        true);
    warnings(builder, result.warnings());
    builder.append("}\n");
    return builder.toString();
  }

  /**
   * Appends one scalar JSON field and its trailing comma.
   *
   * <p>Most fields are strings and therefore escaped and quoted. A small number of numeric schema
   * fields pass {@code false} for {@code quoteValue}; callers are responsible for supplying a value
   * that is already valid JSON for those numeric positions.
   *
   * @param builder destination JSON builder currently inside the top-level object
   * @param name field name to escape and write
   * @param value scalar value to escape when quoted or write directly when numeric
   * @param quoteValue whether the value should be emitted as a JSON string
   */
  private static void stringField(
      StringBuilder builder, String name, String value, boolean quoteValue) {
    builder.append("  \"").append(escape(name)).append("\": ");
    if (quoteValue) {
      builder.append('"').append(escape(value)).append('"');
    } else {
      builder.append(value);
    }
    builder.append(",\n");
  }

  /**
   * Appends one optional JSON string field.
   *
   * <p>Optional fields are present in the schema even when no live node reported a resolved source
   * or edition. This avoids consumers needing two separate object shapes for verified and
   * not-yet-verified publications.
   *
   * @param builder destination JSON builder currently inside the top-level object
   * @param name field name to escape and write
   * @param value sanitized value, or {@code null} for a JSON {@code null}
   */
  private static void optionalStringField(StringBuilder builder, String name, String value) {
    builder.append("  \"").append(escape(name)).append("\": ");
    if (value == null) {
      builder.append("null");
    } else {
      builder.append('"').append(escape(value)).append('"');
    }
    builder.append(",\n");
  }

  /**
   * Appends the warning array at the end of the JSON object.
   *
   * <p>Warnings are already sanitized by the publication service. This renderer still escapes JSON
   * control characters so a warning cannot break the evidence format or hide following fields.
   *
   * @param builder destination JSON builder currently inside the top-level object
   * @param warnings ordered warning values to render as JSON strings
   */
  private static void warnings(StringBuilder builder, List<String> warnings) {
    builder.append("  \"warnings\": [");
    if (!warnings.isEmpty()) {
      builder.append('\n');
    }
    for (int index = 0; index < warnings.size(); index++) {
      builder.append("    \"").append(escape(warnings.get(index))).append('"');
      if (index + 1 < warnings.size()) {
        builder.append(',');
      }
      builder.append('\n');
    }
    if (!warnings.isEmpty()) {
      builder.append("  ");
    }
    builder.append("]\n");
  }

  /**
   * Escapes the JSON string characters emitted by this writer.
   *
   * <p>The writer only needs the common scalar escapes used by release evidence: backslash, double
   * quote, newline, carriage return, and tab. Other characters are copied unchanged so public
   * Crypta URIs and digest strings remain readable.
   *
   * @param value non-null scalar value to place inside a JSON string
   * @return escaped text without surrounding quote characters
   */
  private static String escape(String value) {
    StringBuilder escaped = new StringBuilder(value.length());
    for (int index = 0; index < value.length(); index++) {
      char character = value.charAt(index);
      switch (character) {
        case '\\' -> escaped.append("\\\\");
        case '"' -> escaped.append("\\\"");
        case '\n' -> escaped.append("\\n");
        case '\r' -> escaped.append("\\r");
        case '\t' -> escaped.append("\\t");
        default -> escaped.append(character);
      }
    }
    return escaped.toString();
  }
}

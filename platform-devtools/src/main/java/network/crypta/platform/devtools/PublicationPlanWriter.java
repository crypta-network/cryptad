package network.crypta.platform.devtools;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;
import network.crypta.platform.appcatalog.AppCatalog;
import network.crypta.platform.appcatalog.AppCatalogEntry;
import network.crypta.platform.appcatalog.AppCatalogSignature;

/**
 * Writes offline Crypta USK publication plans for signed app catalogs.
 *
 * <p>This helper backs {@code crypta-app publish-usk --dry-run}. It validates that a catalog file
 * parses, that its signature sidecar is structurally readable, and that the advertised catalog
 * source is a public {@code crypta:USK@.../cryptad-app-catalog.properties} path. It then writes a
 * redacted markdown or JSON checklist that developers can follow when publishing catalog bytes and
 * signature bytes through a separate, trusted insertion workflow.
 *
 * <p>The writer does not perform live inserts and does not validate network availability. Its
 * responsibility is local evidence: name the catalog artifacts, summarize entries, remind the
 * developer about immutable bundle URIs and review receipts, and avoid leaking local paths or
 * private Crypta insert material into generated plans.
 */
final class PublicationPlanWriter {
  /** Prevents construction of this stateless plan writer. */
  private PublicationPlanWriter() {}

  /**
   * Validates catalog inputs and writes one publication plan.
   *
   * @param request local catalog artifacts, public source URI, and output path
   * @return catalog id, entry count, and normalized output path for the generated plan
   * @throws IOException if catalog artifacts cannot be read or the plan cannot be written
   */
  static Result write(Request request) throws IOException {
    ValidatedPublicationInputs checked =
        PublicationInputValidator.validate(
            request.catalogFile(),
            request.catalogSignatureFile(),
            request.catalogSource(),
            request.output());
    String content =
        checked.output().toString().endsWith(".json") ? json(checked) : markdown(checked);
    Path parent = checked.output().getParent();
    if (parent != null) {
      Files.createDirectories(parent);
    }
    Files.writeString(
        checked.output(),
        content,
        StandardCharsets.UTF_8,
        StandardOpenOption.CREATE,
        StandardOpenOption.TRUNCATE_EXISTING,
        StandardOpenOption.WRITE,
        LinkOption.NOFOLLOW_LINKS);
    return new Result(
        checked.catalog().catalogId(), checked.catalog().entries().size(), checked.output());
  }

  /**
   * Renders the human-readable publication checklist.
   *
   * @param request normalized plan request with local file names and catalog source
   * @return Markdown plan text with redacted Crypta URI material
   */
  private static String markdown(ValidatedPublicationInputs request) {
    AppCatalog catalog = request.catalog();
    StringBuilder builder = new StringBuilder();
    builder
        .append("# Crypta Catalog USK Publication Plan\n\n")
        .append("- Catalog: `")
        .append(AppTestRedactor.fileName(request.catalogFile()))
        .append("`\n")
        .append("- Signature sidecar: `")
        .append(AppTestRedactor.fileName(request.catalogSignatureFile()))
        .append("`\n")
        .append("- Expected public source: `")
        .append(redactCryptaUri(request.catalogSource()))
        .append("`\n")
        .append("- Catalog id: `")
        .append(catalog.catalogId())
        .append("`\n")
        .append("- Entries: `")
        .append(catalog.entries().size())
        .append("`\n\n")
        .append("## Checklist\n\n")
        .append("- Insert the catalog properties bytes as `")
        .append(AppCatalogSignature.CATALOG_FILE_NAME)
        .append("`.\n")
        .append("- Insert the signature sidecar bytes as `")
        .append(AppCatalogSignature.SIGNATURE_FILE_NAME)
        .append("` at the same USK path edition.\n")
        .append(
            "- Publish app bundle artifacts first and use immutable `crypta:CHK@...` bundle URIs in"
                + " catalog entries.\n")
        .append(
            "- Attach trusted review receipts when the target catalog policy requires review"
                + " evidence.\n")
        .append(
            "- Add or refresh the catalog source in Web Shell using the public catalog source"
                + " URI.\n")
        .append("- Verify catalog and bundle signatures after fetching from Crypta.\n\n")
        .append("## Bundle Artifacts\n\n");
    for (AppCatalogEntry entry : catalog.entries()) {
      builder
          .append("- `")
          .append(entry.appId())
          .append("` ")
          .append(entry.version())
          .append(": ")
          .append(redactCryptaUri(entry.bundleUri().toString()))
          .append("\n");
    }
    return builder.toString();
  }

  /**
   * Renders the machine-readable publication checklist.
   *
   * @param request normalized plan request with local file names and catalog source
   * @return deterministic JSON plan text with redacted Crypta URI material
   */
  private static String json(ValidatedPublicationInputs request) {
    AppCatalog catalog = request.catalog();
    StringBuilder builder = new StringBuilder();
    builder.append("{\n");
    field(builder, "schemaVersion", "1", false);
    field(builder, "catalogId", catalog.catalogId(), true);
    field(builder, "catalogFile", AppTestRedactor.fileName(request.catalogFile()), true);
    field(
        builder,
        "catalogSignatureFile",
        AppTestRedactor.fileName(request.catalogSignatureFile()),
        true);
    field(builder, "catalogSource", redactCryptaUri(request.catalogSource()), true);
    builder.append("  \"entries\": [");
    if (!catalog.entries().isEmpty()) {
      builder.append('\n');
    }
    List<AppCatalogEntry> entries = catalog.entries();
    for (int index = 0; index < entries.size(); index++) {
      AppCatalogEntry entry = entries.get(index);
      builder
          .append("    {\"appId\":\"")
          .append(escape(entry.appId()))
          .append("\",\"version\":\"")
          .append(escape(entry.version()))
          .append("\",\"bundleUri\":\"")
          .append(escape(redactCryptaUri(entry.bundleUri().toString())))
          .append("\"}");
      if (index + 1 < entries.size()) {
        builder.append(',');
      }
      builder.append('\n');
    }
    if (!entries.isEmpty()) {
      builder.append("  ");
    }
    builder.append("]\n}\n");
    return builder.toString();
  }

  /**
   * Appends one top-level scalar field to a JSON publication plan.
   *
   * @param builder destination builder for the JSON plan
   * @param name JSON field name to escape
   * @param value scalar value to write
   * @param quote whether the value should be emitted as a JSON string
   */
  private static void field(StringBuilder builder, String name, String value, boolean quote) {
    builder.append("  \"").append(escape(name)).append("\": ");
    if (quote) {
      builder.append('"').append(escape(value)).append('"');
    } else {
      builder.append(value);
    }
    builder.append(",\n");
  }

  /**
   * Redacts private or capability-bearing parts of Crypta URIs in generated plans.
   *
   * @param uri catalog source or bundle URI from local catalog metadata
   * @return URI text with USK, SSK, and CHK payload material replaced
   */
  private static String redactCryptaUri(String uri) {
    return uri.replaceAll("crypta:USK@[^/]+", "crypta:USK@[REDACTED]")
        .replaceAll("crypta:SSK@[^/]+", "crypta:SSK@[REDACTED]")
        .replaceAll("crypta:CHK@[^?\\s]+", "crypta:CHK@[REDACTED]");
  }

  /**
   * Escapes the subset of JSON string characters used by publication-plan fields.
   *
   * @param value non-null scalar field value
   * @return escaped value without surrounding quote characters
   */
  private static String escape(String value) {
    return value.replace("\\", "\\\\").replace("\"", "\\\"");
  }

  /**
   * Input for one offline publication plan.
   *
   * @param catalogFile local catalog properties file to publish
   * @param catalogSignatureFile local catalog signature sidecar to publish at the same edition
   * @param catalogSource expected public {@code crypta:USK@...} catalog source URI
   * @param output Markdown or JSON plan output path
   */
  record Request(Path catalogFile, Path catalogSignatureFile, String catalogSource, Path output) {
    /**
     * Normalizes local filesystem paths before validation and output.
     *
     * @return equivalent request with absolute normalized paths
     */
    @SuppressWarnings("unused")
    Request normalize() {
      return new Request(
          catalogFile.toAbsolutePath().normalize(),
          catalogSignatureFile.toAbsolutePath().normalize(),
          catalogSource,
          output.toAbsolutePath().normalize());
    }
  }

  /**
   * Summary of a written publication plan.
   *
   * @param catalogId catalog id parsed from the local catalog properties
   * @param entryCount number of app entries included in the parsed catalog
   * @param output normalized path where the plan was written
   */
  record Result(String catalogId, int entryCount, Path output) {}
}

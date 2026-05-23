package network.crypta.platform.devtools;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import network.crypta.platform.appcatalog.AppCatalogSignature;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class LiveUskPublicationResultWriterTest {
  private static final String RESOLVED_CATALOG_SOURCE =
      "crypta:USK@PUBLIC/catalog/43/" + AppCatalogSignature.CATALOG_FILE_NAME;
  private static final String RESOLVED_EDITION = "43";

  @TempDir private Path tempDir;

  @Test
  void write_whenJsonOutputRequested_expectNullOptionalsAndEscapedWarnings() throws Exception {
    Path output = tempDir.resolve("live-summary.json");
    LiveUskPublicationResult result =
        resultWithoutResolvedMetadata(output, List.of("quoted \"warning\"\nnext"));

    LiveUskPublicationResultWriter.write(result);

    String json = Files.readString(output, StandardCharsets.UTF_8);
    assertTrue(json.contains("\"mode\": \"live\""));
    assertTrue(json.contains("\"resolvedCatalogSource\": null"));
    assertTrue(json.contains("\"edition\": null"));
    assertTrue(json.contains("\"entryCount\": 2"));
    assertTrue(json.contains("quoted \\\"warning\\\"\\nnext"));
    assertFalse(json.contains(tempDir.toString()));
  }

  @Test
  void write_whenMarkdownOutputRequested_expectOptionalFieldsAndWarnings() throws Exception {
    Path output = tempDir.resolve("live-summary.md");
    LiveUskPublicationResult result =
        resultWithResolvedMetadata(
            output, List.of("staging_sidecars_retained_until_live_insert_completion"));

    LiveUskPublicationResultWriter.write(result);

    String markdown = Files.readString(output, StandardCharsets.UTF_8);
    assertTrue(markdown.contains("# Crypta Catalog Live USK Publication Summary"));
    assertTrue(markdown.contains("- Resolved catalog source: `crypta:USK@PUBLIC/catalog/43/"));
    assertTrue(markdown.contains("- Edition: `43`"));
    assertTrue(markdown.contains("## Warnings"));
    assertTrue(markdown.contains("staging_sidecars_retained_until_live_insert_completion"));
    assertFalse(markdown.contains(tempDir.toString()));
  }

  private static LiveUskPublicationResult resultWithoutResolvedMetadata(
      Path output, List<String> warnings) {
    return result(output, false, "", "", warnings);
  }

  private static LiveUskPublicationResult resultWithResolvedMetadata(
      Path output, List<String> warnings) {
    return result(output, true, RESOLVED_CATALOG_SOURCE, RESOLVED_EDITION, warnings);
  }

  private static LiveUskPublicationResult result(
      Path output,
      boolean includeResolvedMetadata,
      String resolvedCatalogSource,
      String edition,
      List<String> warnings) {
    return new LiveUskPublicationResult(
        "dev",
        AppCatalogSignature.CATALOG_FILE_NAME,
        AppCatalogSignature.SIGNATURE_FILE_NAME,
        "crypta:USK@PUBLIC/catalog/42/" + AppCatalogSignature.CATALOG_FILE_NAME,
        "crypta:USK@PUBLIC/catalog/42/" + AppCatalogSignature.SIGNATURE_FILE_NAME,
        includeResolvedMetadata ? Optional.of(resolvedCatalogSource) : Optional.empty(),
        includeResolvedMetadata ? Optional.of(edition) : Optional.empty(),
        "0".repeat(64),
        "1".repeat(64),
        "dev-local",
        2,
        "queued",
        "queued",
        "verified",
        "not_run",
        warnings,
        output);
  }
}

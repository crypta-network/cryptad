package network.crypta.platform.appcatalog;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class AppCatalogEntryDescriptorTest {
  @TempDir private Path tempDir;

  @Test
  void parse_whenDescriptorContainsCommentsAndBlankPermissions_expectNormalizedDescriptor()
      throws Exception {
    Path artifact = tempDir.resolve("sample-app.zip").toAbsolutePath().normalize();
    URI bundleUri = URI.create("https://example.invalid/apps/sample-app.zip");
    Path descriptor =
        Files.writeString(
            tempDir.resolve("entry.properties"),
            lines(
                "# comment",
                "! another comment",
                "artifact.path=" + artifact,
                "bundle.uri=" + bundleUri,
                "summary= Sample app catalog entry ",
                "app.id= Sample-App ",
                "name= Sample App ",
                "version= 0.1.0 ",
                "permissions= "),
            StandardCharsets.UTF_8);

    AppCatalogEntryDescriptor parsed = AppCatalogEntryDescriptor.parse(descriptor);

    assertEquals(artifact, parsed.artifactPath());
    assertEquals(bundleUri, parsed.bundleUri());
    assertEquals("Sample app catalog entry", parsed.summary());
    assertEquals(Optional.of("Sample-App"), parsed.appIdOverride());
    assertEquals(Optional.of("Sample App"), parsed.nameOverride());
    assertEquals(Optional.of("0.1.0"), parsed.versionOverride());
    assertEquals(Optional.of(List.of()), parsed.permissionsOverride());
  }

  @Test
  void parse_whenArtifactPathIsRelative_expectInvalidCatalogEntry() throws Exception {
    Path descriptor =
        Files.writeString(
            tempDir.resolve("entry.properties"),
            lines(
                "artifact.path=sample-app.zip",
                "bundle.uri=https://example.invalid/apps/sample-app.zip",
                "summary=Sample app catalog entry"),
            StandardCharsets.UTF_8);

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> AppCatalogEntryDescriptor.parse(descriptor));

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_ENTRY, exception.errorCode());
    assertTrue(exception.getMessage().contains("artifact.path must be absolute"));
  }

  @Test
  void parse_whenDescriptorContainsUnsupportedProperty_expectInvalidCatalogEntry()
      throws Exception {
    Path descriptor =
        Files.writeString(
            tempDir.resolve("entry.properties"),
            lines(
                "artifact.path=" + tempDir.resolve("sample-app.zip").toAbsolutePath().normalize(),
                "bundle.uri=https://example.invalid/apps/sample-app.zip",
                "summary=Sample app catalog entry",
                "unexpected=value"),
            StandardCharsets.UTF_8);

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> AppCatalogEntryDescriptor.parse(descriptor));

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_ENTRY, exception.errorCode());
    assertTrue(exception.getMessage().contains("unsupported catalog entry descriptor property"));
  }

  private static String lines(String... values) {
    return String.join("\n", values) + "\n";
  }
}

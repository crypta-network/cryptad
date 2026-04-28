package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class AppCatalogBundleExtractorTest {
  private static final int IGNORED_METADATA_BYTES = 32;

  @TempDir private Path tempDir;

  @Test
  void extractZip_whenIgnoredAppleDoubleEntryExceedsExtractedCap_expectInvalidAppBundle()
      throws Exception {
    Path artifact = ignoredAppleDoubleZip(tempDir.resolve("appledouble-large.zip"));
    Path stagedRoot = Files.createDirectory(tempDir.resolve("staged"));

    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class,
            () -> AppCatalogBundleExtractor.extractZip(artifact, stagedRoot, 16L));

    assertEquals(AppCatalogSidecars.INVALID_APP_BUNDLE, exception.errorCode());
    assertEquals("zip artifact exceeds extracted size cap", exception.getMessage());
    assertFalse(Files.exists(stagedRoot.resolve("._cryptad-app.properties")));
  }

  private static Path ignoredAppleDoubleZip(Path targetZip) throws IOException {
    byte[] payload = "x".repeat(IGNORED_METADATA_BYTES).getBytes(StandardCharsets.UTF_8);
    try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(targetZip))) {
      zip.putNextEntry(new ZipEntry("._cryptad-app.properties"));
      zip.write(payload);
      zip.closeEntry();
    }
    return targetZip;
  }
}

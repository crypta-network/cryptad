package network.crypta.platform.appcatalog;

import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;

@SuppressWarnings("java:S100")
class AppCatalogInstallPlanTest {
  private static final String DIGEST = "1".repeat(64);

  @TempDir Path tempDir;

  @Test
  void constructor_whenVerificationIsProvided_expectUnscopedCompatibilityPlan() throws Exception {
    Path scratch = tempDir.resolve("scratch");
    Path staged = scratch.resolve("nested").resolve("..").resolve("bundle");
    Files.createDirectories(staged.normalize());
    AppCatalogBundleVerificationResult verification =
        new AppCatalogBundleVerificationResult(
            "publisher-key", DIGEST, "publisher-binding", DIGEST, true, DIGEST);

    try (AppCatalogInstallPlan plan =
        new AppCatalogInstallPlan("Core", entry(), staged, scratch, verification)) {
      assertEquals("core", plan.catalogId());
      assertEquals(staged.toAbsolutePath().normalize(), plan.stagedBundleDirectory());
      assertEquals(scratch.toAbsolutePath().normalize(), plan.scratchDirectory());
      assertSame(verification, plan.bundleVerification());
      assertEquals(java.util.Optional.empty(), plan.originContext());
    }

    assertFalse(Files.exists(scratch));
  }

  @Test
  void constructor_whenAuthorizationIsUnrecorded_expectLegacyCompatibilityMarkers()
      throws Exception {
    Path scratch = tempDir.resolve("legacy-scratch");
    Path staged = scratch.resolve("bundle");
    Files.createDirectories(staged);

    try (AppCatalogInstallPlan plan = new AppCatalogInstallPlan("core", entry(), staged, scratch)) {
      assertEquals("unrecorded", plan.bundleVerification().publisherKeyId());
      assertFalse(plan.bundleVerification().catalogScoped());
      assertEquals(java.util.Optional.empty(), plan.originContext());
    }
  }

  private static AppCatalogEntry entry() {
    return new AppCatalogEntry(
        "feed-reader",
        "Feed Reader",
        "1",
        "Catalog install-plan test.",
        URI.create("https://catalog.example/feed-reader.zip"),
        "0".repeat(64),
        1L,
        AppCatalogEntry.ZIP_BUNDLE_TYPE,
        List.of());
  }
}

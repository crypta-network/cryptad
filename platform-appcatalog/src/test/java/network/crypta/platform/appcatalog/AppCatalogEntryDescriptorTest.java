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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
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
                "homepage=https://example.invalid/app",
                "source=https://example.invalid/repo",
                "license= MIT ",
                "categories=Productivity,network,productivity",
                "minimumCryptaVersion= 0.1.0 ",
                "maximumCryptaVersion= 0.9.99 ",
                "channel= nightly ",
                "support.status= experimental ",
                "deprecation.status= deprecated ",
                "deprecation.message= Use Sample App Stable. ",
                "replacementAppId= Sample-App-Stable ",
                "securityAdvisories= CRYPTA-2026-0001 ",
                "securityAdvisory.CRYPTA-2026-0001.uri=https://example.invalid/advisories/CRYPTA-2026-0001",
                "api.minimumVersion=1",
                "api.maximumTestedVersion=2",
                "api.optionalCapabilities=alerts.read,diagnostics.read",
                "api.experimentalCapabilitiesAccepted=true",
                "review.status= reviewed ",
                "review.note= Reviewed for local operator safety. ",
                "permissions= ",
                "permissions.rationale.queue.read= Reads the local transfer queue. ",
                "screenshot.1=https://example.invalid/assets/shot-1.png",
                "changelog.summary= Adds queue retry controls. ",
                "changelog.uri=https://example.invalid/changelog.txt"),
            StandardCharsets.UTF_8);

    AppCatalogEntryDescriptor parsed = AppCatalogEntryDescriptor.parse(descriptor);

    assertEquals(artifact, parsed.artifactPath());
    assertEquals(bundleUri, parsed.bundleUri());
    assertEquals("Sample app catalog entry", parsed.summary());
    assertEquals(Optional.of("Sample-App"), parsed.appIdOverride());
    assertEquals(Optional.of("Sample App"), parsed.nameOverride());
    assertEquals(Optional.of("0.1.0"), parsed.versionOverride());
    assertEquals("https://example.invalid/app", parsed.homepage().orElseThrow().toString());
    assertEquals("https://example.invalid/repo", parsed.source().orElseThrow().toString());
    assertEquals(Optional.of("MIT"), parsed.license());
    assertEquals(List.of("productivity", "network"), parsed.categories());
    assertEquals("0.1.0", parsed.compatibility().minimumCryptaVersion());
    assertEquals("0.9.99", parsed.compatibility().maximumCryptaVersion());
    assertEquals(AppCatalogChannel.NIGHTLY, parsed.productionMetadata().channel());
    assertEquals(AppCatalogSupportStatus.EXPERIMENTAL, parsed.productionMetadata().supportStatus());
    assertEquals(
        AppCatalogDeprecationStatus.DEPRECATED, parsed.productionMetadata().deprecationStatus());
    assertEquals(
        "Use Sample App Stable.", parsed.productionMetadata().deprecationMessage().orElseThrow());
    assertEquals("sample-app-stable", parsed.productionMetadata().replacementAppId().orElseThrow());
    assertEquals(
        "CRYPTA-2026-0001", parsed.productionMetadata().securityAdvisories().getFirst().id());
    assertEquals(Integer.valueOf(1), parsed.compatibility().apiCompatibility().minimumVersion());
    assertEquals(
        Integer.valueOf(2), parsed.compatibility().apiCompatibility().maximumTestedVersion());
    assertEquals(
        List.of("alerts.read", "diagnostics.read"),
        parsed.compatibility().apiCompatibility().optionalCapabilities());
    assertTrue(parsed.compatibility().apiCompatibility().experimentalCapabilitiesAccepted());
    assertEquals(AppCatalogReviewStatus.REVIEWED, parsed.review().status());
    assertEquals("Reviewed for local operator safety.", parsed.review().note().orElseThrow());
    assertEquals(Optional.of(List.of()), parsed.permissionsOverride());
    assertEquals(
        "Reads the local transfer queue.", parsed.permissionRationales().get("queue.read"));
    assertEquals(
        List.of(URI.create("https://example.invalid/assets/shot-1.png")), parsed.screenshots());
    assertEquals("Adds queue retry controls.", parsed.changelog().summary().orElseThrow());
    assertEquals(
        "https://example.invalid/changelog.txt", parsed.changelog().uri().orElseThrow().toString());
  }

  @Test
  void parse_whenDescriptorOmitsStoreMetadata_expectEmptyMetadata() throws Exception {
    Path artifact = tempDir.resolve("sample-app.zip").toAbsolutePath().normalize();
    URI bundleUri = URI.create("https://example.invalid/apps/sample-app.zip");
    Path descriptor =
        descriptor(
            "artifact.path=" + artifact,
            "bundle.uri=" + bundleUri,
            "summary=Sample app catalog entry");

    AppCatalogEntryDescriptor parsed = AppCatalogEntryDescriptor.parse(descriptor);

    assertEquals(Optional.empty(), parsed.homepage());
    assertEquals(Optional.empty(), parsed.source());
    assertEquals(Optional.empty(), parsed.license());
    assertEquals(List.of(), parsed.categories());
    assertNull(parsed.compatibility().minimumCryptaVersion());
    assertNull(parsed.compatibility().maximumCryptaVersion());
    assertFalse(parsed.compatibility().apiCompatibility().declared());
    assertEquals(AppCatalogProductionMetadata.DEFAULT, parsed.productionMetadata());
    assertEquals(AppCatalogReviewMetadata.EMPTY, parsed.review());
    assertEquals(AppCatalogChangelog.EMPTY, parsed.changelog());
    assertEquals(List.of(), parsed.screenshots());
    assertEquals(Optional.empty(), parsed.permissionsOverride());
    assertTrue(parsed.permissionRationales().isEmpty());
  }

  @Test
  void parse_whenDescriptorUsesCryptaChkArtifactUri_expectAccepted() throws Exception {
    Path artifact = tempDir.resolve("sample-app.zip").toAbsolutePath().normalize();
    Path descriptor =
        descriptor(
            "artifact.path=" + artifact,
            "bundle.uri=crypta:CHK@sample-app-artifact",
            "summary=Sample app catalog entry");

    AppCatalogEntryDescriptor parsed = AppCatalogEntryDescriptor.parse(descriptor);

    assertEquals(URI.create("crypta:CHK@sample-app-artifact"), parsed.bundleUri());
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

  @Test
  void parse_whenDescriptorMetadataUriUsesFileScheme_expectInvalidCatalogEntry() throws Exception {
    Path descriptor =
        descriptor(
            "artifact.path=" + tempDir.resolve("sample-app.zip").toAbsolutePath().normalize(),
            "bundle.uri=https://example.invalid/apps/sample-app.zip",
            "summary=Sample app catalog entry",
            "homepage=file:///tmp/sample-app");

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> AppCatalogEntryDescriptor.parse(descriptor));

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_ENTRY, exception.errorCode());
  }

  @Test
  void parse_whenDescriptorChannelIsUnsupported_expectInvalidCatalogEntry() throws Exception {
    Path descriptor =
        descriptor(
            "artifact.path=" + tempDir.resolve("sample-app.zip").toAbsolutePath().normalize(),
            "bundle.uri=https://example.invalid/apps/sample-app.zip",
            "summary=Sample app catalog entry",
            "channel=preview");

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> AppCatalogEntryDescriptor.parse(descriptor));

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_ENTRY, exception.errorCode());
  }

  @Test
  void parse_whenDescriptorSecurityAdvisoryUriIsMissing_expectInvalidCatalogEntry()
      throws Exception {
    Path descriptor =
        descriptor(
            "artifact.path=" + tempDir.resolve("sample-app.zip").toAbsolutePath().normalize(),
            "bundle.uri=https://example.invalid/apps/sample-app.zip",
            "summary=Sample app catalog entry",
            "securityAdvisories=CRYPTA-2026-0001");

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> AppCatalogEntryDescriptor.parse(descriptor));

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_ENTRY, exception.errorCode());
  }

  @Test
  void parse_whenDescriptorScreenshotIndexesHaveGap_expectInvalidCatalogEntry() throws Exception {
    Path descriptor =
        descriptor(
            "artifact.path=" + tempDir.resolve("sample-app.zip").toAbsolutePath().normalize(),
            "bundle.uri=https://example.invalid/apps/sample-app.zip",
            "summary=Sample app catalog entry",
            "screenshot.2=https://example.invalid/assets/shot-2.png");

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> AppCatalogEntryDescriptor.parse(descriptor));

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_ENTRY, exception.errorCode());
  }

  @Test
  void parse_whenPermissionRationaleKeysNormalizeToDuplicate_expectInvalidCatalogEntry()
      throws Exception {
    Path descriptor =
        descriptor(
            "artifact.path=" + tempDir.resolve("sample-app.zip").toAbsolutePath().normalize(),
            "bundle.uri=https://example.invalid/apps/sample-app.zip",
            "summary=Sample app catalog entry",
            "permissions.rationale.queue.read=Reads queues.",
            "permissions.rationale.QUEUE.READ=Reads queues again.");

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> AppCatalogEntryDescriptor.parse(descriptor));

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_ENTRY, exception.errorCode());
  }

  private Path descriptor(String... properties) throws Exception {
    return Files.writeString(
        tempDir.resolve("entry.properties"), lines(properties), StandardCharsets.UTF_8);
  }

  private static String lines(String... values) {
    return String.join("\n", values) + "\n";
  }
}

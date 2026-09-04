package network.crypta.platform.appcatalog;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

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
                "maintenance.owner= crypta-core ",
                "maintenance.ownerUri=https://example.invalid/crypta/owners/core",
                "maintenance.supportLevel= core ",
                "maintenance.dataSchemaPolicy= stateless ",
                "maintenance.migrationPolicy= none ",
                "maintenance.backupRestore= not-applicable ",
                "maintenance.securityPolicy= catalog-advisories ",
                "maintenance.deprecationPolicy= none ",
                "maintenance.supportUri=https://example.invalid/crypta/apps/sample-app/support",
                "api.minimumVersion=1",
                "api.maximumTestedVersion=2",
                "api.optionalCapabilities=alerts.read,diagnostics.read",
                "api.targetStability=experimental",
                "api.targetBaseline=1.1",
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

    assertStoreIdentity(parsed, artifact, bundleUri);
    assertStoreMetadata(parsed);
    assertProductionMetadata(parsed);
    assertMaintenanceMetadata(parsed.maintenanceMetadata());
    assertApiCompatibility(parsed);
    assertReviewMetadata(parsed);
    assertStoreMedia(parsed);
  }

  private static void assertStoreIdentity(
      AppCatalogEntryDescriptor parsed, Path artifact, URI bundleUri) {
    assertEquals(artifact, parsed.artifactPath());
    assertEquals(bundleUri, parsed.bundleUri());
    assertEquals("Sample app catalog entry", parsed.summary());
    assertEquals(Optional.of("Sample-App"), parsed.appIdOverride());
    assertEquals(Optional.of("Sample App"), parsed.nameOverride());
    assertEquals(Optional.of("0.1.0"), parsed.versionOverride());
  }

  private static void assertStoreMetadata(AppCatalogEntryDescriptor parsed) {
    assertEquals("https://example.invalid/app", parsed.homepage().orElseThrow().toString());
    assertEquals("https://example.invalid/repo", parsed.source().orElseThrow().toString());
    assertEquals(Optional.of("MIT"), parsed.license());
    assertEquals(List.of("productivity", "network"), parsed.categories());
    assertEquals("0.1.0", parsed.compatibility().minimumCryptaVersion());
    assertEquals("0.9.99", parsed.compatibility().maximumCryptaVersion());
  }

  private static void assertProductionMetadata(AppCatalogEntryDescriptor parsed) {
    assertEquals(AppCatalogChannel.NIGHTLY, parsed.productionMetadata().channel());
    assertEquals(AppCatalogSupportStatus.EXPERIMENTAL, parsed.productionMetadata().supportStatus());
    assertEquals(
        AppCatalogDeprecationStatus.DEPRECATED, parsed.productionMetadata().deprecationStatus());
    assertEquals(
        "Use Sample App Stable.", parsed.productionMetadata().deprecationMessage().orElseThrow());
    assertEquals("sample-app-stable", parsed.productionMetadata().replacementAppId().orElseThrow());
    assertEquals(
        "CRYPTA-2026-0001", parsed.productionMetadata().securityAdvisories().getFirst().id());
  }

  private static void assertMaintenanceMetadata(AppCatalogMaintenanceMetadata maintenance) {
    assertEquals("crypta-core", maintenance.owner().orElseThrow());
    assertEquals(
        "https://example.invalid/crypta/owners/core",
        maintenance.ownerUri().orElseThrow().toString());
    assertEquals(
        AppCatalogMaintenanceMetadata.SupportLevel.CORE, maintenance.supportLevel().orElseThrow());
    assertEquals(
        AppCatalogMaintenanceMetadata.DataSchemaPolicy.STATELESS,
        maintenance.dataSchemaPolicy().orElseThrow());
    assertEquals(
        AppCatalogMaintenanceMetadata.MigrationPolicy.NONE,
        maintenance.migrationPolicy().orElseThrow());
    assertEquals(
        AppCatalogMaintenanceMetadata.BackupRestoreSupport.NOT_APPLICABLE,
        maintenance.backupRestore().orElseThrow());
    assertEquals(
        AppCatalogMaintenanceMetadata.SecurityPolicy.CATALOG_ADVISORIES,
        maintenance.securityPolicy().orElseThrow());
    assertEquals(
        AppCatalogMaintenanceMetadata.DeprecationPolicy.NONE,
        maintenance.deprecationPolicy().orElseThrow());
    assertEquals(
        "https://example.invalid/crypta/apps/sample-app/support",
        maintenance.supportUri().orElseThrow().toString());
  }

  private static void assertApiCompatibility(AppCatalogEntryDescriptor parsed) {
    assertEquals(Integer.valueOf(1), parsed.compatibility().apiCompatibility().minimumVersion());
    assertEquals(
        Integer.valueOf(2), parsed.compatibility().apiCompatibility().maximumTestedVersion());
    assertEquals(
        List.of("alerts.read", "diagnostics.read"),
        parsed.compatibility().apiCompatibility().optionalCapabilities());
    assertEquals(
        network.crypta.platform.appdist.AppApiCompatibilityMetadata.TargetStability.EXPERIMENTAL,
        parsed.compatibility().apiCompatibility().targetStability());
    assertTrue(parsed.compatibility().apiCompatibility().targetStabilityDeclared());
    assertEquals("1.1", parsed.compatibility().apiCompatibility().targetBaseline());
    assertTrue(parsed.compatibility().apiCompatibility().targetBaselineDeclared());
    assertTrue(parsed.compatibility().apiCompatibility().experimentalCapabilitiesAccepted());
    assertTrue(
        parsed.compatibility().apiCompatibility().experimentalCapabilitiesAcceptedDeclared());
  }

  private static void assertReviewMetadata(AppCatalogEntryDescriptor parsed) {
    assertEquals(AppCatalogReviewStatus.REVIEWED, parsed.review().status());
    assertEquals("Reviewed for local operator safety.", parsed.review().note().orElseThrow());
    assertEquals(Optional.of(List.of()), parsed.permissionsOverride());
    assertEquals(
        "Reads the local transfer queue.", parsed.permissionRationales().get("queue.read"));
  }

  private static void assertStoreMedia(AppCatalogEntryDescriptor parsed) {
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
    assertEquals(AppCatalogMaintenanceMetadata.EMPTY, parsed.maintenanceMetadata());
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

  @ParameterizedTest(name = "{0}")
  @MethodSource("invalidDescriptorCases")
  void parse_whenInvalidDescriptorPropertyIsDeclared_expectInvalidCatalogEntry(
      String caseName, String[] extraProperties) throws Exception {
    Path descriptor = descriptor(descriptorPropertiesWith(extraProperties));

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> AppCatalogEntryDescriptor.parse(descriptor));

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_ENTRY, exception.errorCode(), caseName);
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

  private String[] descriptorPropertiesWith(String... extraProperties) {
    return Stream.concat(
            Stream.of(
                "artifact.path=" + tempDir.resolve("sample-app.zip").toAbsolutePath().normalize(),
                "bundle.uri=https://example.invalid/apps/sample-app.zip",
                "summary=Sample app catalog entry"),
            Stream.of(extraProperties))
        .toArray(String[]::new);
  }

  private static Stream<Arguments> invalidDescriptorCases() {
    return Stream.of(
        invalidDescriptorCase("metadata URI uses file scheme", "homepage=file:///tmp/sample-app"),
        invalidDescriptorCase("channel is unsupported", "channel=preview"),
        invalidDescriptorCase("target baseline is aliased", "api.targetBaseline=1.01"),
        invalidDescriptorCase(
            "maintenance support level is unsupported",
            "maintenance.owner=crypta-core",
            "maintenance.supportLevel=forever",
            "maintenance.dataSchemaPolicy=stateless",
            "maintenance.migrationPolicy=none",
            "maintenance.backupRestore=not-applicable",
            "maintenance.securityPolicy=catalog-advisories",
            "maintenance.deprecationPolicy=none"),
        invalidDescriptorCase(
            "maintenance owner URI uses unsafe scheme",
            "maintenance.owner=crypta-core",
            "maintenance.ownerUri=file:///tmp/owner",
            "maintenance.supportLevel=core",
            "maintenance.dataSchemaPolicy=stateless",
            "maintenance.migrationPolicy=none",
            "maintenance.backupRestore=not-applicable",
            "maintenance.securityPolicy=catalog-advisories",
            "maintenance.deprecationPolicy=none"));
  }

  private static Arguments invalidDescriptorCase(String caseName, String... extraProperties) {
    return Arguments.of(caseName, extraProperties);
  }

  private static String lines(String... values) {
    return String.join("\n", values) + "\n";
  }
}

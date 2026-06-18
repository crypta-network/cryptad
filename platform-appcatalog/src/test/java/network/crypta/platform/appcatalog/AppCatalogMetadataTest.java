package network.crypta.platform.appcatalog;

import java.net.URI;
import java.util.Optional;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class AppCatalogMetadataTest {
  @Test
  void parse_whenReviewStatusUsesMixedCaseAndWhitespace_expectNormalizedStatus() {
    AppCatalogReviewStatus status = AppCatalogReviewStatus.parse(" Reviewed ", "review.status");

    assertEquals(AppCatalogReviewStatus.REVIEWED, status);
    assertEquals("reviewed", status.catalogValue());
  }

  @Test
  void parse_whenReviewStatusIsUnsupported_expectInvalidCatalogEntry() {
    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class,
            () -> AppCatalogReviewStatus.parse("trusted", "review.status"));

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_ENTRY, exception.errorCode());
  }

  @Test
  void hasCatalogFields_whenReviewIsDefault_expectFalse() {
    assertFalse(AppCatalogReviewMetadata.EMPTY.hasCatalogFields());
  }

  @Test
  void hasCatalogFields_whenReviewHasNote_expectTrue() {
    AppCatalogReviewMetadata review =
        new AppCatalogReviewMetadata(AppCatalogReviewStatus.UNREVIEWED, "Review pending.");

    assertTrue(review.hasCatalogFields());
    assertEquals("Review pending.", review.note().orElseThrow());
  }

  @Test
  void reviewMetadata_whenNoteIsBlank_expectInvalidCatalogEntry() {
    String blankNote = "   ";

    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class,
            () -> new AppCatalogReviewMetadata(AppCatalogReviewStatus.CAUTION, blankNote));

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_ENTRY, exception.errorCode());
  }

  @Test
  void isEmpty_whenChangelogHasNoFields_expectTrue() {
    assertTrue(AppCatalogChangelog.EMPTY.isEmpty());
  }

  @Test
  void isEmpty_whenChangelogHasSummary_expectFalse() {
    AppCatalogChangelog changelog =
        new AppCatalogChangelog(Optional.of("Adds queue retry controls."), Optional.empty());

    assertFalse(changelog.isEmpty());
  }

  @Test
  void changelog_whenUriHasFragment_expectInvalidCatalogEntry() {
    Optional<String> noSummary = Optional.empty();
    Optional<URI> fragmentUri =
        Optional.of(URI.create("https://example.invalid/changelog.txt#section"));

    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class, () -> new AppCatalogChangelog(noSummary, fragmentUri));

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_ENTRY, exception.errorCode());
  }

  @Test
  void compatibilityMetadata_whenVersionIsTooLong_expectInvalidCatalogEntry() {
    String oversizedVersion = "1".repeat(97);

    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class, () -> new AppCatalogCompatibilityMetadata(oversizedVersion));

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_ENTRY, exception.errorCode());
  }

  @Test
  void parse_whenProductionMetadataUsesMixedCase_expectNormalizedEnums() {
    AppCatalogProductionMetadata metadata =
        new AppCatalogProductionMetadata(
            AppCatalogChannel.parse(" Beta ", "channel"),
            AppCatalogSupportStatus.parse(" Maintenance ", "support.status"),
            AppCatalogDeprecationStatus.parse(" None ", "deprecation.status"),
            Optional.empty(),
            Optional.empty(),
            java.util.List.of(),
            true);

    assertEquals(AppCatalogChannel.BETA, metadata.channel());
    assertEquals(AppCatalogSupportStatus.MAINTENANCE, metadata.supportStatus());
    assertEquals(AppCatalogDeprecationStatus.NONE, metadata.deprecationStatus());
    assertTrue(metadata.hasCatalogFields());
  }

  @Test
  void parse_whenMaintenanceMetadataUsesMixedCase_expectNormalizedEnums() {
    AppCatalogMaintenanceMetadata metadata =
        new AppCatalogMaintenanceMetadata(
            Optional.of(" crypta-core "),
            Optional.of(URI.create("https://example.invalid/crypta/owners/core")),
            Optional.of(
                AppCatalogMaintenanceMetadata.SupportLevel.parse(
                    " Core ", "maintenance.supportLevel")),
            Optional.of(
                AppCatalogMaintenanceMetadata.DataSchemaPolicy.parse(
                    " Stateless ", "maintenance.dataSchemaPolicy")),
            Optional.of(
                AppCatalogMaintenanceMetadata.MigrationPolicy.parse(
                    " None ", "maintenance.migrationPolicy")),
            Optional.of(
                AppCatalogMaintenanceMetadata.BackupRestoreSupport.parse(
                    " Not-Applicable ", "maintenance.backupRestore")),
            Optional.of(
                AppCatalogMaintenanceMetadata.SecurityPolicy.parse(
                    " Catalog-Advisories ", "maintenance.securityPolicy")),
            Optional.of(
                AppCatalogMaintenanceMetadata.DeprecationPolicy.parse(
                    " None ", "maintenance.deprecationPolicy")),
            Optional.of(URI.create("https://example.invalid/crypta/apps/queue-manager/support")),
            true);

    assertEquals("crypta-core", metadata.owner().orElseThrow());
    assertEquals(
        AppCatalogMaintenanceMetadata.SupportLevel.CORE, metadata.supportLevel().orElseThrow());
    assertEquals(
        AppCatalogMaintenanceMetadata.DataSchemaPolicy.STATELESS,
        metadata.dataSchemaPolicy().orElseThrow());
    assertTrue(metadata.hasCatalogFields());
  }

  @Test
  void maintenanceMetadata_whenDeclaredWithoutOptionalUris_expectDeclaredMetadata() {
    AppCatalogMaintenanceMetadata metadata =
        new AppCatalogMaintenanceMetadata(
            Optional.of("crypta-core"),
            Optional.empty(),
            Optional.of(AppCatalogMaintenanceMetadata.SupportLevel.CORE),
            Optional.of(AppCatalogMaintenanceMetadata.DataSchemaPolicy.STATELESS),
            Optional.of(AppCatalogMaintenanceMetadata.MigrationPolicy.NONE),
            Optional.of(AppCatalogMaintenanceMetadata.BackupRestoreSupport.NOT_APPLICABLE),
            Optional.of(AppCatalogMaintenanceMetadata.SecurityPolicy.CATALOG_ADVISORIES),
            Optional.of(AppCatalogMaintenanceMetadata.DeprecationPolicy.NONE),
            Optional.empty(),
            true);

    assertTrue(metadata.hasCatalogFields());
    assertTrue(metadata.ownerUri().isEmpty());
    assertTrue(metadata.supportUri().isEmpty());
  }

  @Test
  void maintenanceMetadata_whenOnlyOptionalUriIsDeclared_expectInvalidCatalogEntry() {
    Optional<String> noOwner = Optional.empty();
    Optional<URI> ownerUri = Optional.of(URI.create("https://example.invalid/crypta/owners/core"));
    Optional<AppCatalogMaintenanceMetadata.SupportLevel> noSupportLevel = Optional.empty();
    Optional<AppCatalogMaintenanceMetadata.DataSchemaPolicy> noDataSchemaPolicy = Optional.empty();
    Optional<AppCatalogMaintenanceMetadata.MigrationPolicy> noMigrationPolicy = Optional.empty();
    Optional<AppCatalogMaintenanceMetadata.BackupRestoreSupport> noBackupRestore = Optional.empty();
    Optional<AppCatalogMaintenanceMetadata.SecurityPolicy> noSecurityPolicy = Optional.empty();
    Optional<AppCatalogMaintenanceMetadata.DeprecationPolicy> noDeprecationPolicy =
        Optional.empty();
    Optional<URI> noSupportUri = Optional.empty();

    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class,
            () ->
                new AppCatalogMaintenanceMetadata(
                    noOwner,
                    ownerUri,
                    noSupportLevel,
                    noDataSchemaPolicy,
                    noMigrationPolicy,
                    noBackupRestore,
                    noSecurityPolicy,
                    noDeprecationPolicy,
                    noSupportUri,
                    false));

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_ENTRY, exception.errorCode());
    assertTrue(exception.getMessage().contains("maintenance.owner is required"));
  }

  @Test
  void maintenanceMetadata_whenOwnerIsMultiline_expectInvalidCatalogEntry() {
    Optional<String> multilineOwner = Optional.of("crypta-core\nextra");
    Optional<URI> noOwnerUri = Optional.empty();
    Optional<AppCatalogMaintenanceMetadata.SupportLevel> supportLevel =
        Optional.of(AppCatalogMaintenanceMetadata.SupportLevel.CORE);
    Optional<AppCatalogMaintenanceMetadata.DataSchemaPolicy> dataSchemaPolicy =
        Optional.of(AppCatalogMaintenanceMetadata.DataSchemaPolicy.STATELESS);
    Optional<AppCatalogMaintenanceMetadata.MigrationPolicy> migrationPolicy =
        Optional.of(AppCatalogMaintenanceMetadata.MigrationPolicy.NONE);
    Optional<AppCatalogMaintenanceMetadata.BackupRestoreSupport> backupRestore =
        Optional.of(AppCatalogMaintenanceMetadata.BackupRestoreSupport.NOT_APPLICABLE);
    Optional<AppCatalogMaintenanceMetadata.SecurityPolicy> securityPolicy =
        Optional.of(AppCatalogMaintenanceMetadata.SecurityPolicy.CATALOG_ADVISORIES);
    Optional<AppCatalogMaintenanceMetadata.DeprecationPolicy> deprecationPolicy =
        Optional.of(AppCatalogMaintenanceMetadata.DeprecationPolicy.NONE);
    Optional<URI> noSupportUri = Optional.empty();

    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class,
            () ->
                new AppCatalogMaintenanceMetadata(
                    multilineOwner,
                    noOwnerUri,
                    supportLevel,
                    dataSchemaPolicy,
                    migrationPolicy,
                    backupRestore,
                    securityPolicy,
                    deprecationPolicy,
                    noSupportUri,
                    true));

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_ENTRY, exception.errorCode());
  }

  @Test
  void securityAdvisory_whenIdContainsSpaces_expectInvalidCatalogEntry() {
    URI advisoryUri = URI.create("https://example.invalid/advisory");

    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class,
            () -> new AppCatalogSecurityAdvisory("CRYPTA 2026 0001", advisoryUri));

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_ENTRY, exception.errorCode());
  }
}

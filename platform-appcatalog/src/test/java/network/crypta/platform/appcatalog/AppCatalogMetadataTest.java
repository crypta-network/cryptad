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
        new AppCatalogReviewMetadata(
            AppCatalogReviewStatus.UNREVIEWED, Optional.of("Review pending."));

    assertTrue(review.hasCatalogFields());
    assertEquals("Review pending.", review.note().orElseThrow());
  }

  @Test
  void reviewMetadata_whenNoteIsBlank_expectInvalidCatalogEntry() {
    Optional<String> blankNote = Optional.of("   ");

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
  void securityAdvisory_whenIdContainsSpaces_expectInvalidCatalogEntry() {
    URI advisoryUri = URI.create("https://example.invalid/advisory");

    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class,
            () -> new AppCatalogSecurityAdvisory("CRYPTA 2026 0001", advisoryUri));

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_ENTRY, exception.errorCode());
  }
}

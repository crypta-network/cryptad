package network.crypta.platform.api.appcatalogs;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.appcatalog.AppCatalogChangelog;
import network.crypta.platform.appcatalog.AppCatalogChannel;
import network.crypta.platform.appcatalog.AppCatalogCompatibilityMetadata;
import network.crypta.platform.appcatalog.AppCatalogDeprecationStatus;
import network.crypta.platform.appcatalog.AppCatalogEntry;
import network.crypta.platform.appcatalog.AppCatalogException;
import network.crypta.platform.appcatalog.AppCatalogFetchStatus;
import network.crypta.platform.appcatalog.AppCatalogInstallPlan;
import network.crypta.platform.appcatalog.AppCatalogMaintenanceMetadata;
import network.crypta.platform.appcatalog.AppCatalogManager;
import network.crypta.platform.appcatalog.AppCatalogProductionMetadata;
import network.crypta.platform.appcatalog.AppCatalogReviewMetadata;
import network.crypta.platform.appcatalog.AppCatalogReviewStatus;
import network.crypta.platform.appcatalog.AppCatalogSecurityAction;
import network.crypta.platform.appcatalog.AppCatalogSecurityAdvisory;
import network.crypta.platform.appcatalog.AppCatalogSecurityDecision;
import network.crypta.platform.appcatalog.AppCatalogSecurityDecisionStatus;
import network.crypta.platform.appcatalog.AppCatalogSecuritySeverity;
import network.crypta.platform.appcatalog.AppCatalogSourceSnapshot;
import network.crypta.platform.appcatalog.AppCatalogSupportStatus;
import network.crypta.platform.appcatalog.AppReviewPolicy;
import network.crypta.platform.appcatalog.AppReviewPolicyMode;
import network.crypta.platform.appcatalog.AppReviewReceipt;
import network.crypta.platform.appcatalog.AppReviewReceiptPayload;
import network.crypta.platform.appcatalog.AppReviewReceiptSigner;
import network.crypta.platform.appcatalog.AppReviewReceiptStatus;
import network.crypta.platform.appcatalog.AppReviewTransparencyEventKind;
import network.crypta.platform.appcatalog.AppReviewTransparencyLog;
import network.crypta.platform.appcatalog.RecommendedAppCatalog;
import network.crypta.platform.appcatalog.RecommendedAppCatalogs;
import network.crypta.platform.appcatalog.TrustedReviewerKey;
import network.crypta.platform.appcatalog.TrustedReviewerKeys;
import network.crypta.platform.appdist.AppUiMode;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.InstalledAppPaths;
import network.crypta.platform.apphost.InstalledAppSnapshot;
import network.crypta.platform.apphost.manifest.AppManifest;
import network.crypta.platform.appvault.AppIdentityGrant;
import network.crypta.platform.appvault.AppIdentityGrantScope;
import network.crypta.platform.appvault.AppIdentityGrantStatus;
import network.crypta.platform.appvault.AppIdentityKind;
import network.crypta.platform.appvault.AppIdentityRecord;
import network.crypta.platform.appvault.AppVaultService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings({"java:S100", "unchecked", "resource"})
class AppCatalogsApiHandlerTest {
  private static final String APP_ID = "queue-manager";
  private static final String REVIEWER_KEY_ID = "crypta-first-party-review";
  private static final String REVIEW_POLICY_ID = "crypta-app-review-v1";
  private static final String REVIEW_POLICY_VERSION = "1";
  private static final String FIRST_PARTY_SOURCE =
      "crypta:USK@example/catalog/cryptad-app-catalog.properties";
  private static final String FIRST_PARTY_TRUSTED_KEY_ID = "first-party-catalog";
  private static final Instant REVIEWED_AT = Instant.parse("2026-05-01T00:00:00Z");

  @Mock private AppCatalogManager catalogManager;
  @Mock private AppHost appHost;

  @TempDir private Path tempDir;

  @Test
  void listCatalogs_whenSnapshotHasSourceUri_expectSourceKindAndSyncFields() throws Exception {
    AppCatalogsApiHandler handler = new AppCatalogsApiHandler(catalogManager, appHost, () -> null);
    Instant generatedAt = Instant.parse("2026-04-24T12:00:00Z");
    Instant addedAt = Instant.parse("2026-04-24T12:01:00Z");
    Instant refreshedAt = Instant.parse("2026-04-24T12:02:00Z");
    AppCatalogSourceSnapshot snapshot =
        new AppCatalogSourceSnapshot(
            "core",
            "Core Apps",
            URI.create("https://example.invalid/cryptad-app-catalog.properties"),
            generatedAt,
            2,
            addedAt,
            refreshedAt,
            refreshedAt,
            refreshedAt,
            AppCatalogFetchStatus.SUCCESS,
            Optional.empty(),
            Optional.empty(),
            Optional.of("https://example.invalid/cryptad-app-catalog.properties"),
            Optional.of("core-catalog-key"));
    when(catalogManager.listCatalogs()).thenReturn(List.of(snapshot));

    Map<String, Object> catalog = handler.listCatalogs().getFirst();

    assertEquals("core", catalog.get("catalogId"));
    assertEquals("Core Apps", catalog.get("name"));
    assertEquals("https://example.invalid/cryptad-app-catalog.properties", catalog.get("source"));
    assertEquals("https", catalog.get("sourceType"));
    assertEquals("https", catalog.get("sourceKind"));
    assertEquals(generatedAt.toString(), catalog.get("generatedAt"));
    assertEquals(2, catalog.get("appCount"));
    assertEquals(addedAt.toString(), catalog.get("addedAt"));
    assertEquals(refreshedAt.toString(), catalog.get("refreshedAt"));
    assertEquals(refreshedAt.toString(), catalog.get("lastAttemptAt"));
    assertEquals(refreshedAt.toString(), catalog.get("lastSuccessfulRefreshAt"));
    assertEquals("success", catalog.get("lastFetchStatus"));
    assertNull(catalog.get("lastFetchErrorCode"));
    assertNull(catalog.get("lastFetchErrorMessage"));
    assertEquals(
        "https://example.invalid/cryptad-app-catalog.properties", catalog.get("lastResolvedUri"));
    assertEquals("core-catalog-key", catalog.get("signatureKeyId"));
  }

  @Test
  void listRecommendedCatalogs_whenSourceAndTrustedKeyAreMissing_expectNotConfiguredStatus()
      throws Exception {
    AppCatalogsApiHandler handler = handlerWithRecommended(List.of(recommended(null, null)));
    when(catalogManager.listCatalogs()).thenReturn(List.of());

    Map<String, Object> catalog = handler.listRecommendedCatalogs().getFirst();

    assertEquals(RecommendedAppCatalogs.FIRST_PARTY_BETA_CATALOG_ID, catalog.get("catalogId"));
    assertEquals("Crypta First-Party Beta Catalog", catalog.get("name"));
    assertEquals("beta", catalog.get("channel"));
    assertNull(catalog.get("sourceKind"));
    assertNull(catalog.get("source"));
    assertEquals(false, catalog.get("sourceConfigured"));
    assertEquals(false, catalog.get("configured"));
    assertEquals(false, catalog.get("trustedCatalogKeyConfigured"));
    assertEquals(false, catalog.get("canAdd"));
    assertEquals(List.of("source", "trusted_catalog_key"), catalog.get("missingConfiguration"));
  }

  @Test
  void listRecommendedCatalogs_whenConfiguredAndTrusted_expectCanAddAndRedactedSource()
      throws Exception {
    AppCatalogsApiHandler handler =
        handlerWithRecommended(
            List.of(recommended(FIRST_PARTY_SOURCE, FIRST_PARTY_TRUSTED_KEY_ID)));
    when(catalogManager.listCatalogs()).thenReturn(List.of());
    when(catalogManager.hasTrustedCatalogKey(FIRST_PARTY_TRUSTED_KEY_ID)).thenReturn(true);

    Map<String, Object> catalog = handler.listRecommendedCatalogs().getFirst();

    assertEquals("crypta", catalog.get("sourceKind"));
    assertEquals("crypta:<configured>", catalog.get("source"));
    assertEquals(true, catalog.get("sourceConfigured"));
    assertEquals(true, catalog.get("trustedCatalogKeyConfigured"));
    assertEquals(true, catalog.get("canAdd"));
    assertEquals(List.of(), catalog.get("missingConfiguration"));
    assertFalse(catalog.toString().contains("USK@example"));
  }

  @Test
  void listRecommendedCatalogs_whenHttpsSourceHasQuery_expectQueryRedacted() throws Exception {
    String sourceWithToken =
        "https://example.invalid/cryptad-app-catalog.properties?token=secret-value";
    AppCatalogsApiHandler handler =
        handlerWithRecommended(List.of(recommended(sourceWithToken, FIRST_PARTY_TRUSTED_KEY_ID)));
    when(catalogManager.listCatalogs()).thenReturn(List.of());
    when(catalogManager.hasTrustedCatalogKey(FIRST_PARTY_TRUSTED_KEY_ID)).thenReturn(true);

    Map<String, Object> catalog = handler.listRecommendedCatalogs().getFirst();

    assertEquals("https", catalog.get("sourceKind"));
    assertTrue(((String) catalog.get("source")).contains("redacted"));
    assertFalse(catalog.toString().contains("secret-value"));
    assertFalse(catalog.toString().contains("token"));
  }

  @Test
  void listRecommendedCatalogs_whenFileSourceConfigured_expectPathRedacted() throws Exception {
    String source = tempDir.resolve("private/catalog.properties").toUri().toString();
    AppCatalogsApiHandler handler =
        handlerWithRecommended(List.of(recommended(source, FIRST_PARTY_TRUSTED_KEY_ID)));
    when(catalogManager.listCatalogs()).thenReturn(List.of());
    when(catalogManager.hasTrustedCatalogKey(FIRST_PARTY_TRUSTED_KEY_ID)).thenReturn(true);

    Map<String, Object> catalog = handler.listRecommendedCatalogs().getFirst();

    assertEquals("file", catalog.get("sourceKind"));
    assertEquals("file:<configured>", catalog.get("source"));
    assertFalse(catalog.toString().contains("catalog.properties"));
  }

  @Test
  void listRecommendedCatalogs_whenTrustedKeyLookupFails_expectMissingTrustedKeyStatus()
      throws Exception {
    AppCatalogsApiHandler handler =
        handlerWithRecommended(
            List.of(recommended(FIRST_PARTY_SOURCE, FIRST_PARTY_TRUSTED_KEY_ID)));
    when(catalogManager.listCatalogs()).thenReturn(List.of());
    when(catalogManager.hasTrustedCatalogKey(FIRST_PARTY_TRUSTED_KEY_ID))
        .thenThrow(new IOException("trusted key store unavailable"));

    Map<String, Object> catalog = handler.listRecommendedCatalogs().getFirst();

    assertEquals(false, catalog.get("trustedCatalogKeyConfigured"));
    assertEquals(false, catalog.get("canAdd"));
    assertEquals(List.of("trusted_catalog_key"), catalog.get("missingConfiguration"));
    assertEquals(List.of("missing_trusted_catalog_key"), catalog.get("warnings"));
  }

  @Test
  void addRecommended_whenConfigurationIsReady_expectVerifiedAddSourceAndNoInstall()
      throws Exception {
    AppCatalogsApiHandler handler =
        handlerWithRecommended(
            List.of(recommended(FIRST_PARTY_SOURCE, FIRST_PARTY_TRUSTED_KEY_ID)));
    AppCatalogSourceSnapshot snapshot = firstPartyCatalogSnapshot();
    when(catalogManager.listCatalogs()).thenReturn(List.of());
    when(catalogManager.hasTrustedCatalogKey(FIRST_PARTY_TRUSTED_KEY_ID)).thenReturn(true);
    when(catalogManager.addSource(
            FIRST_PARTY_SOURCE, RecommendedAppCatalogs.FIRST_PARTY_BETA_CATALOG_ID))
        .thenReturn(snapshot);

    Map<String, Object> catalog =
        handler.addRecommended(RecommendedAppCatalogs.FIRST_PARTY_BETA_CATALOG_ID);

    assertEquals(RecommendedAppCatalogs.FIRST_PARTY_BETA_CATALOG_ID, catalog.get("catalogId"));
    verify(catalogManager)
        .addSource(FIRST_PARTY_SOURCE, RecommendedAppCatalogs.FIRST_PARTY_BETA_CATALOG_ID);
    verify(appHost, never()).installFromDirectory(any());
  }

  @Test
  void addRecommended_whenSourceIsMissing_expectStableSourceMissingError() {
    AppCatalogsApiHandler handler = handlerWithRecommended(List.of(recommended(null, null)));

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class,
            () -> handler.addRecommended(RecommendedAppCatalogs.FIRST_PARTY_BETA_CATALOG_ID));

    assertEquals(400, exception.statusCode());
    assertEquals("recommended_catalog_source_missing", exception.errorCode());
  }

  @Test
  void addRecommended_whenTrustedKeyIsMissing_expectStableTrustedKeyError() throws Exception {
    AppCatalogsApiHandler handler =
        handlerWithRecommended(
            List.of(recommended(FIRST_PARTY_SOURCE, FIRST_PARTY_TRUSTED_KEY_ID)));
    when(catalogManager.listCatalogs()).thenReturn(List.of());
    when(catalogManager.hasTrustedCatalogKey(FIRST_PARTY_TRUSTED_KEY_ID)).thenReturn(false);

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class,
            () -> handler.addRecommended(RecommendedAppCatalogs.FIRST_PARTY_BETA_CATALOG_ID));

    assertEquals(400, exception.statusCode());
    assertEquals("recommended_catalog_trusted_key_missing", exception.errorCode());
    verify(catalogManager, never()).addSource(any(), any());
  }

  @Test
  void addRecommended_whenAlreadyConfigured_expectStableAlreadyConfiguredError() throws Exception {
    AppCatalogsApiHandler handler =
        handlerWithRecommended(
            List.of(recommended(FIRST_PARTY_SOURCE, FIRST_PARTY_TRUSTED_KEY_ID)));
    when(catalogManager.listCatalogs()).thenReturn(List.of(firstPartyCatalogSnapshot()));

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class,
            () -> handler.addRecommended(RecommendedAppCatalogs.FIRST_PARTY_BETA_CATALOG_ID));

    assertEquals(409, exception.statusCode());
    assertEquals("recommended_catalog_already_configured", exception.errorCode());
    verify(catalogManager, never()).addSource(any(), any());
  }

  @Test
  void addRecommended_whenIdIsUnknown_expectStableNotFoundError() {
    AppCatalogsApiHandler handler = handlerWithRecommended(List.of(recommended(null, null)));

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> handler.addRecommended("unknown"));

    assertEquals(404, exception.statusCode());
    assertEquals("recommended_catalog_not_found", exception.errorCode());
  }

  @Test
  void listCatalogs_whenCatalogSourceOrFetchFails_expectStableStatusCodes() throws Exception {
    assertCatalogFailureStatus("unsupported_catalog_source", 400);
    assertCatalogFailureStatus("invalid_catalog_source", 400);
    assertCatalogFailureStatus("catalog_fetch_unavailable", 503);
    assertCatalogFailureStatus("catalog_fetch_failed", 502);
    assertCatalogFailureStatus("invalid_catalog_signature", 400);
    assertCatalogFailureStatus("catalog_signature_missing", 400);
  }

  @Test
  void listApps_whenEntryHasStoreMetadataAndInstalledAppDiffers_expectReviewMetadata()
      throws Exception {
    Map<String, Object> app = listRichInstalledCatalogApp();

    assertEquals(
        Map.of(
            "appId",
            APP_ID,
            "version",
            "1.2.0",
            "installedVersion",
            "1.1.0",
            "installed",
            true,
            "versionDifferent",
            true,
            "updateAvailable",
            true,
            "versionStatus",
            "different"),
        fields(
            app,
            "appId",
            "version",
            "installedVersion",
            "installed",
            "versionDifferent",
            "updateAvailable",
            "versionStatus"));
    assertEquals(
        Map.of(
            "categories",
            List.of("productivity", "network"),
            "homepage",
            "https://example.invalid/app",
            "source",
            "https://example.invalid/repo",
            "license",
            "MIT",
            "channel",
            "beta",
            "supportStatus",
            "experimental"),
        fields(app, "categories", "homepage", "source", "license", "channel", "supportStatus"));
    Map<String, Object> maintenance = (Map<String, Object>) app.get("maintenance");
    assertEquals(
        Map.of(
            "owner",
            "crypta-core",
            "ownerUri",
            "https://example.invalid/crypta/owners/core",
            "supportLevel",
            "core",
            "dataSchemaPolicy",
            "stateless",
            "migrationPolicy",
            "none",
            "backupRestore",
            "not-applicable",
            "securityPolicy",
            "catalog-advisories",
            "deprecationPolicy",
            "none",
            "supportUri",
            "https://example.invalid/crypta/apps/queue-manager/support"),
        maintenance);
    Map<String, Object> deprecation = (Map<String, Object>) app.get("deprecation");
    assertEquals(
        Map.of(
            "status",
            "deprecated",
            "message",
            "Use Queue Manager stable.",
            "replacementAppId",
            "queue-manager-stable"),
        deprecation);
    List<Map<String, Object>> advisories =
        (List<Map<String, Object>>) app.get("securityAdvisories");
    assertEquals(
        List.of(
            Map.of(
                "id",
                "CRYPTA-2026-0001",
                "uri",
                "https://example.invalid/advisories/CRYPTA-2026-0001")),
        advisories);

    Map<String, Object> review = (Map<String, Object>) app.get("review");
    assertEquals(
        Map.of(
            "status", "reviewed", "note", "Reviewed for local operator safety.", "advisory", true),
        review);

    Map<String, Object> reviewTrust = (Map<String, Object>) app.get("reviewTrust");
    assertEquals(
        Map.of(
            "status",
            "publisher_claim_only",
            "trusted",
            false,
            "positive",
            false,
            "blocksInstall",
            false,
            "blocksUpdate",
            false),
        fields(reviewTrust, "status", "trusted", "positive", "blocksInstall", "blocksUpdate"));
    assertFalse(app.toString().contains("PUBLIC KEY"));

    Map<String, Object> rationales = (Map<String, Object>) app.get("permissionRationales");
    assertEquals(
        Map.of(
            "queue.read",
            "Reads the local transfer queue.",
            "queue.write",
            "Lets the app manage queue entries."),
        rationales);
  }

  @Test
  void listApps_whenEntryHasStoreMetadataAndInstalledAppDiffers_expectCompatibilityAndChangelog()
      throws Exception {
    Map<String, Object> app = listRichInstalledCatalogApp();

    Map<String, Object> compatibility = (Map<String, Object>) app.get("compatibility");
    assertEquals("0.1.0", compatibility.get("minimumCryptaVersion"));
    assertEquals("0.9.99", compatibility.get("maximumCryptaVersion"));
    assertEquals("0.2.0", compatibility.get("currentCryptaVersion"));
    assertEquals(true, compatibility.get("satisfied"));
    assertEquals(true, compatibility.get("advisory"));
    assertEquals("satisfied", compatibility.get("status"));
    Map<String, Object> changelog = (Map<String, Object>) app.get("changelog");
    assertEquals("Adds queue retry controls.", changelog.get("summary"));
    assertEquals("https://example.invalid/changelog.txt", changelog.get("uri"));
    assertEquals(List.of("https://example.invalid/shot-1.png"), app.get("screenshots"));
  }

  @Test
  void listApps_whenEntryHasStoreMetadataAndInstalledAppDiffers_expectPermissionDelta()
      throws Exception {
    Map<String, Object> app = listRichInstalledCatalogApp();

    Map<String, Object> delta = (Map<String, Object>) app.get("permissionDelta");
    assertEquals(List.of("queue.write"), delta.get("added"));
    assertEquals(List.of("network.access"), delta.get("removed"));
    assertEquals(List.of("queue.read"), delta.get("unchanged"));
  }

  @Test
  void listApps_whenMinimalCatalogEntryIsNotInstalled_expectBackwardCompatibleApiMetadata()
      throws Exception {
    AppCatalogsApiHandler handler = new AppCatalogsApiHandler(catalogManager, appHost, () -> null);
    when(catalogManager.listApps("core")).thenReturn(List.of(minimalCatalogEntry()));
    when(appHost.describe(APP_ID)).thenReturn(Optional.empty());
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());

    Map<String, Object> app = handler.listApps("core").getFirst();

    assertNull(app.get("homepage"));
    assertNull(app.get("source"));
    assertNull(app.get("license"));
    assertEquals(List.of(), app.get("categories"));
    assertEquals("stable", app.get("channel"));
    assertEquals("supported", app.get("supportStatus"));
    Map<String, Object> maintenance = (Map<String, Object>) app.get("maintenance");
    assertNull(maintenance.get("owner"));
    assertNull(maintenance.get("supportLevel"));
    assertNull(maintenance.get("supportUri"));
    assertEquals("none", ((Map<?, ?>) app.get("deprecation")).get("status"));
    assertEquals(List.of(), app.get("securityAdvisories"));
    assertFalse((Boolean) app.get("installed"));
    assertEquals(false, app.get("versionDifferent"));
    assertEquals(false, app.get("updateAvailable"));
    assertEquals("not_installed", app.get("versionStatus"));

    Map<String, Object> review = (Map<String, Object>) app.get("review");
    assertEquals("unreviewed", review.get("status"));
    assertNull(review.get("note"));
    assertTrue((Boolean) review.get("advisory"));

    Map<String, Object> reviewTrust = (Map<String, Object>) app.get("reviewTrust");
    assertEquals("not_configured", reviewTrust.get("status"));
    assertEquals(false, reviewTrust.get("trusted"));

    Map<String, Object> compatibility = (Map<String, Object>) app.get("compatibility");
    assertNull(compatibility.get("minimumCryptaVersion"));
    assertNull(compatibility.get("maximumCryptaVersion"));
    assertNull(compatibility.get("currentCryptaVersion"));
    assertEquals(true, compatibility.get("satisfied"));
    assertEquals("not_declared", compatibility.get("status"));
  }

  @Test
  void listApps_whenCatalogSecurityDecisionExists_expectRedactedDecisionIncluded()
      throws Exception {
    AppCatalogsApiHandler handler = new AppCatalogsApiHandler(catalogManager, appHost, () -> null);
    when(catalogManager.listApps("core")).thenReturn(List.of(richCatalogEntry()));
    when(catalogManager.securityDecision("core", APP_ID)).thenReturn(denylistedSecurityDecision());
    when(appHost.describe(APP_ID)).thenReturn(Optional.empty());
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());

    Map<String, Object> app = handler.listApps("core").getFirst();

    Map<String, Object> securityDecision = (Map<String, Object>) app.get("securityDecision");
    assertEquals("denylisted", securityDecision.get("status"));
    assertEquals("denylist", securityDecision.get("action"));
    assertEquals("critical", securityDecision.get("severity"));
    assertEquals(List.of("CRYPTA-2026-0001"), securityDecision.get("advisoryIds"));
    assertEquals(true, securityDecision.get("blocksInstall"));
    assertFalse(securityDecision.toString().contains(tempDir.toString()));
  }

  @Test
  void listApps_whenTargetVersionDenylistedByConfiguredCatalog_expectRedactedDecisionIncluded()
      throws Exception {
    AppCatalogsApiHandler handler = new AppCatalogsApiHandler(catalogManager, appHost, () -> null);
    AppCatalogEntry entry = richCatalogEntry();
    when(catalogManager.listApps("core")).thenReturn(List.of(entry));
    when(catalogManager.installedSecurityDecision(APP_ID, entry.version()))
        .thenReturn(denylistedSecurityDecision());
    when(appHost.describe(APP_ID)).thenReturn(Optional.empty());
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());

    Map<String, Object> app = handler.listApps("core").getFirst();

    Map<String, Object> securityDecision = (Map<String, Object>) app.get("securityDecision");
    assertEquals("denylisted", securityDecision.get("status"));
    assertEquals("denylist", securityDecision.get("action"));
    assertEquals(true, securityDecision.get("blocksInstall"));
  }

  @Test
  void listApps_whenInstalledVersionAndPermissionsMatchCatalog_expectCurrentVersionReview()
      throws Exception {
    AppCatalogsApiHandler handler =
        new AppCatalogsApiHandler(catalogManager, appHost, () -> "1.2.0");
    when(catalogManager.listApps("core")).thenReturn(List.of(richCatalogEntry()));
    when(appHost.describe(APP_ID))
        .thenReturn(Optional.of(installedSnapshot("1.2.0", List.of("queue.read", "queue.write"))));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());

    Map<String, Object> app = handler.listApps("core").getFirst();

    assertEquals(false, app.get("versionDifferent"));
    assertEquals(false, app.get("updateAvailable"));
    assertEquals("current", app.get("versionStatus"));

    Map<String, Object> delta = (Map<String, Object>) app.get("permissionDelta");
    assertEquals(List.of(), delta.get("added"));
    assertEquals(List.of(), delta.get("removed"));
    assertEquals(List.of("queue.read", "queue.write"), delta.get("unchanged"));
  }

  @Test
  void listApps_whenInstalledVersionIsNewerThanCatalog_expectDifferenceWithoutUpdateAvailable()
      throws Exception {
    AppCatalogsApiHandler handler = new AppCatalogsApiHandler(catalogManager, appHost, () -> null);
    when(catalogManager.listApps("core")).thenReturn(List.of(catalogEntryWithVersion("1.2.0")));
    when(appHost.describe(APP_ID))
        .thenReturn(Optional.of(installedSnapshot("1.3.0", List.of("queue.read"))));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());

    Map<String, Object> app = handler.listApps("core").getFirst();

    assertEquals(true, app.get("versionDifferent"));
    assertEquals(false, app.get("updateAvailable"));
    assertEquals("different", app.get("versionStatus"));
  }

  @Test
  void listApps_whenDifferingVersionsAreNotComparable_expectUnknownUpdateAvailable()
      throws Exception {
    AppCatalogsApiHandler handler = new AppCatalogsApiHandler(catalogManager, appHost, () -> null);
    when(catalogManager.listApps("core")).thenReturn(List.of(catalogEntryWithVersion("1.2-beta")));
    when(appHost.describe(APP_ID))
        .thenReturn(Optional.of(installedSnapshot("1.1.0", List.of("queue.read"))));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());

    Map<String, Object> app = handler.listApps("core").getFirst();

    assertEquals(true, app.get("versionDifferent"));
    assertNull(app.get("updateAvailable"));
    assertEquals("different", app.get("versionStatus"));
  }

  @Test
  void listApps_whenMinimumVersionExceedsCurrentVersion_expectNotSatisfiedCompatibility()
      throws Exception {
    AppCatalogsApiHandler handler =
        new AppCatalogsApiHandler(catalogManager, appHost, () -> "1.2.0");
    when(catalogManager.listApps("core"))
        .thenReturn(List.of(catalogEntryWithMinimumCryptaVersion("1.3.0")));
    when(appHost.describe(APP_ID)).thenReturn(Optional.empty());
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());

    Map<String, Object> app = handler.listApps("core").getFirst();

    Map<String, Object> compatibility = (Map<String, Object>) app.get("compatibility");
    assertEquals("1.3.0", compatibility.get("minimumCryptaVersion"));
    assertEquals("1.2.0", compatibility.get("currentCryptaVersion"));
    assertEquals(false, compatibility.get("satisfied"));
    assertEquals("not_satisfied", compatibility.get("status"));
  }

  @Test
  void listApps_whenCurrentVersionSupplierFails_expectUnknownCompatibility() throws Exception {
    AppCatalogsApiHandler handler =
        new AppCatalogsApiHandler(
            catalogManager,
            appHost,
            () -> {
              throw new IllegalStateException("runtime unavailable");
            });
    when(catalogManager.listApps("core"))
        .thenReturn(List.of(catalogEntryWithMinimumCryptaVersion("1.0.0")));
    when(appHost.describe(APP_ID)).thenReturn(Optional.empty());
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());

    Map<String, Object> app = handler.listApps("core").getFirst();

    Map<String, Object> compatibility = (Map<String, Object>) app.get("compatibility");
    assertEquals("1.0.0", compatibility.get("minimumCryptaVersion"));
    assertNull(compatibility.get("currentCryptaVersion"));
    assertNull(compatibility.get("satisfied"));
    assertEquals("unknown", compatibility.get("status"));
  }

  @Test
  void governance_whenReviewRegistryAndTransparencyLogConfigured_expectRedactedStatus()
      throws Exception {
    KeyPair reviewerKeyPair = reviewerKeyPair();
    AppReviewTransparencyLog log = AppReviewTransparencyLog.inMemory();
    log.recordReviewTrustMap(
        AppReviewTransparencyEventKind.REVIEW_TRUST_EVALUATED,
        reviewTrustMapSubject("1.2.0", "0".repeat(64), 0L),
        trustedReviewTrustMap(),
        List.of("api-test"));
    when(catalogManager.reviewTransparencyLog()).thenReturn(log);
    AppCatalogsApiHandler handler =
        new AppCatalogsApiHandler(
            catalogManager,
            appHost,
            () -> null,
            AppReviewPolicy.DEFAULT,
            () -> trustedReviewerKeys(reviewerKeyPair));

    Map<String, Object> governance = handler.governance();

    assertEquals(AppReviewPolicy.DEFAULT.mode().jsonValue(), governance.get("reviewPolicyMode"));
    Map<String, Object> registry = (Map<String, Object>) governance.get("trustedReviewerRegistry");
    assertEquals(true, registry.get("configured"));
    Map<String, Object> counts = (Map<String, Object>) registry.get("counts");
    assertEquals(1, counts.get("active"));
    assertEquals(0, counts.get("retired"));
    assertEquals(0, counts.get("revoked"));
    Map<String, Object> transparency = (Map<String, Object>) governance.get("transparencyLog");
    assertEquals(true, transparency.get("configured"));
    assertEquals(1L, transparency.get("recordCount"));
    assertEquals(true, transparency.get("verified"));
    assertInstanceOf(String.class, transparency.get("latestRecordHash"));
    assertRedactsReviewerPublicKey(governance, reviewerKeyPair);
  }

  @Test
  void reviewerKeys_whenCalled_expectRedactedKeySummaries() throws Exception {
    KeyPair reviewerKeyPair = reviewerKeyPair();
    AppCatalogsApiHandler handler =
        new AppCatalogsApiHandler(
            catalogManager,
            appHost,
            () -> null,
            AppReviewPolicy.DEFAULT,
            () -> trustedReviewerKeys(reviewerKeyPair));

    Map<String, Object> response = handler.reviewerKeys();

    List<Map<String, Object>> keys = (List<Map<String, Object>>) response.get("keys");
    assertEquals(1, keys.size());
    Map<String, Object> key = keys.getFirst();
    assertEquals(REVIEWER_KEY_ID, key.get("keyId"));
    assertEquals("Crypta First-Party Review", key.get("displayName"));
    assertEquals("Ed25519", key.get("algorithm"));
    assertEquals("active", key.get("status"));
    assertEquals(REVIEW_POLICY_ID, key.get("policyId"));
    assertFalse(key.containsKey("publicKey"));
    assertFalse(key.containsKey("publicKeyBase64"));
    assertRedactsReviewerPublicKey(response, reviewerKeyPair);
  }

  @Test
  void transparencyLog_whenFilteredByKind_expectPagedRedactedRecords() {
    AppReviewTransparencyLog log = AppReviewTransparencyLog.inMemory();
    log.recordReviewTrustMap(
        AppReviewTransparencyEventKind.REVIEW_TRUST_EVALUATED,
        reviewTrustMapSubject("1.2.0", "0".repeat(64), 0L),
        trustedReviewTrustMap(),
        List.of("api-test"));
    log.recordReviewTrustMap(
        AppReviewTransparencyEventKind.REVIEW_GATE_INSTALL,
        reviewTrustMapSubject("1.2.0", "0".repeat(64), 0L),
        trustedReviewTrustMap(),
        List.of("phase=install"));
    when(catalogManager.reviewTransparencyLog()).thenReturn(log);
    AppCatalogsApiHandler handler =
        new AppCatalogsApiHandler(
            catalogManager,
            appHost,
            () -> null,
            AppReviewPolicy.DEFAULT,
            TrustedReviewerKeys::empty);

    Map<String, Object> page =
        handler.transparencyLog(
            Map.of("kind", List.of("review_gate_install"), "limit", List.of("1")));

    List<Map<String, Object>> records = (List<Map<String, Object>>) page.get("records");
    assertEquals(1, records.size());
    Map<String, Object> transparencyRecord = records.getFirst();
    assertEquals("review_gate_install", transparencyRecord.get("kind"));
    assertEquals(APP_ID, transparencyRecord.get("appId"));
    assertEquals("core", transparencyRecord.get("catalogId"));
    assertEquals("trusted_reviewed", transparencyRecord.get("trustStatus"));
    assertFalse(page.toString().contains(tempDir.toString()));
  }

  @Test
  void transparencyLog_whenKindIsInvalid_expectBadRequest() {
    AppCatalogsApiHandler handler =
        new AppCatalogsApiHandler(
            catalogManager,
            appHost,
            () -> null,
            AppReviewPolicy.DEFAULT,
            TrustedReviewerKeys::empty);
    Map<String, List<String>> invalidKindQuery = Map.of("kind", List.of("not-a-kind"));

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> handler.transparencyLog(invalidKindQuery));

    assertEquals(400, exception.statusCode());
    assertEquals("invalid_query_parameter", exception.errorCode());
  }

  @Test
  void reviewHistory_whenTrustedReceiptExists_expectTrustReviewerAndTransparencyHistory()
      throws Exception {
    KeyPair reviewerKeyPair = reviewerKeyPair();
    AppCatalogEntry entry = richCatalogEntryWithTrustedReceipt(reviewerKeyPair);
    AppReviewTransparencyLog log = AppReviewTransparencyLog.inMemory();
    log.recordReviewTrustMap(
        AppReviewTransparencyEventKind.REVIEW_TRUST_EVALUATED,
        reviewTrustMapSubject(entry.version(), entry.bundleSha256(), entry.bundleSizeBytes()),
        trustedReviewTrustMap(),
        List.of("api-test"));
    when(catalogManager.getApp("core", APP_ID)).thenReturn(entry);
    when(catalogManager.reviewTransparencyLog()).thenReturn(log);
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installedSnapshot()));
    AppCatalogsApiHandler handler =
        new AppCatalogsApiHandler(
            catalogManager,
            appHost,
            () -> null,
            AppReviewPolicy.DEFAULT,
            () -> trustedReviewerKeys(reviewerKeyPair));

    Map<String, Object> history = handler.reviewHistory("core", APP_ID);

    assertEquals("core", history.get("catalogId"));
    assertEquals(APP_ID, history.get("appId"));
    assertEquals("1.2.0", history.get("catalogVersion"));
    assertEquals("1.1.0", history.get("installedVersion"));
    Map<String, Object> reviewTrust = (Map<String, Object>) history.get("reviewTrust");
    assertEquals("trusted_reviewed", reviewTrust.get("status"));
    assertEquals(true, reviewTrust.get("trusted"));
    assertEquals(true, reviewTrust.get("positive"));
    assertEquals(REVIEWER_KEY_ID, reviewTrust.get("reviewerKeyId"));
    assertEquals("active", reviewTrust.get("reviewerKeyStatus"));
    assertEquals(REVIEW_POLICY_VERSION, reviewTrust.get("policyVersion"));
    Map<String, Object> reviewerKey = (Map<String, Object>) history.get("reviewerKey");
    assertNotNull(reviewerKey);
    assertEquals(REVIEWER_KEY_ID, reviewerKey.get("keyId"));
    assertEquals("active", reviewerKey.get("status"));
    Map<String, Object> transparency = (Map<String, Object>) history.get("transparencyLog");
    List<Map<String, Object>> records = (List<Map<String, Object>>) transparency.get("records");
    assertEquals(1, records.size());
    assertEquals("review_trust_evaluated", records.getFirst().get("kind"));
    Map<String, Object> delta = (Map<String, Object>) history.get("trustDelta");
    assertEquals(true, delta.get("versionChanged"));
    assertEquals("trusted_reviewed", delta.get("trustStatus"));
    assertRedactsReviewerPublicKey(history, reviewerKeyPair);
  }

  @Test
  void install_whenPolicyRequiresTrustedReviewAndReceiptIsMissing_expectStableReviewError()
      throws Exception {
    AppCatalogsApiHandler handler =
        new AppCatalogsApiHandler(
            catalogManager,
            appHost,
            () -> null,
            new AppReviewPolicy(AppReviewPolicyMode.REQUIRE_TRUSTED_REVIEW),
            TrustedReviewerKeys::empty);
    when(catalogManager.getApp("core", APP_ID)).thenReturn(richCatalogEntry());
    when(appHost.describe(APP_ID)).thenReturn(Optional.empty());

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> handler.install("core", APP_ID));

    assertEquals(409, exception.statusCode());
    assertEquals("app_review_missing", exception.errorCode());
    assertFalse(exception.getMessage().contains(tempDir.toString()));
  }

  @Test
  void install_whenCatalogSecurityDecisionIsDenylisted_expectStableSecurityError()
      throws Exception {
    AppCatalogsApiHandler handler = new AppCatalogsApiHandler(catalogManager, appHost, () -> null);
    when(catalogManager.getApp("core", APP_ID)).thenReturn(richCatalogEntry());
    when(catalogManager.securityDecision("core", APP_ID)).thenReturn(denylistedSecurityDecision());
    when(appHost.describe(APP_ID)).thenReturn(Optional.empty());

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> handler.install("core", APP_ID));

    assertEquals(409, exception.statusCode());
    assertEquals("app_security_denylisted", exception.errorCode());
    verify(catalogManager, never()).prepareInstallPlan(any(), any());
    verify(appHost, never()).installFromDirectory(any());
  }

  @Test
  void install_whenTargetVersionDenylistedByConfiguredCatalog_expectStableSecurityError()
      throws Exception {
    AppCatalogsApiHandler handler = new AppCatalogsApiHandler(catalogManager, appHost, () -> null);
    AppCatalogEntry entry = richCatalogEntry();
    when(catalogManager.getApp("core", APP_ID)).thenReturn(entry);
    when(catalogManager.installedSecurityDecision(APP_ID, entry.version()))
        .thenReturn(denylistedSecurityDecision());
    when(appHost.describe(APP_ID)).thenReturn(Optional.empty());

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> handler.install("core", APP_ID));

    assertEquals(409, exception.statusCode());
    assertEquals("app_security_denylisted", exception.errorCode());
    verify(catalogManager, never()).prepareInstallPlan(any(), any());
    verify(appHost, never()).installFromDirectory(any());
  }

  @Test
  void install_whenCatalogSecurityDecisionWarnsWithoutAcknowledgement_expectSecurityAckError()
      throws Exception {
    AppCatalogsApiHandler handler = new AppCatalogsApiHandler(catalogManager, appHost, () -> null);
    when(catalogManager.getApp("core", APP_ID)).thenReturn(richCatalogEntry());
    when(catalogManager.securityDecision("core", APP_ID)).thenReturn(warningSecurityDecision());
    when(appHost.describe(APP_ID)).thenReturn(Optional.empty());

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> handler.install("core", APP_ID));

    assertEquals(409, exception.statusCode());
    assertEquals("app_security_acknowledgement_required", exception.errorCode());
    verify(catalogManager, never()).prepareInstallPlan(any(), any());
    verify(appHost, never()).installFromDirectory(any());
  }

  @Test
  void update_whenTargetVersionDenylistedByConfiguredCatalog_expectStableSecurityError()
      throws Exception {
    AppCatalogsApiHandler handler = new AppCatalogsApiHandler(catalogManager, appHost, () -> null);
    AppCatalogEntry entry = richCatalogEntry();
    when(catalogManager.getApp("core", APP_ID)).thenReturn(entry);
    when(catalogManager.installedSecurityDecision(APP_ID, entry.version()))
        .thenReturn(denylistedSecurityDecision());
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installedSnapshot()));
    Map<String, List<String>> securityAcknowledgedQuery =
        Map.of("securityAcknowledged", List.of("true"));

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class,
            () -> handler.update("core", APP_ID, securityAcknowledgedQuery));

    assertEquals(409, exception.statusCode());
    assertEquals("app_security_denylisted", exception.errorCode());
    verify(catalogManager, never()).prepareInstallPlan(any(), any());
    verify(appHost, never()).updateFromDirectory(any(), any());
  }

  @Test
  void install_whenPreparedPlanLosesTrustedReview_expectPlanReviewGateBlocks() throws Exception {
    KeyPair reviewerKeyPair = reviewerKeyPair();
    AppCatalogsApiHandler handler =
        new AppCatalogsApiHandler(
            catalogManager,
            appHost,
            () -> null,
            new AppReviewPolicy(AppReviewPolicyMode.REQUIRE_TRUSTED_REVIEW),
            () -> trustedReviewerKeys(reviewerKeyPair));
    AppCatalogEntry trustedEntry = richCatalogEntryWithTrustedReceipt(reviewerKeyPair);
    AppCatalogEntry refreshedEntryWithoutReceipt = richCatalogEntry();
    AppCatalogInstallPlan plan = plan(refreshedEntryWithoutReceipt);
    when(catalogManager.getApp("core", APP_ID)).thenReturn(trustedEntry);
    when(catalogManager.prepareInstallPlan("core", APP_ID)).thenReturn(plan);
    when(appHost.describe(APP_ID)).thenReturn(Optional.empty());

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> handler.install("core", APP_ID));

    assertEquals(409, exception.statusCode());
    assertEquals("app_review_missing", exception.errorCode());
    verify(appHost, never()).installFromDirectory(any());
  }

  @Test
  void update_whenPreparedPlanLosesTrustedReview_expectPlanReviewGateBlocks() throws Exception {
    KeyPair reviewerKeyPair = reviewerKeyPair();
    AppCatalogsApiHandler handler =
        new AppCatalogsApiHandler(
            catalogManager,
            appHost,
            () -> null,
            new AppReviewPolicy(AppReviewPolicyMode.REQUIRE_TRUSTED_REVIEW),
            () -> trustedReviewerKeys(reviewerKeyPair));
    AppCatalogEntry trustedEntry = richCatalogEntryWithTrustedReceipt(reviewerKeyPair);
    AppCatalogEntry refreshedEntryWithoutReceipt = richCatalogEntry();
    AppCatalogInstallPlan plan = plan(refreshedEntryWithoutReceipt);
    when(catalogManager.getApp("core", APP_ID)).thenReturn(trustedEntry);
    when(catalogManager.prepareInstallPlan("core", APP_ID)).thenReturn(plan);
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installedSnapshot()));

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> handler.update("core", APP_ID));

    assertEquals(409, exception.statusCode());
    assertEquals("app_review_missing", exception.errorCode());
    verify(appHost, never()).updateFromDirectory(any(), any());
  }

  @Test
  void install_whenAcknowledgedReviewTrustChangesAfterPlan_expectFreshAcknowledgementRequired()
      throws Exception {
    KeyPair reviewerKeyPair = reviewerKeyPair();
    AppCatalogsApiHandler handler =
        new AppCatalogsApiHandler(
            catalogManager,
            appHost,
            () -> null,
            new AppReviewPolicy(AppReviewPolicyMode.WARN_UNTRUSTED),
            () -> trustedReviewerKeys(reviewerKeyPair));
    AppCatalogEntry acknowledgedEntry = richCatalogEntry();
    AppCatalogEntry refreshedRejectedEntry =
        richCatalogEntryWithTrustedReceipt(reviewerKeyPair, AppReviewReceiptStatus.REJECTED);
    AppCatalogInstallPlan plan = plan(refreshedRejectedEntry);
    when(catalogManager.getApp("core", APP_ID)).thenReturn(acknowledgedEntry);
    when(catalogManager.prepareInstallPlan("core", APP_ID)).thenReturn(plan);
    when(appHost.describe(APP_ID)).thenReturn(Optional.empty());
    Map<String, List<String>> queryParameters = reviewAcknowledgedQuery();

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class, () -> handler.install("core", APP_ID, queryParameters));

    assertEquals(409, exception.statusCode());
    assertEquals("app_review_rejected", exception.errorCode());
    verify(appHost, never()).installFromDirectory(any());
  }

  @Test
  void update_whenAcknowledgedReviewTrustChangesAfterPlan_expectFreshAcknowledgementRequired()
      throws Exception {
    KeyPair reviewerKeyPair = reviewerKeyPair();
    AppCatalogsApiHandler handler =
        new AppCatalogsApiHandler(
            catalogManager,
            appHost,
            () -> null,
            new AppReviewPolicy(AppReviewPolicyMode.WARN_UNTRUSTED),
            () -> trustedReviewerKeys(reviewerKeyPair));
    AppCatalogEntry acknowledgedEntry = richCatalogEntry();
    AppCatalogEntry refreshedRejectedEntry =
        richCatalogEntryWithTrustedReceipt(reviewerKeyPair, AppReviewReceiptStatus.REJECTED);
    AppCatalogInstallPlan plan = plan(refreshedRejectedEntry);
    when(catalogManager.getApp("core", APP_ID)).thenReturn(acknowledgedEntry);
    when(catalogManager.prepareInstallPlan("core", APP_ID)).thenReturn(plan);
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installedSnapshot()));
    Map<String, List<String>> queryParameters = reviewAcknowledgedQuery();

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class, () -> handler.update("core", APP_ID, queryParameters));

    assertEquals(409, exception.statusCode());
    assertEquals("app_review_rejected", exception.errorCode());
    verify(appHost, never()).updateFromDirectory(any(), any());
  }

  @Test
  void update_whenCatalogUpdateRemovesVaultUsePermission_expectMatchingGrantInactive()
      throws Exception {
    AppVaultService vaultService = AppVaultService.open(tempDir.resolve("vault"));
    AppIdentityRecord identity =
        vaultService.createOperatorIdentity(
            AppIdentityKind.LOCAL_ED25519_SIGNING,
            "Operator publisher",
            null,
            Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED));
    AppIdentityGrant grant =
        vaultService.grantIdentity(
            identity.identityId(),
            APP_ID,
            Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED),
            "operator",
            "test grant",
            null,
            null);
    AppCatalogsApiHandler handler =
        new AppCatalogsApiHandler(
            catalogManager,
            appHost,
            () -> null,
            new AppReviewPolicy(AppReviewPolicyMode.ADVISORY),
            TrustedReviewerKeys::empty,
            vaultService);
    AppCatalogEntry entry = richCatalogEntry();
    AppCatalogInstallPlan plan = plan(entry);
    when(catalogManager.getApp("core", APP_ID)).thenReturn(entry);
    when(catalogManager.prepareInstallPlan("core", APP_ID)).thenReturn(plan);
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    when(appHost.describe(APP_ID))
        .thenReturn(
            Optional.of(installedSnapshot("1.1.0", List.of("queue.read", "vault.identities.use"))));
    when(appHost.updateFromDirectory(APP_ID, plan.stagedBundleDirectory()))
        .thenReturn(installedSnapshot("1.2.0", List.of("queue.read", "vault.identities.read")));

    handler.update("core", APP_ID);

    assertEquals(
        AppIdentityGrantStatus.INACTIVE,
        vaultService.listGrantsForApp(APP_ID).stream()
            .filter(candidate -> candidate.grantId().equals(grant.grantId()))
            .findFirst()
            .orElseThrow()
            .status());
  }

  @Test
  void update_whenVaultGrantCleanupFailsAfterCatalogUpdate_expectWarning() throws Exception {
    AppVaultService vaultService = AppVaultService.open(tempDir.resolve("vault"));
    AppIdentityRecord identity =
        vaultService.createOperatorIdentity(
            AppIdentityKind.LOCAL_ED25519_SIGNING,
            "Operator publisher",
            null,
            Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED));
    AppIdentityGrant grant =
        vaultService.grantIdentity(
            identity.identityId(),
            APP_ID,
            Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED),
            "operator",
            "test grant",
            null,
            null);
    Files.writeString(
        tempDir.resolve("vault").resolve("grants").resolve(grant.grantId() + ".properties"),
        """
        grantId=%s
        identityId=%s
        appId=%s
        scopes=sign.domain-separated
        status=not-a-status
        createdAt=%s
        updatedAt=%s
        """
            .formatted(
                grant.grantId(),
                grant.identityId(),
                grant.appId(),
                grant.createdAt(),
                grant.updatedAt()));
    AppCatalogsApiHandler handler =
        new AppCatalogsApiHandler(
            catalogManager,
            appHost,
            () -> null,
            new AppReviewPolicy(AppReviewPolicyMode.ADVISORY),
            TrustedReviewerKeys::empty,
            vaultService);
    AppCatalogEntry entry = richCatalogEntry();
    AppCatalogInstallPlan plan = plan(entry);
    when(catalogManager.getApp("core", APP_ID)).thenReturn(entry);
    when(catalogManager.prepareInstallPlan("core", APP_ID)).thenReturn(plan);
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    when(appHost.describe(APP_ID))
        .thenReturn(
            Optional.of(installedSnapshot("1.1.0", List.of("queue.read", "vault.identities.use"))));
    when(appHost.updateFromDirectory(APP_ID, plan.stagedBundleDirectory()))
        .thenReturn(installedSnapshot("1.2.0", List.of("queue.read", "vault.identities.read")));

    Map<String, Object> summary = handler.update("core", APP_ID);

    assertEquals(
        List.of("Vault grant cleanup failed and requires operator review."),
        summary.get("warnings"));
  }

  private Map<String, Object> listRichInstalledCatalogApp() throws Exception {
    AppCatalogsApiHandler handler =
        new AppCatalogsApiHandler(catalogManager, appHost, () -> "0.2.0");
    when(catalogManager.listApps("core")).thenReturn(List.of(richCatalogEntry()));
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installedSnapshot()));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());

    return handler.listApps("core").getFirst();
  }

  private static Map<String, Object> fields(Map<String, Object> source, String... keys) {
    Map<String, Object> selected = new LinkedHashMap<>();
    for (String key : keys) {
      selected.put(key, source.get(key));
    }
    return selected;
  }

  private AppCatalogsApiHandler handlerWithRecommended(List<RecommendedAppCatalog> recommended) {
    return new AppCatalogsApiHandler(
        catalogManager,
        appHost,
        () -> null,
        AppReviewPolicy.DEFAULT,
        TrustedReviewerKeys::empty,
        null,
        () -> recommended);
  }

  private static RecommendedAppCatalog recommended(String source, String trustedKeyId) {
    return RecommendedAppCatalog.fromRawSource(
        RecommendedAppCatalogs.FIRST_PARTY_BETA_CATALOG_ID,
        "Crypta First-Party Beta Catalog",
        "First-party beta apps maintained by the Crypta project.",
        "beta",
        source,
        trustedKeyId,
        "first-party-review");
  }

  private static AppCatalogSourceSnapshot firstPartyCatalogSnapshot() {
    Instant generatedAt = Instant.parse("2026-04-24T12:00:00Z");
    Instant addedAt = Instant.parse("2026-04-24T12:01:00Z");
    Instant refreshedAt = Instant.parse("2026-04-24T12:02:00Z");
    URI source = URI.create(FIRST_PARTY_SOURCE);
    return new AppCatalogSourceSnapshot(
        RecommendedAppCatalogs.FIRST_PARTY_BETA_CATALOG_ID,
        "Core Apps",
        source,
        generatedAt,
        2,
        addedAt,
        refreshedAt,
        refreshedAt,
        refreshedAt,
        AppCatalogFetchStatus.SUCCESS,
        Optional.empty(),
        Optional.empty(),
        Optional.of(source.toString()),
        Optional.of(FIRST_PARTY_TRUSTED_KEY_ID));
  }

  private void assertCatalogFailureStatus(String code, int statusCode) throws Exception {
    reset(catalogManager);
    AppCatalogsApiHandler handler = new AppCatalogsApiHandler(catalogManager, appHost, () -> null);
    when(catalogManager.listCatalogs()).thenThrow(new AppCatalogException(code, "catalog failed"));

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, handler::listCatalogs);

    assertEquals(statusCode, exception.statusCode());
    assertEquals(code, exception.errorCode());
    assertEquals("catalog failed", exception.getMessage());
  }

  private AppCatalogEntry richCatalogEntry() {
    return new AppCatalogEntry(
        APP_ID,
        "Queue Manager",
        "1.2.0",
        "Manage local Crypta transfer queues.",
        URI.create("https://example.invalid/app"),
        URI.create("https://example.invalid/repo"),
        "MIT",
        List.of("productivity", "network"),
        new AppCatalogCompatibilityMetadata("0.1.0", "0.9.99"),
        new AppCatalogReviewMetadata(
            AppCatalogReviewStatus.REVIEWED, Optional.of("Reviewed for local operator safety.")),
        new AppCatalogChangelog(
            Optional.of("Adds queue retry controls."),
            Optional.of(URI.create("https://example.invalid/changelog.txt"))),
        List.of(URI.create("https://example.invalid/shot-1.png")),
        productionMetadata(),
        maintenanceMetadata(),
        URI.create("https://example.invalid/apps/queue-manager.zip"),
        "0".repeat(64),
        0L,
        AppCatalogEntry.ZIP_BUNDLE_TYPE,
        List.of("queue.read", "queue.write"),
        Map.of(
            "queue.read",
            "Reads the local transfer queue.",
            "queue.write",
            "Lets the app manage queue entries."));
  }

  private AppCatalogEntry richCatalogEntryWithTrustedReceipt(KeyPair reviewerKeyPair) {
    return richCatalogEntryWithTrustedReceipt(reviewerKeyPair, AppReviewReceiptStatus.REVIEWED);
  }

  private AppCatalogEntry richCatalogEntryWithTrustedReceipt(
      KeyPair reviewerKeyPair, AppReviewReceiptStatus status) {
    AppCatalogEntry entry = richCatalogEntry();
    AppReviewReceipt receipt =
        AppReviewReceiptSigner.sign(reviewPayload(entry, status), reviewerKeyPair.getPrivate());
    return new AppCatalogEntry(
        entry.appId(),
        entry.name(),
        entry.version(),
        entry.summary(),
        entry.homepage().orElse(null),
        entry.source().orElse(null),
        entry.license().orElse(null),
        entry.categories(),
        entry.compatibility(),
        entry.review(),
        receipt,
        entry.changelog(),
        entry.screenshots(),
        entry.productionMetadata(),
        entry.maintenanceMetadata(),
        entry.bundleUri(),
        entry.bundleSha256(),
        entry.bundleSizeBytes(),
        entry.bundleType(),
        entry.permissions(),
        entry.permissionRationales());
  }

  private static AppCatalogProductionMetadata productionMetadata() {
    return new AppCatalogProductionMetadata(
        AppCatalogChannel.BETA,
        AppCatalogSupportStatus.EXPERIMENTAL,
        AppCatalogDeprecationStatus.DEPRECATED,
        Optional.of("Use Queue Manager stable."),
        Optional.of("queue-manager-stable"),
        List.of(
            new AppCatalogSecurityAdvisory(
                "CRYPTA-2026-0001",
                URI.create("https://example.invalid/advisories/CRYPTA-2026-0001"))),
        true);
  }

  private static AppCatalogMaintenanceMetadata maintenanceMetadata() {
    return new AppCatalogMaintenanceMetadata(
        Optional.of("crypta-core"),
        Optional.of(URI.create("https://example.invalid/crypta/owners/core")),
        Optional.of(AppCatalogMaintenanceMetadata.SupportLevel.CORE),
        Optional.of(AppCatalogMaintenanceMetadata.DataSchemaPolicy.STATELESS),
        Optional.of(AppCatalogMaintenanceMetadata.MigrationPolicy.NONE),
        Optional.of(AppCatalogMaintenanceMetadata.BackupRestoreSupport.NOT_APPLICABLE),
        Optional.of(AppCatalogMaintenanceMetadata.SecurityPolicy.CATALOG_ADVISORIES),
        Optional.of(AppCatalogMaintenanceMetadata.DeprecationPolicy.NONE),
        Optional.of(URI.create("https://example.invalid/crypta/apps/queue-manager/support")),
        true);
  }

  private static AppReviewReceiptPayload reviewPayload(
      AppCatalogEntry entry, AppReviewReceiptStatus status) {
    return new AppReviewReceiptPayload(
        AppReviewReceiptPayload.RECEIPT_VERSION,
        entry.appId(),
        entry.version(),
        entry.bundleSha256(),
        entry.bundleSizeBytes(),
        Optional.empty(),
        REVIEW_POLICY_ID,
        REVIEW_POLICY_VERSION,
        status,
        REVIEWER_KEY_ID,
        REVIEWED_AT,
        Optional.empty(),
        Optional.empty(),
        Optional.empty(),
        Optional.empty());
  }

  private static TrustedReviewerKeys trustedReviewerKeys(KeyPair keyPair) {
    return TrustedReviewerKeys.of(
        TrustedReviewerKey.ed25519(
            REVIEWER_KEY_ID,
            keyPair.getPublic().getEncoded(),
            "Crypta First-Party Review",
            REVIEW_POLICY_ID));
  }

  private static AppCatalogSecurityDecision denylistedSecurityDecision() {
    return new AppCatalogSecurityDecision(
        AppCatalogSecurityDecisionStatus.DENYLISTED,
        AppCatalogSecurityAction.DENYLIST,
        AppCatalogSecuritySeverity.CRITICAL,
        List.of("CRYPTA-2026-0001"),
        false,
        true,
        true,
        true,
        "Export app data before uninstalling.",
        APP_ID,
        List.of("Known vulnerable release."));
  }

  private static AppCatalogSecurityDecision warningSecurityDecision() {
    return new AppCatalogSecurityDecision(
        AppCatalogSecurityDecisionStatus.WARNING,
        AppCatalogSecurityAction.WARN,
        AppCatalogSecuritySeverity.HIGH,
        List.of("CRYPTA-2026-0002"),
        true,
        false,
        false,
        true,
        null,
        null,
        List.of("Security advisory requires operator acknowledgement."));
  }

  private static Map<String, List<String>> reviewAcknowledgedQuery() {
    return Map.of("reviewAcknowledged", List.of("true"));
  }

  private static Map<String, Object> trustedReviewTrustMap() {
    return Map.of(
        "status",
        "trusted_reviewed",
        "trusted",
        true,
        "positive",
        true,
        "reviewerKeyId",
        REVIEWER_KEY_ID,
        "reviewerKeyStatus",
        "active",
        "policyId",
        REVIEW_POLICY_ID,
        "policyVersion",
        REVIEW_POLICY_VERSION);
  }

  private static AppReviewTransparencyLog.ReviewTrustMapSubject reviewTrustMapSubject(
      String appVersion, String artifactSha256, long artifactSizeBytes) {
    return new AppReviewTransparencyLog.ReviewTrustMapSubject(
        APP_ID, appVersion, "core", artifactSha256, artifactSizeBytes);
  }

  private static void assertRedactsReviewerPublicKey(Object output, KeyPair reviewerKeyPair) {
    String encodedPublicKey =
        Base64.getEncoder().encodeToString(reviewerKeyPair.getPublic().getEncoded());
    String rendered = output.toString();
    assertFalse(rendered.contains(encodedPublicKey));
    assertFalse(rendered.contains("public.key.base64"));
  }

  private static KeyPair reviewerKeyPair() throws Exception {
    return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
  }

  private AppCatalogInstallPlan plan(AppCatalogEntry entry) throws IOException {
    Path scratch = tempDir.resolve("scratch-" + entry.version());
    Path staged = scratch.resolve("bundle");
    Files.createDirectories(staged);
    return new AppCatalogInstallPlan("core", entry, staged, scratch);
  }

  private AppCatalogEntry minimalCatalogEntry() {
    return catalogEntryWithVersion("1.2.0");
  }

  private AppCatalogEntry catalogEntryWithVersion(String version) {
    return new AppCatalogEntry(
        APP_ID,
        "Queue Manager",
        version,
        "Manage local Crypta transfer queues.",
        URI.create("https://example.invalid/apps/queue-manager.zip"),
        "0".repeat(64),
        0L,
        AppCatalogEntry.ZIP_BUNDLE_TYPE,
        List.of("queue.read"));
  }

  private AppCatalogEntry catalogEntryWithMinimumCryptaVersion(String minimumCryptaVersion) {
    return new AppCatalogEntry(
        APP_ID,
        "Queue Manager",
        "1.2.0",
        "Manage local Crypta transfer queues.",
        null,
        null,
        null,
        List.of(),
        new AppCatalogCompatibilityMetadata(minimumCryptaVersion),
        AppCatalogReviewMetadata.EMPTY,
        AppCatalogChangelog.EMPTY,
        List.of(),
        URI.create("https://example.invalid/apps/queue-manager.zip"),
        "0".repeat(64),
        0L,
        AppCatalogEntry.ZIP_BUNDLE_TYPE,
        List.of("queue.read"),
        Map.of());
  }

  private InstalledAppSnapshot installedSnapshot() {
    return installedSnapshot("1.1.0", List.of("queue.read", "network.access"));
  }

  private InstalledAppSnapshot installedSnapshot(String version, List<String> permissions) {
    AppManifest manifest =
        new AppManifest(
            1,
            APP_ID,
            "Queue Manager",
            version,
            "bin/launch.sh",
            AppUiMode.STATIC,
            "static/index.html",
            permissions,
            null,
            null);
    InstalledAppPaths paths =
        new InstalledAppPaths(
            APP_ID,
            tempDir.resolve("installed").resolve(APP_ID),
            tempDir.resolve("data").resolve(APP_ID),
            tempDir.resolve("cache").resolve(APP_ID),
            tempDir.resolve("run").resolve(APP_ID));
    return new InstalledAppSnapshot(manifest, paths);
  }
}

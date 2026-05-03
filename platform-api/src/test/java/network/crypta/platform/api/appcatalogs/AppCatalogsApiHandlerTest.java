package network.crypta.platform.api.appcatalogs;

import java.net.URI;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.appcatalog.AppCatalogChangelog;
import network.crypta.platform.appcatalog.AppCatalogCompatibilityMetadata;
import network.crypta.platform.appcatalog.AppCatalogEntry;
import network.crypta.platform.appcatalog.AppCatalogException;
import network.crypta.platform.appcatalog.AppCatalogFetchStatus;
import network.crypta.platform.appcatalog.AppCatalogManager;
import network.crypta.platform.appcatalog.AppCatalogReviewMetadata;
import network.crypta.platform.appcatalog.AppCatalogReviewStatus;
import network.crypta.platform.appcatalog.AppCatalogSourceSnapshot;
import network.crypta.platform.appdist.AppUiMode;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.InstalledAppPaths;
import network.crypta.platform.apphost.InstalledAppSnapshot;
import network.crypta.platform.apphost.manifest.AppManifest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings({"java:S100", "unchecked"})
class AppCatalogsApiHandlerTest {
  private static final String APP_ID = "queue-manager";

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
            Optional.of("https://example.invalid/cryptad-app-catalog.properties"));
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

    assertEquals(APP_ID, app.get("appId"));
    assertEquals("1.2.0", app.get("version"));
    assertEquals("1.1.0", app.get("installedVersion"));
    assertEquals(true, app.get("installed"));
    assertEquals(true, app.get("versionDifferent"));
    assertEquals(true, app.get("updateAvailable"));
    assertEquals("different", app.get("versionStatus"));
    assertEquals(List.of("productivity", "network"), app.get("categories"));
    assertEquals("https://example.invalid/app", app.get("homepage"));
    assertEquals("https://example.invalid/repo", app.get("source"));
    assertEquals("MIT", app.get("license"));

    Map<String, Object> review = (Map<String, Object>) app.get("review");
    assertEquals("reviewed", review.get("status"));
    assertEquals("Reviewed for local operator safety.", review.get("note"));
    assertEquals(true, review.get("advisory"));

    Map<String, Object> rationales = (Map<String, Object>) app.get("permissionRationales");
    assertEquals("Reads the local transfer queue.", rationales.get("queue.read"));
    assertEquals("Lets the app manage queue entries.", rationales.get("queue.write"));

    Map<String, Object> compatibility = (Map<String, Object>) app.get("compatibility");
    assertEquals("0.1.0", compatibility.get("minimumCryptaVersion"));
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
    assertFalse((Boolean) app.get("installed"));
    assertEquals(false, app.get("versionDifferent"));
    assertEquals(false, app.get("updateAvailable"));
    assertEquals("not_installed", app.get("versionStatus"));

    Map<String, Object> review = (Map<String, Object>) app.get("review");
    assertEquals("unreviewed", review.get("status"));
    assertNull(review.get("note"));
    assertTrue((Boolean) review.get("advisory"));

    Map<String, Object> compatibility = (Map<String, Object>) app.get("compatibility");
    assertNull(compatibility.get("minimumCryptaVersion"));
    assertNull(compatibility.get("currentCryptaVersion"));
    assertEquals(true, compatibility.get("satisfied"));
    assertEquals("not_declared", compatibility.get("status"));
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

  private Map<String, Object> listRichInstalledCatalogApp() throws Exception {
    AppCatalogsApiHandler handler =
        new AppCatalogsApiHandler(catalogManager, appHost, () -> "0.2.0");
    when(catalogManager.listApps("core")).thenReturn(List.of(richCatalogEntry()));
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installedSnapshot()));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());

    return handler.listApps("core").getFirst();
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
        Optional.of(URI.create("https://example.invalid/app")),
        Optional.of(URI.create("https://example.invalid/repo")),
        Optional.of("MIT"),
        List.of("productivity", "network"),
        new AppCatalogCompatibilityMetadata("0.1.0"),
        new AppCatalogReviewMetadata(
            AppCatalogReviewStatus.REVIEWED, Optional.of("Reviewed for local operator safety.")),
        new AppCatalogChangelog(
            Optional.of("Adds queue retry controls."),
            Optional.of(URI.create("https://example.invalid/changelog.txt"))),
        List.of(URI.create("https://example.invalid/shot-1.png")),
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
        Optional.empty(),
        Optional.empty(),
        Optional.empty(),
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

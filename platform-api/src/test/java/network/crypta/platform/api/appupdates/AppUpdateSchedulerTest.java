package network.crypta.platform.api.appupdates;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import network.crypta.platform.api.PlatformApiContract;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.appcatalog.AppCatalogChangelog;
import network.crypta.platform.appcatalog.AppCatalogCompatibilityMetadata;
import network.crypta.platform.appcatalog.AppCatalogEntry;
import network.crypta.platform.appcatalog.AppCatalogFetchStatus;
import network.crypta.platform.appcatalog.AppCatalogInstallPlan;
import network.crypta.platform.appcatalog.AppCatalogManager;
import network.crypta.platform.appcatalog.AppCatalogReviewMetadata;
import network.crypta.platform.appcatalog.AppCatalogReviewStatus;
import network.crypta.platform.appcatalog.AppCatalogSourceSnapshot;
import network.crypta.platform.appcatalog.AppReviewPolicy;
import network.crypta.platform.appcatalog.AppReviewReceipt;
import network.crypta.platform.appcatalog.AppReviewReceiptPayload;
import network.crypta.platform.appcatalog.AppReviewReceiptSigner;
import network.crypta.platform.appcatalog.AppReviewReceiptStatus;
import network.crypta.platform.appcatalog.TrustedReviewerKey;
import network.crypta.platform.appcatalog.TrustedReviewerKeys;
import network.crypta.platform.appdist.AppApiCompatibilityMetadata.TargetStability;
import network.crypta.platform.appdist.AppApiCompatibilityMetadata;
import network.crypta.platform.appdist.AppUiMode;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.InstalledAppPaths;
import network.crypta.platform.apphost.InstalledAppSnapshot;
import network.crypta.platform.apphost.RunningAppSnapshot;
import network.crypta.platform.apphost.manifest.AppManifest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings({"java:S100", "java:S2245", "unchecked", "resource"})
class AppUpdateSchedulerTest {
  private static final String APP_ID = "queue-manager";
  private static final String APP_NAME = "Queue Manager";
  private static final String CATALOG_ID = "core";
  private static final String FIELD_STATUS = "status";
  private static final String FIELD_LAST_RESULT = "lastResult";
  private static final String FIELD_LAST_ERROR_CODE = "lastErrorCode";
  private static final String FIELD_MESSAGE = "message";
  private static final String STAGED = "staged";
  private static final String AVAILABLE = "available";
  private static final String ERROR_UPDATE_FAILED = "update_failed";
  private static final String FAILED_BELOW = "failed below ";
  private static final String SECRET_TOKEN = "secret-token";
  private static final String MESSAGE_SCHEDULER_UPDATE_CHECK_FAILED =
      "Scheduler update check failed.";
  private static final String DIGEST =
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  private static final String INSTALLED_VERSION = "1.0.0";
  private static final String UPDATE_VERSION = "1.1.0";
  private static final String QUEUE_READ_PERMISSION = "queue.read";
  private static final String REVIEWER_KEY_ID = "crypta-first-party-review";
  private static final String REVIEW_POLICY_ID = "crypta-app-review-v1";
  private static final String REVIEW_POLICY_VERSION = "1";
  private static final Instant STARTED_AT = Instant.parse("2026-05-12T00:00:00Z");
  private static final Instant REVIEWED_AT = Instant.parse("2026-05-01T00:00:00Z");
  private static final Instant DUE_AT = STARTED_AT.plusSeconds(1);

  @Mock private AppHost appHost;
  @Mock private AppCatalogManager catalogManager;
  @Mock private AppUpdateService updateService;

  @TempDir private Path tempDir;

  @Test
  void tick_whenSchedulerDisabled_expectDisabledSummaryAndNoWork() {
    InMemoryAppUpdateSchedulerStore store = new InMemoryAppUpdateSchedulerStore();
    AppUpdateScheduler scheduler = scheduler(disabledConfig(), store, updateService);

    AppUpdateSchedulerTickResult result = scheduler.tick(DUE_AT);

    assertEquals(AppUpdateSchedulerStatus.DISABLED, result.status());
    assertEquals(AppUpdateSchedulerState.RESULT_SKIPPED, result.result());
    Map<String, Object> summary = scheduler.summary(APP_ID);
    assertEquals(false, summary.get("enabled"));
    assertEquals(AppUpdateSchedulerStatus.DISABLED.jsonValue(), summary.get(FIELD_STATUS));
    assertNull(summary.get("lastCheckAt"));
    verifyNoInteractions(appHost, catalogManager, updateService);
  }

  @Test
  void tick_whenCatalogAndAppAreDue_expectRefreshOnceThenDelegatesCheck() throws Exception {
    InMemoryAppUpdateSchedulerStore store = new InMemoryAppUpdateSchedulerStore();
    AppUpdateScheduler scheduler = scheduler(enabledConfig(), store, updateService);
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.refresh(CATALOG_ID)).thenReturn(catalog());
    when(appHost.listInstalled()).thenReturn(List.of(installed));
    when(updateService.check(APP_ID, false)).thenReturn(Map.of());

    AppUpdateSchedulerTickResult result = scheduler.tick(DUE_AT);

    assertEquals(AppUpdateSchedulerStatus.SUCCESS, result.status());
    assertEquals(1, result.catalogsAttempted());
    assertEquals(1, result.appsChecked());
    verify(catalogManager).refresh(CATALOG_ID);
    var inOrder = inOrder(catalogManager, updateService);
    inOrder.verify(catalogManager).listCatalogs();
    inOrder.verify(catalogManager).refresh(CATALOG_ID);
    inOrder.verify(updateService).check(APP_ID, false);
    verify(updateService).check(APP_ID, false);
    Map<String, Object> summary = scheduler.summary(APP_ID);
    assertEquals(true, summary.get("enabled"));
    assertEquals(AppUpdateSchedulerStatus.SUCCESS.jsonValue(), summary.get(FIELD_STATUS));
    assertEquals(DUE_AT.toString(), summary.get("lastCheckAt"));
    assertEquals(DUE_AT.plusSeconds(60).toString(), summary.get("nextCheckAt"));
    assertEquals("per-app-serialized", summary.get("concurrency"));
  }

  @Test
  void tick_whenCheckFails_expectSanitizedFailureAndBackoff() throws Exception {
    InMemoryAppUpdateSchedulerStore store = new InMemoryAppUpdateSchedulerStore();
    AppUpdateScheduler scheduler = scheduler(enabledConfig(), store, updateService);
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(catalogManager.listCatalogs()).thenReturn(List.of());
    when(appHost.listInstalled()).thenReturn(List.of(installed));
    when(updateService.check(APP_ID, false))
        .thenThrow(
            new PlatformApiException(
                500, ERROR_UPDATE_FAILED, FAILED_BELOW + tempDir.resolve(SECRET_TOKEN)));

    AppUpdateSchedulerTickResult result = scheduler.tick(DUE_AT);

    assertEquals(AppUpdateSchedulerStatus.BACKOFF, result.status());
    assertEquals(1, result.appFailures());
    Map<String, Object> summary = scheduler.summary(APP_ID);
    assertEquals(AppUpdateSchedulerStatus.BACKOFF.jsonValue(), summary.get(FIELD_STATUS));
    assertEquals(AppUpdateSchedulerState.RESULT_FAILED, summary.get(FIELD_LAST_RESULT));
    assertEquals(ERROR_UPDATE_FAILED, summary.get(FIELD_LAST_ERROR_CODE));
    assertEquals(1, summary.get("failureCount"));
    assertEquals(MESSAGE_SCHEDULER_UPDATE_CHECK_FAILED, summary.get(FIELD_MESSAGE));
    assertFalse(summary.toString().contains(tempDir.toString()));
    assertEquals(DUE_AT.plusSeconds(30).toString(), summary.get("nextCheckAt"));
  }

  @Test
  void tick_whenCatalogRefreshFails_expectFailureContainedAndAppsStillChecked() throws Exception {
    InMemoryAppUpdateSchedulerStore store = new InMemoryAppUpdateSchedulerStore();
    AppUpdateScheduler scheduler = scheduler(enabledConfig(), store, updateService);
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.refresh(CATALOG_ID))
        .thenThrow(new IOException(FAILED_BELOW + tempDir.resolve("catalog-scratch")));
    when(appHost.listInstalled()).thenReturn(List.of(installed));
    when(updateService.check(APP_ID, false)).thenReturn(Map.of());

    AppUpdateSchedulerTickResult result = scheduler.tick(DUE_AT);

    assertEquals(AppUpdateSchedulerStatus.BACKOFF, result.status());
    assertEquals(1, result.catalogFailures());
    assertEquals(1, result.appsChecked());
    verify(updateService).check(APP_ID, false);
    AppUpdateSchedulerState catalogState = store.readCatalogState().orElseThrow();
    assertEquals("catalog_refresh_failed", catalogState.lastErrorCode());
    assertEquals(
        "Scheduler catalog refresh failed; cached verified catalogs remain in use.",
        catalogState.message());
    assertFalse(catalogState.toJsonValue().toString().contains(tempDir.toString()));
  }

  @Test
  void tick_whenCatalogListFailsAndNoAppsInstalled_expectFailedResultAndBackoff() throws Exception {
    InMemoryAppUpdateSchedulerStore store = new InMemoryAppUpdateSchedulerStore();
    AppUpdateScheduler scheduler = scheduler(enabledConfig(), store, updateService);
    when(catalogManager.listCatalogs())
        .thenThrow(new IOException(FAILED_BELOW + tempDir.resolve("catalog-scratch")));
    when(appHost.listInstalled()).thenReturn(List.of());

    AppUpdateSchedulerTickResult result = scheduler.tick(DUE_AT);

    assertEquals(AppUpdateSchedulerStatus.BACKOFF, result.status());
    assertEquals(AppUpdateSchedulerState.RESULT_FAILED, result.result());
    assertEquals(0, result.catalogsAttempted());
    assertEquals(1, result.catalogFailures());
    assertEquals("Scheduler pass completed with failures.", result.message());
    verifyNoInteractions(updateService);
    AppUpdateSchedulerState catalogState = store.readCatalogState().orElseThrow();
    assertEquals("catalog_list_failed", catalogState.lastErrorCode());
    assertFalse(catalogState.toJsonValue().toString().contains(tempDir.toString()));
  }

  @Test
  void tick_whenStoreWritesFail_expectBackoffAndNoRepeatedAppCheck() throws Exception {
    AppUpdateScheduler scheduler =
        scheduler(enabledConfig(), new FailingWriteSchedulerStore(), updateService);
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.listInstalled()).thenReturn(List.of(installed), List.of(installed));

    AppUpdateSchedulerTickResult firstResult = scheduler.tick(DUE_AT);
    AppUpdateSchedulerTickResult secondResult = scheduler.tick(DUE_AT.plusSeconds(1));

    assertEquals(AppUpdateSchedulerStatus.BACKOFF, firstResult.status());
    assertEquals(AppUpdateSchedulerState.RESULT_FAILED, firstResult.result());
    assertEquals(1, firstResult.catalogFailures());
    assertEquals(1, firstResult.appsChecked());
    assertEquals(1, firstResult.appFailures());
    assertEquals(AppUpdateSchedulerStatus.SKIPPED, secondResult.status());
    assertEquals(1, secondResult.skippedApps());
    verifyNoInteractions(catalogManager, updateService);
    Map<String, Object> summary = scheduler.summary(APP_ID);
    assertEquals(AppUpdateSchedulerStatus.BACKOFF.jsonValue(), summary.get(FIELD_STATUS));
    assertEquals(AppUpdateSchedulerState.RESULT_FAILED, summary.get(FIELD_LAST_RESULT));
    assertEquals("scheduler_store_failed", summary.get(FIELD_LAST_ERROR_CODE));
    assertEquals("Scheduler state could not be persisted.", summary.get(FIELD_MESSAGE));
  }

  @Test
  void tick_whenStoreReadsFail_expectBackoffAndNoAppCheck() throws Exception {
    AppUpdateScheduler scheduler =
        scheduler(enabledConfig(), new FailingReadSchedulerStore(), updateService);
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.listInstalled()).thenReturn(List.of(installed));

    AppUpdateSchedulerTickResult result = scheduler.tick(DUE_AT);

    assertEquals(AppUpdateSchedulerStatus.BACKOFF, result.status());
    assertEquals(AppUpdateSchedulerState.RESULT_FAILED, result.result());
    assertEquals(1, result.catalogFailures());
    assertEquals(0, result.appsChecked());
    assertEquals(1, result.appFailures());
    verifyNoInteractions(catalogManager, updateService);
    Map<String, Object> summary = scheduler.summary(APP_ID);
    assertEquals(AppUpdateSchedulerStatus.BACKOFF.jsonValue(), summary.get(FIELD_STATUS));
    assertEquals("scheduler_store_failed", summary.get(FIELD_LAST_ERROR_CODE));
    assertEquals("Scheduler state could not be read.", summary.get(FIELD_MESSAGE));
  }

  @Test
  void tick_whenListedAppIsMissingBeforeCheck_expectSchedulerStateCleared() throws Exception {
    InMemoryAppUpdateSchedulerStore store = new InMemoryAppUpdateSchedulerStore();
    AppUpdateScheduler scheduler = scheduler(enabledConfig(), store, updateService);
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(catalogManager.listCatalogs()).thenReturn(List.of());
    when(appHost.listInstalled()).thenReturn(List.of(installed));
    when(updateService.check(APP_ID, false))
        .thenThrow(new PlatformApiException(404, "app_not_found", "App not found."));

    AppUpdateSchedulerTickResult result = scheduler.tick(DUE_AT);

    assertEquals(AppUpdateSchedulerStatus.SUCCESS, result.status());
    assertEquals(1, result.appsChecked());
    assertEquals(0, result.appFailures());
    assertTrue(store.readAppState(APP_ID).isEmpty());
    Map<String, Object> summary = scheduler.summary(APP_ID);
    assertEquals(AppUpdateSchedulerStatus.SCHEDULED.jsonValue(), summary.get(FIELD_STATUS));
    assertEquals(AppUpdateSchedulerState.RESULT_NONE, summary.get(FIELD_LAST_RESULT));
    verify(updateService).check(APP_ID, false);
  }

  @Test
  void tick_whenManualPolicy_expectCheckOnlyAndNoStageOrApply() throws Exception {
    AppUpdateService service = realServiceWithInstalled(List.of(QUEUE_READ_PERMISSION));
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()), List.of(catalog()));
    when(catalogManager.refresh(CATALOG_ID)).thenReturn(catalog());
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(updateEntry()));
    when(appHost.listInstalled())
        .thenReturn(List.of(installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION))));

    scheduler(enabledConfig(), new InMemoryAppUpdateSchedulerStore(), service).tick(DUE_AT);

    Map<String, Object> summary = service.summary(APP_ID);
    Map<String, Object> candidate = (Map<String, Object>) summary.get("candidate");
    Map<String, Object> staged = (Map<String, Object>) summary.get(STAGED);
    assertEquals("manual", ((Map<?, ?>) summary.get("policy")).get("mode"));
    assertEquals(AVAILABLE, candidate.get(FIELD_STATUS));
    assertEquals(false, staged.get(AVAILABLE));
    verify(catalogManager, never()).prepareInstallPlan(CATALOG_ID, APP_ID);
    verify(appHost, never()).updateFromDirectory(eq(APP_ID), any(Path.class));
  }

  @Test
  void tick_whenStagePolicy_expectVerifiedCandidateStagedByServicePolicy() throws Exception {
    KeyPair reviewerKeyPair = reviewerKeyPair();
    AppUpdateService service =
        realServiceWithInstalled(List.of(QUEUE_READ_PERMISSION), reviewerKeyPair);
    service.setPolicy(APP_ID, AppUpdatePolicyMode.STAGE);
    AppCatalogEntry updateEntry = reviewedEntryWithTrustedReceipt(reviewerKeyPair);
    AppCatalogInstallPlan plan = plan(updateEntry);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()), List.of(catalog()));
    when(catalogManager.refresh(CATALOG_ID)).thenReturn(catalog());
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(updateEntry));
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
    when(appHost.listInstalled())
        .thenReturn(List.of(installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION))));

    scheduler(enabledConfig(), new InMemoryAppUpdateSchedulerStore(), service).tick(DUE_AT);

    Map<String, Object> staged = (Map<String, Object>) service.summary(APP_ID).get(STAGED);
    assertEquals(true, staged.get(AVAILABLE));
    assertEquals(STAGED, staged.get(FIELD_STATUS));
    assertEquals(UPDATE_VERSION, staged.get("targetVersion"));
    verify(appHost, never()).updateFromDirectory(APP_ID, plan.stagedBundleDirectory());
  }

  @Test
  void tick_whenApplyWhenStoppedPolicy_expectStoppedAppAppliedByServicePolicy() throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    InstalledAppSnapshot updated = installed(UPDATE_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID))
        .thenReturn(
            Optional.of(installed),
            Optional.of(installed),
            Optional.of(installed),
            Optional.of(updated));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    KeyPair reviewerKeyPair = reviewerKeyPair();
    AppUpdateService service =
        new AppUpdateService(
            appHost,
            catalogManager,
            AppReviewPolicy.DEFAULT,
            () -> trustedReviewerKeys(reviewerKeyPair));
    service.setPolicy(APP_ID, AppUpdatePolicyMode.APPLY_WHEN_STOPPED);
    AppCatalogEntry updateEntry = reviewedEntryWithTrustedReceipt(reviewerKeyPair);
    AppCatalogInstallPlan plan = plan(updateEntry);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()), List.of(catalog()));
    when(catalogManager.refresh(CATALOG_ID)).thenReturn(catalog());
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(updateEntry));
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
    when(appHost.listInstalled()).thenReturn(List.of(installed));
    when(appHost.updateFromDirectory(APP_ID, plan.stagedBundleDirectory())).thenReturn(updated);

    scheduler(enabledConfig(), new InMemoryAppUpdateSchedulerStore(), service).tick(DUE_AT);

    Map<String, Object> summary = service.summary(APP_ID);
    Map<String, Object> staged = (Map<String, Object>) summary.get(STAGED);
    assertEquals(false, staged.get(AVAILABLE));
    List<Map<String, Object>> history = (List<Map<String, Object>>) summary.get("history");
    assertTrue(
        history.stream()
            .anyMatch(
                entry ->
                    "apply".equals(entry.get("action"))
                        && AppUpdateSchedulerState.RESULT_SUCCESS.equals(entry.get(FIELD_STATUS))
                        && UPDATE_VERSION.equals(entry.get("targetVersion"))),
        summary::toString);
    verify(appHost).updateFromDirectory(APP_ID, plan.stagedBundleDirectory());
  }

  @Test
  void tick_whenApplyWhenStoppedPolicyAndAppRunning_expectRunningAppNotStoppedOrUpdated()
      throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installed));
    when(appHost.status(APP_ID)).thenReturn(Optional.of(running(installed)));
    KeyPair reviewerKeyPair = reviewerKeyPair();
    AppUpdateService service =
        new AppUpdateService(
            appHost,
            catalogManager,
            AppReviewPolicy.DEFAULT,
            () -> trustedReviewerKeys(reviewerKeyPair));
    service.setPolicy(APP_ID, AppUpdatePolicyMode.APPLY_WHEN_STOPPED);
    AppCatalogEntry updateEntry = reviewedEntryWithTrustedReceipt(reviewerKeyPair);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()), List.of(catalog()));
    when(catalogManager.refresh(CATALOG_ID)).thenReturn(catalog());
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(updateEntry));
    when(appHost.listInstalled()).thenReturn(List.of(installed));

    scheduler(enabledConfig(), new InMemoryAppUpdateSchedulerStore(), service).tick(DUE_AT);

    verify(appHost, never()).stop(APP_ID);
    verify(appHost, never()).updateFromDirectory(eq(APP_ID), any(Path.class));
    List<Map<String, Object>> history =
        (List<Map<String, Object>>) service.summary(APP_ID).get("history");
    assertTrue(
        history.stream()
            .anyMatch(
                entry ->
                    "app_running".equals(entry.get("errorCode"))
                        && "Policy skipped apply because the app is running."
                            .equals(entry.get(FIELD_MESSAGE))));
  }

  @Test
  void summary_whenSchedulerStatePresent_expectPathFreeSchedulerSummary() {
    InMemoryAppUpdateSchedulerStore store = new InMemoryAppUpdateSchedulerStore();
    store.writeAppState(
        new AppUpdateSchedulerState(
            APP_ID,
            true,
            AppUpdateSchedulerStatus.BACKOFF,
            DUE_AT,
            DUE_AT.plusSeconds(30),
            AppUpdateSchedulerState.RESULT_FAILED,
            DUE_AT,
            2,
            ERROR_UPDATE_FAILED,
            MESSAGE_SCHEDULER_UPDATE_CHECK_FAILED));
    AppUpdateScheduler scheduler = scheduler(enabledConfig(), store, updateService);

    Map<String, Object> summary = scheduler.summary(APP_ID);

    assertEquals(APP_ID, summary.get("appId"));
    assertEquals(AppUpdateSchedulerStatus.BACKOFF.jsonValue(), summary.get(FIELD_STATUS));
    assertEquals(ERROR_UPDATE_FAILED, summary.get(FIELD_LAST_ERROR_CODE));
    assertEquals(MESSAGE_SCHEDULER_UPDATE_CHECK_FAILED, summary.get(FIELD_MESSAGE));
    assertEquals("per-app-serialized", summary.get("concurrency"));
    assertFalse(summary.toString().contains(SECRET_TOKEN));
    assertFalse(summary.toString().contains(tempDir.toString()));
  }

  private AppUpdateScheduler scheduler(
      AppUpdateSchedulerConfig config,
      AppUpdateSchedulerStore store,
      AppUpdateService updateService) {
    return new AppUpdateScheduler(
        appHost,
        catalogManager,
        updateService,
        config,
        store,
        Clock.fixed(STARTED_AT, ZoneOffset.UTC),
        new Random(0));
  }

  private static AppUpdateSchedulerConfig enabledConfig() {
    return new AppUpdateSchedulerConfig(
        true,
        Duration.ZERO,
        Duration.ofSeconds(120),
        Duration.ofSeconds(60),
        Duration.ZERO,
        Duration.ofSeconds(30),
        Duration.ofSeconds(300));
  }

  private static AppUpdateSchedulerConfig disabledConfig() {
    return new AppUpdateSchedulerConfig(
        false,
        Duration.ZERO,
        Duration.ofSeconds(120),
        Duration.ofSeconds(60),
        Duration.ZERO,
        Duration.ofSeconds(30),
        Duration.ofSeconds(300));
  }

  private static final class FailingWriteSchedulerStore implements AppUpdateSchedulerStore {
    @Override
    public Optional<AppUpdateSchedulerState> readAppState(String appId) {
      return Optional.empty();
    }

    @Override
    public void writeAppState(AppUpdateSchedulerState state) throws IOException {
      throw new IOException("write failed below /tmp/secret-token");
    }

    @Override
    public void clearAppState(String appId) throws IOException {
      throw new IOException("delete failed below /tmp/secret-token");
    }

    @Override
    public Optional<AppUpdateSchedulerState> readCatalogState() {
      return Optional.empty();
    }

    @Override
    public void writeCatalogState(AppUpdateSchedulerState state) throws IOException {
      throw new IOException("write failed below /tmp/secret-token");
    }
  }

  private static final class FailingReadSchedulerStore implements AppUpdateSchedulerStore {
    @Override
    public Optional<AppUpdateSchedulerState> readAppState(String appId) throws IOException {
      throw new IOException("read failed below /tmp/secret-token");
    }

    @Override
    public void writeAppState(AppUpdateSchedulerState state) {
      // Intentionally empty: read failures keep this fake store on the scheduler read-failure path.
    }

    @Override
    public void clearAppState(String appId) {
      // Intentionally empty: read-failure tests never exercise scheduler cleanup persistence.
    }

    @Override
    public Optional<AppUpdateSchedulerState> readCatalogState() throws IOException {
      throw new IOException("read failed below /tmp/secret-token");
    }

    @Override
    public void writeCatalogState(AppUpdateSchedulerState state) {
      // Intentionally empty: catalog reads fail before this fake store can persist state.
    }
  }

  private AppUpdateService realServiceWithInstalled(List<String> permissions) throws IOException {
    return realServiceWithInstalled(permissions, null);
  }

  private AppUpdateService realServiceWithInstalled(
      List<String> permissions, KeyPair reviewerKeyPair) throws IOException {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, permissions);
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installed));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AppUpdateService.ReviewerKeysProvider reviewerKeysProvider =
        reviewerKeyPair == null
            ? TrustedReviewerKeys::empty
            : () -> trustedReviewerKeys(reviewerKeyPair);
    return new AppUpdateService(
        appHost, catalogManager, AppReviewPolicy.DEFAULT, reviewerKeysProvider);
  }

  private InstalledAppSnapshot installed(String version, List<String> permissions) {
    AppManifest manifest =
        new AppManifest(
            1,
            APP_ID,
            APP_NAME,
            version,
            "bin/launch.sh",
            AppUiMode.NONE,
            null,
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

  private RunningAppSnapshot running(InstalledAppSnapshot installed) {
    return new RunningAppSnapshot(
        installed.manifest(), installed.paths(), SECRET_TOKEN, 1234L, DUE_AT);
  }

  private static AppCatalogSourceSnapshot catalog() {
    return new AppCatalogSourceSnapshot(
        CATALOG_ID,
        "Core Apps",
        URI.create("https://example.invalid/cryptad-app-catalog.properties"),
        STARTED_AT,
        1,
        STARTED_AT,
        STARTED_AT,
        STARTED_AT,
        STARTED_AT,
        AppCatalogFetchStatus.SUCCESS,
        Optional.empty(),
        Optional.empty(),
        Optional.of("https://example.invalid/cryptad-app-catalog.properties"),
        Optional.empty());
  }

  private static AppCatalogEntry updateEntry() {
    return new AppCatalogEntry(
        APP_ID,
        APP_NAME,
        UPDATE_VERSION,
        "Manage queues.",
        null,
        null,
        null,
        List.of(),
        new AppCatalogCompatibilityMetadata(null, compatibleApiMetadata()),
        new AppCatalogReviewMetadata(AppCatalogReviewStatus.REVIEWED, null),
        AppCatalogChangelog.EMPTY,
        List.of(),
        URI.create("file:///tmp/queue-manager-" + UPDATE_VERSION + ".zip"),
        DIGEST,
        1234L,
        AppCatalogEntry.ZIP_BUNDLE_TYPE,
        List.of(QUEUE_READ_PERMISSION),
        Map.of());
  }

  private static AppCatalogEntry reviewedEntryWithTrustedReceipt(KeyPair reviewerKeyPair) {
    AppCatalogEntry unsignedEntry = updateEntry();
    AppReviewReceipt receipt =
        AppReviewReceiptSigner.sign(reviewPayload(unsignedEntry), reviewerKeyPair.getPrivate());
    return new AppCatalogEntry(
        unsignedEntry.appId(),
        unsignedEntry.name(),
        unsignedEntry.version(),
        unsignedEntry.summary(),
        unsignedEntry.homepage().orElse(null),
        unsignedEntry.source().orElse(null),
        unsignedEntry.license().orElse(null),
        unsignedEntry.categories(),
        unsignedEntry.compatibility(),
        unsignedEntry.review(),
        receipt,
        unsignedEntry.changelog(),
        unsignedEntry.screenshots(),
        unsignedEntry.bundleUri(),
        unsignedEntry.bundleSha256(),
        unsignedEntry.bundleSizeBytes(),
        unsignedEntry.bundleType(),
        unsignedEntry.permissions(),
        unsignedEntry.permissionRationales());
  }

  private static AppReviewReceiptPayload reviewPayload(AppCatalogEntry entry) {
    return new AppReviewReceiptPayload(
        AppReviewReceiptPayload.RECEIPT_VERSION,
        entry.appId(),
        entry.version(),
        entry.bundleSha256(),
        entry.bundleSizeBytes(),
        Optional.empty(),
        REVIEW_POLICY_ID,
        REVIEW_POLICY_VERSION,
        AppReviewReceiptStatus.REVIEWED,
        REVIEWER_KEY_ID,
        REVIEWED_AT,
        Optional.empty(),
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

  private static KeyPair reviewerKeyPair() throws GeneralSecurityException {
    return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
  }

  private static AppApiCompatibilityMetadata compatibleApiMetadata() {
    return new AppApiCompatibilityMetadata(
        1,
        PlatformApiContract.current().contractVersion(),
        List.of(),
        TargetStability.STABLE,
        false);
  }

  private AppCatalogInstallPlan plan(AppCatalogEntry entry) throws IOException {
    Path scratch = tempDir.resolve("scratch-" + entry.version());
    Path staged = scratch.resolve("bundle");
    Files.createDirectories(staged);
    Files.writeString(
        staged.resolve("cryptad-app.properties"),
        """
        manifest.version=1
        app.id=%s
        app.name=%s
        app.version=%s
        app.exec=bin/launch.sh
        app.permissions=%s
        """
            .formatted(
                entry.appId(),
                entry.name(),
                entry.version(),
                String.join(",", entry.permissions())));
    return new AppCatalogInstallPlan(CATALOG_ID, entry, staged, scratch);
  }
}

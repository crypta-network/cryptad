package network.crypta.platform.api.appupdates;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
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
import network.crypta.platform.appdist.AppApiCompatibilityMetadata;
import network.crypta.platform.appdist.AppUiMode;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.AppHostException;
import network.crypta.platform.apphost.AppRollbackRecord;
import network.crypta.platform.apphost.InstalledAppPaths;
import network.crypta.platform.apphost.InstalledAppSnapshot;
import network.crypta.platform.apphost.RunningAppSnapshot;
import network.crypta.platform.apphost.manifest.AppManifest;
import network.crypta.platform.apphost.manifest.AppManifestException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mockingDetails;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings({"java:S100", "unchecked"})
class AppUpdateServiceTest {
  private static final String APP_ID = "queue-manager";
  private static final String APP_NAME = "Queue Manager";
  private static final String CATALOG_ID = "core";
  private static final String DIGEST =
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  private static final String INSTALLED_VERSION = "1.0.0";
  private static final String UPDATE_VERSION = "1.1.0";
  private static final String EXTERNAL_VERSION = "1.2.0";
  private static final String QUEUE_READ_PERMISSION = "queue.read";
  private static final String CANDIDATE = "candidate";
  private static final String STAGED = "staged";
  private static final String ROLLBACK = "rollback";
  private static final String AVAILABLE = "available";
  private static final String STATUS = "status";
  private static final String VERSION_COMPARISON = "versionComparison";
  private static final String TARGET_VERSION = "targetVersion";
  private static final String INSTALLED_VERSION_FIELD = "installedVersion";
  private static final String OPERATOR_ACTION_REQUIRED = "operatorActionRequired";
  private static final String ERROR_CODE = "errorCode";
  private static final String MESSAGE = "message";
  private static final String FAILED = "failed";
  private static final String APPLIED = "applied";
  private static final String UPDATE_CANDIDATE_CHANGED = "update_candidate_changed";
  private static final String APP_NOT_FOUND = "app_not_found";
  private static final String ROLLBACK_FAILED = "rollback_failed";
  private static final AppUpdateService.ApplyOptions APPLY_NO_RESTART_NO_HEALTH =
      new AppUpdateService.ApplyOptions(false, AppUpdateService.HealthCheckMode.NONE, false);
  private static final AppUpdateService.ApplyOptions APPLY_NO_RESTART_PROCESS_HEALTH =
      new AppUpdateService.ApplyOptions(false, AppUpdateService.HealthCheckMode.PROCESS, false);
  private static final AppUpdateService.ApplyOptions APPLY_RESTART_NO_HEALTH =
      new AppUpdateService.ApplyOptions(true, AppUpdateService.HealthCheckMode.NONE, false);
  private static final AppUpdateService.ApplyOptions APPLY_RESTART_PROCESS_HEALTH =
      new AppUpdateService.ApplyOptions(true, AppUpdateService.HealthCheckMode.PROCESS, false);
  private static final AppUpdateService.ApplyOptions APPLY_RESTART_PROCESS_HEALTH_ROLLBACK =
      new AppUpdateService.ApplyOptions(true, AppUpdateService.HealthCheckMode.PROCESS, true);

  @Mock private AppHost appHost;
  @Mock private AppCatalogManager catalogManager;

  @TempDir private Path tempDir;

  @Test
  void check_whenManualPolicyFindsNewerCatalogVersion_expectCandidateOnly() throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listApps(CATALOG_ID))
        .thenReturn(List.of(entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED)));

    Map<String, Object> summary = service.check(APP_ID, false);

    Map<String, Object> candidate = (Map<String, Object>) summary.get(CANDIDATE);
    Map<String, Object> staged = (Map<String, Object>) summary.get(STAGED);
    assertEquals("manual", ((Map<?, ?>) summary.get("policy")).get("mode"));
    assertEquals(AVAILABLE, candidate.get(STATUS));
    assertEquals("newer", candidate.get(VERSION_COMPARISON));
    assertEquals(UPDATE_VERSION, candidate.get(TARGET_VERSION));
    assertEquals(false, staged.get(AVAILABLE));
    verifyNoInstallPlanPreparation();
    verify(appHost, never()).updateFromDirectory(any(), any());
  }

  @Test
  void check_whenCatalogVersionIsEqual_expectNoUpdateCandidate() throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listApps(CATALOG_ID))
        .thenReturn(List.of(entry(INSTALLED_VERSION, AppCatalogReviewStatus.REVIEWED)));

    Map<String, Object> candidate =
        (Map<String, Object>) service.check(APP_ID, false).get(CANDIDATE);

    assertEquals("none", candidate.get(STATUS));
    assertEquals("equal", candidate.get(VERSION_COMPARISON));
    assertEquals(false, candidate.get(OPERATOR_ACTION_REQUIRED));
  }

  @Test
  void check_whenEqualCatalogVersionRequiresFuturePlatformApi_expectNoUpdateCandidate()
      throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    AppApiCompatibilityMetadata futureContract =
        new AppApiCompatibilityMetadata(3, 3, List.of(), false);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listApps(CATALOG_ID))
        .thenReturn(
            List.of(entry(INSTALLED_VERSION, AppCatalogReviewStatus.REVIEWED, futureContract)));

    Map<String, Object> candidate =
        (Map<String, Object>) service.check(APP_ID, false).get(CANDIDATE);

    assertEquals("none", candidate.get(STATUS));
    assertEquals("equal", candidate.get(VERSION_COMPARISON));
    assertEquals(false, candidate.get(OPERATOR_ACTION_REQUIRED));
  }

  @Test
  void check_whenCatalogVersionIsLower_expectNoOperatorActionRequired() throws Exception {
    AppUpdateService service = serviceWithInstalled(UPDATE_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listApps(CATALOG_ID))
        .thenReturn(List.of(entry(INSTALLED_VERSION, AppCatalogReviewStatus.REVIEWED)));

    Map<String, Object> candidate =
        (Map<String, Object>) service.check(APP_ID, false).get(CANDIDATE);

    assertEquals("not_newer", candidate.get(STATUS));
    assertEquals("lower", candidate.get(VERSION_COMPARISON));
    assertEquals(false, candidate.get(OPERATOR_ACTION_REQUIRED));
  }

  @Test
  void check_whenLowerCatalogVersionRequiresFuturePlatformApi_expectNotNewerCandidate()
      throws Exception {
    AppUpdateService service = serviceWithInstalled(UPDATE_VERSION, List.of(QUEUE_READ_PERMISSION));
    AppApiCompatibilityMetadata futureContract =
        new AppApiCompatibilityMetadata(3, 3, List.of(), false);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listApps(CATALOG_ID))
        .thenReturn(
            List.of(entry(INSTALLED_VERSION, AppCatalogReviewStatus.REVIEWED, futureContract)));

    Map<String, Object> candidate =
        (Map<String, Object>) service.check(APP_ID, false).get(CANDIDATE);

    assertEquals("not_newer", candidate.get(STATUS));
    assertEquals("lower", candidate.get(VERSION_COMPARISON));
    assertEquals(false, candidate.get(OPERATOR_ACTION_REQUIRED));
  }

  @Test
  void check_whenCatalogVersionIsAmbiguous_expectOperatorActionRequired() throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listApps(CATALOG_ID))
        .thenReturn(List.of(entry("1.0-beta", AppCatalogReviewStatus.REVIEWED)));

    Map<String, Object> candidate =
        (Map<String, Object>) service.check(APP_ID, false).get(CANDIDATE);

    assertEquals("ambiguous", candidate.get(STATUS));
    assertEquals("ambiguous", candidate.get(VERSION_COMPARISON));
    assertEquals(true, candidate.get(OPERATOR_ACTION_REQUIRED));
  }

  @Test
  void check_whenMultipleCatalogsHaveAvailableUpdates_expectNewestComparableCandidate()
      throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog("alpha"), catalog("beta")));
    when(catalogManager.listApps("alpha"))
        .thenReturn(List.of(entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED)));
    when(catalogManager.listApps("beta"))
        .thenReturn(List.of(entry("2.0.0", AppCatalogReviewStatus.REVIEWED)));

    Map<String, Object> candidate =
        (Map<String, Object>) service.check(APP_ID, false).get(CANDIDATE);

    assertEquals(AVAILABLE, candidate.get(STATUS));
    assertEquals("beta", candidate.get("catalogId"));
    assertEquals("2.0.0", candidate.get(TARGET_VERSION));
  }

  @Test
  void check_whenCatalogListingFails_expectLastCheckFailureRecorded() throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(catalogManager.listCatalogs()).thenThrow(new IOException("catalog store failed"));

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> service.check(APP_ID, false));

    assertEquals(500, exception.statusCode());
    assertEquals("catalog_list_failed", exception.errorCode());
    Map<String, Object> lastCheck = (Map<String, Object>) service.summary(APP_ID).get("lastCheck");
    assertEquals(FAILED, lastCheck.get(STATUS));
    assertEquals("catalog_list_failed", lastCheck.get(ERROR_CODE));
    assertEquals("Update candidate check failed.", lastCheck.get(MESSAGE));
    verifyNoInstallPlanPreparation();
  }

  @Test
  void check_whenPolicyStageFails_expectLastCheckFailureRecorded() throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    AppCatalogEntry entry =
        entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED, compatibleApiMetadata());
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listApps(CATALOG_ID)).thenReturn(List.of(entry));
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID))
        .thenThrow(new IOException("stage failed"));
    service.setPolicy(APP_ID, AppUpdatePolicyMode.STAGE);

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> service.check(APP_ID, false));

    assertEquals(500, exception.statusCode());
    assertEquals("stage_failed", exception.errorCode());
    Map<String, Object> lastCheck = (Map<String, Object>) service.summary(APP_ID).get("lastCheck");
    assertEquals(FAILED, lastCheck.get(STATUS));
    assertEquals("stage_failed", lastCheck.get(ERROR_CODE));
    assertEquals("Update candidate check failed.", lastCheck.get(MESSAGE));
  }

  @Test
  void stage_whenCandidateRequiresFuturePlatformApi_expectStableIncompatibleFailure()
      throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    AppApiCompatibilityMetadata futureContract =
        new AppApiCompatibilityMetadata(3, 3, List.of(), false);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listApps(CATALOG_ID))
        .thenReturn(
            List.of(entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED, futureContract)));
    service.check(APP_ID, false);

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> service.stage(APP_ID));

    assertEquals(409, exception.statusCode());
    assertEquals("update_incompatible", exception.errorCode());
    verifyNoInstallPlanPreparation();
  }

  @Test
  void stage_whenPreparedPlanNoLongerMatchesReviewedCandidate_expectCandidateChangedFailure()
      throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    AppCatalogEntry reviewedEntry = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    AppCatalogEntry changedEntry = entry(UPDATE_VERSION, AppCatalogReviewStatus.CAUTION);
    AppCatalogInstallPlan changedPlan = plan(changedEntry);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listApps(CATALOG_ID)).thenReturn(List.of(reviewedEntry));
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(changedPlan);
    service.check(APP_ID, false);

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> service.stage(APP_ID));

    assertEquals(409, exception.statusCode());
    assertEquals(UPDATE_CANDIDATE_CHANGED, exception.errorCode());
    assertFalse(Files.exists(changedPlan.scratchDirectory()));
    verify(appHost, never()).updateFromDirectory(any(), any());
  }

  @Test
  void check_whenCatalogGateMetadataChangesAfterStage_expectStageInvalidated() throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    AppCatalogEntry compatibleEntry = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    AppApiCompatibilityMetadata futureContract =
        new AppApiCompatibilityMetadata(3, 3, List.of(), false);
    AppCatalogEntry incompatibleEntry =
        entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED, futureContract);
    AppCatalogInstallPlan plan = plan(compatibleEntry);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listApps(CATALOG_ID))
        .thenReturn(List.of(compatibleEntry), List.of(incompatibleEntry));
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
    service.stage(APP_ID);

    Map<String, Object> summary = service.check(APP_ID, false);

    assertEquals(false, ((Map<?, ?>) summary.get(STAGED)).get(AVAILABLE));
    assertEquals("incompatible", ((Map<?, ?>) summary.get(CANDIDATE)).get(STATUS));
    assertFalse(Files.exists(plan.scratchDirectory()));
    verify(appHost, never()).updateFromDirectory(any(), any());
  }

  @Test
  void check_whenPolicyIsStage_expectVerifiedCandidateStagedWithoutApply() throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    AppCatalogEntry entry =
        entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED, compatibleApiMetadata());
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listApps(CATALOG_ID)).thenReturn(List.of(entry));
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan(entry));
    service.setPolicy(APP_ID, AppUpdatePolicyMode.STAGE);

    Map<String, Object> summary = service.check(APP_ID, false);

    Map<String, Object> staged = (Map<String, Object>) summary.get(STAGED);
    assertEquals(true, staged.get(AVAILABLE));
    assertEquals(STAGED, staged.get(STATUS));
    assertEquals(UPDATE_VERSION, staged.get(TARGET_VERSION));
    assertFalse(staged.toString().contains(tempDir.toString()));
    verify(appHost, never()).updateFromDirectory(any(), any());
  }

  @Test
  void check_whenPolicyApplyWhenStopped_expectStagedCandidateApplied() throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    InstalledAppSnapshot updated = installed(UPDATE_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID))
        .thenReturn(
            Optional.of(installed),
            Optional.of(installed),
            Optional.of(installed),
            Optional.of(updated));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);
    AppCatalogEntry entry =
        entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED, compatibleApiMetadata());
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listApps(CATALOG_ID)).thenReturn(List.of(entry));
    AppCatalogInstallPlan plan = plan(entry);
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
    when(appHost.updateFromDirectory(APP_ID, plan.stagedBundleDirectory())).thenReturn(updated);
    service.setPolicy(APP_ID, AppUpdatePolicyMode.APPLY_WHEN_STOPPED);

    Map<String, Object> summary = service.check(APP_ID, false);

    assertEquals(UPDATE_VERSION, summary.get(INSTALLED_VERSION_FIELD));
    assertEquals(APPLIED, ((Map<?, ?>) summary.get(CANDIDATE)).get(STATUS));
    verify(appHost).updateFromDirectory(APP_ID, plan.stagedBundleDirectory());
  }

  @Test
  void apply_whenInstalledVersionChangedAfterStage_expectStageInvalidatedAndApplyBlocked()
      throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    InstalledAppSnapshot externallyUpdated =
        installed(EXTERNAL_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID))
        .thenReturn(
            Optional.of(installed), Optional.of(externallyUpdated), Optional.of(externallyUpdated));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);
    AppCatalogEntry entry = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listApps(CATALOG_ID)).thenReturn(List.of(entry));
    AppCatalogInstallPlan plan = plan(entry);
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
    service.stage(APP_ID);

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class, () -> service.apply(APP_ID, APPLY_NO_RESTART_NO_HEALTH));

    assertEquals(409, exception.statusCode());
    assertEquals(UPDATE_CANDIDATE_CHANGED, exception.errorCode());
    assertEquals(false, ((Map<?, ?>) service.summary(APP_ID).get(STAGED)).get(AVAILABLE));
    assertFalse(Files.exists(plan.scratchDirectory()));
    verify(appHost, never()).updateFromDirectory(any(), any());
  }

  @Test
  void summary_whenInstalledVersionChangedAfterStage_expectStageInvalidatedAndCandidateCleared()
      throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    InstalledAppSnapshot externallyUpdated =
        installed(EXTERNAL_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID))
        .thenReturn(Optional.of(installed), Optional.of(externallyUpdated));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);
    AppCatalogEntry entry = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listApps(CATALOG_ID)).thenReturn(List.of(entry));
    AppCatalogInstallPlan plan = plan(entry);
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
    service.stage(APP_ID);

    Map<String, Object> summary = service.summary(APP_ID);

    assertEquals(EXTERNAL_VERSION, summary.get(INSTALLED_VERSION_FIELD));
    assertEquals(false, ((Map<?, ?>) summary.get(STAGED)).get(AVAILABLE));
    assertEquals("none", ((Map<?, ?>) summary.get(CANDIDATE)).get(STATUS));
    assertEquals(
        EXTERNAL_VERSION, ((Map<?, ?>) summary.get(CANDIDATE)).get(INSTALLED_VERSION_FIELD));
    assertFalse(Files.exists(plan.scratchDirectory()));
    verify(appHost, never()).updateFromDirectory(any(), any());
  }

  @Test
  void summary_whenSameVersionManifestChangesAfterStage_expectStageInvalidatedAndCandidateCleared()
      throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    InstalledAppSnapshot manifestChanged =
        installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION, "network.access"));
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installed), Optional.of(manifestChanged));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);
    AppCatalogEntry entry = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listApps(CATALOG_ID)).thenReturn(List.of(entry));
    AppCatalogInstallPlan plan = plan(entry);
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
    service.stage(APP_ID);

    Map<String, Object> summary = service.summary(APP_ID);

    assertEquals(INSTALLED_VERSION, summary.get(INSTALLED_VERSION_FIELD));
    assertEquals(false, ((Map<?, ?>) summary.get(STAGED)).get(AVAILABLE));
    assertEquals("none", ((Map<?, ?>) summary.get(CANDIDATE)).get(STATUS));
    assertFalse(Files.exists(plan.scratchDirectory()));
    verify(appHost, never()).updateFromDirectory(any(), any());
  }

  @Test
  void summary_whenAppUninstalledAfterStage_expectStageClosedAndCandidateCleared()
      throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    InstalledAppSnapshot reinstalled = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID))
        .thenReturn(Optional.of(installed), Optional.empty(), Optional.of(reinstalled));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);
    AppCatalogEntry entry = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listApps(CATALOG_ID)).thenReturn(List.of(entry));
    AppCatalogInstallPlan plan = plan(entry);
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
    service.stage(APP_ID);

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> service.summary(APP_ID));

    assertEquals(404, exception.statusCode());
    assertEquals(APP_NOT_FOUND, exception.errorCode());
    assertFalse(Files.exists(plan.scratchDirectory()));
    Map<String, Object> summary = service.summary(APP_ID);
    assertEquals(false, ((Map<?, ?>) summary.get(STAGED)).get(AVAILABLE));
    assertEquals("none", ((Map<?, ?>) summary.get(CANDIDATE)).get(STATUS));
    verify(appHost, never()).updateFromDirectory(any(), any());
  }

  @Test
  void apply_whenSameVersionManifestChangesAfterStage_expectStageInvalidatedAndApplyBlocked()
      throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    InstalledAppSnapshot manifestChanged =
        installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION, "network.access"));
    when(appHost.describe(APP_ID))
        .thenReturn(
            Optional.of(installed), Optional.of(manifestChanged), Optional.of(manifestChanged));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);
    AppCatalogEntry entry = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listApps(CATALOG_ID)).thenReturn(List.of(entry));
    AppCatalogInstallPlan plan = plan(entry);
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
    service.stage(APP_ID);

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class, () -> service.apply(APP_ID, APPLY_NO_RESTART_NO_HEALTH));

    assertEquals(409, exception.statusCode());
    assertEquals(UPDATE_CANDIDATE_CHANGED, exception.errorCode());
    assertEquals(false, ((Map<?, ?>) service.summary(APP_ID).get(STAGED)).get(AVAILABLE));
    assertFalse(Files.exists(plan.scratchDirectory()));
    verify(appHost, never()).updateFromDirectory(any(), any());
  }

  @Test
  void apply_whenProcessHealthRequestedWithoutRestart_expectInvalidOptionBeforeReplacement()
      throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installed));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);
    AppCatalogEntry entry = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listApps(CATALOG_ID)).thenReturn(List.of(entry));
    AppCatalogInstallPlan plan = plan(entry);
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
    service.stage(APP_ID);

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class,
            () -> service.apply(APP_ID, APPLY_NO_RESTART_PROCESS_HEALTH));

    assertEquals(400, exception.statusCode());
    assertEquals("invalid_update_option", exception.errorCode());
    assertEquals(true, ((Map<?, ?>) service.summary(APP_ID).get(STAGED)).get(AVAILABLE));
    verify(appHost, never()).updateFromDirectory(any(), any());
  }

  @Test
  void apply_whenRestartedRunningAppFailsBeforeReplacement_expectOriginalAppRestarted()
      throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installed));
    when(appHost.status(APP_ID))
        .thenReturn(
            Optional.empty(), Optional.empty(), Optional.of(running(installed)), Optional.empty());
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);
    AppCatalogEntry entry = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listApps(CATALOG_ID)).thenReturn(List.of(entry));
    try (AppCatalogInstallPlan plan = plan(entry)) {
      when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
      when(appHost.updateFromDirectory(APP_ID, plan.stagedBundleDirectory()))
          .thenThrow(new IOException("staged directory disappeared"));
      service.stage(APP_ID);

      PlatformApiException exception =
          assertThrows(
              PlatformApiException.class, () -> service.apply(APP_ID, APPLY_RESTART_NO_HEALTH));

      assertEquals(500, exception.statusCode());
      assertEquals("update_failed", exception.errorCode());
      assertEquals(true, ((Map<?, ?>) service.summary(APP_ID).get(STAGED)).get(AVAILABLE));
      verify(appHost).stop(APP_ID);
      verify(appHost).start(APP_ID);
    }
  }

  @Test
  void apply_whenRestartProcessHealthLaunchFails_expectRollbackAttempted() throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    InstalledAppSnapshot updated = installed(UPDATE_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID))
        .thenReturn(Optional.of(installed), Optional.of(installed), Optional.of(installed));
    when(appHost.status(APP_ID))
        .thenReturn(
            Optional.empty(), Optional.empty(), Optional.of(running(installed)), Optional.empty());
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);
    AppCatalogEntry entry = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listApps(CATALOG_ID)).thenReturn(List.of(entry));
    AppCatalogInstallPlan plan = plan(entry);
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
    when(appHost.updateFromDirectory(APP_ID, plan.stagedBundleDirectory())).thenReturn(updated);
    when(appHost.start(APP_ID)).thenThrow(new IOException("launch failed"));
    when(appHost.rollbackStatus(APP_ID))
        .thenReturn(Optional.of(new AppRollbackRecord(APP_ID, APP_NAME, INSTALLED_VERSION)));
    when(appHost.rollback(APP_ID)).thenReturn(installed);
    service.stage(APP_ID);

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class,
            () -> service.apply(APP_ID, APPLY_RESTART_PROCESS_HEALTH_ROLLBACK));

    assertEquals(409, exception.statusCode());
    assertEquals("health_check_failed", exception.errorCode());
    verify(appHost).stop(APP_ID);
    verify(appHost).updateFromDirectory(APP_ID, plan.stagedBundleDirectory());
    verify(appHost).rollback(APP_ID);
    Map<String, Object> summary = service.summary(APP_ID);
    assertEquals(false, ((Map<?, ?>) summary.get(STAGED)).get(AVAILABLE));
    assertEquals("none", ((Map<?, ?>) summary.get(CANDIDATE)).get(STATUS));
    assertFalse(Files.exists(plan.scratchDirectory()));
  }

  @Test
  void apply_whenHealthRollbackStatusCannotBeRead_expectRollbackFailure() throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    InstalledAppSnapshot updated = installed(UPDATE_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID))
        .thenReturn(Optional.of(installed), Optional.of(installed), Optional.of(updated));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);
    AppCatalogEntry entry = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listApps(CATALOG_ID)).thenReturn(List.of(entry));
    AppCatalogInstallPlan plan = plan(entry);
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
    when(appHost.updateFromDirectory(APP_ID, plan.stagedBundleDirectory())).thenReturn(updated);
    when(appHost.start(APP_ID)).thenReturn(running(updated));
    when(appHost.rollbackStatus(APP_ID)).thenThrow(new IOException("rollback manifest broken"));
    service.stage(APP_ID);

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class,
            () -> service.apply(APP_ID, APPLY_RESTART_PROCESS_HEALTH_ROLLBACK));

    assertEquals(500, exception.statusCode());
    assertEquals(ROLLBACK_FAILED, exception.errorCode());
    Map<String, Object> summary = service.summary(APP_ID);
    assertEquals(false, ((Map<?, ?>) summary.get(STAGED)).get(AVAILABLE));
    assertEquals(APPLIED, ((Map<?, ?>) summary.get(CANDIDATE)).get(STATUS));
    assertEquals(FAILED, ((Map<?, ?>) summary.get(ROLLBACK)).get(STATUS));
    verify(appHost, never()).rollback(APP_ID);
    assertFalse(Files.exists(plan.scratchDirectory()));
  }

  @Test
  void apply_whenProcessHealthFailsAfterReplacementWithoutRollback_expectCandidateMarkedApplied()
      throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    InstalledAppSnapshot updated = installed(UPDATE_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID))
        .thenReturn(Optional.of(installed), Optional.of(installed), Optional.of(updated));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);
    AppCatalogEntry entry = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listApps(CATALOG_ID)).thenReturn(List.of(entry));
    AppCatalogInstallPlan plan = plan(entry);
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
    when(appHost.updateFromDirectory(APP_ID, plan.stagedBundleDirectory())).thenReturn(updated);
    when(appHost.start(APP_ID)).thenReturn(running(updated));
    service.stage(APP_ID);

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class, () -> service.apply(APP_ID, APPLY_RESTART_PROCESS_HEALTH));

    assertEquals(409, exception.statusCode());
    assertEquals("health_check_failed", exception.errorCode());
    Map<String, Object> summary = service.summary(APP_ID);
    assertEquals(false, ((Map<?, ?>) summary.get(STAGED)).get(AVAILABLE));
    assertEquals(APPLIED, ((Map<?, ?>) summary.get(CANDIDATE)).get(STATUS));
    verify(appHost, never()).rollback(APP_ID);
    assertFalse(Files.exists(plan.scratchDirectory()));
  }

  @Test
  void apply_whenRestartWithoutHealthCheckFailsAfterReplacement_expectStageCleared()
      throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    InstalledAppSnapshot updated = installed(UPDATE_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID))
        .thenReturn(Optional.of(installed), Optional.of(installed), Optional.of(updated));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);
    AppCatalogEntry entry = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listApps(CATALOG_ID)).thenReturn(List.of(entry));
    AppCatalogInstallPlan plan = plan(entry);
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
    when(appHost.updateFromDirectory(APP_ID, plan.stagedBundleDirectory())).thenReturn(updated);
    when(appHost.start(APP_ID)).thenThrow(new IOException("launch failed"));
    service.stage(APP_ID);

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class, () -> service.apply(APP_ID, APPLY_RESTART_NO_HEALTH));

    assertEquals(500, exception.statusCode());
    assertEquals("update_failed", exception.errorCode());
    Map<String, Object> summary = service.summary(APP_ID);
    assertEquals(false, ((Map<?, ?>) summary.get(STAGED)).get(AVAILABLE));
    assertEquals(APPLIED, ((Map<?, ?>) summary.get(CANDIDATE)).get(STATUS));
    assertFalse(Files.exists(plan.scratchDirectory()));
  }

  @Test
  void apply_whenAppStartsAfterPrecheck_expectConflictNotServerError() throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    AppCatalogEntry entry = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listApps(CATALOG_ID)).thenReturn(List.of(entry));
    AppCatalogInstallPlan plan = plan(entry);
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
    when(appHost.updateFromDirectory(APP_ID, plan.stagedBundleDirectory()))
        .thenThrow(new AppHostException("cannot update a running app: " + APP_ID));
    service.stage(APP_ID);

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class, () -> service.apply(APP_ID, APPLY_NO_RESTART_NO_HEALTH));

    assertEquals(409, exception.statusCode());
    assertEquals("app_running", exception.errorCode());
    assertEquals(true, ((Map<?, ?>) service.summary(APP_ID).get(STAGED)).get(AVAILABLE));
  }

  @Test
  void apply_whenAppIsUninstalledAfterPrecheck_expectNotFoundNotServerError() throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    AppCatalogEntry entry = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listApps(CATALOG_ID)).thenReturn(List.of(entry));
    AppCatalogInstallPlan plan = plan(entry);
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
    when(appHost.updateFromDirectory(APP_ID, plan.stagedBundleDirectory()))
        .thenThrow(new AppHostException("app is not installed: " + APP_ID));
    service.stage(APP_ID);

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class, () -> service.apply(APP_ID, APPLY_NO_RESTART_NO_HEALTH));

    assertEquals(404, exception.statusCode());
    assertEquals(APP_NOT_FOUND, exception.errorCode());
  }

  @Test
  void apply_whenAppHostRejectsStagedBundle_expectInvalidBundleNotServerError() throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    AppCatalogEntry entry = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listApps(CATALOG_ID)).thenReturn(List.of(entry));
    AppCatalogInstallPlan plan = plan(entry);
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
    when(appHost.updateFromDirectory(APP_ID, plan.stagedBundleDirectory()))
        .thenThrow(new AppManifestException("copied manifest is invalid"));
    service.stage(APP_ID);

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class, () -> service.apply(APP_ID, APPLY_NO_RESTART_NO_HEALTH));

    assertEquals(400, exception.statusCode());
    assertEquals("invalid_app_bundle", exception.errorCode());
  }

  @Test
  void check_whenPolicyApplyWhenStoppedAndReviewRequiresCaution_expectAutoApplyBlocked()
      throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listApps(CATALOG_ID))
        .thenReturn(
            List.of(
                entry(UPDATE_VERSION, AppCatalogReviewStatus.CAUTION, compatibleApiMetadata())));
    service.setPolicy(APP_ID, AppUpdatePolicyMode.APPLY_WHEN_STOPPED);

    Map<String, Object> summary = service.check(APP_ID, false);

    Map<String, Object> candidate = (Map<String, Object>) summary.get(CANDIDATE);
    assertEquals(AVAILABLE, candidate.get(STATUS));
    assertEquals(false, candidate.get("autoApplyAllowed"));
    assertEquals(false, ((Map<?, ?>) summary.get(STAGED)).get(AVAILABLE));
    verifyNoInstallPlanPreparation();
    verify(appHost, never()).updateFromDirectory(any(), any());
  }

  @Test
  void check_whenPolicyApplyWhenStoppedAndApiNewerThanTested_expectAutoApplyBlocked()
      throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    AppApiCompatibilityMetadata newerThanTested =
        new AppApiCompatibilityMetadata(1, 1, List.of(), false);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listApps(CATALOG_ID))
        .thenReturn(
            List.of(entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED, newerThanTested)));
    service.setPolicy(APP_ID, AppUpdatePolicyMode.APPLY_WHEN_STOPPED);

    Map<String, Object> summary = service.check(APP_ID, false);

    Map<String, Object> candidate = (Map<String, Object>) summary.get(CANDIDATE);
    assertEquals(AVAILABLE, candidate.get(STATUS));
    assertEquals(false, candidate.get("autoApplyAllowed"));
    assertEquals("newer_than_tested", ((Map<?, ?>) candidate.get("apiCompatibility")).get(STATUS));
    assertEquals(false, ((Map<?, ?>) summary.get(STAGED)).get(AVAILABLE));
    verifyNoInstallPlanPreparation();
    verify(appHost, never()).updateFromDirectory(any(), any());
  }

  @Test
  void check_whenPolicyApplyWhenStoppedAndAppRunning_expectApplySkipped() throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installed));
    when(appHost.status(APP_ID)).thenReturn(Optional.of(running(installed)));
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listApps(CATALOG_ID))
        .thenReturn(
            List.of(
                entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED, compatibleApiMetadata())));
    service.setPolicy(APP_ID, AppUpdatePolicyMode.APPLY_WHEN_STOPPED);

    Map<String, Object> summary = service.check(APP_ID, false);

    assertEquals(false, ((Map<?, ?>) summary.get(STAGED)).get(AVAILABLE));
    assertEquals(true, ((Map<?, ?>) summary.get(CANDIDATE)).get("running"));
    verify(appHost, never()).updateFromDirectory(any(), any());
  }

  @Test
  void summary_whenRollbackRecordExists_expectPathFreeRollbackSummary() throws Exception {
    AppUpdateService service = serviceWithInstalled(UPDATE_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.rollbackStatus(APP_ID))
        .thenReturn(Optional.of(new AppRollbackRecord(APP_ID, APP_NAME, INSTALLED_VERSION)));

    Map<String, Object> summary = service.summary(APP_ID);

    Map<String, Object> rollback = (Map<String, Object>) summary.get(ROLLBACK);
    assertEquals(true, rollback.get(AVAILABLE));
    assertEquals(INSTALLED_VERSION, rollback.get("previousVersion"));
    assertEquals("bundle_only", rollback.get("scope"));
    assertFalse(summary.toString().contains(tempDir.toString()));
    assertFalse(summary.toString().contains("secret-token"));
  }

  @Test
  void summary_whenRollbackStatusFails_expectPathFreeFailureSummary() throws Exception {
    AppUpdateService service = serviceWithInstalled(UPDATE_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.rollbackStatus(APP_ID)).thenThrow(new IOException("bad rollback path"));

    Map<String, Object> summary = service.summary(APP_ID);

    Map<String, Object> rollback = (Map<String, Object>) summary.get(ROLLBACK);
    assertEquals(false, rollback.get(AVAILABLE));
    assertEquals(FAILED, rollback.get(STATUS));
    assertEquals(ROLLBACK_FAILED, rollback.get(ERROR_CODE));
    assertEquals("Rollback state could not be inspected.", rollback.get(MESSAGE));
    assertFalse(summary.toString().contains("bad rollback path"));
    assertFalse(summary.toString().contains(tempDir.toString()));
  }

  @Test
  void rollback_whenCurrentManifestWouldBeUnreadable_expectNoDescribePreflight() throws Exception {
    InstalledAppSnapshot rolledBack = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    when(appHost.rollback(APP_ID)).thenReturn(rolledBack);
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);

    Map<String, Object> summary = service.rollback(APP_ID, false);

    assertEquals(INSTALLED_VERSION, summary.get(INSTALLED_VERSION_FIELD));
    verify(appHost).rollback(APP_ID);
    verify(appHost, never()).describe(APP_ID);
  }

  @Test
  void rollback_whenRestartFailsAfterRestore_expectStateCleanedAndRestartFailureReported()
      throws Exception {
    InstalledAppSnapshot installed = installed(UPDATE_VERSION, List.of(QUEUE_READ_PERMISSION));
    InstalledAppSnapshot rolledBack = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID))
        .thenReturn(Optional.of(installed), Optional.of(installed), Optional.of(rolledBack));
    when(appHost.status(APP_ID))
        .thenReturn(
            Optional.empty(), Optional.empty(), Optional.of(running(installed)), Optional.empty());
    when(appHost.rollbackStatus(APP_ID))
        .thenReturn(Optional.of(new AppRollbackRecord(APP_ID, APP_NAME, INSTALLED_VERSION)));
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);
    AppCatalogEntry entry = entry(EXTERNAL_VERSION, AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listApps(CATALOG_ID)).thenReturn(List.of(entry));
    AppCatalogInstallPlan plan = plan(entry);
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
    when(appHost.rollback(APP_ID)).thenReturn(rolledBack);
    when(appHost.start(APP_ID)).thenThrow(new IOException("restart failed"));
    service.stage(APP_ID);

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> service.rollback(APP_ID, true));

    assertEquals(500, exception.statusCode());
    assertEquals("rollback_restart_failed", exception.errorCode());
    Map<String, Object> summary = service.summary(APP_ID);
    assertEquals(false, ((Map<?, ?>) summary.get(STAGED)).get(AVAILABLE));
    assertEquals("none", ((Map<?, ?>) summary.get(CANDIDATE)).get(STATUS));
    assertFalse(Files.exists(plan.scratchDirectory()));
    verify(appHost).stop(APP_ID);
    verify(appHost).start(APP_ID);
  }

  @Test
  void rollback_whenStoppedAppUsesRestartFlag_expectBundleRestoredWithoutStart() throws Exception {
    InstalledAppSnapshot rolledBack = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    when(appHost.rollback(APP_ID)).thenReturn(rolledBack);
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);

    Map<String, Object> summary = service.rollback(APP_ID, true);

    assertEquals(INSTALLED_VERSION, summary.get(INSTALLED_VERSION_FIELD));
    verify(appHost, never()).stop(APP_ID);
    verify(appHost, never()).start(APP_ID);
  }

  @Test
  void rollback_whenRunningAppCannotRestoreRecord_expectOriginalAppRestarted() throws Exception {
    InstalledAppSnapshot installed = installed(UPDATE_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.status(APP_ID)).thenReturn(Optional.of(running(installed)), Optional.empty());
    when(appHost.rollback(APP_ID))
        .thenThrow(new AppHostException("rollback record is not available: " + APP_ID));
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> service.rollback(APP_ID, true));

    assertEquals(404, exception.statusCode());
    assertEquals("rollback_not_available", exception.errorCode());
    verify(appHost).stop(APP_ID);
    verify(appHost).start(APP_ID);
  }

  @Test
  void rollback_whenRollbackRecordCannotBeRestored_expectFailureNotUnavailable() throws Exception {
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    when(appHost.rollback(APP_ID)).thenThrow(new IOException("rollback manifest broken"));
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> service.rollback(APP_ID, false));

    assertEquals(500, exception.statusCode());
    assertEquals(ROLLBACK_FAILED, exception.errorCode());
    verify(appHost).rollback(APP_ID);
  }

  @Test
  void rollback_whenAppStartsBeforeRestore_expectConflictNotServerError() throws Exception {
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    when(appHost.rollback(APP_ID))
        .thenThrow(new AppHostException("cannot rollback a running app: " + APP_ID));
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> service.rollback(APP_ID, false));

    assertEquals(409, exception.statusCode());
    assertEquals("rollback_app_running", exception.errorCode());
  }

  @Test
  void rollback_whenAppIsUninstalledBeforeRestore_expectNotFoundNotServerError() throws Exception {
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    when(appHost.rollback(APP_ID))
        .thenThrow(new AppHostException("app is not installed: " + APP_ID));
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> service.rollback(APP_ID, false));

    assertEquals(404, exception.statusCode());
    assertEquals(APP_NOT_FOUND, exception.errorCode());
  }

  @Test
  void rollback_whenRecordIsRemovedBeforeRestore_expectUnavailableNotServerError()
      throws Exception {
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    when(appHost.rollback(APP_ID))
        .thenThrow(new AppHostException("rollback record is not available: " + APP_ID));
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> service.rollback(APP_ID, false));

    assertEquals(404, exception.statusCode());
    assertEquals("rollback_not_available", exception.errorCode());
  }

  private void verifyNoInstallPlanPreparation() {
    assertFalse(
        mockingDetails(catalogManager).getInvocations().stream()
            .map(invocation -> invocation.getMethod().getName())
            .anyMatch("prepareInstallPlan"::equals),
        "prepareInstallPlan should not be called");
  }

  private AppUpdateService serviceWithInstalled(String version, List<String> permissions)
      throws Exception {
    InstalledAppSnapshot installed = installed(version, permissions);
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installed));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    return new AppUpdateService(appHost, catalogManager);
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
        installed.manifest(),
        installed.paths(),
        "secret-token",
        1234L,
        Instant.parse("2026-05-03T00:00:00Z"));
  }

  private static AppCatalogSourceSnapshot catalog() {
    return catalog(CATALOG_ID);
  }

  private static AppCatalogSourceSnapshot catalog(String catalogId) {
    Instant now = Instant.parse("2026-05-03T00:00:00Z");
    return new AppCatalogSourceSnapshot(
        catalogId,
        "Core Apps",
        URI.create("https://example.invalid/cryptad-app-catalog.properties"),
        now,
        1,
        now,
        now,
        now,
        now,
        AppCatalogFetchStatus.SUCCESS,
        Optional.empty(),
        Optional.empty(),
        Optional.of("https://example.invalid/cryptad-app-catalog.properties"));
  }

  private static AppCatalogEntry entry(String version, AppCatalogReviewStatus reviewStatus) {
    return entry(version, reviewStatus, AppApiCompatibilityMetadata.undeclared());
  }

  private static AppApiCompatibilityMetadata compatibleApiMetadata() {
    return new AppApiCompatibilityMetadata(
        1, PlatformApiContract.current().contractVersion(), List.of(), false);
  }

  private static AppCatalogEntry entry(
      String version, AppCatalogReviewStatus reviewStatus, AppApiCompatibilityMetadata metadata) {
    return new AppCatalogEntry(
        APP_ID,
        APP_NAME,
        version,
        "Manage queues.",
        Optional.empty(),
        Optional.empty(),
        Optional.empty(),
        List.of(),
        new AppCatalogCompatibilityMetadata(null, metadata),
        new AppCatalogReviewMetadata(reviewStatus, Optional.empty()),
        AppCatalogChangelog.EMPTY,
        List.of(),
        URI.create("file:///tmp/queue-manager-" + version + ".zip"),
        DIGEST,
        1234L,
        AppCatalogEntry.ZIP_BUNDLE_TYPE,
        List.of(QUEUE_READ_PERMISSION, "queue.write"),
        Map.of("queue.write", "Lets the app manage queue entries."));
  }

  private AppCatalogInstallPlan plan(AppCatalogEntry entry) throws IOException {
    Path scratch = tempDir.resolve("scratch-" + entry.version());
    Path staged = scratch.resolve("bundle");
    Files.createDirectories(staged);
    return new AppCatalogInstallPlan(CATALOG_ID, entry, staged, scratch);
  }
}

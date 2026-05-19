package network.crypta.platform.api.appupdates;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import network.crypta.platform.api.PlatformApiContract;
import network.crypta.platform.api.PlatformApiContractVerifier;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.appcatalog.AppCatalogEntry;
import network.crypta.platform.appcatalog.AppCatalogException;
import network.crypta.platform.appcatalog.AppCatalogInstallPlan;
import network.crypta.platform.appcatalog.AppCatalogManager;
import network.crypta.platform.appcatalog.AppCatalogReviewMetadata;
import network.crypta.platform.appcatalog.AppCatalogReviewStatus;
import network.crypta.platform.appcatalog.AppCatalogSourceSnapshot;
import network.crypta.platform.appcatalog.AppReviewPolicy;
import network.crypta.platform.appcatalog.AppReviewReceiptVerifier;
import network.crypta.platform.appcatalog.AppReviewTransparencyEventKind;
import network.crypta.platform.appcatalog.AppReviewTransparencyLog;
import network.crypta.platform.appcatalog.AppReviewTrustDecision;
import network.crypta.platform.appcatalog.TrustedReviewerKeys;
import network.crypta.platform.appcatalog.TrustedReviewerKeysLoader;
import network.crypta.platform.apphost.AppBundleVerificationException;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.AppHostException;
import network.crypta.platform.apphost.AppRollbackRecord;
import network.crypta.platform.apphost.InstalledAppSnapshot;
import network.crypta.platform.apphost.RunningAppSnapshot;
import network.crypta.platform.apphost.manifest.AppManifest;
import network.crypta.platform.apphost.manifest.AppManifestException;
import network.crypta.platform.appvault.AppVaultException;
import network.crypta.platform.appvault.AppVaultService;

/**
 * Coordinates conservative app update checks, staging, apply, policy, history, and rollback.
 *
 * <p>The service deliberately stays above signed catalog and AppHost primitives. Catalog entries
 * are still verified by {@link AppCatalogManager}; immutable bundle replacement and rollback remain
 * AppHost responsibilities. This layer stores only display-safe update lifecycle metadata and keeps
 * temporary staging paths private.
 *
 * <p>All public methods are synchronized because the current implementation keeps lifecycle state
 * in memory: pending staged plans, last-check summaries, recent history, cached candidates, and
 * local policy. The service revalidates cached candidates against the current installed manifest
 * and against the prepared catalog plan before applying. This protects operators from stale review
 * metadata, catalog refresh races, and updates performed through the legacy immediate endpoints.
 *
 * <p>The lifecycle is intentionally conservative. Default policy is manual, running apps are not
 * stopped unless the request allows restart choreography, and rollback restores only the immutable
 * installed bundle retained by AppHost. Mutable app data, cache, run directories, app tokens,
 * browser-session tokens, catalog scratch paths, and private catalog URIs are never exposed in
 * summaries.
 *
 * @see AppCatalogManager
 * @see AppHost
 */
public final class AppUpdateService {
  private static final int MAX_HISTORY_ENTRIES = 20;
  private static final String STATUS_SUCCESS = "success";
  private static final String STATUS_FAILED = "failed";
  private static final String ACTION_CHECK = "check";
  private static final String ACTION_STAGE = "stage";
  private static final String ACTION_APPLY = "apply";
  private static final String ACTION_ROLLBACK = "rollback";
  private static final String APP_NOT_INSTALLED_PREFIX = "app is not installed: ";
  private static final String CANNOT_UPDATE_RUNNING_APP_PREFIX = "cannot update a running app: ";
  private static final String CANNOT_ROLLBACK_RUNNING_APP_PREFIX =
      "cannot rollback a running app: ";
  private static final String ROLLBACK_RECORD_NOT_AVAILABLE_PREFIX =
      "rollback record is not available: ";
  private static final String ERROR_APP_RUNNING = "app_running";
  private static final String ERROR_UPDATE_NOT_AVAILABLE = "update_not_available";
  private static final String ERROR_UPDATE_NOT_STAGED = "update_not_staged";
  private static final String ERROR_UPDATE_INCOMPATIBLE = "update_incompatible";
  private static final String ERROR_UPDATE_POLICY_BLOCKED = "update_policy_blocked";
  private static final String ERROR_UPDATE_CANDIDATE_CHANGED = "update_candidate_changed";
  private static final String ERROR_ROLLBACK_NOT_AVAILABLE = "rollback_not_available";
  private static final String ERROR_ROLLBACK_APP_RUNNING = "rollback_app_running";
  private static final String ERROR_ROLLBACK_FAILED = "rollback_failed";
  private static final String ERROR_ROLLBACK_RESTART_FAILED = "rollback_restart_failed";
  private static final String ERROR_HEALTH_CHECK_FAILED = "health_check_failed";
  private static final String ERROR_UPDATE_FAILED = "update_failed";
  private static final String ERROR_STAGE_FAILED = "stage_failed";
  private static final String ERROR_INVALID_UPDATE_OPTION = "invalid_update_option";
  private static final String ERROR_INVALID_APP_BUNDLE = "invalid_app_bundle";
  private static final String ERROR_APP_REVIEW_MISSING = "app_review_missing";
  private static final String ERROR_APP_REVIEW_UNTRUSTED = "app_review_untrusted";
  private static final String ERROR_APP_REVIEW_REJECTED = "app_review_rejected";
  private static final String ERROR_APP_REVIEW_MISMATCH = "app_review_mismatch";
  private static final String ERROR_APP_REVIEW_EXPIRED = "app_review_expired";
  private static final String MESSAGE_APPLY_FAILED = "Failed to apply staged update.";
  private static final String MESSAGE_APPLY_VAULT_CLEANUP_FAILED =
      "Staged update applied; vault grant cleanup failed and requires operator review.";
  private static final String MESSAGE_STAGE_FAILED = "Failed to stage update candidate.";
  private static final String MESSAGE_ROLLBACK_FAILED = "Rollback failed.";
  private static final String VERSION_NEWER = "newer";
  private static final String VERSION_LOWER = "lower";
  private static final String VERSION_EQUAL = "equal";
  private static final String VERSION_AMBIGUOUS = "ambiguous";
  private static final String JSON_APP_ID = "appId";
  private static final String JSON_STATUS = "status";
  private static final String JSON_AVAILABLE = "available";
  private static final String JSON_STAGED_AT = "stagedAt";
  private static final String JSON_REVIEW_TRUST = "reviewTrust";
  private static final String JSON_REQUIRES_ACKNOWLEDGEMENT = "requiresAcknowledgement";
  private static final String JSON_BLOCKS_UPDATE = "blocksUpdate";
  private static final String JSON_BLOCKS_POLICY_APPLY = "blocksPolicyApply";
  private static final String JSON_MESSAGE = "message";

  private final AppHost appHost;
  private final AppCatalogManager catalogManager;
  private final AppReviewPolicy reviewPolicy;
  private final ReviewerKeysProvider reviewerKeysProvider;
  private final AppVaultService appVaultService;
  private SchedulerSummaryProvider schedulerSummaryProvider;
  private SchedulerStateCleaner schedulerStateCleaner = _ -> {};
  private final Map<String, AppUpdatePolicy> policies = new LinkedHashMap<>();
  private final Map<String, AppUpdateCandidate> candidates = new LinkedHashMap<>();
  private final Map<String, StagedUpdate> stagedUpdates = new LinkedHashMap<>();
  private final Map<String, LastCheck> lastChecks = new LinkedHashMap<>();
  private final Map<String, Deque<AppUpdateHistoryEntry>> history = new LinkedHashMap<>();

  /**
   * Creates an app-update service backed by signed catalogs and AppHost.
   *
   * <p>The service does not own process execution or catalog verification. It coordinates the two
   * existing subsystems and stores only path-free lifecycle summaries. Callers should normally keep
   * one service instance for the router lifetime so staged plans and recent history remain
   * consistent across update requests.
   *
   * @param appHost AppHost used for installed state, apply, start, stop, and rollback
   * @param catalogManager signed catalog manager used for candidate discovery and staging
   */
  public AppUpdateService(AppHost appHost, AppCatalogManager catalogManager) {
    this(appHost, catalogManager, null);
  }

  /**
   * Creates an app-update service with optional vault grant lifecycle integration.
   *
   * @param appHost AppHost used for installed state, apply, start, stop, and rollback
   * @param catalogManager signed catalog manager used for candidate discovery and staging
   * @param appVaultService optional app-vault service used to disable grants after permission
   *     removal
   */
  public AppUpdateService(
      AppHost appHost, AppCatalogManager catalogManager, AppVaultService appVaultService) {
    this(
        appHost,
        catalogManager,
        AppReviewPolicy.loadFromSystem(),
        trustedReviewerKeysFromSystem(),
        appVaultService,
        AppUpdateService::disabledSchedulerSummary);
  }

  /**
   * Creates an app-update service with explicit review policy and reviewer-key provider.
   *
   * @param appHost AppHost used for installed state, apply, start, stop, and rollback
   * @param catalogManager signed catalog manager used for candidate discovery and staging
   * @param reviewPolicy local review policy
   * @param reviewerKeysProvider provider for trusted reviewer keys
   */
  public AppUpdateService(
      AppHost appHost,
      AppCatalogManager catalogManager,
      AppReviewPolicy reviewPolicy,
      ReviewerKeysProvider reviewerKeysProvider) {
    this(appHost, catalogManager, reviewPolicy, reviewerKeysProvider, null);
  }

  /**
   * Creates an app-update service with explicit review policy, reviewer keys, and optional vault.
   *
   * @param appHost AppHost used for installed state, apply, start, stop, and rollback
   * @param catalogManager signed catalog manager used for candidate discovery and staging
   * @param reviewPolicy local review policy
   * @param reviewerKeysProvider provider for trusted reviewer keys
   * @param appVaultService optional app-vault service used to disable grants after permission
   *     removal
   */
  public AppUpdateService(
      AppHost appHost,
      AppCatalogManager catalogManager,
      AppReviewPolicy reviewPolicy,
      ReviewerKeysProvider reviewerKeysProvider,
      AppVaultService appVaultService) {
    this(
        appHost,
        catalogManager,
        reviewPolicy,
        reviewerKeysProvider,
        appVaultService,
        AppUpdateService::disabledSchedulerSummary);
  }

  /**
   * Creates an app-update service with explicit review policy, reviewer keys, vault, and scheduler
   * summaries.
   *
   * <p>The scheduler provider is deliberately injected instead of started by the service
   * constructor. Runtime composition can create one shared service, create the scheduler around
   * that service, and then attach {@link AppUpdateScheduler#summary(String)} so API summaries and
   * background checks describe the same lifecycle state. Unit tests can keep the provider disabled
   * unless they are explicitly testing scheduler metadata.
   *
   * @param appHost AppHost used for installed state, apply, start, stop, and rollback
   * @param catalogManager signed catalog manager used for candidate discovery and staging
   * @param reviewPolicy local review policy
   * @param reviewerKeysProvider provider for trusted reviewer keys
   * @param appVaultService optional app-vault service used to disable grants after permission
   *     removal
   * @param schedulerSummaryProvider provider for path-free scheduler state
   */
  public AppUpdateService(
      AppHost appHost,
      AppCatalogManager catalogManager,
      AppReviewPolicy reviewPolicy,
      ReviewerKeysProvider reviewerKeysProvider,
      AppVaultService appVaultService,
      SchedulerSummaryProvider schedulerSummaryProvider) {
    this.appHost = Objects.requireNonNull(appHost, "appHost");
    this.catalogManager = Objects.requireNonNull(catalogManager, "catalogManager");
    this.reviewPolicy = Objects.requireNonNull(reviewPolicy, "reviewPolicy");
    this.reviewerKeysProvider =
        Objects.requireNonNull(reviewerKeysProvider, "reviewerKeysProvider");
    this.appVaultService = appVaultService;
    this.schedulerSummaryProvider =
        Objects.requireNonNull(schedulerSummaryProvider, "schedulerSummaryProvider");
  }

  private static ReviewerKeysProvider trustedReviewerKeysFromSystem() {
    return TrustedReviewerKeysLoader::loadFromSystem;
  }

  /**
   * Supplies trusted reviewer keys for review-receipt verification.
   *
   * <p>The provider exists so unit tests and embedders can inject ephemeral reviewer keys without
   * using process-wide system properties or environment variables.
   */
  @FunctionalInterface
  public interface ReviewerKeysProvider {
    /**
     * Returns trusted reviewer keys for the current request.
     *
     * @return local trusted reviewer keys
     * @throws IOException if configured key material cannot be read
     */
    TrustedReviewerKeys trustedReviewerKeys() throws IOException;
  }

  /**
   * Supplies path-free scheduler metadata for update summaries.
   *
   * <p>The update service owns lifecycle state, while the optional background scheduler owns
   * scheduler timestamps, backoff, and failure counters. This provider keeps the two lifecycles
   * loosely coupled: services constructed for unit tests or alternate embeddings can use the
   * disabled default, and the HTTP runtime can attach its durable scheduler after both objects are
   * constructed.
   */
  @FunctionalInterface
  public interface SchedulerSummaryProvider {
    /**
     * Returns path-free scheduler state for one installed app.
     *
     * @param appId normalized app id
     * @return JSON-compatible scheduler summary
     */
    Map<String, Object> schedulerSummary(String appId);
  }

  /**
   * Clears path-free scheduler metadata for an app whose update lifecycle state is being reset.
   *
   * <p>The background scheduler owns durable scheduler timestamps and backoff state. This callback
   * lets uninstall and missing-app cleanup reset that scheduler-owned metadata together with the
   * service-owned candidate, policy, staged, and history state.
   */
  @FunctionalInterface
  public interface SchedulerStateCleaner {
    /**
     * Clears scheduler metadata for one app.
     *
     * @param appId normalized app id
     */
    void clearSchedulerState(String appId);
  }

  /**
   * Attaches the scheduler summary provider used by later update summaries.
   *
   * <p>The method is synchronized to coordinate with the service's summary path. It changes only
   * display metadata; it does not start background work, check catalogs, stage updates, apply
   * bundles, or alter per-app update policy.
   *
   * @param schedulerSummaryProvider provider for scheduler state
   */
  public synchronized void setSchedulerSummaryProvider(
      SchedulerSummaryProvider schedulerSummaryProvider) {
    this.schedulerSummaryProvider =
        Objects.requireNonNull(schedulerSummaryProvider, "schedulerSummaryProvider");
  }

  /**
   * Attaches the scheduler-state cleanup callback used when app update state is cleared.
   *
   * <p>The callback is separate from summary rendering so embeddings that do not start a background
   * scheduler can keep the default no-op, while the HTTP runtime can remove durable scheduler
   * metadata for uninstalled apps.
   *
   * @param schedulerStateCleaner callback that clears scheduler metadata for an app
   */
  public synchronized void setSchedulerStateCleaner(SchedulerStateCleaner schedulerStateCleaner) {
    this.schedulerStateCleaner =
        Objects.requireNonNull(schedulerStateCleaner, "schedulerStateCleaner");
  }

  /**
   * Discards all local update lifecycle state for an app removed outside this service.
   *
   * <p>The existing app-management endpoint owns uninstall. When it removes an app, this method
   * closes any retained catalog staging plan and clears cached update metadata so catalog scratch
   * storage cannot leak and a later reinstall cannot inherit a stale reviewed candidate. The method
   * intentionally removes local policy, last-check, and history records as well because they
   * describe the removed installation rather than a future app with the same id.
   *
   * @param appId app id whose update state should be removed
   */
  public synchronized void clearAppState(String appId) {
    String normalizedAppId = normalizeInstalledAppId(appId);
    closeStage(normalizedAppId);
    candidates.remove(normalizedAppId);
    policies.remove(normalizedAppId);
    lastChecks.remove(normalizedAppId);
    history.remove(normalizedAppId);
    schedulerStateCleaner.clearSchedulerState(normalizedAppId);
  }

  /**
   * Returns the current update lifecycle summary for one app.
   *
   * <p>The summary includes the installed version, running state, policy, candidate, staged update,
   * rollback availability, last check, scheduler state, and recent history. It also performs
   * stale-state cleanup: if the app was updated or removed outside this service, incompatible
   * staged plans are closed before the response is built.
   *
   * @param appId app id from the request path
   * @return path-free update summary safe for Platform API responses
   */
  public synchronized Map<String, Object> summary(String appId) {
    String normalizedAppId = normalizeInstalledAppId(appId);
    InstalledAppSnapshot installed = requireInstalled(normalizedAppId);
    return summary(normalizedAppId, installed);
  }

  /**
   * Detects the current catalog update candidate and applies the configured policy.
   *
   * <p>Candidate detection starts from verified catalog snapshots. If refresh is requested, catalog
   * refresh failures are contained to that catalog and the last known verified snapshot remains in
   * use. The method records both successful and failed attempts in {@code lastCheck}. Policy may
   * stage or apply an eligible candidate, but manual policy only records the candidate.
   *
   * @param appId app id from the request path
   * @param refreshCatalogs whether to refresh catalog sidecars before detection
   * @return path-free update summary after detection and policy handling
   */
  public synchronized Map<String, Object> check(String appId, boolean refreshCatalogs) {
    String normalizedAppId = normalizeInstalledAppId(appId);
    Instant checkedAt = Instant.now();
    AppUpdateCandidate candidate = null;
    try {
      InstalledAppSnapshot installed = requireInstalled(normalizedAppId);
      candidate = detectCandidate(normalizedAppId, installed, refreshCatalogs);
      candidates.put(normalizedAppId, candidate);
      invalidateStaleStage(normalizedAppId, candidate);
      followPolicyAfterCheck(normalizedAppId, installed, candidate);
      recordLastCheck(normalizedAppId, checkedAt, null, null);
      appendHistory(
          normalizedAppId,
          ACTION_CHECK,
          STATUS_SUCCESS,
          candidate.catalogId(),
          candidate.targetVersion(),
          null,
          "Update candidate check completed.");
      return summary(normalizedAppId, requireInstalled(normalizedAppId));
    } catch (PlatformApiException exception) {
      recordLastCheck(
          normalizedAppId, checkedAt, exception.errorCode(), "Update candidate check failed.");
      appendHistory(
          normalizedAppId,
          ACTION_CHECK,
          STATUS_FAILED,
          candidate == null ? null : candidate.catalogId(),
          candidate == null ? null : candidate.targetVersion(),
          exception.errorCode(),
          "Update candidate check failed.");
      throw exception;
    }
  }

  /**
   * Stages a verified catalog update candidate for later explicit apply.
   *
   * <p>Staging uses {@link AppCatalogManager#prepareInstallPlan(String, String)} so the catalog
   * manager still owns download, extraction, signature verification, and scratch cleanup. The
   * prepared plan must match the reviewed candidate metadata before it is retained. The returned
   * summary never includes the staged directory or catalog scratch path.
   *
   * @param appId app id from the request path
   * @return path-free update summary after a verified candidate is staged
   */
  public synchronized Map<String, Object> stage(String appId) {
    return stage(appId, false);
  }

  /**
   * Stages a verified catalog update candidate with an explicit review acknowledgement option.
   *
   * @param appId app id from the request path
   * @param reviewAcknowledged whether the operator acknowledged an untrusted review decision
   * @return path-free update summary after a verified candidate is staged
   */
  public synchronized Map<String, Object> stage(String appId, boolean reviewAcknowledged) {
    String normalizedAppId = normalizeInstalledAppId(appId);
    InstalledAppSnapshot installed = requireInstalled(normalizedAppId);
    AppUpdateCandidate candidate = candidateOrDetect(normalizedAppId, installed);
    try {
      requireStageableCandidate(candidate, reviewAcknowledged);
      recordUpdateReviewGate(
          AppReviewTransparencyEventKind.REVIEW_GATE_UPDATE, candidate, "explicit_stage_allowed");
    } catch (PlatformApiException exception) {
      recordUpdateReviewGate(
          AppReviewTransparencyEventKind.REVIEW_GATE_UPDATE,
          candidate,
          "explicit_stage_blocked:" + exception.errorCode());
      throw exception;
    }
    stageCandidate(normalizedAppId, installed, candidate);
    return summary(normalizedAppId, installed);
  }

  /**
   * Applies the currently staged update candidate.
   *
   * <p>Apply refuses stale staged plans, incompatible candidates, and running apps unless restart
   * choreography was explicitly requested. When restart and process health are requested, a launch
   * failure or missing running status is treated as a health failure; optional rollback is
   * attempted only after AppHost has committed the new bundle and reports a rollback record.
   * Successful apply clears staged state and records an applied candidate.
   *
   * @param appId app id from the request path
   * @param options apply options decoded from query parameters
   * @return path-free update summary after apply or post-apply cleanup
   */
  public synchronized Map<String, Object> apply(String appId, ApplyOptions options) {
    String normalizedAppId = normalizeInstalledAppId(appId);
    InstalledAppSnapshot installed = requireInstalled(normalizedAppId);
    StagedUpdate staged = requireStagedUpdate(normalizedAppId);
    boolean wasRunning;
    try {
      wasRunning = validateApplyRequest(normalizedAppId, staged, installed, options);
      recordUpdateReviewGate(
          AppReviewTransparencyEventKind.REVIEW_GATE_POLICY_APPLY,
          staged.candidate(),
          "explicit_apply_allowed");
    } catch (PlatformApiException exception) {
      recordUpdateReviewGate(
          AppReviewTransparencyEventKind.REVIEW_GATE_POLICY_APPLY,
          staged.candidate(),
          "explicit_apply_blocked:" + exception.errorCode());
      throw exception;
    }

    InstalledAppSnapshot updated = null;
    HealthFailureState healthFailureState = new HealthFailureState();
    boolean vaultCleanupFailed;
    try {
      if (wasRunning) {
        appHost.stop(normalizedAppId);
      }
      updated = appHost.updateFromDirectory(normalizedAppId, staged.stagedBundleDirectory());
      if (options.restart()) {
        startOrTreatAsHealthFailure(normalizedAppId, options, healthFailureState);
      }
      verifyHealthOrRollback(normalizedAppId, options, healthFailureState);
      vaultCleanupFailed = !disableVaultGrantsAfterCommittedUpdate(updated, healthFailureState);
      closeStage(normalizedAppId);
      candidates.put(normalizedAppId, appliedCandidate(staged.candidate(), updated));
      appendHistory(
          normalizedAppId,
          ACTION_APPLY,
          STATUS_SUCCESS,
          staged.candidate().catalogId(),
          staged.candidate().targetVersion(),
          null,
          vaultCleanupFailed ? MESSAGE_APPLY_VAULT_CLEANUP_FAILED : "Staged update applied.");
      recordUpdateReviewGate(
          AppReviewTransparencyEventKind.REVIEW_GATE_POLICY_APPLY,
          staged.candidate(),
          "explicit_apply_applied");
      return summary(normalizedAppId, updated);
    } catch (PlatformApiException exception) {
      closeStage(normalizedAppId);
      if (updated != null) {
        disableVaultGrantsAfterCommittedUpdate(updated, healthFailureState);
        updateCandidateAfterPostApplyFailure(
            normalizedAppId, staged.candidate(), updated, healthFailureState);
      }
      recordApplyFailure(normalizedAppId, staged.candidate(), exception.errorCode());
      throw exception;
    } catch (AppHostException exception) {
      restartOriginalAfterUncommittedApplyFailure(normalizedAppId, wasRunning, updated);
      PlatformApiException mapped =
          appHostApplyFailure(normalizedAppId, staged, updated, healthFailureState, exception);
      recordApplyFailure(normalizedAppId, staged.candidate(), mapped.errorCode());
      throw mapped;
    } catch (IOException _) {
      if (updated != null) {
        disableVaultGrantsAfterCommittedUpdate(updated, healthFailureState);
        closeStage(normalizedAppId);
        updateCandidateAfterPostApplyFailure(
            normalizedAppId, staged.candidate(), updated, healthFailureState);
      } else {
        restartOriginalAfterUncommittedApplyFailure(normalizedAppId, wasRunning, null);
      }
      recordApplyFailure(normalizedAppId, staged.candidate(), ERROR_UPDATE_FAILED);
      throw lifecycleFailure(500, ERROR_UPDATE_FAILED, MESSAGE_APPLY_FAILED);
    }
  }

  private StagedUpdate requireStagedUpdate(String appId) {
    StagedUpdate staged = stagedUpdates.get(appId);
    if (staged == null) {
      throw lifecycleFailure(409, ERROR_UPDATE_NOT_STAGED, "No staged update is available.");
    }
    return staged;
  }

  private boolean validateApplyRequest(
      String appId, StagedUpdate staged, InstalledAppSnapshot installed, ApplyOptions options) {
    if (!staged.candidate().eligibleByDefault()) {
      throw lifecycleFailure(
          409, ERROR_UPDATE_POLICY_BLOCKED, "The staged update is not eligible by default.");
    }
    if (stageDiffersFromInstalled(staged, installed)) {
      closeStage(appId);
      candidates.remove(appId);
      appendHistory(
          appId,
          ACTION_APPLY,
          STATUS_FAILED,
          staged.candidate().catalogId(),
          staged.candidate().targetVersion(),
          ERROR_UPDATE_CANDIDATE_CHANGED,
          "Staged update no longer matches the installed app version.");
      throw lifecycleFailure(
          409,
          ERROR_UPDATE_CANDIDATE_CHANGED,
          "Installed app version changed since the update was staged.");
    }
    boolean wasRunning = appHost.status(appId).isPresent();
    if (wasRunning && !options.restart()) {
      throw lifecycleFailure(409, ERROR_APP_RUNNING, "App must be stopped before update.");
    }
    if (!options.restart() && options.healthCheck() == HealthCheckMode.PROCESS) {
      throw lifecycleFailure(
          400, ERROR_INVALID_UPDATE_OPTION, "healthCheck=process requires restart=true.");
    }
    return wasRunning;
  }

  private void recordApplyFailure(String appId, AppUpdateCandidate candidate, String errorCode) {
    appendHistory(
        appId,
        ACTION_APPLY,
        STATUS_FAILED,
        candidate.catalogId(),
        candidate.targetVersion(),
        errorCode,
        MESSAGE_APPLY_FAILED);
    recordUpdateReviewGate(
        AppReviewTransparencyEventKind.REVIEW_GATE_POLICY_APPLY,
        candidate,
        "apply_failed:" + errorCode);
  }

  private PlatformApiException appHostApplyFailure(
      String appId,
      StagedUpdate staged,
      InstalledAppSnapshot updated,
      HealthFailureState healthFailureState,
      AppHostException exception) {
    if (updated != null) {
      closeStage(appId);
      updateCandidateAfterPostApplyFailure(appId, staged.candidate(), updated, healthFailureState);
      return lifecycleFailure(500, ERROR_UPDATE_FAILED, MESSAGE_APPLY_FAILED);
    }
    if (isRunningUpdateFailure(exception) || appHost.status(appId).isPresent()) {
      return lifecycleFailure(409, ERROR_APP_RUNNING, "App must be stopped before update.");
    }
    if (isMissingAppFailure(exception)) {
      clearAppState(appId);
      return appNotFound();
    }
    if (isSignedBundleVerificationFailure(exception) || isInvalidAppBundleFailure(exception)) {
      clearRejectedStage(appId);
      return lifecycleFailure(
          400, ERROR_INVALID_APP_BUNDLE, "Staged app bundle failed AppHost validation.");
    }
    return lifecycleFailure(500, ERROR_UPDATE_FAILED, MESSAGE_APPLY_FAILED);
  }

  private void clearRejectedStage(String appId) {
    closeStage(appId);
    candidates.remove(appId);
  }

  /**
   * Restores the previous installed bundle retained by AppHost.
   *
   * <p>Rollback operates on the immutable installed bundle only. App data, cache, and run
   * directories remain attached to the app id and are not reverted. A running app blocks rollback
   * unless restart choreography is explicitly allowed. If the bundle restore commits but the
   * post-rollback restart fails, the method reports that restart failure while leaving stale staged
   * update state cleared.
   *
   * @param appId app id from the request path
   * @param restart whether the service may stop and restart a running app
   * @return path-free update summary after rollback completes
   */
  public synchronized Map<String, Object> rollback(String appId, boolean restart) {
    String normalizedAppId = normalizeInstalledAppId(appId);
    boolean wasRunning = appHost.status(normalizedAppId).isPresent();
    if (wasRunning && !restart) {
      throw lifecycleFailure(
          409, ERROR_ROLLBACK_APP_RUNNING, "App must be stopped before rollback.");
    }
    if (wasRunning) {
      requireRollbackAvailableBeforeStop(normalizedAppId);
    }
    try {
      if (wasRunning) {
        appHost.stop(normalizedAppId);
      }
      InstalledAppSnapshot rolledBack = invokeRollback(normalizedAppId);
      closeStage(normalizedAppId);
      candidates.remove(normalizedAppId);
      if (wasRunning) {
        startAfterRollback(normalizedAppId, rolledBack);
      }
      appendHistory(
          normalizedAppId,
          ACTION_ROLLBACK,
          STATUS_SUCCESS,
          null,
          rolledBack.manifest().appVersion(),
          null,
          "Previous app bundle restored.");
      return summary(normalizedAppId, rolledBack);
    } catch (AppHostException exception) {
      restartOriginalAfterUncommittedRollbackFailure(normalizedAppId, wasRunning);
      PlatformApiException mapped = appHostRollbackFailure(exception);
      recordRollbackFailure(normalizedAppId, mapped.errorCode());
      throw mapped;
    } catch (IOException _) {
      restartOriginalAfterUncommittedRollbackFailure(normalizedAppId, wasRunning);
      recordRollbackFailure(normalizedAppId, ERROR_ROLLBACK_FAILED);
      throw lifecycleFailure(500, ERROR_ROLLBACK_FAILED, MESSAGE_ROLLBACK_FAILED);
    }
  }

  private void requireRollbackAvailableBeforeStop(String appId) {
    try {
      if (rollbackStatusOrFailure(appId).isPresent()) {
        return;
      }
    } catch (PlatformApiException exception) {
      recordRollbackFailure(appId, exception.errorCode());
      throw exception;
    }
    recordRollbackFailure(appId, ERROR_ROLLBACK_NOT_AVAILABLE);
    throw lifecycleFailure(404, ERROR_ROLLBACK_NOT_AVAILABLE, "Rollback is not available.");
  }

  private boolean disableVaultGrantsRemovedByUpdate(InstalledAppSnapshot updated) {
    if (appVaultService == null) {
      return true;
    }
    try {
      appVaultService.disableGrantsForRemovedVaultPermissions(
          updated.appId(), new java.util.LinkedHashSet<>(updated.manifest().permissions()));
      return true;
    } catch (AppVaultException _) {
      return false;
    }
  }

  private boolean disableVaultGrantsAfterCommittedUpdate(
      InstalledAppSnapshot updated, HealthFailureState healthFailureState) {
    if (healthFailureState.rollbackCommitted()) {
      return true;
    }
    return disableVaultGrantsRemovedByUpdate(updated);
  }

  private void restartOriginalAfterUncommittedApplyFailure(
      String appId, boolean wasRunning, InstalledAppSnapshot updated) {
    if (updated != null) {
      return;
    }
    restartOriginalAfterUncommittedFailure(
        appId,
        wasRunning,
        ACTION_APPLY,
        ERROR_UPDATE_FAILED,
        "Update failed before replacement, and original app restart failed.");
  }

  private void restartOriginalAfterUncommittedRollbackFailure(String appId, boolean wasRunning) {
    restartOriginalAfterUncommittedFailure(
        appId,
        wasRunning,
        ACTION_ROLLBACK,
        ERROR_ROLLBACK_FAILED,
        "Rollback failed before restore, and original app restart failed.");
  }

  private void restartOriginalAfterUncommittedFailure(
      String appId, boolean wasRunning, String action, String errorCode, String message) {
    if (!wasRunning || appHost.status(appId).isPresent()) {
      return;
    }
    try {
      appHost.start(appId);
    } catch (IOException _) {
      appendHistory(appId, action, STATUS_FAILED, null, null, errorCode, message);
    }
  }

  private static PlatformApiException appHostRollbackFailure(AppHostException exception) {
    if (isRunningRollbackFailure(exception)) {
      return lifecycleFailure(
          409, ERROR_ROLLBACK_APP_RUNNING, "App must be stopped before rollback.");
    }
    if (isMissingAppFailure(exception)) {
      return appNotFound();
    }
    if (isRollbackRecordUnavailableFailure(exception)) {
      return lifecycleFailure(404, ERROR_ROLLBACK_NOT_AVAILABLE, "Rollback is not available.");
    }
    return lifecycleFailure(500, ERROR_ROLLBACK_FAILED, MESSAGE_ROLLBACK_FAILED);
  }

  private void startAfterRollback(String appId, InstalledAppSnapshot rolledBack) {
    try {
      appHost.start(appId);
    } catch (IOException _) {
      appendHistory(
          appId,
          ACTION_ROLLBACK,
          STATUS_FAILED,
          null,
          rolledBack.manifest().appVersion(),
          ERROR_ROLLBACK_RESTART_FAILED,
          "Previous app bundle restored, but restart failed.");
      throw lifecycleFailure(
          500, ERROR_ROLLBACK_RESTART_FAILED, "Previous app bundle restored, but restart failed.");
    }
  }

  private void recordRollbackFailure(String appId, String errorCode) {
    appendHistory(
        appId, ACTION_ROLLBACK, STATUS_FAILED, null, null, errorCode, MESSAGE_ROLLBACK_FAILED);
  }

  /**
   * Returns the current policy for one app.
   *
   * <p>The policy is local administrative state. Reading it requires the app to exist, but it does
   * not touch catalogs or staged bundle directories. Missing apps clear stale lifecycle state
   * before a not-found response is returned.
   *
   * @param appId app id from the request path
   * @return path-free policy summary for the installed app
   */
  public synchronized Map<String, Object> policy(String appId) {
    String normalizedAppId = normalizeInstalledAppId(appId);
    requireInstalled(normalizedAppId);
    return policyFor(normalizedAppId).toJsonValue();
  }

  /**
   * Updates the policy for one app.
   *
   * <p>This method only changes the local policy value. It does not immediately check catalogs,
   * stage a candidate, apply a bundle, or restart an app. Route authorization keeps policy changes
   * host/operator-only so app principals cannot grant themselves update automation.
   *
   * @param appId app id from the request path
   * @param mode new policy mode selected by the operator
   * @return path-free policy summary after the policy is stored
   */
  public synchronized Map<String, Object> setPolicy(String appId, AppUpdatePolicyMode mode) {
    String normalizedAppId = normalizeInstalledAppId(appId);
    requireInstalled(normalizedAppId);
    AppUpdatePolicy policy = new AppUpdatePolicy(mode);
    policies.put(normalizedAppId, policy);
    return policy.toJsonValue();
  }

  private void followPolicyAfterCheck(
      String appId, InstalledAppSnapshot installed, AppUpdateCandidate candidate) {
    AppUpdatePolicy policy = policyFor(appId);
    if (policy.mode() == AppUpdatePolicyMode.MANUAL || !candidate.eligibleByDefault()) {
      return;
    }
    if (policy.mode() == AppUpdatePolicyMode.STAGE) {
      if (reviewGateRequiresOperator(candidate)) {
        appendReviewGateHistory(appId, ACTION_STAGE, candidate);
        return;
      }
      stageCandidate(appId, installed, candidate);
      return;
    }
    if (policy.mode() == AppUpdatePolicyMode.APPLY_WHEN_STOPPED) {
      if (appHost.status(appId).isPresent()) {
        appendHistory(
            appId,
            ACTION_APPLY,
            STATUS_FAILED,
            candidate.catalogId(),
            candidate.targetVersion(),
            ERROR_APP_RUNNING,
            "Policy skipped apply because the app is running.");
        recordUpdateReviewGate(
            AppReviewTransparencyEventKind.REVIEW_GATE_POLICY_APPLY,
            candidate,
            "policy_apply_skipped:" + ERROR_APP_RUNNING);
        return;
      }
      if (!candidate.reviewTrustAllowsAutomaticApply()) {
        appendReviewGateHistory(appId, ACTION_APPLY, candidate);
        return;
      }
      if (!candidate.apiCompatibilityAllowsAutomaticApply()) {
        appendCompatibilityGateHistory(appId, candidate);
        recordUpdateReviewGate(
            AppReviewTransparencyEventKind.REVIEW_GATE_POLICY_APPLY,
            candidate,
            "policy_apply_blocked:" + ERROR_UPDATE_INCOMPATIBLE);
        return;
      }
      stageCandidate(appId, installed, candidate);
      apply(appId, ApplyOptions.policyDefault());
    }
  }

  private void stageCandidate(
      String appId, InstalledAppSnapshot installed, AppUpdateCandidate candidate) {
    if (candidateDiffersFromInstalled(candidate, installed)) {
      closeStage(appId);
      candidates.remove(appId);
      appendHistory(
          appId,
          ACTION_STAGE,
          STATUS_FAILED,
          candidate.catalogId(),
          candidate.targetVersion(),
          ERROR_UPDATE_CANDIDATE_CHANGED,
          "Candidate no longer matches the installed app version.");
      recordUpdateReviewGate(
          AppReviewTransparencyEventKind.REVIEW_GATE_UPDATE,
          candidate,
          "stage_blocked:" + ERROR_UPDATE_CANDIDATE_CHANGED);
      throw lifecycleFailure(
          409,
          ERROR_UPDATE_CANDIDATE_CHANGED,
          "Installed app version changed since candidate detection.");
    }
    AppCatalogInstallPlan plan = prepareStagePlan(appId, candidate);
    if (planDiffersFromCandidate(candidate, installed, plan)) {
      closeStage(appId);
      closePlan(plan);
      candidates.remove(appId);
      appendHistory(
          appId,
          ACTION_STAGE,
          STATUS_FAILED,
          candidate.catalogId(),
          candidate.targetVersion(),
          ERROR_UPDATE_CANDIDATE_CHANGED,
          "Prepared catalog plan no longer matches the reviewed candidate.");
      recordUpdateReviewGate(
          AppReviewTransparencyEventKind.REVIEW_GATE_UPDATE,
          candidate,
          "stage_blocked:" + ERROR_UPDATE_CANDIDATE_CHANGED);
      throw lifecycleFailure(
          409,
          ERROR_UPDATE_CANDIDATE_CHANGED,
          "Catalog candidate changed since review; check for updates again.");
    }
    closeStage(appId);
    stagedUpdates.put(appId, new StagedUpdate(candidate, plan, Instant.now()));
    appendHistory(
        appId,
        ACTION_STAGE,
        STATUS_SUCCESS,
        candidate.catalogId(),
        candidate.targetVersion(),
        null,
        "Verified update candidate staged.");
    recordUpdateReviewGate(
        AppReviewTransparencyEventKind.REVIEW_GATE_UPDATE, candidate, "stage_staged");
  }

  private AppCatalogInstallPlan prepareStagePlan(String appId, AppUpdateCandidate candidate) {
    try {
      return catalogManager.prepareInstallPlan(candidate.catalogId(), appId);
    } catch (AppCatalogException exception) {
      recordStageFailure(appId, candidate, exception.errorCode());
      throw catalogFailure(exception);
    } catch (IOException _) {
      recordStageFailure(appId, candidate, ERROR_STAGE_FAILED);
      throw lifecycleFailure(500, ERROR_STAGE_FAILED, MESSAGE_STAGE_FAILED);
    }
  }

  private AppUpdateCandidate candidateOrDetect(String appId, InstalledAppSnapshot installed) {
    return candidates.computeIfAbsent(appId, _ -> detectCandidate(appId, installed, false));
  }

  private void recordStageFailure(String appId, AppUpdateCandidate candidate, String errorCode) {
    appendHistory(
        appId,
        ACTION_STAGE,
        STATUS_FAILED,
        candidate.catalogId(),
        candidate.targetVersion(),
        errorCode,
        MESSAGE_STAGE_FAILED);
    recordUpdateReviewGate(
        AppReviewTransparencyEventKind.REVIEW_GATE_UPDATE, candidate, "stage_failed:" + errorCode);
  }

  private AppUpdateCandidate detectCandidate(
      String appId, InstalledAppSnapshot installed, boolean refreshCatalogs) {
    List<AppCatalogSourceSnapshot> catalogs = listCatalogs();
    if (refreshCatalogs) {
      catalogs = refreshCatalogs(catalogs);
    }
    List<AppUpdateCandidate> matches = new ArrayList<>();
    for (AppCatalogSourceSnapshot catalog : catalogs) {
      for (AppCatalogEntry entry : listCatalogApps(catalog.catalogId())) {
        if (appId.equals(entry.appId())) {
          matches.add(candidateFor(catalog.catalogId(), entry, installed));
        }
      }
    }
    return selectBestCandidate(appId, installed, matches);
  }

  private List<AppCatalogSourceSnapshot> listCatalogs() {
    try {
      return catalogManager.listCatalogs();
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw lifecycleFailure(500, "catalog_list_failed", "Failed to list app catalogs.");
    }
  }

  private List<AppCatalogSourceSnapshot> refreshCatalogs(List<AppCatalogSourceSnapshot> catalogs) {
    List<AppCatalogSourceSnapshot> refreshed = new ArrayList<>(catalogs.size());
    for (AppCatalogSourceSnapshot catalog : catalogs) {
      try {
        refreshed.add(catalogManager.refresh(catalog.catalogId()));
      } catch (AppCatalogException | IOException _) {
        refreshed.add(catalog);
      }
    }
    return List.copyOf(refreshed);
  }

  private List<AppCatalogEntry> listCatalogApps(String catalogId) {
    try {
      return catalogManager.listApps(catalogId);
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw lifecycleFailure(500, "catalog_list_failed", "Failed to list catalog apps.");
    }
  }

  private AppUpdateCandidate selectBestCandidate(
      String appId, InstalledAppSnapshot installed, List<AppUpdateCandidate> matches) {
    if (matches.isEmpty()) {
      return noneCandidate(appId, installed);
    }
    return matches.stream()
        .max(AppUpdateService::compareCandidates)
        .orElseGet(() -> noneCandidate(appId, installed));
  }

  private static int compareCandidates(AppUpdateCandidate left, AppUpdateCandidate right) {
    int rankComparison = Integer.compare(candidateRank(left), candidateRank(right));
    if (rankComparison != 0) {
      return rankComparison;
    }
    int stageabilityComparison = Integer.compare(stageabilityRank(left), stageabilityRank(right));
    if (stageabilityComparison != 0) {
      return stageabilityComparison;
    }
    Integer versionComparison =
        compareDottedNumericVersions(left.targetVersion(), right.targetVersion());
    if (versionComparison != null && versionComparison != 0) {
      return versionComparison;
    }
    int reviewTrustComparison =
        Integer.compare(reviewTrustRank(left.reviewTrust()), reviewTrustRank(right.reviewTrust()));
    if (reviewTrustComparison != 0) {
      return reviewTrustComparison;
    }
    int catalogComparison = left.catalogId().compareTo(right.catalogId());
    if (catalogComparison != 0) {
      return catalogComparison;
    }
    return left.catalogSourceId().compareTo(right.catalogSourceId());
  }

  private static int candidateRank(AppUpdateCandidate candidate) {
    return switch (candidate.status()) {
      case AVAILABLE -> 50;
      case AMBIGUOUS -> 40;
      case INCOMPATIBLE -> 35;
      case NOT_NEWER -> 20;
      case NONE -> 10;
      case STAGED, BLOCKED, APPLIED, ROLLBACK_AVAILABLE, ROLLBACK_IN_PROGRESS, FAILED -> 0;
    };
  }

  private static int stageabilityRank(AppUpdateCandidate candidate) {
    Map<String, Object> reviewTrust = candidate.reviewTrust();
    if (Boolean.TRUE.equals(reviewTrust.get(JSON_BLOCKS_UPDATE))
        || Boolean.TRUE.equals(reviewTrust.get(JSON_BLOCKS_POLICY_APPLY))) {
      return 0;
    }
    if (Boolean.TRUE.equals(reviewTrust.get(JSON_REQUIRES_ACKNOWLEDGEMENT))) {
      return 1;
    }
    return 2;
  }

  private static int reviewTrustRank(Map<String, Object> reviewTrust) {
    int rank = 0;
    if (!Boolean.TRUE.equals(reviewTrust.get(JSON_BLOCKS_UPDATE))) {
      rank += 1000;
    }
    if (!Boolean.TRUE.equals(reviewTrust.get(JSON_REQUIRES_ACKNOWLEDGEMENT))) {
      rank += 100;
    }
    Object statusValue = reviewTrust.get(JSON_STATUS);
    if (!(statusValue instanceof String status)) {
      return rank;
    }
    return rank
        + switch (status) {
          case "trusted_reviewed" -> 80;
          case "trusted_caution" -> 60;
          case "publisher_claim_only" -> 40;
          case "missing_receipt", "not_configured" -> 30;
          case "unknown_reviewer",
              "retired_reviewer",
              "revoked_reviewer",
              "reviewer_not_yet_valid",
              "reviewer_expired",
              "review_policy_mismatch",
              "invalid_signature",
              "artifact_mismatch",
              "app_mismatch",
              "expired" ->
              20;
          default -> 0;
        };
  }

  private AppUpdateCandidate candidateFor(
      String catalogId, AppCatalogEntry entry, InstalledAppSnapshot installed) {
    String installedVersion = installed.manifest().appVersion();
    VersionDecision decision = versionDecision(entry.version(), installedVersion);
    Map<String, Object> apiCompatibility =
        PlatformApiContractVerifier.summarize(
            entry.compatibility().apiCompatibility(),
            entry.permissions(),
            PlatformApiContract.current());
    AppUpdateCandidateStatus status = statusFor(decision, apiCompatibility);
    AppCatalogReviewMetadata review = entry.review();
    Map<String, Object> reviewTrust = reviewTrust(entry).toJsonValue();
    return new AppUpdateCandidate(
        installed.appId(),
        catalogId,
        catalogId,
        installedVersion,
        entry.version(),
        status,
        decision.label(),
        entry.bundleSha256(),
        entry.bundleSizeBytes(),
        entry.bundleType(),
        AppUpdateCandidate.reviewSummary(
            review.status().catalogValue(), review.note().orElse(null)),
        reviewTrust,
        apiCompatibility,
        AppUpdateCandidate.permissionDelta(entry.permissions(), installed.manifest().permissions()),
        appHost.status(installed.appId()).isPresent(),
        Instant.now());
  }

  private AppReviewTrustDecision reviewTrust(AppCatalogEntry entry) {
    return AppReviewReceiptVerifier.evaluate(
        entry, trustedReviewerKeysOrEmpty(), reviewPolicy, Instant.now());
  }

  private AppReviewTransparencyLog reviewTransparencyLog() {
    AppReviewTransparencyLog log = catalogManager.reviewTransparencyLog();
    return log == null ? AppReviewTransparencyLog.disabled() : log;
  }

  private void recordUpdateReviewGate(
      AppReviewTransparencyEventKind kind, AppUpdateCandidate candidate, String phase) {
    reviewTransparencyLog()
        .recordReviewTrustMap(
            kind,
            new AppReviewTransparencyLog.ReviewTrustMapSubject(
                candidate.appId(),
                candidate.targetVersion(),
                candidate.catalogId(),
                candidate.bundleSha256(),
                candidate.bundleSizeBytes()),
            candidate.reviewTrust(),
            List.of("phase=" + phase));
  }

  private TrustedReviewerKeys trustedReviewerKeysOrEmpty() {
    try {
      return reviewerKeysProvider.trustedReviewerKeys();
    } catch (AppCatalogException | IOException _) {
      return TrustedReviewerKeys.empty();
    }
  }

  private AppUpdateCandidate noneCandidate(String appId, InstalledAppSnapshot installed) {
    return new AppUpdateCandidate(
        appId,
        "none",
        "none",
        installed.manifest().appVersion(),
        installed.manifest().appVersion(),
        AppUpdateCandidateStatus.NONE,
        VERSION_EQUAL,
        "not_applicable",
        0L,
        "not_applicable",
        AppUpdateCandidate.reviewSummary(AppCatalogReviewStatus.UNREVIEWED.catalogValue(), null),
        AppReviewReceiptVerifier.evaluateMissingReceipt(
                AppCatalogReviewMetadata.EMPTY, TrustedReviewerKeys.empty(), reviewPolicy)
            .toJsonValue(),
        PlatformApiContractVerifier.summarize(
            installed.manifest().apiCompatibility(),
            installed.manifest().permissions(),
            PlatformApiContract.current()),
        AppUpdateCandidate.permissionDelta(
            installed.manifest().permissions(), installed.manifest().permissions()),
        appHost.status(appId).isPresent(),
        Instant.now());
  }

  private static AppUpdateCandidateStatus statusFor(
      VersionDecision decision, Map<String, Object> apiCompatibility) {
    return switch (decision.label()) {
      case VERSION_NEWER ->
          apiCompatibilityBlocksUpdate(apiCompatibility)
              ? AppUpdateCandidateStatus.INCOMPATIBLE
              : AppUpdateCandidateStatus.AVAILABLE;
      case VERSION_AMBIGUOUS ->
          apiCompatibilityBlocksUpdate(apiCompatibility)
              ? AppUpdateCandidateStatus.INCOMPATIBLE
              : AppUpdateCandidateStatus.AMBIGUOUS;
      case VERSION_LOWER -> AppUpdateCandidateStatus.NOT_NEWER;
      case VERSION_EQUAL -> AppUpdateCandidateStatus.NONE;
      default -> AppUpdateCandidateStatus.AMBIGUOUS;
    };
  }

  private static boolean apiCompatibilityBlocksUpdate(Map<String, Object> apiCompatibility) {
    String apiStatus = String.valueOf(apiCompatibility.get(JSON_STATUS));
    return "below_minimum".equals(apiStatus) || "incompatible".equals(apiStatus);
  }

  private static VersionDecision versionDecision(String catalogVersion, String installedVersion) {
    if (catalogVersion == null || installedVersion == null) {
      return new VersionDecision(VERSION_AMBIGUOUS);
    }
    if (catalogVersion.equals(installedVersion)) {
      return new VersionDecision(VERSION_EQUAL);
    }
    Integer comparison = compareDottedNumericVersions(catalogVersion, installedVersion);
    if (comparison == null) {
      return new VersionDecision(VERSION_AMBIGUOUS);
    }
    return new VersionDecision(comparison > 0 ? VERSION_NEWER : VERSION_LOWER);
  }

  private static Integer compareDottedNumericVersions(String left, String right) {
    List<Integer> leftParts = parseDottedNumericVersion(left);
    List<Integer> rightParts = parseDottedNumericVersion(right);
    if (leftParts.isEmpty() || rightParts.isEmpty()) {
      return null;
    }
    int count = Math.max(leftParts.size(), rightParts.size());
    for (int index = 0; index < count; index++) {
      int leftPart = index < leftParts.size() ? leftParts.get(index) : 0;
      int rightPart = index < rightParts.size() ? rightParts.get(index) : 0;
      if (leftPart != rightPart) {
        return Integer.compare(leftPart, rightPart);
      }
    }
    return 0;
  }

  private static List<Integer> parseDottedNumericVersion(String version) {
    if (version == null || version.isBlank()) {
      return List.of();
    }
    String[] tokens = version.trim().split("\\.", -1);
    List<Integer> parts = new ArrayList<>(tokens.length);
    for (String token : tokens) {
      if (token.isBlank() || !token.chars().allMatch(Character::isDigit)) {
        return List.of();
      }
      try {
        parts.add(Integer.parseInt(token));
      } catch (NumberFormatException _) {
        return List.of();
      }
    }
    return List.copyOf(parts);
  }

  private static void requireStageableCandidate(
      AppUpdateCandidate candidate, boolean reviewAcknowledged) {
    if (candidate.status() == AppUpdateCandidateStatus.INCOMPATIBLE) {
      throw lifecycleFailure(
          409, ERROR_UPDATE_INCOMPATIBLE, "Candidate is incompatible with this Platform API.");
    }
    if (!candidate.eligibleByDefault()) {
      throw lifecycleFailure(
          409, ERROR_UPDATE_NOT_AVAILABLE, "No safely newer update candidate is available.");
    }
    requireReviewGate(candidate.reviewTrust(), reviewAcknowledged);
  }

  private static void requireReviewGate(
      Map<String, Object> reviewTrust, boolean reviewAcknowledged) {
    if (Boolean.TRUE.equals(reviewTrust.get(JSON_BLOCKS_UPDATE))) {
      throw lifecycleFailure(
          409, reviewGateFailureCode(reviewTrust), "Update blocked by app review policy.");
    }
    if (Boolean.TRUE.equals(reviewTrust.get(JSON_REQUIRES_ACKNOWLEDGEMENT))
        && !reviewAcknowledged) {
      throw lifecycleFailure(
          409,
          reviewGateFailureCode(reviewTrust),
          "Update requires explicit acknowledgement of the review trust decision.");
    }
  }

  private static boolean reviewGateRequiresOperator(AppUpdateCandidate candidate) {
    Map<String, Object> reviewTrust = candidate.reviewTrust();
    return Boolean.TRUE.equals(reviewTrust.get(JSON_BLOCKS_UPDATE))
        || Boolean.TRUE.equals(reviewTrust.get(JSON_BLOCKS_POLICY_APPLY))
        || Boolean.TRUE.equals(reviewTrust.get(JSON_REQUIRES_ACKNOWLEDGEMENT));
  }

  private void appendReviewGateHistory(String appId, String action, AppUpdateCandidate candidate) {
    appendHistory(
        appId,
        action,
        STATUS_FAILED,
        candidate.catalogId(),
        candidate.targetVersion(),
        reviewGateFailureCode(candidate.reviewTrust()),
        "Policy skipped update because no trusted positive review receipt verified.");
    recordUpdateReviewGate(
        ACTION_STAGE.equals(action)
            ? AppReviewTransparencyEventKind.REVIEW_GATE_UPDATE
            : AppReviewTransparencyEventKind.REVIEW_GATE_POLICY_APPLY,
        candidate,
        "policy_" + action + "_blocked:" + reviewGateFailureCode(candidate.reviewTrust()));
  }

  private void appendCompatibilityGateHistory(String appId, AppUpdateCandidate candidate) {
    appendHistory(
        appId,
        ACTION_APPLY,
        STATUS_FAILED,
        candidate.catalogId(),
        candidate.targetVersion(),
        ERROR_UPDATE_INCOMPATIBLE,
        "Policy skipped apply because Platform API compatibility is not compatible.");
  }

  private static String reviewGateFailureCode(Map<String, Object> reviewTrust) {
    Object statusValue = reviewTrust.get(JSON_STATUS);
    if (!(statusValue instanceof String status)) {
      return ERROR_APP_REVIEW_UNTRUSTED;
    }
    return switch (status) {
      case "missing_receipt", "publisher_claim_only", "not_configured" -> ERROR_APP_REVIEW_MISSING;
      case "artifact_mismatch", "app_mismatch" -> ERROR_APP_REVIEW_MISMATCH;
      case "expired", "reviewer_expired", "retired_reviewer" -> ERROR_APP_REVIEW_EXPIRED;
      case "trusted_rejected" -> ERROR_APP_REVIEW_REJECTED;
      default -> ERROR_APP_REVIEW_UNTRUSTED;
    };
  }

  private Map<String, Object> summary(String appId, InstalledAppSnapshot installed) {
    invalidateStaleSummaryState(appId, installed);
    RunningAppSnapshot running = appHost.status(appId).orElse(null);
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(10);
    json.put(JSON_APP_ID, appId);
    json.put("installedVersion", installed.manifest().appVersion());
    json.put("running", running != null);
    json.put("policy", policyFor(appId).toJsonValue());
    json.put("candidate", candidateSummary(appId, installed));
    json.put("staged", stagedSummary(appId));
    json.put(ACTION_ROLLBACK, rollbackSummary(appId));
    json.put("lastCheck", lastCheckSummary(appId));
    json.put("scheduler", schedulerSummaryProvider.schedulerSummary(appId));
    json.put("history", historySummary(appId));
    return json;
  }

  private Map<String, Object> candidateSummary(String appId, InstalledAppSnapshot installed) {
    AppUpdateCandidate candidate = candidates.get(appId);
    return candidate == null
        ? noneCandidate(appId, installed).toJsonValue()
        : candidate.toJsonValue();
  }

  private Map<String, Object> stagedSummary(String appId) {
    StagedUpdate staged = stagedUpdates.get(appId);
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(12);
    if (staged == null) {
      json.put(JSON_STATUS, "none");
      json.put(JSON_AVAILABLE, false);
      json.put(JSON_STAGED_AT, null);
      json.put("expiresAt", null);
      json.put("durable", false);
      json.put("reason", "not_staged");
      return json;
    }
    AppUpdateCandidate candidate = staged.candidate();
    json.put(JSON_STATUS, AppUpdateCandidateStatus.STAGED.jsonValue());
    json.put(JSON_AVAILABLE, true);
    json.put(JSON_APP_ID, appId);
    json.put("catalogId", candidate.catalogId());
    json.put("catalogSourceId", candidate.catalogSourceId());
    json.put("targetVersion", candidate.targetVersion());
    json.put("bundleSha256", candidate.bundleSha256());
    json.put("bundleSizeBytes", candidate.bundleSizeBytes());
    json.put("review", candidate.review());
    json.put(JSON_REVIEW_TRUST, candidate.reviewTrust());
    json.put("apiCompatibility", candidate.apiCompatibility());
    json.put("permissionDelta", candidate.permissionDelta());
    json.put(JSON_STAGED_AT, staged.stagedAt().toString());
    json.put("expiresAt", null);
    json.put("durable", false);
    return json;
  }

  private Map<String, Object> rollbackSummary(String appId) {
    AppRollbackRecord rollbackRecord;
    String statusErrorCode = null;
    String statusMessage = null;
    try {
      rollbackRecord = appHost.rollbackStatus(appId).orElse(null);
    } catch (IOException _) {
      rollbackRecord = null;
      statusErrorCode = ERROR_ROLLBACK_FAILED;
      statusMessage = "Rollback state could not be inspected.";
    }
    boolean available = rollbackRecord != null;
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(8);
    json.put(JSON_AVAILABLE, available);
    json.put(
        JSON_STATUS, statusErrorCode == null ? rollbackStatusStatus(available) : STATUS_FAILED);
    json.put(JSON_APP_ID, appId);
    json.put("createdAt", null);
    json.put("previousVersion", rollbackRecord == null ? null : rollbackRecord.appVersion());
    json.put("previousName", rollbackRecord == null ? null : rollbackRecord.appName());
    json.put("replacedVersion", null);
    json.put("retentionLimit", 1);
    json.put("scope", "bundle_only");
    json.put("errorCode", statusErrorCode);
    json.put(JSON_MESSAGE, statusMessage);
    return json;
  }

  private static String rollbackStatusStatus(boolean rollbackAvailable) {
    return rollbackAvailable ? JSON_AVAILABLE : "none";
  }

  private Map<String, Object> lastCheckSummary(String appId) {
    LastCheck lastCheck = lastChecks.get(appId);
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(4);
    json.put("checkedAt", lastCheck == null ? null : lastCheck.checkedAt().toString());
    json.put(JSON_STATUS, lastCheck == null ? "never" : lastCheck.status());
    json.put("errorCode", lastCheck == null ? null : lastCheck.errorCode());
    json.put(JSON_MESSAGE, lastCheck == null ? null : lastCheck.message());
    return json;
  }

  private static Map<String, Object> disabledSchedulerSummary(String appId) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(11);
    json.put(JSON_APP_ID, appId);
    json.put("enabled", false);
    json.put(JSON_STATUS, AppUpdateSchedulerStatus.DISABLED.jsonValue());
    json.put("lastCheckAt", null);
    json.put("nextCheckAt", null);
    json.put("lastResult", AppUpdateSchedulerState.RESULT_NONE);
    json.put("lastFailureAt", null);
    json.put("failureCount", 0);
    json.put("lastErrorCode", null);
    json.put(JSON_MESSAGE, "Background scheduler is not configured for this service.");
    json.put("concurrency", "per-app-serialized");
    return json;
  }

  private List<Map<String, Object>> historySummary(String appId) {
    Deque<AppUpdateHistoryEntry> entries = history.get(appId);
    if (entries == null || entries.isEmpty()) {
      return List.of();
    }
    return entries.stream().map(AppUpdateHistoryEntry::toJsonValue).toList();
  }

  private AppUpdatePolicy policyFor(String appId) {
    return policies.getOrDefault(appId, AppUpdatePolicy.DEFAULT);
  }

  private AppUpdateCandidate appliedCandidate(
      AppUpdateCandidate candidate, InstalledAppSnapshot updated) {
    return new AppUpdateCandidate(
        candidate.appId(),
        candidate.catalogId(),
        candidate.catalogSourceId(),
        candidate.installedVersion(),
        updated.manifest().appVersion(),
        AppUpdateCandidateStatus.APPLIED,
        candidate.versionComparison(),
        candidate.bundleSha256(),
        candidate.bundleSizeBytes(),
        candidate.bundleType(),
        candidate.review(),
        candidate.reviewTrust(),
        candidate.apiCompatibility(),
        candidate.permissionDelta(),
        appHost.status(candidate.appId()).isPresent(),
        Instant.now());
  }

  private boolean planDiffersFromCandidate(
      AppUpdateCandidate candidate, InstalledAppSnapshot installed, AppCatalogInstallPlan plan) {
    AppCatalogEntry entry = plan.entry();
    if (!candidate.catalogId().equals(plan.catalogId())
        || !candidate.appId().equals(entry.appId())
        || !candidate.targetVersion().equals(entry.version())
        || !candidate.bundleSha256().equals(entry.bundleSha256())
        || candidate.bundleSizeBytes() != entry.bundleSizeBytes()
        || !candidate.bundleType().equals(entry.bundleType())) {
      return true;
    }
    AppCatalogReviewMetadata review = entry.review();
    Map<String, Object> reviewSummary =
        AppUpdateCandidate.reviewSummary(
            review.status().catalogValue(), review.note().orElse(null));
    Map<String, Object> apiCompatibility =
        PlatformApiContractVerifier.summarize(
            entry.compatibility().apiCompatibility(),
            entry.permissions(),
            PlatformApiContract.current());
    Map<String, Object> permissionDelta =
        AppUpdateCandidate.permissionDelta(entry.permissions(), installed.manifest().permissions());
    return !candidate.review().equals(reviewSummary)
        || !candidate.reviewTrust().equals(reviewTrust(entry).toJsonValue())
        || !candidate.apiCompatibility().equals(apiCompatibility)
        || !candidate.permissionDelta().equals(permissionDelta);
  }

  private void updateCandidateAfterPostApplyFailure(
      String appId,
      AppUpdateCandidate stagedCandidate,
      InstalledAppSnapshot updated,
      HealthFailureState healthFailureState) {
    if (healthFailureState.rollbackCommitted()) {
      candidates.remove(appId);
      return;
    }
    candidates.put(appId, appliedCandidate(stagedCandidate, updated));
  }

  private void startOrTreatAsHealthFailure(
      String appId, ApplyOptions options, HealthFailureState healthFailureState)
      throws IOException {
    try {
      appHost.start(appId);
    } catch (IOException exception) {
      if (options.healthCheck() == HealthCheckMode.PROCESS) {
        failProcessHealthCheck(appId, options, healthFailureState);
      }
      throw exception;
    }
  }

  private void verifyHealthOrRollback(
      String appId, ApplyOptions options, HealthFailureState healthFailureState) {
    if (options.healthCheck() == HealthCheckMode.NONE) {
      return;
    }
    if (appHost.status(appId).isPresent()) {
      return;
    }
    failProcessHealthCheck(appId, options, healthFailureState);
  }

  private void failProcessHealthCheck(
      String appId, ApplyOptions options, HealthFailureState healthFailureState) {
    if (options.rollbackOnHealthFailure() && rollbackAvailable(appId)) {
      try {
        invokeRollback(appId);
        healthFailureState.markRollbackCommitted();
      } catch (IOException _) {
        throw lifecycleFailure(
            500,
            ERROR_ROLLBACK_FAILED,
            "Process health check failed and automatic rollback failed.");
      }
    }
    throw lifecycleFailure(409, ERROR_HEALTH_CHECK_FAILED, "Process health check failed.");
  }

  private boolean rollbackAvailable(String appId) {
    return rollbackStatusOrFailure(appId).isPresent();
  }

  private Optional<AppRollbackRecord> rollbackStatusOrFailure(String appId) {
    try {
      return appHost.rollbackStatus(appId);
    } catch (IOException _) {
      throw lifecycleFailure(500, ERROR_ROLLBACK_FAILED, "Rollback state could not be inspected.");
    }
  }

  private InstalledAppSnapshot invokeRollback(String appId) throws IOException {
    return appHost.rollback(appId);
  }

  private InstalledAppSnapshot requireInstalled(String appId) {
    try {
      Optional<InstalledAppSnapshot> installed = appHost.describe(appId);
      if (installed.isPresent()) {
        return installed.get();
      }
      clearStateForMissingApp(appId);
      throw appNotFound();
    } catch (IOException _) {
      throw lifecycleFailure(500, "app_read_failed", "Failed to read installed app.");
    }
  }

  private void clearStateForMissingApp(String appId) {
    clearAppState(appId);
  }

  private static PlatformApiException appNotFound() {
    return new PlatformApiException(404, "app_not_found", "App not found.");
  }

  private static String normalizeInstalledAppId(String appId) {
    try {
      return AppManifest.normalizeAppId(appId);
    } catch (IllegalArgumentException _) {
      throw new PlatformApiException(
          400, "invalid_app_id", "App identifier is not a valid AppHost id.");
    }
  }

  private void invalidateStaleStage(String appId, AppUpdateCandidate candidate) {
    StagedUpdate staged = stagedUpdates.get(appId);
    if (staged == null) {
      return;
    }
    if (!sameStagedCandidate(staged.candidate(), candidate)) {
      closeStage(appId);
      appendHistory(
          appId,
          ACTION_STAGE,
          STATUS_FAILED,
          candidate.catalogId(),
          candidate.targetVersion(),
          "staged_candidate_invalidated",
          "Previous staged update no longer matches the catalog candidate.");
    }
  }

  private void invalidateStaleSummaryState(String appId, InstalledAppSnapshot installed) {
    StagedUpdate staged = stagedUpdates.get(appId);
    if (staged != null && stageDiffersFromInstalled(staged, installed)) {
      AppUpdateCandidate stagedCandidate = staged.candidate();
      closeStage(appId);
      appendHistory(
          appId,
          ACTION_STAGE,
          STATUS_FAILED,
          stagedCandidate.catalogId(),
          stagedCandidate.targetVersion(),
          ERROR_UPDATE_CANDIDATE_CHANGED,
          "Staged update no longer matches the installed app version.");
    }
    AppUpdateCandidate candidate = candidates.get(appId);
    if (candidate != null && candidateDiffersFromInstalled(candidate, installed)) {
      candidates.remove(appId);
    }
  }

  private boolean stageDiffersFromInstalled(StagedUpdate staged, InstalledAppSnapshot installed) {
    return candidateDiffersFromInstalled(staged.candidate(), installed)
        || planDiffersFromCandidate(staged.candidate(), installed, staged.plan());
  }

  private static boolean candidateDiffersFromInstalled(
      AppUpdateCandidate candidate, InstalledAppSnapshot installed) {
    String installedVersion = installed.manifest().appVersion();
    if (candidate.status() == AppUpdateCandidateStatus.APPLIED) {
      return !candidate.targetVersion().equals(installedVersion);
    }
    return !candidate.installedVersion().equals(installedVersion)
        || !candidateInstalledPermissions(candidate).equals(permissionSet(installed));
  }

  private static java.util.Set<String> candidateInstalledPermissions(AppUpdateCandidate candidate) {
    java.util.LinkedHashSet<String> permissions = new java.util.LinkedHashSet<>();
    permissions.addAll(deltaPermissions(candidate.permissionDelta(), "unchanged"));
    permissions.addAll(deltaPermissions(candidate.permissionDelta(), "removed"));
    return java.util.Collections.unmodifiableSet(permissions);
  }

  private static java.util.Set<String> permissionSet(InstalledAppSnapshot installed) {
    return java.util.Collections.unmodifiableSet(
        new java.util.LinkedHashSet<>(installed.manifest().permissions()));
  }

  private static List<String> deltaPermissions(Map<String, Object> permissionDelta, String key) {
    Object value = permissionDelta.get(key);
    if (!(value instanceof List<?> values)) {
      return List.of();
    }
    java.util.ArrayList<String> permissions = new java.util.ArrayList<>(values.size());
    for (Object item : values) {
      if (item instanceof String permission) {
        permissions.add(permission);
      }
    }
    return List.copyOf(permissions);
  }

  private static boolean sameStagedCandidate(
      AppUpdateCandidate stagedCandidate, AppUpdateCandidate currentCandidate) {
    return stagedCandidate.appId().equals(currentCandidate.appId())
        && stagedCandidate.catalogId().equals(currentCandidate.catalogId())
        && stagedCandidate.catalogSourceId().equals(currentCandidate.catalogSourceId())
        && stagedCandidate.installedVersion().equals(currentCandidate.installedVersion())
        && stagedCandidate.targetVersion().equals(currentCandidate.targetVersion())
        && stagedCandidate.status() == currentCandidate.status()
        && stagedCandidate.versionComparison().equals(currentCandidate.versionComparison())
        && stagedCandidate.bundleSha256().equals(currentCandidate.bundleSha256())
        && stagedCandidate.bundleSizeBytes() == currentCandidate.bundleSizeBytes()
        && stagedCandidate.bundleType().equals(currentCandidate.bundleType())
        && stagedCandidate.review().equals(currentCandidate.review())
        && stagedCandidate.reviewTrust().equals(currentCandidate.reviewTrust())
        && stagedCandidate.apiCompatibility().equals(currentCandidate.apiCompatibility())
        && stagedCandidate.permissionDelta().equals(currentCandidate.permissionDelta());
  }

  private void closeStage(String appId) {
    StagedUpdate staged = stagedUpdates.remove(appId);
    if (staged != null) {
      closePlan(staged.plan());
    }
  }

  private static void closePlan(AppCatalogInstallPlan plan) {
    if (plan == null) {
      return;
    }
    try {
      plan.close();
    } catch (IOException _) {
      // A failed cleanup must not expose or promote the private staging path.
    }
  }

  private void appendHistory(
      String appId,
      String action,
      String status,
      String catalogId,
      String targetVersion,
      String errorCode,
      String message) {
    Deque<AppUpdateHistoryEntry> entries =
        history.computeIfAbsent(appId, _ -> new ArrayDeque<>(MAX_HISTORY_ENTRIES));
    entries.addFirst(
        new AppUpdateHistoryEntry(
            Instant.now(), action, status, catalogId, targetVersion, errorCode, message));
    while (entries.size() > MAX_HISTORY_ENTRIES) {
      entries.removeLast();
    }
  }

  private void recordLastCheck(String appId, Instant checkedAt, String errorCode, String message) {
    lastChecks.put(appId, new LastCheck(checkedAt, errorCode, message));
  }

  private static PlatformApiException catalogFailure(AppCatalogException exception) {
    return switch (exception.errorCode()) {
      case "catalog_not_found", "app_not_found" ->
          new PlatformApiException(404, exception.errorCode(), exception.getMessage());
      case "catalog_conflict" ->
          new PlatformApiException(409, exception.errorCode(), exception.getMessage());
      case "catalog_fetch_unavailable" ->
          new PlatformApiException(503, exception.errorCode(), exception.getMessage());
      case "catalog_fetch_failed" ->
          new PlatformApiException(502, exception.errorCode(), exception.getMessage());
      default -> new PlatformApiException(400, exception.errorCode(), exception.getMessage());
    };
  }

  private static boolean isRunningUpdateFailure(AppHostException exception) {
    String message = exception.getMessage();
    return message != null && message.startsWith(CANNOT_UPDATE_RUNNING_APP_PREFIX);
  }

  private static boolean isRunningRollbackFailure(AppHostException exception) {
    String message = exception.getMessage();
    return message != null && message.startsWith(CANNOT_ROLLBACK_RUNNING_APP_PREFIX);
  }

  private static boolean isMissingAppFailure(AppHostException exception) {
    String message = exception.getMessage();
    return message != null && message.startsWith(APP_NOT_INSTALLED_PREFIX);
  }

  private static boolean isRollbackRecordUnavailableFailure(AppHostException exception) {
    String message = exception.getMessage();
    return message != null && message.startsWith(ROLLBACK_RECORD_NOT_AVAILABLE_PREFIX);
  }

  private static boolean isSignedBundleVerificationFailure(AppHostException exception) {
    return exception instanceof AppBundleVerificationException;
  }

  private static boolean isInvalidAppBundleFailure(AppHostException exception) {
    if (exception instanceof AppManifestException) {
      return true;
    }
    String message = exception.getMessage();
    if (message == null || message.isBlank()) {
      return false;
    }
    return message.startsWith("stagedAppDirectory ")
        || message.startsWith("staging directory ")
        || message.startsWith("copied manifest ")
        || message.startsWith("copied app.exec ")
        || message.startsWith("app.ui.entry ")
        || message.startsWith("app.exec ")
        || message.startsWith("staged app bundle ");
  }

  private static PlatformApiException lifecycleFailure(
      int statusCode, String errorCode, String message) {
    return new PlatformApiException(statusCode, errorCode, message);
  }

  /**
   * Supported process health check modes for apply.
   *
   * <p>Health checks are intentionally limited in this first lifecycle version. The service can
   * either skip post-apply health verification or require that AppHost can observe a running
   * process after an explicit restart. App-provided HTTP health endpoints are outside this enum and
   * can be added later without changing the existing meanings.
   */
  public enum HealthCheckMode {
    /**
     * Do not perform a post-apply health check.
     *
     * <p>The service still reports apply failures from AppHost. It simply does not start or inspect
     * a process for health after replacement.
     */
    NONE,

    /**
     * Treat a readable running process state as the v1 health check.
     *
     * <p>This mode is valid only when restart is requested, because a stopped app cannot satisfy a
     * process health check without launching a new process.
     */
    PROCESS
  }

  /**
   * Apply options decoded by the API handler.
   *
   * <p>The options are request-scoped and do not change the stored app update policy. They describe
   * whether the service may stop/start the app for this apply, whether process health should be
   * verified after restart, and whether a committed update should be rolled back when that health
   * check fails. The service validates combinations that cannot work, such as process health
   * without restart, before replacing the bundle.
   *
   * @param restart whether this applies request may stop and start the app
   * @param healthCheck post-apply health check mode requested by the caller
   * @param rollbackOnHealthFailure whether a committed update should roll back after health failure
   */
  public record ApplyOptions(
      boolean restart, HealthCheckMode healthCheck, boolean rollbackOnHealthFailure) {
    /**
     * Creates validated apply options.
     *
     * <p>Only the health check enum requires structural validation here. Cross-field validation is
     * performed by {@link #apply(String, ApplyOptions)} because it needs current app state.
     */
    public ApplyOptions {
      Objects.requireNonNull(healthCheck, "healthCheck");
    }

    static ApplyOptions policyDefault() {
      return new ApplyOptions(false, HealthCheckMode.NONE, false);
    }
  }

  private record StagedUpdate(
      AppUpdateCandidate candidate, AppCatalogInstallPlan plan, Instant stagedAt) {
    private StagedUpdate {
      Objects.requireNonNull(candidate, "candidate");
      Objects.requireNonNull(plan, "plan");
      Objects.requireNonNull(stagedAt, JSON_STAGED_AT);
    }

    private Path stagedBundleDirectory() {
      return plan.stagedBundleDirectory();
    }
  }

  private record LastCheck(Instant checkedAt, String errorCode, String message) {
    private LastCheck {
      Objects.requireNonNull(checkedAt, "checkedAt");
    }

    private String status() {
      return errorCode == null ? STATUS_SUCCESS : STATUS_FAILED;
    }
  }

  private static final class HealthFailureState {
    private boolean rollbackCommitted;

    private boolean rollbackCommitted() {
      return rollbackCommitted;
    }

    private void markRollbackCommitted() {
      rollbackCommitted = true;
    }
  }

  private record VersionDecision(String label) {}
}

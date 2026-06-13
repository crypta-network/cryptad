package network.crypta.platform.api.operator.recovery;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.function.Supplier;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.api.PlatformApiParameters;
import network.crypta.platform.api.PlatformApiPrincipal;
import network.crypta.platform.api.appcatalogs.AppCatalogsApiHandler;
import network.crypta.platform.api.appdata.AppDataService;
import network.crypta.platform.api.apps.AppsApiHandler;
import network.crypta.platform.api.appservices.AppServiceCoordinator;
import network.crypta.platform.api.appupdates.AppUpdateService;
import network.crypta.platform.api.content.subscriptions.ContentSubscriptionService;
import network.crypta.platform.api.networkbudget.AppNetworkBudgetService;
import network.crypta.platform.api.networkbudget.AppNetworkBudgetSnapshot;
import network.crypta.platform.api.operator.OperatorBetaDashboardService;
import network.crypta.platform.api.operator.OperatorSupportRedactor;
import network.crypta.platform.api.trust.TrustGraphApiHandler;
import network.crypta.platform.trustgraph.TrustGraphException;

/**
 * Plans and executes the closed operator RC recovery action set.
 *
 * <p>This service is intentionally a coordinator over existing app-platform services. It does not
 * accept arbitrary paths, methods, shell commands, or route fragments. Every execution starts by
 * building the same typed plan returned by the plan endpoint, checks destructive confirmation, and
 * then dispatches through a switch over {@link OperatorRecoveryActionId}. Existing catalog,
 * AppHost, app-update, app-data, app-service, Trust Graph, subscription, and network-budget
 * services remain responsible for their normal security gates.
 *
 * <p>The service owns only recovery-specific sequencing, plan-token bookkeeping, bounded audit
 * events, and redacted result envelopes. Route handlers must still perform host/operator
 * authorization before calling it. Methods that expose ordinary dashboard, support, or audit data
 * deliberately avoid raw backup payloads, private URIs, app tokens, Trust Graph statement bodies,
 * local paths, queue HTML, process environments, and request bodies.
 *
 * <p>Instances keep small in-memory plan-token and audit buffers and synchronize mutating entry
 * points. They are suitable for the daemon-local operator surface, not for distributed workflow
 * coordination or durable support-ticket storage.
 */
public final class OperatorRecoveryService {
  private static final int PLAN_VERSION = 1;
  private static final int RESULT_VERSION = 1;
  private static final int AUDIT_LIMIT = 50;
  private static final int PLAN_TOKEN_LIMIT = 100;
  private static final String PARAM_ACTION_ID = "actionId";
  private static final String PARAM_APP_ID = "appId";
  private static final String PARAM_BUNDLE_ID = "bundleId";
  private static final String PARAM_CATALOG_ID = "catalogId";
  private static final String PARAM_CONFIRM = "confirm";
  private static final String PARAM_CONFIRMATION_PHRASE = "confirmationPhrase";
  private static final String PARAM_GRANT_ID = "grantId";
  private static final String PARAM_PLAN_TOKEN = "planToken";
  private static final String PARAM_SUBSCRIPTION_ID = "subscriptionId";
  private static final String KEY_AVAILABLE = "available";
  private static final String KEY_APP_PLATFORM_STATE_CLEARED = "appPlatformStateCleared";
  private static final String KEY_ERROR_CODE = "errorCode";
  private static final String KEY_STATUS = "status";
  private static final String KEY_WARNINGS = "warnings";
  private static final String VALUE_AVAILABLE = KEY_AVAILABLE;
  private static final String RECOVERY_KIND_APP_DATA = "app-data";
  private static final String RECOVERY_KIND_CATALOG = "catalog";
  private static final String RECOVERY_KIND_SUBSCRIPTION = "subscription";
  private static final String RECOVERY_KIND_UPDATE = "update";
  private static final String STEP_CREATE_BACKUP = "create-backup";
  private static final String STEP_CREATE_BACKUP_LABEL = "Create app-data backup";
  private static final String STEP_UNINSTALL_APP = "uninstall-app";
  private static final String STEP_UNINSTALL_APP_LABEL = "Uninstall app bundle after backup";
  private static final String PRECONDITION_APP_STOPPED = "app.stopped";
  private static final String BLOCK_APP_RUNNING = "app_running";
  private static final String MESSAGE_APP_IS_STOPPED = "App is stopped.";
  private static final HexFormat HEX = HexFormat.of();

  private final AppsApiHandler appsApiHandler;
  private final AppCatalogsApiHandler appCatalogsApiHandler;
  private final AppUpdateService appUpdateService;
  private final ContentSubscriptionService contentSubscriptionService;
  private final AppDataService appDataService;
  private final TrustGraphApiHandler trustGraphApiHandler;
  private final AppServiceCoordinator appServiceCoordinator;
  private final AppNetworkBudgetService networkBudgetService;
  private final OperatorBetaDashboardService dashboardService;
  private final AppUninstallCleanup appUninstallCleanup;
  private final Supplier<String> currentCryptaVersion;
  private final Supplier<Map<String, Object>> supportBundleSupplier;
  private final Clock clock;
  private final ArrayList<Map<String, Object>> auditEvents = new ArrayList<>();
  private final LinkedHashMap<String, String> issuedPlanTokens = new LinkedHashMap<>();
  private long auditSequence;
  private long planSequence;

  /**
   * Recovery service collaborators supplied by the operator route composer.
   *
   * @param appsApiHandler optional app lifecycle handler
   * @param appCatalogsApiHandler optional signed catalog handler
   * @param appUpdateService optional app-update lifecycle service
   * @param contentSubscriptionService optional content subscription service
   * @param appDataService optional app-data backup and restore service
   * @param trustGraphApiHandler optional local Trust Graph RC handler
   * @param appServiceCoordinator optional app-service grant coordinator
   * @param networkBudgetService optional app-network budget service
   * @param dashboardService existing dashboard projection helper used for operator-safe summaries
   * @param appUninstallCleanup optional cleanup callback shared with normal app DELETE routing
   * @param currentCryptaVersion path-free daemon version supplier for app-data backup manifests
   * @param supportBundleSupplier optional redacted support-bundle builder
   */
  public record Dependencies(
      AppsApiHandler appsApiHandler,
      AppCatalogsApiHandler appCatalogsApiHandler,
      AppUpdateService appUpdateService,
      ContentSubscriptionService contentSubscriptionService,
      AppDataService appDataService,
      TrustGraphApiHandler trustGraphApiHandler,
      AppServiceCoordinator appServiceCoordinator,
      AppNetworkBudgetService networkBudgetService,
      OperatorBetaDashboardService dashboardService,
      AppUninstallCleanup appUninstallCleanup,
      Supplier<String> currentCryptaVersion,
      Supplier<Map<String, Object>> supportBundleSupplier) {}

  /** Callback used after a committed recovery uninstall to clear related app-platform state. */
  @FunctionalInterface
  public interface AppUninstallCleanup {
    /**
     * Clears scheduler, subscription, app-service, and optionally app-data state for an app.
     *
     * @param appId stable app identifier whose bundle has been removed
     * @param preserveData whether durable app-data should be retained
     */
    void clearAppState(String appId, boolean preserveData);
  }

  /**
   * Creates a recovery service using the system UTC clock.
   *
   * <p>The public constructor is used by runtime route composition. Tests can use the
   * package-private constructor to supply a deterministic clock for audit timestamps, plan-token
   * digests, and result envelopes. The dependency record must include the dashboard service because
   * dashboard and support projections remain available even when optional recovery collaborators
   * are absent.
   *
   * @param dependencies route-composed handlers and suppliers used by recovery planning
   */
  public OperatorRecoveryService(Dependencies dependencies) {
    this(dependencies, Clock.systemUTC());
  }

  OperatorRecoveryService(Dependencies dependencies, Clock clock) {
    Dependencies checked = Objects.requireNonNull(dependencies, "dependencies");
    this.appsApiHandler = checked.appsApiHandler();
    this.appCatalogsApiHandler = checked.appCatalogsApiHandler();
    this.appUpdateService = checked.appUpdateService();
    this.contentSubscriptionService = checked.contentSubscriptionService();
    this.appDataService = checked.appDataService();
    this.trustGraphApiHandler = checked.trustGraphApiHandler();
    this.appServiceCoordinator = checked.appServiceCoordinator();
    this.networkBudgetService = checked.networkBudgetService();
    this.dashboardService = Objects.requireNonNull(checked.dashboardService(), "dashboardService");
    this.appUninstallCleanup = checked.appUninstallCleanup();
    this.currentCryptaVersion =
        checked.currentCryptaVersion() == null ? () -> "unknown" : checked.currentCryptaVersion();
    this.supportBundleSupplier =
        checked.supportBundleSupplier() == null
            ? dashboardService::supportBundle
            : checked.supportBundleSupplier();
    this.clock = Objects.requireNonNull(clock, "clock");
  }

  /**
   * Returns action descriptors for the closed PR-257 recovery action set.
   *
   * <p>The descriptors are safe for Web Shell rendering and certification evidence. They include
   * action id, label, category, severity, target kind, destructive flag, confirmation requirement,
   * description, and required target fields, but never include executable paths, HTTP methods,
   * commands, tokens, or backing-service request bodies.
   *
   * @return ordered descriptor maps for every allowlisted recovery action
   */
  public List<Map<String, Object>> actions() {
    return java.util.Arrays.stream(OperatorRecoveryActionId.values())
        .map(OperatorRecoveryService::actionDescriptor)
        .toList();
  }

  /**
   * Returns the dashboard block embedded in {@code /operator/rc-dashboard}.
   *
   * <p>The block describes recovery workflow capabilities rather than live sensitive state. It
   * advertises plan-before-execute semantics, closed action dispatch, grouped action descriptors,
   * and recent redacted audit entries. Callers compose it with the broader operator dashboard
   * projection after host/operator authorization has already succeeded.
   *
   * @return a deterministic, metadata-only dashboard block for the RC operator surface
   */
  public Map<String, Object> dashboardState() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(6);
    json.put("surface", "operator-rc-recovery");
    json.put(KEY_STATUS, VALUE_AVAILABLE);
    json.put("planBeforeExecute", true);
    json.put("closedActionDispatch", true);
    json.put("actions", actionsByCategory());
    json.put("recentAudit", recentAudit());
    return json;
  }

  /**
   * Returns a support-bundle context that excludes payloads and request bodies.
   *
   * <p>The context is intentionally smaller than execution results. It records recent recovery
   * event summaries and the payload policy, then passes the map through the support redactor before
   * returning it. Sensitive backup payloads, raw Trust Graph statements, app-data values, form
   * passwords, and operator-supplied unsafe target strings must not survive in this projection.
   *
   * @return redacted recovery context safe to include in support bundles
   */
  public Map<String, Object> supportContext() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(4);
    json.put("kind", "operator-recovery-context");
    json.put("recentRecoveryEvents", recentAudit());
    json.put("supportBundlePayloadPolicy", "metadata-only");
    json.put("omitsSensitiveBackupPayloads", true);
    return redactedMap(json);
  }

  /**
   * Returns support-bundle preview metadata for the Web Shell wizard.
   *
   * <p>The preview lets the browser show section inventory and redaction metadata before exporting
   * a bundle. It reuses the already-built support bundle rather than fetching unrelated state
   * again, and it adds recovery context plus review warnings. The preview is metadata-only and must
   * not expose app-data backup payloads or raw Trust Graph statement data.
   *
   * @param supportBundle redacted support-bundle map produced by the existing support builder
   * @return preview metadata suitable for ordinary Web Shell rendering
   */
  public Map<String, Object> supportBundlePreview(Map<String, Object> supportBundle) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(7);
    json.put("kind", "crypta-operator-support-bundle-preview");
    json.put("supportBundleVersion", supportBundle.get("schemaVersion"));
    json.put("generatedAtEpochMillis", supportBundle.get("generatedAtEpochMillis"));
    json.put("includedSections", includedSections(supportBundle));
    json.put("redaction", supportBundle.get("redaction"));
    json.put("recoveryContext", supportContext());
    json.put(
        KEY_WARNINGS,
        List.of(
            "Support bundles are redacted but should be reviewed before sharing.",
            "App-data backup payloads and raw Trust Graph statements are not included."));
    return json;
  }

  /**
   * Returns safe app-network budget snapshots for operator diagnostics.
   *
   * <p>The projection exposes only counters, limits, leases, window metadata, operation names, and
   * next-availability fields supplied by the budget service. When the service is unavailable, the
   * result remains a structured unavailable response instead of throwing. It does not reset budgets
   * or reveal raw content, URIs, request bodies, queue internals, or tokens.
   *
   * @return metadata-only network-budget diagnostics for the operator surface
   */
  public Map<String, Object> networkBudgets() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(4);
    json.put("kind", "crypta-operator-network-budgets");
    if (networkBudgetService == null) {
      json.put(KEY_AVAILABLE, false);
      json.put("snapshots", List.of());
      json.put(KEY_WARNINGS, List.of("App-network budget service is unavailable."));
      return json;
    }
    json.put(KEY_AVAILABLE, true);
    json.put(
        "snapshots",
        networkBudgetService.snapshots().stream().map(AppNetworkBudgetSnapshot::toJson).toList());
    json.put(KEY_WARNINGS, List.of());
    return json;
  }

  /**
   * Builds a metadata-only plan from decoded form or query parameters.
   *
   * <p>The method parses the closed action id, normalizes the target for that action, issues a
   * one-use plan token, and evaluates service and state preconditions. It does not execute backing
   * services or mutate app-platform state. The returned plan is the shape that execute must later
   * match with the same action, target, and token.
   *
   * @param parameters decoded request parameters from the operator route layer
   * @return the deterministic plan envelope for the requested action and target
   */
  public synchronized OperatorRecoveryPlan plan(Map<String, List<String>> parameters) {
    OperatorRecoveryActionId actionId = requireActionId(parameters);
    OperatorRecoveryTarget target = target(actionId, parameters);
    String planToken = issuePlanToken(actionId, target);
    return plan(actionId, target, planToken);
  }

  /**
   * Executes a confirmed recovery action after validating the previously issued plan token.
   *
   * <p>Execution reparses the action and target, requires a token issued by {@link #plan(Map)} for
   * the exact same fingerprint, checks destructive confirmation, consumes the token, and then
   * dispatches only through the enum-backed recovery switch. Backing-service failures are converted
   * to failed or partial recovery result envelopes where possible so the Web Shell can show the
   * outcome without treating every HTTP-success response as completed work.
   *
   * @param parameters decoded request parameters including action id, target fields, and plan token
   * @return a completed, blocked, failed, or partial result envelope for the execution attempt
   */
  public synchronized OperatorRecoveryResult execute(Map<String, List<String>> parameters) {
    OperatorRecoveryActionId actionId = requireActionId(parameters);
    OperatorRecoveryTarget target = target(actionId, parameters);
    String planToken = requireIssuedPlanToken(parameters, actionId, target);
    OperatorRecoveryPlan plan = plan(actionId, target, planToken);
    requireConfirmationIfNeeded(plan, parameters);
    consumePlanToken(planToken);
    if (!plan.executable()) {
      OperatorRecoveryResult result = blockedResult(plan);
      appendAudit(actionId, target, result.status(), result.reasonCode());
      return result;
    }
    try {
      OperatorRecoveryResult result = executePlanned(plan);
      appendAudit(actionId, target, result.status(), result.reasonCode());
      return result;
    } catch (PlatformApiException exception) {
      OperatorRecoveryResult result = failedResult(plan, exception);
      appendAudit(actionId, target, result.status(), result.reasonCode());
      return result;
    } catch (TrustGraphException exception) {
      OperatorRecoveryResult result = failedResult(plan, mappedTrustGraphException(exception));
      appendAudit(actionId, target, result.status(), result.reasonCode());
      return result;
    }
  }

  /**
   * Returns bounded newest-first recovery audit entries.
   *
   * <p>The audit list is in-memory and intentionally small. Entries contain stable event ids,
   * action ids, target kind, redacted target ids, status, timestamp, and reason code. They do not
   * include request bodies, backup payloads, raw fetched content, local paths, form passwords,
   * tokens, or raw Trust Graph statements.
   *
   * @return newest-first immutable snapshot of recent redacted recovery audit events
   */
  public synchronized List<Map<String, Object>> recentAudit() {
    return List.copyOf(auditEvents.reversed());
  }

  private OperatorRecoveryPlan plan(
      OperatorRecoveryActionId actionId, OperatorRecoveryTarget target, String planToken) {
    ArrayList<OperatorRecoveryPrecondition> preconditions = new ArrayList<>();
    ArrayList<String> warnings = new ArrayList<>();
    ArrayList<String> blockReasons = new ArrayList<>();
    OperatorRecoveryErrorCode reasonCode = OperatorRecoveryErrorCode.NONE;

    addRequiredTargetPreconditions(actionId, target, preconditions, blockReasons);
    reasonCode = mergeReason(reasonCode, blockReasons);
    reasonCode = addServicePreconditions(actionId, preconditions, blockReasons, reasonCode);
    reasonCode = addStatePreconditions(actionId, target, preconditions, blockReasons, reasonCode);
    addActionWarnings(actionId, warnings);

    OperatorRecoveryStatus status = planStatus(actionId, warnings, blockReasons, reasonCode);
    return new OperatorRecoveryPlan(
        PLAN_VERSION,
        planToken,
        actionId,
        actionId.category(),
        target,
        status,
        actionId.destructive(),
        actionId.requiresConfirmation(),
        confirmationPhrase(actionId, target),
        requiresStoppedApp(actionId),
        backupRecommended(actionId),
        backupRequired(actionId),
        List.copyOf(preconditions),
        steps(actionId),
        List.copyOf(warnings),
        List.copyOf(blockReasons),
        reasonCode);
  }

  private OperatorRecoveryResult executePlanned(OperatorRecoveryPlan plan) {
    OperatorRecoveryActionId action = plan.actionId();
    OperatorRecoveryTarget target = plan.target();
    return switch (action) {
      case CATALOG_REFRESH ->
          completed(
              plan,
              "catalog-refresh",
              redactedDetails(
                  RECOVERY_KIND_CATALOG, appCatalogsApiHandler.refresh(target.catalogId())),
              null);
      case CATALOG_REVERIFY ->
          completed(
              plan,
              "catalog-reverify",
              redactedDetails(RECOVERY_KIND_CATALOG, reverifiedCatalog(target.catalogId())),
              null);
      case CATALOG_REPAIR_FIRST_PARTY_SOURCE ->
          completed(
              plan,
              "catalog-repair",
              redactedDetails(
                  RECOVERY_KIND_CATALOG, appCatalogsApiHandler.addRecommended(target.catalogId())),
              null);
      case APP_CHECK_UPDATE ->
          completed(
              plan,
              "app-update-check",
              redactedDetails(RECOVERY_KIND_UPDATE, appUpdateService.check(target.appId(), true)),
              null);
      case APP_STAGE_UPDATE ->
          completed(
              plan,
              "app-update-stage",
              redactedDetails(RECOVERY_KIND_UPDATE, appUpdateService.stage(target.appId())),
              null);
      case APP_APPLY_UPDATE ->
          completed(
              plan,
              "app-update-apply",
              redactedDetails(
                  RECOVERY_KIND_UPDATE,
                  appUpdateService.apply(
                      target.appId(),
                      new AppUpdateService.ApplyOptions(
                          false, AppUpdateService.HealthCheckMode.NONE, false))),
              null);
      case APP_ROLLBACK ->
          completed(
              plan,
              "app-rollback",
              redactedDetails(
                  RECOVERY_KIND_UPDATE, appUpdateService.rollback(target.appId(), false)),
              null);
      case APP_EXPORT_BEFORE_UNINSTALL -> exportBeforeUninstall(plan);
      case APP_STOP ->
          completed(
              plan,
              "app-stop",
              redactedDetails("app", appsApiHandler.stop(target.appId(), false)),
              null);
      case APP_START ->
          completed(
              plan,
              "app-start",
              redactedDetails("app", appsApiHandler.start(target.appId(), false)),
              null);
      case SUBSCRIPTION_REFRESH ->
          completed(
              plan,
              "subscription-refresh",
              redactedDetails(
                  RECOVERY_KIND_SUBSCRIPTION,
                  dashboardService.operatorSubscriptionSummary(
                      contentSubscriptionService.refresh(target.appId(), target.subscriptionId()))),
              null);
      case SUBSCRIPTION_PAUSE ->
          completed(
              plan,
              "subscription-pause",
              redactedDetails(
                  RECOVERY_KIND_SUBSCRIPTION,
                  dashboardService.operatorSubscriptionSummary(
                      contentSubscriptionService.pause(target.appId(), target.subscriptionId()))),
              null);
      case SUBSCRIPTION_RESUME ->
          completed(
              plan,
              "subscription-resume",
              redactedDetails(
                  RECOVERY_KIND_SUBSCRIPTION,
                  dashboardService.operatorSubscriptionSummary(
                      contentSubscriptionService.resume(target.appId(), target.subscriptionId()))),
              null);
      case SUBSCRIPTION_RESET_BACKOFF ->
          completed(
              plan,
              "subscription-reset-backoff",
              redactedDetails(
                  RECOVERY_KIND_SUBSCRIPTION,
                  dashboardService.operatorSubscriptionSummary(
                      contentSubscriptionService.resetBackoff(
                          target.appId(), target.subscriptionId()))),
              null);
      case SUBSCRIPTION_RESCHEDULE_NOW ->
          completed(
              plan,
              "subscription-reschedule-now",
              redactedDetails(
                  RECOVERY_KIND_SUBSCRIPTION,
                  dashboardService.operatorSubscriptionSummary(
                      contentSubscriptionService.rescheduleNow(
                          target.appId(), target.subscriptionId()))),
              null);
      case SUBSCRIPTION_DELETE ->
          completed(
              plan,
              "subscription-delete",
              redactedDetails(
                  RECOVERY_KIND_SUBSCRIPTION,
                  dashboardService.operatorSubscriptionSummary(
                      contentSubscriptionService.delete(target.appId(), target.subscriptionId()))),
              null);
      case APP_SERVICE_GRANT_REVOKE ->
          completed(
              plan,
              "app-service-grant-revoke",
              redactedDetails(
                  "grant",
                  appServiceCoordinator.revokeGrant(
                      PlatformApiPrincipal.hostOperator(), target.grantId())),
              null);
      case APP_SERVICE_BUNDLE_RENEW, APP_SERVICE_BUNDLE_REVALIDATE ->
          completed(
              plan,
              "app-service-bundle-renew",
              redactedDetails(
                  "bundle",
                  appServiceCoordinator.renewBundle(
                      PlatformApiPrincipal.hostOperator(), target.bundleId())),
              null);
      case APP_SERVICE_BUNDLE_REJECT ->
          completed(
              plan,
              "app-service-bundle-reject",
              redactedDetails(
                  "bundle",
                  appServiceCoordinator.rejectBundle(
                      PlatformApiPrincipal.hostOperator(), target.bundleId())),
              null);
      case TRUST_GRAPH_EXPORT_SUMMARY, TRUST_GRAPH_RECOMPUTE_SUMMARY ->
          completed(
              plan,
              "trust-graph-summary",
              redactedDetails("trustGraph", trustGraphExportSummary()),
              null);
      case NETWORK_BUDGET_VIEW -> completed(plan, "network-budget-view", networkBudgets(), null);
      case SUPPORT_BUNDLE_PREVIEW ->
          completed(
              plan,
              "support-bundle-preview",
              redactedDetails(
                  "supportBundlePreview", supportBundlePreview(recoverySupportBundle())),
              null);
      case SUPPORT_BUNDLE_EXPORT ->
          completed(
              plan,
              "support-bundle-export",
              redactedDetails("supportBundle", recoverySupportBundle()),
              null);
      case APP_REINSTALL_FROM_CATALOG, TRUST_GRAPH_RESET_LOCAL_STATE, TRUST_GRAPH_CLEAR_AUDIT ->
          blockedResult(plan);
    };
  }

  private OperatorRecoveryResult exportBeforeUninstall(OperatorRecoveryPlan plan) {
    OperatorRecoveryTarget target = plan.target();
    Map<String, Object> backup =
        appDataService.exportBackup(
            Map.of(PARAM_APP_ID, List.of(target.appId())), currentCryptaVersion.get());
    LinkedHashMap<String, Object> details = LinkedHashMap.newLinkedHashMap(5);
    details.put("backupCreated", true);
    details.put("backupPayloadReturnedInSensitiveBackup", true);

    Map<String, Object> uninstall;
    try {
      uninstall = appsApiHandler.uninstall(target.appId(), false, true);
    } catch (RuntimeException exception) {
      details.put(KEY_APP_PLATFORM_STATE_CLEARED, false);
      details.put(
          "uninstallFailure", failureDetails(exception, "app_uninstall_failed_after_backup"));
      return partialExportBeforeUninstallResult(
          plan,
          details,
          backup,
          List.of(
              OperatorRecoveryStep.completed(
                  STEP_CREATE_BACKUP,
                  STEP_CREATE_BACKUP_LABEL,
                  RECOVERY_KIND_APP_DATA,
                  "Backup completed."),
              OperatorRecoveryStep.failed(
                  STEP_UNINSTALL_APP,
                  STEP_UNINSTALL_APP_LABEL,
                  "app",
                  "Uninstall failed after backup creation.")),
          "App-data backup completed but uninstall failed; download the returned backup before"
              + " continuing recovery.");
    }
    details.put("uninstall", OperatorSupportRedactor.redact(uninstall).value());
    try {
      clearAppStateAfterRecoveryUninstall(target.appId());
      details.put(KEY_APP_PLATFORM_STATE_CLEARED, appUninstallCleanup != null);
    } catch (RuntimeException exception) {
      details.put(KEY_APP_PLATFORM_STATE_CLEARED, false);
      details.put("cleanupFailure", failureDetails(exception, "post_uninstall_cleanup_failed"));
      return partialExportBeforeUninstallResult(
          plan,
          details,
          backup,
          List.of(
              OperatorRecoveryStep.completed(
                  STEP_CREATE_BACKUP,
                  STEP_CREATE_BACKUP_LABEL,
                  RECOVERY_KIND_APP_DATA,
                  "Backup completed."),
              OperatorRecoveryStep.completed(
                  STEP_UNINSTALL_APP, STEP_UNINSTALL_APP_LABEL, "app", "Uninstall completed."),
              OperatorRecoveryStep.failed(
                  "clear-app-platform-state",
                  "Clear related app-platform state",
                  "app",
                  "Post-uninstall cleanup failed.")),
          "Post-uninstall app-platform cleanup failed; download the returned backup before"
              + " continuing recovery.");
    }
    return completed(plan, "app-export-before-uninstall", details, backup);
  }

  private void clearAppStateAfterRecoveryUninstall(String appId) {
    if (appUninstallCleanup != null) {
      appUninstallCleanup.clearAppState(appId, true);
    }
  }

  private OperatorRecoveryResult partialExportBeforeUninstallResult(
      OperatorRecoveryPlan plan,
      Map<String, Object> details,
      Map<String, Object> sensitiveBackup,
      List<OperatorRecoveryStep> steps,
      String warning) {
    ArrayList<String> warnings = new ArrayList<>(plan.warnings());
    warnings.add(warning);
    return new OperatorRecoveryResult(
        RESULT_VERSION,
        plan.actionId(),
        plan.target(),
        OperatorRecoveryStatus.PARTIAL,
        clock.instant().toString(),
        steps,
        warnings,
        supportReference(plan.actionId(), plan.target(), OperatorRecoveryStatus.PARTIAL),
        details,
        sensitiveBackup,
        OperatorRecoveryErrorCode.OPERATION_FAILED);
  }

  private OperatorRecoveryResult completed(
      OperatorRecoveryPlan plan,
      String stepId,
      Map<String, Object> details,
      Map<String, Object> sensitiveBackup) {
    return new OperatorRecoveryResult(
        RESULT_VERSION,
        plan.actionId(),
        plan.target(),
        OperatorRecoveryStatus.COMPLETED,
        clock.instant().toString(),
        List.of(
            OperatorRecoveryStep.completed(
                stepId,
                plan.actionId().label(),
                plan.actionId().category().jsonValue(),
                "Recovery action completed.")),
        plan.warnings(),
        supportReference(plan.actionId(), plan.target(), OperatorRecoveryStatus.COMPLETED),
        details,
        sensitiveBackup,
        OperatorRecoveryErrorCode.NONE);
  }

  private OperatorRecoveryResult blockedResult(OperatorRecoveryPlan plan) {
    return new OperatorRecoveryResult(
        RESULT_VERSION,
        plan.actionId(),
        plan.target(),
        OperatorRecoveryStatus.BLOCKED,
        clock.instant().toString(),
        List.of(
            OperatorRecoveryStep.failed(
                "preconditions",
                "Validate recovery preconditions",
                plan.actionId().category().jsonValue(),
                "Recovery action did not execute.")),
        plan.warnings(),
        supportReference(plan.actionId(), plan.target(), OperatorRecoveryStatus.BLOCKED),
        Map.of("blockReasons", plan.blockReasons()),
        null,
        plan.reasonCode());
  }

  private OperatorRecoveryResult failedResult(
      OperatorRecoveryPlan plan, PlatformApiException exception) {
    LinkedHashMap<String, Object> details = LinkedHashMap.newLinkedHashMap(2);
    details.put(KEY_ERROR_CODE, exception.errorCode());
    details.put("statusCode", exception.statusCode());
    return new OperatorRecoveryResult(
        RESULT_VERSION,
        plan.actionId(),
        plan.target(),
        OperatorRecoveryStatus.FAILED,
        clock.instant().toString(),
        List.of(
            OperatorRecoveryStep.failed(
                "execute",
                plan.actionId().label(),
                plan.actionId().category().jsonValue(),
                "Recovery action failed with a stable Platform API error code.")),
        plan.warnings(),
        supportReference(plan.actionId(), plan.target(), OperatorRecoveryStatus.FAILED),
        details,
        null,
        OperatorRecoveryErrorCode.OPERATION_FAILED);
  }

  private Map<String, Object> reverifiedCatalog(String catalogId) {
    return appCatalogsApiHandler.listCatalogs().stream()
        .filter(catalog -> catalogId.equals(catalog.get(PARAM_CATALOG_ID)))
        .findFirst()
        .orElseThrow(
            () -> new PlatformApiException(404, "catalog_not_found", "App catalog was not found."));
  }

  private Map<String, Object> trustGraphExportSummary() {
    Map<String, Object> status = trustGraphApiHandler.status();
    List<Map<String, Object>> statements = trustGraphApiHandler.statements(Map.of());
    LinkedHashMap<String, Long> lifecycleCounts = LinkedHashMap.newLinkedHashMap(4);
    for (Map<String, Object> statement : statements) {
      String lifecycleStatus =
          stringValue(mapValue(statement.get("lifecycle")).get(KEY_STATUS), "active");
      lifecycleCounts.merge(lifecycleStatus, 1L, Long::sum);
    }
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(10);
    json.put("scope", status.get("scope"));
    json.put("anchorCount", status.get("anchorCount"));
    json.put("statementCount", status.get("statementCount"));
    json.put("lifecycleCounts", lifecycleCounts);
    json.put("auditCount", status.get("auditCount"));
    json.put("subjects", trustGraphApiHandler.subjects().stream().limit(25).toList());
    json.put("anchors", trustGraphApiHandler.anchors().stream().limit(25).toList());
    json.put("metadataOnly", true);
    json.put("completeWot", false);
    json.put(
        "warning", "Trust Graph Local RC is local operator-curated state only, not global trust.");
    return json;
  }

  private Map<String, Object> redactedDetails(String key, Object value) {
    OperatorSupportRedactor.RedactionResult redacted = OperatorSupportRedactor.redact(value);
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(2);
    json.put(key, redacted.value());
    if (!redacted.omittedFields().isEmpty()) {
      json.put("redactionOmittedFields", redacted.omittedFields());
    }
    return json;
  }

  private Map<String, Object> recoverySupportBundle() {
    LinkedHashMap<String, Object> bundle = LinkedHashMap.newLinkedHashMap(12);
    Map<String, Object> supplied = supportBundleSupplier.get();
    if (supplied != null) {
      bundle.putAll(supplied);
    }
    bundle.put("supportBundleVersion", bundle.get("schemaVersion"));
    bundle.put("recoveryContext", supportContext());
    return redactedMap(bundle);
  }

  private void addRequiredTargetPreconditions(
      OperatorRecoveryActionId actionId,
      OperatorRecoveryTarget target,
      List<OperatorRecoveryPrecondition> preconditions,
      List<String> blockReasons) {
    for (String field : actionId.targetFields()) {
      String value = targetField(target, field);
      if (value == null || value.isBlank()) {
        preconditions.add(
            new OperatorRecoveryPrecondition(
                "target." + field,
                OperatorRecoveryStatus.FAIL,
                "Target field '" + field + "' is required."));
        blockReasons.add("missing_" + field);
      } else {
        preconditions.add(
            new OperatorRecoveryPrecondition(
                "target." + field,
                OperatorRecoveryStatus.PASS,
                "Target field '" + field + "' is present."));
      }
    }
  }

  private OperatorRecoveryErrorCode addServicePreconditions(
      OperatorRecoveryActionId actionId,
      List<OperatorRecoveryPrecondition> preconditions,
      List<String> blockReasons,
      OperatorRecoveryErrorCode currentReason) {
    String unavailable = unavailableService(actionId);
    if (unavailable == null) {
      preconditions.add(
          new OperatorRecoveryPrecondition(
              "service.available",
              OperatorRecoveryStatus.PASS,
              "Required recovery service is available."));
      return currentReason;
    }
    preconditions.add(
        new OperatorRecoveryPrecondition(
            "service.available", OperatorRecoveryStatus.FAIL, unavailable));
    blockReasons.add(unavailable.toLowerCase(Locale.ROOT).replace(' ', '_'));
    return OperatorRecoveryErrorCode.SERVICE_UNAVAILABLE;
  }

  private OperatorRecoveryErrorCode addStatePreconditions(
      OperatorRecoveryActionId actionId,
      OperatorRecoveryTarget target,
      List<OperatorRecoveryPrecondition> preconditions,
      List<String> blockReasons,
      OperatorRecoveryErrorCode currentReason) {
    if (hasMissingRequiredTarget(actionId, target) || unavailableService(actionId) != null) {
      return currentReason;
    }
    return switch (actionId) {
      case APP_ROLLBACK -> appRollbackPreconditions(target.appId(), preconditions, blockReasons);
      case APP_APPLY_UPDATE -> appApplyPreconditions(target.appId(), preconditions, blockReasons);
      case APP_STOP -> appRunningPrecondition(target.appId(), true, preconditions, blockReasons);
      case APP_START -> appRunningPrecondition(target.appId(), false, preconditions, blockReasons);
      case APP_EXPORT_BEFORE_UNINSTALL ->
          appExportBeforeUninstallPreconditions(target.appId(), preconditions, blockReasons);
      case APP_REINSTALL_FROM_CATALOG ->
          unavailableActionPrecondition(
              "app.reinstall.safe-api",
              "A dedicated verified catalog reinstall API is not available.",
              preconditions,
              blockReasons);
      case TRUST_GRAPH_RESET_LOCAL_STATE ->
          unavailableActionPrecondition(
              "trust-graph.reset.safe-api",
              "Trust Graph stores do not expose a tested local-state reset API.",
              preconditions,
              blockReasons);
      case TRUST_GRAPH_CLEAR_AUDIT ->
          unavailableActionPrecondition(
              "trust-graph.audit-clear.safe-api",
              "Trust Graph stores do not expose a tested audit-clear API.",
              preconditions,
              blockReasons);
      case APP_SERVICE_GRANT_REVOKE ->
          appServiceGrantPrecondition(target.grantId(), preconditions, blockReasons);
      case APP_SERVICE_BUNDLE_RENEW, APP_SERVICE_BUNDLE_REVALIDATE, APP_SERVICE_BUNDLE_REJECT ->
          appServiceBundlePrecondition(target.bundleId(), preconditions, blockReasons);
      default -> currentReason;
    };
  }

  private OperatorRecoveryErrorCode appRollbackPreconditions(
      String appId, List<OperatorRecoveryPrecondition> preconditions, List<String> blockReasons) {
    boolean running = appRunning(appId);
    if (running) {
      preconditions.add(
          new OperatorRecoveryPrecondition(
              PRECONDITION_APP_STOPPED,
              OperatorRecoveryStatus.FAIL,
              "App must be stopped before rollback."));
      blockReasons.add(BLOCK_APP_RUNNING);
    } else {
      preconditions.add(
          new OperatorRecoveryPrecondition(
              PRECONDITION_APP_STOPPED, OperatorRecoveryStatus.PASS, MESSAGE_APP_IS_STOPPED));
    }
    Map<String, Object> rollback = mapValue(appUpdateService.summary(appId).get("rollback"));
    if (!Boolean.TRUE.equals(rollback.get(KEY_AVAILABLE))) {
      preconditions.add(
          new OperatorRecoveryPrecondition(
              "app.rollback.available",
              OperatorRecoveryStatus.FAIL,
              "Rollback metadata is not available."));
      blockReasons.add("rollback_unavailable");
    } else {
      preconditions.add(
          new OperatorRecoveryPrecondition(
              "app.rollback.available",
              OperatorRecoveryStatus.PASS,
              "Rollback metadata is available."));
    }
    return blockReasons.isEmpty()
        ? OperatorRecoveryErrorCode.NONE
        : OperatorRecoveryErrorCode.PRECONDITION_FAILED;
  }

  private OperatorRecoveryErrorCode appApplyPreconditions(
      String appId, List<OperatorRecoveryPrecondition> preconditions, List<String> blockReasons) {
    boolean running = appRunning(appId);
    if (running) {
      preconditions.add(
          new OperatorRecoveryPrecondition(
              PRECONDITION_APP_STOPPED,
              OperatorRecoveryStatus.FAIL,
              "App must be stopped before applying the staged update."));
      blockReasons.add(BLOCK_APP_RUNNING);
    } else {
      preconditions.add(
          new OperatorRecoveryPrecondition(
              PRECONDITION_APP_STOPPED, OperatorRecoveryStatus.PASS, MESSAGE_APP_IS_STOPPED));
    }
    Map<String, Object> staged = mapValue(appUpdateService.summary(appId).get("staged"));
    if (!Boolean.TRUE.equals(staged.get(KEY_AVAILABLE))) {
      preconditions.add(
          new OperatorRecoveryPrecondition(
              "app.update.staged", OperatorRecoveryStatus.FAIL, "No staged update is available."));
      blockReasons.add("staged_update_unavailable");
    } else {
      preconditions.add(
          new OperatorRecoveryPrecondition(
              "app.update.staged", OperatorRecoveryStatus.PASS, "A staged update is available."));
    }
    return blockReasons.isEmpty()
        ? OperatorRecoveryErrorCode.NONE
        : OperatorRecoveryErrorCode.PRECONDITION_FAILED;
  }

  private OperatorRecoveryErrorCode appRunningPrecondition(
      String appId,
      boolean expectedRunning,
      List<OperatorRecoveryPrecondition> preconditions,
      List<String> blockReasons) {
    boolean running = appRunning(appId);
    boolean pass = running == expectedRunning;
    preconditions.add(
        new OperatorRecoveryPrecondition(
            expectedRunning ? "app.running" : PRECONDITION_APP_STOPPED,
            pass ? OperatorRecoveryStatus.PASS : OperatorRecoveryStatus.FAIL,
            expectedRunning
                ? "App must be running before it can be stopped."
                : "App must be stopped before it can be started."));
    if (!pass) {
      blockReasons.add(expectedRunning ? "app_not_running" : "app_already_running");
      return OperatorRecoveryErrorCode.PRECONDITION_FAILED;
    }
    return OperatorRecoveryErrorCode.NONE;
  }

  private OperatorRecoveryErrorCode appExportBeforeUninstallPreconditions(
      String appId, List<OperatorRecoveryPrecondition> preconditions, List<String> blockReasons) {
    boolean running = appRunning(appId);
    if (running) {
      preconditions.add(
          new OperatorRecoveryPrecondition(
              PRECONDITION_APP_STOPPED,
              OperatorRecoveryStatus.FAIL,
              "App must be stopped before export-before-uninstall."));
      blockReasons.add(BLOCK_APP_RUNNING);
      return OperatorRecoveryErrorCode.PRECONDITION_FAILED;
    }
    preconditions.add(
        new OperatorRecoveryPrecondition(
            PRECONDITION_APP_STOPPED, OperatorRecoveryStatus.PASS, MESSAGE_APP_IS_STOPPED));
    return OperatorRecoveryErrorCode.NONE;
  }

  private OperatorRecoveryErrorCode appServiceGrantPrecondition(
      String grantId, List<OperatorRecoveryPrecondition> preconditions, List<String> blockReasons) {
    boolean found =
        appServiceCoordinator.listGrants(PlatformApiPrincipal.hostOperator()).stream()
            .anyMatch(grant -> grantId.equals(grant.get(PARAM_GRANT_ID)));
    preconditions.add(
        new OperatorRecoveryPrecondition(
            "app-service.grant.exists",
            found ? OperatorRecoveryStatus.PASS : OperatorRecoveryStatus.FAIL,
            found ? "App-service grant exists." : "App-service grant was not found."));
    if (!found) {
      blockReasons.add("app_service_grant_not_found");
      return OperatorRecoveryErrorCode.PRECONDITION_FAILED;
    }
    return OperatorRecoveryErrorCode.NONE;
  }

  private OperatorRecoveryErrorCode appServiceBundlePrecondition(
      String bundleId,
      List<OperatorRecoveryPrecondition> preconditions,
      List<String> blockReasons) {
    boolean found =
        appServiceCoordinator.listBundles(PlatformApiPrincipal.hostOperator()).stream()
            .anyMatch(bundle -> bundleId.equals(bundle.get(PARAM_BUNDLE_ID)));
    preconditions.add(
        new OperatorRecoveryPrecondition(
            "app-service.bundle.exists",
            found ? OperatorRecoveryStatus.PASS : OperatorRecoveryStatus.FAIL,
            found
                ? "App-service grant bundle exists."
                : "App-service grant bundle was not found."));
    if (!found) {
      blockReasons.add("app_service_bundle_not_found");
      return OperatorRecoveryErrorCode.PRECONDITION_FAILED;
    }
    return OperatorRecoveryErrorCode.NONE;
  }

  private OperatorRecoveryErrorCode unavailableActionPrecondition(
      String id,
      String message,
      List<OperatorRecoveryPrecondition> preconditions,
      List<String> blockReasons) {
    preconditions.add(new OperatorRecoveryPrecondition(id, OperatorRecoveryStatus.FAIL, message));
    blockReasons.add("action_unavailable");
    return OperatorRecoveryErrorCode.ACTION_UNAVAILABLE;
  }

  private boolean appRunning(String appId) {
    return Boolean.TRUE.equals(appsApiHandler.get(appId, false).get("running"));
  }

  private void addActionWarnings(OperatorRecoveryActionId actionId, List<String> warnings) {
    switch (actionId) {
      case SUBSCRIPTION_REFRESH ->
          warnings.add("Subscription refresh fetches content and consumes app-network budget.");
      case SUBSCRIPTION_RESET_BACKOFF, SUBSCRIPTION_RESCHEDULE_NOW ->
          warnings.add(
              "This subscription action updates metadata only and does not fetch content.");
      case TRUST_GRAPH_EXPORT_SUMMARY, TRUST_GRAPH_RECOMPUTE_SUMMARY ->
          warnings.add(
              "Trust Graph Local RC export is metadata-only and does not represent global trust.");
      case APP_EXPORT_BEFORE_UNINSTALL ->
          warnings.add("The backup payload is returned only in this explicit action response.");
      case APP_REINSTALL_FROM_CATALOG ->
          warnings.add(
              "Use update check/stage/apply when a verified update candidate is available.");
      default -> {
        // Most actions rely on preconditions and existing service gates.
      }
    }
  }

  private static OperatorRecoveryStatus planStatus(
      OperatorRecoveryActionId actionId,
      List<String> warnings,
      List<String> blockReasons,
      OperatorRecoveryErrorCode reasonCode) {
    if (!blockReasons.isEmpty()) {
      return reasonCode == OperatorRecoveryErrorCode.SERVICE_UNAVAILABLE
              || reasonCode == OperatorRecoveryErrorCode.ACTION_UNAVAILABLE
          ? OperatorRecoveryStatus.UNAVAILABLE
          : OperatorRecoveryStatus.BLOCKED;
    }
    if (actionId.destructive()) {
      return OperatorRecoveryStatus.DESTRUCTIVE;
    }
    if (!warnings.isEmpty()) {
      return OperatorRecoveryStatus.WARNING;
    }
    return OperatorRecoveryStatus.READY;
  }

  private static OperatorRecoveryErrorCode mergeReason(
      OperatorRecoveryErrorCode currentReason, List<String> blockReasons) {
    return blockReasons.isEmpty() ? currentReason : OperatorRecoveryErrorCode.INVALID_TARGET;
  }

  private String unavailableService(OperatorRecoveryActionId actionId) {
    return switch (actionId.category()) {
      case CATALOG -> appCatalogsApiHandler == null ? "Catalog service is unavailable." : null;
      case APP -> unavailableAppService(actionId);
      case SUBSCRIPTION ->
          contentSubscriptionService == null
              ? "Content subscription service is unavailable."
              : null;
      case APP_SERVICE ->
          appServiceCoordinator == null ? "App-service coordinator is unavailable." : null;
      case TRUST_GRAPH ->
          trustGraphApiHandler == null ? "Trust Graph Local RC service is unavailable." : null;
      case NETWORK_BUDGET ->
          networkBudgetService == null ? "App-network budget service is unavailable." : null;
      case SUPPORT -> null;
    };
  }

  private String unavailableAppService(OperatorRecoveryActionId actionId) {
    boolean directAppHostAction =
        actionId == OperatorRecoveryActionId.APP_STOP
            || actionId == OperatorRecoveryActionId.APP_START
            || actionId == OperatorRecoveryActionId.APP_EXPORT_BEFORE_UNINSTALL;
    if (directAppHostAction && appsApiHandler == null) {
      return "AppHost service is unavailable.";
    }
    if (actionId == OperatorRecoveryActionId.APP_EXPORT_BEFORE_UNINSTALL
        && appDataService == null) {
      return "App-data service is unavailable.";
    }
    boolean updateAction =
        actionId == OperatorRecoveryActionId.APP_CHECK_UPDATE
            || actionId == OperatorRecoveryActionId.APP_STAGE_UPDATE
            || actionId == OperatorRecoveryActionId.APP_APPLY_UPDATE
            || actionId == OperatorRecoveryActionId.APP_ROLLBACK
            || actionId == OperatorRecoveryActionId.APP_REINSTALL_FROM_CATALOG;
    if (updateAction && appUpdateService == null) {
      return "App-update lifecycle service is unavailable.";
    }
    boolean appHostUpdateAction =
        actionId == OperatorRecoveryActionId.APP_APPLY_UPDATE
            || actionId == OperatorRecoveryActionId.APP_ROLLBACK
            || actionId == OperatorRecoveryActionId.APP_REINSTALL_FROM_CATALOG;
    if (appHostUpdateAction && appsApiHandler == null) {
      return "AppHost service is unavailable.";
    }
    return null;
  }

  private static List<OperatorRecoveryStep> steps(OperatorRecoveryActionId actionId) {
    return switch (actionId) {
      case CATALOG_REFRESH ->
          List.of(
              OperatorRecoveryStep.planned(
                  "fetch-catalog", "Fetch configured catalog source", RECOVERY_KIND_CATALOG, false),
              OperatorRecoveryStep.planned(
                  "verify-catalog",
                  "Verify catalog signature and policy",
                  RECOVERY_KIND_CATALOG,
                  true));
      case CATALOG_REVERIFY ->
          List.of(
              OperatorRecoveryStep.planned(
                  "reverify-catalog",
                  "Re-read and verify stored catalog sidecars",
                  RECOVERY_KIND_CATALOG,
                  true));
      case APP_EXPORT_BEFORE_UNINSTALL ->
          List.of(
              OperatorRecoveryStep.planned(
                  STEP_CREATE_BACKUP, STEP_CREATE_BACKUP_LABEL, RECOVERY_KIND_APP_DATA, true),
              OperatorRecoveryStep.planned(
                  STEP_UNINSTALL_APP, STEP_UNINSTALL_APP_LABEL, "app", false));
      case TRUST_GRAPH_EXPORT_SUMMARY, TRUST_GRAPH_RECOMPUTE_SUMMARY ->
          List.of(
              OperatorRecoveryStep.planned(
                  "trust-graph-summary",
                  "Collect metadata-only Trust Graph summary",
                  "trust-graph",
                  true));
      case NETWORK_BUDGET_VIEW ->
          List.of(
              OperatorRecoveryStep.planned(
                  "network-budget-snapshots",
                  "Read safe budget snapshots",
                  "network-budget",
                  true));
      default ->
          List.of(
              OperatorRecoveryStep.planned(
                  actionId.jsonValue(),
                  actionId.label(),
                  actionId.category().jsonValue(),
                  !actionId.destructive()));
    };
  }

  private static boolean requiresStoppedApp(OperatorRecoveryActionId actionId) {
    return actionId == OperatorRecoveryActionId.APP_APPLY_UPDATE
        || actionId == OperatorRecoveryActionId.APP_ROLLBACK
        || actionId == OperatorRecoveryActionId.APP_START
        || actionId == OperatorRecoveryActionId.APP_EXPORT_BEFORE_UNINSTALL
        || actionId == OperatorRecoveryActionId.APP_REINSTALL_FROM_CATALOG;
  }

  private static boolean backupRecommended(OperatorRecoveryActionId actionId) {
    return actionId == OperatorRecoveryActionId.APP_APPLY_UPDATE
        || actionId == OperatorRecoveryActionId.APP_ROLLBACK
        || actionId == OperatorRecoveryActionId.APP_REINSTALL_FROM_CATALOG;
  }

  private static boolean backupRequired(OperatorRecoveryActionId actionId) {
    return actionId == OperatorRecoveryActionId.APP_EXPORT_BEFORE_UNINSTALL;
  }

  private static String confirmationPhrase(
      OperatorRecoveryActionId actionId, OperatorRecoveryTarget target) {
    if (!actionId.requiresConfirmation()) {
      return null;
    }
    String targetId = target.safePrimaryId();
    return switch (actionId) {
      case APP_APPLY_UPDATE -> "APPLY " + targetId;
      case APP_ROLLBACK -> "ROLLBACK " + targetId;
      case APP_REINSTALL_FROM_CATALOG -> "REINSTALL " + targetId;
      case APP_EXPORT_BEFORE_UNINSTALL -> "UNINSTALL " + targetId;
      case SUBSCRIPTION_DELETE -> "DELETE SUBSCRIPTION " + targetId;
      case APP_SERVICE_GRANT_REVOKE -> "REVOKE GRANT " + targetId;
      case APP_SERVICE_BUNDLE_REJECT -> "REJECT BUNDLE " + targetId;
      case TRUST_GRAPH_RESET_LOCAL_STATE -> "RESET TRUST GRAPH";
      case TRUST_GRAPH_CLEAR_AUDIT -> "CLEAR TRUST GRAPH AUDIT";
      default -> actionId.jsonValue().toUpperCase(Locale.ROOT) + " " + targetId;
    };
  }

  private static void requireConfirmationIfNeeded(
      OperatorRecoveryPlan plan, Map<String, List<String>> parameters) {
    if (!plan.requiresConfirmation()) {
      return;
    }
    boolean confirmed = PlatformApiParameters.readBoolean(parameters, PARAM_CONFIRM, false);
    if (!confirmed) {
      throw new PlatformApiException(
          409,
          "recovery_confirmation_required",
          "Destructive recovery action requires explicit confirmation.");
    }
    String supplied =
        PlatformApiParameters.readOptionalString(parameters, PARAM_CONFIRMATION_PHRASE);
    if (!Objects.equals(plan.confirmationPhrase(), supplied)) {
      throw new PlatformApiException(
          409,
          "recovery_confirmation_mismatch",
          "Destructive recovery action confirmation phrase did not match.");
    }
  }

  private static OperatorRecoveryActionId requireActionId(Map<String, List<String>> parameters) {
    String raw = PlatformApiParameters.requireString(parameters, PARAM_ACTION_ID);
    return OperatorRecoveryActionId.fromJsonValue(raw)
        .orElseThrow(
            () ->
                new PlatformApiException(
                    400,
                    "unknown_recovery_action",
                    "Recovery action id is not in the operator allowlist."));
  }

  private static OperatorRecoveryTarget target(
      OperatorRecoveryActionId actionId, Map<String, List<String>> parameters) {
    return new OperatorRecoveryTarget(
        actionId.targetKind(),
        optional(parameters, PARAM_APP_ID),
        optional(parameters, PARAM_CATALOG_ID),
        optional(parameters, PARAM_SUBSCRIPTION_ID),
        optional(parameters, PARAM_GRANT_ID),
        optional(parameters, PARAM_BUNDLE_ID));
  }

  private static boolean hasMissingRequiredTarget(
      OperatorRecoveryActionId actionId, OperatorRecoveryTarget target) {
    return actionId.targetFields().stream()
        .anyMatch(
            field -> {
              String value = targetField(target, field);
              return value == null || value.isBlank();
            });
  }

  private static String targetField(OperatorRecoveryTarget target, String field) {
    return switch (field) {
      case PARAM_APP_ID -> target.appId();
      case PARAM_CATALOG_ID -> target.catalogId();
      case PARAM_SUBSCRIPTION_ID -> target.subscriptionId();
      case PARAM_GRANT_ID -> target.grantId();
      case PARAM_BUNDLE_ID -> target.bundleId();
      default -> null;
    };
  }

  private static String optional(Map<String, List<String>> parameters, String name) {
    String value = PlatformApiParameters.readOptionalString(parameters, name);
    return value == null || value.isBlank() ? null : value.trim();
  }

  private Map<String, Object> supportReference(
      OperatorRecoveryActionId actionId,
      OperatorRecoveryTarget target,
      OperatorRecoveryStatus status) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(3);
    json.put(
        "safeDigest",
        safeDigest(actionId.jsonValue() + "|" + target.fingerprintSource() + "|" + status));
    json.put("includeInSupportBundle", true);
    json.put("auditEventType", "operator_recovery_executed");
    return json;
  }

  private synchronized void appendAudit(
      OperatorRecoveryActionId actionId,
      OperatorRecoveryTarget target,
      OperatorRecoveryStatus status,
      OperatorRecoveryErrorCode reasonCode) {
    auditSequence++;
    LinkedHashMap<String, Object> event = LinkedHashMap.newLinkedHashMap(8);
    event.put("eventId", "operator-recovery-" + auditSequence);
    event.put("eventType", "operator_recovery_executed");
    event.put(PARAM_ACTION_ID, actionId.jsonValue());
    event.put("targetKind", target.kind());
    event.put("targetId", safeAuditTargetId(target));
    event.put(KEY_STATUS, status.jsonValue());
    event.put("timestamp", clock.instant().toString());
    event.put("reasonCode", reasonCode.jsonValue());
    auditEvents.add(event);
    while (auditEvents.size() > AUDIT_LIMIT) {
      auditEvents.removeFirst();
    }
  }

  private Map<String, Object> actionsByCategory() {
    LinkedHashMap<String, Object> grouped = LinkedHashMap.newLinkedHashMap(7);
    for (OperatorRecoveryActionCategory category : OperatorRecoveryActionCategory.values()) {
      grouped.put(
          category.jsonValue(),
          actions().stream()
              .filter(action -> category.jsonValue().equals(action.get("category")))
              .toList());
    }
    return grouped;
  }

  private static Map<String, Object> actionDescriptor(OperatorRecoveryActionId action) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(10);
    json.put(PARAM_ACTION_ID, action.jsonValue());
    json.put("label", action.label());
    json.put("category", action.category().jsonValue());
    json.put("severity", action.severity().jsonValue());
    json.put("targetKind", action.targetKind());
    json.put("targetFields", action.targetFields());
    json.put("destructive", action.destructive());
    json.put("requiresConfirmation", action.requiresConfirmation());
    json.put("description", action.description());
    json.put("planRoute", "operator/recovery/plan");
    json.put("executeRoute", "operator/recovery/execute");
    return json;
  }

  private static List<String> includedSections(Map<String, Object> supportBundle) {
    LinkedHashSet<String> sections = new LinkedHashSet<>(supportBundle.keySet());
    sections.remove(KEY_WARNINGS);
    return List.copyOf(sections);
  }

  private String issuePlanToken(OperatorRecoveryActionId actionId, OperatorRecoveryTarget target) {
    String fingerprint = planFingerprint(actionId, target);
    planSequence++;
    String token = safeDigest(fingerprint + "|" + clock.instant() + "|" + planSequence);
    issuedPlanTokens.put(token, fingerprint);
    while (issuedPlanTokens.size() > PLAN_TOKEN_LIMIT) {
      var iterator = issuedPlanTokens.keySet().iterator();
      if (!iterator.hasNext()) {
        break;
      }
      iterator.next();
      iterator.remove();
    }
    return token;
  }

  private String requireIssuedPlanToken(
      Map<String, List<String>> parameters,
      OperatorRecoveryActionId actionId,
      OperatorRecoveryTarget target) {
    String supplied = PlatformApiParameters.readOptionalString(parameters, PARAM_PLAN_TOKEN);
    if (supplied == null || supplied.isBlank()) {
      throw new PlatformApiException(
          409,
          "recovery_plan_required",
          "Recovery execute requires a plan token returned by the plan endpoint.");
    }
    String expectedFingerprint = issuedPlanTokens.get(supplied);
    if (!Objects.equals(expectedFingerprint, planFingerprint(actionId, target))) {
      throw new PlatformApiException(
          409,
          "recovery_plan_mismatch",
          "Recovery execute plan token does not match the requested action and target.");
    }
    return supplied;
  }

  private void consumePlanToken(String planToken) {
    issuedPlanTokens.remove(planToken);
  }

  private static String planFingerprint(
      OperatorRecoveryActionId actionId, OperatorRecoveryTarget target) {
    return safeDigest(actionId.jsonValue() + "|" + target.fingerprintSource());
  }

  private static PlatformApiException mappedTrustGraphException(TrustGraphException exception) {
    return new PlatformApiException(
        "trust_graph_store_unavailable".equals(exception.errorCode()) ? 503 : 400,
        exception.errorCode(),
        exception.getMessage());
  }

  private static Map<String, Object> failureDetails(
      RuntimeException exception, String fallbackErrorCode) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(2);
    if (exception instanceof PlatformApiException platformApiException) {
      json.put(KEY_ERROR_CODE, platformApiException.errorCode());
      json.put("statusCode", platformApiException.statusCode());
      return json;
    }
    json.put(KEY_ERROR_CODE, fallbackErrorCode);
    json.put("exceptionType", exception.getClass().getSimpleName());
    return json;
  }

  private static String safeAuditTargetId(OperatorRecoveryTarget target) {
    String targetId = target.primaryId();
    if (targetId == null || targetId.isBlank()) {
      return "";
    }
    String redacted = stringValue(OperatorSupportRedactor.redact(targetId).value(), "");
    if (!Objects.equals(targetId, redacted)) {
      return "sha256:" + safeDigest(targetId).substring(0, 16);
    }
    return targetId.length() <= 160 ? targetId : targetId.substring(0, 157) + "...";
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> redactedMap(Map<String, Object> value) {
    Object redacted = OperatorSupportRedactor.redact(value).value();
    if (redacted instanceof Map<?, ?> map) {
      return (Map<String, Object>) map;
    }
    return Map.of();
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> mapValue(Object value) {
    if (value instanceof Map<?, ?> map) {
      return (Map<String, Object>) map;
    }
    return Map.of();
  }

  private static String stringValue(Object value, String fallback) {
    return value instanceof String text && !text.isBlank() ? text : fallback;
  }

  private static String safeDigest(String value) {
    try {
      return HEX.formatHex(
          MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
    } catch (NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable", exception);
    }
  }
}

package network.crypta.platform.api.operator;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.api.PlatformApiPrincipal;
import network.crypta.platform.api.appcatalogs.AppCatalogsApiHandler;
import network.crypta.platform.api.appdata.AppDataService;
import network.crypta.platform.api.apps.AppsApiHandler;
import network.crypta.platform.api.appservices.AppServiceCoordinator;
import network.crypta.platform.api.appupdates.AppUpdateService;
import network.crypta.platform.api.content.subscriptions.ContentSubscriptionService;
import network.crypta.platform.api.diagnostics.DiagnosticsApiHandler;
import network.crypta.platform.api.trust.TrustGraphApiHandler;

/**
 * Builds the host/operator app-ecosystem beta dashboard and support bundle.
 *
 * <p>The service is deliberately a read-mostly composition layer over existing Platform API
 * handlers. Optional app-platform services are reported as unavailable blocks instead of failing
 * the whole dashboard, and support-bundle output passes through {@link OperatorSupportRedactor}
 * before it is serialized. The resulting maps are suitable for the local Web Shell and legacy admin
 * bridge; they are not an app-facing API contract, and they do not grant app origins access to
 * host-only state.
 *
 * <p>The dashboard favors operator actionability over raw detail. It summarizes catalog health,
 * installed apps, update state, subscription backoff, local Trust Graph Preview status, app-service
 * grants, and legacy-admin usage counters, then attaches safe recovery actions for the UI to
 * render. Source URIs, raw fetched content, local file paths, and diagnostic bodies are either
 * omitted, redacted, or replaced by bounded digests. Instances are lightweight and hold references
 * to long-lived services supplied by router composition; they do not start schedulers or persist
 * dashboard state.
 */
public final class OperatorBetaDashboardService {
  private static final Pattern CONTENT_URI =
      Pattern.compile("(?i)^(?:crypta:)?(?:CHK|SSK|USK|KSK)@.*");
  private static final String ACTION_REQUIRED = "action_required";
  private static final String WARNING = "warning";
  private static final String UNAVAILABLE = "unavailable";
  private static final String HEALTHY = "healthy";
  private static final String ACTIVE = "active";
  private static final String BACKOFF = "backoff";
  private static final String CANDIDATE_FIELD = "candidate";
  private static final String CATALOG_ID_FIELD = "catalogId";
  private static final String DIAGNOSTICS_UNAVAILABLE = "Diagnostics service is unavailable.";
  private static final String FIRST_PARTY = "first-party";
  private static final String LIVE_USK = "live-usk";
  private static final String PENDING = "pending";
  private static final String STAGED_FIELD = "staged";
  private static final String STALE = "stale";
  private static final String LEGACY_ADMIN_USAGE_UNAVAILABLE =
      "Legacy-admin usage counters are unavailable.";
  private static final String UNKNOWN = "unknown";
  private static final String STATUS_FIELD = "status";
  private static final String AVAILABLE_FIELD = "available";
  private static final String AVAILABLE_STATUS = "available";
  private static final String WARNINGS_FIELD = "warnings";
  private static final String APP_ID_FIELD = "appId";
  private static final String APPS_ROUTE_PREFIX = "apps/";
  private static final String BLOCKED_MUTATING_REQUEST_COUNT_FIELD = "blockedMutatingRequestCount";
  private static final String FAILURE_COUNT_FIELD = "failureCount";
  private static final String GENERATED_AT_FIELD = "generatedAtEpochMillis";
  private static final String LABEL_FIELD = "label";
  private static final String LAST_SUCCESS_AT_FIELD = "lastSuccessAt";
  private static final String LEGACY_ADMIN_FIELD = "legacyAdmin";
  private static final String NEXT_CHECK_AT_FIELD = "nextCheckAt";
  private static final String PENDING_GRANT_COUNT_FIELD = "pendingGrantCount";
  private static final String QUOTA_FIELD = "quota";
  private static final String RECOVERY_ACTIONS_FIELD = "recoveryActions";
  private static final String RETAINED_OR_PENDING_RENDER_COUNT_FIELD =
      "retainedOrPendingRenderCount";
  private static final String REVIEW_TRUST_FIELD = "reviewTrust";
  private static final String RUNNING_FIELD = "running";
  private static final String SANDBOX_FIELD = "sandbox";
  private static final String SECTION_COUNT_FIELD = "sectionCount";
  private static final String SOURCE_KIND_FIELD = "sourceKind";
  private static final String STATE_FIELD = "state";
  private static final String UPDATE_FIELD = "update";
  private static final String CATALOGS_UNAVAILABLE = "Catalog service is unavailable.";
  private static final String APPS_UNAVAILABLE = "AppHost service is unavailable.";
  private static final HexFormat HEX = HexFormat.of();

  /**
   * Host-side handlers that read app runtime, catalog, update, and diagnostic state.
   *
   * <p>The dashboard treats each component as optional because release, test, and embedded
   * deployments can intentionally omit platform subsystems. A {@code null} component does not mean
   * the subsystem is healthy but empty; it means the corresponding dashboard section should render
   * as unavailable and contribute a warning. Grouping these handlers keeps route composition
   * explicit without exposing a broad mutable dependency bag.
   *
   * @param appsApiHandler installed-app summary handler, or {@code null} when AppHost is absent
   * @param appCatalogsApiHandler catalog summary handler, or {@code null} when catalogs are absent
   * @param appUpdateService app-update lifecycle service, or {@code null} when updates are absent
   * @param diagnosticsApiHandler diagnostics handler, or {@code null} when diagnostics are absent
   */
  public record HandlerSources(
      AppsApiHandler appsApiHandler,
      AppCatalogsApiHandler appCatalogsApiHandler,
      AppUpdateService appUpdateService,
      DiagnosticsApiHandler diagnosticsApiHandler) {}

  /**
   * App-owned state services summarized by the operator beta dashboard.
   *
   * <p>These collaborators describe durable app data, content subscriptions, local Trust Graph
   * Preview state, and app-to-app service grants. They are separate from {@link HandlerSources}
   * because they represent stateful app-platform services rather than HTTP handler facades. Null
   * components are preserved so dashboard sections can explain exactly which subsystem is not wired
   * instead of silently fabricating an empty state.
   *
   * @param contentSubscriptionService durable subscription service, or {@code null} when disabled
   * @param appDataService durable app-data service, or {@code null} when storage is absent
   * @param trustGraphApiHandler local Trust Graph Preview handler, or {@code null} when unavailable
   * @param appServiceCoordinator app-service coordinator, or {@code null} when grants are disabled
   */
  public record AppStateSources(
      ContentSubscriptionService contentSubscriptionService,
      AppDataService appDataService,
      TrustGraphApiHandler trustGraphApiHandler,
      AppServiceCoordinator appServiceCoordinator) {}

  private final AppsApiHandler appsApiHandler;
  private final AppCatalogsApiHandler appCatalogsApiHandler;
  private final AppUpdateService appUpdateService;
  private final ContentSubscriptionService contentSubscriptionService;
  private final AppDataService appDataService;
  private final TrustGraphApiHandler trustGraphApiHandler;
  private final AppServiceCoordinator appServiceCoordinator;
  private final DiagnosticsApiHandler diagnosticsApiHandler;
  private final Clock clock;

  /**
   * Creates an operator dashboard service from optional platform collaborators.
   *
   * <p>Runtime composition may omit services when a node build, unit test, or embedded deployment
   * does not expose a particular app-platform subsystem. This constructor preserves that partial
   * availability instead of substituting mock health. Later dashboard calls return section-level
   * unavailable blocks and top-level warnings so operators can distinguish a healthy empty state
   * from a service that was not wired.
   *
   * @param handlers host-side API handlers used for runtime, catalog, update, and diagnostics
   *     sections
   * @param appState stateful app-platform services used for subscription, app-data, trust graph,
   *     and grant sections
   */
  public OperatorBetaDashboardService(HandlerSources handlers, AppStateSources appState) {
    this(handlers, appState, Clock.systemUTC());
  }

  OperatorBetaDashboardService(HandlerSources handlers, AppStateSources appState, Clock clock) {
    HandlerSources checkedHandlers = Objects.requireNonNull(handlers, "handlers");
    AppStateSources checkedAppState = Objects.requireNonNull(appState, "appState");
    this.appsApiHandler = checkedHandlers.appsApiHandler();
    this.appCatalogsApiHandler = checkedHandlers.appCatalogsApiHandler();
    this.appUpdateService = checkedHandlers.appUpdateService();
    this.contentSubscriptionService = checkedAppState.contentSubscriptionService();
    this.appDataService = checkedAppState.appDataService();
    this.trustGraphApiHandler = checkedAppState.trustGraphApiHandler();
    this.appServiceCoordinator = checkedAppState.appServiceCoordinator();
    this.diagnosticsApiHandler = checkedHandlers.diagnosticsApiHandler();
    this.clock = Objects.requireNonNull(clock, "clock");
  }

  /**
   * Returns the current operator beta dashboard.
   *
   * <p>The dashboard is assembled on demand from current service state and contains only
   * JSON-compatible values. It is intentionally tolerant of subsystem failures: each section
   * catches runtime inspection failures, records a stable warning, and lets the remaining sections
   * render. Recovery actions are descriptive route references for the local UI. Callers still need
   * the host/operator principal and form-password flow enforced by the outer Platform API transport
   * before those actions can be executed.
   *
   * @return JSON-compatible dashboard object with summary, section, warning, and recovery fields
   */
  public Map<String, Object> dashboard() {
    ArrayList<String> warnings = new ArrayList<>();
    List<Map<String, Object>> catalogs = catalogSummaries(warnings);
    List<Map<String, Object>> apps = appSummaries(warnings);
    List<Map<String, Object>> subscriptions = subscriptionSummaries(warnings);
    Map<String, Object> trustGraph = trustGraphSummary(warnings);
    Map<String, Object> appServices = appServicesSummary(warnings);
    Map<String, Object> diagnostics = diagnosticsSummary(warnings);
    Map<String, Object> legacyAdmin = legacyAdminSummary(diagnostics, warnings);
    Map<String, Object> summary =
        summary(catalogs, apps, subscriptions, appServices, warnings.size());

    LinkedHashMap<String, Object> dashboard = LinkedHashMap.newLinkedHashMap(12);
    dashboard.put(GENERATED_AT_FIELD, clock.millis());
    dashboard.put("overallStatus", overallStatus(summary, warnings));
    dashboard.put("summary", summary);
    dashboard.put("catalogs", catalogs);
    dashboard.put("apps", apps);
    dashboard.put("subscriptions", subscriptions);
    dashboard.put("trustGraph", trustGraph);
    dashboard.put("appServices", appServices);
    dashboard.put(LEGACY_ADMIN_FIELD, legacyAdmin);
    dashboard.put("diagnostics", diagnostics);
    dashboard.put(RECOVERY_ACTIONS_FIELD, topLevelRecoveryActions(catalogs, apps, subscriptions));
    dashboard.put(WARNINGS_FIELD, List.copyOf(warnings));
    return dashboard;
  }

  /**
   * Returns a redacted support bundle suitable for client-side export.
   *
   * <p>The bundle includes the dashboard, diagnostics snapshot, recent app-service audit entries,
   * and legacy-admin counters after each part has passed through {@link OperatorSupportRedactor}.
   * Redaction removes high-risk fields and scrubs common secret-bearing string patterns, but the
   * returned warnings still instruct operators to review the export before sharing it. This method
   * never stores the bundle; callers decide whether and where to write the JSON payload.
   *
   * @return JSON-compatible support bundle object with redaction metadata and operator warnings
   */
  public Map<String, Object> supportBundle() {
    Map<String, Object> dashboard = dashboard();
    Map<String, Object> diagnostics = supportDiagnostics();
    List<Map<String, Object>> recentAudit = supportAppServiceAudit();
    Map<String, Object> legacyAdmin = legacyAdminFromDiagnostics(diagnostics);

    OperatorSupportRedactor.RedactionResult redactedDashboard =
        OperatorSupportRedactor.redact(dashboard);
    OperatorSupportRedactor.RedactionResult redactedDiagnostics =
        OperatorSupportRedactor.redact(diagnostics);
    OperatorSupportRedactor.RedactionResult redactedAudit =
        OperatorSupportRedactor.redact(recentAudit);
    OperatorSupportRedactor.RedactionResult redactedLegacyAdmin =
        OperatorSupportRedactor.redact(legacyAdmin);

    LinkedHashSet<String> omittedFields = new LinkedHashSet<>();
    omittedFields.addAll(redactedDashboard.omittedFields());
    omittedFields.addAll(redactedDiagnostics.omittedFields());
    omittedFields.addAll(redactedAudit.omittedFields());
    omittedFields.addAll(redactedLegacyAdmin.omittedFields());

    LinkedHashMap<String, Object> redaction = LinkedHashMap.newLinkedHashMap(3);
    redaction.put(STATUS_FIELD, "pass");
    redaction.put("patternsChecked", OperatorSupportRedactor.patternsChecked());
    redaction.put("omittedFields", List.copyOf(omittedFields));

    LinkedHashMap<String, Object> bundle = LinkedHashMap.newLinkedHashMap(8);
    bundle.put("kind", "cryptad-operator-support-bundle");
    bundle.put(GENERATED_AT_FIELD, clock.millis());
    bundle.put("schemaVersion", 1);
    bundle.put("dashboard", redactedDashboard.value());
    bundle.put("diagnostics", redactedDiagnostics.value());
    bundle.put("recentAppServiceAudit", redactedAudit.value());
    bundle.put(LEGACY_ADMIN_FIELD, redactedLegacyAdmin.value());
    bundle.put("redaction", redaction);
    bundle.put(WARNINGS_FIELD, supportWarnings(redaction));
    return bundle;
  }

  private List<Map<String, Object>> catalogSummaries(List<String> warnings) {
    if (appCatalogsApiHandler == null) {
      warnings.add(CATALOGS_UNAVAILABLE);
      return List.of();
    }
    try {
      List<Map<String, Object>> catalogs =
          appCatalogsApiHandler.listCatalogs().stream().map(this::catalogSummary).toList();
      warnWhenFirstPartyRecommendationMissing(catalogs, warnings);
      return catalogs;
    } catch (RuntimeException exception) {
      warnings.add("Catalog health could not be inspected: " + safeReason(exception));
      return List.of();
    }
  }

  private Map<String, Object> catalogSummary(Map<String, Object> catalog) {
    String catalogId = stringValue(catalog.get(CATALOG_ID_FIELD));
    String source = stringValue(catalog.get("source"));
    String sourceKind = catalogSourceKind(catalog, source);
    ArrayList<String> warnings = new ArrayList<>();
    String lastFetchStatus = stringValue(catalog.get("lastFetchStatus"));
    if (lastFetchStatus != null && !"success".equalsIgnoreCase(lastFetchStatus)) {
      warnings.add("catalog_refresh_" + lastFetchStatus.toLowerCase(Locale.ROOT));
    }

    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(14);
    json.put(CATALOG_ID_FIELD, catalogId);
    json.put("name", catalog.get("name"));
    json.put(SOURCE_KIND_FIELD, sourceKind);
    json.put("sourceDisplay", safeSourceDisplay(source, sourceKind));
    json.put("sourceDigest", digestOrNull(source));
    json.put(
        "trustedCatalogKeyStatus", catalog.get("signatureKeyId") == null ? UNKNOWN : "configured");
    json.put("lastFetchStatus", lastFetchStatus == null ? UNKNOWN : lastFetchStatus);
    json.put("lastAttemptAt", catalog.get("lastAttemptAt"));
    json.put("lastSuccessfulRefreshAt", catalog.get("lastSuccessfulRefreshAt"));
    json.put("entryCount", catalog.get("appCount"));
    json.put("reviewGovernanceAvailable", appCatalogsApiHandler != null);
    json.put("recommendedFirstPartyPresent", isFirstPartyCatalog(catalog));
    json.put(WARNINGS_FIELD, List.copyOf(warnings));
    json.put(
        RECOVERY_ACTIONS_FIELD,
        catalogId == null
            ? List.of()
            : List.of(
                action(
                    "refresh-catalog",
                    "Refresh catalog",
                    "POST",
                    "app-catalogs/" + encodePathSegment(catalogId) + "/refresh",
                    true)));
    return json;
  }

  private void warnWhenFirstPartyRecommendationMissing(
      List<Map<String, Object>> configuredCatalogs, List<String> warnings) {
    boolean firstPartyConfigured =
        configuredCatalogs.stream()
            .anyMatch(catalog -> booleanValue(catalog.get("recommendedFirstPartyPresent")));
    if (firstPartyConfigured) {
      return;
    }
    try {
      boolean missingRecommended =
          appCatalogsApiHandler.listRecommendedCatalogs().stream()
              .filter(this::isFirstPartyCatalog)
              .anyMatch(recommended -> !booleanValue(recommended.get("configured")));
      if (missingRecommended) {
        warnings.add("Recommended first-party beta catalog is not configured.");
      }
    } catch (RuntimeException exception) {
      warnings.add("Recommended catalog state could not be inspected: " + safeReason(exception));
    }
  }

  private List<Map<String, Object>> appSummaries(List<String> warnings) {
    if (appsApiHandler == null) {
      warnings.add(APPS_UNAVAILABLE);
      return List.of();
    }
    List<Map<String, Object>> appServiceGrants = allAppServiceGrants(warnings);
    try {
      return appsApiHandler.list(false).stream()
          .map(app -> appSummary(app, appServiceGrants, warnings))
          .toList();
    } catch (RuntimeException exception) {
      warnings.add("Installed apps could not be inspected: " + safeReason(exception));
      return List.of();
    }
  }

  private Map<String, Object> appSummary(
      Map<String, Object> app, List<Map<String, Object>> grants, List<String> dashboardWarnings) {
    String appId = stringValue(app.get(APP_ID_FIELD));
    Map<String, Object> update = updateSummary(appId);
    Map<String, Object> appData = appDataSummary(appId);
    Map<String, Object> grantSummary = grantsForApp(appId, grants);
    ArrayList<String> warnings = new ArrayList<>();
    warnings.addAll(stringList(mapValue(app.get(QUOTA_FIELD)).get(WARNINGS_FIELD)));
    warnings.addAll(stringList(mapValue(app.get(SANDBOX_FIELD)).get(WARNINGS_FIELD)));
    warnings.addAll(stringList(appData.get(WARNINGS_FIELD)));
    if (booleanValue(mapValue(app.get(QUOTA_FIELD)).get("dataOverLimit"))
        || booleanValue(mapValue(app.get(QUOTA_FIELD)).get("cacheOverLimit"))) {
      warnings.add("apphost_quota_over_limit");
    }
    if (!booleanValue(mapValue(appData.get(QUOTA_FIELD)).get("dataQuotaAvailable"))
        && appData.containsKey(QUOTA_FIELD)) {
      warnings.add("app_data_quota_unavailable");
    }
    if (isUpdateBlocked(update)) {
      warnings.add("app_update_blocked");
    }
    if (!warnings.isEmpty() && appId != null) {
      dashboardWarnings.add("App " + appId + " needs operator review.");
    }

    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(17);
    json.put(APP_ID_FIELD, appId);
    json.put("name", app.get("name"));
    json.put("version", app.get("version"));
    json.put(STATE_FIELD, booleanValue(app.get(RUNNING_FIELD)) ? RUNNING_FIELD : "stopped");
    json.put(RUNNING_FIELD, app.get(RUNNING_FIELD));
    json.put("signedBundleStatus", "verified-by-apphost");
    json.put(REVIEW_TRUST_FIELD, updateReviewTrust(update));
    json.put(SANDBOX_FIELD, app.get(SANDBOX_FIELD));
    json.put("apiCompatibility", app.get("apiCompatibility"));
    json.put(UPDATE_FIELD, update);
    json.put("appData", appData);
    json.put(QUOTA_FIELD, app.get(QUOTA_FIELD));
    json.put("appServiceGrants", grantSummary);
    json.put(WARNINGS_FIELD, List.copyOf(new LinkedHashSet<>(warnings)));
    json.put(
        RECOVERY_ACTIONS_FIELD,
        appRecoveryActions(
            appId, booleanValue(app.get(RUNNING_FIELD)), update, appUpdateService != null));
    return json;
  }

  private Map<String, Object> updateSummary(String appId) {
    if (appId == null || appUpdateService == null) {
      return unavailableBlock("App-update lifecycle service is unavailable.");
    }
    try {
      return appUpdateService.summary(appId);
    } catch (RuntimeException exception) {
      return unavailableBlock("App-update state could not be inspected: " + safeReason(exception));
    }
  }

  private Map<String, Object> appDataSummary(String appId) {
    if (appId == null || appDataService == null) {
      return unavailableBlock("App-data service is unavailable.");
    }
    try {
      return appDataService.status(appId);
    } catch (RuntimeException exception) {
      return unavailableBlock(
          "App-data quota state could not be inspected: " + safeReason(exception));
    }
  }

  private List<Map<String, Object>> subscriptionSummaries(List<String> warnings) {
    if (contentSubscriptionService == null) {
      warnings.add("Content subscription service is unavailable.");
      return List.of();
    }
    try {
      return contentSubscriptionService.listAllForOperator().stream()
          .map(this::operatorSubscriptionSummary)
          .toList();
    } catch (RuntimeException exception) {
      warnings.add("Content subscriptions could not be inspected: " + safeReason(exception));
      return List.of();
    }
  }

  /**
   * Projects an app-facing content-subscription summary into the host/operator-safe dashboard
   * shape.
   *
   * <p>The app-facing summary includes the raw app-owned source URI and resolved runtime URI. The
   * operator dashboard and recovery-action responses must instead expose only a bounded display
   * placeholder plus a digest for correlation, while preserving status, timing, and recovery action
   * fields useful to the local Web Shell.
   *
   * @param subscription app-facing subscription summary returned by {@link
   *     ContentSubscriptionService}
   * @return redacted operator-safe subscription summary
   */
  public Map<String, Object> operatorSubscriptionSummary(Map<String, Object> subscription) {
    String appId = stringValue(subscription.get(APP_ID_FIELD));
    String subscriptionId = stringValue(subscription.get("subscriptionId"));
    String sourceUri = stringValue(subscription.get("sourceUri"));
    String operatorStatus = operatorSubscriptionStatus(subscription);
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(17);
    json.put(APP_ID_FIELD, appId);
    json.put("subscriptionId", subscriptionId);
    json.put(LABEL_FIELD, subscription.get(LABEL_FIELD));
    json.put(SOURCE_KIND_FIELD, subscription.get("normalizedSourceKind"));
    json.put("sourceDisplay", safeSourceDisplay(sourceUri, "crypta"));
    json.put("sourceDigest", digestOrNull(sourceUri));
    json.put(STATUS_FIELD, operatorStatus);
    json.put("rawStatus", subscription.get(STATUS_FIELD));
    json.put("lastSeenEdition", subscription.get("lastSeenEdition"));
    json.put("lastContentDigest", digestPrefix(stringValue(subscription.get("contentSha256"))));
    json.put(LAST_SUCCESS_AT_FIELD, subscription.get(LAST_SUCCESS_AT_FIELD));
    json.put("lastFailureAt", subscription.get("lastFailureAt"));
    json.put(NEXT_CHECK_AT_FIELD, subscription.get(NEXT_CHECK_AT_FIELD));
    json.put(FAILURE_COUNT_FIELD, subscription.get(FAILURE_COUNT_FIELD));
    json.put("lastErrorCode", subscription.get("lastErrorCode"));
    json.put(WARNINGS_FIELD, subscriptionWarnings(subscription, operatorStatus));
    json.put(RECOVERY_ACTIONS_FIELD, subscriptionRecoveryActions(appId, subscriptionId));
    return json;
  }

  private Map<String, Object> trustGraphSummary(List<String> warnings) {
    if (trustGraphApiHandler == null) {
      warnings.add("Trust Graph Preview service is unavailable.");
      return unavailableBlock("Trust Graph Preview service is unavailable.");
    }
    try {
      Map<String, Object> status = trustGraphApiHandler.status();
      LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(9);
      json.put(AVAILABLE_FIELD, status.get(AVAILABLE_FIELD));
      json.put("previewOnly", true);
      json.put("completeWot", false);
      json.put("service", status.get("service"));
      json.put("durable", status.get("durable"));
      json.put("storeType", status.get("storeType"));
      json.put("anchorCount", status.get("anchorCount"));
      json.put("statementCount", status.get("statementCount"));
      json.put("auditCount", status.get("auditCount"));
      json.put(
          WARNINGS_FIELD,
          List.of("Trust Graph Preview is local preview state only, not complete Web of Trust."));
      return json;
    } catch (RuntimeException exception) {
      warnings.add("Trust Graph Preview status could not be inspected: " + safeReason(exception));
      return unavailableBlock("Trust Graph Preview status could not be inspected.");
    }
  }

  private Map<String, Object> appServicesSummary(List<String> warnings) {
    if (appServiceCoordinator == null) {
      warnings.add("App-service coordinator is unavailable.");
      return unavailableBlock("App-service coordinator is unavailable.");
    }
    try {
      List<Map<String, Object>> grants =
          appServiceCoordinator.listGrants(PlatformApiPrincipal.hostOperator());
      List<Map<String, Object>> audit =
          appServiceCoordinator.audit(
              PlatformApiPrincipal.hostOperator(), Map.of("limit", List.of("10")));
      long pending = countStatus(grants, PENDING);
      long active = countStatus(grants, ACTIVE);
      long revoked = countStatus(grants, "revoked") + countStatus(grants, "inactive");
      LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(9);
      json.put(AVAILABLE_FIELD, true);
      json.put("serviceCount", appServiceCoordinator.listServices().size());
      json.put(
          "requestCount",
          appServiceCoordinator.listRequests(PlatformApiPrincipal.hostOperator()).size());
      json.put(PENDING_GRANT_COUNT_FIELD, pending);
      json.put("activeGrantCount", active);
      json.put("revokedOrInactiveGrantCount", revoked);
      json.put("recentAudit", audit);
      json.put("grantsUrl", "#apps");
      json.put(WARNINGS_FIELD, pending > 0 ? List.of("pending_app_service_grants") : List.of());
      return json;
    } catch (RuntimeException exception) {
      warnings.add("App-service grants could not be inspected: " + safeReason(exception));
      return unavailableBlock("App-service grant state could not be inspected.");
    }
  }

  private Map<String, Object> diagnosticsSummary(List<String> warnings) {
    if (diagnosticsApiHandler == null) {
      warnings.add(DIAGNOSTICS_UNAVAILABLE);
      return unavailableBlock(DIAGNOSTICS_UNAVAILABLE);
    }
    try {
      Map<String, Object> snapshot = diagnosticsApiHandler.snapshot();
      LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(5);
      json.put(AVAILABLE_FIELD, true);
      json.put(SECTION_COUNT_FIELD, snapshot.get(SECTION_COUNT_FIELD));
      json.put(
          "plainTextExportAvailable",
          snapshot.get("plainTextExport") instanceof String text && !text.isBlank());
      json.put(LEGACY_ADMIN_FIELD, snapshot.get(LEGACY_ADMIN_FIELD));
      json.put(WARNINGS_FIELD, List.of());
      return json;
    } catch (RuntimeException exception) {
      warnings.add("Diagnostics could not be inspected: " + safeReason(exception));
      return unavailableBlock("Diagnostics could not be inspected.");
    }
  }

  private Map<String, Object> legacyAdminSummary(
      Map<String, Object> diagnostics, List<String> warnings) {
    Map<String, Object> legacy = mapValue(diagnostics.get(LEGACY_ADMIN_FIELD));
    if (legacy.isEmpty()) {
      if (booleanValue(diagnostics.get(AVAILABLE_FIELD))) {
        warnings.add(LEGACY_ADMIN_USAGE_UNAVAILABLE);
      }
      return unavailableBlock(LEGACY_ADMIN_USAGE_UNAVAILABLE);
    }
    List<Map<String, Object>> surfaces = listOfMaps(legacy.get("surfaces"));
    long retained =
        surfaces.stream()
            .mapToLong(surface -> longValue(surface.get(RETAINED_OR_PENDING_RENDER_COUNT_FIELD)))
            .sum();
    long blocked =
        surfaces.stream()
            .mapToLong(surface -> longValue(surface.get(BLOCKED_MUTATING_REQUEST_COUNT_FIELD)))
            .sum();
    if (retained > 0L) {
      warnings.add("Retained or pending legacy admin surfaces are still being used.");
    }
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(5);
    json.put(AVAILABLE_FIELD, true);
    json.put("surfaceCount", surfaces.size());
    json.put(RETAINED_OR_PENDING_RENDER_COUNT_FIELD, retained);
    json.put(BLOCKED_MUTATING_REQUEST_COUNT_FIELD, blocked);
    json.put(
        "surfaces",
        surfaces.stream().map(OperatorBetaDashboardService::legacySurfaceSummary).toList());
    return json;
  }

  private Map<String, Object> summary(
      List<Map<String, Object>> catalogs,
      List<Map<String, Object>> apps,
      List<Map<String, Object>> subscriptions,
      Map<String, Object> appServices,
      int supportWarningCount) {
    long runningApps =
        apps.stream().filter(app -> RUNNING_FIELD.equals(app.get(STATE_FIELD))).count();
    long pendingUpdates =
        apps.stream()
            .filter(app -> hasAvailableUpdateCandidate(mapValue(app.get(UPDATE_FIELD))))
            .count();
    long stagedUpdates =
        apps.stream()
            .filter(
                app ->
                    booleanValue(
                        mapValue(mapValue(app.get(UPDATE_FIELD)).get(STAGED_FIELD))
                            .get(AVAILABLE_FIELD)))
            .count();
    long rollbackAvailable =
        apps.stream()
            .filter(
                app ->
                    booleanValue(
                        mapValue(mapValue(app.get(UPDATE_FIELD)).get("rollback"))
                            .get(AVAILABLE_FIELD)))
            .count();
    long staleSubscriptions =
        subscriptions.stream()
            .filter(subscription -> STALE.equals(subscription.get(STATUS_FIELD)))
            .count();
    long quotaWarnings =
        apps.stream().filter(OperatorBetaDashboardService::hasQuotaWarning).count();

    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(10);
    json.put("catalogCount", catalogs.size());
    json.put("installedAppCount", apps.size());
    json.put("runningAppCount", runningApps);
    json.put("pendingUpdateCount", pendingUpdates);
    json.put("stagedUpdateCount", stagedUpdates);
    json.put("rollbackAvailableCount", rollbackAvailable);
    json.put("staleSubscriptionCount", staleSubscriptions);
    json.put(PENDING_GRANT_COUNT_FIELD, longValue(appServices.get(PENDING_GRANT_COUNT_FIELD)));
    json.put("quotaWarningCount", quotaWarnings);
    json.put("supportWarningCount", supportWarningCount);
    return json;
  }

  private static boolean hasQuotaWarning(Map<String, Object> app) {
    Map<String, Object> appHostQuota = mapValue(app.get(QUOTA_FIELD));
    Map<String, Object> appData = mapValue(app.get("appData"));
    return !stringList(appHostQuota.get(WARNINGS_FIELD)).isEmpty()
        || booleanValue(appHostQuota.get("dataOverLimit"))
        || booleanValue(appHostQuota.get("cacheOverLimit"))
        || hasAppDataQuotaWarning(appData);
  }

  private static boolean hasAppDataQuotaWarning(Map<String, Object> appData) {
    Map<String, Object> appDataQuota = mapValue(appData.get(QUOTA_FIELD));
    return appData.containsKey(QUOTA_FIELD)
        && (!stringList(appData.get(WARNINGS_FIELD)).isEmpty()
            || !booleanValue(appDataQuota.get("dataQuotaAvailable")));
  }

  private static String overallStatus(Map<String, Object> summary, List<String> warnings) {
    if (!warnings.isEmpty()
        && warnings.stream().anyMatch(warning -> warning.contains(UNAVAILABLE))) {
      return UNAVAILABLE;
    }
    if (longValue(summary.get("quotaWarningCount")) > 0L
        || longValue(summary.get("staleSubscriptionCount")) > 0L) {
      return ACTION_REQUIRED;
    }
    if (!warnings.isEmpty()
        || longValue(summary.get("pendingUpdateCount")) > 0L
        || longValue(summary.get("stagedUpdateCount")) > 0L
        || longValue(summary.get(PENDING_GRANT_COUNT_FIELD)) > 0L) {
      return WARNING;
    }
    return HEALTHY;
  }

  private List<Map<String, Object>> topLevelRecoveryActions(
      List<Map<String, Object>> catalogs,
      List<Map<String, Object>> apps,
      List<Map<String, Object>> subscriptions) {
    ArrayList<Map<String, Object>> actions = new ArrayList<>();
    catalogs.stream()
        .flatMap(catalog -> listOfMaps(catalog.get(RECOVERY_ACTIONS_FIELD)).stream())
        .limit(6)
        .forEach(actions::add);
    apps.stream()
        .flatMap(app -> listOfMaps(app.get(RECOVERY_ACTIONS_FIELD)).stream())
        .limit(12)
        .forEach(actions::add);
    subscriptions.stream()
        .flatMap(subscription -> listOfMaps(subscription.get(RECOVERY_ACTIONS_FIELD)).stream())
        .limit(9)
        .forEach(actions::add);
    actions.add(
        action(
            "export-support-bundle",
            "Export support bundle",
            "GET",
            "operator/support-bundle",
            true));
    return List.copyOf(actions);
  }

  private Map<String, Object> supportDiagnostics() {
    if (diagnosticsApiHandler == null) {
      return unavailableBlock(DIAGNOSTICS_UNAVAILABLE);
    }
    try {
      Map<String, Object> snapshot = diagnosticsApiHandler.snapshot();
      LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(3);
      json.put(SECTION_COUNT_FIELD, snapshot.get(SECTION_COUNT_FIELD));
      json.put("sections", snapshot.get("sections"));
      json.put(LEGACY_ADMIN_FIELD, snapshot.get(LEGACY_ADMIN_FIELD));
      return json;
    } catch (RuntimeException exception) {
      return unavailableBlock("Diagnostics could not be collected: " + safeReason(exception));
    }
  }

  private List<Map<String, Object>> supportAppServiceAudit() {
    if (appServiceCoordinator == null) {
      return List.of();
    }
    try {
      return appServiceCoordinator.audit(
          PlatformApiPrincipal.hostOperator(), Map.of("limit", List.of("25")));
    } catch (RuntimeException _) {
      return List.of();
    }
  }

  private static List<String> supportWarnings(Map<String, Object> redaction) {
    return List.of(
        "Support bundles are redacted but should be reviewed by the operator before sharing.",
        "Trust Graph Preview entries describe local preview state only, not complete Web of Trust.",
        "Redaction status: " + redaction.get(STATUS_FIELD));
  }

  private List<Map<String, Object>> allAppServiceGrants(List<String> warnings) {
    if (appServiceCoordinator == null) {
      return List.of();
    }
    try {
      return appServiceCoordinator.listGrants(PlatformApiPrincipal.hostOperator());
    } catch (RuntimeException exception) {
      warnings.add("App-service grants could not be inspected: " + safeReason(exception));
      return List.of();
    }
  }

  private static Map<String, Object> grantsForApp(String appId, List<Map<String, Object>> grants) {
    if (appId == null) {
      return Map.of(PENDING, 0, ACTIVE, 0, "revokedOrInactive", 0);
    }
    List<Map<String, Object>> matching =
        grants.stream()
            .filter(
                grant ->
                    appId.equals(grant.get("consumerAppId"))
                        || appId.equals(grant.get("providerAppId")))
            .toList();
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(4);
    json.put(PENDING, countStatus(matching, PENDING));
    json.put(ACTIVE, countStatus(matching, ACTIVE));
    json.put(
        "revokedOrInactive", countStatus(matching, "revoked") + countStatus(matching, "inactive"));
    json.put("total", matching.size());
    return json;
  }

  private static List<Map<String, Object>> appRecoveryActions(
      String appId, boolean running, Map<String, Object> update, boolean updateRoutesAvailable) {
    if (appId == null) {
      return List.of();
    }
    String encodedAppId = encodePathSegment(appId);
    ArrayList<Map<String, Object>> actions = new ArrayList<>();
    actions.add(
        action(
            running ? "stop-app" : "start-app",
            running ? "Stop app" : "Start app",
            "POST",
            APPS_ROUTE_PREFIX + encodedAppId + "/" + (running ? "stop" : "start"),
            true));
    actions.add(
        action(
            "check-app-update",
            "Check update",
            "POST",
            APPS_ROUTE_PREFIX + encodedAppId + "/updates/check",
            updateRoutesAvailable));
    actions.add(
        action(
            "stage-app-update",
            "Stage update",
            "POST",
            APPS_ROUTE_PREFIX + encodedAppId + "/updates/stage",
            updateRoutesAvailable && stageUpdateActionAvailable(update)));
    actions.add(
        action(
            "apply-app-update",
            "Apply staged update",
            "POST",
            APPS_ROUTE_PREFIX + encodedAppId + "/updates/apply",
            updateRoutesAvailable
                && !running
                && booleanValue(mapValue(update.get(STAGED_FIELD)).get(AVAILABLE_FIELD))));
    actions.add(
        action(
            "rollback-app",
            "Rollback app bundle",
            "POST",
            APPS_ROUTE_PREFIX + encodedAppId + "/updates/rollback",
            updateRoutesAvailable
                && !running
                && booleanValue(mapValue(update.get("rollback")).get(AVAILABLE_FIELD))));
    actions.add(
        action(
            "open-app-logs",
            "Open app logs",
            "GET",
            APPS_ROUTE_PREFIX + encodedAppId + "/logs",
            true));
    actions.add(
        action(
            "preserve-data-uninstall",
            "Uninstall preserving data",
            "DELETE",
            APPS_ROUTE_PREFIX + encodedAppId + "?preserveData=true",
            true));
    return List.copyOf(actions);
  }

  private static List<Map<String, Object>> subscriptionRecoveryActions(
      String appId, String subscriptionId) {
    if (appId == null || subscriptionId == null) {
      return List.of();
    }
    String base =
        "operator/subscriptions/"
            + encodePathSegment(appId)
            + "/"
            + encodePathSegment(subscriptionId);
    return List.of(
        action("refresh-subscription", "Refresh subscription", "POST", base + "/refresh", true),
        action("pause-subscription", "Pause subscription", "POST", base + "/pause", true),
        action("resume-subscription", "Resume subscription", "POST", base + "/resume", true));
  }

  private static Map<String, Object> action(
      String id, String label, String method, String path, boolean available) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(6);
    json.put("id", id);
    json.put(LABEL_FIELD, label);
    json.put("method", method);
    json.put("path", path);
    json.put(AVAILABLE_FIELD, available);
    json.put("requiresFormPassword", "POST".equals(method) || "DELETE".equals(method));
    return json;
  }

  private static List<String> subscriptionWarnings(
      Map<String, Object> subscription, String operatorStatus) {
    ArrayList<String> warnings = new ArrayList<>();
    if (BACKOFF.equals(operatorStatus)) {
      warnings.add("subscription_backing_off");
    }
    if (STALE.equals(operatorStatus)) {
      warnings.add("subscription_stale");
    }
    if ("never-fetched".equals(operatorStatus)) {
      warnings.add("subscription_never_fetched");
    }
    if (longValue(subscription.get(FAILURE_COUNT_FIELD)) > 0L) {
      warnings.add("subscription_failures_present");
    }
    return List.copyOf(new LinkedHashSet<>(warnings));
  }

  private String operatorSubscriptionStatus(Map<String, Object> subscription) {
    if (booleanValue(subscription.get("paused"))) {
      return "paused";
    }
    String raw = stringValue(subscription.get(STATUS_FIELD));
    if (BACKOFF.equals(raw) || "queue_pressure".equals(raw) || "runtime_unavailable".equals(raw)) {
      return BACKOFF;
    }
    if (subscription.get(LAST_SUCCESS_AT_FIELD) == null) {
      return "never-fetched";
    }
    if (isStale(subscription.get(NEXT_CHECK_AT_FIELD))) {
      return STALE;
    }
    return raw == null ? ACTIVE : raw;
  }

  private boolean isStale(Object timestamp) {
    String text = stringValue(timestamp);
    if (text == null) {
      return false;
    }
    try {
      Instant nextCheck = Instant.parse(text);
      return nextCheck.isBefore(clock.instant().minusSeconds(86_400L));
    } catch (DateTimeParseException _) {
      return false;
    }
  }

  private static Map<String, Object> updateReviewTrust(Map<String, Object> update) {
    Map<String, Object> stagedReview =
        mapValue(mapValue(update.get(STAGED_FIELD)).get(REVIEW_TRUST_FIELD));
    if (!stagedReview.isEmpty()) {
      return stagedReview;
    }
    return mapValue(mapValue(update.get(CANDIDATE_FIELD)).get(REVIEW_TRUST_FIELD));
  }

  private static boolean isUpdateBlocked(Map<String, Object> update) {
    Map<String, Object> reviewTrust = updateReviewTrust(update);
    return booleanValue(reviewTrust.get("blocksUpdate"))
        || booleanValue(reviewTrust.get("blocksPolicyApply"));
  }

  private static boolean hasAvailableUpdateCandidate(Map<String, Object> update) {
    Map<String, Object> candidate = mapValue(update.get(CANDIDATE_FIELD));
    return AVAILABLE_STATUS.equals(candidate.get(STATUS_FIELD))
        || booleanValue(candidate.get("autoStageAllowed"));
  }

  private static boolean stageUpdateActionAvailable(Map<String, Object> update) {
    Map<String, Object> candidate = mapValue(update.get(CANDIDATE_FIELD));
    Map<String, Object> reviewTrust = mapValue(candidate.get(REVIEW_TRUST_FIELD));
    return hasAvailableUpdateCandidate(update)
        && !booleanValue(reviewTrust.get("blocksUpdate"))
        && !booleanValue(reviewTrust.get("requiresAcknowledgement"));
  }

  private static Map<String, Object> legacySurfaceSummary(Map<String, Object> surface) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(8);
    json.put("id", surface.get("id"));
    json.put("title", surface.get("title"));
    json.put(STATE_FIELD, surface.get(STATE_FIELD));
    json.put("replacementUrl", surface.get("replacementUrl"));
    json.put("removalWave", surface.get("removalWave"));
    json.put("count", surface.get("count"));
    json.put(
        BLOCKED_MUTATING_REQUEST_COUNT_FIELD, surface.get(BLOCKED_MUTATING_REQUEST_COUNT_FIELD));
    json.put(
        RETAINED_OR_PENDING_RENDER_COUNT_FIELD,
        surface.get(RETAINED_OR_PENDING_RENDER_COUNT_FIELD));
    return json;
  }

  private static Map<String, Object> legacyAdminFromDiagnostics(Map<String, Object> diagnostics) {
    return mapValue(diagnostics.get(LEGACY_ADMIN_FIELD));
  }

  private static Map<String, Object> unavailableBlock(String message) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(3);
    json.put(AVAILABLE_FIELD, false);
    json.put(STATUS_FIELD, UNAVAILABLE);
    json.put(WARNINGS_FIELD, List.of(message));
    return json;
  }

  private static String catalogSourceKind(Map<String, Object> catalog, String source) {
    String explicit = stringValue(catalog.get(SOURCE_KIND_FIELD));
    if (explicit != null && !explicit.isBlank()) {
      return normalizedSourceKind(explicit);
    }
    return normalizedSourceKind(source);
  }

  private static String normalizedSourceKind(String value) {
    if (value == null || value.isBlank()) {
      return UNKNOWN;
    }
    String lower = value.toLowerCase(Locale.ROOT);
    if (lower.contains(FIRST_PARTY)) {
      return FIRST_PARTY;
    }
    if (lower.startsWith("crypta:") || lower.startsWith("usk@") || lower.contains(LIVE_USK)) {
      return LIVE_USK;
    }
    if (lower.startsWith("http")) {
      return "manual";
    }
    if (lower.startsWith("file")) {
      return "manual";
    }
    return lower;
  }

  private boolean isFirstPartyCatalog(Map<String, Object> catalog) {
    return containsFirstParty(catalog.get(CATALOG_ID_FIELD))
        || containsFirstParty(catalog.get("name"))
        || containsFirstParty(catalog.get("channel"))
        || containsFirstParty(catalog.get(SOURCE_KIND_FIELD));
  }

  private static boolean containsFirstParty(Object value) {
    return value instanceof String text && text.toLowerCase(Locale.ROOT).contains(FIRST_PARTY);
  }

  private static String safeSourceDisplay(String source, String sourceKind) {
    if (source == null || source.isBlank()) {
      return UNAVAILABLE;
    }
    if (isFileSource(source, sourceKind)) {
      return "file:<redacted>";
    }
    if ("crypta".equals(sourceKind)
        || LIVE_USK.equals(sourceKind)
        || CONTENT_URI.matcher(source).matches()) {
      return "crypta:<redacted-content-uri>";
    }
    try {
      URI uri = new URI(source);
      if (uri.getScheme() == null) {
        return "source:<redacted>";
      }
      String scheme = uri.getScheme().toLowerCase(Locale.ROOT);
      if ("http".equals(scheme) || "https".equals(scheme)) {
        return scheme + ":<redacted>";
      }
      if (uri.getQuery() == null) {
        return uri.toString();
      }
      return new URI(uri.getScheme(), null, uri.getHost(), uri.getPort(), uri.getPath(), null, null)
          .toString();
    } catch (URISyntaxException _) {
      return "source:<redacted>";
    }
  }

  private static boolean isFileSource(String source, String sourceKind) {
    return "file".equalsIgnoreCase(sourceKind)
        || source.regionMatches(true, 0, "file:", 0, "file:".length())
        || source.startsWith("/");
  }

  private static String digestOrNull(String value) {
    if (value == null || value.isBlank()) {
      return null;
    }
    try {
      return HEX.formatHex(
          MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
    } catch (NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable", exception);
    }
  }

  private static String digestPrefix(String digest) {
    if (digest == null || digest.length() < 16) {
      return digest;
    }
    return digest.substring(0, 16);
  }

  private static String safeReason(RuntimeException exception) {
    if (exception instanceof PlatformApiException platformApiException) {
      return platformApiException.errorCode();
    }
    return exception.getClass().getSimpleName();
  }

  private static long countStatus(List<Map<String, Object>> items, String status) {
    return items.stream().filter(item -> status.equals(item.get(STATUS_FIELD))).count();
  }

  private static String encodePathSegment(String value) {
    return java.net.URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
  }

  private static String stringValue(Object value) {
    return value instanceof String text && !text.isBlank() ? text : null;
  }

  private static boolean booleanValue(Object value) {
    return Boolean.TRUE.equals(value);
  }

  private static long longValue(Object value) {
    if (value instanceof Number number) {
      return number.longValue();
    }
    return 0L;
  }

  private static List<String> stringList(Object value) {
    if (!(value instanceof List<?> list)) {
      return List.of();
    }
    return list.stream().filter(String.class::isInstance).map(String.class::cast).toList();
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> mapValue(Object value) {
    if (value instanceof Map<?, ?> map) {
      return (Map<String, Object>) map;
    }
    return Map.of();
  }

  @SuppressWarnings("unchecked")
  private static List<Map<String, Object>> listOfMaps(Object value) {
    if (!(value instanceof List<?> list)) {
      return List.of();
    }
    return list.stream()
        .filter(Map.class::isInstance)
        .map(item -> (Map<String, Object>) item)
        .toList();
  }
}

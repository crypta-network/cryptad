package network.crypta.platform.api.operator;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;
import network.crypta.fs.AppEnv;
import network.crypta.platform.api.PlatformApiContract;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.api.PlatformApiPrincipal;
import network.crypta.platform.api.appcatalogs.AppCatalogsApiHandler;
import network.crypta.platform.api.appdata.AppDataService;
import network.crypta.platform.api.apps.AppsApiHandler;
import network.crypta.platform.api.appservices.AppServiceCoordinator;
import network.crypta.platform.api.appupdates.AppUpdateService;
import network.crypta.platform.api.content.subscriptions.ContentSubscriptionService;
import network.crypta.platform.api.diagnostics.DiagnosticsApiHandler;
import network.crypta.platform.api.json.PlatformApiJsonWriter;
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
 * installed apps, update state, subscription backoff, local Trust Graph Local RC status,
 * app-service grants, and legacy-admin usage counters, then attaches safe recovery actions for the
 * UI to render. Source URIs, raw fetched content, local file paths, and diagnostic bodies are
 * either omitted, redacted, or replaced by bounded digests. Instances are lightweight and hold
 * references to long-lived services supplied by router composition; they do not start schedulers or
 * persist dashboard state.
 */
public final class OperatorBetaDashboardService {
  private static final Pattern CONTENT_URI =
      Pattern.compile("(?i)^(?:crypta:)?(?:CHK|SSK|USK|KSK)@.*");
  private static final String ACTION_REQUIRED = "action_required";
  private static final String WARNING = "warning";
  private static final String UNAVAILABLE = "unavailable";
  private static final String HEALTHY = "healthy";
  private static final String ACTIVE = "active";
  private static final String ACTIVE_GRANT_COUNT_FIELD = "activeGrantCount";
  private static final String BACKOFF = "backoff";
  private static final String APP_DATA_FIELD = "appData";
  private static final String APP_SERVICE_GRANTS_FIELD = "appServiceGrants";
  private static final String ANCHOR_COUNT_FIELD = "anchorCount";
  private static final String AUDIT_COUNT_FIELD = "auditCount";
  private static final String BOUNDED_COUNT_FIELD = "boundedCount";
  private static final String CANDIDATE_FIELD = "candidate";
  private static final String CATALOG_ID_FIELD = "catalogId";
  private static final String CONSENT_FIELD = "consent";
  private static final String DIAGNOSTICS_UNAVAILABLE = "Diagnostics service is unavailable.";
  private static final String DIAGNOSTICS_FIELD = "diagnostics";
  private static final String DIGEST_FIELD = "digest";
  private static final String FIRST_PARTY = "first-party";
  private static final String LAST_ERROR_CODE_FIELD = "lastErrorCode";
  private static final String LAST_SAFE_STATUS_MESSAGE_FIELD = "lastSafeStatusMessage";
  private static final String LEGACY_FALLBACK_AVAILABLE_FIELD = "legacyFallbackAvailable";
  private static final String LIVE_USK = "live-usk";
  private static final String METADATA_ONLY_STATUS = "metadata_only";
  private static final String PENDING = "pending";
  private static final String PAUSED_STATUS = "paused";
  private static final String PLAIN_TEXT_EXPORT_AVAILABLE_FIELD = "plainTextExportAvailable";
  private static final String RECOMMENDED_FIRST_PARTY_CATALOG_MISSING =
      "Recommended first-party beta catalog is not configured.";
  private static final String RECOVERY_ACTION_IDS_FIELD = "recoveryActionIds";
  private static final String REVOKED_OR_INACTIVE_GRANT_COUNT_FIELD = "revokedOrInactiveGrantCount";
  private static final String SAFE_IDS_FIELD = "safeIds";
  private static final String SECTIONS_FIELD = "sections";
  private static final String STAGED_FIELD = "staged";
  private static final String STALE = "stale";
  private static final String STATEMENT_COUNT_FIELD = "statementCount";
  private static final String LEGACY_ADMIN_USAGE_UNAVAILABLE =
      "Legacy-admin usage counters are unavailable.";
  private static final String UNKNOWN = "unknown";
  private static final String STATUS_FIELD = "status";
  private static final String PASS = "pass";
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
  private static final String PENDING_UPDATE_COUNT_FIELD = "pendingUpdateCount";
  private static final String QUOTA_FIELD = "quota";
  private static final String QUOTA_WARNING_COUNT_FIELD = "quotaWarningCount";
  private static final String RECOVERY_ACTIONS_FIELD = "recoveryActions";
  private static final String RETAINED_OR_PENDING_RENDER_COUNT_FIELD =
      "retainedOrPendingRenderCount";
  private static final String REVIEW_TRUST_FIELD = "reviewTrust";
  private static final String SECURITY_DECISION_FIELD = "securityDecision";
  private static final String BLOCKS_UPDATE_FIELD = "blocksUpdate";
  private static final String REQUIRES_ACKNOWLEDGEMENT_FIELD = "requiresAcknowledgement";
  private static final String RUNNING_FIELD = "running";
  private static final String SANDBOX_FIELD = "sandbox";
  private static final String SECTION_COUNT_FIELD = "sectionCount";
  private static final String SOURCE_KIND_FIELD = "sourceKind";
  private static final String STAGED_UPDATE_COUNT_FIELD = "stagedUpdateCount";
  private static final String SUBSCRIPTION_ID_FIELD = "subscriptionId";
  private static final String SUBSCRIPTIONS_FIELD = "subscriptions";
  private static final String SUPPORT_DIGEST_FIELD = "supportDigest";
  private static final String STATE_FIELD = "state";
  private static final String SURFACES_FIELD = "surfaces";
  private static final String TRUST_GRAPH_FIELD = "trustGraph";
  private static final String UPDATE_FIELD = "update";
  private static final String VERSION_FIELD = "version";
  private static final String CATALOGS_UNAVAILABLE = "Catalog service is unavailable.";
  private static final String APPS_UNAVAILABLE = "AppHost service is unavailable.";
  private static final String APP_UPDATE_UNAVAILABLE =
      "App-update lifecycle service is unavailable.";
  private static final String CONTENT_SUBSCRIPTIONS_UNAVAILABLE =
      "Content subscription service is unavailable.";
  private static final int SUPPORT_BUNDLE_SCHEMA_VERSION = 2;
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
   * @param trustGraphApiHandler local Trust Graph Local RC handler, or {@code null} when
   *     unavailable
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
    Map<String, Object> securityResponse = securityResponseSummary(warnings);
    Map<String, Object> summary =
        summary(catalogs, apps, subscriptions, appServices, warnings.size());

    LinkedHashMap<String, Object> dashboard = LinkedHashMap.newLinkedHashMap(13);
    dashboard.put(GENERATED_AT_FIELD, clock.millis());
    dashboard.put("overallStatus", overallStatus(summary, warnings));
    dashboard.put("summary", summary);
    dashboard.put("catalogs", catalogs);
    dashboard.put("apps", apps);
    dashboard.put(SUBSCRIPTIONS_FIELD, subscriptions);
    dashboard.put(TRUST_GRAPH_FIELD, trustGraph);
    dashboard.put("appServices", appServices);
    dashboard.put("securityResponse", securityResponse);
    dashboard.put(LEGACY_ADMIN_FIELD, legacyAdmin);
    dashboard.put(DIAGNOSTICS_FIELD, diagnostics);
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
    Map<String, Object> sections =
        supportSections(dashboard, diagnostics, recentAudit, legacyAdmin);

    OperatorSupportRedactor.RedactionResult redactedDashboard =
        OperatorSupportRedactor.redact(dashboard);
    OperatorSupportRedactor.RedactionResult redactedDiagnostics =
        OperatorSupportRedactor.redact(diagnostics);
    OperatorSupportRedactor.RedactionResult redactedAudit =
        OperatorSupportRedactor.redact(recentAudit);
    OperatorSupportRedactor.RedactionResult redactedLegacyAdmin =
        OperatorSupportRedactor.redact(legacyAdmin);
    OperatorSupportRedactor.RedactionResult redactedSections =
        OperatorSupportRedactor.redact(sections);

    LinkedHashSet<String> omittedFields = new LinkedHashSet<>();
    omittedFields.addAll(redactedDashboard.omittedFields());
    omittedFields.addAll(redactedDiagnostics.omittedFields());
    omittedFields.addAll(redactedAudit.omittedFields());
    omittedFields.addAll(redactedLegacyAdmin.omittedFields());
    omittedFields.addAll(redactedSections.omittedFields());

    LinkedHashMap<String, Object> redaction = LinkedHashMap.newLinkedHashMap(8);
    redaction.put(STATUS_FIELD, PASS);
    redaction.put("patternsChecked", OperatorSupportRedactor.patternsChecked());
    redaction.put("omittedFieldNames", List.copyOf(omittedFields));
    redaction.put("omittedFields", List.copyOf(omittedFields));
    redaction.put("omittedFieldCount", omittedFields.size());
    redaction.put("redactionFindings", List.of());
    redaction.put("rawSensitiveMaterialExcluded", true);
    redaction.put("localOnlyUntilExported", true);

    LinkedHashMap<String, Object> bundle = LinkedHashMap.newLinkedHashMap(18);
    bundle.put("kind", "cryptad-operator-support-bundle");
    bundle.put(GENERATED_AT_FIELD, clock.millis());
    bundle.put("generatedAt", boundedGeneratedAt());
    bundle.put("createdAt", boundedGeneratedAt());
    bundle.put("schemaVersion", SUPPORT_BUNDLE_SCHEMA_VERSION);
    bundle.put("nodeSummary", nodeSummary());
    bundle.put("releaseSummary", releaseSummary());
    bundle.put("privacy", privacyMetadata());
    bundle.put("redaction", redaction);
    bundle.put(SECTIONS_FIELD, redactedSections.value());
    bundle.put("dashboard", redactedDashboard.value());
    bundle.put(DIAGNOSTICS_FIELD, redactedDiagnostics.value());
    bundle.put("recentAppServiceAudit", redactedAudit.value());
    bundle.put(LEGACY_ADMIN_FIELD, redactedLegacyAdmin.value());
    bundle.put(WARNINGS_FIELD, supportWarnings(redaction));
    bundle.put(SUPPORT_DIGEST_FIELD, supportDigestForPayload(bundle));
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
        warnings.add(RECOMMENDED_FIRST_PARTY_CATALOG_MISSING);
      }
    } catch (RuntimeException exception) {
      warnings.add("Recommended catalog state could not be inspected: " + safeReason(exception));
    }
  }

  private Map<String, Object> securityResponseSummary(List<String> warnings) {
    if (appCatalogsApiHandler == null) {
      return unavailableBlock(CATALOGS_UNAVAILABLE);
    }
    try {
      Map<String, Object> securityResponse = appCatalogsApiHandler.securityResponseSummary();
      String status = stringValue(securityResponse.get(STATUS_FIELD));
      if ("denylist_active".equals(status)) {
        warnings.add("Catalog security response has active denylist entries.");
      } else if ("advisory_active".equals(status)) {
        warnings.add("Catalog security response has active advisories.");
      } else if ("reviewer_revocation_active".equals(status)) {
        warnings.add("Catalog security response has reviewer revocations.");
      }
      return securityResponse;
    } catch (RuntimeException exception) {
      warnings.add("Catalog security response could not be inspected: " + safeReason(exception));
      return unavailableBlock(CATALOGS_UNAVAILABLE);
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
    warnings.addAll(stringList(update.get(WARNINGS_FIELD)));
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
    if (isSecurityUpdateBlocked(update)) {
      warnings.add("app_update_security_blocked");
    } else if (isSecurityAcknowledgementRequired(update)) {
      warnings.add("app_update_security_advisory");
    }
    if (isUnavailable(update) && appId != null) {
      dashboardWarnings.add("App " + appId + " update state is unavailable.");
    }
    if (!warnings.isEmpty() && appId != null) {
      dashboardWarnings.add("App " + appId + " needs operator review.");
    }

    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(17);
    json.put(APP_ID_FIELD, appId);
    json.put("name", app.get("name"));
    json.put(VERSION_FIELD, app.get(VERSION_FIELD));
    json.put(STATE_FIELD, booleanValue(app.get(RUNNING_FIELD)) ? RUNNING_FIELD : "stopped");
    json.put(RUNNING_FIELD, app.get(RUNNING_FIELD));
    json.put("signedBundleStatus", "verified-by-apphost");
    json.put(REVIEW_TRUST_FIELD, updateReviewTrust(update));
    json.put(SANDBOX_FIELD, app.get(SANDBOX_FIELD));
    json.put("apiCompatibility", app.get("apiCompatibility"));
    json.put(UPDATE_FIELD, update);
    json.put(APP_DATA_FIELD, appData);
    json.put(QUOTA_FIELD, app.get(QUOTA_FIELD));
    json.put(APP_SERVICE_GRANTS_FIELD, grantSummary);
    json.put(WARNINGS_FIELD, List.copyOf(new LinkedHashSet<>(warnings)));
    json.put(
        RECOVERY_ACTIONS_FIELD,
        appRecoveryActions(
            appId, booleanValue(app.get(RUNNING_FIELD)), update, appUpdateService != null));
    return json;
  }

  private Map<String, Object> updateSummary(String appId) {
    if (appId == null || appUpdateService == null) {
      return unavailableBlock(APP_UPDATE_UNAVAILABLE);
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
      warnings.add(CONTENT_SUBSCRIPTIONS_UNAVAILABLE);
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
    String subscriptionId = stringValue(subscription.get(SUBSCRIPTION_ID_FIELD));
    String sourceUri = stringValue(subscription.get("sourceUri"));
    String operatorStatus = operatorSubscriptionStatus(subscription);
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(17);
    json.put(APP_ID_FIELD, appId);
    json.put(SUBSCRIPTION_ID_FIELD, subscriptionId);
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
    json.put(LAST_ERROR_CODE_FIELD, subscription.get(LAST_ERROR_CODE_FIELD));
    json.put(WARNINGS_FIELD, subscriptionWarnings(subscription, operatorStatus));
    json.put(RECOVERY_ACTIONS_FIELD, subscriptionRecoveryActions(appId, subscriptionId));
    return json;
  }

  private Map<String, Object> trustGraphSummary(List<String> warnings) {
    if (trustGraphApiHandler == null) {
      warnings.add("Trust Graph Local RC service is unavailable.");
      return unavailableBlock("Trust Graph Local RC service is unavailable.");
    }
    try {
      Map<String, Object> status = trustGraphApiHandler.status();
      LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(16);
      json.put(AVAILABLE_FIELD, status.get(AVAILABLE_FIELD));
      json.put("mode", status.get("mode"));
      json.put("previewOnly", true);
      json.put("completeWot", false);
      json.put("service", status.get("service"));
      json.put("scoring", status.get("scoring"));
      json.put("scope", status.get("scope"));
      json.put("statementLifecycle", status.get("statementLifecycle"));
      json.put("limits", status.get("limits"));
      json.put("durable", status.get("durable"));
      json.put("storeType", status.get("storeType"));
      json.put(ANCHOR_COUNT_FIELD, status.get(ANCHOR_COUNT_FIELD));
      json.put(STATEMENT_COUNT_FIELD, status.get(STATEMENT_COUNT_FIELD));
      json.put(AUDIT_COUNT_FIELD, status.get(AUDIT_COUNT_FIELD));
      json.put(
          WARNINGS_FIELD,
          List.of(
              "Trust Graph Local RC is local operator-curated state only, not global truth, "
                  + "moderation, blocking, routing policy, or legacy Web of Trust compatibility."));
      return json;
    } catch (RuntimeException exception) {
      warnings.add("Trust Graph Local RC status could not be inspected: " + safeReason(exception));
      return unavailableBlock("Trust Graph Local RC status could not be inspected.");
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
      json.put(ACTIVE_GRANT_COUNT_FIELD, active);
      json.put(REVOKED_OR_INACTIVE_GRANT_COUNT_FIELD, revoked);
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
          PLAIN_TEXT_EXPORT_AVAILABLE_FIELD,
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
    List<Map<String, Object>> surfaces = listOfMaps(legacy.get(SURFACES_FIELD));
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
        SURFACES_FIELD,
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
    json.put(PENDING_UPDATE_COUNT_FIELD, pendingUpdates);
    json.put(STAGED_UPDATE_COUNT_FIELD, stagedUpdates);
    json.put("rollbackAvailableCount", rollbackAvailable);
    json.put("staleSubscriptionCount", staleSubscriptions);
    json.put(PENDING_GRANT_COUNT_FIELD, longValue(appServices.get(PENDING_GRANT_COUNT_FIELD)));
    json.put(QUOTA_WARNING_COUNT_FIELD, quotaWarnings);
    json.put("supportWarningCount", supportWarningCount);
    return json;
  }

  private static boolean hasQuotaWarning(Map<String, Object> app) {
    Map<String, Object> appHostQuota = mapValue(app.get(QUOTA_FIELD));
    Map<String, Object> appData = mapValue(app.get(APP_DATA_FIELD));
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
    if (longValue(summary.get(QUOTA_WARNING_COUNT_FIELD)) > 0L
        || longValue(summary.get("staleSubscriptionCount")) > 0L) {
      return ACTION_REQUIRED;
    }
    if (!warnings.isEmpty()
        || longValue(summary.get(PENDING_UPDATE_COUNT_FIELD)) > 0L
        || longValue(summary.get(STAGED_UPDATE_COUNT_FIELD)) > 0L
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
      return diagnosticsApiHandler.supportSummary();
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
        "This support bundle is generated locally and is not uploaded automatically.",
        "Support bundles are redacted but should be reviewed by the operator before sharing.",
        "Raw content, raw app data, private insert URIs, tokens, identity material, and local paths"
            + " are excluded from the default support bundle.",
        "Trust Graph Local RC entries describe local operator-curated state only, not global truth,"
            + " moderation, blocking, routing policy, or legacy Web of Trust compatibility.",
        "Redaction status: " + redaction.get(STATUS_FIELD));
  }

  private String boundedGeneratedAt() {
    return clock.instant().truncatedTo(ChronoUnit.SECONDS).toString();
  }

  private static Map<String, Object> nodeSummary() {
    AppEnv appEnv = new AppEnv();
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(5);
    json.put(VERSION_FIELD, UNKNOWN);
    json.put("build", UNKNOWN);
    json.put("javaVersion", System.getProperty("java.version", UNKNOWN));
    json.put("operatingSystem", unknownIfBlank(appEnv.osNameRaw()));
    json.put("architecture", appEnv.arch());
    return json;
  }

  private static Map<String, Object> releaseSummary() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(4);
    json.put("releaseId", UNKNOWN);
    json.put("channel", UNKNOWN);
    json.put("platformApiVersion", PlatformApiContract.CURRENT_API_VERSION);
    json.put("platformApiContractVersion", PlatformApiContract.CURRENT_CONTRACT_VERSION);
    return json;
  }

  private static Map<String, Object> privacyMetadata() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(7);
    json.put("includesRawContent", false);
    json.put("includesRawAppData", false);
    json.put("includesPrivateInsertUris", false);
    json.put("includesTokens", false);
    json.put("includesIdentityMaterial", false);
    json.put("includesLocalPaths", false);
    json.put("localOnlyUntilExported", true);
    return json;
  }

  /**
   * Computes the support-bundle digest for an already assembled payload.
   *
   * <p>The digest input is a shallow copy of the supplied payload with any existing {@code
   * supportDigest} field removed. Route layers that append export metadata such as recovery context
   * must call this after the final export shape is assembled so the advertised digest identifies
   * the JSON operators actually download or copy.
   *
   * @param supportBundlePayload JSON-compatible support-bundle payload
   * @return JSON-compatible digest metadata
   */
  public static Map<String, Object> supportDigestForPayload(
      Map<String, Object> supportBundlePayload) {
    LinkedHashMap<String, Object> digestInput =
        LinkedHashMap.newLinkedHashMap(supportBundlePayload.size());
    digestInput.putAll(Objects.requireNonNull(supportBundlePayload, "supportBundlePayload"));
    digestInput.remove(SUPPORT_DIGEST_FIELD);
    String json = PlatformApiJsonWriter.write(digestInput);
    LinkedHashMap<String, Object> digest = LinkedHashMap.newLinkedHashMap(2);
    digest.put("algorithm", "SHA-256");
    digest.put(DIGEST_FIELD, digestOrNull(json));
    return digest;
  }

  private static Map<String, Object> supportSections(
      Map<String, Object> dashboard,
      Map<String, Object> diagnostics,
      List<Map<String, Object>> recentAudit,
      Map<String, Object> legacyAdmin) {
    List<Map<String, Object>> catalogs = listOfMaps(dashboard.get("catalogs"));
    List<Map<String, Object>> apps = listOfMaps(dashboard.get("apps"));
    List<Map<String, Object>> subscriptions = listOfMaps(dashboard.get(SUBSCRIPTIONS_FIELD));
    Map<String, Object> appServices = mapValue(dashboard.get("appServices"));
    Map<String, Object> trustGraph = mapValue(dashboard.get(TRUST_GRAPH_FIELD));
    List<Map<String, Object>> recoveryActions = listOfMaps(dashboard.get(RECOVERY_ACTIONS_FIELD));
    List<String> dashboardWarnings = stringList(dashboard.get(WARNINGS_FIELD));

    LinkedHashMap<String, Object> sections = LinkedHashMap.newLinkedHashMap(15);
    sections.put(
        "catalog",
        lifecycleSummary(
            "catalog",
            catalogs,
            CATALOG_ID_FIELD,
            dashboardDerivedLifecycleStatus(
                catalogs,
                dashboardWarnings,
                List.of(CATALOGS_UNAVAILABLE, "Catalog health could not be inspected"),
                List.of(
                    RECOMMENDED_FIRST_PARTY_CATALOG_MISSING,
                    "Recommended catalog state could not be inspected")),
            firstMatchingWarning(
                dashboardWarnings,
                CATALOGS_UNAVAILABLE,
                "Catalog health could not be inspected",
                RECOMMENDED_FIRST_PARTY_CATALOG_MISSING,
                "Recommended catalog state could not be inspected")));
    sections.put("appUpdates", appUpdateLifecycleSummary(apps));
    sections.put(
        SUBSCRIPTIONS_FIELD,
        lifecycleSummary(
            SUBSCRIPTIONS_FIELD,
            subscriptions,
            SUBSCRIPTION_ID_FIELD,
            dashboardDerivedLifecycleStatus(
                subscriptions,
                dashboardWarnings,
                List.of(CONTENT_SUBSCRIPTIONS_UNAVAILABLE, "Content subscriptions could not"),
                List.of()),
            firstMatchingWarning(
                dashboardWarnings,
                CONTENT_SUBSCRIPTIONS_UNAVAILABLE,
                "Content subscriptions could not")));
    sections.put(APP_DATA_FIELD, appDataLifecycleSummary(apps));
    sections.put(APP_SERVICE_GRANTS_FIELD, appServiceLifecycleSummary(appServices, recentAudit));
    sections.put(CONSENT_FIELD, consentLifecycleSummary(apps));
    sections.put("migrations", migrationLifecycleSummary(apps));
    sections.put(SANDBOX_FIELD, sandboxLifecycleSummary(apps));
    sections.put("contentFormats", contentFormatLifecycleSummary());
    sections.put(TRUST_GRAPH_FIELD, trustGraphLifecycleSummary(trustGraph));
    sections.put("socialInbox", socialInboxLifecycleSummary(apps));
    sections.put("recovery", recoveryLifecycleSummary(recoveryActions));
    sections.put(DIAGNOSTICS_FIELD, diagnosticsLifecycleSummary(diagnostics));
    sections.put("legacyFallbacks", legacyFallbackLifecycleSummary(diagnostics, legacyAdmin));
    sections.put("releaseCertification", releaseCertificationLifecycleSummary());
    return sections;
  }

  private static Map<String, Object> lifecycleSummary(
      String category,
      List<Map<String, Object>> items,
      String safeIdField,
      String status,
      String lastSafeStatusMessage) {
    Map<String, Object> json = baseLifecycleSummary(category, status);
    json.put(BOUNDED_COUNT_FIELD, items.size());
    json.put(LAST_ERROR_CODE_FIELD, firstLastErrorCode(items));
    json.put(
        LAST_SAFE_STATUS_MESSAGE_FIELD, firstNonNull(lastSafeStatusMessage, firstWarning(items)));
    json.put(SAFE_IDS_FIELD, safeIds(items, safeIdField));
    json.put(RECOVERY_ACTION_IDS_FIELD, recoveryActionIds(items));
    json.put(DIGEST_FIELD, digestOrNull(PlatformApiJsonWriter.write(json)));
    return json;
  }

  private static Map<String, Object> appUpdateLifecycleSummary(List<Map<String, Object>> apps) {
    long pending = 0L;
    long staged = 0L;
    long blocked = 0L;
    for (Map<String, Object> app : apps) {
      Map<String, Object> update = mapValue(app.get(UPDATE_FIELD));
      if (hasAvailableUpdateCandidate(update)) {
        pending++;
      }
      if (booleanValue(mapValue(update.get(STAGED_FIELD)).get(AVAILABLE_FIELD))) {
        staged++;
      }
      if (isUpdateBlocked(update) || isSecurityUpdateBlocked(update)) {
        blocked++;
      }
    }
    Map<String, Object> json =
        baseLifecycleSummary("appUpdates", blocked > 0L ? ACTION_REQUIRED : lifecycleStatus(apps));
    json.put(BOUNDED_COUNT_FIELD, apps.size());
    json.put(PENDING_UPDATE_COUNT_FIELD, pending);
    json.put(STAGED_UPDATE_COUNT_FIELD, staged);
    json.put("blockedUpdateCount", blocked);
    json.put(LAST_ERROR_CODE_FIELD, firstNestedLastErrorCode(apps, UPDATE_FIELD));
    json.put(SAFE_IDS_FIELD, safeIds(apps, APP_ID_FIELD));
    json.put(RECOVERY_ACTION_IDS_FIELD, recoveryActionIds(apps));
    json.put(DIGEST_FIELD, digestOrNull(PlatformApiJsonWriter.write(json)));
    return json;
  }

  private static Map<String, Object> appDataLifecycleSummary(List<Map<String, Object>> apps) {
    long unavailable = 0L;
    long quotaWarnings = 0L;
    for (Map<String, Object> app : apps) {
      Map<String, Object> appData = mapValue(app.get(APP_DATA_FIELD));
      if (isUnavailable(appData)) {
        unavailable++;
      }
      if (hasAppDataQuotaWarning(appData)) {
        quotaWarnings++;
      }
    }
    Map<String, Object> json =
        baseLifecycleSummary(APP_DATA_FIELD, unavailable > 0L ? WARNING : lifecycleStatus(apps));
    json.put(BOUNDED_COUNT_FIELD, apps.size());
    json.put("unavailableCount", unavailable);
    json.put(QUOTA_WARNING_COUNT_FIELD, quotaWarnings);
    json.put("rawAppDataExcluded", true);
    json.put("backupPayloadsExcluded", true);
    json.put(SAFE_IDS_FIELD, safeIds(apps, APP_ID_FIELD));
    json.put(DIGEST_FIELD, digestOrNull(PlatformApiJsonWriter.write(json)));
    return json;
  }

  private static Map<String, Object> appServiceLifecycleSummary(
      Map<String, Object> appServices, List<Map<String, Object>> recentAudit) {
    Map<String, Object> json =
        baseLifecycleSummary(
            APP_SERVICE_GRANTS_FIELD,
            booleanValue(appServices.get(AVAILABLE_FIELD)) ? AVAILABLE_STATUS : UNAVAILABLE);
    json.put(BOUNDED_COUNT_FIELD, longValue(appServices.get("serviceCount")));
    json.put(PENDING_GRANT_COUNT_FIELD, longValue(appServices.get(PENDING_GRANT_COUNT_FIELD)));
    json.put(ACTIVE_GRANT_COUNT_FIELD, longValue(appServices.get(ACTIVE_GRANT_COUNT_FIELD)));
    json.put(
        REVOKED_OR_INACTIVE_GRANT_COUNT_FIELD,
        longValue(appServices.get(REVOKED_OR_INACTIVE_GRANT_COUNT_FIELD)));
    json.put("recentAuditCount", recentAudit.size());
    json.put("rawInvocationBodiesExcluded", true);
    json.put(LAST_SAFE_STATUS_MESSAGE_FIELD, firstWarning(appServices));
    json.put(DIGEST_FIELD, digestOrNull(PlatformApiJsonWriter.write(json)));
    return json;
  }

  private static Map<String, Object> consentLifecycleSummary(List<Map<String, Object>> apps) {
    Map<String, Object> json = baseLifecycleSummary(CONSENT_FIELD, METADATA_ONLY_STATUS);
    json.put(BOUNDED_COUNT_FIELD, apps.size());
    json.put("pendingOrRejectedCount", countNestedWarning(apps, CONSENT_FIELD));
    json.put(LAST_SAFE_STATUS_MESSAGE_FIELD, "Consent details are summarized only when present.");
    json.put("rawConsentBodiesExcluded", true);
    json.put(DIGEST_FIELD, digestOrNull(PlatformApiJsonWriter.write(json)));
    return json;
  }

  private static Map<String, Object> migrationLifecycleSummary(List<Map<String, Object>> apps) {
    long migrationWarnings = countNestedWarning(apps, "migration");
    Map<String, Object> json =
        baseLifecycleSummary("migrations", migrationWarnings > 0L ? WARNING : METADATA_ONLY_STATUS);
    json.put(BOUNDED_COUNT_FIELD, apps.size());
    json.put("migrationWarningCount", migrationWarnings);
    json.put(LAST_ERROR_CODE_FIELD, firstNestedLastErrorCode(apps, "migration"));
    json.put("rawMigrationLogsExcluded", true);
    json.put("rawAppDataValuesExcluded", true);
    json.put(SAFE_IDS_FIELD, safeIds(apps, APP_ID_FIELD));
    json.put(DIGEST_FIELD, digestOrNull(PlatformApiJsonWriter.write(json)));
    return json;
  }

  private static Map<String, Object> sandboxLifecycleSummary(List<Map<String, Object>> apps) {
    long unavailable = 0L;
    for (Map<String, Object> app : apps) {
      Map<String, Object> sandbox = mapValue(app.get(SANDBOX_FIELD));
      if (isUnavailable(sandbox) || !stringList(sandbox.get(WARNINGS_FIELD)).isEmpty()) {
        unavailable++;
      }
    }
    Map<String, Object> json =
        baseLifecycleSummary(SANDBOX_FIELD, unavailable > 0L ? WARNING : lifecycleStatus(apps));
    json.put(BOUNDED_COUNT_FIELD, apps.size());
    json.put("warningCount", unavailable);
    json.put("providerPathsExcluded", true);
    json.put(SAFE_IDS_FIELD, safeIds(apps, APP_ID_FIELD));
    json.put(DIGEST_FIELD, digestOrNull(PlatformApiJsonWriter.write(json)));
    return json;
  }

  private static Map<String, Object> contentFormatLifecycleSummary() {
    Map<String, Object> json = baseLifecycleSummary("contentFormats", METADATA_ONLY_STATUS);
    json.put(BOUNDED_COUNT_FIELD, 5);
    json.put(
        "formatIds",
        List.of(
            "crypta.profile.v1",
            "crypta.feed.snapshot.v1",
            "crypta.trust.statement.v1",
            "crypta.social.message.v1",
            "crypta.social.outbox.v1"));
    json.put("validationFailureCount", 0L);
    json.put("rawDocumentBodiesExcluded", true);
    json.put("rawSignaturesExcluded", true);
    json.put(DIGEST_FIELD, digestOrNull(PlatformApiJsonWriter.write(json)));
    return json;
  }

  private static Map<String, Object> trustGraphLifecycleSummary(Map<String, Object> trustGraph) {
    Map<String, Object> json =
        baseLifecycleSummary(
            TRUST_GRAPH_FIELD,
            booleanValue(trustGraph.get(AVAILABLE_FIELD)) ? AVAILABLE_STATUS : UNAVAILABLE);
    json.put(BOUNDED_COUNT_FIELD, longValue(trustGraph.get(STATEMENT_COUNT_FIELD)));
    json.put(ANCHOR_COUNT_FIELD, longValue(trustGraph.get(ANCHOR_COUNT_FIELD)));
    json.put(AUDIT_COUNT_FIELD, longValue(trustGraph.get(AUDIT_COUNT_FIELD)));
    json.put("rawTrustStatementsExcluded", true);
    json.put("rawSignaturesExcluded", true);
    json.put(LAST_SAFE_STATUS_MESSAGE_FIELD, firstWarning(trustGraph));
    json.put(DIGEST_FIELD, digestOrNull(PlatformApiJsonWriter.write(json)));
    return json;
  }

  private static Map<String, Object> socialInboxLifecycleSummary(List<Map<String, Object>> apps) {
    List<Map<String, Object>> socialApps =
        apps.stream().filter(app -> "social-inbox".equals(app.get(APP_ID_FIELD))).toList();
    Map<String, Object> json =
        baseLifecycleSummary(
            "socialInbox", socialApps.isEmpty() ? "not_installed" : lifecycleStatus(socialApps));
    json.put(BOUNDED_COUNT_FIELD, socialApps.size());
    json.put("sourcePausedCount", countWarningContaining(socialApps, PAUSED_STATUS));
    json.put("malformedMessageRejectedCount", countWarningContaining(socialApps, "malformed"));
    json.put("rawMessagesExcluded", true);
    json.put("rawOutboxesExcluded", true);
    json.put(SAFE_IDS_FIELD, safeIds(socialApps, APP_ID_FIELD));
    json.put(DIGEST_FIELD, digestOrNull(PlatformApiJsonWriter.write(json)));
    return json;
  }

  private static Map<String, Object> recoveryLifecycleSummary(
      List<Map<String, Object>> recoveryActions) {
    Map<String, Object> json = baseLifecycleSummary("recovery", AVAILABLE_STATUS);
    json.put(BOUNDED_COUNT_FIELD, recoveryActions.size());
    json.put("availableActionCount", countAvailable(recoveryActions));
    json.put(RECOVERY_ACTION_IDS_FIELD, recoveryActionIdsFromActions(recoveryActions));
    json.put("planTokensExcluded", true);
    json.put(DIGEST_FIELD, digestOrNull(PlatformApiJsonWriter.write(json)));
    return json;
  }

  private static Map<String, Object> diagnosticsLifecycleSummary(Map<String, Object> diagnostics) {
    Map<String, Object> json =
        baseLifecycleSummary(
            DIAGNOSTICS_FIELD,
            booleanValue(diagnostics.get(AVAILABLE_FIELD)) ? AVAILABLE_STATUS : UNAVAILABLE);
    json.put(BOUNDED_COUNT_FIELD, longValue(diagnostics.get(SECTION_COUNT_FIELD)));
    json.put(
        LEGACY_FALLBACK_AVAILABLE_FIELD,
        booleanValue(diagnostics.get(LEGACY_FALLBACK_AVAILABLE_FIELD)));
    json.put(
        PLAIN_TEXT_EXPORT_AVAILABLE_FIELD,
        booleanValue(diagnostics.get(PLAIN_TEXT_EXPORT_AVAILABLE_FIELD)));
    json.put("rawDiagnosticBodiesExcluded", true);
    json.put(SECTIONS_FIELD, diagnostics.getOrDefault(SECTIONS_FIELD, List.of()));
    json.put(DIGEST_FIELD, digestOrNull(PlatformApiJsonWriter.write(json)));
    return json;
  }

  private static Map<String, Object> legacyFallbackLifecycleSummary(
      Map<String, Object> diagnostics, Map<String, Object> legacyAdmin) {
    Map<String, Object> json = baseLifecycleSummary("legacyFallbacks", "retained");
    json.put(BOUNDED_COUNT_FIELD, legacySurfaceCount(legacyAdmin));
    json.put("plaintextDiagnosticsFallbackRetained", true);
    json.put("plainTextExportEmbeddedInDefaultBundle", false);
    json.put(
        LEGACY_FALLBACK_AVAILABLE_FIELD,
        booleanValue(diagnostics.get(LEGACY_FALLBACK_AVAILABLE_FIELD)));
    json.put("rawLegacyDiagnosticsExcluded", true);
    json.put(DIGEST_FIELD, digestOrNull(PlatformApiJsonWriter.write(json)));
    return json;
  }

  private static long legacySurfaceCount(Map<String, Object> legacyAdmin) {
    List<Map<String, Object>> surfaces = listOfMaps(legacyAdmin.get(SURFACES_FIELD));
    if (!surfaces.isEmpty()) {
      return surfaces.size();
    }
    return longValue(legacyAdmin.get("surfaceCount"));
  }

  private static Map<String, Object> releaseCertificationLifecycleSummary() {
    Map<String, Object> json =
        baseLifecycleSummary("releaseCertification", "deterministic_source_check");
    json.put(BOUNDED_COUNT_FIELD, 1);
    json.put("evidenceId", "app-platform.privacy-preserving-beta-diagnostics");
    json.put("redactionFailuresAreProductionBlockers", true);
    json.put("rawCertificationArtifactsExcluded", true);
    json.put(DIGEST_FIELD, digestOrNull(PlatformApiJsonWriter.write(json)));
    return json;
  }

  private static Map<String, Object> baseLifecycleSummary(String category, String status) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(8);
    json.put("category", category);
    json.put(STATUS_FIELD, status);
    json.put(LAST_ERROR_CODE_FIELD, null);
    json.put(LAST_SAFE_STATUS_MESSAGE_FIELD, null);
    json.put("redactedSourceDigest", null);
    return json;
  }

  private static String lifecycleStatus(List<Map<String, Object>> items) {
    if (items.isEmpty()) {
      return "empty";
    }
    if (items.stream()
        .anyMatch(item -> isUnavailable(item) || !stringList(item.get(WARNINGS_FIELD)).isEmpty())) {
      return WARNING;
    }
    return AVAILABLE_STATUS;
  }

  private static String dashboardDerivedLifecycleStatus(
      List<Map<String, Object>> items,
      List<String> dashboardWarnings,
      List<String> unavailableWarningMarkers,
      List<String> warningMarkers) {
    if (containsWarning(dashboardWarnings, unavailableWarningMarkers)) {
      return UNAVAILABLE;
    }
    if (containsWarning(dashboardWarnings, warningMarkers)) {
      return WARNING;
    }
    return lifecycleStatus(items);
  }

  private static boolean containsWarning(List<String> warnings, List<String> markers) {
    return markers.stream().anyMatch(marker -> firstMatchingWarning(warnings, marker) != null);
  }

  private static List<String> safeIds(List<Map<String, Object>> items, String fieldName) {
    return items.stream()
        .map(item -> stringValue(item.get(fieldName)))
        .filter(Objects::nonNull)
        .distinct()
        .limit(12)
        .toList();
  }

  private static List<String> recoveryActionIds(List<Map<String, Object>> items) {
    return items.stream()
        .flatMap(item -> listOfMaps(item.get(RECOVERY_ACTIONS_FIELD)).stream())
        .map(action -> stringValue(action.get("id")))
        .filter(Objects::nonNull)
        .distinct()
        .limit(16)
        .toList();
  }

  private static List<String> recoveryActionIdsFromActions(List<Map<String, Object>> actions) {
    return actions.stream()
        .map(action -> stringValue(action.get("id")))
        .filter(Objects::nonNull)
        .distinct()
        .limit(24)
        .toList();
  }

  private static String firstWarning(List<Map<String, Object>> items) {
    return items.stream()
        .flatMap(item -> stringList(item.get(WARNINGS_FIELD)).stream())
        .findFirst()
        .orElse(null);
  }

  private static String firstWarning(Map<String, Object> item) {
    return stringList(item.get(WARNINGS_FIELD)).stream().findFirst().orElse(null);
  }

  private static String firstMatchingWarning(List<String> warnings, String... markers) {
    for (String marker : markers) {
      for (String warning : warnings) {
        if (warning.contains(marker)) {
          return warning;
        }
      }
    }
    return null;
  }

  private static String firstNonNull(String first, String second) {
    return first != null ? first : second;
  }

  private static String firstLastErrorCode(List<Map<String, Object>> items) {
    return items.stream()
        .map(item -> stringValue(item.get(LAST_ERROR_CODE_FIELD)))
        .filter(Objects::nonNull)
        .findFirst()
        .orElse(null);
  }

  private static String firstNestedLastErrorCode(
      List<Map<String, Object>> items, String nestedField) {
    return items.stream()
        .map(item -> stringValue(mapValue(item.get(nestedField)).get(LAST_ERROR_CODE_FIELD)))
        .filter(Objects::nonNull)
        .findFirst()
        .orElse(null);
  }

  private static long countAvailable(List<Map<String, Object>> items) {
    return items.stream().filter(item -> booleanValue(item.get(AVAILABLE_FIELD))).count();
  }

  private static long countNestedWarning(List<Map<String, Object>> apps, String fieldFragment) {
    String normalized = fieldFragment.toLowerCase(Locale.ROOT);
    return apps.stream()
        .flatMap(app -> stringList(app.get(WARNINGS_FIELD)).stream())
        .filter(warning -> warning.toLowerCase(Locale.ROOT).contains(normalized))
        .count();
  }

  private static long countWarningContaining(List<Map<String, Object>> items, String needle) {
    String normalized = needle.toLowerCase(Locale.ROOT);
    return items.stream()
        .flatMap(item -> stringList(item.get(WARNINGS_FIELD)).stream())
        .filter(warning -> warning.toLowerCase(Locale.ROOT).contains(normalized))
        .count();
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
                && booleanValue(mapValue(update.get(STAGED_FIELD)).get(AVAILABLE_FIELD))
                && !stagedSecurityBlocksUpdate(update)));
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
        action(
            "reset-subscription-backoff",
            "Reset subscription backoff",
            "POST",
            base + "/reset-backoff",
            true),
        action(
            "reschedule-subscription-now",
            "Reschedule subscription now",
            "POST",
            base + "/reschedule-now",
            true),
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
    if (booleanValue(subscription.get(PAUSED_STATUS))) {
      return PAUSED_STATUS;
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

  private static Map<String, Object> updateSecurityDecision(Map<String, Object> update) {
    Map<String, Object> stagedSecurity =
        mapValue(mapValue(update.get(STAGED_FIELD)).get(SECURITY_DECISION_FIELD));
    if (!stagedSecurity.isEmpty()) {
      return stagedSecurity;
    }
    return mapValue(mapValue(update.get(CANDIDATE_FIELD)).get(SECURITY_DECISION_FIELD));
  }

  private static boolean isUpdateBlocked(Map<String, Object> update) {
    Map<String, Object> reviewTrust = updateReviewTrust(update);
    return booleanValue(reviewTrust.get(BLOCKS_UPDATE_FIELD))
        || booleanValue(reviewTrust.get("blocksPolicyApply"));
  }

  private static boolean isSecurityUpdateBlocked(Map<String, Object> update) {
    Map<String, Object> securityDecision = updateSecurityDecision(update);
    return booleanValue(securityDecision.get(BLOCKS_UPDATE_FIELD));
  }

  private static boolean isSecurityAcknowledgementRequired(Map<String, Object> update) {
    Map<String, Object> securityDecision = updateSecurityDecision(update);
    return booleanValue(securityDecision.get(REQUIRES_ACKNOWLEDGEMENT_FIELD))
        || booleanValue(securityDecision.get("blocksAutomaticApply"));
  }

  private static boolean isUnavailable(Map<String, Object> section) {
    return UNAVAILABLE.equals(section.get(STATUS_FIELD));
  }

  private static boolean hasAvailableUpdateCandidate(Map<String, Object> update) {
    Map<String, Object> candidate = mapValue(update.get(CANDIDATE_FIELD));
    return AVAILABLE_STATUS.equals(candidate.get(STATUS_FIELD))
        || booleanValue(candidate.get("autoStageAllowed"));
  }

  private static boolean stageUpdateActionAvailable(Map<String, Object> update) {
    Map<String, Object> candidate = mapValue(update.get(CANDIDATE_FIELD));
    Map<String, Object> reviewTrust = mapValue(candidate.get(REVIEW_TRUST_FIELD));
    Map<String, Object> securityDecision = mapValue(candidate.get(SECURITY_DECISION_FIELD));
    return hasAvailableUpdateCandidate(update)
        && !booleanValue(reviewTrust.get(BLOCKS_UPDATE_FIELD))
        && !booleanValue(reviewTrust.get(REQUIRES_ACKNOWLEDGEMENT_FIELD))
        && !booleanValue(securityDecision.get(BLOCKS_UPDATE_FIELD))
        && !booleanValue(securityDecision.get(REQUIRES_ACKNOWLEDGEMENT_FIELD));
  }

  private static boolean stagedSecurityBlocksUpdate(Map<String, Object> update) {
    Map<String, Object> stagedSecurity =
        mapValue(mapValue(update.get(STAGED_FIELD)).get(SECURITY_DECISION_FIELD));
    return booleanValue(stagedSecurity.get(BLOCKS_UPDATE_FIELD));
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

  private static String unknownIfBlank(String value) {
    return value == null || value.isBlank() ? UNKNOWN : value;
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

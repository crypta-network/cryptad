package network.crypta.platform.api;

import java.io.IOException;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;
import network.crypta.platform.api.appcatalogs.AppCatalogsApiHandler;
import network.crypta.platform.api.appdata.AppDataService;
import network.crypta.platform.api.apps.AppsApiHandler;
import network.crypta.platform.api.content.subscriptions.ContentSubscriptionService;
import network.crypta.platform.api.diagnostics.DiagnosticsApiHandler;
import network.crypta.platform.api.operator.OperatorBetaDashboardService;
import network.crypta.platform.api.operator.recovery.OperatorRecoveryService;
import network.crypta.platform.api.trust.TrustGraphApiHandler;
import network.crypta.platform.appcatalog.AppCatalogException;
import network.crypta.platform.appcatalog.AppCatalogManager;
import network.crypta.platform.appcatalog.AppSubmissionIntakeRecord;
import network.crypta.platform.appcatalog.AppSubmissionIntakeSummary;
import network.crypta.platform.appcatalog.FileAppSubmissionIntakeStore;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.appui.AppUiOriginRegistry;
import network.crypta.platform.appvault.AppVaultService;
import network.crypta.runtime.spi.CoreSupportLifecycleSnapshot;
import network.crypta.runtime.spi.CoreUpdateActionPort;
import network.crypta.runtime.spi.LegacyAdminUsagePort;
import network.crypta.runtime.spi.RuntimePorts;

/**
 * Routes host/operator-only beta dashboard and recovery endpoints.
 *
 * <p>This route family is intentionally local-management-only. It gives the desktop shell and
 * legacy admin bridge a compact view of beta app health, redacted support evidence, and manual
 * recovery actions for durable content subscriptions. App principals are already default-denied by
 * the capability matrix because these routes are not part of the app-facing contract; this class
 * still checks the principal defensively before returning dashboard, support-bundle, or
 * subscription-recovery responses.
 *
 * <p>Instances are request-router collaborators. They do not own background work or persistent
 * state; instead, they compose the existing app, catalog, diagnostics, trust graph, and
 * subscription services into operator-safe JSON envelopes. Missing optional services are reported
 * through stable Platform API errors so the operator dashboard can explain what is unavailable
 * without granting app-origin callers any new privileges.
 */
final class PlatformApiOperatorRoutes {
  /** HTTP method accepted by read-only operator dashboard resources. */
  private static final String METHOD_GET = "GET";

  /** HTTP method accepted by operator recovery actions that mutate app-platform state. */
  private static final String METHOD_POST = "POST";

  /** Stable 405 response text for resources that are safe to read only. */
  private static final String GET_ONLY_MESSAGE = "Platform API v1 supports GET requests only.";

  /** Stable 405 response text for action routes that require an explicit POST. */
  private static final String POST_ONLY_MESSAGE = "Platform API v1 supports POST requests only.";

  /** Path segment that identifies subscription recovery routes under the operator namespace. */
  private static final String SUBSCRIPTIONS_SEGMENT = "subscriptions";

  /** Path segment that identifies app-data backup and restore routes. */
  private static final String APP_DATA_SEGMENT = "app-data";

  /** Path segment that identifies typed RC recovery routes. */
  private static final String RECOVERY_SEGMENT = "recovery";

  /** Path segment that identifies local public-beta app submission intake diagnostics. */
  private static final String APP_SUBMISSIONS_SEGMENT = "app-submissions";

  /** Non-colliding sub-resource for local intake transparency-log summaries. */
  private static final String TRANSPARENCY_SEGMENT = "transparency";

  /** Leaf segment used by metadata-only operator summaries. */
  private static final String SUMMARY_SEGMENT = "summary";

  /** Shared JSON field for operator-visible warning summaries. */
  private static final String FIELD_WARNINGS = "warnings";

  /** System property used to point operator routes at a local intake queue. */
  private static final String APP_SUBMISSION_INTAKE_DIR_PROPERTY = "cryptad.appSubmissionIntakeDir";

  /** Environment fallback used to point operator routes at a local intake queue. */
  private static final String APP_SUBMISSION_INTAKE_DIR_ENV = "CRYPTAD_APP_INTAKE_QUEUE_DIR";

  /** Builds redacted dashboard and support-bundle payloads from shared app-platform services. */
  private final OperatorBetaDashboardService dashboardService;

  /** Plans and executes closed allowlisted operator RC recovery actions. */
  private final OperatorRecoveryService recoveryService;

  /** Shared durable subscription service used by operator-initiated refresh and pause actions. */
  private final ContentSubscriptionService contentSubscriptionService;

  /** Shared app-data service used for operator backup and restore portability routes. */
  private final AppDataService appDataService;

  /** Path-free Cryptad version label included in backup manifests. */
  private final Supplier<String> currentCryptaVersion;

  /** Detached source for redacted last-known-good core support-lifecycle state. */
  private final CoreUpdateActionPort coreUpdateActionPort;

  /**
   * Required route-composition inputs that come from the top-level router.
   *
   * <p>The values mirror the runtime and AppHost collaborators already used by app-management
   * routes. Keeping them in one typed aggregate avoids long positional constructor calls while
   * preserving the same optional-service behavior: missing AppHost, catalog, diagnostics, or legacy
   * admin collaborators still produce unavailable dashboard sections instead of synthetic health.
   *
   * @param runtimePorts detached runtime-port aggregate used for diagnostics
   * @param appHost optional AppHost used for installed-app and catalog-install state
   * @param appCatalogManager optional signed catalog manager used for catalog evidence
   * @param legacyAdminUsage optional legacy-admin usage source included in diagnostics
   * @param appAuditLog bounded app-platform audit log shared with app route handlers
   * @param appUiOriginRegistry registry used to resolve app UI origin metadata
   * @param currentCryptaVersion supplier for the daemon version reported to catalog handlers
   */
  record RouteDependencies(
      RuntimePorts runtimePorts,
      AppHost appHost,
      AppCatalogManager appCatalogManager,
      LegacyAdminUsagePort legacyAdminUsage,
      AppAuditLog appAuditLog,
      AppUiOriginRegistry appUiOriginRegistry,
      Supplier<String> currentCryptaVersion) {}

  /**
   * Creates operator routes backed by the router's shared app-platform services.
   *
   * <p>The constructor mirrors the top-level router composition so operator support evidence is
   * collected from the same services that answer normal Platform API requests. Optional runtime
   * pieces may be {@code null}; the resulting dashboard records unavailable sections instead of
   * fabricating health, while action routes still fail closed when their backing service is absent.
   *
   * @param dependencies route-composition inputs owned by the top-level router
   * @param appServices optional shared services used by schedulers and request handlers
   * @param appRoutes app route collaborator that owns the shared app-update service
   * @param trustGraphApiHandler Trust Graph handler already used by the top-level Trust Graph
   *     routes
   */
  PlatformApiOperatorRoutes(
      RouteDependencies dependencies,
      PlatformApiSharedAppServices appServices,
      PlatformApiAppRoutes appRoutes,
      TrustGraphApiHandler trustGraphApiHandler) {
    AppVaultService appVaultService = appServices.vaultService();
    AppsApiHandler appsApiHandler =
        dependencies.appHost() == null
            ? null
            : new AppsApiHandler(
                dependencies.appHost(),
                dependencies.appAuditLog(),
                dependencies.appUiOriginRegistry(),
                appVaultService);
    AppCatalogsApiHandler appCatalogsApiHandler =
        dependencies.appHost() == null || dependencies.appCatalogManager() == null
            ? null
            : new AppCatalogsApiHandler(
                dependencies.appCatalogManager(),
                dependencies.appHost(),
                dependencies.currentCryptaVersion(),
                appVaultService);
    DiagnosticsApiHandler diagnosticsApiHandler =
        dependencies.runtimePorts().diagnostic() == null
            ? null
            : new DiagnosticsApiHandler(
                dependencies.runtimePorts().diagnostic(), dependencies.legacyAdminUsage());
    contentSubscriptionService = appServices.contentSubscriptionService();
    appDataService = appServices.appDataService();
    currentCryptaVersion = dependencies.currentCryptaVersion();
    coreUpdateActionPort = dependencies.runtimePorts().coreUpdateAction();
    dashboardService =
        new OperatorBetaDashboardService(
            new OperatorBetaDashboardService.HandlerSources(
                appsApiHandler,
                appCatalogsApiHandler,
                appRoutes.appUpdateService(),
                diagnosticsApiHandler),
            new OperatorBetaDashboardService.AppStateSources(
                contentSubscriptionService,
                appServices.appDataService(),
                trustGraphApiHandler,
                appServices.appServiceCoordinator()));
    recoveryService =
        new OperatorRecoveryService(
            new OperatorRecoveryService.Dependencies(
                appsApiHandler,
                appCatalogsApiHandler,
                appRoutes.appUpdateService(),
                contentSubscriptionService,
                appDataService,
                trustGraphApiHandler,
                appServices.appServiceCoordinator(),
                appServices.networkBudgetService(),
                dashboardService,
                appRoutes::clearAppStateAfterUninstall,
                currentCryptaVersion,
                this::supportBundleWithoutRecoveryContext));
  }

  /**
   * Routes a request beneath the {@code /operator} Platform API namespace.
   *
   * <p>The method expects decoded path segments relative to the Platform API mount point. It always
   * verifies the caller is the host operator before dispatching so app-origin requests cannot probe
   * dashboard, support, or recovery resources through alternate paths. Unknown resources and
   * malformed paths use the same stable {@code 404 not_found} response as the rest of the router.
   *
   * @param segments decoded path segments beginning with the {@code operator} namespace
   * @param request full request metadata, including method, principal, and query parameters
   * @return JSON response for the selected operator resource or recovery action
   */
  PlatformApiResponse route(List<String> segments, PlatformApiRequest request) {
    requireHostOperator(request);
    return switch (segments.size()) {
      case 2 -> routeCollection(segments.get(1), request);
      case 3 -> routeThreeSegmentResource(segments, request);
      case 4 -> routeFourSegmentResource(segments, request);
      case 5 -> routeSubscriptionAction(segments, request);
      default -> throw notFound();
    };
  }

  /**
   * Routes read-only operator resources such as the dashboard and support bundle.
   *
   * @param resource resource segment immediately beneath {@code /operator}
   * @param request full request metadata used to validate the HTTP method
   * @return JSON response containing redacted operator support data
   */
  private PlatformApiResponse routeCollection(String resource, PlatformApiRequest request) {
    if ("beta-dashboard".equals(resource)) {
      if (!METHOD_GET.equals(request.method())) {
        return methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
      }
      return PlatformApiResponse.ok(dashboard());
    }
    if ("rc-dashboard".equals(resource)) {
      if (!METHOD_GET.equals(request.method())) {
        return methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
      }
      return PlatformApiResponse.ok(rcDashboard());
    }
    if ("support-bundle".equals(resource)) {
      if (!METHOD_GET.equals(request.method())) {
        return methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
      }
      return PlatformApiResponse.ok(supportBundle());
    }
    if ("network-budgets".equals(resource)) {
      if (!METHOD_GET.equals(request.method())) {
        return methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
      }
      return PlatformApiResponse.ok(recoveryService.networkBudgets());
    }
    if (APP_SUBMISSIONS_SEGMENT.equals(resource)) {
      if (!METHOD_GET.equals(request.method())) {
        return methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
      }
      return PlatformApiResponse.ok(appSubmissionIntakeSummary());
    }
    throw notFound();
  }

  private PlatformApiResponse routeThreeSegmentResource(
      List<String> segments, PlatformApiRequest request) {
    if (APP_DATA_SEGMENT.equals(segments.get(1))) {
      return routeAppData(segments, request);
    }
    if ("support-bundle".equals(segments.get(1)) && "preview".equals(segments.get(2))) {
      if (!METHOD_GET.equals(request.method())) {
        return methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
      }
      return PlatformApiResponse.ok(recoveryService.supportBundlePreview(supportBundle()));
    }
    if (RECOVERY_SEGMENT.equals(segments.get(1))) {
      return routeRecovery(segments.get(2), request);
    }
    if (APP_SUBMISSIONS_SEGMENT.equals(segments.get(1))) {
      return routeAppSubmissionIntakeRecord(segments.get(2), request);
    }
    throw notFound();
  }

  private PlatformApiResponse routeFourSegmentResource(
      List<String> segments, PlatformApiRequest request) {
    if (APP_SUBMISSIONS_SEGMENT.equals(segments.get(1))
        && TRANSPARENCY_SEGMENT.equals(segments.get(2))
        && SUMMARY_SEGMENT.equals(segments.get(3))) {
      if (!METHOD_GET.equals(request.method())) {
        return methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
      }
      return PlatformApiResponse.ok(appSubmissionTransparencySummary());
    }
    return routeAppDataRestore(segments, request);
  }

  private PlatformApiResponse routeAppSubmissionIntakeRecord(
      String submissionId, PlatformApiRequest request) {
    if (!METHOD_GET.equals(request.method())) {
      return methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
    }
    FileAppSubmissionIntakeStore store =
        appSubmissionIntakeStore()
            .orElseThrow(
                () ->
                    new PlatformApiException(
                        503,
                        "app_submission_intake_unconfigured",
                        "App submission intake queue is not configured."));
    AppSubmissionIntakeRecord intakeRecord;
    try {
      intakeRecord =
          store
              .load(submissionId)
              .orElseThrow(
                  () ->
                      new PlatformApiException(
                          404, "app_submission_not_found", "Submission intake record not found."));
    } catch (IOException | AppCatalogException _) {
      throw appSubmissionIntakeUnavailable();
    }
    return PlatformApiResponse.ok(envelope("submission", intakeRecord.toJsonValue()));
  }

  private PlatformApiResponse routeRecovery(String action, PlatformApiRequest request) {
    return switch (action) {
      case "actions" -> {
        if (!METHOD_GET.equals(request.method())) {
          yield methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
        }
        yield PlatformApiResponse.ok(envelope("actions", recoveryService.actions()));
      }
      case "plan" -> {
        if (!METHOD_POST.equals(request.method())) {
          yield methodNotAllowed(METHOD_POST, POST_ONLY_MESSAGE);
        }
        yield PlatformApiResponse.ok(
            envelope("plan", recoveryService.plan(request.queryParameters()).toJson()));
      }
      case "execute" -> {
        if (!METHOD_POST.equals(request.method())) {
          yield methodNotAllowed(METHOD_POST, POST_ONLY_MESSAGE);
        }
        yield PlatformApiResponse.ok(
            envelope("result", recoveryService.execute(request.queryParameters()).toJson()));
      }
      default -> throw notFound();
    };
  }

  private Map<String, Object> rcDashboard() {
    LinkedHashMap<String, Object> dashboard = LinkedHashMap.newLinkedHashMap(16);
    dashboard.putAll(dashboard());
    dashboard.put("dashboardKind", "operator-rc-recovery-dashboard");
    dashboard.put(
        "betaCompatibility",
        Map.of(
            "route",
            "operator/beta-dashboard",
            "retained",
            true,
            "operatorRoutesInAppContract",
            false));
    dashboard.put("operatorRcRecovery", recoveryService.dashboardState());
    dashboard.put("networkBudgets", recoveryService.networkBudgets());
    dashboard.put("supportBundlePreviewRoute", "operator/support-bundle/preview");
    return dashboard;
  }

  private Map<String, Object> supportBundle() {
    return supportBundleForExport(
        supportBundleWithoutRecoveryContext(), recoveryService.supportContext());
  }

  private Map<String, Object> dashboard() {
    LinkedHashMap<String, Object> dashboard = new LinkedHashMap<>(dashboardService.dashboard());
    dashboard.put("coreSupportLifecycle", lifecycleSnapshot());
    return dashboard;
  }

  private Map<String, Object> supportBundleWithoutRecoveryContext() {
    LinkedHashMap<String, Object> bundle = new LinkedHashMap<>(dashboardService.supportBundle());
    bundle.put("coreSupportLifecycle", lifecycleSnapshot());
    bundle.put("supportDigest", OperatorBetaDashboardService.supportDigestForPayload(bundle));
    return bundle;
  }

  private Map<String, Object> lifecycleSnapshot() {
    CoreSupportLifecycleSnapshot snapshot = coreUpdateActionPort.supportLifecycleSnapshot();
    return (snapshot == null
            ? CoreSupportLifecycleSnapshot.unknown(
                -1, List.of("lifecycle_runtime_snapshot_unavailable"))
            : snapshot)
        .toJsonValue();
  }

  static Map<String, Object> supportBundleForExport(
      Map<String, Object> supportBundle, Map<String, Object> recoveryContext) {
    LinkedHashMap<String, Object> bundle = LinkedHashMap.newLinkedHashMap(12);
    bundle.putAll(supportBundle);
    bundle.put("supportBundleVersion", bundle.get("schemaVersion"));
    bundle.put("recoveryContext", recoveryContext);
    bundle.put("supportDigest", OperatorBetaDashboardService.supportDigestForPayload(bundle));
    return bundle;
  }

  private Map<String, Object> appSubmissionIntakeSummary() {
    Optional<FileAppSubmissionIntakeStore> maybeStore = appSubmissionIntakeStore();
    Map<String, Object> summary = appSubmissionIntakeBaseEnvelope(maybeStore.isPresent());
    if (maybeStore.isEmpty()) {
      summary.put("queueCount", 0);
      summary.put("submissions", List.of());
      summary.put(FIELD_WARNINGS, List.of("appSubmissionIntakeQueueNotConfigured"));
      return summary;
    }
    List<AppSubmissionIntakeSummary> submissions;
    try {
      submissions = maybeStore.orElseThrow().listSummaries();
    } catch (IOException | AppCatalogException _) {
      throw appSubmissionIntakeUnavailable();
    }
    summary.put("queueCount", submissions.size());
    summary.put(
        "submissions", submissions.stream().map(AppSubmissionIntakeSummary::toJsonValue).toList());
    summary.put(FIELD_WARNINGS, List.of());
    return summary;
  }

  private Map<String, Object> appSubmissionTransparencySummary() {
    Optional<FileAppSubmissionIntakeStore> maybeStore = appSubmissionIntakeStore();
    Map<String, Object> summary = appSubmissionIntakeBaseEnvelope(maybeStore.isPresent());
    summary.put("kind", "crypta-operator-app-submission-transparency-summary");
    if (maybeStore.isEmpty()) {
      summary.put("recordsWithTransparencyDigest", 0);
      summary.put(FIELD_WARNINGS, List.of("appSubmissionIntakeQueueNotConfigured"));
      return summary;
    }
    List<AppSubmissionIntakeSummary> submissions;
    try {
      submissions = maybeStore.orElseThrow().listSummaries();
    } catch (IOException | AppCatalogException _) {
      throw appSubmissionIntakeUnavailable();
    }
    summary.put(
        "recordsWithTransparencyDigest",
        submissions.stream().filter(item -> item.transparencyLogDigest() != null).count());
    summary.put(
        "submissionIds",
        submissions.stream()
            .filter(item -> item.transparencyLogDigest() != null)
            .map(AppSubmissionIntakeSummary::submissionId)
            .toList());
    summary.put(FIELD_WARNINGS, List.of());
    return summary;
  }

  private static Map<String, Object> appSubmissionIntakeBaseEnvelope(boolean configured) {
    LinkedHashMap<String, Object> envelope = LinkedHashMap.newLinkedHashMap(8);
    envelope.put("schemaVersion", 1);
    envelope.put("kind", "crypta-operator-app-submission-intake");
    envelope.put("configured", configured);
    envelope.put("route", "operator/app-submissions");
    envelope.put("operatorOnly", true);
    envelope.put("operatorRoutesInAppContract", false);
    return envelope;
  }

  private static Optional<FileAppSubmissionIntakeStore> appSubmissionIntakeStore() {
    String configured = System.getProperty(APP_SUBMISSION_INTAKE_DIR_PROPERTY);
    if (configured == null || configured.isBlank()) {
      configured = System.getenv(APP_SUBMISSION_INTAKE_DIR_ENV);
    }
    if (configured == null || configured.isBlank()) {
      return Optional.empty();
    }
    return Optional.of(new FileAppSubmissionIntakeStore(Path.of(configured)));
  }

  private static PlatformApiException appSubmissionIntakeUnavailable() {
    return new PlatformApiException(
        503, "app_submission_intake_unavailable", "App submission intake queue is unavailable.");
  }

  /**
   * Routes app-data backup creation and restore commit under {@code /operator/app-data}.
   *
   * @param segments decoded operator route segments
   * @param request full request metadata used to validate the method and query parameters
   * @return sensitive backup response containing an app-data backup bundle
   */
  private PlatformApiResponse routeAppData(List<String> segments, PlatformApiRequest request) {
    if (!APP_DATA_SEGMENT.equals(segments.get(1))) {
      throw notFound();
    }
    if ("backups".equals(segments.get(2))) {
      return routeAppDataBackup(request);
    }
    if ("restore".equals(segments.get(2))) {
      return routeAppDataRestoreCommit(request);
    }
    throw notFound();
  }

  private PlatformApiResponse routeAppDataBackup(PlatformApiRequest request) {
    if (!METHOD_POST.equals(request.method())) {
      return methodNotAllowed(METHOD_POST, POST_ONLY_MESSAGE);
    }
    if (appDataService == null) {
      throw new PlatformApiException(
          503, "app_data_service_unavailable", "App-data service is unavailable.");
    }
    return PlatformApiResponse.ok(
        appDataService.exportBackup(request.queryParameters(), currentCryptaVersion.get()));
  }

  private PlatformApiResponse routeAppDataRestoreCommit(PlatformApiRequest request) {
    if (!METHOD_POST.equals(request.method())) {
      return methodNotAllowed(METHOD_POST, POST_ONLY_MESSAGE);
    }
    if (appDataService == null) {
      throw new PlatformApiException(
          503, "app_data_service_unavailable", "App-data service is unavailable.");
    }
    return PlatformApiResponse.ok(appDataService.restoreBackup(request.queryParameters()));
  }

  /**
   * Routes app-data restore planning and commit under {@code /operator/app-data/restore}.
   *
   * @param segments decoded operator route segments
   * @param request full request metadata used to validate the method and form fields
   * @return metadata-only restore plan or result response
   */
  private PlatformApiResponse routeAppDataRestore(
      List<String> segments, PlatformApiRequest request) {
    if (!APP_DATA_SEGMENT.equals(segments.get(1)) || !"restore".equals(segments.get(2))) {
      throw notFound();
    }
    if (!METHOD_POST.equals(request.method())) {
      return methodNotAllowed(METHOD_POST, POST_ONLY_MESSAGE);
    }
    if (appDataService == null) {
      throw new PlatformApiException(
          503, "app_data_service_unavailable", "App-data service is unavailable.");
    }
    if ("plan".equals(segments.get(3))) {
      return PlatformApiResponse.ok(appDataService.planRestore(request.queryParameters()));
    }
    throw notFound();
  }

  /**
   * Routes operator-triggered recovery actions for durable content subscriptions.
   *
   * <p>These actions intentionally reuse {@link ContentSubscriptionService} rather than duplicating
   * subscription state handling in the dashboard layer. The response wraps the updated
   * operator-safe subscription summary in a stable envelope, and the service remains responsible
   * for validating app and subscription identifiers.
   *
   * @param segments decoded route segments for {@code /operator/subscriptions/{app}/{id}/{action}}
   * @param request full request metadata used to validate the HTTP method
   * @return JSON response containing the updated subscription summary
   */
  private PlatformApiResponse routeSubscriptionAction(
      List<String> segments, PlatformApiRequest request) {
    if (!SUBSCRIPTIONS_SEGMENT.equals(segments.get(1))) {
      throw notFound();
    }
    if (!METHOD_POST.equals(request.method())) {
      return methodNotAllowed(METHOD_POST, POST_ONLY_MESSAGE);
    }
    if (contentSubscriptionService == null) {
      throw new PlatformApiException(
          503,
          "content_subscription_service_unavailable",
          "Content subscription service is unavailable.");
    }

    String appId = segments.get(2);
    String subscriptionId = segments.get(3);
    String action = segments.get(4);
    Map<String, Object> subscription =
        switch (action) {
          case "refresh" -> contentSubscriptionService.refresh(appId, subscriptionId);
          case "pause" -> contentSubscriptionService.pause(appId, subscriptionId);
          case "resume" -> contentSubscriptionService.resume(appId, subscriptionId);
          case "reset-backoff" -> contentSubscriptionService.resetBackoff(appId, subscriptionId);
          case "reschedule-now" -> contentSubscriptionService.rescheduleNow(appId, subscriptionId);
          default -> throw notFound();
        };
    LinkedHashMap<String, Object> envelope = LinkedHashMap.newLinkedHashMap(1);
    envelope.put("subscription", dashboardService.operatorSubscriptionSummary(subscription));
    return PlatformApiResponse.ok(envelope);
  }

  /**
   * Rejects app principals before any operator-only evidence is assembled.
   *
   * @param request full request metadata containing the authenticated principal
   * @throws PlatformApiException when an app principal reaches an operator route
   */
  private static void requireHostOperator(PlatformApiRequest request) {
    if (request.principal().isApp()) {
      throw new PlatformApiException(
          403,
          "host_operator_required",
          "This Platform API route requires a host/operator principal.");
    }
  }

  /**
   * Creates a stable method-not-allowed response for operator route families.
   *
   * @param allow value for the response {@code Allow} header
   * @param message human-readable error message returned in the JSON body
   * @return Platform API error response with status {@code 405}
   */
  private static PlatformApiResponse methodNotAllowed(String allow, String message) {
    return PlatformApiResponse.error(405, Map.of("Allow", allow), "method_not_allowed", message);
  }

  /**
   * Creates the standard missing-route exception used by the Platform API router.
   *
   * @return exception that serializes to the stable {@code not_found} response shape
   */
  private static PlatformApiException notFound() {
    return new PlatformApiException(404, "not_found", "Platform API route not found.");
  }

  private static Map<String, Object> envelope(String key, Object value) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(1);
    json.put(key, value);
    return json;
  }
}

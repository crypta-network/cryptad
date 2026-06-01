package network.crypta.platform.api;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import network.crypta.platform.api.appcatalogs.AppCatalogsApiHandler;
import network.crypta.platform.api.apps.AppsApiHandler;
import network.crypta.platform.api.content.subscriptions.ContentSubscriptionService;
import network.crypta.platform.api.diagnostics.DiagnosticsApiHandler;
import network.crypta.platform.api.operator.OperatorBetaDashboardService;
import network.crypta.platform.api.trust.TrustGraphApiHandler;
import network.crypta.platform.appcatalog.AppCatalogManager;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.appui.AppUiOriginRegistry;
import network.crypta.platform.appvault.AppVaultService;
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

  /** Builds redacted dashboard and support-bundle payloads from shared app-platform services. */
  private final OperatorBetaDashboardService dashboardService;

  /** Shared durable subscription service used by operator-initiated refresh and pause actions. */
  private final ContentSubscriptionService contentSubscriptionService;

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
   */
  PlatformApiOperatorRoutes(
      RouteDependencies dependencies,
      PlatformApiSharedAppServices appServices,
      PlatformApiAppRoutes appRoutes) {
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
    TrustGraphApiHandler trustGraphApiHandler =
        appServices.trustGraphApiHandler() == null
            ? new TrustGraphApiHandler()
            : appServices.trustGraphApiHandler();
    contentSubscriptionService = appServices.contentSubscriptionService();
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
      return PlatformApiResponse.ok(dashboardService.dashboard());
    }
    if ("support-bundle".equals(resource)) {
      if (!METHOD_GET.equals(request.method())) {
        return methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
      }
      return PlatformApiResponse.ok(dashboardService.supportBundle());
    }
    throw notFound();
  }

  /**
   * Routes operator-triggered recovery actions for durable content subscriptions.
   *
   * <p>These actions intentionally reuse {@link ContentSubscriptionService} rather than duplicating
   * subscription state handling in the dashboard layer. The response wraps the updated subscription
   * summary in a stable envelope, and the service remains responsible for validating app and
   * subscription identifiers.
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
    Object subscription =
        switch (action) {
          case "refresh" -> contentSubscriptionService.refresh(appId, subscriptionId);
          case "pause" -> contentSubscriptionService.pause(appId, subscriptionId);
          case "resume" -> contentSubscriptionService.resume(appId, subscriptionId);
          default -> throw notFound();
        };
    LinkedHashMap<String, Object> envelope = LinkedHashMap.newLinkedHashMap(1);
    envelope.put("subscription", subscription);
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
}

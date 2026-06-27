package network.crypta.platform.api;

import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import network.crypta.platform.api.appcatalogs.AppCatalogsApiHandler;
import network.crypta.platform.api.appdata.AppDataService;
import network.crypta.platform.api.apps.AppsApiHandler;
import network.crypta.platform.api.appservices.AppServiceCoordinator;
import network.crypta.platform.api.appupdates.AppUpdateService;
import network.crypta.platform.api.appupdates.AppUpdatesApiHandler;
import network.crypta.platform.api.consent.ConsentApiHandler;
import network.crypta.platform.api.consent.ConsentService;
import network.crypta.platform.api.content.subscriptions.ContentSubscriptionService;
import network.crypta.platform.appcatalog.AppCatalogManager;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.appui.AppUiOriginRegistry;
import network.crypta.platform.appvault.AppVaultService;

/**
 * Routes the app-platform endpoint families that hang off Platform API v1.
 *
 * <p>The main {@link PlatformApiRouter} owns authorization, audit recording, and the top-level
 * route switch. This collaborator owns the app-specific families below that switch: installed-app
 * lifecycle routes, signed app-catalog routes, app-update lifecycle routes, and app/identity vault
 * routing. Keeping those handlers together matters because uninstall cleanup, app-update state, and
 * vault grant cleanup interact with each other after successful and failed app-management
 * mutations.
 *
 * <p>Instances are lightweight and process-local. They keep references to the long-lived AppHost,
 * catalog, vault, and update services supplied by runtime composition, but they do not start
 * background work. Missing optional services are represented by {@code null} handlers and produce
 * the same {@code 404 not_found} route response that the router used before this extraction.
 */
final class PlatformApiAppRoutes {
  private static final System.Logger LOG = System.getLogger(PlatformApiAppRoutes.class.getName());
  private static final String CATALOG_ENVELOPE_KEY = "catalog";
  private static final String GET_ONLY_MESSAGE = "Platform API v1 supports GET requests only.";
  private static final String GET_POST_ONLY_MESSAGE =
      "Platform API v1 supports GET and POST requests only.";
  private static final String METHOD_DELETE = "DELETE";
  private static final String METHOD_GET = "GET";
  private static final String METHOD_POST = "POST";
  private static final String METHODS_GET_POST = "GET, POST";
  private static final String POLICY_ROUTE_SEGMENT = "policy";
  private static final String POST_ONLY_MESSAGE = "Platform API v1 supports POST requests only.";
  private static final String UPDATES_ROUTE_SEGMENT = "updates";

  private final AppsApiHandler appsApiHandler;
  private final AppUpdatesApiHandler appUpdatesApiHandler;
  private final AppUpdateService appUpdateService;
  private final ContentSubscriptionService contentSubscriptionService;
  private final AppDataService appDataService;
  private final AppServiceCoordinator appServiceCoordinator;
  private final AppCatalogsApiHandler appCatalogsApiHandler;
  private final ConsentService consentService;
  private final ConsentApiHandler consentApiHandler;
  private final PlatformApiVaultRouter vaultRouter;

  /**
   * Required route-composition inputs that are not scheduler-owned services.
   *
   * <p>The AppHost and catalog manager remain optional because some router test and embedded
   * configurations expose only non-app Platform API families. The audit log, UI origin registry,
   * and version supplier follow the same lifecycle as the top-level router.
   */
  record RouteDependencies(
      AppHost appHost,
      AppCatalogManager appCatalogManager,
      AppAuditLog appAuditLog,
      AppUiOriginRegistry appUiOriginRegistry,
      Supplier<String> currentCryptaVersion) {}

  /**
   * Optional app-platform services shared with background schedulers.
   *
   * <p>When these services are present, request handlers and schedulers observe the same state.
   * When they are absent, app routes either create their legacy request-scoped coordinator or
   * report the same route-unavailable result as before.
   */
  record SharedServices(
      AppVaultService appVaultService,
      AppUpdateService appUpdateService,
      ContentSubscriptionService contentSubscriptionService,
      AppDataService appDataService,
      AppServiceCoordinator appServiceCoordinator) {}

  /**
   * Creates app-platform routes from the optional app runtime services.
   *
   * <p>The supplied update service may be shared with the background app-update scheduler. When no
   * shared service is supplied, this constructor creates the default request-scoped app-update
   * coordinator only when both AppHost and app-catalog support are available.
   *
   * @param dependencies route-composition inputs owned by the top-level router
   * @param sharedServices optional services also used by background schedulers
   */
  PlatformApiAppRoutes(RouteDependencies dependencies, SharedServices sharedServices) {
    AppHost appHost = dependencies.appHost();
    AppCatalogManager appCatalogManager = dependencies.appCatalogManager();
    AppVaultService appVaultService = sharedServices.appVaultService();
    appsApiHandler =
        appHost == null
            ? null
            : new AppsApiHandler(
                appHost,
                dependencies.appAuditLog(),
                dependencies.appUiOriginRegistry(),
                appVaultService);
    AppUpdateService resolvedUpdateService = sharedServices.appUpdateService();
    if (resolvedUpdateService == null && appHost != null && appCatalogManager != null) {
      resolvedUpdateService =
          new AppUpdateService(
              appHost, appCatalogManager, appVaultService, sharedServices.appDataService());
    }
    appUpdateService = resolvedUpdateService;
    contentSubscriptionService = sharedServices.contentSubscriptionService();
    appDataService = sharedServices.appDataService();
    appServiceCoordinator = sharedServices.appServiceCoordinator();
    appUpdatesApiHandler =
        appUpdateService == null ? null : new AppUpdatesApiHandler(appUpdateService);
    appCatalogsApiHandler =
        appHost == null || appCatalogManager == null
            ? null
            : new AppCatalogsApiHandler(
                appCatalogManager, appHost, dependencies.currentCryptaVersion(), appVaultService);
    consentService =
        appCatalogsApiHandler == null && appUpdateService == null && appServiceCoordinator == null
            ? null
            : new ConsentService(appCatalogsApiHandler, appUpdateService, appServiceCoordinator);
    consentApiHandler = consentService == null ? null : new ConsentApiHandler(consentService);
    vaultRouter = appVaultService == null ? null : new PlatformApiVaultRouter(appVaultService);
  }

  /**
   * Routes app-principal requests beneath the {@code /app-vault} endpoint family.
   *
   * @param segments decoded path segments relative to the Platform API mount point
   * @param request full request metadata, including principal and query parameters
   * @return JSON response for the selected app-vault endpoint
   */
  PlatformApiResponse routeAppVaultRequest(List<String> segments, PlatformApiRequest request) {
    if (vaultRouter == null) {
      throw notFound();
    }
    return vaultRouter.routeAppVaultRequest(segments, request, requireAppPrincipal(request));
  }

  /**
   * Routes host/operator requests beneath the {@code /identity-vault} endpoint family.
   *
   * @param segments decoded path segments relative to the Platform API mount point
   * @param request full request metadata, including principal and query parameters
   * @return JSON response for the selected identity-vault endpoint
   */
  PlatformApiResponse routeIdentityVaultRequest(List<String> segments, PlatformApiRequest request) {
    if (vaultRouter == null) {
      throw notFound();
    }
    requireHostOperator(request);
    return vaultRouter.routeIdentityVaultRequest(segments, request);
  }

  PlatformApiResponse routeConsentRequest(List<String> segments, PlatformApiRequest request) {
    if (consentApiHandler == null) {
      throw notFound();
    }
    return consentApiHandler.route(segments, request);
  }

  ConsentService consentService() {
    return consentService;
  }

  /**
   * Routes requests beneath the {@code /apps} endpoint family.
   *
   * @param segments decoded path segments relative to the Platform API mount point
   * @param request full request metadata, including query parameters
   * @return JSON response for the selected app-management endpoint
   */
  PlatformApiResponse routeAppsRequest(List<String> segments, PlatformApiRequest request) {
    if (appsApiHandler == null) {
      throw notFound();
    }
    return switch (segments.size()) {
      case 1 -> routeAppsCollection(request);
      case 2 -> routeAppsResource(segments.get(1), request);
      case 3 -> routeAppsAction(segments.get(1), segments.get(2), request);
      case 4 -> routeAppsNestedAction(segments.get(1), segments.get(2), segments.get(3), request);
      default -> throw notFound();
    };
  }

  /**
   * Routes requests beneath the {@code /app-catalogs} endpoint family.
   *
   * @param segments decoded path segments relative to the Platform API mount point
   * @param request full request metadata, including query parameters
   * @return JSON response for the selected catalog endpoint
   */
  PlatformApiResponse routeAppCatalogsRequest(List<String> segments, PlatformApiRequest request) {
    if (appCatalogsApiHandler == null) {
      throw notFound();
    }
    return switch (segments.size()) {
      case 1 -> routeAppCatalogsCollection(request);
      case 2 -> routeAppCatalogsResource(segments.get(1), request);
      case 3 -> routeAppCatalogsActionOrApps(segments.get(1), segments.get(2), request);
      case 4 ->
          routeRecommendedAppCatalogAddOrApp(
              segments.get(1), segments.get(2), segments.get(3), request);
      case 5 ->
          routeAppCatalogAppAction(
              segments.get(1), segments.get(2), segments.get(3), segments.get(4), request);
      default -> throw notFound();
    };
  }

  /**
   * Routes requests beneath the {@code /app-review} endpoint family.
   *
   * @param segments decoded path segments relative to the Platform API mount point
   * @param request full request metadata
   * @return JSON response for review governance endpoints
   */
  PlatformApiResponse routeAppReviewRequest(List<String> segments, PlatformApiRequest request) {
    if (appCatalogsApiHandler == null) {
      throw notFound();
    }
    if (!METHOD_GET.equals(request.method())) {
      return methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
    }
    if (segments.size() == 2 && "governance".equals(segments.get(1))) {
      return PlatformApiResponse.ok(envelope("governance", appCatalogsApiHandler.governance()));
    }
    if (segments.size() == 2 && "reviewer-keys".equals(segments.get(1))) {
      return PlatformApiResponse.ok(envelope("reviewerKeys", appCatalogsApiHandler.reviewerKeys()));
    }
    if (segments.size() == 2 && "transparency-log".equals(segments.get(1))) {
      return PlatformApiResponse.ok(
          envelope(
              "transparencyLog", appCatalogsApiHandler.transparencyLog(request.queryParameters())));
    }
    if (segments.size() == 3
        && "transparency-log".equals(segments.get(1))
        && "verify".equals(segments.get(2))) {
      return PlatformApiResponse.ok(
          envelope("verification", appCatalogsApiHandler.verifyTransparencyLog()));
    }
    throw notFound();
  }

  private PlatformApiResponse routeAppsCollection(PlatformApiRequest request) {
    if (!METHOD_GET.equals(request.method())) {
      return methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
    }
    return PlatformApiResponse.ok(
        envelope("apps", appsApiHandler.list(includeVaultDetails(request))));
  }

  private PlatformApiResponse routeAppsResource(
      String resourceSegment, PlatformApiRequest request) {
    if ("install".equals(resourceSegment) && !targetsInstalledAppResource(request.method())) {
      return routeAppsInstall(request);
    }
    return routeInstalledApp(resourceSegment, request);
  }

  private PlatformApiResponse routeAppsInstall(PlatformApiRequest request) {
    if (!METHOD_POST.equals(request.method())) {
      return methodNotAllowed(METHOD_POST, POST_ONLY_MESSAGE);
    }
    return PlatformApiResponse.created(
        envelope(
            "app",
            appsApiHandler.install(request.queryParameters(), includeVaultDetails(request))));
  }

  private PlatformApiResponse routeInstalledApp(String appId, PlatformApiRequest request) {
    if (METHOD_GET.equals(request.method())) {
      return PlatformApiResponse.ok(
          envelope("app", appsApiHandler.get(appId, includeVaultDetails(request))));
    }
    if (METHOD_DELETE.equals(request.method())) {
      return uninstallInstalledApp(appId, includeVaultDetails(request), preserveData(request));
    }
    return methodNotAllowed(
        "GET, DELETE", "Platform API v1 supports GET and DELETE requests only.");
  }

  private PlatformApiResponse uninstallInstalledApp(
      String appId, boolean includeVaultDetails, boolean preserveData) {
    try {
      Map<String, Object> app = appsApiHandler.uninstall(appId, includeVaultDetails, preserveData);
      clearAppStateAfterUninstall(appId, preserveData);
      return PlatformApiResponse.ok(envelope("app", app));
    } catch (PlatformApiException exception) {
      if (exception.statusCode() == 404) {
        clearAppStateAfterUninstall(appId, preserveData);
      }
      throw exception;
    } catch (RuntimeException exception) {
      if (!PlatformApiVaultRouter.isVaultException(exception)) {
        throw exception;
      }
      if (!appsApiHandler.stillInstalledBestEffort(appId)) {
        clearAppStateAfterUninstall(appId, preserveData);
      }
      throw exception;
    }
  }

  void clearAppStateAfterUninstall(String appId, boolean preserveData) {
    clearAppState(appId, preserveData);
  }

  private void clearAppState(String appId, boolean preserveData) {
    clearAppUpdateState(appId);
    clearContentSubscriptionState(appId);
    clearAppServiceState(appId);
    if (!preserveData) {
      clearAppDataState(appId);
    }
  }

  private void clearAppUpdateState(String appId) {
    if (appUpdateService != null) {
      appUpdateService.clearAppState(appId);
    }
  }

  private void clearContentSubscriptionState(String appId) {
    if (contentSubscriptionService != null) {
      try {
        contentSubscriptionService.clearAppState(appId);
      } catch (RuntimeException exception) {
        LOG.log(
            System.Logger.Level.WARNING,
            "Failed to clear content subscription state for removed app: "
                + cleanupFailureReason(exception));
      }
    }
  }

  private void clearAppDataState(String appId) {
    if (appDataService != null) {
      appDataService.clearAppState(appId);
    }
  }

  private void clearAppServiceState(String appId) {
    if (appServiceCoordinator != null) {
      appServiceCoordinator.clearAppState(appId);
    }
  }

  AppUpdateService appUpdateService() {
    return appUpdateService;
  }

  private static String cleanupFailureReason(RuntimeException exception) {
    if (exception instanceof PlatformApiException platformApiException) {
      return platformApiException.errorCode();
    }
    return exception.getClass().getSimpleName();
  }

  private static boolean includeVaultDetails(PlatformApiRequest request) {
    return !request.principal().isApp();
  }

  private static boolean preserveData(PlatformApiRequest request) {
    return !request.principal().isApp()
        && PlatformApiParameters.readBoolean(request.queryParameters(), "preserveData", false);
  }

  private static boolean targetsInstalledAppResource(String method) {
    return METHOD_GET.equals(method) || METHOD_DELETE.equals(method);
  }

  private PlatformApiResponse routeAppsAction(
      String appId, String action, PlatformApiRequest request) {
    String method = request.method();
    return switch (action) {
      case "runtime" -> {
        if (!METHOD_GET.equals(method)) {
          yield methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
        }
        yield PlatformApiResponse.ok(envelope("runtime", appsApiHandler.runtime(appId)));
      }
      case "logs" -> {
        if (!METHOD_GET.equals(method)) {
          yield methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
        }
        yield PlatformApiResponse.ok(
            envelope("logs", appsApiHandler.logs(appId, request.queryParameters())));
      }
      case "permissions" -> {
        if (!METHOD_GET.equals(method)) {
          yield methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
        }
        yield PlatformApiResponse.ok(envelope("permissions", appsApiHandler.permissions(appId)));
      }
      case "audit" -> {
        if (!METHOD_GET.equals(method)) {
          yield methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
        }
        yield PlatformApiResponse.ok(envelope("audit", appsApiHandler.audit(appId)));
      }
      case UPDATES_ROUTE_SEGMENT -> {
        if (appUpdatesApiHandler == null) {
          throw notFound();
        }
        if (!METHOD_GET.equals(method)) {
          yield methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
        }
        yield PlatformApiResponse.ok(
            envelope(UPDATES_ROUTE_SEGMENT, appUpdatesApiHandler.summary(appId)));
      }
      case "start" -> {
        if (!METHOD_POST.equals(method)) {
          yield methodNotAllowed(METHOD_POST, POST_ONLY_MESSAGE);
        }
        yield PlatformApiResponse.ok(
            envelope("app", appsApiHandler.start(appId, includeVaultDetails(request))));
      }
      case "stop" -> {
        if (!METHOD_POST.equals(method)) {
          yield methodNotAllowed(METHOD_POST, POST_ONLY_MESSAGE);
        }
        yield PlatformApiResponse.ok(
            envelope("app", appsApiHandler.stop(appId, includeVaultDetails(request))));
      }
      case "update" -> {
        if (!METHOD_POST.equals(method)) {
          yield methodNotAllowed(METHOD_POST, POST_ONLY_MESSAGE);
        }
        yield PlatformApiResponse.ok(
            envelope(
                "app",
                appsApiHandler.update(
                    appId, request.queryParameters(), includeVaultDetails(request))));
      }
      default -> throw notFound();
    };
  }

  private PlatformApiResponse routeAppsNestedAction(
      String appId, String resource, String action, PlatformApiRequest request) {
    if (!UPDATES_ROUTE_SEGMENT.equals(resource) || appUpdatesApiHandler == null) {
      throw notFound();
    }
    return switch (action) {
      case "check" -> {
        if (!METHOD_POST.equals(request.method())) {
          yield methodNotAllowed(METHOD_POST, POST_ONLY_MESSAGE);
        }
        yield PlatformApiResponse.ok(
            envelope(
                UPDATES_ROUTE_SEGMENT,
                appUpdatesApiHandler.check(appId, request.queryParameters())));
      }
      case "stage" -> {
        if (!METHOD_POST.equals(request.method())) {
          yield methodNotAllowed(METHOD_POST, POST_ONLY_MESSAGE);
        }
        Map<String, List<String>> queryParameters =
            consentService == null
                ? request.queryParameters()
                : consentService.requireApprovedUpdateIfRequired(
                    appId, request.queryParameters(), request.principal());
        yield PlatformApiResponse.ok(
            envelope(UPDATES_ROUTE_SEGMENT, appUpdatesApiHandler.stage(appId, queryParameters)));
      }
      case "apply" -> {
        if (!METHOD_POST.equals(request.method())) {
          yield methodNotAllowed(METHOD_POST, POST_ONLY_MESSAGE);
        }
        yield PlatformApiResponse.ok(
            envelope(
                UPDATES_ROUTE_SEGMENT,
                appUpdatesApiHandler.apply(appId, request.queryParameters())));
      }
      case "rollback" -> {
        if (!METHOD_POST.equals(request.method())) {
          yield methodNotAllowed(METHOD_POST, POST_ONLY_MESSAGE);
        }
        yield PlatformApiResponse.ok(
            envelope(
                UPDATES_ROUTE_SEGMENT,
                appUpdatesApiHandler.rollback(appId, request.queryParameters())));
      }
      case POLICY_ROUTE_SEGMENT -> routeAppUpdatesPolicy(appId, request);
      default -> throw notFound();
    };
  }

  private PlatformApiResponse routeAppUpdatesPolicy(String appId, PlatformApiRequest request) {
    if (METHOD_GET.equals(request.method())) {
      return PlatformApiResponse.ok(
          envelope(POLICY_ROUTE_SEGMENT, appUpdatesApiHandler.policy(appId)));
    }
    if (METHOD_POST.equals(request.method())) {
      return PlatformApiResponse.ok(
          envelope(
              POLICY_ROUTE_SEGMENT,
              appUpdatesApiHandler.setPolicy(appId, request.queryParameters())));
    }
    return methodNotAllowed(METHODS_GET_POST, GET_POST_ONLY_MESSAGE);
  }

  private PlatformApiResponse routeAppCatalogsCollection(PlatformApiRequest request) {
    if (!METHOD_GET.equals(request.method())) {
      return methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
    }
    return PlatformApiResponse.ok(envelope("catalogs", appCatalogsApiHandler.listCatalogs()));
  }

  private PlatformApiResponse routeAppCatalogsResource(
      String resource, PlatformApiRequest request) {
    if (METHOD_DELETE.equals(request.method())) {
      return PlatformApiResponse.ok(
          envelope(CATALOG_ENVELOPE_KEY, appCatalogsApiHandler.remove(resource)));
    }
    if ("recommended".equals(resource)) {
      return routeRecommendedAppCatalogs(request);
    }
    if ("add".equals(resource)) {
      if (!METHOD_POST.equals(request.method())) {
        return methodNotAllowed(METHOD_POST, POST_ONLY_MESSAGE);
      }
      return PlatformApiResponse.created(
          envelope(CATALOG_ENVELOPE_KEY, appCatalogsApiHandler.add(request.queryParameters())));
    }
    return methodNotAllowed(METHOD_DELETE, "Platform API v1 supports DELETE requests only.");
  }

  private PlatformApiResponse routeRecommendedAppCatalogs(PlatformApiRequest request) {
    if (!METHOD_GET.equals(request.method())) {
      return methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
    }
    return PlatformApiResponse.ok(
        envelope("catalogs", appCatalogsApiHandler.listRecommendedCatalogs()));
  }

  private PlatformApiResponse routeAppCatalogsActionOrApps(
      String catalogId, String action, PlatformApiRequest request) {
    if ("refresh".equals(action)) {
      if (!METHOD_POST.equals(request.method())) {
        return methodNotAllowed(METHOD_POST, POST_ONLY_MESSAGE);
      }
      return PlatformApiResponse.ok(
          envelope(CATALOG_ENVELOPE_KEY, appCatalogsApiHandler.refresh(catalogId)));
    }
    if ("mirrors".equals(action)) {
      if (METHOD_GET.equals(request.method())) {
        return PlatformApiResponse.ok(
            envelope("mirrors", appCatalogsApiHandler.mirrors(catalogId)));
      }
      if (METHOD_POST.equals(request.method())) {
        return PlatformApiResponse.created(
            envelope(
                "mirror", appCatalogsApiHandler.addMirror(catalogId, request.queryParameters())));
      }
      return methodNotAllowed(METHODS_GET_POST, GET_POST_ONLY_MESSAGE);
    }
    if ("apps".equals(action)) {
      if (!METHOD_GET.equals(request.method())) {
        return methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
      }
      return PlatformApiResponse.ok(envelope("apps", appCatalogsApiHandler.listApps(catalogId)));
    }
    throw notFound();
  }

  private PlatformApiResponse routeRecommendedAppCatalogAddOrApp(
      String firstSegment, String secondSegment, String thirdSegment, PlatformApiRequest request) {
    if ("recommended".equals(firstSegment) && "add".equals(thirdSegment)) {
      if (!METHOD_POST.equals(request.method()) && !"apps".equals(secondSegment)) {
        return methodNotAllowed(METHOD_POST, POST_ONLY_MESSAGE);
      }
      if (METHOD_POST.equals(request.method())) {
        return PlatformApiResponse.created(
            envelope(CATALOG_ENVELOPE_KEY, appCatalogsApiHandler.addRecommended(secondSegment)));
      }
    }
    if ("operations".equals(secondSegment)) {
      return routeAppCatalogOperation(firstSegment, thirdSegment, request);
    }
    if ("mirrors".equals(secondSegment)) {
      return routeAppCatalogMirror(firstSegment, thirdSegment, request);
    }
    return routeAppCatalogApp(firstSegment, secondSegment, thirdSegment, request);
  }

  private PlatformApiResponse routeAppCatalogOperation(
      String catalogId, String operation, PlatformApiRequest request) {
    return switch (operation) {
      case "health" -> {
        if (!METHOD_GET.equals(request.method())) {
          yield methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
        }
        yield PlatformApiResponse.ok(envelope("health", appCatalogsApiHandler.health(catalogId)));
      }
      case "revisions" -> {
        if (!METHOD_GET.equals(request.method())) {
          yield methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
        }
        yield PlatformApiResponse.ok(
            envelope("revisions", appCatalogsApiHandler.rollbackCandidates(catalogId)));
      }
      case "key-rotation" -> {
        if (!METHOD_GET.equals(request.method())) {
          yield methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
        }
        yield PlatformApiResponse.ok(
            envelope("keyRotation", appCatalogsApiHandler.keyRotationStatus(catalogId)));
      }
      case "refresh-primary" -> {
        if (!METHOD_POST.equals(request.method())) {
          yield methodNotAllowed(METHOD_POST, POST_ONLY_MESSAGE);
        }
        yield PlatformApiResponse.ok(
            envelope(CATALOG_ENVELOPE_KEY, appCatalogsApiHandler.refreshPrimaryOnly(catalogId)));
      }
      case "rollback" -> {
        if (!METHOD_POST.equals(request.method())) {
          yield methodNotAllowed(METHOD_POST, POST_ONLY_MESSAGE);
        }
        yield PlatformApiResponse.ok(
            envelope(
                CATALOG_ENVELOPE_KEY,
                appCatalogsApiHandler.rollback(catalogId, request.queryParameters())));
      }
      case "emergency-refresh" -> {
        if (!METHOD_POST.equals(request.method())) {
          yield methodNotAllowed(METHOD_POST, POST_ONLY_MESSAGE);
        }
        yield PlatformApiResponse.ok(
            envelope("emergencyRefresh", appCatalogsApiHandler.emergencyRefresh(catalogId)));
      }
      default -> throw notFound();
    };
  }

  private PlatformApiResponse routeAppCatalogMirror(
      String catalogId, String mirrorId, PlatformApiRequest request) {
    if (METHOD_POST.equals(request.method())) {
      return PlatformApiResponse.ok(
          envelope(
              "mirror",
              appCatalogsApiHandler.updateMirror(catalogId, mirrorId, request.queryParameters())));
    }
    if (METHOD_DELETE.equals(request.method())) {
      return PlatformApiResponse.ok(
          envelope("mirror", appCatalogsApiHandler.removeMirror(catalogId, mirrorId)));
    }
    return methodNotAllowed(
        "POST, DELETE", "Platform API v1 supports POST and DELETE requests only.");
  }

  private PlatformApiResponse routeAppCatalogApp(
      String catalogId, String appsSegment, String appId, PlatformApiRequest request) {
    if (!"apps".equals(appsSegment)) {
      throw notFound();
    }
    if (!METHOD_GET.equals(request.method())) {
      return methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
    }
    return PlatformApiResponse.ok(envelope("app", appCatalogsApiHandler.getApp(catalogId, appId)));
  }

  private PlatformApiResponse routeAppCatalogAppAction(
      String catalogId,
      String appsSegment,
      String appId,
      String action,
      PlatformApiRequest request) {
    if (!"apps".equals(appsSegment)) {
      throw notFound();
    }
    if ("review-history".equals(action)) {
      if (!METHOD_GET.equals(request.method())) {
        return methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
      }
      return PlatformApiResponse.ok(
          envelope("reviewHistory", appCatalogsApiHandler.reviewHistory(catalogId, appId)));
    }
    if (!METHOD_POST.equals(request.method())) {
      return methodNotAllowed(METHOD_POST, POST_ONLY_MESSAGE);
    }
    return switch (action) {
      case "install" ->
          PlatformApiResponse.created(
              envelope("app", installCatalogApp(catalogId, appId, request)));
      case "update" ->
          PlatformApiResponse.ok(envelope("app", updateCatalogApp(catalogId, appId, request)));
      default -> throw notFound();
    };
  }

  private Map<String, Object> installCatalogApp(
      String catalogId, String appId, PlatformApiRequest request) {
    if (consentService == null) {
      return appCatalogsApiHandler.install(catalogId, appId, request.queryParameters());
    }
    appCatalogsApiHandler.requireInstallPreconditions(catalogId, appId);
    Map<String, List<String>> consentParameters =
        consentService.requireApprovedInstallIfRequired(
            catalogId, appId, request.queryParameters(), request.principal());
    return appCatalogsApiHandler.install(
        catalogId,
        appId,
        consentParameters,
        (preparedCatalogId, preparedEntry) ->
            consentService.requireApprovedPreparedInstallIfRequired(
                preparedCatalogId, preparedEntry, consentParameters, request.principal()));
  }

  private Map<String, Object> updateCatalogApp(
      String catalogId, String appId, PlatformApiRequest request) {
    if (consentService == null) {
      return appCatalogsApiHandler.update(catalogId, appId, request.queryParameters());
    }
    appCatalogsApiHandler.requireUpdatePreconditions(catalogId, appId);
    Map<String, List<String>> consentParameters =
        consentService.requireApprovedCatalogUpdateIfRequired(
            catalogId, appId, request.queryParameters(), request.principal());
    return appCatalogsApiHandler.update(
        catalogId,
        appId,
        consentParameters,
        (preparedCatalogId, preparedEntry) ->
            consentService.requireApprovedPreparedCatalogUpdateIfRequired(
                preparedCatalogId, preparedEntry, consentParameters, request.principal()));
  }

  private static String requireAppPrincipal(PlatformApiRequest request) {
    if (!request.principal().isApp() || request.principal().appId() == null) {
      throw new PlatformApiException(
          403, "app_principal_required", "This Platform API route requires an app principal.");
    }
    return request.principal().appId();
  }

  private static void requireHostOperator(PlatformApiRequest request) {
    if (request.principal().isApp()) {
      throw new PlatformApiException(
          403,
          "host_operator_required",
          "This Platform API route requires a host/operator principal.");
    }
  }

  private static PlatformApiException notFound() {
    return new PlatformApiException(404, "not_found", "Platform API route not found.");
  }

  private static PlatformApiResponse methodNotAllowed(String allow, String message) {
    return PlatformApiResponse.error(405, Map.of("Allow", allow), "method_not_allowed", message);
  }

  private static Map<String, Object> envelope(String key, Object value) {
    return Map.of(key, value);
  }
}

package network.crypta.platform.api;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import network.crypta.platform.api.alerts.AlertsApiHandler;
import network.crypta.platform.api.appcatalogs.AppCatalogsApiHandler;
import network.crypta.platform.api.apps.AppsApiHandler;
import network.crypta.platform.api.appupdates.AppUpdateService;
import network.crypta.platform.api.appupdates.AppUpdatesApiHandler;
import network.crypta.platform.api.config.ConfigApiHandler;
import network.crypta.platform.api.connectivity.ConnectivityApiHandler;
import network.crypta.platform.api.diagnostics.DiagnosticsApiHandler;
import network.crypta.platform.api.node.NodeApiHandler;
import network.crypta.platform.api.peers.PeersApiHandler;
import network.crypta.platform.api.queue.QueueApiHandler;
import network.crypta.platform.api.security.SecurityLevelsApiHandler;
import network.crypta.platform.api.updates.UpdatesApiHandler;
import network.crypta.platform.api.wizard.FirstTimeWizardApiHandler;
import network.crypta.platform.appcatalog.AppCatalogManager;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.appui.AppUiOriginRegistry;
import network.crypta.runtime.spi.LegacyAdminUsagePort;
import network.crypta.runtime.spi.RuntimePorts;

/**
 * Routes transport-neutral Platform API requests onto detached runtime ports.
 *
 * <p>The router keeps the Platform API v1 surface small and predictable. It accepts one request
 * descriptor, validates the method and relative path beneath {@link
 * PlatformApiPaths#API_V1_PREFIX}, delegates to the relevant endpoint family, and emits a JSON
 * response with stable status codes for malformed requests and missing resources.
 */
public final class PlatformApiRouter {
  /** Logger used for unexpected failures that escape endpoint-specific validation. */
  private static final System.Logger LOG = System.getLogger(PlatformApiRouter.class.getName());

  /** Shared 405 message for routes that only support GET. */
  private static final String GET_ONLY_MESSAGE = "Platform API v1 supports GET requests only.";

  /** Shared 405 message for routes that only support POST. */
  private static final String POST_ONLY_MESSAGE = "Platform API v1 supports POST requests only.";

  /** HTTP-style method name for DELETE routes. */
  private static final String METHOD_DELETE = "DELETE";

  /** Envelope key for one catalog summary. */
  private static final String CATALOG_ENVELOPE_KEY = "catalog";

  /** Shared route segment and envelope key for app-update lifecycle responses. */
  private static final String UPDATES_ROUTE_SEGMENT = "updates";

  /** Shared route segment and envelope key for app-update policy responses. */
  private static final String POLICY_ROUTE_SEGMENT = "policy";

  /** Handler for the {@code /node/...} endpoint family. */
  private final NodeApiHandler nodeApiHandler;

  /** Handler for the {@code /peers/...} endpoint family. */
  private final PeersApiHandler peersApiHandler;

  /** Handler for the {@code /config} endpoint. */
  private final ConfigApiHandler configApiHandler;

  /** Handler for the {@code /connectivity} endpoint. */
  private final ConnectivityApiHandler connectivityApiHandler;

  /** Handler for the {@code /security-levels} endpoint. */
  private final SecurityLevelsApiHandler securityLevelsApiHandler;

  /** Handler for the {@code /updates/core} endpoint family. */
  private final UpdatesApiHandler updatesApiHandler;

  /** Handler for the {@code /wizard/first-time} endpoint family. */
  private final FirstTimeWizardApiHandler firstTimeWizardApiHandler;

  /** Handler for the {@code /queue/...} endpoint family. */
  private final QueueApiHandler queueApiHandler;

  /** Handler for the {@code /alerts/...} endpoint family. */
  private final AlertsApiHandler alertsApiHandler;

  /** Handler for the {@code /diagnostics} endpoint family. */
  private final DiagnosticsApiHandler diagnosticsApiHandler;

  /** Handler for the {@code /apps/...} endpoint family, when AppHost support is available. */
  private final AppsApiHandler appsApiHandler;

  /** Handler for the {@code /apps/{appId}/updates/...} endpoint family. */
  private final AppUpdatesApiHandler appUpdatesApiHandler;

  /** App-update lifecycle coordinator shared by update routes and app uninstall cleanup. */
  private final AppUpdateService appUpdateService;

  /** Bounded process-local audit log for app-originated authorization decisions. */
  private final AppAuditLog appAuditLog;

  /**
   * Handler for the {@code /app-catalogs/...} endpoint family, when catalog support is available.
   */
  private final AppCatalogsApiHandler appCatalogsApiHandler;

  /**
   * Creates a router backed by the supplied runtime ports.
   *
   * @param runtimePorts detached runtime-port aggregate used to resolve API requests
   * @throws NullPointerException if {@code runtimePorts} is {@code null}
   */
  @SuppressWarnings("unused")
  public PlatformApiRouter(RuntimePorts runtimePorts) {
    this(runtimePorts, null, null);
  }

  /**
   * Creates a router backed by the supplied runtime ports and AppHost instance.
   *
   * @param runtimePorts detached runtime-port aggregate used to resolve API requests
   * @param appHost detached AppHost used by the app-management endpoint family
   * @throws NullPointerException if {@code runtimePorts} is {@code null}
   */
  public PlatformApiRouter(RuntimePorts runtimePorts, AppHost appHost) {
    this(runtimePorts, appHost, null);
  }

  /**
   * Creates a router backed by runtime ports, AppHost, and signed app catalogs.
   *
   * @param runtimePorts detached runtime-port aggregate used to resolve API requests
   * @param appHost detached AppHost used by app lifecycle and catalog install/update routes
   * @param appCatalogManager signed catalog manager used by the catalog endpoint family
   * @throws NullPointerException if {@code runtimePorts} is {@code null}
   */
  public PlatformApiRouter(
      RuntimePorts runtimePorts, AppHost appHost, AppCatalogManager appCatalogManager) {
    this(runtimePorts, appHost, appCatalogManager, null);
  }

  /**
   * Creates a router backed by runtime ports, AppHost, signed app catalogs, and optional
   * legacy-admin usage diagnostics.
   *
   * @param runtimePorts detached runtime-port aggregate used to resolve API requests
   * @param appHost detached AppHost used by app lifecycle and catalog install/update routes
   * @param appCatalogManager signed catalog manager used by the catalog endpoint family
   * @param legacyAdminUsage optional process-local legacy admin usage source
   * @throws NullPointerException if {@code runtimePorts} is {@code null}
   */
  public PlatformApiRouter(
      RuntimePorts runtimePorts,
      AppHost appHost,
      AppCatalogManager appCatalogManager,
      LegacyAdminUsagePort legacyAdminUsage) {
    this(
        runtimePorts,
        appHost,
        appCatalogManager,
        legacyAdminUsage,
        new AppAuditLog(),
        AppUiOriginRegistry.sameOriginOnly());
  }

  /**
   * Creates a router backed by runtime ports, AppHost, signed catalogs, diagnostics, and app UI
   * origin metadata.
   *
   * @param runtimePorts detached runtime-port aggregate used to resolve API requests
   * @param appHost detached AppHost used by app lifecycle and catalog install/update routes
   * @param appCatalogManager signed catalog manager used by the catalog endpoint family
   * @param legacyAdminUsage optional process-local legacy admin usage source
   * @param appUiOriginRegistry registry used to publish isolated app UI launch URLs
   */
  public PlatformApiRouter(
      RuntimePorts runtimePorts,
      AppHost appHost,
      AppCatalogManager appCatalogManager,
      LegacyAdminUsagePort legacyAdminUsage,
      AppUiOriginRegistry appUiOriginRegistry) {
    this(
        runtimePorts,
        appHost,
        appCatalogManager,
        legacyAdminUsage,
        new AppAuditLog(),
        appUiOriginRegistry);
  }

  PlatformApiRouter(
      RuntimePorts runtimePorts,
      AppHost appHost,
      AppCatalogManager appCatalogManager,
      LegacyAdminUsagePort legacyAdminUsage,
      AppAuditLog appAuditLog) {
    this(
        runtimePorts,
        appHost,
        appCatalogManager,
        legacyAdminUsage,
        appAuditLog,
        AppUiOriginRegistry.sameOriginOnly());
  }

  PlatformApiRouter(
      RuntimePorts runtimePorts,
      AppHost appHost,
      AppCatalogManager appCatalogManager,
      LegacyAdminUsagePort legacyAdminUsage,
      AppAuditLog appAuditLog,
      AppUiOriginRegistry appUiOriginRegistry) {
    Objects.requireNonNull(runtimePorts, "runtimePorts");
    this.appAuditLog = Objects.requireNonNull(appAuditLog, "appAuditLog");
    Objects.requireNonNull(appUiOriginRegistry, "appUiOriginRegistry");
    nodeApiHandler = new NodeApiHandler(runtimePorts.nodeInfo());
    peersApiHandler = new PeersApiHandler(runtimePorts.peer(), runtimePorts.darknetConnections());
    configApiHandler = new ConfigApiHandler(runtimePorts.config());
    connectivityApiHandler = new ConnectivityApiHandler(runtimePorts.connectivity());
    securityLevelsApiHandler =
        new SecurityLevelsApiHandler(
            runtimePorts.securityLevels(), runtimePorts.config(), runtimePorts.firstTimeWizard());
    updatesApiHandler = new UpdatesApiHandler(runtimePorts.coreUpdateAction());
    firstTimeWizardApiHandler = new FirstTimeWizardApiHandler(runtimePorts.firstTimeWizard());
    queueApiHandler =
        new QueueApiHandler(
            runtimePorts.queuePage(),
            runtimePorts.queueMutation(),
            runtimePorts.queueDownload(),
            runtimePorts.queueInsert(),
            runtimePorts.queueSupport(),
            runtimePorts.queueCompletion());
    alertsApiHandler = new AlertsApiHandler(runtimePorts.alertFeed(), runtimePorts.alertMutation());
    diagnosticsApiHandler = new DiagnosticsApiHandler(runtimePorts.diagnostic(), legacyAdminUsage);
    appsApiHandler =
        appHost == null ? null : new AppsApiHandler(appHost, this.appAuditLog, appUiOriginRegistry);
    appUpdateService =
        appHost == null || appCatalogManager == null
            ? null
            : new AppUpdateService(appHost, appCatalogManager);
    appUpdatesApiHandler =
        appUpdateService == null ? null : new AppUpdatesApiHandler(appUpdateService);
    appCatalogsApiHandler =
        appHost == null || appCatalogManager == null
            ? null
            : new AppCatalogsApiHandler(appCatalogManager, appHost, this::currentCryptaVersion);
  }

  /**
   * Routes one request and returns the corresponding JSON response.
   *
   * <p>Known request validation failures are converted into structured error responses. Unexpected
   * runtime failures are allowed to propagate so the transport-specific bridge can log them and map
   * them onto a generic {@code 500} response.
   *
   * @param request transport-neutral request metadata to route
   * @return JSON response for the routed endpoint
   */
  public PlatformApiResponse route(PlatformApiRequest request) {
    PlatformApiRequest checkedRequest = Objects.requireNonNull(request, "request");
    PlatformApiAuthorizationDecision authorization =
        PlatformApiCapabilities.authorize(checkedRequest);
    if (!authorization.allowed()) {
      PlatformApiResponse response =
          PlatformApiResponse.error(
              403, "forbidden", "App principal lacks the required Platform API capability.");
      appAuditLog.appendDecision(
          checkedRequest,
          authorization,
          AppAuditDecision.DENIED,
          response.statusCode(),
          authorization.reasonCode());
      return response;
    }

    try {
      PlatformApiResponse response = routeInternal(checkedRequest);
      appAuditLog.appendDecision(
          checkedRequest,
          authorization,
          AppAuditDecision.ALLOWED,
          response.statusCode(),
          "route_completed");
      return response;
    } catch (PlatformApiException e) {
      PlatformApiResponse response =
          PlatformApiResponse.error(e.statusCode(), e.errorCode(), e.getMessage());
      appAuditLog.appendDecision(
          checkedRequest,
          authorization,
          AppAuditDecision.ALLOWED,
          response.statusCode(),
          e.errorCode());
      return response;
    } catch (RuntimeException e) {
      LOG.log(System.Logger.Level.ERROR, "Unexpected Platform API failure", e);
      PlatformApiResponse response =
          PlatformApiResponse.error(500, "internal_error", "Unexpected platform API failure.");
      appAuditLog.appendDecision(
          checkedRequest,
          authorization,
          AppAuditDecision.ALLOWED,
          response.statusCode(),
          "internal_error");
      return response;
    }
  }

  /**
   * Performs method and path validation after null checking has already completed.
   *
   * @param request non-null transport-neutral request metadata
   * @return JSON response for the routed endpoint or a structured error response
   */
  private PlatformApiResponse routeInternal(PlatformApiRequest request) {
    List<String> segments = request.pathSegments();
    if (segments.isEmpty()) {
      throw new PlatformApiException(404, "not_found", "Platform API route not found.");
    }

    String firstSegment = segments.getFirst();
    if ("platform".equals(firstSegment)) {
      return routePlatformRequest(segments, request);
    }
    if ("app-catalogs".equals(firstSegment)) {
      return routeAppCatalogsRequest(segments, request);
    }
    if ("apps".equals(firstSegment)) {
      return routeAppsRequest(segments, request);
    }
    if ("queue".equals(firstSegment)) {
      return routeQueueRequest(segments, request);
    }
    if ("peers".equals(firstSegment)) {
      return routePeersRequest(segments, request);
    }
    if ("config".equals(firstSegment)) {
      return routeConfigRequest(segments, request);
    }
    if ("security-levels".equals(firstSegment)) {
      return routeSecurityLevelsRequest(segments, request);
    }
    if (UPDATES_ROUTE_SEGMENT.equals(firstSegment)) {
      return routeUpdatesRequest(segments, request);
    }
    if ("wizard".equals(firstSegment)) {
      return routeWizardRequest(segments, request);
    }
    if ("alerts".equals(firstSegment)) {
      return routeAlertsRequest(segments, request);
    }

    return routeGetOnlyRequest(segments, request, firstSegment);
  }

  private PlatformApiResponse routePlatformRequest(
      List<String> segments, PlatformApiRequest request) {
    if (segments.size() == 2 && "contract".equals(segments.get(1))) {
      if (!"GET".equals(request.method())) {
        return methodNotAllowed("GET", GET_ONLY_MESSAGE);
      }
      return PlatformApiResponse.ok(
          PlatformApiContractJson.envelope(PlatformApiContract.current()));
    }
    throw new PlatformApiException(404, "not_found", "Platform API route not found.");
  }

  private String currentCryptaVersion() {
    var greeting = nodeApiHandler.rawGreeting();
    return greeting == null ? null : Integer.toString(greeting.buildNumber());
  }

  private PlatformApiResponse routeGetOnlyRequest(
      List<String> segments, PlatformApiRequest request, String firstSegment) {
    if (!"GET".equals(request.method())) {
      return methodNotAllowed("GET", GET_ONLY_MESSAGE);
    }
    if ("node".equals(firstSegment)) {
      return routeNodeRequest(segments, request);
    }
    if ("connectivity".equals(firstSegment) && segments.size() == 1) {
      return PlatformApiResponse.ok(connectivityApiHandler.snapshot(request.queryParameters()));
    }
    if ("diagnostics".equals(firstSegment) && segments.size() == 1) {
      return PlatformApiResponse.ok(diagnosticsApiHandler.snapshot());
    }
    throw new PlatformApiException(404, "not_found", "Platform API route not found.");
  }

  /**
   * Routes requests beneath the {@code /alerts} endpoint family.
   *
   * @param segments decoded path segments relative to the Platform API mount point
   * @param request full request metadata, including query parameters
   * @return JSON response for the selected alert endpoint
   */
  private PlatformApiResponse routeAlertsRequest(
      List<String> segments, PlatformApiRequest request) {
    return switch (segments.size()) {
      case 1 -> routeAlertsCollection(request);
      case 3 -> routeAlertAction(segments.get(1), segments.get(2), request);
      default -> throw new PlatformApiException(404, "not_found", "Platform API route not found.");
    };
  }

  private PlatformApiResponse routeAlertsCollection(PlatformApiRequest request) {
    if (!"GET".equals(request.method())) {
      return methodNotAllowed("GET", GET_ONLY_MESSAGE);
    }
    return PlatformApiResponse.ok(alertsApiHandler.list());
  }

  private PlatformApiResponse routeAlertAction(
      String alertIdSegment, String action, PlatformApiRequest request) {
    if (!"POST".equals(request.method())) {
      return methodNotAllowed("POST", POST_ONLY_MESSAGE);
    }
    if ("dismiss".equals(action)) {
      return PlatformApiResponse.ok(alertsApiHandler.dismiss(alertIdSegment));
    }
    throw new PlatformApiException(404, "not_found", "Platform API route not found.");
  }

  /**
   * Routes requests beneath the {@code /config} endpoint family.
   *
   * @param segments decoded path segments relative to the Platform API mount point
   * @param request full request metadata, including query parameters
   * @return JSON response for the selected configuration endpoint
   */
  private PlatformApiResponse routeConfigRequest(
      List<String> segments, PlatformApiRequest request) {
    return switch (segments.size()) {
      case 1 -> routeConfigRoot(request);
      case 2 -> routeConfigAction(segments.get(1), request);
      default -> throw new PlatformApiException(404, "not_found", "Platform API route not found.");
    };
  }

  private PlatformApiResponse routeConfigRoot(PlatformApiRequest request) {
    if (!"GET".equals(request.method())) {
      return methodNotAllowed("GET", GET_ONLY_MESSAGE);
    }
    return PlatformApiResponse.ok(configApiHandler.exportConfig(request.queryParameters()));
  }

  private PlatformApiResponse routeConfigAction(String action, PlatformApiRequest request) {
    if ("overrides".equals(action)) {
      if (!"POST".equals(request.method())) {
        return methodNotAllowed("POST", POST_ONLY_MESSAGE);
      }
      return PlatformApiResponse.ok(configApiHandler.applyOverrides(request.queryParameters()));
    }
    if ("persist".equals(action)) {
      if (!"POST".equals(request.method())) {
        return methodNotAllowed("POST", POST_ONLY_MESSAGE);
      }
      return PlatformApiResponse.ok(configApiHandler.persist());
    }
    throw new PlatformApiException(404, "not_found", "Platform API route not found.");
  }

  /**
   * Routes requests beneath the {@code /security-levels} endpoint family.
   *
   * @param segments decoded path segments relative to the Platform API mount point
   * @param request full request metadata, including query parameters
   * @return JSON response for the selected security-levels endpoint
   */
  private PlatformApiResponse routeSecurityLevelsRequest(
      List<String> segments, PlatformApiRequest request) {
    return switch (segments.size()) {
      case 1 -> routeSecurityLevelsRoot(request);
      case 2 -> routeSecurityLevelsAction(segments.get(1), request);
      default -> throw new PlatformApiException(404, "not_found", "Platform API route not found.");
    };
  }

  private PlatformApiResponse routeSecurityLevelsRoot(PlatformApiRequest request) {
    if (!"GET".equals(request.method())) {
      return methodNotAllowed("GET", GET_ONLY_MESSAGE);
    }
    return PlatformApiResponse.ok(securityLevelsApiHandler.snapshot());
  }

  private PlatformApiResponse routeSecurityLevelsAction(String action, PlatformApiRequest request) {
    if ("network-warning".equals(action)) {
      if (!"GET".equals(request.method())) {
        return methodNotAllowed("GET", GET_ONLY_MESSAGE);
      }
      return PlatformApiResponse.ok(
          securityLevelsApiHandler.networkThreatLevelWarning(request.queryParameters()));
    }
    if ("network".equals(action)) {
      if (!"POST".equals(request.method())) {
        return methodNotAllowed("POST", POST_ONLY_MESSAGE);
      }
      return PlatformApiResponse.ok(
          securityLevelsApiHandler.setNetworkThreatLevel(request.queryParameters()));
    }
    if ("physical".equals(action)) {
      if (!"POST".equals(request.method())) {
        return methodNotAllowed("POST", POST_ONLY_MESSAGE);
      }
      return PlatformApiResponse.ok(
          securityLevelsApiHandler.setPhysicalThreatLevel(request.queryParameters()));
    }
    throw new PlatformApiException(404, "not_found", "Platform API route not found.");
  }

  /**
   * Routes requests beneath the {@code /updates} endpoint family.
   *
   * @param segments decoded path segments relative to the Platform API mount point
   * @param request full request metadata, including query parameters
   * @return JSON response for the selected update endpoint
   */
  private PlatformApiResponse routeUpdatesRequest(
      List<String> segments, PlatformApiRequest request) {
    if (segments.size() == 2 && "core".equals(segments.get(1))) {
      if (!"GET".equals(request.method())) {
        return methodNotAllowed("GET", GET_ONLY_MESSAGE);
      }
      return PlatformApiResponse.ok(updatesApiHandler.coreSnapshot());
    }
    if (segments.size() == 3
        && "core".equals(segments.get(1))
        && "download".equals(segments.get(2))) {
      if (!"POST".equals(request.method())) {
        return methodNotAllowed("POST", POST_ONLY_MESSAGE);
      }
      return PlatformApiResponse.ok(updatesApiHandler.startCoreDownload());
    }
    throw new PlatformApiException(404, "not_found", "Platform API route not found.");
  }

  /**
   * Routes requests beneath the {@code /wizard} endpoint family.
   *
   * @param segments decoded path segments relative to the Platform API mount point
   * @param request full request metadata, including query parameters
   * @return JSON response for the selected wizard endpoint
   */
  private PlatformApiResponse routeWizardRequest(
      List<String> segments, PlatformApiRequest request) {
    if (segments.size() == 2 && "first-time".equals(segments.get(1))) {
      if (!"GET".equals(request.method())) {
        return methodNotAllowed("GET", GET_ONLY_MESSAGE);
      }
      return PlatformApiResponse.ok(firstTimeWizardApiHandler.snapshot());
    }
    if (segments.size() == 3
        && "first-time".equals(segments.get(1))
        && "apply".equals(segments.get(2))) {
      if (!"POST".equals(request.method())) {
        return methodNotAllowed("POST", POST_ONLY_MESSAGE);
      }
      return PlatformApiResponse.ok(firstTimeWizardApiHandler.apply(request.queryParameters()));
    }
    throw new PlatformApiException(404, "not_found", "Platform API route not found.");
  }

  /**
   * Routes requests beneath the {@code /apps} endpoint family.
   *
   * @param segments decoded path segments relative to the Platform API mount point
   * @param request full request metadata, including query parameters
   * @return JSON response for the selected app-management endpoint
   * @throws PlatformApiException if the path or method does not identify a supported app endpoint
   */
  private PlatformApiResponse routeAppsRequest(List<String> segments, PlatformApiRequest request) {
    if (appsApiHandler == null) {
      throw new PlatformApiException(404, "not_found", "Platform API route not found.");
    }

    return switch (segments.size()) {
      case 1 -> routeAppsCollection(request.method());
      case 2 -> routeAppsResource(segments.get(1), request);
      case 3 -> routeAppsAction(segments.get(1), segments.get(2), request);
      case 4 -> routeAppsNestedAction(segments.get(1), segments.get(2), segments.get(3), request);
      default -> throw new PlatformApiException(404, "not_found", "Platform API route not found.");
    };
  }

  /**
   * Routes the {@code /apps} collection endpoint.
   *
   * @param method HTTP-style request method
   * @return JSON response for the app collection
   */
  private PlatformApiResponse routeAppsCollection(String method) {
    if (!"GET".equals(method)) {
      return methodNotAllowed("GET", GET_ONLY_MESSAGE);
    }
    return PlatformApiResponse.ok(envelope("apps", appsApiHandler.list()));
  }

  /**
   * Routes either one installed-app resource or the installation endpoint.
   *
   * @param resourceSegment second path segment beneath {@code /apps}
   * @param request full request metadata, including query parameters
   * @return JSON response for the selected app endpoint
   */
  private PlatformApiResponse routeAppsResource(
      String resourceSegment, PlatformApiRequest request) {
    if ("install".equals(resourceSegment) && !targetsInstalledAppResource(request.method())) {
      return routeAppsInstall(request);
    }
    return routeInstalledApp(resourceSegment, request.method());
  }

  /**
   * Routes the {@code /apps/install} endpoint.
   *
   * @param request full request metadata, including query parameters
   * @return JSON response for the installation operation
   */
  private PlatformApiResponse routeAppsInstall(PlatformApiRequest request) {
    if (!"POST".equals(request.method())) {
      return methodNotAllowed("POST", POST_ONLY_MESSAGE);
    }
    return PlatformApiResponse.created(
        envelope("app", appsApiHandler.install(request.queryParameters())));
  }

  /**
   * Routes one installed app resource at {@code /apps/{appId}}.
   *
   * @param appId normalized app identifier segment
   * @param method HTTP-style request method
   * @return JSON response for the requested app resource
   */
  private PlatformApiResponse routeInstalledApp(String appId, String method) {
    if ("GET".equals(method)) {
      return PlatformApiResponse.ok(envelope("app", appsApiHandler.get(appId)));
    }
    if (METHOD_DELETE.equals(method)) {
      return uninstallInstalledApp(appId);
    }
    return methodNotAllowed(
        "GET, DELETE", "Platform API v1 supports GET and DELETE requests only.");
  }

  private PlatformApiResponse uninstallInstalledApp(String appId) {
    try {
      Map<String, Object> app = appsApiHandler.uninstall(appId);
      clearAppUpdateState(appId);
      return PlatformApiResponse.ok(envelope("app", app));
    } catch (PlatformApiException exception) {
      if (exception.statusCode() == 404) {
        clearAppUpdateState(appId);
      }
      throw exception;
    }
  }

  private void clearAppUpdateState(String appId) {
    if (appUpdateService != null) {
      appUpdateService.clearAppState(appId);
    }
  }

  /**
   * Returns whether the current method should target an installed-app resource rather than the
   * reserved installation endpoint.
   *
   * <p>The id {@code install} remains valid for the app-resource routes on GET and DELETE, while
   * method discovery and unsupported-method handling for {@code /apps/install} continue to
   * advertise the installation endpoint's POST contract.
   *
   * @param method HTTP-style request method
   * @return {@code true} when the request should be treated as {@code /apps/{appId}}
   */
  private static boolean targetsInstalledAppResource(String method) {
    return "GET".equals(method) || METHOD_DELETE.equals(method);
  }

  /**
   * Routes app lifecycle actions beneath {@code /apps/{appId}/...}.
   *
   * @param appId normalized app identifier segment
   * @param action lifecycle action segment such as {@code start}, {@code stop}, or {@code update}
   * @param request full request metadata, including query parameters
   * @return JSON response for the selected app action
   */
  private PlatformApiResponse routeAppsAction(
      String appId, String action, PlatformApiRequest request) {
    String method = request.method();
    return switch (action) {
      case "runtime" -> {
        if (!"GET".equals(method)) {
          yield methodNotAllowed("GET", GET_ONLY_MESSAGE);
        }
        yield PlatformApiResponse.ok(envelope("runtime", appsApiHandler.runtime(appId)));
      }
      case "logs" -> {
        if (!"GET".equals(method)) {
          yield methodNotAllowed("GET", GET_ONLY_MESSAGE);
        }
        yield PlatformApiResponse.ok(
            envelope("logs", appsApiHandler.logs(appId, request.queryParameters())));
      }
      case "permissions" -> {
        if (!"GET".equals(method)) {
          yield methodNotAllowed("GET", GET_ONLY_MESSAGE);
        }
        yield PlatformApiResponse.ok(envelope("permissions", appsApiHandler.permissions(appId)));
      }
      case "audit" -> {
        if (!"GET".equals(method)) {
          yield methodNotAllowed("GET", GET_ONLY_MESSAGE);
        }
        yield PlatformApiResponse.ok(envelope("audit", appsApiHandler.audit(appId)));
      }
      case UPDATES_ROUTE_SEGMENT -> {
        if (appUpdatesApiHandler == null) {
          throw new PlatformApiException(404, "not_found", "Platform API route not found.");
        }
        if (!"GET".equals(method)) {
          yield methodNotAllowed("GET", GET_ONLY_MESSAGE);
        }
        yield PlatformApiResponse.ok(
            envelope(UPDATES_ROUTE_SEGMENT, appUpdatesApiHandler.summary(appId)));
      }
      case "start" -> {
        if (!"POST".equals(method)) {
          yield methodNotAllowed("POST", POST_ONLY_MESSAGE);
        }
        yield PlatformApiResponse.ok(envelope("app", appsApiHandler.start(appId)));
      }
      case "stop" -> {
        if (!"POST".equals(method)) {
          yield methodNotAllowed("POST", POST_ONLY_MESSAGE);
        }
        yield PlatformApiResponse.ok(envelope("app", appsApiHandler.stop(appId)));
      }
      case "update" -> {
        if (!"POST".equals(method)) {
          yield methodNotAllowed("POST", POST_ONLY_MESSAGE);
        }
        yield PlatformApiResponse.ok(
            envelope("app", appsApiHandler.update(appId, request.queryParameters())));
      }
      default -> throw new PlatformApiException(404, "not_found", "Platform API route not found.");
    };
  }

  private PlatformApiResponse routeAppsNestedAction(
      String appId, String resource, String action, PlatformApiRequest request) {
    if (!UPDATES_ROUTE_SEGMENT.equals(resource) || appUpdatesApiHandler == null) {
      throw new PlatformApiException(404, "not_found", "Platform API route not found.");
    }
    return switch (action) {
      case "check" -> {
        if (!"POST".equals(request.method())) {
          yield methodNotAllowed("POST", POST_ONLY_MESSAGE);
        }
        yield PlatformApiResponse.ok(
            envelope(
                UPDATES_ROUTE_SEGMENT,
                appUpdatesApiHandler.check(appId, request.queryParameters())));
      }
      case "stage" -> {
        if (!"POST".equals(request.method())) {
          yield methodNotAllowed("POST", POST_ONLY_MESSAGE);
        }
        yield PlatformApiResponse.ok(
            envelope(
                UPDATES_ROUTE_SEGMENT,
                appUpdatesApiHandler.stage(appId, request.queryParameters())));
      }
      case "apply" -> {
        if (!"POST".equals(request.method())) {
          yield methodNotAllowed("POST", POST_ONLY_MESSAGE);
        }
        yield PlatformApiResponse.ok(
            envelope(
                UPDATES_ROUTE_SEGMENT,
                appUpdatesApiHandler.apply(appId, request.queryParameters())));
      }
      case "rollback" -> {
        if (!"POST".equals(request.method())) {
          yield methodNotAllowed("POST", POST_ONLY_MESSAGE);
        }
        yield PlatformApiResponse.ok(
            envelope(
                UPDATES_ROUTE_SEGMENT,
                appUpdatesApiHandler.rollback(appId, request.queryParameters())));
      }
      case POLICY_ROUTE_SEGMENT -> routeAppUpdatesPolicy(appId, request);
      default -> throw new PlatformApiException(404, "not_found", "Platform API route not found.");
    };
  }

  private PlatformApiResponse routeAppUpdatesPolicy(String appId, PlatformApiRequest request) {
    if ("GET".equals(request.method())) {
      return PlatformApiResponse.ok(
          envelope(POLICY_ROUTE_SEGMENT, appUpdatesApiHandler.policy(appId)));
    }
    if ("POST".equals(request.method())) {
      return PlatformApiResponse.ok(
          envelope(
              POLICY_ROUTE_SEGMENT,
              appUpdatesApiHandler.setPolicy(appId, request.queryParameters())));
    }
    return methodNotAllowed("GET, POST", "Platform API v1 supports GET and POST requests only.");
  }

  /**
   * Routes requests beneath the {@code /app-catalogs} endpoint family.
   *
   * @param segments decoded path segments relative to the Platform API mount point
   * @param request full request metadata, including query parameters
   * @return JSON response for the selected catalog endpoint
   */
  private PlatformApiResponse routeAppCatalogsRequest(
      List<String> segments, PlatformApiRequest request) {
    if (appCatalogsApiHandler == null) {
      throw new PlatformApiException(404, "not_found", "Platform API route not found.");
    }
    return switch (segments.size()) {
      case 1 -> routeAppCatalogsCollection(request);
      case 2 -> routeAppCatalogsResource(segments.get(1), request);
      case 3 -> routeAppCatalogsActionOrApps(segments.get(1), segments.get(2), request);
      case 4 -> routeAppCatalogApp(segments.get(1), segments.get(2), segments.get(3), request);
      case 5 ->
          routeAppCatalogAppAction(
              segments.get(1), segments.get(2), segments.get(3), segments.get(4), request);
      default -> throw new PlatformApiException(404, "not_found", "Platform API route not found.");
    };
  }

  private PlatformApiResponse routeAppCatalogsCollection(PlatformApiRequest request) {
    if (!"GET".equals(request.method())) {
      return methodNotAllowed("GET", GET_ONLY_MESSAGE);
    }
    return PlatformApiResponse.ok(envelope("catalogs", appCatalogsApiHandler.listCatalogs()));
  }

  private PlatformApiResponse routeAppCatalogsResource(
      String resource, PlatformApiRequest request) {
    if (METHOD_DELETE.equals(request.method())) {
      return PlatformApiResponse.ok(
          envelope(CATALOG_ENVELOPE_KEY, appCatalogsApiHandler.remove(resource)));
    }
    if ("add".equals(resource)) {
      if (!"POST".equals(request.method())) {
        return methodNotAllowed("POST", POST_ONLY_MESSAGE);
      }
      return PlatformApiResponse.created(
          envelope(CATALOG_ENVELOPE_KEY, appCatalogsApiHandler.add(request.queryParameters())));
    }
    return methodNotAllowed(METHOD_DELETE, "Platform API v1 supports DELETE requests only.");
  }

  private PlatformApiResponse routeAppCatalogsActionOrApps(
      String catalogId, String action, PlatformApiRequest request) {
    if ("refresh".equals(action)) {
      if (!"POST".equals(request.method())) {
        return methodNotAllowed("POST", POST_ONLY_MESSAGE);
      }
      return PlatformApiResponse.ok(
          envelope(CATALOG_ENVELOPE_KEY, appCatalogsApiHandler.refresh(catalogId)));
    }
    if ("apps".equals(action)) {
      if (!"GET".equals(request.method())) {
        return methodNotAllowed("GET", GET_ONLY_MESSAGE);
      }
      return PlatformApiResponse.ok(envelope("apps", appCatalogsApiHandler.listApps(catalogId)));
    }
    throw new PlatformApiException(404, "not_found", "Platform API route not found.");
  }

  private PlatformApiResponse routeAppCatalogApp(
      String catalogId, String appsSegment, String appId, PlatformApiRequest request) {
    if (!"apps".equals(appsSegment)) {
      throw new PlatformApiException(404, "not_found", "Platform API route not found.");
    }
    if (!"GET".equals(request.method())) {
      return methodNotAllowed("GET", GET_ONLY_MESSAGE);
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
      throw new PlatformApiException(404, "not_found", "Platform API route not found.");
    }
    if (!"POST".equals(request.method())) {
      return methodNotAllowed("POST", POST_ONLY_MESSAGE);
    }
    return switch (action) {
      case "install" ->
          PlatformApiResponse.created(
              envelope(
                  "app",
                  appCatalogsApiHandler.install(catalogId, appId, request.queryParameters())));
      case "update" ->
          PlatformApiResponse.ok(
              envelope(
                  "app",
                  appCatalogsApiHandler.update(catalogId, appId, request.queryParameters())));
      default -> throw new PlatformApiException(404, "not_found", "Platform API route not found.");
    };
  }

  /**
   * Routes requests beneath the {@code /queue} endpoint family.
   *
   * @param segments decoded path segments relative to the Platform API mount point
   * @param request full request metadata, including query parameters
   * @return JSON response for the selected queue endpoint
   */
  private PlatformApiResponse routeQueueRequest(List<String> segments, PlatformApiRequest request) {
    return switch (segments.size()) {
      case 1 -> routeQueueRoot(request);
      case 2 -> routeQueueResource(segments.get(1), request);
      case 3 -> routeQueueAction(segments.get(1), segments.get(2), request);
      default -> throw new PlatformApiException(404, "not_found", "Platform API route not found.");
    };
  }

  /**
   * Routes the queue snapshot endpoint at {@code /queue}.
   *
   * @param request full request metadata, including query parameters
   * @return JSON response containing one detached queue snapshot
   */
  private PlatformApiResponse routeQueueRoot(PlatformApiRequest request) {
    if (!"GET".equals(request.method())) {
      return methodNotAllowed("GET", GET_ONLY_MESSAGE);
    }
    return PlatformApiResponse.ok(queueApiHandler.snapshot(request.queryParameters()));
  }

  /**
   * Routes queue resources such as count, keys, and direct-download creation.
   *
   * @param resource second path segment beneath {@code /queue}
   * @param request full request metadata, including query parameters
   * @return JSON response for the selected queue resource
   */
  private PlatformApiResponse routeQueueResource(String resource, PlatformApiRequest request) {
    return switch (resource) {
      case "count" -> routeQueueCount(request);
      case "keys" -> routeQueueKeys(request);
      case "downloads" -> routeQueueDownloads(request);
      default -> throw new PlatformApiException(404, "not_found", "Platform API route not found.");
    };
  }

  /**
   * Routes queue snapshot count requests.
   *
   * @param request full request metadata, including query parameters
   * @return JSON response containing one detached count snapshot
   */
  private PlatformApiResponse routeQueueCount(PlatformApiRequest request) {
    if (!"GET".equals(request.method())) {
      return methodNotAllowed("GET", GET_ONLY_MESSAGE);
    }
    return PlatformApiResponse.ok(queueApiHandler.count(request.queryParameters()));
  }

  /**
   * Routes queue key-export requests.
   *
   * @param request full request metadata, including query parameters
   * @return JSON response containing the detached queue key export
   */
  private PlatformApiResponse routeQueueKeys(PlatformApiRequest request) {
    if (!"GET".equals(request.method())) {
      return methodNotAllowed("GET", GET_ONLY_MESSAGE);
    }
    return PlatformApiResponse.ok(queueApiHandler.keys(request.queryParameters()));
  }

  /**
   * Routes direct-download creation requests.
   *
   * @param request full request metadata, including query parameters
   * @return JSON response describing the newly queued direct download
   */
  private PlatformApiResponse routeQueueDownloads(PlatformApiRequest request) {
    if (!"POST".equals(request.method())) {
      return methodNotAllowed("POST", POST_ONLY_MESSAGE);
    }
    return PlatformApiResponse.created(
        queueApiHandler.createDirectDownload(request.queryParameters()));
  }

  /**
   * Routes queue mutation actions beneath {@code /queue/...}.
   *
   * @param resource second path segment beneath {@code /queue}
   * @param action queue action segment
   * @param request full request metadata, including query parameters
   * @return JSON response for the selected queue mutation
   */
  private PlatformApiResponse routeQueueAction(
      String resource, String action, PlatformApiRequest request) {
    if (!"POST".equals(request.method())) {
      return methodNotAllowed("POST", POST_ONLY_MESSAGE);
    }
    if ("inserts".equals(resource)) {
      return switch (action) {
        case "file" ->
            PlatformApiResponse.created(
                queueApiHandler.createLocalFileInsert(request.queryParameters()));
        case "directory" ->
            PlatformApiResponse.created(
                queueApiHandler.createLocalDirectoryInsert(request.queryParameters()));
        default ->
            throw new PlatformApiException(404, "not_found", "Platform API route not found.");
      };
    }
    if ("requests".equals(resource)) {
      return switch (action) {
        case "remove" ->
            PlatformApiResponse.ok(queueApiHandler.removeRequests(request.queryParameters()));
        case "restart" ->
            PlatformApiResponse.ok(queueApiHandler.restartRequests(request.queryParameters()));
        case "priority" ->
            PlatformApiResponse.ok(queueApiHandler.changePriority(request.queryParameters()));
        default ->
            throw new PlatformApiException(404, "not_found", "Platform API route not found.");
      };
    }
    if ("cleanup".equals(resource)) {
      return switch (action) {
        case "uploads" ->
            PlatformApiResponse.ok(queueApiHandler.cleanupUploads(request.queryParameters()));
        case "downloads" ->
            PlatformApiResponse.ok(queueApiHandler.cleanupDownloads(request.queryParameters()));
        default ->
            throw new PlatformApiException(404, "not_found", "Platform API route not found.");
      };
    }
    throw new PlatformApiException(404, "not_found", "Platform API route not found.");
  }

  /**
   * Routes requests beneath the {@code /node} endpoint family.
   *
   * @param segments decoded path segments relative to the Platform API mount point
   * @param request full request metadata, including query parameters
   * @return JSON response for the selected node endpoint
   * @throws PlatformApiException if the path does not identify a supported node endpoint
   */
  private PlatformApiResponse routeNodeRequest(List<String> segments, PlatformApiRequest request) {
    if (segments.size() == 2 && "greeting".equals(segments.get(1))) {
      return PlatformApiResponse.ok(nodeApiHandler.greeting());
    }
    if (segments.size() == 2 && "reference".equals(segments.get(1))) {
      return PlatformApiResponse.ok(nodeApiHandler.reference(request.queryParameters()));
    }
    throw new PlatformApiException(404, "not_found", "Platform API route not found.");
  }

  /**
   * Routes requests beneath the {@code /peers} endpoint family.
   *
   * @param segments decoded path segments relative to the Platform API mount point
   * @param request full request metadata, including query parameters
   * @return JSON response for either the peer list or one peer detail endpoint
   * @throws PlatformApiException if the path does not identify a supported peers endpoint
   */
  private PlatformApiResponse routePeersRequest(List<String> segments, PlatformApiRequest request) {
    return switch (segments.size()) {
      case 1 -> routePeersRoot(request);
      case 2 -> routePeerResource(segments.get(1), request);
      case 3 -> routePeerAction(segments.get(1), segments.get(2), request);
      default -> throw new PlatformApiException(404, "not_found", "Platform API route not found.");
    };
  }

  /**
   * Routes either the raw peer collection export or the shell summary view at {@code /peers}.
   *
   * @param request full request metadata, including query parameters
   * @return JSON response containing the requested peer collection view
   */
  private PlatformApiResponse routePeersRoot(PlatformApiRequest request) {
    if (!"GET".equals(request.method())) {
      return methodNotAllowed("GET", GET_ONLY_MESSAGE);
    }
    String view = PlatformApiParameters.readOptionalString(request.queryParameters(), "view");
    if (view != null) {
      if ("summary".equals(view)) {
        return PlatformApiResponse.ok(peersApiHandler.roster());
      }
      throw new PlatformApiException(
          400, "invalid_query_parameter", "Query parameter 'view' must be 'summary'.");
    }
    return PlatformApiResponse.ok(peersApiHandler.list(request.queryParameters()));
  }

  /**
   * Routes either the add-peer endpoint or one raw peer resource.
   *
   * @param resource second path segment beneath {@code /peers}
   * @param request full request metadata, including query parameters
   * @return JSON response for the selected peer endpoint
   */
  private PlatformApiResponse routePeerResource(String resource, PlatformApiRequest request) {
    if ("add".equals(resource) && "POST".equals(request.method())) {
      return PlatformApiResponse.created(peersApiHandler.add(request.queryParameters()));
    }

    if (!"GET".equals(request.method())) {
      return methodNotAllowed("GET", GET_ONLY_MESSAGE);
    }
    return PlatformApiResponse.ok(peersApiHandler.get(resource, request.queryParameters()));
  }

  /**
   * Routes peer mutations beneath {@code /peers/{peerIdentity}/...}.
   *
   * @param peerIdentity exact peer identity segment
   * @param action peer action segment
   * @param request full request metadata, including query parameters
   * @return JSON response for the selected peer mutation
   */
  private PlatformApiResponse routePeerAction(
      String peerIdentity, String action, PlatformApiRequest request) {
    if (!"POST".equals(request.method())) {
      return methodNotAllowed("POST", POST_ONLY_MESSAGE);
    }
    return switch (action) {
      case "settings" ->
          PlatformApiResponse.ok(
              peersApiHandler.updateSettings(peerIdentity, request.queryParameters()));
      case "note" ->
          PlatformApiResponse.ok(
              peersApiHandler.updateNote(peerIdentity, request.queryParameters()));
      case "remove" ->
          PlatformApiResponse.ok(peersApiHandler.remove(peerIdentity, request.queryParameters()));
      default -> throw new PlatformApiException(404, "not_found", "Platform API route not found.");
    };
  }

  /**
   * Builds a small single-entry JSON envelope.
   *
   * @param key envelope field name
   * @param value envelope value
   * @return ordered JSON-compatible envelope object
   */
  private static Map<String, Object> envelope(String key, Object value) {
    java.util.LinkedHashMap<String, Object> envelope = java.util.LinkedHashMap.newLinkedHashMap(1);
    envelope.put(key, value);
    return envelope;
  }

  /**
   * Creates a structured 405 response with a stable Allow header.
   *
   * @param allow allowed methods for the current route
   * @param message human-readable error message
   * @return structured platform API response
   */
  private static PlatformApiResponse methodNotAllowed(String allow, String message) {
    return PlatformApiResponse.error(405, Map.of("Allow", allow), "method_not_allowed", message);
  }
}

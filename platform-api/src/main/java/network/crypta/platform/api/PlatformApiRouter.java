package network.crypta.platform.api;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import network.crypta.platform.api.apps.AppsApiHandler;
import network.crypta.platform.api.config.ConfigApiHandler;
import network.crypta.platform.api.connectivity.ConnectivityApiHandler;
import network.crypta.platform.api.node.NodeApiHandler;
import network.crypta.platform.api.peers.PeersApiHandler;
import network.crypta.platform.api.security.SecurityLevelsApiHandler;
import network.crypta.platform.apphost.AppHost;
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

  /** Handler for the {@code /apps/...} endpoint family, when AppHost support is available. */
  private final AppsApiHandler appsApiHandler;

  /**
   * Creates a router backed by the supplied runtime ports.
   *
   * @param runtimePorts detached runtime-port aggregate used to resolve API requests
   * @throws NullPointerException if {@code runtimePorts} is {@code null}
   */
  public PlatformApiRouter(RuntimePorts runtimePorts) {
    this(runtimePorts, null);
  }

  /**
   * Creates a router backed by the supplied runtime ports and AppHost instance.
   *
   * @param runtimePorts detached runtime-port aggregate used to resolve API requests
   * @param appHost detached AppHost used by the app-management endpoint family
   * @throws NullPointerException if {@code runtimePorts} is {@code null}
   */
  public PlatformApiRouter(RuntimePorts runtimePorts, AppHost appHost) {
    Objects.requireNonNull(runtimePorts, "runtimePorts");
    nodeApiHandler = new NodeApiHandler(runtimePorts.nodeInfo());
    peersApiHandler = new PeersApiHandler(runtimePorts.peer());
    configApiHandler = new ConfigApiHandler(runtimePorts.config());
    connectivityApiHandler = new ConnectivityApiHandler(runtimePorts.connectivity());
    securityLevelsApiHandler = new SecurityLevelsApiHandler(runtimePorts.securityLevels());
    appsApiHandler = appHost == null ? null : new AppsApiHandler(appHost);
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
    try {
      return routeInternal(Objects.requireNonNull(request, "request"));
    } catch (PlatformApiException e) {
      return PlatformApiResponse.error(e.statusCode(), e.errorCode(), e.getMessage());
    } catch (RuntimeException e) {
      LOG.log(System.Logger.Level.ERROR, "Unexpected Platform API failure", e);
      return PlatformApiResponse.error(500, "internal_error", "Unexpected platform API failure.");
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
    if ("apps".equals(firstSegment)) {
      return routeAppsRequest(segments, request);
    }

    if (!"GET".equals(request.method())) {
      return PlatformApiResponse.error(
          405,
          Map.of("Allow", "GET"),
          "method_not_allowed",
          "Platform API v1 supports GET requests only.");
    }

    if ("node".equals(firstSegment)) {
      return routeNodeRequest(segments, request);
    }
    if ("peers".equals(firstSegment)) {
      return routePeersRequest(segments, request);
    }
    if ("config".equals(firstSegment) && segments.size() == 1) {
      return PlatformApiResponse.ok(configApiHandler.exportConfig(request.queryParameters()));
    }
    if ("connectivity".equals(firstSegment) && segments.size() == 1) {
      return PlatformApiResponse.ok(connectivityApiHandler.snapshot(request.queryParameters()));
    }
    if ("security-levels".equals(firstSegment) && segments.size() == 1) {
      return PlatformApiResponse.ok(securityLevelsApiHandler.snapshot());
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
      case 3 -> routeAppsAction(segments.get(1), segments.get(2), request.method());
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
      return methodNotAllowed("GET", "Platform API v1 supports GET requests only.");
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
      return methodNotAllowed("POST", "Platform API v1 supports POST requests only.");
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
    if ("DELETE".equals(method)) {
      return PlatformApiResponse.ok(envelope("app", appsApiHandler.uninstall(appId)));
    }
    return methodNotAllowed(
        "GET, DELETE", "Platform API v1 supports GET and DELETE requests only.");
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
    return "GET".equals(method) || "DELETE".equals(method);
  }

  /**
   * Routes app lifecycle actions beneath {@code /apps/{appId}/...}.
   *
   * @param appId normalized app identifier segment
   * @param action lifecycle action segment
   * @param method HTTP-style request method
   * @return JSON response for the selected app action
   */
  private PlatformApiResponse routeAppsAction(String appId, String action, String method) {
    if (!"POST".equals(method)) {
      return methodNotAllowed("POST", "Platform API v1 supports POST requests only.");
    }
    return switch (action) {
      case "start" -> PlatformApiResponse.ok(envelope("app", appsApiHandler.start(appId)));
      case "stop" -> PlatformApiResponse.ok(envelope("app", appsApiHandler.stop(appId)));
      default -> throw new PlatformApiException(404, "not_found", "Platform API route not found.");
    };
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
    if (segments.size() == 1) {
      return PlatformApiResponse.ok(peersApiHandler.list(request.queryParameters()));
    }
    if (segments.size() == 2) {
      return PlatformApiResponse.ok(
          peersApiHandler.get(segments.get(1), request.queryParameters()));
    }
    throw new PlatformApiException(404, "not_found", "Platform API route not found.");
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

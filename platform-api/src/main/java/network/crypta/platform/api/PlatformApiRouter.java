package network.crypta.platform.api;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import network.crypta.platform.api.config.ConfigApiHandler;
import network.crypta.platform.api.connectivity.ConnectivityApiHandler;
import network.crypta.platform.api.node.NodeApiHandler;
import network.crypta.platform.api.peers.PeersApiHandler;
import network.crypta.platform.api.security.SecurityLevelsApiHandler;
import network.crypta.runtime.spi.RuntimePorts;

/**
 * Routes transport-neutral Platform API requests onto detached runtime ports.
 *
 * <p>The router keeps the initial Platform API v1 surface small and predictable. It accepts one
 * request descriptor, validates the method and relative path beneath {@link
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

  /**
   * Creates a router backed by the supplied runtime ports.
   *
   * @param runtimePorts detached runtime-port aggregate used to resolve API requests
   * @throws NullPointerException if {@code runtimePorts} is {@code null}
   */
  public PlatformApiRouter(RuntimePorts runtimePorts) {
    Objects.requireNonNull(runtimePorts, "runtimePorts");
    nodeApiHandler = new NodeApiHandler(runtimePorts.nodeInfo());
    peersApiHandler = new PeersApiHandler(runtimePorts.peer());
    configApiHandler = new ConfigApiHandler(runtimePorts.config());
    connectivityApiHandler = new ConnectivityApiHandler(runtimePorts.connectivity());
    securityLevelsApiHandler = new SecurityLevelsApiHandler(runtimePorts.securityLevels());
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
    if (!"GET".equals(request.method())) {
      return PlatformApiResponse.error(
          405,
          Map.of("Allow", "GET"),
          "method_not_allowed",
          "Platform API v1 supports GET requests only.");
    }

    List<String> segments = request.pathSegments();
    if (segments.isEmpty()) {
      throw new PlatformApiException(404, "not_found", "Platform API route not found.");
    }

    String firstSegment = segments.getFirst();
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
}

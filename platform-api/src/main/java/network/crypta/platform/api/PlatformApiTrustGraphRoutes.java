package network.crypta.platform.api;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import network.crypta.platform.api.trust.TrustGraphApiHandler;
import network.crypta.platform.trustgraph.TrustGraphException;
import network.crypta.runtime.spi.ContentFetchPort;

/**
 * Routes the local Trust Graph RC Platform API endpoint family.
 *
 * <p>The top-level router owns authentication, capability checks, and app audit recording. This
 * collaborator owns only the {@code /trust-graph} path grammar and the small amount of bridge state
 * needed by Trust Graph RC: its API handler and the optional bounded content-fetch port used by
 * {@code /trust-graph/import-uri}. Keeping those details here prevents the main router from
 * depending directly on Trust Graph model exceptions or handler internals while preserving the same
 * method checks and error envelopes.
 *
 * <p>Trust Graph RC remains a local, bounded operator-curated API. This dispatcher never exposes
 * raw statement bodies, private identity material, local paths, or fetched content; it delegates
 * those redaction and validation decisions to {@link TrustGraphApiHandler}, then maps any remaining
 * {@link TrustGraphException} to the stable Platform API error shape.
 */
final class PlatformApiTrustGraphRoutes {
  /** Shared method token for routes that read Trust Graph RC state. */
  private static final String METHOD_GET = "GET";

  /** Shared method token for routes that mutate Trust Graph RC state. */
  private static final String METHOD_POST = "POST";

  /** Shared method token for routes that remove Trust Graph RC resources. */
  private static final String METHOD_DELETE = "DELETE";

  /** Shared 405 message for routes that only support GET. */
  private static final String GET_ONLY_MESSAGE = "Platform API v1 supports GET requests only.";

  /** Shared 405 message for routes that only support POST. */
  private static final String POST_ONLY_MESSAGE = "Platform API v1 supports POST requests only.";

  /** Shared 405 message for routes that only support DELETE. */
  private static final String DELETE_ONLY_MESSAGE =
      "Platform API v1 supports DELETE requests only.";

  /** Shared route segment and list envelope key for Trust Graph RC anchors. */
  private static final String ANCHORS_SEGMENT = "anchors";

  /** Shared route segment and list envelope key for Trust Graph statement summaries. */
  private static final String STATEMENTS_SEGMENT = "statements";

  /** Shared envelope key for Trust Graph statement lifecycle mutation responses. */
  private static final String LIFECYCLE_ENVELOPE_KEY = "lifecycle";

  /** Handler that performs bounded Trust Graph RC validation, storage, and redaction. */
  private final TrustGraphApiHandler trustGraphApiHandler;

  /** Optional runtime content-fetch port for import-by-URI requests. */
  private final ContentFetchPort contentFetchPort;

  /**
   * Builds Trust Graph routes from the shared Platform API service group.
   *
   * <p>Reduced embeddings can omit a durable shared Trust Graph handler. In that case the route
   * family falls back to the same process-local local-RC handler used before durable app-platform
   * services were wired in.
   *
   * @param appServices shared app-platform services supplied to the Platform API router
   * @param contentFetchPort optional bounded content-fetch port used by import-by-URI
   * @return initialized Trust Graph route dispatcher
   */
  static PlatformApiTrustGraphRoutes from(
      PlatformApiSharedAppServices appServices, ContentFetchPort contentFetchPort) {
    TrustGraphApiHandler handler = appServices.trustGraphApiHandler();
    return new PlatformApiTrustGraphRoutes(
        handler == null ? new TrustGraphApiHandler() : handler, contentFetchPort);
  }

  private PlatformApiTrustGraphRoutes(
      TrustGraphApiHandler trustGraphApiHandler, ContentFetchPort contentFetchPort) {
    this.trustGraphApiHandler = trustGraphApiHandler;
    this.contentFetchPort = contentFetchPort;
  }

  /**
   * Returns the handler backing this route family.
   *
   * <p>Reduced router embeddings create a process-local fallback handler when no shared Trust Graph
   * service is supplied. Operator dashboard routes must inspect that same handler so imported
   * statements and anchors remain visible across both route families.
   *
   * @return Trust Graph handler used by {@code /trust-graph} routes
   */
  TrustGraphApiHandler trustGraphApiHandler() {
    return trustGraphApiHandler;
  }

  /**
   * Routes one request whose first path segment is {@code trust-graph}.
   *
   * @param segments decoded path segments relative to the Platform API mount point
   * @param request full request metadata, including method, principal, and query parameters
   * @return JSON response for the selected Trust Graph RC endpoint
   */
  PlatformApiResponse route(List<String> segments, PlatformApiRequest request) {
    try {
      return routeInternal(segments, request);
    } catch (TrustGraphException exception) {
      throw mappedTrustGraphException(exception);
    }
  }

  private PlatformApiResponse routeInternal(List<String> segments, PlatformApiRequest request) {
    return switch (segments.size()) {
      case 2 -> routeCollection(segments.get(1), request);
      case 3 -> routeResource(segments.get(1), segments.get(2), request);
      case 4 ->
          routeNestedResourceAction(segments.get(1), segments.get(2), segments.get(3), request);
      default -> throw notFound();
    };
  }

  private PlatformApiResponse routeCollection(String resource, PlatformApiRequest request) {
    return switch (resource) {
      case "status" -> {
        if (!METHOD_GET.equals(request.method())) {
          yield methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
        }
        yield PlatformApiResponse.ok(envelope("trustGraph", trustGraphApiHandler.status()));
      }
      case ANCHORS_SEGMENT -> routeAnchors(request);
      case "import" -> {
        if (!METHOD_POST.equals(request.method())) {
          yield methodNotAllowed(METHOD_POST, POST_ONLY_MESSAGE);
        }
        yield PlatformApiResponse.ok(
            envelope(
                "importResult",
                trustGraphApiHandler.importStatement(
                    request.queryParameters(), optionalAppPrincipalId(request))));
      }
      case "import-uri" -> {
        if (!METHOD_POST.equals(request.method())) {
          yield methodNotAllowed(METHOD_POST, POST_ONLY_MESSAGE);
        }
        yield PlatformApiResponse.ok(
            envelope(
                "importResult",
                trustGraphApiHandler.importUri(
                    request.queryParameters(), contentFetchPort, optionalAppPrincipalId(request))));
      }
      case "audit" -> {
        if (!METHOD_GET.equals(request.method())) {
          yield methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
        }
        yield PlatformApiResponse.ok(
            envelope("audit", trustGraphApiHandler.audit(request.queryParameters())));
      }
      case "subjects" -> {
        if (!METHOD_GET.equals(request.method())) {
          yield methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
        }
        yield PlatformApiResponse.ok(envelope("subjects", trustGraphApiHandler.subjects()));
      }
      case STATEMENTS_SEGMENT -> {
        if (!METHOD_GET.equals(request.method())) {
          yield methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
        }
        yield PlatformApiResponse.ok(
            envelope(
                STATEMENTS_SEGMENT, trustGraphApiHandler.statements(request.queryParameters())));
      }
      case "score" -> {
        if (!METHOD_GET.equals(request.method())) {
          yield methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
        }
        yield PlatformApiResponse.ok(
            envelope("score", trustGraphApiHandler.score(request.queryParameters())));
      }
      default -> throw notFound();
    };
  }

  private PlatformApiResponse routeAnchors(PlatformApiRequest request) {
    if (METHOD_GET.equals(request.method())) {
      return PlatformApiResponse.ok(envelope(ANCHORS_SEGMENT, trustGraphApiHandler.anchors()));
    }
    if (METHOD_POST.equals(request.method())) {
      return PlatformApiResponse.created(
          envelope(
              "anchor",
              trustGraphApiHandler.addAnchor(
                  request.queryParameters(), optionalAppPrincipalId(request))));
    }
    return methodNotAllowed("GET, POST", "Platform API v1 supports GET and POST requests only.");
  }

  private PlatformApiResponse routeResource(
      String resource, String resourceId, PlatformApiRequest request) {
    if (ANCHORS_SEGMENT.equals(resource)) {
      if (!METHOD_DELETE.equals(request.method())) {
        return methodNotAllowed(METHOD_DELETE, DELETE_ONLY_MESSAGE);
      }
      return PlatformApiResponse.ok(
          envelope(
              "anchor",
              trustGraphApiHandler.removeAnchor(resourceId, optionalAppPrincipalId(request))));
    }
    if (STATEMENTS_SEGMENT.equals(resource)) {
      if (!METHOD_GET.equals(request.method())) {
        return methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
      }
      return PlatformApiResponse.ok(
          envelope("statement", trustGraphApiHandler.statement(resourceId)));
    }
    throw notFound();
  }

  private PlatformApiResponse routeNestedResourceAction(
      String resource, String resourceId, String action, PlatformApiRequest request) {
    if (!STATEMENTS_SEGMENT.equals(resource)) {
      throw notFound();
    }
    if (!METHOD_POST.equals(request.method())) {
      return methodNotAllowed(METHOD_POST, POST_ONLY_MESSAGE);
    }
    return switch (action) {
      case "deprecate" ->
          PlatformApiResponse.ok(
              envelope(
                  LIFECYCLE_ENVELOPE_KEY,
                  trustGraphApiHandler.deprecateStatement(
                      resourceId, request.queryParameters(), optionalAppPrincipalId(request))));
      case "revoke" ->
          PlatformApiResponse.ok(
              envelope(
                  LIFECYCLE_ENVELOPE_KEY,
                  trustGraphApiHandler.revokeStatement(
                      resourceId, request.queryParameters(), optionalAppPrincipalId(request))));
      case "reactivate" ->
          PlatformApiResponse.ok(
              envelope(
                  LIFECYCLE_ENVELOPE_KEY,
                  trustGraphApiHandler.reactivateStatement(
                      resourceId, request.queryParameters(), optionalAppPrincipalId(request))));
      default -> throw notFound();
    };
  }

  private static String optionalAppPrincipalId(PlatformApiRequest request) {
    return request.principal().isApp() ? request.principal().appId() : null;
  }

  private static PlatformApiException mappedTrustGraphException(TrustGraphException exception) {
    return new PlatformApiException(
        "trust_graph_store_unavailable".equals(exception.errorCode()) ? 503 : 400,
        exception.errorCode(),
        exception.getMessage());
  }

  private static Map<String, Object> envelope(String key, Object value) {
    LinkedHashMap<String, Object> envelope = LinkedHashMap.newLinkedHashMap(1);
    envelope.put(key, value);
    return envelope;
  }

  private static PlatformApiResponse methodNotAllowed(String allow, String message) {
    return PlatformApiResponse.error(405, Map.of("Allow", allow), "method_not_allowed", message);
  }

  private static PlatformApiException notFound() {
    return new PlatformApiException(404, "not_found", "Platform API route not found.");
  }
}

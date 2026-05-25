package network.crypta.platform.api;

import java.util.List;
import java.util.Map;
import network.crypta.platform.api.appdata.AppDataApiHandler;
import network.crypta.platform.api.appdata.AppDataService;

/**
 * Routes the app-scoped durable {@code /app-data} endpoint family.
 *
 * <p>This package-private router keeps the Platform API v1 app-data path grammar in one place while
 * leaving request authorization to {@link PlatformApiRouter}. The top-level router applies the
 * stable contract descriptors, capability checks, and audit labels before this class sees the
 * request. This class then performs method/path dispatch and verifies that the principal is an app
 * principal, because every durable app-data operation is scoped to the authenticated app id.
 *
 * <p>Callers never supply the target app id as a form field or route parameter. The app id comes
 * only from {@link PlatformApiPrincipal#appId()}, and each handler call passes that value to the
 * service layer. That convention keeps cross-app access out of the route grammar and makes app-data
 * URLs stable across app restarts, browser sessions, and catalog refreshes.
 *
 * <p>The app-data service is optional during runtime composition. When it is absent, route matching
 * still succeeds far enough to return a deterministic {@code 503 app_data_service_unavailable}
 * response instead of silently exposing a partial app-data surface.
 */
final class PlatformApiAppDataRoutes {
  private static final String METHOD_DELETE = "DELETE";
  private static final String METHOD_GET = "GET";
  private static final String METHOD_POST = "POST";
  private static final String GET_ONLY_MESSAGE = "Platform API v1 supports GET requests only.";
  private static final String POST_ONLY_MESSAGE = "Platform API v1 supports POST requests only.";

  private final AppDataService appDataService;

  /**
   * Creates routes for the optional app-data service.
   *
   * <p>The service is normally the durable file-backed service assembled by the HTTP bridge. Tests
   * and embedded runtimes may pass {@code null}; in that mode the route family remains present but
   * fails closed when a matched endpoint needs the handler.
   *
   * @param appDataService shared app-data service, or {@code null} when unavailable at startup
   */
  PlatformApiAppDataRoutes(AppDataService appDataService) {
    this.appDataService = appDataService;
  }

  /**
   * Routes a request whose first path segment is {@code app-data}.
   *
   * <p>The first segment is retained in {@code segments} so callers can pass the same decoded path
   * list used by the top-level switch. Supported subfamilies are {@code status}, {@code
   * namespaces}, {@code records}, {@code export}, and {@code import}. Unsupported methods return
   * stable {@code 405 method_not_allowed} responses with an {@code Allow} header map, while
   * unsupported path shapes raise the same {@code 404 not_found} exception used by other Platform
   * API route families.
   *
   * @param segments decoded path segments relative to the Platform API mount point, including
   *     {@code app-data} as the first segment
   * @param request full request metadata, including method, principal, and decoded form/query data
   * @return JSON response for the selected endpoint after app-principal scoping is applied
   */
  PlatformApiResponse route(List<String> segments, PlatformApiRequest request) {
    String appId = requireAppPrincipalId(request);
    AppDataApiHandler handler = appDataApiHandler();
    if (segments.size() < 2) {
      throw notFound();
    }
    return switch (segments.get(1)) {
      case "status" -> routeStatus(segments, request, handler, appId);
      case "namespaces" -> routeNamespaces(segments, request, handler, appId);
      case "records" -> routeRecords(segments, request, handler, appId);
      case "export" -> routeExport(segments, request, handler, appId);
      case "import" -> routeImport(segments, request, handler, appId);
      default -> throw notFound();
    };
  }

  private PlatformApiResponse routeStatus(
      List<String> segments, PlatformApiRequest request, AppDataApiHandler handler, String appId) {
    requireTopLevelEndpoint(segments);
    if (!METHOD_GET.equals(request.method())) {
      return methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
    }
    return PlatformApiResponse.ok(handler.status(appId));
  }

  private PlatformApiResponse routeExport(
      List<String> segments, PlatformApiRequest request, AppDataApiHandler handler, String appId) {
    requireTopLevelEndpoint(segments);
    if (!METHOD_GET.equals(request.method())) {
      return methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
    }
    return PlatformApiResponse.ok(handler.exportData(appId, request.queryParameters()));
  }

  private PlatformApiResponse routeImport(
      List<String> segments, PlatformApiRequest request, AppDataApiHandler handler, String appId) {
    requireTopLevelEndpoint(segments);
    if (!METHOD_POST.equals(request.method())) {
      return methodNotAllowed(METHOD_POST, POST_ONLY_MESSAGE);
    }
    return PlatformApiResponse.ok(handler.importData(appId, request.queryParameters()));
  }

  private PlatformApiResponse routeNamespaces(
      List<String> segments, PlatformApiRequest request, AppDataApiHandler handler, String appId) {
    if (segments.size() == 2) {
      if (!METHOD_GET.equals(request.method())) {
        return methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
      }
      return PlatformApiResponse.ok(handler.listNamespaces(appId));
    }
    if (segments.size() == 3) {
      if (METHOD_GET.equals(request.method())) {
        return PlatformApiResponse.ok(handler.getNamespace(appId, segments.get(2)));
      }
      if (METHOD_DELETE.equals(request.method())) {
        return PlatformApiResponse.ok(handler.deleteNamespace(appId, segments.get(2)));
      }
      return methodNotAllowed(
          "GET, DELETE", "Platform API v1 supports GET and DELETE requests only.");
    }
    if (segments.size() == 4 && "schema".equals(segments.get(3))) {
      if (!METHOD_POST.equals(request.method())) {
        return methodNotAllowed(METHOD_POST, POST_ONLY_MESSAGE);
      }
      return PlatformApiResponse.ok(
          handler.updateSchema(appId, segments.get(2), request.queryParameters()));
    }
    throw notFound();
  }

  private PlatformApiResponse routeRecords(
      List<String> segments, PlatformApiRequest request, AppDataApiHandler handler, String appId) {
    if (segments.size() == 2) {
      if (METHOD_GET.equals(request.method())) {
        return PlatformApiResponse.ok(handler.listRecords(appId, request.queryParameters()));
      }
      if (METHOD_POST.equals(request.method())) {
        return PlatformApiResponse.created(handler.putRecord(appId, request.queryParameters()));
      }
      return methodNotAllowed("GET, POST", "Platform API v1 supports GET and POST requests only.");
    }
    if (segments.size() == 4) {
      if (METHOD_GET.equals(request.method())) {
        return PlatformApiResponse.ok(handler.getRecord(appId, segments.get(2), segments.get(3)));
      }
      if (METHOD_DELETE.equals(request.method())) {
        return PlatformApiResponse.ok(
            handler.deleteRecord(appId, segments.get(2), segments.get(3)));
      }
      return methodNotAllowed(
          "GET, DELETE", "Platform API v1 supports GET and DELETE requests only.");
    }
    throw notFound();
  }

  private AppDataApiHandler appDataApiHandler() {
    if (appDataService == null) {
      throw new PlatformApiException(
          503, "app_data_service_unavailable", "App-data service is unavailable.");
    }
    return new AppDataApiHandler(appDataService);
  }

  private static String requireAppPrincipalId(PlatformApiRequest request) {
    if (!request.principal().isApp()) {
      throw new PlatformApiException(
          403, "forbidden", "This Platform API route requires an app principal.");
    }
    return request.principal().appId();
  }

  private static PlatformApiResponse methodNotAllowed(String allow, String message) {
    return PlatformApiResponse.error(405, Map.of("Allow", allow), "method_not_allowed", message);
  }

  private static void requireTopLevelEndpoint(List<String> segments) {
    if (segments.size() != 2) {
      throw notFound();
    }
  }

  private static PlatformApiException notFound() {
    return new PlatformApiException(404, "not_found", "Platform API route not found.");
  }
}

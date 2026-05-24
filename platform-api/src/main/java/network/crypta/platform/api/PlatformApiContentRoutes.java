package network.crypta.platform.api;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import network.crypta.platform.api.content.ContentApiHandler;
import network.crypta.platform.api.content.subscriptions.ContentSubscriptionService;
import network.crypta.platform.api.content.subscriptions.ContentSubscriptionsApiHandler;
import network.crypta.runtime.spi.ContentFetchPort;
import network.crypta.runtime.spi.RuntimePorts;

/**
 * Routes the Platform API {@code /content} endpoint family.
 *
 * <p>The top-level router owns authorization and audit recording. This collaborator owns the
 * content-specific path switch: bounded foreground fetches at {@code /content/fetch} and app-scoped
 * durable subscriptions beneath {@code /content/subscriptions}. Keeping this branch separate keeps
 * the main router from depending directly on the foreground-fetch and subscription handler classes
 * while preserving the same method checks, app-principal scoping, and stable error responses.
 */
final class PlatformApiContentRoutes {
  private static final String METHOD_DELETE = "DELETE";
  private static final String METHOD_GET = "GET";
  private static final String METHOD_POST = "POST";
  private static final String GET_POST_ONLY_MESSAGE =
      "Platform API v1 supports GET and POST requests only.";
  private static final String POST_ONLY_MESSAGE = "Platform API v1 supports POST requests only.";

  private final RuntimePorts runtimePorts;
  private final ContentSubscriptionService contentSubscriptionService;

  /**
   * Creates content routes from runtime ports and the optional subscription service.
   *
   * @param runtimePorts detached runtime-port aggregate used for foreground content fetches
   * @param contentSubscriptionService optional shared content-subscription service
   * @throws NullPointerException if {@code runtimePorts} is {@code null}
   */
  PlatformApiContentRoutes(
      RuntimePorts runtimePorts, ContentSubscriptionService contentSubscriptionService) {
    this.runtimePorts = Objects.requireNonNull(runtimePorts, "runtimePorts");
    this.contentSubscriptionService = contentSubscriptionService;
  }

  /**
   * Routes a request whose first path segment is {@code content}.
   *
   * @param segments decoded path segments relative to the Platform API mount point
   * @param request full request metadata, including principal and query parameters
   * @return JSON response for the selected content endpoint
   */
  PlatformApiResponse route(List<String> segments, PlatformApiRequest request) {
    if (segments.size() == 2 && "fetch".equals(segments.get(1))) {
      if (!METHOD_POST.equals(request.method())) {
        return methodNotAllowed(METHOD_POST, POST_ONLY_MESSAGE);
      }
      return PlatformApiResponse.ok(contentApiHandler().fetch(request.queryParameters()));
    }
    if (segments.size() >= 2 && "subscriptions".equals(segments.get(1))) {
      return routeContentSubscriptionsRequest(segments, request);
    }
    throw notFound();
  }

  private PlatformApiResponse routeContentSubscriptionsRequest(
      List<String> segments, PlatformApiRequest request) {
    String appId = requireAppPrincipalId(request);
    ContentSubscriptionsApiHandler handler = contentSubscriptionsApiHandler();
    if (segments.size() == 2) {
      if (METHOD_GET.equals(request.method())) {
        return PlatformApiResponse.ok(handler.list(appId));
      }
      if (METHOD_POST.equals(request.method())) {
        return PlatformApiResponse.created(handler.create(appId, request.queryParameters()));
      }
      return methodNotAllowed("GET, POST", GET_POST_ONLY_MESSAGE);
    }
    if (segments.size() == 3) {
      if (METHOD_GET.equals(request.method())) {
        return PlatformApiResponse.ok(handler.get(appId, segments.get(2)));
      }
      if (METHOD_DELETE.equals(request.method())) {
        return PlatformApiResponse.ok(handler.delete(appId, segments.get(2)));
      }
      return methodNotAllowed(
          "GET, DELETE", "Platform API v1 supports GET and DELETE requests only.");
    }
    if (segments.size() == 4) {
      if (!METHOD_POST.equals(request.method())) {
        return methodNotAllowed(METHOD_POST, POST_ONLY_MESSAGE);
      }
      return switch (segments.get(3)) {
        case "refresh" -> PlatformApiResponse.ok(handler.refresh(appId, segments.get(2)));
        case "pause" -> PlatformApiResponse.ok(handler.pause(appId, segments.get(2)));
        case "resume" -> PlatformApiResponse.ok(handler.resume(appId, segments.get(2)));
        default -> throw notFound();
      };
    }
    throw notFound();
  }

  private ContentApiHandler contentApiHandler() {
    ContentFetchPort contentFetchPort = runtimePorts.contentFetch();
    if (contentFetchPort == null) {
      throw new PlatformApiException(
          503, "content_fetch_failed", "Content fetch service is unavailable.");
    }
    return new ContentApiHandler(contentFetchPort);
  }

  private ContentSubscriptionsApiHandler contentSubscriptionsApiHandler() {
    if (contentSubscriptionService == null) {
      throw new PlatformApiException(
          503,
          "content_subscription_service_unavailable",
          "Content subscription service is unavailable.");
    }
    return new ContentSubscriptionsApiHandler(contentSubscriptionService);
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

  private static PlatformApiException notFound() {
    return new PlatformApiException(404, "not_found", "Platform API route not found.");
  }
}

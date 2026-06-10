package network.crypta.platform.api;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import network.crypta.platform.api.appservices.AppServiceCoordinator;

/**
 * Routes local app-service discovery, grant lifecycle, audit, and invocation endpoints.
 *
 * <p>Authorization remains contract-driven in {@link PlatformApiRouter}. This route class keeps
 * method/path dispatch deterministic and enforces the principal boundaries that the contract cannot
 * express alone, such as host-only approval/audit and app-only invocation.
 *
 * <p>The dispatcher deliberately avoids a reserved provider-id list. It treats path shape as the
 * source of truth: {@code /app-services/{provider}/services/...} is always a provider-service
 * route, even when {@code {provider}} is the literal {@code grants}. Only the exact {@code
 * /app-services/grants/{grantId}/{action}} shape reaches grant mutation. That rule keeps signed app
 * ids usable without making the public API depend on a growing set of internal words.
 *
 * <p>The route family is deliberately small:
 *
 * <ul>
 *   <li>{@code /app-services} lists advertised services and manifest-declared requests.
 *   <li>{@code /app-services/dependencies} lists the caller-visible dependency graph.
 *   <li>{@code /app-services/dependencies/consumers/{consumerAppId}} reads one consumer graph
 *       without conflicting with provider app ids.
 *   <li>{@code /app-services/grant-bundles} lists or requests grant bundles.
 *   <li>{@code /app-services/grants} lists or creates consumer grant records.
 *   <li>{@code /app-services/grants/{grantId}/approve} and {@code revoke} mutate grant state.
 *   <li>{@code /app-services/{providerAppId}/services/{serviceId}/invoke} calls an explicit
 *       platform adapter through the coordinator.
 * </ul>
 *
 * <p>This class does not decide whether a caller has {@code app.services.read} or {@code
 * app.services.call}; the router capability table performs that check before dispatch. The
 * coordinator then rechecks the app principal, current manifests, grant state, and adapter binding
 * at the point where those values are actually used.
 *
 * <p>Route methods intentionally do not inspect raw invocation payloads beyond method and path
 * shape. That keeps parsing, normalization, redaction, and audit decisions in the coordinator and
 * service adapters, where they can be applied consistently to app calls, Web Shell calls, and
 * release-certification fixtures.
 *
 * @param coordinator shared coordinator, or {@code null} when app services are unavailable
 */
record PlatformApiAppServiceRoutes(AppServiceCoordinator coordinator) {
  /** HTTP method token for discovery, list, and audit routes. */
  private static final String METHOD_GET = "GET";

  /** HTTP method token for grant creation, grant mutation, and invocation routes. */
  private static final String METHOD_POST = "POST";

  /** Shared route segment and response key for one grant record. */
  private static final String RESOURCE_GRANT = "grant";

  /** Shared route segment and response key for one grant-bundle record. */
  private static final String RESOURCE_BUNDLE = "bundle";

  /** Shared top-level route segment for dependency graph reads. */
  private static final String RESOURCE_DEPENDENCIES = "dependencies";

  /** Disambiguating dependency route segment for per-consumer graph reads. */
  private static final String RESOURCE_CONSUMERS = "consumers";

  /** Shared top-level route segment for grant-bundle collections. */
  private static final String RESOURCE_GRANT_BUNDLES = "grant-bundles";

  /** Shared route segment and response key for grant collections. */
  private static final String RESOURCE_GRANTS = "grants";

  /** Shared route segment and response key for service collections. */
  private static final String RESOURCE_SERVICES = "services";

  /** Stable method error text shared by GET-only app-service routes. */
  private static final String GET_ONLY_MESSAGE = "Platform API v1 supports GET requests only.";

  /** Stable method error text shared by POST-only app-service routes. */
  private static final String POST_ONLY_MESSAGE = "Platform API v1 supports POST requests only.";

  /**
   * Dispatches a Platform API request below {@code /api/v1/app-services}.
   *
   * <p>The segment list includes the leading {@code app-services} segment. Method validation stays
   * local to each route so callers receive the same {@code Allow} metadata used elsewhere in the
   * Platform API. All response bodies are JSON-compatible envelopes produced by the coordinator.
   *
   * @param segments path segments including {@code app-services}
   * @param request request with method, principal, and decoded parameters
   * @return response envelope for the matched route
   */
  PlatformApiResponse route(List<String> segments, PlatformApiRequest request) {
    AppServiceCoordinator service = requireCoordinator();
    return switch (segments.size()) {
      case 1 -> routeRoot(request, service);
      case 2 -> routeTopLevel(segments.get(1), request, service);
      case 3 ->
          routeDependencyOrProviderServices(segments.get(1), segments.get(2), request, service);
      case 4 ->
          routeDependencyConsumerGrantActionOrService(
              segments.get(1), segments.get(2), segments.get(3), request, service);
      case 5 ->
          routeInvocation(
              segments.get(1), segments.get(2), segments.get(3), segments.get(4), request, service);
      default -> throw notFound();
    };
  }

  /**
   * Handles {@code GET /app-services}.
   *
   * <p>The response combines advertised provider services with manifest-declared consumer requests.
   * App principals see only request declarations for their own app; host/operator callers see the
   * full local review surface. The envelope is intentionally read-only metadata: it can explain
   * what an app provides or intends to request, but it cannot create, approve, or exercise a grant.
   *
   * @param request original request, used for method and principal checks
   * @param service coordinator that supplies descriptor and request JSON
   * @return service and request envelope
   */
  private PlatformApiResponse routeRoot(PlatformApiRequest request, AppServiceCoordinator service) {
    if (!METHOD_GET.equals(request.method())) {
      return methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
    }
    LinkedHashMap<String, Object> envelope = LinkedHashMap.newLinkedHashMap(2);
    envelope.put(RESOURCE_SERVICES, service.listServices());
    envelope.put("requests", service.listRequests(request.principal()));
    return PlatformApiResponse.ok(envelope);
  }

  /**
   * Dispatches top-level collection resources below {@code /app-services}.
   *
   * <p>Only {@code grants} and {@code audit} are top-level resources. Provider service routes need
   * at least one additional segment and are routed separately so provider app ids can use ordinary
   * app-id syntax without a reserved-word list.
   *
   * @param resource second path segment
   * @param request original request, including method and principal
   * @param service coordinator that owns grants and audit records
   * @return response for the top-level collection route
   */
  private PlatformApiResponse routeTopLevel(
      String resource, PlatformApiRequest request, AppServiceCoordinator service) {
    if (RESOURCE_GRANTS.equals(resource)) {
      return routeGrantsCollection(request, service);
    }
    if (RESOURCE_GRANT_BUNDLES.equals(resource)) {
      return routeGrantBundlesCollection(request, service);
    }
    if (RESOURCE_DEPENDENCIES.equals(resource)) {
      if (!METHOD_GET.equals(request.method())) {
        return methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
      }
      return PlatformApiResponse.ok(
          envelope("dependencyGraph", service.dependencyGraph(request.principal())));
    }
    if ("audit".equals(resource)) {
      if (!METHOD_GET.equals(request.method())) {
        return methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
      }
      return PlatformApiResponse.ok(
          envelope("audit", service.audit(request.principal(), request.queryParameters())));
    }
    throw notFound();
  }

  /**
   * Handles grant collection listing and creation.
   *
   * <p>GET returns the caller-visible grant list. POST creates a pending request for the
   * authenticated app principal; the coordinator rejects host/operator callers for creation and
   * validates provider, service, scopes, contexts, and app manifest permissions. The route wraps
   * the created record in a {@code grant} envelope and leaves all lifecycle transitions to the
   * coordinator so audit and persistence stay centralized.
   *
   * @param request request containing method, principal, and form parameters
   * @param service coordinator that reads or creates grant records
   * @return grant list or newly created grant envelope
   */
  private PlatformApiResponse routeGrantsCollection(
      PlatformApiRequest request, AppServiceCoordinator service) {
    if (METHOD_GET.equals(request.method())) {
      return PlatformApiResponse.ok(
          envelope(RESOURCE_GRANTS, service.listGrants(request.principal())));
    }
    if (METHOD_POST.equals(request.method())) {
      return PlatformApiResponse.created(
          envelope(
              RESOURCE_GRANT,
              service.requestGrant(request.principal(), request.queryParameters())));
    }
    return methodNotAllowed("GET, POST", "Platform API v1 supports GET and POST requests only.");
  }

  private PlatformApiResponse routeGrantBundlesCollection(
      PlatformApiRequest request, AppServiceCoordinator service) {
    if (METHOD_GET.equals(request.method())) {
      return PlatformApiResponse.ok(envelope("bundles", service.listBundles(request.principal())));
    }
    if (METHOD_POST.equals(request.method())) {
      return PlatformApiResponse.created(
          envelope(
              RESOURCE_BUNDLE,
              service.requestBundle(request.principal(), request.queryParameters())));
    }
    return methodNotAllowed("GET, POST", "Platform API v1 supports GET and POST requests only.");
  }

  private PlatformApiResponse routeDependencyOrProviderServices(
      String first, String second, PlatformApiRequest request, AppServiceCoordinator service) {
    if (RESOURCE_SERVICES.equals(second)) {
      return routeProviderServices(first, second, request, service);
    }
    if (RESOURCE_DEPENDENCIES.equals(first)) {
      return routeConsumerDependencies(second, request, service);
    }
    return routeProviderServices(first, second, request, service);
  }

  private PlatformApiResponse routeConsumerDependencies(
      String consumerAppId, PlatformApiRequest request, AppServiceCoordinator service) {
    if (!METHOD_GET.equals(request.method())) {
      return methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
    }
    return PlatformApiResponse.ok(
        envelope("dependencyGraph", service.dependencyGraph(request.principal(), consumerAppId)));
  }

  /**
   * Handles {@code /app-services/{providerAppId}/services}.
   *
   * <p>This route lists all services currently advertised by a single installed provider. The
   * provider id is normalized and checked by the coordinator, and no installed paths or process
   * details are included in the response.
   *
   * @param providerAppId provider app id path segment
   * @param servicesSegment path segment that selects provider service listing
   * @param request request containing the HTTP method
   * @param service coordinator used for provider service discovery
   * @return provider-scoped service descriptor envelope
   */
  private PlatformApiResponse routeProviderServices(
      String providerAppId,
      String servicesSegment,
      PlatformApiRequest request,
      AppServiceCoordinator service) {
    if (!RESOURCE_SERVICES.equals(servicesSegment)) {
      throw notFound();
    }
    if (!METHOD_GET.equals(request.method())) {
      return methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
    }
    return PlatformApiResponse.ok(
        envelope(RESOURCE_SERVICES, service.listProviderServices(providerAppId)));
  }

  /**
   * Resolves four-segment routes that can mean per-consumer dependency read, grant mutation, or
   * service read.
   *
   * <p>Provider service reads are checked before grant actions so an installed provider with app id
   * {@code grants} remains reachable at {@code /app-services/grants/services/{serviceId}}. Grant
   * actions still use {@code /app-services/grants/{grantId}/{approve|revoke}}.
   *
   * @param first provider app id, literal {@code dependencies}, or literal {@code grants}
   * @param second service-list marker segment, literal {@code consumers}, or a grant id
   * @param third consumer app id, service id, or grant action
   * @param request request containing method and principal
   * @param service coordinator used for service reads or grant mutation
   * @return service descriptor or updated grant envelope
   */
  private PlatformApiResponse routeDependencyConsumerGrantActionOrService(
      String first,
      String second,
      String third,
      PlatformApiRequest request,
      AppServiceCoordinator service) {
    if (RESOURCE_DEPENDENCIES.equals(first) && RESOURCE_CONSUMERS.equals(second)) {
      return routeConsumerDependencies(third, request, service);
    }
    if (RESOURCE_SERVICES.equals(second)) {
      if (!METHOD_GET.equals(request.method())) {
        return methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
      }
      return PlatformApiResponse.ok(envelope("service", service.getService(first, third)));
    }
    if (RESOURCE_GRANTS.equals(first)) {
      return routeGrantAction(second, third, request, service);
    }
    if (RESOURCE_GRANT_BUNDLES.equals(first)) {
      return routeGrantBundleAction(second, third, request, service);
    }
    throw notFound();
  }

  /**
   * Handles one grant lifecycle action.
   *
   * <p>Approval is host/operator-only inside the coordinator. Revocation can be host/operator
   * initiated or app-initiated when the app owns the grant. Unknown actions are reported as route
   * misses rather than generic mutation failures.
   *
   * @param grantId stable grant id path segment
   * @param action literal {@code approve} or {@code revoke}
   * @param request request containing method and principal
   * @param service coordinator that mutates the grant
   * @return updated grant envelope
   */
  private PlatformApiResponse routeGrantAction(
      String grantId, String action, PlatformApiRequest request, AppServiceCoordinator service) {
    if (!METHOD_POST.equals(request.method())) {
      return methodNotAllowed(METHOD_POST, POST_ONLY_MESSAGE);
    }
    return switch (action) {
      case "approve" ->
          PlatformApiResponse.ok(
              envelope(RESOURCE_GRANT, service.approveGrant(request.principal(), grantId)));
      case "revoke" ->
          PlatformApiResponse.ok(
              envelope(RESOURCE_GRANT, service.revokeGrant(request.principal(), grantId)));
      default -> throw notFound();
    };
  }

  private PlatformApiResponse routeGrantBundleAction(
      String bundleId, String action, PlatformApiRequest request, AppServiceCoordinator service) {
    if (!METHOD_POST.equals(request.method())) {
      return methodNotAllowed(METHOD_POST, POST_ONLY_MESSAGE);
    }
    return switch (action) {
      case "approve" ->
          PlatformApiResponse.ok(
              envelope(RESOURCE_BUNDLE, service.approveBundle(request.principal(), bundleId)));
      case "reject" ->
          PlatformApiResponse.ok(
              envelope(RESOURCE_BUNDLE, service.rejectBundle(request.principal(), bundleId)));
      case "renew" ->
          PlatformApiResponse.ok(
              envelope(RESOURCE_BUNDLE, service.renewBundle(request.principal(), bundleId)));
      default -> throw notFound();
    };
  }

  /**
   * Handles platform-mediated service invocation.
   *
   * <p>The route accepts only the explicit {@code invoke} action below a provider service. It is
   * not a generic proxy and it never forwards arbitrary hostnames, ports, or URLs. The coordinator
   * rechecks the app principal, consumer permissions, provider advertisement, active grant,
   * requested scope and context, and registered adapter for every invocation before calling any
   * service-specific code.
   *
   * @param providerAppId provider app id path segment
   * @param servicesSegment path segment that selects provider service invocation
   * @param serviceId public service id path segment
   * @param action literal {@code invoke} segment
   * @param request request containing method, principal, and invocation parameters
   * @param service coordinator that authorizes and dispatches the invocation
   * @return service-call envelope from the coordinator
   */
  private PlatformApiResponse routeInvocation(
      String providerAppId,
      String servicesSegment,
      String serviceId,
      String action,
      PlatformApiRequest request,
      AppServiceCoordinator service) {
    if (!RESOURCE_SERVICES.equals(servicesSegment) || !"invoke".equals(action)) {
      throw notFound();
    }
    if (!METHOD_POST.equals(request.method())) {
      return methodNotAllowed(METHOD_POST, POST_ONLY_MESSAGE);
    }
    return PlatformApiResponse.ok(
        service.invoke(request.principal(), providerAppId, serviceId, request.queryParameters()));
  }

  /**
   * Returns the configured coordinator or raises the app-service unavailable error.
   *
   * @return initialized coordinator for this route family
   */
  private AppServiceCoordinator requireCoordinator() {
    if (coordinator == null) {
      throw new PlatformApiException(
          503, "app_services_unavailable", "App-service coordinator is unavailable.");
    }
    return coordinator;
  }

  /**
   * Wraps one JSON-compatible value in a deterministic single-key response map.
   *
   * @param key public envelope key
   * @param value JSON-compatible value to expose under {@code key}
   * @return linked map preserving envelope field order
   */
  private static Map<String, Object> envelope(String key, Object value) {
    LinkedHashMap<String, Object> envelope = LinkedHashMap.newLinkedHashMap(1);
    envelope.put(key, value);
    return envelope;
  }

  /**
   * Builds a method-not-allowed response with the route-specific {@code Allow} value.
   *
   * @param allow comma-separated allowed method list
   * @param message stable human-readable error text
   * @return Platform API error response with status {@code 405}
   */
  private static PlatformApiResponse methodNotAllowed(String allow, String message) {
    return PlatformApiResponse.error(405, Map.of("Allow", allow), "method_not_allowed", message);
  }

  /**
   * Builds the shared route-miss exception for unmatched app-service paths.
   *
   * @return Platform API not-found exception
   */
  private static PlatformApiException notFound() {
    return new PlatformApiException(404, "not_found", "Platform API route not found.");
  }
}

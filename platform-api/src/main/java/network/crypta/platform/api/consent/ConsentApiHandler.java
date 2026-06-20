package network.crypta.platform.api.consent;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.api.PlatformApiParameters;
import network.crypta.platform.api.PlatformApiRequest;
import network.crypta.platform.api.PlatformApiResponse;

/**
 * Host/operator route handler for Platform API v1 consent previews, decisions, and audit reads.
 *
 * <p>The handler exposes only local operator endpoints beneath {@code /api/v1/consent}. It
 * translates HTTP method and path validation into Platform API responses, delegates consent
 * semantics to {@link ConsentService}, and wraps successful payloads in the stable response
 * envelopes consumed by Web Shell and other host UI clients. App principals are rejected before
 * dispatch so apps cannot approve their own install, update, migration, or service-grant decisions.
 */
public final class ConsentApiHandler {
  private static final String METHOD_GET = "GET";
  private static final String METHOD_POST = "POST";
  private static final String GET_ONLY_MESSAGE = "Platform API v1 supports GET requests only.";
  private static final String POST_ONLY_MESSAGE = "Platform API v1 supports POST requests only.";
  private static final String PARAM_APP_ID = "appId";
  private static final String ENVELOPE_CONSENT = "consent";
  private static final String ENVELOPE_DECISION = "decision";

  private final ConsentService consentService;

  /**
   * Creates a route handler backed by the shared consent service.
   *
   * <p>The supplied service owns preview construction, decision storage, stale-digest checks, and
   * audit persistence. The handler keeps no per-request state beyond method/path dispatch.
   *
   * @param consentService service that implements the consent policy and audit workflow
   */
  public ConsentApiHandler(ConsentService consentService) {
    this.consentService = Objects.requireNonNull(consentService, "consentService");
  }

  /**
   * Dispatches a host/operator consent request.
   *
   * <p>Expected routes use a two-segment consent path, such as {@code consent/install-preview} or
   * {@code consent/approve}. Preview routes return a freshly registered snapshot and decision
   * routes record an approval, rejection, or deferral for an existing snapshot digest.
   *
   * @param segments path segments beneath the Platform API version prefix
   * @param request request metadata, query parameters, and authenticated principal
   * @return Platform API response containing a {@code consent}, {@code decision}, or {@code audit}
   *     envelope
   */
  public PlatformApiResponse route(List<String> segments, PlatformApiRequest request) {
    requireHostOperator(request);
    if (segments.size() != 2) {
      throw notFound();
    }
    String action = segments.get(1);
    return switch (action) {
      case "install-preview" -> installPreview(request);
      case "catalog-update-preview" -> catalogUpdatePreview(request);
      case "update-preview" -> updatePreview(request);
      case "service-grant-preview" -> serviceGrantPreview(request);
      case "approve" -> approve(request);
      case "reject" -> reject(request);
      case "defer" -> defer(request);
      case "audit" -> audit(request);
      default -> throw notFound();
    };
  }

  private PlatformApiResponse installPreview(PlatformApiRequest request) {
    if (!METHOD_GET.equals(request.method())) {
      return methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
    }
    String catalogId = PlatformApiParameters.requireString(request.queryParameters(), "catalogId");
    String appId = PlatformApiParameters.requireString(request.queryParameters(), PARAM_APP_ID);
    return PlatformApiResponse.ok(
        envelope(ENVELOPE_CONSENT, consentService.installPreview(catalogId, appId)));
  }

  private PlatformApiResponse updatePreview(PlatformApiRequest request) {
    if (METHOD_GET.equals(request.method())) {
      String appId = PlatformApiParameters.requireString(request.queryParameters(), PARAM_APP_ID);
      return PlatformApiResponse.ok(
          envelope(ENVELOPE_CONSENT, consentService.updatePreviewReadOnly(appId)));
    }
    if (!METHOD_POST.equals(request.method())) {
      return methodNotAllowed("GET, POST", "Platform API v1 supports GET or POST requests.");
    }
    String appId = PlatformApiParameters.requireString(request.queryParameters(), PARAM_APP_ID);
    boolean refreshCatalogs =
        PlatformApiParameters.readBoolean(request.queryParameters(), "refreshCatalogs", false);
    return PlatformApiResponse.ok(
        envelope(ENVELOPE_CONSENT, consentService.updatePreview(appId, refreshCatalogs)));
  }

  private PlatformApiResponse catalogUpdatePreview(PlatformApiRequest request) {
    if (!METHOD_GET.equals(request.method())) {
      return methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
    }
    String catalogId = PlatformApiParameters.requireString(request.queryParameters(), "catalogId");
    String appId = PlatformApiParameters.requireString(request.queryParameters(), PARAM_APP_ID);
    return PlatformApiResponse.ok(
        envelope(ENVELOPE_CONSENT, consentService.catalogUpdatePreview(catalogId, appId)));
  }

  private PlatformApiResponse serviceGrantPreview(PlatformApiRequest request) {
    if (!METHOD_GET.equals(request.method())) {
      return methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
    }
    String bundleId = PlatformApiParameters.requireString(request.queryParameters(), "bundleId");
    return PlatformApiResponse.ok(
        envelope(ENVELOPE_CONSENT, consentService.serviceGrantPreview(bundleId)));
  }

  private PlatformApiResponse approve(PlatformApiRequest request) {
    if (!METHOD_POST.equals(request.method())) {
      return methodNotAllowed(METHOD_POST, POST_ONLY_MESSAGE);
    }
    return PlatformApiResponse.ok(
        envelope(
            ENVELOPE_DECISION,
            consentService.approve(request.queryParameters(), request.principal())));
  }

  private PlatformApiResponse reject(PlatformApiRequest request) {
    if (!METHOD_POST.equals(request.method())) {
      return methodNotAllowed(METHOD_POST, POST_ONLY_MESSAGE);
    }
    return PlatformApiResponse.ok(
        envelope(
            ENVELOPE_DECISION,
            consentService.reject(request.queryParameters(), request.principal())));
  }

  private PlatformApiResponse defer(PlatformApiRequest request) {
    if (!METHOD_POST.equals(request.method())) {
      return methodNotAllowed(METHOD_POST, POST_ONLY_MESSAGE);
    }
    return PlatformApiResponse.ok(
        envelope(
            ENVELOPE_DECISION,
            consentService.defer(request.queryParameters(), request.principal())));
  }

  private PlatformApiResponse audit(PlatformApiRequest request) {
    if (!METHOD_GET.equals(request.method())) {
      return methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
    }
    String appId =
        PlatformApiParameters.readOptionalString(request.queryParameters(), PARAM_APP_ID);
    return PlatformApiResponse.ok(envelope("audit", consentService.audit(appId)));
  }

  private static void requireHostOperator(PlatformApiRequest request) {
    if (request.principal().isApp()) {
      throw new PlatformApiException(
          403,
          "host_operator_required",
          "This Platform API route requires a host/operator principal.");
    }
  }

  private static Map<String, Object> envelope(String key, Object value) {
    return Map.of(key, value);
  }

  private static PlatformApiResponse methodNotAllowed(String allow, String message) {
    return PlatformApiResponse.error(405, Map.of("Allow", allow), "method_not_allowed", message);
  }

  private static PlatformApiException notFound() {
    return new PlatformApiException(404, "not_found", "Platform API route not found.");
  }
}

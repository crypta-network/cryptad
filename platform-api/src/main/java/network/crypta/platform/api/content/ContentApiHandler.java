package network.crypta.platform.api.content;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.api.PlatformApiParameters;
import network.crypta.platform.api.networkbudget.AppNetworkBudgetDecision;
import network.crypta.platform.api.networkbudget.AppNetworkBudgetLease;
import network.crypta.platform.api.networkbudget.AppNetworkBudgetOperation;
import network.crypta.platform.api.networkbudget.AppNetworkBudgetService;
import network.crypta.runtime.spi.BoundedContentFetchRequest;
import network.crypta.runtime.spi.BoundedContentFetchResult;
import network.crypta.runtime.spi.ContentFetchException;
import network.crypta.runtime.spi.ContentFetchPort;

/**
 * Handles foreground, app-facing content reads for the Platform API content route.
 *
 * <p>This handler backs {@code POST /api/v1/content/fetch}. It receives already decoded form
 * parameters from the router, validates that the caller supplied a Crypta/Freenet content key,
 * normalizes optional {@code crypta:} URI forms, and then delegates the actual network read to the
 * detached {@link ContentFetchPort}. The handler is deliberately narrower than the runtime fetch
 * SPI: app principals can request bounded {@code CHK@}, {@code SSK@}, {@code USK@}, and {@code
 * KSK@} keys, but cannot use the route as a local file reader, an arbitrary HTTP client, or a
 * source of daemon-internal diagnostics.
 *
 * <p>Instances keep no per-request mutable state beyond the injected fetch port. They can therefore
 * be reused by a router as long as the supplied port is safe for that router's concurrency model.
 * Response maps are ordered for stable JSON output and contain only app-facing fields such as the
 * requested URI, sanitized resolved URI, byte length, selected format, and either UTF-8 text or
 * base64 content.
 *
 * <p>Notable behavior:
 *
 * <ul>
 *   <li>Defaults are conservative: 256 KiB and 30 seconds.
 *   <li>Hard app-facing caps are 1 MiB and 60 seconds.
 *   <li>Runtime failures are mapped to stable {@link PlatformApiException} codes without exposing
 *       raw exception text.
 * </ul>
 */
public final class ContentApiHandler {
  private static final String DEFAULT_PURPOSE = "reference-app";
  private static final String FORMAT_PARAMETER = "format";
  private static final String FORMAT_TEXT = "text";
  private static final String FORMAT_BASE64 = "base64";

  private final ContentFetchPort contentFetchPort;
  private final AppNetworkBudgetService networkBudgetService;
  private final AppNetworkBudgetOperation budgetOperation;

  /**
   * Creates a handler bound to one detached runtime fetch port.
   *
   * <p>The port is the only boundary through which fetched content enters this API layer. The
   * handler performs app-facing validation before invoking it and then applies a second byte-bound
   * check to the returned payload. Passing {@code null} is a wiring error and is rejected during
   * construction rather than deferred to the first request.
   *
   * @param contentFetchPort runtime content-fetch port used after request validation succeeds
   * @throws NullPointerException when {@code contentFetchPort} is {@code null}
   */
  public ContentApiHandler(ContentFetchPort contentFetchPort) {
    this(contentFetchPort, null, AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH);
  }

  /**
   * Creates a handler with an optional shared app-network budget service.
   *
   * <p>When the service is present and callers supply an app id to {@link #fetch(Map, String)}, the
   * handler acquires budget after source validation and before invoking the runtime fetch port.
   * Reduced embeddings and host/operator callers can omit the service or app id to preserve the
   * existing unbudgeted path.
   *
   * @param contentFetchPort runtime content-fetch port used after request validation succeeds
   * @param networkBudgetService optional shared app-network budget service
   */
  public ContentApiHandler(
      ContentFetchPort contentFetchPort, AppNetworkBudgetService networkBudgetService) {
    this(
        contentFetchPort, networkBudgetService, AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH);
  }

  /**
   * Creates a handler with an explicit budget operation for internal content-fetch users.
   *
   * @param contentFetchPort runtime content-fetch port used after request validation succeeds
   * @param networkBudgetService optional shared app-network budget service
   * @param budgetOperation budget operation charged when an app id is supplied
   */
  public ContentApiHandler(
      ContentFetchPort contentFetchPort,
      AppNetworkBudgetService networkBudgetService,
      AppNetworkBudgetOperation budgetOperation) {
    this.contentFetchPort = Objects.requireNonNull(contentFetchPort, "contentFetchPort");
    this.networkBudgetService = networkBudgetService;
    this.budgetOperation = Objects.requireNonNull(budgetOperation, "budgetOperation");
  }

  /**
   * Fetches one bounded Crypta content document for an app-facing form request.
   *
   * <p>The required {@code uri} parameter must name a supported Crypta/Freenet content key.
   * Optional {@code maxBytes}, {@code timeoutMillis}, {@code format}, and {@code purpose}
   * parameters refine the bounded runtime request. {@code format=text} decodes the fetched bytes as
   * strict UTF-8, while {@code format=base64} leaves binary content encoded for the caller. The
   * method returns a JSON-compatible map; it does not log request bodies, fetched bodies,
   * browser-session tokens, or raw runtime exception messages.
   *
   * @param parameters decoded form parameters keyed by Platform API parameter name
   * @return ordered JSON-compatible response containing fetch metadata and content bytes
   * @throws PlatformApiException when validation, fetching, bounds checking, or text decoding fails
   */
  public Map<String, Object> fetch(Map<String, List<String>> parameters) {
    return fetch(parameters, null);
  }

  /**
   * Fetches one bounded Crypta content document with optional app budget enforcement.
   *
   * <p>Budget acquisition happens only after the request URI and app-facing bounds pass validation.
   * That prevents rejected local paths, arbitrary URLs, and malformed sources from consuming quota.
   *
   * @param parameters decoded form parameters keyed by Platform API parameter name
   * @param appId authenticated app id to charge, or {@code null} for host/operator/reduced callers
   * @return ordered JSON-compatible response containing fetch metadata and content bytes
   * @throws PlatformApiException when validation, budget, fetching, bounds checking, or text
   *     decoding fails
   */
  public Map<String, Object> fetch(Map<String, List<String>> parameters, String appId) {
    FetchRequest request = parseRequest(parameters);
    try (var _ = acquireBudget(appId)) {
      BoundedContentFetchResult result = fetchContent(request);
      byte[] bytes = result.bytes();
      if (bytes.length > request.maxBytes()) {
        throw new PlatformApiException(
            502, "content_fetch_too_large", "Fetched content exceeded the configured byte bound.");
      }
      return responseBody(request, result, bytes);
    }
  }

  private AppNetworkBudgetLease acquireBudget(String appId) {
    if (networkBudgetService == null || appId == null || appId.isBlank()) {
      return AppNetworkBudgetLease.noop();
    }
    AppNetworkBudgetDecision decision = networkBudgetService.acquire(appId, budgetOperation);
    if (!decision.allowed()) {
      throw new PlatformApiException(
          decision.statusCode(), decision.errorCode(), decision.message());
    }
    return decision.lease();
  }

  private FetchRequest parseRequest(Map<String, List<String>> parameters) {
    ContentFetchPolicy.NormalizedContentSource source =
        ContentFetchPolicy.normalizeForegroundSource(
            PlatformApiParameters.requireString(parameters, "uri"));
    long maxBytes =
        readPositiveLong(
            parameters,
            "maxBytes",
            ContentFetchPolicy.DEFAULT_APP_FETCH_MAX_BYTES,
            ContentFetchPolicy.HARD_APP_FETCH_MAX_BYTES);
    long timeoutMillis =
        readPositiveLong(
            parameters,
            "timeoutMillis",
            ContentFetchPolicy.DEFAULT_APP_FETCH_TIMEOUT_MILLIS,
            ContentFetchPolicy.HARD_APP_FETCH_TIMEOUT_MILLIS);
    String format = readFormat(parameters);
    String purpose = readPurpose(parameters);
    return new FetchRequest(
        source.requestedUri(), source.runtimeUri(), maxBytes, timeoutMillis, format, purpose);
  }

  private BoundedContentFetchResult fetchContent(FetchRequest request) {
    try {
      return contentFetchPort.fetchContent(
          new BoundedContentFetchRequest(
              request.runtimeUri(),
              request.maxBytes(),
              Duration.ofMillis(request.timeoutMillis()),
              request.purpose()));
    } catch (ContentFetchException exception) {
      throw mappedFetchException(exception);
    } catch (RuntimeException _) {
      throw new PlatformApiException(502, "content_fetch_failed", "Content fetch failed.");
    }
  }

  private static PlatformApiException mappedFetchException(ContentFetchException exception) {
    return switch (exception.errorCode()) {
      case ContentFetchException.INVALID_CATALOG_SOURCE ->
          new PlatformApiException(
              400, "invalid_content_uri", "The content URI is malformed or unsupported.");
      case ContentFetchException.CATALOG_FETCH_TIMEOUT ->
          new PlatformApiException(504, "content_fetch_timeout", "Content fetch timed out.");
      case ContentFetchException.CATALOG_FETCH_TOO_LARGE ->
          new PlatformApiException(
              502,
              "content_fetch_too_large",
              "Fetched content exceeded the configured byte bound.");
      default -> new PlatformApiException(502, "content_fetch_failed", "Content fetch failed.");
    };
  }

  private static Map<String, Object> responseBody(
      FetchRequest request, BoundedContentFetchResult result, byte[] bytes) {
    LinkedHashMap<String, Object> body = LinkedHashMap.newLinkedHashMap(7);
    body.put("requestedUri", request.requestedUri());
    body.put("resolvedUri", ContentFetchPolicy.sanitizeForegroundResolvedUri(result.resolvedUri()));
    body.put("bytesLength", bytes.length);
    if (FORMAT_TEXT.equals(request.format())) {
      body.put(FORMAT_PARAMETER, FORMAT_TEXT);
      body.put("contentText", decodeUtf8(bytes));
      body.put("contentBase64", null);
    } else {
      body.put(FORMAT_PARAMETER, FORMAT_BASE64);
      body.put("contentText", null);
      body.put("contentBase64", Base64.getEncoder().encodeToString(bytes));
    }
    body.put("statusMessage", "Fetched " + bytes.length + " bytes");
    return body;
  }

  private static String decodeUtf8(byte[] bytes) {
    try {
      return StandardCharsets.UTF_8
          .newDecoder()
          .onMalformedInput(CodingErrorAction.REPORT)
          .onUnmappableCharacter(CodingErrorAction.REPORT)
          .decode(ByteBuffer.wrap(bytes))
          .toString();
    } catch (CharacterCodingException _) {
      throw new PlatformApiException(
          415,
          "unsupported_content_encoding",
          "Fetched content is not valid UTF-8; request format=base64 instead.");
    }
  }

  private static String readFormat(Map<String, List<String>> parameters) {
    String raw = PlatformApiParameters.readOptionalString(parameters, FORMAT_PARAMETER);
    if (raw == null || raw.isBlank()) {
      return FORMAT_TEXT;
    }
    String format = raw.trim().toLowerCase(java.util.Locale.ROOT);
    if (FORMAT_TEXT.equals(format) || FORMAT_BASE64.equals(format)) {
      return format;
    }
    throw new PlatformApiException(
        400, "invalid_query_parameter", "Query parameter 'format' must be 'text' or 'base64'.");
  }

  private static String readPurpose(Map<String, List<String>> parameters) {
    String raw = PlatformApiParameters.readOptionalString(parameters, "purpose");
    if (raw == null || raw.isBlank()) {
      return DEFAULT_PURPOSE;
    }
    String purpose = raw.trim();
    if (purpose.indexOf('\n') >= 0 || purpose.indexOf('\r') >= 0 || purpose.length() > 80) {
      throw new PlatformApiException(
          400,
          "invalid_query_parameter",
          "Query parameter 'purpose' must be a short single-line value.");
    }
    return purpose;
  }

  private static long readPositiveLong(
      Map<String, List<String>> parameters, String name, long defaultValue, long hardLimit) {
    String raw = PlatformApiParameters.readOptionalString(parameters, name);
    if (raw == null || raw.isBlank()) {
      return defaultValue;
    }
    long value;
    try {
      value = Long.parseLong(raw.trim());
    } catch (NumberFormatException _) {
      throw invalidPositiveInteger(name);
    }
    if (value <= 0) {
      throw invalidPositiveInteger(name);
    }
    if (value > hardLimit) {
      throw new PlatformApiException(
          400,
          "invalid_query_parameter",
          "Query parameter '" + name + "' exceeds the supported app-facing limit.");
    }
    return value;
  }

  private static PlatformApiException invalidPositiveInteger(String name) {
    return new PlatformApiException(
        400,
        "invalid_query_parameter",
        "Query parameter '" + name + "' must be a positive integer.");
  }

  private record FetchRequest(
      String requestedUri,
      String runtimeUri,
      long maxBytes,
      long timeoutMillis,
      String format,
      String purpose) {}
}

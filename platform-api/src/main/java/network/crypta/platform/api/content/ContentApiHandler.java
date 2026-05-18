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
  private static final long DEFAULT_MAX_BYTES = 262_144L;
  private static final long HARD_MAX_BYTES = 1_048_576L;
  private static final long DEFAULT_TIMEOUT_MILLIS = 30_000L;
  private static final long HARD_TIMEOUT_MILLIS = 60_000L;
  private static final String CRYPTA_SCHEME_PREFIX = "crypta:";
  private static final String CHK_PREFIX = "CHK@";
  private static final String SSK_PREFIX = "SSK@";
  private static final String USK_PREFIX = "USK@";
  private static final String KSK_PREFIX = "KSK@";
  private static final String DEFAULT_PURPOSE = "reference-app";
  private static final String FORMAT_PARAMETER = "format";
  private static final String FORMAT_TEXT = "text";
  private static final String FORMAT_BASE64 = "base64";

  private final ContentFetchPort contentFetchPort;

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
    this.contentFetchPort = Objects.requireNonNull(contentFetchPort, "contentFetchPort");
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
    FetchRequest request = parseRequest(parameters);
    BoundedContentFetchResult result = fetchContent(request);
    byte[] bytes = result.bytes();
    if (bytes.length > request.maxBytes()) {
      throw new PlatformApiException(
          502, "content_fetch_too_large", "Fetched content exceeded the configured byte bound.");
    }
    return responseBody(request, result, bytes);
  }

  private FetchRequest parseRequest(Map<String, List<String>> parameters) {
    String requestedUri =
        normalizeRequestedUri(PlatformApiParameters.requireString(parameters, "uri"));
    String runtimeUri = runtimeFetchUri(requestedUri);
    if (isUnsupportedContentKey(runtimeUri)) {
      throw invalidContentSource();
    }
    long maxBytes = readPositiveLong(parameters, "maxBytes", DEFAULT_MAX_BYTES, HARD_MAX_BYTES);
    long timeoutMillis =
        readPositiveLong(parameters, "timeoutMillis", DEFAULT_TIMEOUT_MILLIS, HARD_TIMEOUT_MILLIS);
    String format = readFormat(parameters);
    String purpose = readPurpose(parameters);
    return new FetchRequest(requestedUri, runtimeUri, maxBytes, timeoutMillis, format, purpose);
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
    body.put("resolvedUri", sanitizeContentDiagnostic(result.resolvedUri()));
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

  private static String normalizeRequestedUri(String rawUri) {
    if (rawUri.indexOf('\n') >= 0 || rawUri.indexOf('\r') >= 0 || rawUri.indexOf('\u0000') >= 0) {
      throw invalidContentSource();
    }
    String uri = rawUri.trim();
    if (uri.isEmpty()
        || containsWhitespace(uri)
        || uri.indexOf('?') >= 0
        || uri.indexOf('#') >= 0) {
      throw invalidContentSource();
    }
    String runtimeUri = runtimeFetchUri(uri);
    if (runtimeUri.startsWith("/")
        || runtimeUri.startsWith("\\")
        || hasDisallowedScheme(runtimeUri)) {
      throw invalidContentSource();
    }
    return uri;
  }

  private static String runtimeFetchUri(String requestedUri) {
    if (requestedUri.regionMatches(
        true, 0, CRYPTA_SCHEME_PREFIX, 0, CRYPTA_SCHEME_PREFIX.length())) {
      return requestedUri.substring(CRYPTA_SCHEME_PREFIX.length()).trim();
    }
    return requestedUri;
  }

  private static boolean hasDisallowedScheme(String uri) {
    int colon = uri.indexOf(':');
    int at = uri.indexOf('@');
    return colon >= 0 && (at < 0 || colon < at);
  }

  private static boolean isUnsupportedContentKey(String uri) {
    return !(startsWithContentKeyPrefix(uri, CHK_PREFIX)
        || startsWithContentKeyPrefix(uri, SSK_PREFIX)
        || startsWithContentKeyPrefix(uri, USK_PREFIX)
        || startsWithContentKeyPrefix(uri, KSK_PREFIX));
  }

  private static boolean startsWithContentKeyPrefix(String uri, String prefix) {
    return uri.regionMatches(true, 0, prefix, 0, prefix.length());
  }

  private static PlatformApiException invalidContentSource() {
    return new PlatformApiException(
        400,
        "unsupported_content_source",
        "Content fetch URI must be a CHK@, SSK@, USK@, KSK@, or crypta: content key.");
  }

  private static String sanitizeContentDiagnostic(String value) {
    if (value == null || value.isBlank()) {
      return null;
    }
    if (value.indexOf('\n') >= 0
        || value.indexOf('\r') >= 0
        || value.indexOf('\u0000') >= 0
        || containsWhitespace(value)
        || value.indexOf('?') >= 0
        || value.indexOf('#') >= 0) {
      return null;
    }
    String sanitized = value.trim();
    if (isUnsupportedContentKey(runtimeFetchUri(sanitized))) {
      return null;
    }
    return sanitized;
  }

  private static boolean containsWhitespace(String value) {
    for (int index = 0; index < value.length(); index++) {
      if (Character.isWhitespace(value.charAt(index))) {
        return true;
      }
    }
    return false;
  }

  private record FetchRequest(
      String requestedUri,
      String runtimeUri,
      long maxBytes,
      long timeoutMillis,
      String format,
      String purpose) {}
}

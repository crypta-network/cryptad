package network.crypta.clients.http;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.api.PlatformApiPaths;
import network.crypta.platform.api.PlatformApiRequest;
import network.crypta.platform.api.PlatformApiResponse;
import network.crypta.platform.api.PlatformApiRouter;
import network.crypta.platform.apphost.AppHost;
import network.crypta.runtime.spi.RuntimePorts;
import network.crypta.support.MultiValueTable;
import network.crypta.support.URLDecoder;
import network.crypta.support.URLEncodedFormatException;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.HTTPRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Thin legacy-HTTP bridge for Platform API v1.
 *
 * <p>This toadlet keeps all transport-neutral routing and JSON construction inside {@code
 * :platform-api}. Its responsibility is limited to enforcing the existing full-access expectation
 * for admin-facing routes, translating legacy HTTP request state into a {@link PlatformApiRequest},
 * and writing the resulting JSON back through the legacy HTTP shell.
 */
@SuppressWarnings("unused")
public final class PlatformApiToadlet extends Toadlet {
  /** Versioned mount path for the legacy HTTP bridge. */
  public static final String MOUNT_PATH = PlatformApiPaths.API_V1_PREFIX;

  /**
   * Logger for unexpected bridge failures that occur before the router can serialize a response.
   */
  private static final Logger LOG = LoggerFactory.getLogger(PlatformApiToadlet.class);

  /** JSON media type advertised for every Platform API response emitted through the bridge. */
  private static final String JSON_CONTENT_TYPE = "application/json; charset=UTF-8";

  /** Legacy maximum accepted size for one URL-encoded request body. */
  private static final long MAX_URL_ENCODED_BODY_LENGTH = 1024L * 1024L;

  private static final String URL_ENCODED_CONTENT_TYPE = "application/x-www-form-urlencoded";

  private static final String DELETE_METHOD = "DELETE";
  private static final String FORM_PASSWORD_PARAMETER = "formPassword";
  private static final int MAX_PLATFORM_API_FORM_FIELD_LENGTH = QueueToadlet.MAX_KEY_LENGTH;
  private static final String CONFIG_SEGMENT = "config";
  private static final String PEERS_SEGMENT = "peers";
  private static final String QUEUE_SEGMENT = "queue";
  private static final String SECURITY_LEVELS_SEGMENT = "security-levels";
  private static final String UPDATES_SEGMENT = "updates";
  private static final String WIZARD_SEGMENT = "wizard";

  /**
   * Transport-neutral router that owns endpoint selection, validation, and JSON payload creation.
   */
  private final PlatformApiRouter router;

  /**
   * Creates a platform API toadlet backed by the supplied runtime ports.
   *
   * @param runtimePorts detached runtime ports exposed to the platform API leaf
   */
  public PlatformApiToadlet(RuntimePorts runtimePorts) {
    this(new PlatformApiRouter(runtimePorts));
  }

  /**
   * Creates a platform API toadlet backed by runtime ports and AppHost.
   *
   * @param runtimePorts detached runtime ports exposed to the platform API leaf
   * @param appHost detached AppHost exposed through the app-management control surface
   */
  public PlatformApiToadlet(RuntimePorts runtimePorts, AppHost appHost) {
    this(new PlatformApiRouter(runtimePorts, appHost));
  }

  /**
   * Creates a platform API toadlet backed by an already constructed router.
   *
   * <p>This constructor exists for tests and narrow composition sites that need to inject a router
   * with controlled behavior. Production wiring normally uses {@link
   * #PlatformApiToadlet(RuntimePorts, AppHost)} so the bridge owns router creation.
   *
   * @param router transport-neutral router that handles request validation and response generation
   */
  PlatformApiToadlet(PlatformApiRouter router) {
    super();
    this.router = Objects.requireNonNull(router, "router");
  }

  @Override
  public void handleMethodGET(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException, RedirectException {
    writePlatformApiResponse("GET", uri, request, ctx);
  }

  /**
   * Routes POST requests through the Platform API router.
   *
   * @param uri request target as seen by the legacy HTTP shell
   * @param request decoded legacy HTTP request wrapper
   * @param ctx current toadlet context, including full-access enforcement state
   * @throws ToadletContextClosedException if the client disconnects while the reply is being sent
   * @throws IOException if the legacy HTTP shell fails while writing the response
   */
  public void handleMethodPOST(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    writePlatformApiResponse("POST", uri, request, ctx);
  }

  /**
   * Returns a JSON {@code 405} error for unsupported HEAD requests in extended-method mode.
   *
   * <p>When the legacy HTTP shell is configured to dispatch HEAD explicitly, this bridge still
   * routes the request through the Platform API router so method handling stays consistent with GET
   * and POST. The bridge then suppresses the response body while preserving the JSON content type
   * and reported content length.
   *
   * @param uri request target as seen by the legacy HTTP shell
   * @param request decoded legacy HTTP request wrapper
   * @param ctx current toadlet context, including full-access enforcement state
   * @throws ToadletContextClosedException if the client disconnects while the reply is being sent
   * @throws IOException if the legacy HTTP shell fails while writing the response headers
   */
  public void handleMethodHEAD(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    writePlatformApiResponse("HEAD", uri, request, ctx, false);
  }

  /**
   * Returns a JSON {@code 405} error for unsupported OPTIONS requests.
   *
   * <p>The bridge forwards OPTIONS through the router when the legacy shell dispatches it. That
   * keeps the Platform API method advertisement consistent with the mounted v1 contract.
   *
   * @param uri request target as seen by the legacy HTTP shell
   * @param request decoded legacy HTTP request wrapper
   * @param ctx current toadlet context, including full-access enforcement state
   * @throws ToadletContextClosedException if the client disconnects while the reply is being sent
   * @throws IOException if the legacy HTTP shell fails while writing the response
   */
  public void handleMethodOPTIONS(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    writePlatformApiResponse("OPTIONS", uri, request, ctx);
  }

  /**
   * Returns a JSON {@code 405} error for unsupported PUT requests.
   *
   * @param uri request target as seen by the legacy HTTP shell
   * @param request decoded legacy HTTP request wrapper
   * @param ctx current toadlet context, including full-access enforcement state
   * @throws ToadletContextClosedException if the client disconnects while the reply is being sent
   * @throws IOException if the legacy HTTP shell fails while writing the response
   */
  public void handleMethodPUT(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    writePlatformApiResponse("PUT", uri, request, ctx);
  }

  /**
   * Routes DELETE requests through the Platform API router.
   *
   * @param uri request target as seen by the legacy HTTP shell
   * @param request decoded legacy HTTP request wrapper
   * @param ctx current toadlet context, including full-access enforcement state
   * @throws ToadletContextClosedException if the client disconnects while the reply is being sent
   * @throws IOException if the legacy HTTP shell fails while writing the response
   */
  public void handleMethodDELETE(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    writePlatformApiResponse(DELETE_METHOD, uri, request, ctx);
  }

  /**
   * Returns a JSON {@code 405} error for unsupported PATCH requests.
   *
   * @param uri request target as seen by the legacy HTTP shell
   * @param request decoded legacy HTTP request wrapper
   * @param ctx current toadlet context, including full-access enforcement state
   * @throws ToadletContextClosedException if the client disconnects while the reply is being sent
   * @throws IOException if the legacy HTTP shell fails while writing the response
   */
  public void handleMethodPATCH(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    writePlatformApiResponse("PATCH", uri, request, ctx);
  }

  /**
   * Returns a JSON {@code 405} error for unsupported TRACE requests.
   *
   * @param uri request target as seen by the legacy HTTP shell
   * @param request decoded legacy HTTP request wrapper
   * @param ctx current toadlet context, including full-access enforcement state
   * @throws ToadletContextClosedException if the client disconnects while the reply is being sent
   * @throws IOException if the legacy HTTP shell fails while writing the response
   */
  public void handleMethodTRACE(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    writePlatformApiResponse("TRACE", uri, request, ctx);
  }

  @Override
  public String path() {
    return MOUNT_PATH;
  }

  /**
   * Keeps the container from applying its POST-only password gate ahead of the bridge.
   *
   * <p>The bridge enforces the legacy form password explicitly after it has checked full-access
   * permissions, which preserves the Platform API's JSON {@code 403} behavior for non-full-access
   * callers and extends the same password requirement to DELETE.
   */
  @Override
  public boolean allowPOSTWithoutPassword() {
    return true;
  }

  /**
   * Routes a request through the Platform API and writes the resulting JSON response.
   *
   * <p>This overload emits the response body normally. HEAD requests use the lower-level overload
   * to suppress the body while still reporting the encoded content length.
   *
   * @param method HTTP method name forwarded into the Platform API router
   * @param uri request target supplied by the legacy HTTP shell
   * @param request decoded legacy HTTP request wrapper
   * @param ctx current toadlet context used for access checks and reply writes
   * @throws ToadletContextClosedException if the client disconnects while the reply is being sent
   * @throws IOException if the legacy HTTP shell fails while writing the response
   */
  private void writePlatformApiResponse(
      String method, URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    writePlatformApiResponse(method, uri, request, ctx, true);
  }

  /**
   * Routes a request through the Platform API and writes either a full or header-only reply.
   *
   * <p>Legacy HTTP integration keeps full-access enforcement at the bridge boundary. Mutating
   * requests then pass through the legacy form-password check before the bridge converts them into
   * a transport-neutral {@link PlatformApiRequest} and delegates to the router. Unexpected runtime
   * failures are converted into a structured {@code 500} response so callers keep the Platform API
   * JSON contract even when the bridge logs the underlying error.
   *
   * @param method HTTP method name forwarded into the Platform API router
   * @param uri request target supplied by the legacy HTTP shell
   * @param request decoded legacy HTTP request wrapper
   * @param ctx current toadlet context used for access checks and reply writes
   * @param includeBody {@code true} to send the encoded JSON body, {@code false} for header-only
   *     replies such as HEAD
   * @throws ToadletContextClosedException if the client disconnects while the reply is being sent
   * @throws IOException if the legacy HTTP shell fails while writing the response
   */
  private void writePlatformApiResponse(
      String method, URI uri, HTTPRequest request, ToadletContext ctx, boolean includeBody)
      throws ToadletContextClosedException, IOException {
    PlatformApiResponse response;
    if (!ctx.isAllowedFullAccess()) {
      response = PlatformApiResponse.error(403, "forbidden", "Full access is required.");
      writeJsonReply(ctx, response, includeBody);
      return;
    }
    if (!authorizeMutationRequest(method, uri, request, ctx)) {
      return;
    }

    try {
      response = router.route(toPlatformApiRequest(method, uri, request));
    } catch (URLEncodedFormatException _) {
      response =
          PlatformApiResponse.error(
              400, "invalid_path", "Request path contains malformed percent-encoding.");
    } catch (PlatformApiException e) {
      response = PlatformApiResponse.error(e.statusCode(), e.errorCode(), e.getMessage());
    } catch (RuntimeException e) {
      LOG.error("Platform API request failed for path {}", requestPath(uri), e);
      response =
          PlatformApiResponse.error(500, "internal_error", "Unexpected platform API failure.");
    }
    writeJsonReply(ctx, response, includeBody);
  }

  /**
   * Returns whether the current request targets one of the mutating app-management routes.
   *
   * <p>The legacy shell only auto-checks form passwords for POST before dispatch. The Platform API
   * bridge keeps full-access checks ahead of password checks and applies the same legacy password
   * guard to every currently supported Platform API mutation family. DELETE remains relevant only
   * for installed-app removal, while the current config, security-levels, updater, wizard, queue,
   * peer, and app actions use POST.
   *
   * @param method HTTP method name forwarded into the router
   * @param uri request target supplied by the legacy HTTP shell
   * @return {@code true} when the request must present the legacy form password
   */
  private static boolean requiresFormPassword(String method, URI uri) {
    if (!requiresFormPasswordEligibleMethod(method)) {
      return false;
    }

    List<String> pathSegments = decodeRelativeApiPath(uri);
    if (pathSegments.isEmpty()) {
      return false;
    }
    if ("apps".equals(pathSegments.getFirst())) {
      return requiresAppsFormPassword(method, pathSegments);
    }
    return requiresNonAppFormPassword(method, pathSegments);
  }

  /**
   * Returns whether the current request method participates in the legacy form-password guard.
   *
   * @param method HTTP method name forwarded into the router
   * @return {@code true} when the bridge should inspect the request path for a mutating route
   */
  private static boolean requiresFormPasswordEligibleMethod(String method) {
    return "POST".equals(method) || DELETE_METHOD.equals(method);
  }

  /**
   * Decodes one relative API path while treating malformed percent-encoding as a non-matching
   * mutation route.
   *
   * @param uri request target supplied by the legacy HTTP shell
   * @return decoded relative API path, or an empty list when decoding fails
   */
  private static List<String> decodeRelativeApiPath(URI uri) {
    try {
      return relativeApiPath(requestPath(uri));
    } catch (URLEncodedFormatException _) {
      return List.of();
    }
  }

  /**
   * Returns whether the current request targets one of the mutating app-management routes.
   *
   * @param method HTTP method name forwarded into the router
   * @param pathSegments decoded path segments beneath the Platform API mount point
   * @return {@code true} when the request must present the legacy form password
   */
  private static boolean requiresAppsFormPassword(String method, List<String> pathSegments) {
    if (DELETE_METHOD.equals(method)) {
      return pathSegments.size() == 2;
    }
    if (pathSegments.size() == 2 && "install".equals(pathSegments.get(1))) {
      return true;
    }
    return pathSegments.size() == 3
        && ("start".equals(pathSegments.get(2))
            || "stop".equals(pathSegments.get(2))
            || "update".equals(pathSegments.get(2)));
  }

  /**
   * Returns whether the current request targets one of the non-app mutating Platform API routes.
   *
   * @param method HTTP method name forwarded into the router
   * @param pathSegments decoded path segments beneath the Platform API mount point
   * @return {@code true} when the request must present the legacy form password
   */
  private static boolean requiresNonAppFormPassword(String method, List<String> pathSegments) {
    return requiresQueueFormPassword(method, pathSegments)
        || requiresPeersFormPassword(method, pathSegments)
        || requiresConfigFormPassword(method, pathSegments)
        || requiresSecurityLevelsFormPassword(method, pathSegments)
        || requiresUpdatesFormPassword(method, pathSegments)
        || requiresWizardFormPassword(method, pathSegments);
  }

  /**
   * Returns whether the current request targets one of the mutating queue routes.
   *
   * @param method HTTP method name forwarded into the router
   * @param pathSegments decoded path segments beneath the Platform API mount point
   * @return {@code true} when the request must present the legacy form password
   */
  private static boolean requiresQueueFormPassword(String method, List<String> pathSegments) {
    if (!"POST".equals(method)
        || pathSegments.isEmpty()
        || !QUEUE_SEGMENT.equals(pathSegments.getFirst())) {
      return false;
    }
    if (pathSegments.size() == 2 && "downloads".equals(pathSegments.get(1))) {
      return true;
    }
    if (pathSegments.size() != 3) {
      return false;
    }
    if ("requests".equals(pathSegments.get(1))) {
      return "remove".equals(pathSegments.get(2))
          || "restart".equals(pathSegments.get(2))
          || "priority".equals(pathSegments.get(2));
    }
    return "cleanup".equals(pathSegments.get(1))
        && ("uploads".equals(pathSegments.get(2)) || "downloads".equals(pathSegments.get(2)));
  }

  /**
   * Returns whether the current request targets one of the mutating peer routes.
   *
   * @param method HTTP method name forwarded into the router
   * @param pathSegments decoded path segments beneath the Platform API mount point
   * @return {@code true} when the request must present the legacy form password
   */
  private static boolean requiresPeersFormPassword(String method, List<String> pathSegments) {
    if (!"POST".equals(method)
        || pathSegments.isEmpty()
        || !PEERS_SEGMENT.equals(pathSegments.getFirst())) {
      return false;
    }
    if (pathSegments.size() == 2) {
      return "add".equals(pathSegments.get(1));
    }
    return pathSegments.size() == 3
        && ("settings".equals(pathSegments.get(2))
            || "note".equals(pathSegments.get(2))
            || "remove".equals(pathSegments.get(2)));
  }

  /**
   * Returns whether the current request targets one of the mutating config routes.
   *
   * @param method HTTP method name forwarded into the router
   * @param pathSegments decoded path segments beneath the Platform API mount point
   * @return {@code true} when the request must present the legacy form password
   */
  private static boolean requiresConfigFormPassword(String method, List<String> pathSegments) {
    return "POST".equals(method)
        && pathSegments.size() == 2
        && CONFIG_SEGMENT.equals(pathSegments.getFirst())
        && ("overrides".equals(pathSegments.get(1)) || "persist".equals(pathSegments.get(1)));
  }

  /**
   * Returns whether the current request targets one of the mutating security-level routes.
   *
   * @param method HTTP method name forwarded into the router
   * @param pathSegments decoded path segments beneath the Platform API mount point
   * @return {@code true} when the request must present the legacy form password
   */
  private static boolean requiresSecurityLevelsFormPassword(
      String method, List<String> pathSegments) {
    return "POST".equals(method)
        && pathSegments.size() == 2
        && SECURITY_LEVELS_SEGMENT.equals(pathSegments.getFirst())
        && ("network".equals(pathSegments.get(1)) || "physical".equals(pathSegments.get(1)));
  }

  /**
   * Returns whether the current request targets the mutating updater download route.
   *
   * @param method HTTP method name forwarded into the router
   * @param pathSegments decoded path segments beneath the Platform API mount point
   * @return {@code true} when the request must present the legacy form password
   */
  private static boolean requiresUpdatesFormPassword(String method, List<String> pathSegments) {
    return "POST".equals(method)
        && pathSegments.size() == 3
        && UPDATES_SEGMENT.equals(pathSegments.getFirst())
        && "core".equals(pathSegments.get(1))
        && "download".equals(pathSegments.get(2));
  }

  /**
   * Returns whether the current request targets the mutating first-time-wizard route.
   *
   * @param method HTTP method name forwarded into the router
   * @param pathSegments decoded path segments beneath the Platform API mount point
   * @return {@code true} when the request must present the legacy form password
   */
  private static boolean requiresWizardFormPassword(String method, List<String> pathSegments) {
    return "POST".equals(method)
        && pathSegments.size() == 3
        && WIZARD_SEGMENT.equals(pathSegments.getFirst())
        && "first-time".equals(pathSegments.get(1))
        && "apply".equals(pathSegments.get(2));
  }

  /**
   * Enforces the legacy form-password requirement for mutating requests.
   *
   * <p>The bridge handles failures itself so callers always receive structured JSON {@code 403}
   * responses instead of legacy redirects.
   *
   * @param method HTTP method name forwarded into the router
   * @param uri request target supplied by the legacy HTTP shell
   * @param request decoded legacy HTTP request wrapper
   * @param ctx current toadlet context used for password validation and response writes
   * @return {@code true} when the request is authorized to mutate state
   * @throws ToadletContextClosedException if the client disconnects while an auth failure is sent
   * @throws IOException if the legacy HTTP shell fails while writing the auth failure
   */
  private boolean authorizeMutationRequest(
      String method, URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    if (!requiresFormPassword(method, uri)) {
      return true;
    }
    if (ctx.hasFormPassword(request)) {
      return true;
    }
    writeJsonReply(
        ctx, PlatformApiResponse.error(403, "forbidden", "Valid form password is required."), true);
    return false;
  }

  /**
   * Converts legacy HTTP request state into the transport-neutral Platform API request model.
   *
   * <p>Query parameters preserve encounter order and repeated values so the router can apply its
   * own validation without depending on the legacy HTTP request type. The bridge excludes the
   * legacy admin {@code formPassword} from that map. It also lifts scalar form fields from request
   * parts into the same map so the transport-neutral router can handle urlencoded and multipart
   * admin submissions without learning legacy HTTP request details. Uploaded-file bodies stay out
   * of that map because Platform API v1 still treats file transfer payloads as adapter-local
   * concerns.
   *
   * @param method HTTP method name forwarded into the router
   * @param uri request target supplied by the legacy HTTP shell
   * @param request decoded legacy HTTP request wrapper
   * @return immutable Platform API request built from the method, relative path, and query values
   * @throws URLEncodedFormatException if the request path contains malformed percent-encoding
   */
  private PlatformApiRequest toPlatformApiRequest(String method, URI uri, HTTPRequest request)
      throws URLEncodedFormatException {
    LinkedHashMap<String, List<String>> queryParameters =
        LinkedHashMap.newLinkedHashMap(request.getParameterNames().size());
    for (String parameterName : request.getParameterNames()) {
      if (FORM_PASSWORD_PARAMETER.equals(parameterName)) {
        continue;
      }
      queryParameters.put(parameterName, List.of(request.getMultipleParam(parameterName)));
    }
    copyBodyParametersIfPresent(request, queryParameters);
    return new PlatformApiRequest(method, relativeApiPath(requestPath(uri)), queryParameters);
  }

  /**
   * Copies body-backed form values into the query-like parameter map when present.
   *
   * <p>This keeps the bridge compatible with legacy-authenticated form submissions while preserving
   * the transport-neutral request model expected by the Platform API router. Existing query-string
   * values win when the same name appears in both places. Urlencoded bodies are reparsed from the
   * raw payload so repeated values survive intact; multipart uploads continue to use scalar parts,
   * with uploaded-file bodies skipped because the Platform API request model is still text-only in
   * this phase.
   *
   * @param request decoded legacy HTTP request wrapper
   * @param queryParameters query-like parameter map being assembled for the router
   */
  private static void copyBodyParametersIfPresent(
      HTTPRequest request, Map<String, List<String>> queryParameters) {
    Bucket rawData = request.getRawData();
    if (rawData == null) {
      return;
    }
    if (isUrlEncodedBodyRequest(request)) {
      mergeUrlEncodedBodyParameters(rawData, queryParameters);
      return;
    }
    copyScalarFormPartsIfPresent(request, queryParameters);
  }

  private static boolean isUrlEncodedBodyRequest(HTTPRequest request) {
    String contentType = request.getHeader("content-type");
    return contentType != null
        && contentType.regionMatches(
            true, 0, URL_ENCODED_CONTENT_TYPE, 0, URL_ENCODED_CONTENT_TYPE.length());
  }

  private static void mergeUrlEncodedBodyParameters(
      Bucket rawData, Map<String, List<String>> queryParameters) {
    if (rawData.size() > MAX_URL_ENCODED_BODY_LENGTH) {
      throw new PlatformApiException(
          400, "invalid_request_body", "URL-encoded request body exceeds the 1048576 byte limit.");
    }
    Map<String, List<String>> bodyParameters;
    try (var input = rawData.getInputStream()) {
      if (input == null) {
        return;
      }
      String body = new String(input.readAllBytes(), StandardCharsets.US_ASCII);
      bodyParameters = HTTPRequestImpl.parseUriParameters(body, true);
    } catch (IOException e) {
      throw new IllegalStateException("Failed to read Platform API form body.", e);
    }
    for (Map.Entry<String, List<String>> entry : bodyParameters.entrySet()) {
      if (FORM_PASSWORD_PARAMETER.equals(entry.getKey())
          || queryParameters.containsKey(entry.getKey())) {
        continue;
      }
      queryParameters.put(entry.getKey(), List.copyOf(entry.getValue()));
    }
  }

  private static void copyScalarFormPartsIfPresent(
      HTTPRequest request, Map<String, List<String>> queryParameters) {
    String[] partNames = request.getParts();
    if (partNames == null) {
      return;
    }
    for (String partName : partNames) {
      if (FORM_PASSWORD_PARAMETER.equals(partName)
          || queryParameters.containsKey(partName)
          || request.getUploadedFile(partName) != null) {
        continue;
      }
      queryParameters.put(
          partName,
          List.of(request.getPartAsStringFailsafe(partName, MAX_PLATFORM_API_FORM_FIELD_LENGTH)));
    }
  }

  /**
   * Splits the mounted request path into decoded Platform API path segments.
   *
   * <p>The bridge trims the API mount prefix, preserves encoded slashes until segment boundaries
   * are determined, and then decodes each segment independently. That allows peer identifiers and
   * similar values to contain {@code /} when they were percent-encoded in the incoming request.
   *
   * @param requestPath raw request path as received from the URI before query parsing
   * @return immutable list of decoded path segments relative to {@link #MOUNT_PATH}
   * @throws URLEncodedFormatException if any segment contains malformed percent-encoding
   */
  private static List<String> relativeApiPath(String requestPath) throws URLEncodedFormatException {
    String relativePath = requestPath;
    if (requestPath.startsWith(MOUNT_PATH)) {
      relativePath = requestPath.substring(MOUNT_PATH.length());
    } else {
      String withoutTrailingSlash = MOUNT_PATH.substring(0, MOUNT_PATH.length() - 1);
      if (requestPath.equals(withoutTrailingSlash)) {
        relativePath = "";
      }
    }
    if (relativePath.isEmpty()) {
      return List.of();
    }
    List<String> pathSegments = new ArrayList<>();
    int segmentStart = 0;
    while (segmentStart < relativePath.length()) {
      int nextSeparator = relativePath.indexOf('/', segmentStart);
      String segment =
          nextSeparator >= 0
              ? relativePath.substring(segmentStart, nextSeparator)
              : relativePath.substring(segmentStart);
      if (!segment.isEmpty()) {
        pathSegments.add(URLDecoder.decode(segment, false));
      }
      if (nextSeparator < 0) {
        break;
      }
      segmentStart = nextSeparator + 1;
    }
    return List.copyOf(pathSegments);
  }

  /**
   * Returns the raw request path when available so encoded path separators remain intact.
   *
   * @param uri request target supplied by the legacy HTTP shell
   * @return raw path if present, otherwise the decoded URI path as a fallback
   */
  private static String requestPath(URI uri) {
    String rawPath = uri.getRawPath();
    return rawPath != null ? rawPath : uri.getPath();
  }

  /**
   * Writes the Platform API response back through the legacy HTTP shell.
   *
   * <p>The bridge preserves router-supplied headers such as {@code Allow} and always advertises the
   * Platform API JSON media type. HEAD responses suppress the body while still reporting the
   * encoded byte length so clients can probe the endpoint without downloading the payload.
   *
   * @param ctx the current toadlet context used to send headers and body bytes
   * @param response transport-neutral Platform API response returned by the router
   * @param includeBody {@code true} to send the encoded JSON body, {@code false} for header-only
   *     replies
   * @throws ToadletContextClosedException if the client disconnects while the reply is being sent
   * @throws IOException if the legacy HTTP shell fails while writing the response
   */
  private void writeJsonReply(ToadletContext ctx, PlatformApiResponse response, boolean includeBody)
      throws ToadletContextClosedException, IOException {
    MultiValueTable<String, String> headers = null;
    if (!response.headers().isEmpty()) {
      headers = new MultiValueTable<>();
      response.headers().forEach(headers::put);
    }
    ReplyHeaders replyHeaders =
        ReplyHeaders.of(response.statusCode(), response.reasonPhrase(), JSON_CONTENT_TYPE, headers);
    if (includeBody) {
      writeReply(ctx, replyHeaders, response.body());
      return;
    }

    byte[] body = response.body().getBytes(StandardCharsets.UTF_8);
    ctx.sendReplyHeaders(
        replyHeaders.code(),
        replyHeaders.description(),
        replyHeaders.headers(),
        replyHeaders.mimeType(),
        body.length);
  }
}

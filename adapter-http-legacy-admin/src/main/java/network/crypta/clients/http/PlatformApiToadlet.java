package network.crypta.clients.http;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Objects;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.platform.api.PlatformApiPaths;
import network.crypta.platform.api.PlatformApiRequest;
import network.crypta.platform.api.PlatformApiResponse;
import network.crypta.platform.api.PlatformApiRouter;
import network.crypta.runtime.spi.RuntimePorts;
import network.crypta.support.MultiValueTable;
import network.crypta.support.URLDecoder;
import network.crypta.support.URLEncodedFormatException;
import network.crypta.support.api.HTTPRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Thin legacy-HTTP bridge for the read-only Platform API v1.
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

  /**
   * Transport-neutral router that owns endpoint selection, validation, and JSON payload creation.
   */
  private final PlatformApiRouter router;

  /**
   * Creates a platform API toadlet backed by the supplied runtime ports.
   *
   * @param client high-level client helper retained by the toadlet base type
   * @param runtimePorts detached runtime ports exposed to the platform API leaf
   */
  public PlatformApiToadlet(HighLevelSimpleClient client, RuntimePorts runtimePorts) {
    this(client, new PlatformApiRouter(runtimePorts));
  }

  /**
   * Creates a platform API toadlet backed by an already constructed router.
   *
   * <p>This constructor exists for tests and narrow composition sites that need to inject a router
   * with controlled behavior. Production wiring normally uses {@link
   * #PlatformApiToadlet(HighLevelSimpleClient, RuntimePorts)} so the bridge owns router creation.
   *
   * @param client high-level client helper retained by the toadlet base type
   * @param router transport-neutral router that handles request validation and response generation
   */
  PlatformApiToadlet(HighLevelSimpleClient client, PlatformApiRouter router) {
    super(client);
    this.router = Objects.requireNonNull(router, "router");
  }

  @Override
  public void handleMethodGET(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException, RedirectException {
    writePlatformApiResponse("GET", uri, request, ctx);
  }

  /**
   * Returns a JSON {@code 405} error for unsupported POST requests.
   *
   * <p>The Platform API v1 surface is read-only. POST still routes through the shared Platform API
   * error handling path, so callers receive the same JSON error shape and {@code Allow: GET} header
   * that they would see for other unsupported verbs.
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
   * keeps the Platform API method advertisement consistent with the read-only v1 contract.
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
   * Returns a JSON {@code 405} error for unsupported DELETE requests.
   *
   * @param uri request target as seen by the legacy HTTP shell
   * @param request decoded legacy HTTP request wrapper
   * @param ctx current toadlet context, including full-access enforcement state
   * @throws ToadletContextClosedException if the client disconnects while the reply is being sent
   * @throws IOException if the legacy HTTP shell fails while writing the response
   */
  public void handleMethodDELETE(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    writePlatformApiResponse("DELETE", uri, request, ctx);
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
   * <p>Legacy HTTP integration keeps full-access enforcement at the bridge boundary. Requests that
   * pass the access check are converted into a transport-neutral {@link PlatformApiRequest} and
   * delegated to the router. Unexpected runtime failures are converted into a structured {@code
   * 500} response so callers keep the Platform API JSON contract even when the bridge logs the
   * underlying error.
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

    try {
      response = router.route(toPlatformApiRequest(method, uri, request));
    } catch (URLEncodedFormatException _) {
      response =
          PlatformApiResponse.error(
              400, "invalid_path", "Request path contains malformed percent-encoding.");
    } catch (RuntimeException e) {
      LOG.error("Platform API request failed for path {}", requestPath(uri), e);
      response =
          PlatformApiResponse.error(500, "internal_error", "Unexpected platform API failure.");
    }
    writeJsonReply(ctx, response, includeBody);
  }

  /**
   * Converts legacy HTTP request state into the transport-neutral Platform API request model.
   *
   * <p>Query parameters preserve encounter order and repeated values so the router can apply its
   * own validation without depending on the legacy HTTP request type.
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
      queryParameters.put(parameterName, List.of(request.getMultipleParam(parameterName)));
    }
    return new PlatformApiRequest(method, relativeApiPath(requestPath(uri)), queryParameters);
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

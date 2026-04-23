package network.crypta.clients.http;

import java.io.IOException;
import java.net.URI;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.appui.AppStaticAsset;
import network.crypta.platform.appui.AppStaticAssetException;
import network.crypta.platform.appui.AppStaticAssetService;
import network.crypta.platform.appui.AppUiPaths;
import network.crypta.platform.appui.AppUiRoute;
import network.crypta.platform.appui.AppUiSecurityHeaders;
import network.crypta.support.MultiValueTable;
import network.crypta.support.api.HTTPRequest;
import network.crypta.support.io.FileBucket;

/**
 * Legacy HTTP bridge for app-owned static browser UI routes.
 *
 * <p>The toadlet serves installed static app UIs under {@code /apps/{appId}/} while keeping the
 * legacy HTTP transport details out of the reusable app UI resolver. It performs the checks that
 * depend on the current HTTP context, such as full-access authorization, method-specific body
 * handling, redirect responses, and conversion from platform security-header maps into the legacy
 * {@link MultiValueTable} representation. Filesystem confinement, AppHost lookup, manifest-mode
 * filtering, content-type selection, and symlink rejection stay in {@link AppStaticAssetService}.
 *
 * <p>Responses use the normal dynamic header path rather than the legacy public static-file helper.
 * The route is stable across app updates, so month-long public caching would otherwise leave
 * browsers showing stale HTML or JavaScript after a bundle reinstall. The implementation streams
 * asset bytes through {@link FileBucket}; it does not buffer installed-bundle files into heap
 * memory before sending them to the client.
 *
 * @see AppStaticAssetService
 * @see AppUiPaths
 */
public final class AppUiToadlet extends Toadlet {
  /** Reason phrase used for app UI misses without exposing installed-bundle filesystem details. */
  private static final String NOT_FOUND_REASON = "Not Found";

  /** Reason phrase used when raw app UI paths contain traversal, encoded separators, or bad ids. */
  private static final String BAD_REQUEST_REASON = "Bad Request";

  /** Request-scoped resolver that keeps AppHost and filesystem validation outside this adapter. */
  private final AppStaticAssetService assetService;

  /**
   * Creates an app UI toadlet backed by the shared AppHost.
   *
   * <p>The supplied host is consulted for each request so route behavior reflects app installs,
   * updates, and uninstalls without rebuilding the HTTP route table. The toadlet does not retain
   * installed-bundle paths directly; path validation remains request scoped inside the asset
   * service.
   *
   * @param appHost AppHost used to describe installed applications and their bundle roots
   */
  public AppUiToadlet(AppHost appHost) {
    this(new AppStaticAssetService(appHost));
  }

  /**
   * Creates an app UI toadlet with an already configured asset service.
   *
   * <p>This constructor exists for focused adapter tests that need to supply deterministic AppHost
   * behavior through the service layer. Production code should use {@link #AppUiToadlet(AppHost)}
   * so the route always uses the default resolver and security checks.
   *
   * @param assetService resolver used to map raw HTTP paths to installed bundle assets
   */
  AppUiToadlet(AppStaticAssetService assetService) {
    this.assetService = Objects.requireNonNull(assetService, "assetService");
  }

  /** {@inheritDoc} */
  @Override
  public void handleMethodGET(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    handleAssetRequest(uri, ctx, true);
  }

  /**
   * Serves a header-only response for app static assets.
   *
   * <p>HEAD follows the same route parsing, authorization, redirect, and error classification as
   * GET, but all success, redirect, and error paths emit headers only. Unauthorized HEAD requests
   * avoid the full-access helper that writes an HTML body, so monitoring probes and browser cache
   * validators receive a response consistent with HTTP method semantics.
   *
   * @param uri request target supplied by the legacy HTTP shell, including raw path and query text
   * @param request decoded legacy HTTP request wrapper; not inspected by this route
   * @param ctx current toadlet context used for access checks and response writing
   * @throws ToadletContextClosedException if the client disconnects while headers are written
   * @throws IOException if AppHost metadata lookup or response I/O fails
   */
  @SuppressWarnings("unused")
  public void handleMethodHEAD(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    handleAssetRequest(uri, ctx, false);
  }

  /**
   * Returns the route prefix mounted by the legacy HTTP registrar.
   *
   * <p>The registrar uses this value as the subtree root for app-owned static UI requests. It is a
   * prefix rather than a single file route; the app id and optional asset path are parsed from the
   * remainder by {@link AppUiRoute}.
   *
   * @return canonical {@code /apps/} route prefix for installed app UI
   */
  @Override
  public String path() {
    return AppUiPaths.APPS_ROOT;
  }

  /**
   * Handles one GET or HEAD request after the legacy server dispatches it to this subtree.
   *
   * <p>The method first enforces full-access requirements, then applies canonical redirects before
   * attempting asset resolution. Redirects and errors preserve HEAD body suppression through the
   * {@code includeBody} flag. App UI resolver exceptions are intentionally collapsed into
   * filesystem-neutral client responses.
   *
   * @param uri request URI supplied by the legacy HTTP server
   * @param ctx response context used for authorization and output
   * @param includeBody whether the response may include an HTML or asset body
   * @throws ToadletContextClosedException if the client connection closes during response writing
   * @throws IOException if AppHost lookup or response output fails
   */
  private void handleAssetRequest(URI uri, ToadletContext ctx, boolean includeBody)
      throws ToadletContextClosedException, IOException {
    if (!ensureFullAccess(ctx, includeBody)) {
      return;
    }

    String requestPath = requestPath(uri);
    try {
      String redirectTarget = AppUiRoute.trailingSlashRedirectTarget(requestPath);
      if (redirectTarget != null) {
        writeRedirect(ctx, appendRawQuery(redirectTarget, uri.getRawQuery()), includeBody);
        return;
      }
      Optional<String> canonicalRootRedirect = assetService.canonicalRootRedirect(requestPath);
      if (canonicalRootRedirect.isPresent()) {
        writeRedirect(
            ctx, appendRawQuery(canonicalRootRedirect.get(), uri.getRawQuery()), includeBody);
        return;
      }
      Optional<AppStaticAsset> asset = assetService.resolve(requestPath);
      if (asset.isEmpty()) {
        sendError(ctx, 404, NOT_FOUND_REASON, "App UI asset not found.", includeBody);
        return;
      }
      writeAsset(ctx, asset.get(), includeBody);
    } catch (AppStaticAssetException exception) {
      if (exception.statusCode() == 404) {
        sendError(ctx, 404, NOT_FOUND_REASON, "App UI asset not found.", includeBody);
      } else {
        sendError(ctx, 400, BAD_REQUEST_REASON, "App UI path is not valid.", includeBody);
      }
    }
  }

  /**
   * Writes a temporary redirect while preserving HEAD header-only behavior.
   *
   * @param ctx response context that receives the redirect headers
   * @param redirectTarget path and optional raw query for the canonical app UI URL
   * @param includeBody whether the legacy HTML redirect body should be written
   * @throws ToadletContextClosedException if the client connection closes during response writing
   * @throws IOException if the redirect cannot be sent
   */
  private void writeRedirect(ToadletContext ctx, String redirectTarget, boolean includeBody)
      throws ToadletContextClosedException, IOException {
    if (includeBody) {
      writeTemporaryRedirect(ctx, "Redirecting to app UI.", redirectTarget);
      return;
    }
    ctx.sendReplyHeaders(
        302, "Found", MultiValueTable.from("Location", redirectTarget), null, 0L, true);
  }

  /**
   * Writes a client error page or a header-only error response.
   *
   * @param ctx response context that receives the error
   * @param statusCode HTTP status code to send
   * @param reasonPhrase stable reason phrase for the status line
   * @param message filesystem-neutral message for GET error pages
   * @param includeBody whether an HTML error page should be generated
   * @throws ToadletContextClosedException if the client connection closes during response writing
   * @throws IOException if the error response cannot be sent
   */
  private void sendError(
      ToadletContext ctx, int statusCode, String reasonPhrase, String message, boolean includeBody)
      throws ToadletContextClosedException, IOException {
    if (includeBody) {
      sendErrorPage(ctx, statusCode, reasonPhrase, message);
      return;
    }
    ctx.sendReplyHeaders(statusCode, reasonPhrase, null, null, 0L, true);
  }

  /**
   * Enforces full-access requirements without writing bodies for HEAD requests.
   *
   * @param ctx current request context with full-access state
   * @param includeBody whether a denied request may use the standard HTML access page
   * @return {@code true} when the request may continue to route resolution
   * @throws ToadletContextClosedException if the client connection closes during denial output
   * @throws IOException if the denial response cannot be sent
   */
  private boolean ensureFullAccess(ToadletContext ctx, boolean includeBody)
      throws ToadletContextClosedException, IOException {
    if (includeBody) {
      return ctx.checkFullAccess(this);
    }
    if (ctx.isAllowedFullAccess()) {
      return true;
    }
    sendError(ctx, 403, "Forbidden", "Full access is required.", false);
    return false;
  }

  /**
   * Sends a resolved installed-bundle asset using streaming response output.
   *
   * @param ctx response context that receives headers and optional body data
   * @param asset resolved immutable bundle asset metadata
   * @param includeBody whether the asset bytes should be streamed after headers
   * @throws ToadletContextClosedException if the client connection closes during response writing
   * @throws IOException if asset streaming or response output fails
   */
  private static void writeAsset(ToadletContext ctx, AppStaticAsset asset, boolean includeBody)
      throws ToadletContextClosedException, IOException {
    ctx.sendReplyHeaders(
        200,
        "OK",
        responseHeaders(ctx.getContainer().isFProxyJavascriptEnabled()),
        asset.contentType(),
        asset.sizeBytes(),
        true);
    if (includeBody) {
      ctx.writeData(new FileBucket(asset.path().toFile(), true, false, false, false));
    }
  }

  /**
   * Converts platform security headers into the legacy multi-value response table.
   *
   * @param javascriptEnabled whether app-owned same-origin scripts may execute
   * @return response headers for app-owned static UI assets
   */
  private static MultiValueTable<String, String> responseHeaders(boolean javascriptEnabled) {
    MultiValueTable<String, String> headers = new MultiValueTable<>();
    for (Map.Entry<String, String> header :
        AppUiSecurityHeaders.headers(javascriptEnabled).entrySet()) {
      headers.put(header.getKey(), header.getValue());
    }
    return headers;
  }

  /**
   * Appends a raw query string to a redirect path without decoding app-visible state.
   *
   * @param path canonical app UI path without a query component
   * @param rawQuery raw query text from the request URI, or {@code null}
   * @return path with the original query attached when one was present
   */
  private static String appendRawQuery(String path, String rawQuery) {
    return rawQuery == null ? path : path + "?" + rawQuery;
  }

  /**
   * Returns the raw request path used by route parsing.
   *
   * @param uri request URI from the legacy HTTP server
   * @return raw path when available, otherwise the decoded URI path fallback
   */
  private static String requestPath(URI uri) {
    String rawPath = uri.getRawPath();
    return rawPath != null ? rawPath : uri.getPath();
  }
}

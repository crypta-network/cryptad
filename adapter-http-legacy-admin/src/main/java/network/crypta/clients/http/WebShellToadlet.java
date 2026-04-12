package network.crypta.clients.http;

import java.io.IOException;
import java.net.JarURLConnection;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import network.crypta.client.DefaultMIMETypes;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.fs.readiness.LauncherReadinessInfo;
import network.crypta.platform.webshell.WebShellPageRenderer;
import network.crypta.platform.webshell.WebShellResources;
import network.crypta.platform.webshell.bootstrap.WebShellBootstrap;
import network.crypta.platform.webshell.routes.WebShellPaths;
import network.crypta.support.api.HTTPRequest;

/**
 * Thin legacy-HTTP bridge for the first-party Web Shell v1.
 *
 * <p>This toadlet keeps HTTP-specific routing and access control inside the legacy admin adapter
 * while reusing the shell-owned browser contract from {@code :platform-web-shell}. It serves the
 * shell index page at {@value WebShellPaths#SHELL_ROOT}, serves the shell-owned static assets
 * beneath {@value WebShellPaths#ASSET_ROOT}, and injects only the small read-only bootstrap payload
 * needed by the browser-side script.
 */
public final class WebShellToadlet extends Toadlet {
  /** Content type used for the shell document returned from the main route. */
  private static final String HTML_CONTENT_TYPE = "text/html; charset=UTF-8";

  /** Shared reason phrase for missing shell routes and shell-owned assets. */
  private static final String NOT_FOUND_REASON = "Not Found";

  /** Leading and trailing separator reused when synthesizing stable legacy UI paths. */
  private static final String ROOT_PATH_DELIMITER = "/";

  /** Path segment for the legacy opennet peers page surfaced from the shell. */
  private static final String STRANGERS_SEGMENT = "strangers";

  /** Path segment for the legacy alerts page surfaced from the shell. */
  private static final String ALERTS_SEGMENT = "alerts";

  /** Adapter-owned bootstrap payload injected into the rendered shell document. */
  private final WebShellBootstrap bootstrap;

  /**
   * Creates a Web Shell bridge backed by the shared interactive HTTP client.
   *
   * @param client high-level client retained by the toadlet base type
   */
  public WebShellToadlet(HighLevelSimpleClient client) {
    this(client, createNodeManagementBootstrap(defaultLegacyLinks()));
  }

  /**
   * Creates a bridge with an explicit bootstrap model.
   *
   * <p>This package-local constructor exists for focused adapter tests that need to verify
   * bootstrap injection without relying on the default legacy-link set.
   *
   * @param client high-level client retained by the toadlet base type
   * @param bootstrap shell bootstrap payload to embed in the rendered page
   */
  WebShellToadlet(HighLevelSimpleClient client, WebShellBootstrap bootstrap) {
    super(client);
    this.bootstrap = Objects.requireNonNull(bootstrap, "bootstrap");
  }

  /** {@inheritDoc} */
  @Override
  public void handleMethodGET(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    if (!ctx.checkFullAccess(this)) {
      return;
    }

    String requestPath = requestPath(uri);
    if (WebShellPaths.SHELL_ROOT.equals(requestPath)) {
      if (!ctx.getContainer().isFProxyJavascriptEnabled()) {
        writeTemporaryRedirect(
            ctx,
            "Web Shell requires JavaScript; redirecting to the legacy UI.",
            LauncherReadinessInfo.DEFAULT_UI_ROOT);
        return;
      }
      writeReply(
          ctx,
          ReplyHeaders.of(200, "OK", HTML_CONTENT_TYPE),
          WebShellPageRenderer.render(bootstrap));
      return;
    }

    if (requestPath.startsWith(WebShellPaths.ASSET_ROOT)) {
      serveAsset(requestPath.substring(WebShellPaths.ASSET_ROOT.length()), ctx);
      return;
    }

    sendErrorPage(ctx, 404, NOT_FOUND_REASON, "Web Shell route not found.");
  }

  @Override
  public String path() {
    return WebShellPaths.SHELL_ROOT;
  }

  /**
   * Creates the node-management bootstrap model from adapter-supplied legacy links.
   *
   * @param legacyLinks ordered legacy deep links to surface in the shell footer area
   * @return immutable bootstrap model for the first-party node-management shell
   */
  static WebShellBootstrap createNodeManagementBootstrap(
      List<WebShellBootstrap.LegacyLink> legacyLinks) {
    return WebShellBootstrap.nodeManagement(legacyLinks);
  }

  /**
   * Returns the default legacy deep links exposed by the Web Shell.
   *
   * <p>The list stays adapter-owned because these routes are defined by the legacy HTTP surface and
   * may include configuration-driven mount points.
   *
   * @return ordered legacy links for friends, peers, downloads, status, and config pages
   */
  private static List<WebShellBootstrap.LegacyLink> defaultLegacyLinks() {
    return List.of(
        legacyLink(LegacyHttpPaths.FRIENDS_PATH, "Friends"),
        legacyLink(legacyPath(STRANGERS_SEGMENT), "Strangers"),
        legacyLink(QueueToadlet.PATH_DOWNLOADS, "Downloads"),
        legacyLink(ConnectivityToadlet.CONNECTIVITY_PATH, "Connectivity"),
        legacyLink(SecurityLevelsToadlet.PATH, "Security levels"),
        legacyLink(StatisticsToadlet.TOADLET_URL, "Statistics"),
        legacyLink(legacyPath(ALERTS_SEGMENT), "Alerts"),
        legacyLink(LegacyHttpPaths.CONFIG_PATH, "Config"));
  }

  /**
   * Creates one shell-visible deep link back into the legacy UI.
   *
   * @param path absolute legacy route path
   * @param label user-facing label shown in the shell
   * @return immutable deep-link descriptor for the bootstrap payload
   */
  private static WebShellBootstrap.LegacyLink legacyLink(String path, String label) {
    return new WebShellBootstrap.LegacyLink(path, label);
  }

  /**
   * Builds one stable legacy route path from a single path segment.
   *
   * @param pathSegment route segment without leading or trailing slashes
   * @return canonical legacy route with a leading and trailing slash
   */
  private static String legacyPath(String pathSegment) {
    return ROOT_PATH_DELIMITER + pathSegment + ROOT_PATH_DELIMITER;
  }

  /**
   * Serves one shell-owned static asset from the classpath.
   *
   * @param assetPath asset path relative to {@link WebShellPaths#ASSET_ROOT}
   * @param ctx active toadlet context used for reply headers and body writes
   * @throws ToadletContextClosedException if the client disconnects before the asset is written
   * @throws IOException if the HTTP response cannot be written
   */
  private void serveAsset(String assetPath, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    if (assetPath.isEmpty() || isInvalidAssetPath(assetPath)) {
      sendErrorPage(ctx, 404, NOT_FOUND_REASON, "Web Shell asset not found.");
      return;
    }

    String resourcePath = WebShellPaths.ASSET_RESOURCE_ROOT + assetPath;
    URL resourceUrl = WebShellToadlet.class.getResource(resourcePath);
    if (resourceUrl == null) {
      sendErrorPage(ctx, 404, NOT_FOUND_REASON, "Web Shell asset not found.");
      return;
    }

    byte[] body = WebShellResources.readText(resourcePath).getBytes(StandardCharsets.UTF_8);
    ctx.sendReplyHeadersStatic(
        200,
        "OK",
        null,
        DefaultMIMETypes.guessMIMEType(assetPath, false),
        body.length,
        getUrlMTime(resourceUrl));
    ctx.writeData(body, 0, body.length);
  }

  /**
   * Rejects asset paths that would escape the shell-owned static subtree.
   *
   * @param assetPath asset path relative to the shell asset root
   * @return {@code true} when the path is empty, malformed, or attempts directory traversal
   */
  private static boolean isInvalidAssetPath(String assetPath) {
    return !assetPath.matches("^[A-Za-z0-9._/\\-]*$") || assetPath.contains("..");
  }

  /**
   * Returns the request path while preserving encoded characters when available.
   *
   * @param uri request URI received by the toadlet
   * @return raw path when present, otherwise the decoded URI path
   */
  private static String requestPath(URI uri) {
    String rawPath = uri.getRawPath();
    return rawPath != null ? rawPath : uri.getPath();
  }

  /**
   * Resolves the last-modified time for one shell-owned classpath resource.
   *
   * <p>Jar-backed resources use the containing JAR timestamp, so HTTP caches can still validate the
   * response even when the resource itself is not exposed as a standalone filesystem entry.
   *
   * @param resourceUrl classpath URL of the asset being served
   * @return best-effort modification time, or {@code null} when it cannot be determined
   */
  private static Instant getUrlMTime(URL resourceUrl) {
    if (resourceUrl == null) {
      return null;
    }
    try {
      URLConnection connection = resourceUrl.openConnection();
      if (connection instanceof JarURLConnection jarConnection) {
        long jarLastModified = jarConnection.getJarFileURL().openConnection().getLastModified();
        return jarLastModified == 0 ? null : Instant.ofEpochMilli(jarLastModified);
      }

      long lastModified = connection.getLastModified();
      return lastModified == 0 ? null : Instant.ofEpochMilli(lastModified);
    } catch (IOException _) {
      return null;
    }
  }
}

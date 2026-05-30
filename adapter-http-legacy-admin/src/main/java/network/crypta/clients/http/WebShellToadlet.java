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
 * beneath {@value WebShellPaths#ASSET_ROOT}, and injects the small bootstrap payload needed by the
 * browser-side script, including the legacy mutation token required by the current Platform API
 * bridge.
 */
public final class WebShellToadlet extends Toadlet {
  /** Content type used for the shell document returned from the main route. */
  private static final String HTML_CONTENT_TYPE = "text/html; charset=UTF-8";

  /** Shared reason phrase for missing shell routes and shell-owned assets. */
  private static final String NOT_FOUND_REASON = "Not Found";

  /** Adapter-owned bootstrap payload injected into the rendered shell document. */
  private final WebShellBootstrap bootstrap;

  /** Creates a Web Shell bridge backed by the default node-management bootstrap payload. */
  public WebShellToadlet() {
    this(createNodeManagementBootstrap(defaultLegacyLinks()));
  }

  /**
   * Creates a bridge with an explicit bootstrap model.
   *
   * <p>This package-local constructor exists for focused adapter tests that need to verify
   * bootstrap injection without relying on the default legacy-link set.
   *
   * @param bootstrap shell bootstrap payload to embed in the rendered page
   */
  WebShellToadlet(WebShellBootstrap bootstrap) {
    super();
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
          WebShellPageRenderer.render(bootstrap.withFormPassword(ctx.getFormPassword())));
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
    return createNodeManagementBootstrap(legacySecurityLevelsPath(), legacyLinks);
  }

  /**
   * Creates the node-management bootstrap model with an explicit security-levels fallback path.
   *
   * @param legacySecurityLevelsPath configured legacy security route for explicit fallback flows
   * @param legacyLinks ordered legacy deep links to surface in the shell footer area
   * @return immutable bootstrap model for the first-party node-management shell
   */
  static WebShellBootstrap createNodeManagementBootstrap(
      String legacySecurityLevelsPath, List<WebShellBootstrap.LegacyLink> legacyLinks) {
    return WebShellBootstrap.nodeManagement(legacySecurityLevelsPath, legacyLinks);
  }

  private static String legacySecurityLevelsPath() {
    return LegacyAdminRetirementRegistry.require("security-levels").legacyPath();
  }

  /**
   * Returns the default legacy deep links exposed by the Web Shell.
   *
   * <p>The list is sourced from the retirement registry so primary-replaced and removed-by-default
   * legacy admin pages do not appear as shell fallback links. Only retained or pending tools that
   * still need a legacy entry point remain here.
   *
   * @return ordered fallback links for retained or pending legacy pages
   */
  static List<WebShellBootstrap.LegacyLink> defaultLegacyLinks() {
    return LegacyAdminRetirementRegistry.webShellFallbackSurfaces().stream()
        .map(surface -> legacyLink(surface.legacyPath(), surface.title()))
        .toList();
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

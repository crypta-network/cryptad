package network.crypta.clients.http;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.JarURLConnection;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.time.Instant;
import network.crypta.client.DefaultMIMETypes;
import network.crypta.l10n.NodeL10n;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.HTTPRequest;
import network.crypta.support.http.StaticResourcePaths;
import network.crypta.support.io.FileBucket;

/**
 * Serves static assets bundled with the node as well as user-supplied override files.
 *
 * <p>This toadlet routes {@code /static/} requests either to classpath resources packaged inside
 * the application JAR or to files located under the configurable override directory. It performs
 * cautious path validation to prevent escaping the allowed roots, sets conservative cache headers
 * so clients refresh modified assets quickly, and hands buckets to the {@link ToadletContext} for
 * streaming without retaining ownership. Typical usage wires an instance into the HTTP server
 * registry so that browsers can fetch theme assets, icons, and HTML fragments. The handler is
 * stateless and thread-safe provided callers supply independent {@link ToadletContext} instances
 * per request.
 *
 * <p>Responsibilities include:
 *
 * <ul>
 *   <li>Normalize and validate incoming resource paths under {@link #ROOT_URL}.
 *   <li>Map override requests to files while ensuring callers cannot traverse outside the override
 *       base.
 *   <li>Stream classpath resources from {@value #ROOT_PATH} with last-modified dates derived from
 *       the hosting JAR or file.
 * </ul>
 *
 * Clients should prefer this toadlet over the ad-hoc file serving to keep consistent validation,
 * cache behavior, and ownership semantics for buckets.
 */
public class StaticToadlet extends Toadlet {
  StaticToadlet() {
    super(null);
  }

  private static final String KEY_PATH_NOT_FOUND_TITLE = "pathNotFoundTitle";
  private static final String KEY_PATH_NOT_FOUND = "pathNotFound";
  private static final String KEY_PATH_INVALID = "pathInvalidChars";

  /**
   * Base URL prefix under which static assets are exposed to HTTP clients.
   *
   * <p>Every request handled by this toadlet must start with this prefix; routing logic strips it
   * before resolving resources. Keeping the prefix centralized makes it easy for callers to mount
   * the toadlet under a different path without changing lookup behavior.
   */
  public static final String ROOT_URL = StaticResourcePaths.ROOT_URL;

  /**
   * Classpath location that contains packaged static resources resolved by {@link
   * Class#getResource}.
   *
   * <p>Files beneath this directory are bundled inside the application JAR and accessed via the
   * classloader, which allows the same asset set to be served in embedded, installed, or test
   * environments without requiring filesystem layout assumptions.
   */
  public static final String ROOT_PATH = "staticfiles/";

  /**
   * Path segment that designates user-supplied override files within the static namespace.
   *
   * <p>When a request path begins with this segment, the toadlet resolves it against the override
   * directory so operators can customize themes or assets without repackaging the node. Traversal
   * checks guard against escaping beyond the configured override root.
   */
  public static final String OVERRIDE = "override/";

  /**
   * Fully qualified URL prefix that maps to the override directory for theme customization.
   *
   * <p>Combining {@link #ROOT_URL} with {@link #OVERRIDE} yields the externally visible path that
   * administrators reference when providing custom files. Keeping it as a constant avoids
   * hard-coded string concatenation throughout the codebase.
   */
  public static final String OVERRIDE_URL = ROOT_URL + OVERRIDE;

  /**
   * Handles HTTP GET requests for static assets or override files.
   *
   * <p>The method validates that the requested path begins with {@link #ROOT_URL}, strips the
   * prefix, rejects traversal attempts, and dispatches to either {@link #serveOverride(String,
   * ToadletContext)} or {@link #serveClasspathResource(String, ToadletContext)}. It sets headers
   * before streaming data and relies on the supplied {@link ToadletContext} to manage bucket
   * lifetime. Callers should provide a distinct context per incoming connection to avoid
   * cross-request interference.
   *
   * @param uri request URI under {@link #ROOT_URL}, expected non-null for routed GET calls.
   * @param request request wrapper carrying headers and parameters; used only for validation.
   * @param ctx response context that emits headers and streams bytes; must stay open while writing.
   * @throws ToadletContextClosedException if the connection closes before headers or body finish.
   * @throws IOException if filesystem lookups or streaming encounter low-level I/O failures.
   */
  @Override
  public void handleMethodGET(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    String requestPath = uri.getPath();

    if (!requestPath.startsWith(ROOT_URL)) {
      return; // we should never get any other path anyway
    }

    String path = stripRootPrefix(requestPath, ctx);
    if (path == null) {
      return;
    }

    if (isInvalidPath(path)) {
      sendPathInvalid(ctx);
      return;
    }

    if (path.startsWith(OVERRIDE)) {
      serveOverride(path, ctx);
      return;
    }

    serveClasspathResource(path, ctx);
  }

  /**
   * Tries to find the modification time for a URL.
   *
   * <p>Returns {@code null} when modification time cannot be determined. Resources are usually
   * loaded from a JAR, but some setups load from plain files. For JAR resources this checks the JAR
   * file mtime; for file resources it checks the file mtime.
   */
  private Instant getUrlMTime(URL url) {
    if (url == null) {
      return null;
    }
    try {
      URLConnection connection = url.openConnection();
      if (connection instanceof JarURLConnection jarConnection) {
        long jarLastModified = jarConnection.getJarFileURL().openConnection().getLastModified();
        return jarLastModified == 0 ? null : Instant.ofEpochMilli(jarLastModified);
      }

      long lastModified = connection.getLastModified();
      return lastModified == 0 ? null : Instant.ofEpochMilli(lastModified);
    } catch (IOException e) {
      return null;
    }
  }

  private static String l10n(String key) {
    return NodeL10n.getBase().getString("StaticToadlet." + key);
  }

  /**
   * Returns the root URL handled by this toadlet.
   *
   * <p>This value is used by the HTTP server wiring to route inbound requests to the correct
   * handler and by clients that want to construct absolute paths to packaged assets. The value is
   * immutable and reflects {@link #ROOT_URL}, keeping configuration centralized while allowing
   * other components to compare or publish the mounted path reliably.
   *
   * @return canonical URL prefix served by this toadlet; never {@code null} or empty.
   */
  @Override
  public String path() {
    return ROOT_URL;
  }

  /**
   * Do we have a specific static file? Note that override files are not supported here as it is a
   * static method.
   *
   * <p>This helper checks only the packaged resources that ship with the application and does not
   * consult the filesystem override directory. It is intended for callers that need to confirm an
   * asset exists before attempting to embed links or references in generated pages. The lookup uses
   * the classloader, so it remains reliable across different distribution formats, including shaded
   * JARs and installed distributions where the working directory is not predictable.
   *
   * @param path relative path under {@link #ROOT_PATH} to check; traversal segments are disallowed.
   * @return {@code true} when a matching classpath resource exists; {@code false} otherwise.
   */
  public static boolean haveFile(String path) {
    URL url = StaticToadlet.class.getResource(ROOT_PATH + path);
    return url != null;
  }

  private String stripRootPrefix(String path, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    try {
      return path.substring(ROOT_URL.length());
    } catch (IndexOutOfBoundsException _) {
      sendPathNotFound(ctx);
      return null;
    }
  }

  private boolean isInvalidPath(String path) {
    return !path.matches("^[A-Za-z0-9._/\\-]*$") || path.contains("..");
  }

  @SuppressWarnings("java:S2095")
  private void serveOverride(String path, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    File overrideFile = this.container.getOverrideFile();
    if (isInvalidFile(overrideFile)) {
      sendPathInvalid(ctx);
      return;
    }
    File absoluteOverride = overrideFile.getAbsoluteFile();
    if (isInvalidFile(absoluteOverride)) {
      sendPathInvalid(ctx);
      return;
    }
    File parent = absoluteOverride.getParentFile();
    // Basic sanity check.
    // Prevents user from specifying root dir.
    // They can still shoot themselves in the foot, but only when developing themes/using custom
    // themes.
    // Because of the .. check above, any malicious thing cannot break out of the dir anyway.
    if (parent.getParentFile() == null) {
      sendPathInvalid(ctx);
      return;
    }
    File from = new File(parent, path.substring(OVERRIDE.length()));
    if (!from.exists() && !from.isFile()) {
      sendPathInvalid(ctx);
      return;
    }
    // Do not use try-with-resources: ToadletContext assumes ownership of the bucket and will free
    // it after sending the response. Closing it here could discard data before the sending
    // completes.
    FileBucket fb = new FileBucket(from, true, false, false, false);
    boolean handedOff = false;
    try {
      ctx.sendReplyHeadersStatic(
          200,
          "OK",
          null,
          DefaultMIMETypes.guessMIMEType(path, false),
          fb.size(),
          Instant.now().minusMillis(1000)); // Already expired, we want it to reload it.
      handedOff = true;
      ctx.writeData(fb);
    } catch (IOException _) {
      // Not strictly accurate but close enough
      sendPathNotFound(ctx);
    } finally {
      if (!handedOff) {
        fb.free();
      }
    }
  }

  private void serveClasspathResource(String path, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    InputStream strm = getClass().getResourceAsStream(ROOT_PATH + path);
    if (strm == null) {
      sendPathNotFound(ctx);
      return;
    }
    Bucket data;
    try (InputStream inputStream = strm) {
      data = ctx.getBucketFactory().makeBucket(inputStream.available());
      try (OutputStream os = data.getOutputStream()) {
        byte[] cbuf = new byte[4096];
        while (true) {
          int r = inputStream.read(cbuf);
          if (r == -1) break;
          os.write(cbuf, 0, r);
        }
      }
    }

    URL url = getClass().getResource(ROOT_PATH + path);
    Instant mTime = getUrlMTime(url);

    ctx.sendReplyHeadersStatic(
        200, "OK", null, DefaultMIMETypes.guessMIMEType(path, false), data.size(), mTime);

    ctx.writeData(data);
  }

  private void sendPathNotFound(ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    this.sendErrorPage(ctx, 404, l10n(KEY_PATH_NOT_FOUND_TITLE), l10n(KEY_PATH_NOT_FOUND));
  }

  private void sendPathInvalid(ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    this.sendErrorPage(ctx, 404, l10n(KEY_PATH_NOT_FOUND_TITLE), l10n(KEY_PATH_INVALID));
  }

  private boolean isInvalidFile(File file) {
    return file == null || !file.exists() || !file.isFile();
  }
}

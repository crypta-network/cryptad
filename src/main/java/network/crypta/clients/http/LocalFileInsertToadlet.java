package network.crypta.clients.http;

import java.io.File;
import java.net.MalformedURLException;
import java.util.HashMap;
import java.util.Map;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.keys.FreenetURI;
import network.crypta.node.NodeClientCore;

/**
 * Serves the local file browser used by FProxy uploads, wiring user selections to the queue on a
 * configurable endpoint. A single instance lives alongside the HTTP server and renders directory
 * listings, enforces upload permissions, and forwards form submissions to the upload queue toadlet.
 * The browse and POST targets default to <code>/insert-browse/</code> and <code>/uploads/</code>
 * but can be overridden via system properties; paths are normalized to include leading and trailing
 * slashes to match toadlet registration. Instances rely on {@link NodeClientCore} to validate
 * directories and to derive the default starting location so users land in a permitted folder. The
 * class is not intended to be thread-safe by itself; the surrounding HTTP framework allocates and
 * synchronizes access per request lifecycle.
 *
 * <p><strong>Responsibilities</strong>
 *
 * <ul>
 *   <li>Render a filesystem browser rooted at an operator-controlled directory.
 *   <li>Emit forms that post multipart uploads to the queue toadlet.
 *   <li>Persist selected keys and compatibility options between requests when possible.
 * </ul>
 *
 * @see LocalFileBrowserToadlet
 * @see QueueToadlet
 */
public class LocalFileInsertToadlet extends LocalFileBrowserToadlet {
  private static final String INSERT_BROWSE_PATH_PROPERTY = "cryptad.http.insertBrowsePath";
  private static final String UPLOADS_PATH_PROPERTY = "cryptad.http.uploadsPath";
  private static final String DEFAULT_INSERT_BROWSE_PATH = surroundWithSlashes("insert-browse");
  private static final String DEFAULT_UPLOADS_PATH = surroundWithSlashes("uploads");

  /**
   * HTTP path where the browser UI is exposed. Defaults to <code>/insert-browse/</code> and can be
   * overridden via {@value #INSERT_BROWSE_PATH_PROPERTY}; normalized to retain leading and trailing
   * slashes for consistency with toadlet registration.
   */
  public static final String INSERT_BROWSE_PATH =
      normalizePath(System.getProperty(INSERT_BROWSE_PATH_PROPERTY, DEFAULT_INSERT_BROWSE_PATH));

  /**
   * Target path for POST submissions that enqueue uploads. Derived from {@value
   * #UPLOADS_PATH_PROPERTY} or defaults to <code>/uploads/</code>, with leading/trailing slashes
   * enforced so generated forms resolve to the registered upload queue handler.
   */
  public static final String UPLOADS_PATH =
      normalizePath(System.getProperty(UPLOADS_PATH_PROPERTY, DEFAULT_UPLOADS_PATH));

  private static String surroundWithSlashes(String segment) {
    return '/' + segment + '/';
  }

  private static String normalizePath(String path) {
    if (path == null || path.isEmpty()) return "/";

    String normalized = path;
    if (!normalized.startsWith("/")) {
      normalized = '/' + normalized;
    }
    if (!normalized.endsWith("/")) {
      normalized = normalized + '/';
    }
    return normalized;
  }

  /**
   * Creates a browser toadlet bound to the node core and a session-aware client facade. The
   * constructor does not perform I/O; callers should register the instance with the HTTP server to
   * make it reachable.
   *
   * @param core node client core used for permission checks and default directory resolution; must
   *     not be {@code null}.
   * @param highLevelSimpleClient client wrapper that binds uploads to the current user session;
   *     must not be {@code null}.
   */
  public LocalFileInsertToadlet(NodeClientCore core, HighLevelSimpleClient highLevelSimpleClient) {
    super(core, highLevelSimpleClient);
  }

  /**
   * Returns the normalized browse path that activates this toadlet. The value mirrors {@link
   * #INSERT_BROWSE_PATH}, which can be configured through a system property, and always includes
   * surrounding slashes so links and redirects remain stable. Callers typically use this path when
   * wiring the toadlet into the HTTP server or when generating anchors that lead users back to the
   * local file browser from other queue pages.
   *
   * @return browse endpoint path with leading and trailing slashes preserved for routing.
   */
  @Override
  public String path() {
    return INSERT_BROWSE_PATH;
  }

  /**
   * Provides the HTTP endpoint that should receive multipart submissions produced by the browser
   * form. The returned value always contains leading and trailing slashes to align with the toadlet
   * registration performed by {@link FProxyRegistrar}. Callers may override the endpoint through
   * {@code cryptad.http.uploadsPath}; the normalization step ensures user-supplied values cannot
   * omit slashes and accidentally diverge from the queue toadlet registration. The path is consumed
   * by HTML form generation so it should remain reachable to avoid 404 responses.
   *
   * @return normalized upload queue path that the form action should target.
   */
  @Override
  protected String postTo() {
    return UPLOADS_PATH;
  }

  /**
   * Determines whether a directory can be displayed for uploads. Delegates to {@link
   * NodeClientCore#allowUploadFrom(File)} to enforce operator-configured allow-lists and gateway
   * restrictions before the listing is shown. The method performs no normalization or
   * canonicalization; it forwards the caller-provided path directly to the core, which decides if
   * the directory falls within the allowed root, respects public gateway limitations, or should be
   * rejected. Returning {@code false} prevents the browser from rendering the directory contents.
   *
   * @param path candidate directory selected by the user; must be an existing filesystem path.
   * @return {@code true} when uploads from the directory are permitted; {@code false} otherwise.
   */
  @Override
  protected boolean allowedDir(File path) {
    return core.allowUploadFrom(path);
  }

  /**
   * Supplies the directory shown when the browser first loads. The default resolves to the
   * configured upload root or the user's home directory depending on node policy. Implementations
   * may override to steer users toward a more constrained subtree. The returned value is passed to
   * the browser template without further validation, so callers should ensure it points to a
   * directory that exists and is permitted by {@link #allowedDir(File)} to avoid empty listings or
   * permission denials on first render.
   *
   * @return normalized path string for the initial directory presented to the browser UI.
   */
  @Override
  protected String startingDir() {
    return defaultUploadDir();
  }

  /**
   * Extracts persistent form fields from the provided parameter map so future renders can retain
   * user choices. Keys are validated and sanitized; malformed URIs are ignored rather than causing
   * failures. Only a subset of options is preserved: compression requests when set to {@code true},
   * compatibility flags, validated keys, and explicit splitfile overrides. Leaving out other
   * entries avoids persisting transient or potentially sensitive fields between requests.
   *
   * @param set mutable map of form parameters captured during submission; expected to include
   *     optional keys such as {@code key}, {@code compress}, and {@code compatibilityMode}.
   * @return new map containing only the fields safe to persist across requests; never {@code null}.
   */
  @Override
  protected Map<String, String> persistenceFields(Map<String, String> set) {
    Map<String, String> fieldPairs = new HashMap<>();
    FreenetURI furi = null;
    String key = set.get("key");
    if (key != null) {
      try {
        furi = new FreenetURI(key);
      } catch (MalformedURLException e) {
        // keep default null when parsing fails
      }
    }

    String element = set.get("compress");
    if (Boolean.parseBoolean(element)) {
      fieldPairs.put("compress", element);
    }

    element = set.get("compatibilityMode");
    if (element != null) {
      fieldPairs.put("compatibilityMode", element);
    }

    if (furi != null) {
      fieldPairs.put("key", furi.toASCIIString());
    }

    element = set.get("overrideSplitfileKey");
    if (element != null) fieldPairs.put("overrideSplitfileKey", element);
    return fieldPairs;
  }
}

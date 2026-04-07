package network.crypta.platform.webshell.routes;

import java.util.Objects;
import network.crypta.platform.webshell.WebShellResources;

/**
 * Route and resource constants for the first-party Web Shell v1.
 *
 * <p>The shell is mounted as an app-style route under {@value #SHELL_ROOT}. Its assets remain
 * sibling resources beneath {@value #ASSET_ROOT}, so the legacy HTTP bridge can serve the shell as
 * a self-contained browser surface without learning any additional routing conventions.
 */
public final class WebShellPaths {
  /** Absolute classpath root that contains the shell-owned HTML, CSS, and JavaScript resources. */
  private static final String RESOURCE_ROOT =
      "/" + WebShellResources.class.getPackageName().replace('.', '/') + "/";

  /** Canonical root path for the node-management shell. */
  public static final String SHELL_ROOT = "/app/node/";

  /** Canonical static-asset root exposed beneath the shell route. */
  public static final String ASSET_ROOT = SHELL_ROOT + "static/";

  /** Classpath resource path for the HTML shell template. */
  public static final String INDEX_RESOURCE_PATH = resourcePath("static/index.html");

  /** Classpath resource root for the shell-owned static assets. */
  public static final String ASSET_RESOURCE_ROOT = resourcePath("static/");

  /** Relative stylesheet path used by the shell template. */
  public static final String STYLESHEET_PATH = "static/web-shell.css";

  /** Relative script path used by the shell template. */
  public static final String SCRIPT_PATH = "static/web-shell.js";

  /** DOM id used for the inline bootstrap JSON blob. */
  public static final String BOOTSTRAP_ELEMENT_ID = "web-shell-bootstrap";

  /**
   * Resolves one shell-owned classpath resource path relative to the shell resource package.
   *
   * @param relativeResourcePath path beneath the shell resource package
   * @return absolute classpath resource path
   * @throws NullPointerException if the path is {@code null}
   * @throws IllegalArgumentException if the path is blank or already absolute
   */
  public static String resourcePath(String relativeResourcePath) {
    String normalizedPath = requireRelativeResourcePath(relativeResourcePath);
    return RESOURCE_ROOT + normalizedPath;
  }

  /** Prevents instantiation of this constant holder. */
  private WebShellPaths() {}

  /**
   * Validates one resource path that must stay relative to the shell resource package.
   *
   * @param relativeResourcePath resource path candidate beneath the shell package
   * @return validated relative resource path
   * @throws NullPointerException if the path is {@code null}
   * @throws IllegalArgumentException if the path is blank or already absolute
   */
  private static String requireRelativeResourcePath(String relativeResourcePath) {
    Objects.requireNonNull(relativeResourcePath, "relativeResourcePath");
    if (relativeResourcePath.isBlank()) {
      throw new IllegalArgumentException("relativeResourcePath must not be blank");
    }
    if (relativeResourcePath.charAt(0) == '/') {
      throw new IllegalArgumentException("relativeResourcePath must be relative");
    }
    return relativeResourcePath;
  }
}

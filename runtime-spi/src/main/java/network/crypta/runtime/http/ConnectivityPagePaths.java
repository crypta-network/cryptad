package network.crypta.runtime.http;

/**
 * Publishes the canonical connectivity dashboard path shared across runtime and adapter layers.
 *
 * <p>This class intentionally keeps the normalized route fragment in a JDK-only location, so both
 * runtime code and detached HTTP adapters can reference the same endpoint name without depending on
 * a node-owned implementation class. The value remains stable for existing links, bookmarks, and
 * tests, while still allowing controlled overrides through a system property for specialized
 * runtime wiring.
 *
 * <p>The exported path includes both leading and trailing separators, so callers can use it
 * directly when registering routes or generating links without additional string handling.
 */
public final class ConnectivityPagePaths {
  private static final String PATH_PROPERTY =
      "network.crypta.runtime.endpoints.http.ConnectivityPagePaths.path";
  private static final char URL_PATH_SEPARATOR = '/';
  private static final String URL_PATH_SEPARATOR_STR = String.valueOf(URL_PATH_SEPARATOR);
  private static final String DEFAULT_CONNECTIVITY_SEGMENT = "connectivity";

  /**
   * Canonical path for the connectivity dashboard, including both boundary separators.
   *
   * <p>The default remains the historical {@code /connectivity/} route so existing links,
   * bookmarks, and handlers continue to work without migration. Tests or custom runtime assembly
   * can override the value with the {@value #PATH_PROPERTY} system property. The resolved path is
   * normalized to start and end with {@code /}, which lets callers reuse it directly for both route
   * registration and rendered links.
   */
  public static final String CONNECTIVITY_PATH = resolvePath(System.getProperty(PATH_PROPERTY));

  private ConnectivityPagePaths() {}

  static String resolvePath(String configuredPath) {
    String path =
        (configuredPath == null || configuredPath.isBlank())
            ? defaultPath()
            : configuredPath.trim();

    if (!path.startsWith(URL_PATH_SEPARATOR_STR)) {
      path = URL_PATH_SEPARATOR_STR + path;
    }
    if (!path.endsWith(URL_PATH_SEPARATOR_STR)) {
      path = path + URL_PATH_SEPARATOR_STR;
    }

    return path;
  }

  private static String defaultPath() {
    return URL_PATH_SEPARATOR_STR + DEFAULT_CONNECTIVITY_SEGMENT + URL_PATH_SEPARATOR_STR;
  }
}

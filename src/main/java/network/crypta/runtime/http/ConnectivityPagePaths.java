package network.crypta.runtime.http;

/**
 * Publishes runtime-owned HTTP path constants that other layers can reuse safely.
 *
 * <p>This type gives the runtime HTTP layer a stable place to describe routes that must remain
 * visible to non-HTTP code. The main use case in this package is the connectivity dashboard, which
 * node classes need to reference when they generate status text and operator guidance. Keeping the
 * canonical route here avoids a direct dependency on legacy toadlet implementations while
 * preserving the exact URL shape that older code and bookmarks already expect.
 *
 * <p>The class exposes normalized paths with a leading and trailing slash so callers can use the
 * same value for link generation and endpoint registration without extra string handling. A system
 * property override exists for controlled test scenarios and specialized runtime wiring.
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

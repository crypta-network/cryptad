package network.crypta.platform.appui;

import java.net.URI;
import java.util.Locale;
import java.util.Objects;
import network.crypta.platform.apphost.manifest.AppManifest;

/**
 * Loopback-only browser origin assigned to one installed static app UI.
 *
 * <p>Cryptad uses distinct loopback ports to create distinct browser origins without exposing app
 * UI listeners on wildcard or LAN-visible interfaces. This value stores only the public browser
 * origin. It does not represent a socket, server lifecycle, or AppHost process sandbox.
 *
 * <p>The record is intentionally narrow: it accepts only {@code http://127.0.0.1:<port>} and
 * rejects paths, remote hosts, wildcard addresses, and HTTPS assumptions. The HTTP adapter owns the
 * actual listener and can recreate it as apps are installed or removed. Other layers use this value
 * to compare browser {@code Origin} headers, build root URLs, and serialize safe UI metadata
 * without leaking filesystem paths or app process credentials.
 *
 * @param appId normalized app identifier assigned to this browser origin
 * @param scheme browser scheme, currently the local {@code http} scheme only
 * @param host loopback host exposed to the browser, currently {@code 127.0.0.1}
 * @param port TCP port bound on the advertised loopback interface
 */
public record AppUiOrigin(String appId, String scheme, String host, int port) {
  /** Default IPv4 loopback host used for app UI origins. */
  public static final String LOOPBACK_HOST = "127.0.0.1";

  /** Local HTTP scheme used for per-app loopback origins. */
  public static final String LOCAL_HTTP_SCHEME = "http";

  /**
   * Creates an isolated loopback origin for one installed app.
   *
   * <p>This factory is the normal path for the loopback listener allocator. It applies the default
   * scheme and host before the canonical constructor validates the app id and port range.
   *
   * @param appId normalized app identifier that owns the allocated listener
   * @param port loopback TCP port allocated to the app UI listener
   * @return validated loopback origin for the supplied app and port
   */
  public static AppUiOrigin loopback(String appId, int port) {
    return new AppUiOrigin(appId, LOCAL_HTTP_SCHEME, LOOPBACK_HOST, port);
  }

  /**
   * Parses and validates one serialized origin for the supplied app id.
   *
   * <p>The serialized value must be an origin, not a full URL. Paths, queries, and fragments are
   * rejected so callers do not accidentally authorize more than a scheme, host, and port tuple.
   *
   * @param appId normalized app identifier expected to own the serialized origin
   * @param origin serialized origin such as {@code http://127.0.0.1:12345}
   * @return validated loopback app origin for the supplied app id
   * @throws IllegalArgumentException if the origin is not a loopback HTTP origin without path,
   *     query, or fragment
   */
  public static AppUiOrigin parse(String appId, String origin) {
    Objects.requireNonNull(origin, "origin");
    URI uri = URI.create(origin);
    if (uri.getRawPath() != null && !uri.getRawPath().isEmpty()) {
      throw new IllegalArgumentException("app UI origin must not include a path");
    }
    if (uri.getRawQuery() != null || uri.getRawFragment() != null) {
      throw new IllegalArgumentException("app UI origin must not include query or fragment");
    }
    return new AppUiOrigin(appId, uri.getScheme(), uri.getHost(), uri.getPort());
  }

  /**
   * Creates a validated loopback origin.
   *
   * <p>The constructor normalizes the app id, scheme, and host before enforcing the supported
   * isolation policy. It is public because records expose their canonical constructor, but callers
   * should prefer {@link #loopback(String, int)} when allocating a new app UI origin.
   *
   * @throws IllegalArgumentException if the app id, scheme, host, or port is not supported for
   *     app-origin isolation
   */
  public AppUiOrigin {
    appId = AppManifest.normalizeAppId(Objects.requireNonNull(appId, "appId"));
    scheme = Objects.requireNonNull(scheme, "scheme").toLowerCase(Locale.ROOT);
    host = Objects.requireNonNull(host, "host").toLowerCase(Locale.ROOT);
    if (!LOCAL_HTTP_SCHEME.equals(scheme)) {
      throw new IllegalArgumentException("app UI origins must use http");
    }
    if (!LOOPBACK_HOST.equals(host)) {
      throw new IllegalArgumentException("app UI origins must use 127.0.0.1 loopback");
    }
    if (port <= 0 || port > 65535) {
      throw new IllegalArgumentException("app UI origin port must be in range 1..65535");
    }
  }

  /**
   * Returns the serialized browser origin.
   *
   * <p>The result is suitable for exact comparison with a browser {@code Origin} header and for
   * storing in app-origin registries. It never includes a trailing slash.
   *
   * @return origin text without a path, query, or fragment
   */
  public String origin() {
    return scheme + "://" + host + ":" + port;
  }

  /**
   * Returns the root URL for this app origin.
   *
   * <p>The result is the base URL that Web Shell can open and that app bootstrap JSON can publish
   * as the UI root. It is derived from {@link #origin()} and always ends in one slash.
   *
   * @return browser root URL ending in {@code /}
   */
  public String rootUrl() {
    return origin() + "/";
  }
}

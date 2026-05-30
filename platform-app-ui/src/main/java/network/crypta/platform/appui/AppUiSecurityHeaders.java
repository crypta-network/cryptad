package network.crypta.platform.appui;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Conservative response headers for app-owned static browser UI.
 *
 * <p>The headers keep static app resources local to their serving origin while avoiding remote
 * scripts, object embedding, base tag rewrites, cross-origin form posts, referrer leakage, and MIME
 * sniffing. They are deliberately adapter-neutral: the app UI layer returns lowercase header names
 * and string values, and HTTP bridges convert them into their transport-specific header container.
 *
 * <p>This policy is not an AppHost process sandbox and does not implement app permissions. It is a
 * defensive default for immutable installed-bundle UI assets on both same-origin fallback routes
 * and isolated loopback origins. When the legacy admin surface has JavaScript disabled, the app UI
 * CSP also disables script execution so app-owned routes follow the same operator preference.
 */
public final class AppUiSecurityHeaders {
  private static final String SELF_SOURCE = "'self'";
  private static final String NONE_SOURCE = "'none'";
  private static final String LOOPBACK_ADMIN_HOST = "127.0.0.1";
  private static final String LOCALHOST_ADMIN_HOST = "localhost";
  private static final String IPV6_LOOPBACK_ADMIN_HOST = "::1";
  private static final String EXPANDED_IPV6_LOOPBACK_ADMIN_HOST = "0:0:0:0:0:0:0:1";
  private static final String HTTP_SCHEME = "http";
  private static final String HTTPS_SCHEME = "https";

  /**
   * Content Security Policy applied to static app UI responses when JavaScript is enabled.
   *
   * <p>The policy allows only same-origin scripts and resources, blocks object embedding, prevents
   * {@code base} tag rewrites, keeps form submissions same-origin, and limits framing to the local
   * origin.
   */
  public static final String CONTENT_SECURITY_POLICY = contentSecurityPolicy(true);

  /**
   * Content Security Policy applied when the legacy admin UI disables JavaScript.
   *
   * <p>This variant keeps the rest of the app UI restrictions intact but changes {@code script-src}
   * to {@code 'none'} so bundled app JavaScript does not execute against an operator preference
   * that already disables scripts in the legacy admin surface.
   */
  public static final String JAVASCRIPT_DISABLED_CONTENT_SECURITY_POLICY =
      contentSecurityPolicy(false);

  private AppUiSecurityHeaders() {}

  /**
   * Returns app UI security headers in deterministic order.
   *
   * <p>This convenience method uses the JavaScript-enabled policy because most adapters already
   * know whether the container has disabled JavaScript and should call {@link #headers(boolean)}
   * when that setting is available.
   *
   * @return immutable header name/value map suitable for adapter conversion
   */
  public static Map<String, String> headers() {
    return headers(true);
  }

  /**
   * Returns app UI security headers for the current JavaScript policy.
   *
   * <p>The map preserves insertion order so tests and adapters can produce stable output. Header
   * names are lowercase to match the platform API style and to avoid case-sensitive duplicate
   * checks in legacy response code.
   *
   * @param javascriptEnabled whether same-origin app scripts are allowed to execute
   * @return immutable header name/value map suitable for adapter conversion
   */
  public static Map<String, String> headers(boolean javascriptEnabled) {
    return headers(javascriptEnabled, null, null);
  }

  /**
   * Returns app UI security headers for an isolated-origin response.
   *
   * <p>The CSP still limits scripts and resources to the app origin by default, but it permits
   * Platform API fetches to the supplied admin API root and limits framing to the supplied Web
   * Shell/admin origin. {@code X-Frame-Options} is intentionally omitted when a cross-origin frame
   * ancestor is configured because the older header cannot express that policy.
   *
   * @param javascriptEnabled whether app scripts are allowed to execute
   * @param platformApiRoot absolute Platform API root, or {@code null} for same-origin only
   * @param shellRoot absolute Web Shell root, or {@code null} for same-origin frame ancestors
   * @return immutable header name/value map suitable for adapter conversion
   */
  public static Map<String, String> headers(
      boolean javascriptEnabled, String platformApiRoot, String shellRoot) {
    LinkedHashMap<String, String> headers = LinkedHashMap.newLinkedHashMap(6);
    String frameAncestor = localAdminOriginSource(shellRoot);
    headers.put(
        "content-security-policy",
        contentSecurityPolicy(
            javascriptEnabled, localAdminOriginSource(platformApiRoot), frameAncestor));
    headers.put("x-content-type-options", "nosniff");
    headers.put("referrer-policy", "no-referrer");
    headers.put(
        "permissions-policy",
        "camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(),"
            + " bluetooth=(), accelerometer=(), gyroscope=(), magnetometer=()");
    headers.put("cross-origin-resource-policy", "same-origin");
    if (frameAncestor == null) {
      headers.put("x-frame-options", "SAMEORIGIN");
    }
    return java.util.Collections.unmodifiableMap(headers);
  }

  private static String contentSecurityPolicy(boolean javascriptEnabled) {
    return contentSecurityPolicy(javascriptEnabled, null, null);
  }

  private static String contentSecurityPolicy(
      boolean javascriptEnabled, String platformApiOrigin, String frameAncestor) {
    String scriptSource = javascriptEnabled ? SELF_SOURCE : NONE_SOURCE;
    String connectSource =
        platformApiOrigin == null ? SELF_SOURCE : SELF_SOURCE + " " + platformApiOrigin;
    String frameAncestors = frameAncestor == null ? SELF_SOURCE : SELF_SOURCE + " " + frameAncestor;
    return "default-src "
        + NONE_SOURCE
        + "; script-src "
        + scriptSource
        + "; style-src "
        + SELF_SOURCE
        + "; img-src "
        + SELF_SOURCE
        + " data:"
        + "; font-src "
        + SELF_SOURCE
        + "; connect-src "
        + connectSource
        + "; media-src "
        + NONE_SOURCE
        + "; frame-src "
        + NONE_SOURCE
        + "; worker-src "
        + NONE_SOURCE
        + "; object-src "
        + NONE_SOURCE
        + "; base-uri "
        + NONE_SOURCE
        + "; form-action "
        + SELF_SOURCE
        + "; frame-ancestors "
        + frameAncestors
        + "; manifest-src "
        + SELF_SOURCE;
  }

  private static String localAdminOriginSource(String rootUrl) {
    if (rootUrl == null || rootUrl.startsWith("/")) {
      return null;
    }
    try {
      URI uri = URI.create(rootUrl);
      if (!isSafeLocalAdminOrigin(uri)) {
        return null;
      }
      return uri.getScheme().toLowerCase(Locale.ROOT)
          + "://"
          + cspHostSource(uri.getHost())
          + ':'
          + uri.getPort();
    } catch (IllegalArgumentException _) {
      return null;
    }
  }

  private static boolean isSafeLocalAdminOrigin(URI uri) {
    String scheme = uri.getScheme();
    if (scheme == null) {
      return false;
    }
    String normalizedScheme = scheme.toLowerCase(Locale.ROOT);
    if (!HTTP_SCHEME.equals(normalizedScheme) && !HTTPS_SCHEME.equals(normalizedScheme)) {
      return false;
    }
    if (!isSupportedLoopbackAdminHost(uri.getHost())) {
      return false;
    }
    return uri.getPort() > 0
        && uri.getRawUserInfo() == null
        && uri.getRawQuery() == null
        && uri.getRawFragment() == null;
  }

  private static boolean isSupportedLoopbackAdminHost(String host) {
    if (host == null) {
      return false;
    }
    String normalized = normalizedHost(host);
    return LOOPBACK_ADMIN_HOST.equals(normalized)
        || LOCALHOST_ADMIN_HOST.equals(normalized)
        || IPV6_LOOPBACK_ADMIN_HOST.equals(normalized)
        || EXPANDED_IPV6_LOOPBACK_ADMIN_HOST.equals(normalized);
  }

  private static String cspHostSource(String host) {
    String normalized = normalizedHost(host);
    return normalized.indexOf(':') >= 0 ? "[" + normalized + "]" : normalized;
  }

  private static String normalizedHost(String host) {
    String normalized = host.toLowerCase(Locale.ROOT);
    if (normalized.startsWith("[") && normalized.endsWith("]")) {
      return normalized.substring(1, normalized.length() - 1);
    }
    return normalized;
  }
}

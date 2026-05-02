package network.crypta.platform.appui;

import java.util.LinkedHashMap;
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
    LinkedHashMap<String, String> headers = LinkedHashMap.newLinkedHashMap(4);
    String frameAncestor = originSource(shellRoot);
    headers.put(
        "content-security-policy",
        contentSecurityPolicy(javascriptEnabled, originSource(platformApiRoot), frameAncestor));
    headers.put("x-content-type-options", "nosniff");
    headers.put("referrer-policy", "no-referrer");
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
    String scriptSource = javascriptEnabled ? SELF_SOURCE : "'none'";
    String connectSource =
        platformApiOrigin == null ? SELF_SOURCE : SELF_SOURCE + " " + platformApiOrigin;
    String frameAncestors = frameAncestor == null ? SELF_SOURCE : SELF_SOURCE + " " + frameAncestor;
    return "default-src "
        + SELF_SOURCE
        + "; script-src "
        + scriptSource
        + "; connect-src "
        + connectSource
        + "; base-uri 'none'; object-src 'none'; form-action "
        + SELF_SOURCE
        + "; frame-ancestors "
        + frameAncestors;
  }

  private static String originSource(String rootUrl) {
    if (rootUrl == null || rootUrl.startsWith("/")) {
      return null;
    }
    try {
      java.net.URI uri = java.net.URI.create(rootUrl);
      if (uri.getScheme() == null || uri.getHost() == null) {
        return null;
      }
      StringBuilder out = new StringBuilder();
      out.append(uri.getScheme().toLowerCase(java.util.Locale.ROOT));
      out.append("://");
      out.append(uri.getHost().toLowerCase(java.util.Locale.ROOT));
      if (uri.getPort() > 0) {
        out.append(':').append(uri.getPort());
      }
      return out.toString();
    } catch (IllegalArgumentException _) {
      return null;
    }
  }
}

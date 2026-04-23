package network.crypta.platform.appui;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Conservative response headers for app-owned static browser UI.
 *
 * <p>The headers keep static apps inside the same-origin local admin boundary while avoiding remote
 * scripts, object embedding, base tag rewrites, cross-origin form posts, referrer leakage, and MIME
 * sniffing. They are deliberately adapter-neutral: the app UI layer returns lowercase header names
 * and string values, and HTTP bridges convert them into their transport-specific header container.
 *
 * <p>This policy is not a sandbox and does not implement app permissions. It is a defensive default
 * for immutable installed-bundle UI assets until later platform phases add stronger isolation. When
 * the legacy admin surface has JavaScript disabled, the app UI CSP also disables script execution
 * so app-owned routes follow the same operator preference.
 */
public final class AppUiSecurityHeaders {
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
    LinkedHashMap<String, String> headers = LinkedHashMap.newLinkedHashMap(4);
    headers.put("content-security-policy", contentSecurityPolicy(javascriptEnabled));
    headers.put("x-content-type-options", "nosniff");
    headers.put("referrer-policy", "no-referrer");
    headers.put("x-frame-options", "SAMEORIGIN");
    return java.util.Collections.unmodifiableMap(headers);
  }

  private static String contentSecurityPolicy(boolean javascriptEnabled) {
    String scriptSource = javascriptEnabled ? "'self'" : "'none'";
    return "default-src 'self'; script-src "
        + scriptSource
        + "; base-uri 'none'; object-src 'none'; form-action 'self'; frame-ancestors 'self'";
  }
}

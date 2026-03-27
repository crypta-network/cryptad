package network.crypta.support.http;

import java.util.Objects;

/**
 * Shared constants and helpers for external-link confirmation URLs.
 *
 * <p>This utility centralizes the small amount of URL composition logic that used to live inside
 * the HTTP toadlet layer. Code in neutral packages such as content filters can use it without
 * depending on {@code network.crypta.clients.http}. The exported path constant is process-wide and
 * is derived from the {@code cryptad.http.externalLinkPath} system property when present. The
 * helper keeps the parameter name stable, so existing FProxy pages, filters, and tests continue to
 * produce the same confirmation links.
 *
 * <p>The class is stateless after initialization. Callers typically use {@link #escape(String)} for
 * the default path and only use {@link #escape(String, String)} when tests or compatibility layers
 * need to assemble the same query parameter against a caller-supplied path.
 */
public final class ExternalLinkSupport {

  private static final char PATH_SEPARATOR = '/';
  private static final String EXTERNAL_LINK_PATH_PROPERTY = "cryptad.http.externalLinkPath";
  private static final String DEFAULT_EXTERNAL_LINK_SEGMENT = "external-link";
  private static final String DEFAULT_EXTERNAL_LINK_PATH =
      PATH_SEPARATOR + DEFAULT_EXTERNAL_LINK_SEGMENT + PATH_SEPARATOR;

  /**
   * Public confirmation-path prefix used for external-link prompts.
   *
   * <p>The value is normalized to start and end with {@code /}. If the related system property is
   * absent, the default remains {@code /external-link/}.
   */
  public static final String EXTERNAL_LINK_PATH =
      normalizePath(System.getProperty(EXTERNAL_LINK_PATH_PROPERTY, DEFAULT_EXTERNAL_LINK_PATH));

  /**
   * Query parameter name that carries the original external URI as opaque text.
   *
   * <p>Downstream code treats the value as already encoded for transport and does not reinterpret
   * it as a structured Crypta URI.
   */
  public static final String MAGIC_HTTP_ESCAPE_STRING = "_CHECKED_HTTP_";

  private ExternalLinkSupport() {}

  /**
   * Builds an external-link confirmation URL using the configured default path.
   *
   * <p>The returned string is suitable for use in sanitized HTML output and matches the legacy
   * FProxy format. This method does not validate or encode the URI argument; callers are expected
   * to provide a string that is already safe for inclusion in a query parameter.
   *
   * @param uri original external URI text to place in the confirmation parameter.
   * @return Confirmation-link path and query string using {@link #EXTERNAL_LINK_PATH}.
   */
  public static String escape(String uri) {
    return escape(EXTERNAL_LINK_PATH, uri);
  }

  /**
   * Builds an external-link confirmation URL using a caller-supplied path prefix.
   *
   * <p>This overload exists primarily for compatibility shims and tests that need the same query
   * parameter format without relying on the process-wide default path. The method preserves the
   * supplied path verbatim and only appends the standard query parameter and value.
   *
   * @param externalLinkPath Path prefix that should receive the confirmation query parameter.
   * @param uri original external URI text to place in the confirmation parameter.
   * @return Confirmation-link path and query string using the supplied path.
   * @throws NullPointerException if {@code externalLinkPath} is {@code null}.
   */
  public static String escape(String externalLinkPath, String uri) {
    Objects.requireNonNull(externalLinkPath, "externalLinkPath");
    return externalLinkPath + "?" + MAGIC_HTTP_ESCAPE_STRING + '=' + uri;
  }

  private static String normalizePath(String path) {
    if (path == null || path.isEmpty()) {
      return Character.toString(PATH_SEPARATOR);
    }

    String normalized = path;
    if (normalized.charAt(0) != PATH_SEPARATOR) {
      normalized = PATH_SEPARATOR + normalized;
    }
    if (normalized.charAt(normalized.length() - 1) != PATH_SEPARATOR) {
      normalized = normalized + PATH_SEPARATOR;
    }
    return normalized;
  }
}

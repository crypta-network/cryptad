package network.crypta.clients.http;

import network.crypta.l10n.NodeL10n;

/**
 * Shared legacy HTTP content-filter helpers.
 *
 * <p>This helper centralizes the small amount of content-filter configuration that still belongs to
 * the legacy HTTP shell after the browse/admin split. Admin-owned flows such as {@link
 * FileInsertWizardToadlet} still need to construct form actions, stable enum names, and localized
 * labels that must match the browse-owned content-filter toadlet. Keeping those seams here lets the
 * admin module remain browse-independent while preserving the exact route and form conventions that
 * older pages and operator overrides already expect.
 *
 * <p>The class is intentionally process-wide and stateless after initialization. It reads the
 * historical system property once, normalizes the resulting route to the directory-style {@code
 * /segment/} form used by the legacy shell, and exposes only the small pieces of state that admin
 * pages must share with the browse module. Callers should treat the exported values as stable
 * constants for the lifetime of the JVM.
 *
 * <ul>
 *   <li>Owns the browse-neutral content-filter path alias used by admin forms.
 *   <li>Defines stable result-handling tokens that serialize into form fields.
 *   <li>Resolves the legacy localization keys without importing the browse toadlet class.
 * </ul>
 */
final class LegacyContentFilterSupport {
  /**
   * System property that overrides the legacy content-filter route when operators need a custom
   * path.
   */
  private static final String PATH_PROPERTY =
      "network.crypta.clients.http.ContentFilterToadlet.path";

  /** Historical terminal path segment used when no content-filter override is configured. */
  private static final String DEFAULT_PATH_SEGMENT = "filterfile";

  /**
   * Canonical path to the browse-owned content-filter endpoint.
   *
   * <p>The value is normalized once during class initialization, so admin callers can reuse it
   * directly in form actions without repeating slash handling. When the related system property is
   * blank or absent, the historical default remains {@code /filterfile/}.
   */
  static final String CONTENT_FILTER_PATH = resolvePath();

  /**
   * Stable result-handling tokens serialized by legacy HTTP forms.
   *
   * <p>The enum names are written into radio-button values and interpreted by the browse-owned
   * content-filter code. Keep them aligned with the existing form contract because bookmarked form
   * submissions and browser autofill may persist these literal values.
   */
  enum ResultHandling {
    /** Render the filtered result back through the browser instead of writing it to disk. */
    DISPLAY,

    /** Save the filtered result as a downloadable file instead of showing it inline. */
    SAVE
  }

  /** Prevents instantiation of this static helper holder. */
  private LegacyContentFilterSupport() {}

  /**
   * Looks up a content-filter localization string from the legacy node bundle.
   *
   * <p>The helper keeps the bundle prefix in one place, so admin callers can request labels such as
   * MIME-type prompts and result-handling captions without depending on the concrete browse toadlet
   * class. The method performs no fallback translation of its own; it relies on {@link NodeL10n} to
   * resolve the requested key.
   *
   * @param key suffix of the {@code ContentFilterToadlet.<key>} localization entry to resolve.
   * @return localized string associated with the requested content-filter UI label.
   */
  static String l10n(String key) {
    return NodeL10n.getBase().getString("ContentFilterToadlet." + key);
  }

  /**
   * Resolves the configured content-filter path and falls back to the historical default when
   * unset.
   *
   * <p>Blank overrides are treated the same as missing properties because older launch scripts and
   * tests may clear the value by setting it to whitespace rather than removing it entirely.
   *
   * @return normalized content-filter route in the slash-delimited form expected by legacy forms.
   */
  private static String resolvePath() {
    String configuredPath = System.getProperty(PATH_PROPERTY);
    if (configuredPath == null || configuredPath.isBlank()) {
      return normalizedPath(DEFAULT_PATH_SEGMENT);
    }
    return normalizedPath(configuredPath);
  }

  /**
   * Converts a path segment or override into the slash-delimited route form used by legacy HTTP.
   *
   * <p>The legacy shell treats these shared form targets as directory-like routes, so callers
   * expect both a leading slash and a trailing slash. This helper preserves compatibility with
   * older configuration values that may omit one or both separators.
   *
   * @param path a configured override or default segment that identifies the content-filter route.
   * @return equivalent path string that starts and ends with {@code /}.
   */
  private static String normalizedPath(String path) {
    String normalized = path;
    if (!normalized.startsWith("/")) {
      normalized = "/" + normalized;
    }
    if (!normalized.endsWith("/")) {
      normalized = normalized + "/";
    }
    return normalized;
  }
}

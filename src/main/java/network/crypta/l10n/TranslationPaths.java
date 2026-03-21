package network.crypta.l10n;

/**
 * Centralizes canonical translation-related UI paths shared across the localization stack.
 *
 * <p>Use this class when code outside the HTTP toadlet needs to build links, placeholders, or
 * diagnostics that point at the translation interface. Keeping the path in one location avoids
 * duplicating string literals between HTTP handlers, localization helpers, and tests, which helps
 * preserve link stability when the UI route changes.
 *
 * <p>The constants are intentionally narrow in scope: this is a route catalog, not a registry of
 * translation behavior or permissions. Callers still perform their own access checks and
 * query-parameter validation.
 *
 * @see network.crypta.clients.http.TranslationToadlet
 */
public final class TranslationPaths {
  /**
   * Canonical route for the translation toadlet, including the trailing slash expected by callers
   * that append query parameters directly.
   */
  public static final String TOADLET_URL = "/translation/";

  private TranslationPaths() {}
}

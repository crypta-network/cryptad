package network.crypta.clients.http;

/**
 * Neutralized legacy HTTP paths shared by the shell and admin-side HTTP toadlets.
 *
 * <p>This holder preserves the canonical legacy route prefixes in a shell-owned location so code
 * that stays outside the future browse leaf does not need to import {@link FProxyToadlet} merely to
 * reach stable path constants. The values still honor the historical system-property overrides,
 * which means operators and tests that customize the legacy shell paths keep the same behavior as
 * before this neutralization step.
 *
 * <p>Every exported path is normalized to the leading-slash and trailing-slash form expected by the
 * current registration code. That keeps callers from having to duplicate slash handling and reduces
 * the risk of menu links and route registrations drifting apart when overrides are set.
 */
final class LegacyHttpPaths {
  /** Historical default path for the legacy downloads page when no override is configured. */
  private static final String DEFAULT_DOWNLOADS_PATH = defaultPath("downloads");

  /** Historical default path for the legacy friends page when no override is configured. */
  private static final String DEFAULT_FRIENDS_PATH = defaultPath("friends");

  /**
   * Historical default path for the legacy configuration subtree when no override is configured.
   */
  private static final String DEFAULT_CONFIG_PATH = defaultPath("config");

  /** Historical default path for the legacy welcome page when no override is configured. */
  private static final String DEFAULT_WELCOME_PATH = defaultPath("welcome");

  /** Canonical downloads route prefix used by queue and shell-facing legacy HTTP code. */
  static final String DOWNLOADS_PATH =
      normalizedPath(System.getProperty("crypta.fproxy.downloadsPath", DEFAULT_DOWNLOADS_PATH));

  /** Canonical friends route prefix used by connectivity and shell-facing legacy HTTP code. */
  static final String FRIENDS_PATH =
      normalizedPath(System.getProperty("crypta.fproxy.friendsPath", DEFAULT_FRIENDS_PATH));

  /** Canonical configuration route prefix used by config and shell-facing legacy HTTP code. */
  static final String CONFIG_PATH =
      normalizedPath(System.getProperty("crypta.fproxy.configPath", DEFAULT_CONFIG_PATH));

  /** Canonical welcome route prefix used by legacy startup and redirect handling. */
  static final String WELCOME_PATH =
      normalizedPath(System.getProperty("crypta.fproxy.welcomePath", DEFAULT_WELCOME_PATH));

  /** Prevents instantiation of this constants' holder. */
  private LegacyHttpPaths() {}

  /**
   * Builds the historical default route shape for a single legacy path segment.
   *
   * @param segment terminal path segment that identifies the legacy route without surrounding
   *     slashes
   * @return normalized default route using the {@code /segment/} form expected by legacy callers
   */
  private static String defaultPath(String segment) {
    return "/" + segment + "/";
  }

  /**
   * Normalizes configured path overrides to the slash-delimited form expected by route
   * registration.
   *
   * <p>The legacy HTTP shell historically treats these shared route prefixes as directory-like
   * paths. This helper therefore adds a leading slash and trailing slash when callers omit either
   * edge, preserving compatibility with older system-property values and tests.
   *
   * @param path configured path override or default path candidate supplied by the caller
   * @return equivalent path string with both a leading slash and a trailing slash
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

package network.crypta.runtime.updater;

/**
 * Centralizes canonical URL path fragments used by the core updater web surface.
 *
 * <p>This utility class provides shared path constants for updater routes, UI links, and related
 * endpoint registration code. Keeping the fragments in one place prevents drift between callers
 * that publish updater links and handlers that consume those requests. The exported values are
 * immutable and initialized once, so they are inherently thread-safe and safe to reuse from any
 * execution context without additional synchronization.
 *
 * <p>Callers should treat these constants as normalized fragments, including required separators,
 * and compose concrete updater URLs from them instead of duplicating raw string literals.
 */
public final class UpdaterPaths {
  private static final char URL_PATH_SEPARATOR = '/';
  private static final String URL_PATH_SEPARATOR_STR = String.valueOf(URL_PATH_SEPARATOR);
  private static final String CORE_UPDATE_SEGMENT = "core-update";

  /**
   * Base path for core updater resources, including both leading and trailing {@code /} separators.
   *
   * <p>Use this normalized value when building updater links or registering updater handlers so all
   * components reference the same updater root path.
   */
  public static final String CORE_UPDATE_PATH =
      URL_PATH_SEPARATOR_STR + CORE_UPDATE_SEGMENT + URL_PATH_SEPARATOR_STR;

  private UpdaterPaths() {}
}

package network.crypta.support.http;

/**
 * Shared mutable size limits used by the HTTP and FProxy fetch path.
 *
 * <p>These values are intentionally process-wide because several legacy entry points read or write
 * the same limits during startup, configuration import, and request handling. Moving the mutable
 * state into a neutral support class lets callers in {@code client} and {@code clients.http} share
 * the same values without taking a direct dependency on the HTTP toadlet implementation classes.
 *
 * <p>The units are bytes. Callers are expected to provide already validated sizes that match the
 * surrounding configuration rules.
 */
public final class HttpFetchSizeLimits {

  private static long maxLengthWithProgress = (100 * 1024 * 1024) * 11 / 10;
  private static long maxLengthNoProgress = (2 * 1024 * 1024) * 11 / 10;

  private HttpFetchSizeLimits() {}

  /**
   * Returns the fetch size limit used when progress tracking is not available.
   *
   * <p>This value is typically applied to simple background fetches where the caller cannot present
   * incremental progress to the user.
   *
   * @return Maximum allowed fetch size in bytes for no-progress fetches.
   */
  public static long getMaxLengthNoProgress() {
    return maxLengthNoProgress;
  }

  /**
   * Updates the fetch size limit used when progress tracking is not available.
   *
   * <p>The new value becomes visible to all callers immediately because the backing state is
   * process-wide.
   *
   * @param length Maximum allowed fetch size in bytes for no-progress fetches.
   */
  public static void setMaxLengthNoProgress(long length) {
    maxLengthNoProgress = length;
  }

  /**
   * Returns the fetch size limit used when progress tracking is available.
   *
   * <p>This larger limit is typically applied to interactive fetches where FProxy can surface
   * progress updates to the user.
   *
   * @return Maximum allowed fetch size in bytes for progress-aware fetches.
   */
  public static long getMaxLengthWithProgress() {
    return maxLengthWithProgress;
  }

  /**
   * Updates the fetch size limit used when progress tracking is available.
   *
   * <p>The caller is responsible for ensuring that the supplied value is meaningful for the active
   * node configuration.
   *
   * @param length Maximum allowed fetch size in bytes for progress-aware fetches.
   */
  public static void setMaxLengthWithProgress(long length) {
    maxLengthWithProgress = length;
  }
}

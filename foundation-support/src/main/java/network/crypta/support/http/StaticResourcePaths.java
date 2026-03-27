package network.crypta.support.http;

/**
 * Shared URL prefixes for HTTP-served static resources.
 *
 * <p>This class holds the small set of path constants that are stable across callers outside the
 * HTTP package. Keeping them here avoids unnecessary dependencies on a specific toadlet class while
 * preserving the exact URL layout used by existing FProxy pages.
 */
public final class StaticResourcePaths {

  /**
   * Root URL prefix for static HTTP assets served by FProxy.
   *
   * <p>Callers append asset-relative paths such as JavaScript or CSS resources beneath this prefix.
   */
  public static final String ROOT_URL = "/static/";

  private StaticResourcePaths() {}
}

package network.crypta.platform.appui;

import java.io.IOException;
import java.util.Objects;
import java.util.Optional;
import network.crypta.platform.appdist.AppUiMode;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.InstalledAppSnapshot;

/**
 * Resolves dynamic bootstrap metadata for installed static app UI routes.
 *
 * <p>This service is the app UI layer's dynamic counterpart to {@link AppStaticAssetService}. It
 * parses the same raw {@code /apps/{appId}/...} route shape, asks AppHost for the current installed
 * snapshot, and filters out apps whose manifests do not declare {@code app.ui.mode=static}. Unlike
 * static asset resolution, it never opens files from an installed bundle. The only accepted asset
 * path is the host-owned bootstrap route, so bundle contents cannot shadow or replace the generated
 * metadata.
 *
 * <p>The service has no mutable request state and does not cache installed app snapshots. Each
 * request reflects the AppHost state at lookup time, which lets installs, updates, and removals
 * change bootstrap behavior without rebuilding HTTP route registrations. Missing apps, non-static
 * apps, and ordinary asset paths return {@link Optional#empty()} so adapters can use the same
 * not-found response policy as static asset misses.
 *
 * @see AppUiBootstrap
 * @see AppUiRoute
 */
public final class AppUiBootstrapService {
  private final AppHost appHost;

  /**
   * Creates a bootstrap resolver backed by one AppHost instance.
   *
   * <p>The supplied host remains the source of truth for installed manifests. The service stores
   * only the reference and performs per-request lookups, so callers can keep a single resolver
   * instance mounted in an HTTP adapter while app installation state changes underneath it.
   *
   * @param appHost AppHost used to describe installed applications and their manifests
   * @throws NullPointerException if {@code appHost} is {@code null}
   */
  public AppUiBootstrapService(AppHost appHost) {
    this.appHost = Objects.requireNonNull(appHost, "appHost");
  }

  /**
   * Resolves one raw HTTP path to app UI bootstrap metadata when it names the reserved resource.
   *
   * <p>The input must be the raw URI path rather than a decoded framework path. {@link AppUiRoute}
   * rejects malformed percent escapes, traversal segments, and other unsafe asset syntax before the
   * AppHost is queried. When the route is valid but does not name the reserved bootstrap resource,
   * the method returns empty and leaves ordinary asset handling to {@link AppStaticAssetService}.
   *
   * <p>The caller supplies host-level route roots and the current form password because those
   * values come from the serving HTTP context. This method only combines them with manifest-derived
   * app metadata after verifying that the app is installed and static.
   *
   * @param rawRequestPath raw URI path such as {@code
   *     /apps/demo-app/.well-known/cryptad-bootstrap.json}
   * @param platformApiRoot absolute local Platform API root to expose to browser code
   * @param shellRoot absolute local Web Shell root to expose for fallback navigation
   * @param formPassword current local-admin mutation token, or {@code null}
   * @return bootstrap metadata, or empty when the path is not the bootstrap resource or the app is
   *     not an installed static UI app
   * @throws IOException if AppHost metadata cannot be read for the requested app id
   * @throws AppStaticAssetException if the raw app UI route path is malformed or unsafe
   */
  public Optional<AppUiBootstrap> resolve(
      String rawRequestPath, String platformApiRoot, String shellRoot, String formPassword)
      throws IOException, AppStaticAssetException {
    AppUiRoute route = AppUiRoute.parse(rawRequestPath);
    if (!AppUiBootstrap.isBootstrapAssetPath(route.assetPath())) {
      return Optional.empty();
    }
    Optional<InstalledAppSnapshot> snapshot = appHost.describe(route.appId());
    if (snapshot.isEmpty() || snapshot.get().manifest().uiMode() != AppUiMode.STATIC) {
      return Optional.empty();
    }
    return Optional.of(
        AppUiBootstrap.forManifest(
            snapshot.get().manifest(), platformApiRoot, shellRoot, formPassword));
  }

  /**
   * Returns whether one raw request path names the reserved bootstrap route.
   *
   * <p>HTTP adapters use this as an early dispatch check before static asset resolution. It applies
   * the same raw-path parsing as {@link #resolve(String, String, String, String)}, which means a
   * syntactically unsafe bootstrap-looking URL fails as a bad app UI route instead of falling
   * through to filesystem lookup.
   *
   * @param rawRequestPath raw URI path to inspect before filesystem resolution
   * @return {@code true} when the path is exactly the app UI bootstrap JSON resource
   * @throws AppStaticAssetException if the raw app UI route path is malformed or unsafe
   */
  public static boolean isBootstrapRequest(String rawRequestPath) throws AppStaticAssetException {
    AppUiRoute route = AppUiRoute.parse(rawRequestPath);
    return AppUiBootstrap.isBootstrapAssetPath(route.assetPath());
  }
}

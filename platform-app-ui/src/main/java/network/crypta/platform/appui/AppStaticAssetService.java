package network.crypta.platform.appui;

import java.io.IOException;
import java.util.Objects;
import java.util.Optional;
import network.crypta.platform.appdist.AppUiMode;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.InstalledAppSnapshot;

/**
 * AppHost-backed service for resolving app-owned static UI requests.
 *
 * <p>The service maps browser routes beneath {@code /apps/{appId}/} onto immutable installed bundle
 * files. It is the layer that combines route parsing, installed-app lookup, manifest UI mode
 * filtering, nested-entry URL policy, and filesystem resolution. HTTP adapters should call {@link
 * #canonicalRootRedirect(String)} first, then {@link #resolve(String)} when no redirect is needed.
 *
 * <p>Nested static entries are intentionally opened at their entry directory instead of always at
 * the virtual app root. That keeps normal browser relative URL resolution working for
 * same-directory assets and parent-directory assets. Requests to the published entry directory
 * resolve to the declared entry file; ordinary asset requests prefer the literal bundle-relative
 * path and only fall back to an app-root compatibility alias under the entry directory when the
 * literal path is absent.
 *
 * <p>Missing apps, non-static apps, missing files, and directories resolve as {@link
 * Optional#empty()}. Malformed or unsafe paths raise {@link AppStaticAssetException} so adapters
 * can return client errors without leaking local filesystem details.
 */
public final class AppStaticAssetService {
  private final AppHost appHost;
  private final AppStaticAssetResolver resolver;

  /**
   * Creates a service backed by one AppHost instance.
   *
   * <p>The service does not cache installed app snapshots. Each request asks the AppHost for the
   * current manifest and installed paths, which lets app installs, updates, and removals take
   * effect without rebuilding the service or HTTP route table.
   *
   * @param appHost AppHost used to describe installed apps and their bundle roots
   */
  public AppStaticAssetService(AppHost appHost) {
    this(appHost, new AppStaticAssetResolver());
  }

  /**
   * Creates a service with an explicit filesystem resolver.
   *
   * <p>This constructor is package scoped for deterministic tests that need to supply a resolver
   * with controlled behavior. Production callers use {@link #AppStaticAssetService(AppHost)} so the
   * default resolver enforces the platform filesystem checks.
   *
   * @param appHost AppHost used to describe installed apps and their bundle roots
   * @param resolver resolver used to validate and describe installed bundle files
   */
  AppStaticAssetService(AppHost appHost, AppStaticAssetResolver resolver) {
    this.appHost = Objects.requireNonNull(appHost, "appHost");
    this.resolver = Objects.requireNonNull(resolver, "resolver");
  }

  /**
   * Resolves one raw HTTP request path to an installed static asset.
   *
   * <p>The input must be the raw URI path, not a decoded servlet path, because encoded separators
   * and encoded traversal must be rejected before any filesystem path is built. The method serves
   * only apps whose installed manifest declares {@link AppUiMode#STATIC}. Shell-panel and no-UI
   * apps return empty so callers can respond with the same not-found behavior used for missing
   * apps.
   *
   * @param rawRequestPath raw URI path such as {@code /apps/demo-app/static/app.js}
   * @return resolved asset metadata, or empty when no static app asset should be served
   * @throws IOException if AppHost or filesystem metadata cannot be read safely
   * @throws AppStaticAssetException if the route is malformed or unsafe
   */
  public Optional<AppStaticAsset> resolve(String rawRequestPath)
      throws IOException, AppStaticAssetException {
    AppUiRoute route = AppUiRoute.parse(rawRequestPath);
    Optional<InstalledAppSnapshot> snapshot = appHost.describe(route.appId());
    if (snapshot.isEmpty()) {
      return Optional.empty();
    }
    InstalledAppSnapshot installed = snapshot.get();
    if (installed.manifest().uiMode() != AppUiMode.STATIC) {
      return Optional.empty();
    }
    if (route.assetPath() == null) {
      return resolver.resolve(installed.paths().installedRoot(), installed.manifest().uiEntry());
    }
    if (isEntryDirectoryRequest(
        rawRequestPath, route.assetPath(), installed.manifest().uiEntry())) {
      return resolver.resolve(installed.paths().installedRoot(), installed.manifest().uiEntry());
    }
    return resolveAssetRoute(installed, route.assetPath());
  }

  /**
   * Returns the canonical nested entry-directory URL for an app-root request when needed.
   *
   * <p>When a static app declares {@code app.ui.entry=static/index.html}, opening {@code
   * /apps/{appId}/} would make the browser resolve {@code ./app.js} and {@code ../shared.js} from
   * the virtual app root. Returning {@code /apps/{appId}/static/} preserves the declared entry
   * directory as the browser base URL. Root-level entries such as {@code index.html}, missing apps,
   * and non-static apps do not need a redirect and return empty.
   *
   * @param rawRequestPath raw URI path such as {@code /apps/demo-app/}
   * @return redirect target, or empty when the request should resolve normally
   * @throws IOException if AppHost metadata cannot be read
   * @throws AppStaticAssetException if the route is malformed or unsafe
   */
  public Optional<String> canonicalRootRedirect(String rawRequestPath)
      throws IOException, AppStaticAssetException {
    AppUiRoute route = AppUiRoute.parse(rawRequestPath);
    if (route.assetPath() != null) {
      return Optional.empty();
    }
    Optional<InstalledAppSnapshot> snapshot = appHost.describe(route.appId());
    if (snapshot.isEmpty() || snapshot.get().manifest().uiMode() != AppUiMode.STATIC) {
      return Optional.empty();
    }
    String canonicalUrl = AppUiPaths.uiUrl(snapshot.get().manifest());
    if (canonicalUrl == null || canonicalUrl.equals(AppUiPaths.appRoot(route.appId()))) {
      return Optional.empty();
    }
    return Optional.of(canonicalUrl);
  }

  private Optional<AppStaticAsset> resolveAssetRoute(
      InstalledAppSnapshot installed, String routeAssetPath)
      throws IOException, AppStaticAssetException {
    String entryDirectory = entryDirectory(installed.manifest().uiEntry());
    if (entryDirectory.isEmpty()
        || routeAssetPath.equals(entryDirectory)
        || routeAssetPath.startsWith(entryDirectory + "/")) {
      return resolver.resolve(installed.paths().installedRoot(), routeAssetPath);
    }

    Optional<AppStaticAsset> bundleRelativeAsset =
        resolver.resolve(installed.paths().installedRoot(), routeAssetPath);
    if (bundleRelativeAsset.isPresent()) {
      return bundleRelativeAsset;
    }
    return resolver.resolve(
        installed.paths().installedRoot(), entryDirectory + "/" + routeAssetPath);
  }

  private static String entryDirectory(String uiEntry) {
    int lastSlash = uiEntry.lastIndexOf('/');
    return lastSlash < 0 ? "" : uiEntry.substring(0, lastSlash);
  }

  private static boolean isEntryDirectoryRequest(
      String rawRequestPath, String routeAssetPath, String uiEntry) {
    return rawRequestPath.endsWith("/")
        && !routeAssetPath.isEmpty()
        && routeAssetPath.equals(entryDirectory(uiEntry));
  }
}

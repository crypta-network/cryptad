package network.crypta.platform.appui;

import java.util.Objects;
import network.crypta.platform.appdist.AppUiMode;
import network.crypta.platform.apphost.manifest.AppManifest;

/**
 * Browser URL assignment for one installed app UI.
 *
 * <p>A binding is the transport-neutral summary shared by bootstrap JSON, app summaries, Web Shell
 * launch links, and Platform API CORS decisions. It contains only browser-visible route metadata.
 * It never contains AppHost launch tokens, browser-session tokens, filesystem paths, or local admin
 * form passwords.
 *
 * <p>Bindings describe the route that should be used now, not a permanent installation property.
 * Static apps normally receive an active isolated-loopback binding with an absolute UI URL on a
 * per-app port. First-party compatibility paths and degraded environments can receive a same-origin
 * fallback binding instead. API handlers and Web Shell should prefer {@link #uiUrl()} when {@link
 * #isolatedAndActive()} is true, while still showing {@link #sameOriginFallbackUrl()} for
 * diagnostics and explicit compatibility flows.
 *
 * @param appId normalized app identifier that owns this browser UI assignment
 * @param mode origin-isolation mode used for this UI route
 * @param status runtime status for this assignment at the time it was produced
 * @param origin serialized app browser origin, or {@code null} for same-origin fallback
 * @param uiRoot root URL for the app UI, ending in {@code /}
 * @param assetRoot URL directory where the declared static entry and sibling assets resolve
 * @param uiUrl public app entry URL for the app entry directory; isolated launch redirects may add
 *     request-specific proof before opening this URL in a browser
 * @param platformApiRoot Platform API v1 root exposed to app browser code
 * @param shellRoot Web Shell/admin UI root exposed for fallback navigation
 * @param sameOriginFallbackUrl legacy same-origin launch path under {@code /apps/{appId}/}
 * @param warning optional operator-facing reason when isolation is unavailable or degraded
 */
public record AppUiOriginBinding(
    String appId,
    AppUiOriginMode mode,
    AppUiOriginStatus status,
    String origin,
    String uiRoot,
    String assetRoot,
    String uiUrl,
    String platformApiRoot,
    String shellRoot,
    String sameOriginFallbackUrl,
    String warning) {
  /**
   * Builds an active isolated-loopback binding for one static app manifest.
   *
   * <p>The static entry directory becomes both {@code assetRoot} and {@code uiUrl}, so an app whose
   * entry is {@code static/index.html} opens at {@code /static/} on its isolated origin. Bootstrap
   * code and sibling assets can then use origin-root or directory-relative paths without exposing
   * the legacy admin {@code /apps/{appId}/} mount as the preferred route.
   *
   * @param manifest installed static app manifest that declares the UI entry point
   * @param origin per-app loopback origin allocated by the HTTP adapter
   * @param platformApiRoot absolute admin-origin Platform API root for browser SDK calls
   * @param shellRoot absolute admin-origin Web Shell root for fallback navigation
   * @return active isolated-loopback binding safe to expose in app summaries
   */
  public static AppUiOriginBinding isolatedLoopback(
      AppManifest manifest, AppUiOrigin origin, String platformApiRoot, String shellRoot) {
    Objects.requireNonNull(manifest, "manifest");
    Objects.requireNonNull(origin, "origin");
    String root = origin.rootUrl();
    String entryDirectory = staticEntryDirectory(manifest);
    String uiUrl =
        entryDirectory.isEmpty()
            ? root
            : root + AppUiPaths.encodeRelativePath(entryDirectory) + "/";
    return new AppUiOriginBinding(
        manifest.appId(),
        AppUiOriginMode.ISOLATED_LOOPBACK,
        AppUiOriginStatus.ACTIVE,
        origin.origin(),
        root,
        uiUrl,
        uiUrl,
        platformApiRoot,
        shellRoot,
        AppUiPaths.appRoot(manifest.appId()),
        null);
  }

  /**
   * Builds the legacy same-origin fallback binding for one manifest.
   *
   * <p>Fallback bindings preserve Phase 5 app UI behavior for diagnostics and environments where an
   * isolated listener cannot be started. They should not be treated as the preferred third-party UI
   * route when an active isolated binding is available.
   *
   * @param manifest installed app manifest used to derive legacy app UI paths
   * @param platformApiRoot Platform API root to expose, usually path-only on the admin origin
   * @param shellRoot Web Shell root to expose, usually path-only on the admin origin
   * @param expectedOrigin serialized admin origin when known, otherwise {@code null}
   * @param warning optional warning or reason shown to operators and diagnostics
   * @return same-origin fallback binding with legacy UI URLs preserved
   */
  public static AppUiOriginBinding sameOriginFallback(
      AppManifest manifest,
      String platformApiRoot,
      String shellRoot,
      String expectedOrigin,
      String warning) {
    Objects.requireNonNull(manifest, "manifest");
    String uiUrl = AppUiPaths.uiUrl(manifest);
    return new AppUiOriginBinding(
        manifest.appId(),
        AppUiOriginMode.SAME_ORIGIN_FALLBACK,
        AppUiOriginStatus.FALLBACK,
        expectedOrigin,
        manifest.uiMode() == AppUiMode.STATIC ? AppUiPaths.appRoot(manifest.appId()) : uiUrl,
        uiUrl,
        uiUrl,
        platformApiRoot,
        shellRoot,
        manifest.uiMode() == AppUiMode.STATIC ? AppUiPaths.appRoot(manifest.appId()) : uiUrl,
        warning);
  }

  /**
   * Builds a binding that reports unavailable browser UI.
   *
   * <p>Unsupported bindings are useful for process-only apps or invalid app records that still need
   * a stable summary shape. All browser-openable URL fields are {@code null}; callers must not
   * synthesize launch routes from this value.
   *
   * @param appId normalized app identifier whose browser UI cannot be opened
   * @param warning reason for the unavailable UI, suitable for diagnostics
   * @return unsupported binding with no browser-openable URL
   */
  public static AppUiOriginBinding unsupported(String appId, String warning) {
    return new AppUiOriginBinding(
        appId,
        AppUiOriginMode.SAME_ORIGIN_FALLBACK,
        AppUiOriginStatus.UNSUPPORTED,
        null,
        null,
        null,
        null,
        null,
        null,
        null,
        warning);
  }

  /**
   * Creates a validated origin binding.
   *
   * <p>The canonical constructor normalizes the app id and requires the mode and status enum
   * values. It intentionally leaves URL cross-field validation to the factories because fallback
   * and unsupported bindings have different nullable fields than active isolated bindings.
   *
   * @throws NullPointerException if required identity or status fields are missing
   * @throws IllegalArgumentException if required app identity is invalid
   */
  public AppUiOriginBinding {
    appId =
        network.crypta.platform.apphost.manifest.AppManifest.normalizeAppId(
            Objects.requireNonNull(appId, "appId"));
    Objects.requireNonNull(mode, "mode");
    Objects.requireNonNull(status, "status");
  }

  /**
   * Returns whether this binding describes an active isolated app origin.
   *
   * <p>Callers use this as the main branch for Web Shell launch behavior and for deciding whether
   * cross-origin CORS checks should expect an app-specific loopback origin.
   *
   * @return {@code true} when the app should be opened on its isolated loopback origin
   */
  public boolean isolatedAndActive() {
    return mode == AppUiOriginMode.ISOLATED_LOOPBACK && status == AppUiOriginStatus.ACTIVE;
  }

  private static String staticEntryDirectory(AppManifest manifest) {
    if (manifest.uiMode() != AppUiMode.STATIC || manifest.uiEntry() == null) {
      return "";
    }
    int lastSlash = manifest.uiEntry().lastIndexOf('/');
    return lastSlash < 0 ? "" : manifest.uiEntry().substring(0, lastSlash);
  }
}

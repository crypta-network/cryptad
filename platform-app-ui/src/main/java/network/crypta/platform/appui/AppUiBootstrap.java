package network.crypta.platform.appui;

import java.net.URI;
import java.util.Objects;
import network.crypta.platform.apphost.manifest.AppManifest;

/**
 * Browser bootstrap metadata for an installed static app UI.
 *
 * <p>This record is the small contract served from the reserved app-owned bootstrap route. A
 * browser page uses it to discover the same-origin roots that are stable for the current node:
 * where the app UI is mounted, where static sibling assets should resolve, where Platform API v1 is
 * mounted, and where the Web Shell lives for fallback navigation. The payload is deliberately
 * route-oriented rather than runtime-oriented. It describes local browser entry points, not the
 * AppHost process launch environment.
 *
 * <p>The payload is host/operator scoped. It may carry the existing local-admin form password so a
 * first-party static UI can submit the same mutation requests as other same-origin admin pages. It
 * must not carry AppHost launch tokens, app process credentials, trusted signing material, or
 * installed bundle filesystem paths. Instances are immutable after construction except for the
 * compact constructor's normalization of blank form passwords to {@code null}.
 *
 * @param appId normalized application identifier from the installed manifest
 * @param name human-readable application name shown in browser-owned UI chrome
 * @param uiRoot canonical app-owned route root ending in {@code /}
 * @param assetRoot canonical directory URL for the static entry and sibling assets
 * @param platformApiRoot Platform API v1 root ending in {@code /}
 * @param shellRoot Web Shell root ending in {@code /}
 * @param formPassword legacy local-admin mutation token, or {@code null} for read-only contexts
 * @see AppUiBootstrapService
 * @see AppUiPaths
 */
public record AppUiBootstrap(
    String appId,
    String name,
    String uiRoot,
    String assetRoot,
    String platformApiRoot,
    String shellRoot,
    String formPassword) {
  /**
   * Reserved bundle-relative route used for dynamic app UI bootstrap JSON.
   *
   * <p>The path lives under {@code .well-known} so ordinary static assets do not need a special
   * naming convention. It is intentionally treated as dynamic metadata by the HTTP adapter before
   * bundle asset lookup. App bundles should not rely on placing a file at this path, because the
   * route is owned by the host and has security-sensitive response behavior such as {@code
   * cache-control: no-store}.
   */
  public static final String BOOTSTRAP_ASSET_PATH = ".well-known/cryptad-bootstrap.json";

  /**
   * Creates bootstrap metadata for one installed static app manifest.
   *
   * <p>The factory derives app-specific browser routes from the same manifest fields used by app
   * summaries and static asset resolution. That keeps links published through Platform API, the Web
   * Shell, and the app UI bootstrap aligned. The caller supplies host-level roots and the current
   * form password because those values come from the serving HTTP context, not from the installed
   * bundle.
   *
   * @param manifest installed app manifest currently being served
   * @param platformApiRoot absolute local Platform API root ending in {@code /}
   * @param shellRoot absolute local Web Shell root ending in {@code /}
   * @param formPassword current local-admin mutation token, or {@code null}
   * @return immutable bootstrap metadata ready for deterministic JSON serialization
   * @throws NullPointerException if {@code manifest} or any required route root is {@code null}
   * @throws IllegalArgumentException if a derived or supplied route root is not valid
   */
  public static AppUiBootstrap forManifest(
      AppManifest manifest, String platformApiRoot, String shellRoot, String formPassword) {
    Objects.requireNonNull(manifest, "manifest");
    return new AppUiBootstrap(
        manifest.appId(),
        manifest.appName(),
        AppUiPaths.appRoot(manifest.appId()),
        AppUiPaths.uiUrl(manifest),
        platformApiRoot,
        shellRoot,
        formPassword);
  }

  /**
   * Returns whether one parsed app UI asset path names the reserved bootstrap resource.
   *
   * <p>The method expects a normalized bundle-relative path from {@link AppUiRoute}; it does not
   * parse raw HTTP paths and does not perform AppHost lookup. Passing {@code null}, which
   * represents the app root, safely returns {@code false}. Callers use this check before filesystem
   * resolution so the reserved route cannot be shadowed by bundle contents.
   *
   * @param assetPath parsed bundle-relative route path, or {@code null} for an app root request
   * @return {@code true} only when the path is the dynamic bootstrap JSON resource
   */
  public static boolean isBootstrapAssetPath(String assetPath) {
    return BOOTSTRAP_ASSET_PATH.equals(assetPath);
  }

  /**
   * Creates an immutable bootstrap payload.
   *
   * <p>Required text fields must be non-blank. Route roots must be same-origin absolute paths that
   * begin with a single {@code /}, contain no query or fragment, and end with {@code /}. The
   * constructor accepts a blank form password but normalizes it to {@code null}; that prevents
   * browser code from treating whitespace as a usable mutation credential.
   *
   * @throws NullPointerException if any required field is {@code null}
   * @throws IllegalArgumentException if a required text field is blank or a route root is invalid
   */
  public AppUiBootstrap {
    requireText(appId, "appId");
    requireText(name, "name");
    requireRootPath(uiRoot, "uiRoot");
    requireRootPath(assetRoot, "assetRoot");
    requireRootPath(platformApiRoot, "platformApiRoot");
    requireRootPath(shellRoot, "shellRoot");
    if (formPassword != null && formPassword.isBlank()) {
      formPassword = null;
    }
  }

  private static String requireText(String value, String label) {
    Objects.requireNonNull(value, label);
    if (value.isBlank()) {
      throw new IllegalArgumentException(label + " must not be blank");
    }
    return value;
  }

  private static void requireRootPath(String value, String label) {
    String path = requireText(value, label);
    requireSingleLeadingSlash(path, label);
    requireUriPathOnly(path, label);
    if (!path.endsWith("/")) {
      throw new IllegalArgumentException(label + " must end with '/'");
    }
  }

  private static void requireSingleLeadingSlash(String path, String label) {
    if (path.charAt(0) != '/' || path.startsWith("//")) {
      throw new IllegalArgumentException(label + " must start with a single leading '/'");
    }
  }

  private static void requireUriPathOnly(String path, String label) {
    try {
      URI uri = URI.create("http://localhost" + path);
      if (!path.equals(uri.getRawPath())
          || uri.getRawQuery() != null
          || uri.getRawFragment() != null) {
        throw new IllegalArgumentException(label + " must be a valid absolute root path");
      }
    } catch (IllegalArgumentException exception) {
      throw new IllegalArgumentException(label + " must be a valid absolute root path", exception);
    }
  }
}

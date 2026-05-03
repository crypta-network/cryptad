package network.crypta.platform.appui;

import java.net.URI;
import java.time.Instant;
import java.util.Objects;
import network.crypta.platform.apphost.manifest.AppManifest;
import org.jetbrains.annotations.NotNull;

/**
 * Browser bootstrap metadata for an installed static app UI.
 *
 * <p>This record is the small contract served from the reserved app-owned bootstrap route. A
 * browser page uses it to discover the local roots that are stable for the current node: where the
 * app UI is mounted, where static sibling assets should resolve, where Platform API v1 is mounted,
 * and where the Web Shell lives for fallback navigation. The payload is deliberately route-oriented
 * rather than runtime-oriented. It describes local browser entry points, not the AppHost process
 * launch environment.
 *
 * <p>The payload carries a browser-scoped app session token for Platform API calls from the static
 * app UI. The token is distinct from AppHost launch tokens and local-admin form passwords. It must
 * not carry AppHost launch tokens, app process credentials, trusted signing material, or installed
 * bundle filesystem paths. The diagnostic string redacts the browser session token.
 *
 * @param appId normalized application identifier from the installed manifest
 * @param name human-readable application name shown in browser-owned UI chrome
 * @param uiRoot canonical app-owned route root ending in {@code /}
 * @param assetRoot canonical directory URL for the static entry and sibling assets
 * @param platformApiRoot Platform API v1 root ending in {@code /}
 * @param shellRoot Web Shell root ending in {@code /}
 * @param uiOrigin serialized browser origin expected for this app UI session, or {@code null} for
 *     legacy path-only fallback bootstrap
 * @param uiOriginMode origin-isolation mode used for this bootstrap
 * @param uiOriginStatus runtime status of the UI origin binding
 * @param sameOriginFallbackUrl legacy {@code /apps/{appId}/} launch URL retained for compatibility
 * @param browserSessionToken opaque app browser session token for {@code X-Crypta-App-Session}
 * @param browserSessionExpiresAt UTC timestamp after which the browser session must be refreshed
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
    String uiOrigin,
    String uiOriginMode,
    String uiOriginStatus,
    String sameOriginFallbackUrl,
    String browserSessionToken,
    Instant browserSessionExpiresAt) {
  private static final String IPV4_LOOPBACK_HOST = "127.0.0.1";
  private static final String IPV6_LOOPBACK_HOST = "::1";
  private static final String IPV6_LOOPBACK_HOST_EXPANDED = "0:0:0:0:0:0:0:1";
  private static final String LOCALHOST_HOST = "localhost";

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
   * Shell, and the app UI bootstrap aligned. The caller supplies host-level roots and an already
   * issued browser session because those values come from the serving HTTP context, not from the
   * installed bundle.
   *
   * @param manifest installed app manifest currently being served
   * @param platformApiRoot absolute local Platform API root ending in {@code /}
   * @param shellRoot absolute local Web Shell root ending in {@code /}
   * @param browserSession issued app browser session metadata
   * @return immutable bootstrap metadata ready for deterministic JSON serialization
   * @throws NullPointerException if {@code manifest} or any required route root is {@code null}
   * @throws IllegalArgumentException if a derived or supplied route root is not valid
   */
  public static AppUiBootstrap forManifest(
      AppManifest manifest,
      String platformApiRoot,
      String shellRoot,
      AppBrowserSessionIssue browserSession) {
    return forManifest(manifest, platformApiRoot, shellRoot, browserSession, null);
  }

  /**
   * Creates bootstrap metadata for one installed static app manifest and origin binding.
   *
   * <p>When an isolated loopback binding is present, URL roots in the returned payload use absolute
   * loopback/admin URLs so app JavaScript can load bootstrap from its own origin and call Platform
   * API through restricted CORS. Without a binding, the method preserves the legacy path-only
   * same-origin bootstrap contract.
   *
   * @param manifest installed app manifest currently being served
   * @param platformApiRoot default Platform API root used when {@code binding} is absent
   * @param shellRoot default Web Shell root used when {@code binding} is absent
   * @param browserSession issued app browser session metadata
   * @param binding app UI origin binding, or {@code null} for compatibility fallback
   * @return immutable bootstrap metadata ready for deterministic JSON serialization
   */
  public static AppUiBootstrap forManifest(
      AppManifest manifest,
      String platformApiRoot,
      String shellRoot,
      AppBrowserSessionIssue browserSession,
      AppUiOriginBinding binding) {
    Objects.requireNonNull(manifest, "manifest");
    Objects.requireNonNull(browserSession, "browserSession");
    AppUiOriginBinding effectiveBinding =
        binding == null
            ? AppUiOriginBinding.sameOriginFallback(
                manifest, platformApiRoot, shellRoot, null, null)
            : binding;
    return new AppUiBootstrap(
        manifest.appId(),
        manifest.appName(),
        effectiveBinding.uiRoot(),
        effectiveBinding.assetRoot(),
        effectiveBinding.platformApiRoot(),
        effectiveBinding.shellRoot(),
        effectiveBinding.origin(),
        effectiveBinding.mode().jsonValue(),
        effectiveBinding.status().jsonValue(),
        effectiveBinding.sameOriginFallbackUrl(),
        browserSession.token(),
        browserSession.expiresAt());
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
   * <p>Required text fields must be non-blank. Route roots must be same-origin fallback paths that
   * begin with a single {@code /} or absolute local HTTP(S) URLs, contain no query or fragment, and
   * end with {@code /}. The browser session token text must be non-blank. The expiry timestamp must
   * be present but is not required to be in the future at construction time because serializers and
   * tests may inspect already-expired values.
   *
   * @throws NullPointerException if any required field is {@code null}
   * @throws IllegalArgumentException if a required text field is blank or a route root is invalid
   */
  public AppUiBootstrap(
      String appId,
      String name,
      String uiRoot,
      String assetRoot,
      String platformApiRoot,
      String shellRoot,
      String browserSessionToken,
      Instant browserSessionExpiresAt) {
    this(
        appId,
        name,
        uiRoot,
        assetRoot,
        platformApiRoot,
        shellRoot,
        null,
        AppUiOriginMode.SAME_ORIGIN_FALLBACK.jsonValue(),
        AppUiOriginStatus.FALLBACK.jsonValue(),
        uiRoot,
        browserSessionToken,
        browserSessionExpiresAt);
  }

  public AppUiBootstrap {
    requireText(appId, "appId");
    requireText(name, "name");
    requireRootPath(uiRoot, "uiRoot");
    requireRootPath(assetRoot, "assetRoot");
    requireRootPath(platformApiRoot, "platformApiRoot");
    requireRootPath(shellRoot, "shellRoot");
    requireOptionalOrigin(uiOrigin);
    requireText(uiOriginMode, "uiOriginMode");
    requireText(uiOriginStatus, "uiOriginStatus");
    requireOptionalFallbackRootPath(sameOriginFallbackUrl);
    requireText(browserSessionToken, "browserSessionToken");
    Objects.requireNonNull(browserSessionExpiresAt, "browserSessionExpiresAt");
  }

  @Override
  public @NotNull String toString() {
    return "AppUiBootstrap[appId="
        + appId
        + ", name="
        + name
        + ", uiRoot="
        + uiRoot
        + ", assetRoot="
        + assetRoot
        + ", platformApiRoot="
        + platformApiRoot
        + ", shellRoot="
        + shellRoot
        + ", uiOrigin="
        + uiOrigin
        + ", uiOriginMode="
        + uiOriginMode
        + ", uiOriginStatus="
        + uiOriginStatus
        + ", sameOriginFallbackUrl="
        + sameOriginFallbackUrl
        + ", browserSessionToken=[REDACTED], browserSessionExpiresAt="
        + browserSessionExpiresAt
        + "]";
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
    if (path.startsWith("/")) {
      requireSingleLeadingSlash(path, label);
      requireUriPathOnly(path, label);
    } else {
      requireAbsoluteLocalRootUrl(path, label);
    }
    if (!path.endsWith("/")) {
      throw new IllegalArgumentException(label + " must end with '/'");
    }
  }

  private static void requireOptionalFallbackRootPath(String value) {
    if (value != null) {
      requireRootPath(value, "sameOriginFallbackUrl");
    }
  }

  private static void requireOptionalOrigin(String value) {
    if (value == null) {
      return;
    }
    try {
      URI uri = URI.create(value);
      if (hasUnsupportedLocalHttpScheme(uri.getScheme())
          || hasNonLoopbackHost(uri.getHost())
          || uri.getPort() <= 0
          || (uri.getRawPath() != null && !uri.getRawPath().isEmpty())
          || uri.getRawQuery() != null
          || uri.getRawFragment() != null) {
        throw new IllegalArgumentException("uiOrigin must be a local HTTP origin");
      }
    } catch (IllegalArgumentException exception) {
      throw new IllegalArgumentException("uiOrigin must be a local HTTP origin", exception);
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

  private static void requireAbsoluteLocalRootUrl(String value, String label) {
    try {
      URI uri = URI.create(value);
      if (hasUnsupportedLocalHttpScheme(uri.getScheme())
          || hasNonLoopbackHost(uri.getHost())
          || uri.getRawQuery() != null
          || uri.getRawFragment() != null
          || uri.getRawPath() == null
          || uri.getRawPath().isBlank()) {
        throw new IllegalArgumentException(label + " must be a local absolute root URL");
      }
    } catch (IllegalArgumentException exception) {
      throw new IllegalArgumentException(label + " must be a local absolute root URL", exception);
    }
  }

  private static boolean hasUnsupportedLocalHttpScheme(String scheme) {
    return !"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme);
  }

  private static boolean hasNonLoopbackHost(String host) {
    String normalizedHost = normalizeBracketedIpv6Host(host);
    return !IPV4_LOOPBACK_HOST.equals(normalizedHost)
        && !LOCALHOST_HOST.equalsIgnoreCase(normalizedHost)
        && !IPV6_LOOPBACK_HOST.equalsIgnoreCase(normalizedHost)
        && !IPV6_LOOPBACK_HOST_EXPANDED.equalsIgnoreCase(normalizedHost);
  }

  private static String normalizeBracketedIpv6Host(String host) {
    if (host != null && host.startsWith("[") && host.endsWith("]")) {
      return host.substring(1, host.length() - 1);
    }
    return host;
  }
}

package network.crypta.platform.appui;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import network.crypta.platform.appdist.AppUiMode;
import network.crypta.platform.apphost.manifest.AppManifest;

/**
 * Public route helpers for app-owned browser UI surfaces.
 *
 * <p>The Platform API uses this class to publish stable browser links, the Web Shell uses those
 * links to open installed apps, and HTTP adapters use the same route root when mounting static app
 * assets. Keeping URL construction here avoids small disagreements between API summaries,
 * redirects, and toadlet registration.
 *
 * <p>The helpers return same-origin local paths only. They do not introduce external app URLs, and
 * they do not decide whether an app is installed or whether the target file exists. Those checks
 * belong to AppHost and {@link AppStaticAssetService}. This class is deliberately limited to
 * canonical route text and per-segment URL encoding.
 */
public final class AppUiPaths {
  /**
   * Canonical route root for installed app-owned browser UI.
   *
   * <p>The value includes the trailing slash because registered HTTP routes treat it as a subtree
   * prefix. Requests beneath this prefix carry an app id segment followed by an optional
   * bundle-relative asset path.
   */
  public static final String APPS_ROOT = "/apps/";

  private AppUiPaths() {}

  /**
   * Builds the canonical app-owned UI root URL for one installed app id.
   *
   * <p>The method assumes the app id was already normalized by AppHost manifest parsing or API
   * input validation. It performs only the null check needed for reliable URL construction and then
   * appends the root trailing slash required for browser-relative links.
   *
   * @param appId normalized AppHost application id to place in the route
   * @return app-owned UI root path ending in {@code /}
   * @throws NullPointerException if {@code appId} is {@code null}
   */
  public static String appRoot(String appId) {
    return APPS_ROOT + Objects.requireNonNull(appId, "appId") + "/";
  }

  /**
   * Computes the browser URL exposed by API summaries for one manifest.
   *
   * <p>Static UIs open at the app-owned root when their entry lives at the bundle root. Nested
   * static entries instead open at a same-origin directory URL beneath {@code /apps/{appId}/} so
   * the browser base URL preserves parent-directory asset references. Shell-panel UIs keep their
   * manifest entry because that entry already names a same-origin shell route. Apps without a UI
   * return {@code null}.
   *
   * <p>The returned path is suitable for API JSON and shell links, but it is still a launch URL,
   * not proof that a file can be served. The HTTP route resolves the path again against the current
   * installed bundle and can return not found if the app was removed or the bundle is invalid.
   *
   * @param manifest installed app manifest to summarize
   * @return browser-openable same-origin URL, or {@code null} when the app has no UI
   */
  public static String uiUrl(AppManifest manifest) {
    Objects.requireNonNull(manifest, "manifest");
    AppUiMode mode = manifest.uiMode();
    return switch (mode) {
      case NONE -> null;
      case SHELL_PANEL -> manifest.uiEntry();
      case STATIC -> staticUiUrl(manifest);
    };
  }

  private static String staticUiUrl(AppManifest manifest) {
    String uiEntry = manifest.uiEntry();
    int lastSlash = uiEntry.lastIndexOf('/');
    if (lastSlash < 0) {
      return appRoot(manifest.appId());
    }
    String entryDirectory = uiEntry.substring(0, lastSlash);
    return appRoot(manifest.appId()) + encodeRelativePath(entryDirectory) + "/";
  }

  static String encodeRelativePath(String relativePath) {
    StringBuilder encoded = new StringBuilder(relativePath.length());
    int start = 0;
    while (start < relativePath.length()) {
      int slash = relativePath.indexOf('/', start);
      if (!encoded.isEmpty()) {
        encoded.append('/');
      }
      if (slash < 0) {
        encoded.append(encodePathSegment(relativePath.substring(start)));
        break;
      }
      encoded.append(encodePathSegment(relativePath.substring(start, slash)));
      start = slash + 1;
    }
    return encoded.toString();
  }

  private static String encodePathSegment(String segment) {
    return URLEncoder.encode(segment, StandardCharsets.UTF_8).replace("+", "%20");
  }
}

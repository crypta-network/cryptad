package network.crypta.platform.devtools.devserver;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import network.crypta.platform.appdist.AppBundleManifest;
import network.crypta.platform.appui.AppUiOriginMode;
import network.crypta.platform.appui.AppUiOriginStatus;

/**
 * Builds bootstrap JSON for the local mock app origin.
 *
 * <p>The browser SDK discovers the Platform API by reading {@code
 * /.well-known/cryptad-bootstrap.json}. In the local dev server this JSON must look like a real
 * app-origin bootstrap response while remaining clearly offline: it points at the mock {@code
 * /api/v1/} routes, uses same-origin fallback fields, and includes a short-lived mock
 * browser-session token. The app root remains {@code /apps/{appId}/}; the asset root follows the
 * directory that contains {@code app.ui.entry} so relative asset references resolve as they do when
 * hosted by AppHost.
 */
final class DevServerBootstrapJson {
  /** Prevents construction of this stateless bootstrap renderer. */
  private DevServerBootstrapJson() {}

  /**
   * Serializes one SDK bootstrap response.
   *
   * @param manifest validated static app manifest being served locally
   * @param baseUrl listener origin URL without a trailing slash
   * @param sessionToken mock browser-session token required by the mock API
   * @param expiresAt instant when the mock browser session expires
   * @return compact JSON object consumed by {@code crypta-platform.js}
   */
  static String serialize(
      AppBundleManifest manifest, String baseUrl, String sessionToken, Instant expiresAt) {
    String appRoot = appRootUrl(manifest, baseUrl);
    String assetRoot = entryDirectoryUrl(manifest, baseUrl);
    return "{"
        + stringField("appId", manifest.appId())
        + ","
        + stringField("name", manifest.appName())
        + ","
        + stringField("uiRoot", appRoot)
        + ","
        + stringField("assetRoot", assetRoot)
        + ","
        + stringField("platformApiRoot", baseUrl + "/api/v1/")
        + ","
        + stringField("shellRoot", baseUrl + "/app/node/")
        + ","
        + stringField("uiOrigin", origin(baseUrl))
        + ","
        + stringField("uiOriginMode", AppUiOriginMode.SAME_ORIGIN_FALLBACK.jsonValue())
        + ","
        + stringField("uiOriginStatus", AppUiOriginStatus.FALLBACK.jsonValue())
        + ","
        + stringField("sameOriginFallbackUrl", appRoot)
        + ","
        + stringField("browserSessionToken", sessionToken)
        + ","
        + stringField("browserSessionExpiresAt", expiresAt.toString())
        + "}";
  }

  /**
   * Builds the local app root path.
   *
   * @param manifest validated app manifest
   * @return path ending in {@code /apps/{appId}/}
   */
  static String appRootPath(AppBundleManifest manifest) {
    return "/apps/" + manifest.appId() + "/";
  }

  /**
   * Builds the path used as the static entry-directory base.
   *
   * @param manifest validated app manifest with the static UI entry
   * @return app root path or nested entry directory path with encoded path segments
   */
  static String entryDirectoryPath(AppBundleManifest manifest) {
    String appRoot = appRootPath(manifest);
    String entryDirectory = entryDirectory(manifest.uiEntry());
    return entryDirectory.isEmpty() ? appRoot : appRoot + encodeRelativePath(entryDirectory) + "/";
  }

  /**
   * Builds the absolute local app root URL.
   *
   * @param manifest validated app manifest
   * @param baseUrl listener origin URL without a trailing slash
   * @return absolute URL ending in {@code /apps/{appId}/}
   */
  static String appRootUrl(AppBundleManifest manifest, String baseUrl) {
    return baseUrl + appRootPath(manifest);
  }

  /**
   * Builds the absolute static entry-directory URL used for {@code assetRoot}.
   *
   * @param manifest validated app manifest with the static UI entry
   * @param baseUrl listener origin URL without a trailing slash
   * @return absolute URL ending at the encoded entry directory
   */
  static String entryDirectoryUrl(AppBundleManifest manifest, String baseUrl) {
    return baseUrl + entryDirectoryPath(manifest);
  }

  /**
   * Renders one escaped JSON string field.
   *
   * @param name field name to escape
   * @param value field value to escape
   * @return JSON string field without surrounding object braces
   */
  private static String stringField(String name, String value) {
    return "\""
        + MockPlatformApiFixtures.Json.escape(name)
        + "\":\""
        + MockPlatformApiFixtures.Json.escape(value)
        + "\"";
  }

  /**
   * Extracts the origin from a local base URL.
   *
   * @param baseUrl listener base URL, with or without a path
   * @return scheme and authority portion of the URL
   */
  private static String origin(String baseUrl) {
    int pathStart = baseUrl.indexOf('/', "http://".length());
    return pathStart < 0 ? baseUrl : baseUrl.substring(0, pathStart);
  }

  /**
   * Returns the directory containing a static UI entry path.
   *
   * @param uiEntry manifest {@code app.ui.entry} value
   * @return relative directory path, or an empty string for root-level entries
   */
  private static String entryDirectory(String uiEntry) {
    int slash = uiEntry.lastIndexOf('/');
    return slash < 0 ? "" : uiEntry.substring(0, slash);
  }

  /**
   * Encodes a relative path one segment at a time.
   *
   * @param relativePath slash-separated manifest path without a leading slash
   * @return path with each segment URL-encoded and slashes preserved
   */
  private static String encodeRelativePath(String relativePath) {
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

  /**
   * Encodes one URL path segment using percent escapes for spaces and reserved characters.
   *
   * @param segment raw path segment from a manifest entry directory
   * @return URL-encoded path segment
   */
  private static String encodePathSegment(String segment) {
    return URLEncoder.encode(segment, StandardCharsets.UTF_8).replace("+", "%20");
  }
}

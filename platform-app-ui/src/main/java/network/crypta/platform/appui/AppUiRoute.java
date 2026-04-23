package network.crypta.platform.appui;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import network.crypta.platform.apphost.manifest.AppManifest;

/**
 * Parsed app-owned static UI request path beneath {@code /apps/}.
 *
 * <p>The parser works from raw URI paths, not decoded framework paths. That matters because encoded
 * traversal, encoded separators, malformed percent escapes, and control characters must be rejected
 * before an adapter or resolver constructs a filesystem path. The parsed route contains a
 * normalized app id and either a normalized bundle-relative asset path or {@code null} for the app
 * root.
 *
 * <p>Invalid app id syntax maps to a not-found-style failure so callers do not reveal which app ids
 * are installed. Invalid asset syntax maps to a bad-request-style failure because it describes a
 * malformed path beneath an otherwise valid route prefix. The record itself is immutable and holds
 * only normalized text; it does not perform AppHost lookup or filesystem validation.
 *
 * @param appId normalized installed application id
 * @param assetPath normalized bundle-relative asset path, or {@code null} for the app root
 */
public record AppUiRoute(String appId, String assetPath) {
  private static final char PERCENT = '%';
  private static final String ASSET_PATH_UNSAFE_MESSAGE = "App UI asset path is unsafe.";
  private static final String ROUTE_NOT_FOUND_MESSAGE = "App UI route not found.";

  /**
   * Parses a raw request path under {@link AppUiPaths#APPS_ROOT}.
   *
   * <p>The returned route is safe to pass to {@link AppStaticAssetService} for AppHost lookup and
   * filesystem resolution. A trailing slash after an asset path is preserved as a directory-style
   * request by omitting only the empty final segment; the resolver decides whether that directory
   * maps to the declared UI entry or to a not-found response.
   *
   * @param rawPath raw URI path, preserving percent escapes from the request target
   * @return parsed app UI route with a normalized app id and optional asset path
   * @throws AppStaticAssetException if the path is malformed, unsafe, or outside {@code /apps/}
   */
  public static AppUiRoute parse(String rawPath) throws AppStaticAssetException {
    if (rawPath == null || !rawPath.startsWith(AppUiPaths.APPS_ROOT)) {
      throw badRequest("App UI path must start with /apps/.");
    }
    String remainder = rawPath.substring(AppUiPaths.APPS_ROOT.length());
    if (remainder.isEmpty()) {
      throw routeNotFound();
    }
    int slashIndex = remainder.indexOf('/');
    String rawAppId = slashIndex < 0 ? remainder : remainder.substring(0, slashIndex);
    String appId = normalizeAppId(rawAppId);
    if (slashIndex < 0 || slashIndex == remainder.length() - 1) {
      return new AppUiRoute(appId, null);
    }
    String assetPath = normalizeAssetPath(remainder.substring(slashIndex + 1));
    return new AppUiRoute(appId, assetPath);
  }

  /**
   * Returns a redirect target when a request omitted the app-root trailing slash.
   *
   * <p>This helper handles only the route shape {@code /apps/{appId}}. It does not inspect AppHost
   * state and does not decide whether a nested static entry needs an entry-directory redirect; that
   * app-specific decision belongs to {@link AppStaticAssetService#canonicalRootRedirect(String)}.
   *
   * @param rawPath raw URI path, preserving percent escapes from the request target
   * @return canonical app root URL, or {@code null} when no slash redirect is needed
   * @throws AppStaticAssetException if the raw app id segment is malformed
   */
  public static String trailingSlashRedirectTarget(String rawPath) throws AppStaticAssetException {
    if (rawPath == null || !rawPath.startsWith(AppUiPaths.APPS_ROOT)) {
      return null;
    }
    String remainder = rawPath.substring(AppUiPaths.APPS_ROOT.length());
    if (remainder.isEmpty() || remainder.indexOf('/') >= 0) {
      return null;
    }
    return AppUiPaths.appRoot(normalizeAppId(remainder));
  }

  private static String normalizeAppId(String rawAppId) throws AppStaticAssetException {
    String decoded = decodePathSegment(rawAppId);
    try {
      return AppManifest.normalizeAppId(decoded);
    } catch (IllegalArgumentException _) {
      throw routeNotFound();
    }
  }

  private static String normalizeAssetPath(String rawPath) throws AppStaticAssetException {
    if (rawPath.isEmpty() || rawPath.charAt(0) == '/') {
      throw unsafeAssetPath();
    }
    String[] rawSegments = rawPath.split("/", -1);
    boolean trailingSlash = rawSegments.length > 1 && rawSegments[rawSegments.length - 1].isEmpty();
    List<String> decodedSegments = new ArrayList<>(rawSegments.length);
    int segmentCount = trailingSlash ? rawSegments.length - 1 : rawSegments.length;
    for (int index = 0; index < segmentCount; index++) {
      String rawSegment = rawSegments[index];
      String segment = decodePathSegment(rawSegment);
      validateAssetSegment(segment);
      decodedSegments.add(segment);
    }
    return String.join("/", decodedSegments);
  }

  private static void validateAssetSegment(String segment) throws AppStaticAssetException {
    if (segment.isBlank()
        || segment.equals(".")
        || segment.equals("..")
        || segment.indexOf('/') >= 0
        || segment.indexOf('\\') >= 0
        || segment.indexOf(':') >= 0
        || segment.indexOf('\0') >= 0) {
      throw unsafeAssetPath();
    }
    for (int index = 0; index < segment.length(); index++) {
      if (Character.isISOControl(segment.charAt(index))) {
        throw unsafeAssetPath();
      }
    }
  }

  private static String decodePathSegment(String rawSegment) throws AppStaticAssetException {
    if (rawSegment == null || rawSegment.isEmpty()) {
      throw badRequest("App UI path segment is unsafe.");
    }
    ByteArrayOutputStream bytes = new ByteArrayOutputStream(rawSegment.length());
    int index = 0;
    while (index < rawSegment.length()) {
      char character = rawSegment.charAt(index);
      if (character == PERCENT) {
        writePercentDecodedByte(bytes, rawSegment, index);
        index += 3;
      } else if (character > 0x7F) {
        bytes.writeBytes(Character.toString(character).getBytes(StandardCharsets.UTF_8));
        index++;
      } else {
        bytes.write((byte) character);
        index++;
      }
    }
    return bytes.toString(StandardCharsets.UTF_8);
  }

  private static void writePercentDecodedByte(
      ByteArrayOutputStream bytes, String rawSegment, int percentIndex)
      throws AppStaticAssetException {
    if (percentIndex + 2 >= rawSegment.length()) {
      throw badRequest("App UI path contains malformed percent-encoding.");
    }
    int high = Character.digit(rawSegment.charAt(percentIndex + 1), 16);
    int low = Character.digit(rawSegment.charAt(percentIndex + 2), 16);
    if (high < 0 || low < 0) {
      throw badRequest("App UI path contains malformed percent-encoding.");
    }
    bytes.write((high << 4) + low);
  }

  private static AppStaticAssetException unsafeAssetPath() {
    return badRequest(ASSET_PATH_UNSAFE_MESSAGE);
  }

  private static AppStaticAssetException badRequest(String message) {
    return new AppStaticAssetException(400, message);
  }

  private static AppStaticAssetException routeNotFound() {
    return new AppStaticAssetException(404, ROUTE_NOT_FOUND_MESSAGE);
  }
}

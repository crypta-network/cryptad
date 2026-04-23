package network.crypta.platform.appui;

import java.util.Locale;

/**
 * Content-type mapping for app-owned static UI files.
 *
 * <p>The mapping is intentionally small, deterministic, and independent of host operating-system
 * MIME databases. App bundles should be portable across nodes, so the same bundle-relative path
 * needs to produce the same response header on Linux, macOS, and Windows. The set covers the file
 * types expected from static browser UIs, including JavaScript modules, JSON data, image assets,
 * and WebAssembly.
 *
 * <p>Unknown extensions are served as opaque bytes. That conservative fallback pairs with the app
 * UI {@code nosniff} header so browsers do not reinterpret unrecognized bundle content as script or
 * markup. The method relies only on the final path suffix and does not inspect file contents.
 */
public final class AppUiContentTypes {
  /**
   * Fallback content type for unrecognized app-owned static files.
   *
   * <p>Adapters use this value when a path has no extension, has a trailing dot, or has an
   * extension outside the static UI allowlist. It intentionally omits a charset because the bytes
   * are opaque.
   */
  public static final String OCTET_STREAM = "application/octet-stream";

  private AppUiContentTypes() {}

  /**
   * Returns a content type for one bundle-relative asset path.
   *
   * <p>The lookup is case-insensitive and considers only the extension after the final slash.
   * Directory names containing dots do not affect the result, and paths without a file extension
   * use {@link #OCTET_STREAM}. The input may be {@code null}; that case is treated as unknown
   * content.
   *
   * @param relativePath normalized bundle-relative path such as {@code static/app.js}
   * @return HTTP content type suitable for the asset response
   */
  public static String forPath(String relativePath) {
    String extension = extensionOf(relativePath);
    return switch (extension) {
      case "html", "htm" -> "text/html; charset=UTF-8";
      case "css" -> "text/css; charset=UTF-8";
      case "js", "mjs" -> "text/javascript; charset=UTF-8";
      case "json" -> "application/json; charset=UTF-8";
      case "wasm" -> "application/wasm";
      case "svg" -> "image/svg+xml";
      case "png" -> "image/png";
      case "jpg", "jpeg" -> "image/jpeg";
      case "gif" -> "image/gif";
      case "webp" -> "image/webp";
      case "ico" -> "image/x-icon";
      default -> OCTET_STREAM;
    };
  }

  private static String extensionOf(String relativePath) {
    if (relativePath == null) {
      return "";
    }
    int lastSlash = relativePath.lastIndexOf('/');
    int lastDot = relativePath.lastIndexOf('.');
    if (lastDot <= lastSlash || lastDot == relativePath.length() - 1) {
      return "";
    }
    return relativePath.substring(lastDot + 1).toLowerCase(Locale.ROOT);
  }
}

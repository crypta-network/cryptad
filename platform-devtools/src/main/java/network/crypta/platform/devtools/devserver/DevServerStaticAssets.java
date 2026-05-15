package network.crypta.platform.devtools.devserver;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import network.crypta.platform.appdist.AppBundleDigest;
import network.crypta.platform.appdist.AppBundleManifest;
import network.crypta.platform.appdist.AppBundleManifestParser;
import network.crypta.platform.appdist.AppBundleSignature;
import network.crypta.platform.appdist.AppDistributionException;
import network.crypta.platform.appui.AppUiContentTypes;

/**
 * Resolves safe staged-bundle static assets for the local dev server.
 *
 * <p>The dev server serves files directly from a developer's staged bundle, so route parsing and
 * filesystem resolution must stay stricter than a generic static file server. This resolver accepts
 * raw request paths under {@code /apps/{appId}/}, decodes path segments one at a time, rejects
 * encoded separators, traversal, control characters, hidden sidecars, signature material, private
 * key-like names, and symlinks in any path segment. It then verifies the real file remains beneath
 * the real bundle root before reading bytes.
 *
 * <p>The resolver also mirrors the app UI routing behavior for nested static entries. Requests to
 * the app root serve the manifest entry file, and relative paths from a nested entry directory can
 * resolve against that directory when they do not exist at the bundle root. This keeps scaffolded
 * apps practical while preserving the same safety checks for every candidate file.
 */
public final class DevServerStaticAssets {
  /** Raw route prefix for app-owned UI files on the local dev origin. */
  private static final String APPS_ROOT = "/apps/";

  /** Percent marker used by the small raw-path decoder. */
  private static final char PERCENT = '%';

  /** Prevents construction of this stateless resolver. */
  private DevServerStaticAssets() {}

  /**
   * Resolves one raw request path beneath {@code /apps/{appId}/}.
   *
   * @param bundleRoot staged bundle root
   * @param manifest parsed app manifest
   * @param rawRequestPath raw HTTP request path
   * @return safe file response, or empty when the route is not for the app
   * @throws IOException if filesystem metadata cannot be read safely
   */
  public static Optional<StaticAsset> resolve(
      Path bundleRoot, AppBundleManifest manifest, String rawRequestPath) throws IOException {
    LocalRoute route = parseRoute(rawRequestPath);
    if (!manifest.appId().equals(route.appId())) {
      return Optional.empty();
    }
    String assetPath = route.assetPath();
    if (assetPath == null || isEntryDirectoryRequest(rawRequestPath, assetPath, manifest)) {
      assetPath = manifest.uiEntry();
    }
    Optional<StaticAsset> direct = resolveBundlePath(bundleRoot, assetPath);
    if (direct.isPresent()) {
      return direct;
    }
    String entryDirectory = entryDirectory(manifest.uiEntry());
    if (!entryDirectory.isEmpty()
        && !assetPath.equals(entryDirectory)
        && !assetPath.startsWith(entryDirectory + "/")) {
      return resolveBundlePath(bundleRoot, entryDirectory + "/" + assetPath);
    }
    return Optional.empty();
  }

  /**
   * Runs a static asset safety pass for offline app tests.
   *
   * @param bundleRoot staged bundle root
   * @param manifest parsed manifest
   * @throws IOException if an unsafe static asset is found
   */
  public static void checkStaticAssetSafety(Path bundleRoot, AppBundleManifest manifest)
      throws IOException {
    if (manifest.uiEntry() == null) {
      return;
    }
    if (resolveBundlePath(bundleRoot, manifest.uiEntry()).isEmpty()) {
      throw new AppDistributionException("static UI entry is not safe to serve");
    }
  }

  /**
   * Resolves one already-normalized asset path against the staged bundle root.
   *
   * @param bundleRoot staged bundle root supplied to the dev server
   * @param assetPath slash-separated relative asset path from the local app route
   * @return safe static asset response, or empty when the candidate is absent or unsafe
   * @throws IOException if filesystem metadata cannot be inspected safely
   */
  private static Optional<StaticAsset> resolveBundlePath(Path bundleRoot, String assetPath)
      throws IOException {
    requireSafeAssetName(assetPath);
    Path root = Objects.requireNonNull(bundleRoot, "bundleRoot").toAbsolutePath().normalize();
    Path realRoot = root.toRealPath();
    Path file = root.resolve(assetPath).normalize();
    if (!file.startsWith(root) || hasSymbolicLinkSegment(root, assetPath)) {
      return Optional.empty();
    }
    if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
      return Optional.empty();
    }
    Path realFile = file.toRealPath();
    if (!realFile.startsWith(realRoot)) {
      return Optional.empty();
    }
    return Optional.of(
        new StaticAsset(
            realFile, Files.readAllBytes(realFile), AppUiContentTypes.forPath(assetPath)));
  }

  /**
   * Checks each path segment for symlinks before any file bytes are read.
   *
   * @param root normalized staged bundle root
   * @param assetPath relative asset path being resolved
   * @return {@code true} when a segment is a symlink or escapes the root during normalization
   */
  private static boolean hasSymbolicLinkSegment(Path root, String assetPath) {
    Path current = root;
    for (String segment : assetPath.replace('\\', '/').split("/", -1)) {
      current = current.resolve(segment).normalize();
      if (!current.startsWith(root) || Files.isSymbolicLink(current)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Rejects path segments and file names that must never be served as UI assets.
   *
   * @param assetPath slash-separated relative path after route decoding
   * @throws AppDistributionException if the path is empty, hidden, reserved, or key-like
   */
  private static void requireSafeAssetName(String assetPath) throws AppDistributionException {
    String normalized = assetPath.replace('\\', '/');
    for (String segment : normalized.split("/", -1)) {
      String name = segment.toLowerCase(Locale.ROOT);
      if (segment.isBlank() || segment.equals(".") || segment.equals("..")) {
        throw new AppDistributionException("static asset path is unsafe");
      }
      if (segment.startsWith(".")
          || sidecarName(segment)
          || privateMaterialName(segment)
          || AppBundleManifestParser.MANIFEST_FILE_NAME.equals(name)) {
        throw new AppDistributionException("static asset is reserved and cannot be served");
      }
    }
  }

  /**
   * Identifies bundle, signature, digest, and catalog sidecar names reserved by app tooling.
   *
   * @param segment single decoded path segment
   * @return {@code true} when the segment names a reserved sidecar file
   */
  private static boolean sidecarName(String segment) {
    String name = segment.toLowerCase(Locale.ROOT);
    return AppBundleDigest.DIGEST_FILE_NAME.equals(name)
        || AppBundleSignature.SIGNATURE_FILE_NAME.equals(name)
        || "cryptad-app.catalog".equals(name)
        || "cryptad-app.catalog.signature".equals(name)
        || "cryptad-app-catalog.properties".equals(name)
        || "cryptad-app-catalog.signature".equals(name);
  }

  /**
   * Identifies file names that commonly contain private keys, passwords, or tokens.
   *
   * @param segment single decoded path segment
   * @return {@code true} when the name is treated as private material
   */
  private static boolean privateMaterialName(String segment) {
    String name = segment.toLowerCase(Locale.ROOT);
    return name.endsWith(".pem")
        || name.endsWith(".key")
        || name.endsWith(".p12")
        || name.endsWith(".pfx")
        || name.endsWith(".der")
        || name.contains("private")
        || name.contains("password")
        || name.equals("token")
        || name.equals("tokens")
        || name.startsWith("token.")
        || name.startsWith("tokens.")
        || name.endsWith(".token")
        || name.endsWith(".tokens");
  }

  /**
   * Checks whether a request targets the directory that contains the manifest UI entry.
   *
   * @param rawRequestPath raw HTTP request path from the exchange
   * @param assetPath decoded route asset path
   * @param manifest validated app manifest with the static entry path
   * @return {@code true} when the request should serve the manifest entry file
   */
  private static boolean isEntryDirectoryRequest(
      String rawRequestPath, String assetPath, AppBundleManifest manifest) {
    return rawRequestPath.endsWith("/")
        && !assetPath.isEmpty()
        && assetPath.equals(entryDirectory(manifest.uiEntry()));
  }

  /**
   * Returns the directory that contains a manifest entry path.
   *
   * @param uiEntry manifest static UI entry path
   * @return relative directory path, or an empty string for root-level entries
   */
  private static String entryDirectory(String uiEntry) {
    int slash = uiEntry.lastIndexOf('/');
    return slash < 0 ? "" : uiEntry.substring(0, slash);
  }

  /**
   * Parses a raw local app route into app id and optional asset path.
   *
   * @param rawPath raw request path from {@link java.net.URI#getRawPath()}
   * @return parsed local app route with normalized app id and decoded asset path
   * @throws AppDistributionException if the route is malformed or unsafe
   */
  private static LocalRoute parseRoute(String rawPath) throws AppDistributionException {
    if (rawPath == null || !rawPath.startsWith(APPS_ROOT)) {
      throw new AppDistributionException("App UI path must start with /apps/.");
    }
    String remainder = rawPath.substring(APPS_ROOT.length());
    if (remainder.isEmpty()) {
      throw new AppDistributionException("App UI route not found.");
    }
    int slashIndex = remainder.indexOf('/');
    String rawAppId = slashIndex < 0 ? remainder : remainder.substring(0, slashIndex);
    String appId;
    try {
      appId = AppBundleManifest.normalizeAppId(decodePathSegment(rawAppId));
    } catch (IllegalArgumentException exception) {
      throw new AppDistributionException("App UI route not found.", exception);
    }
    if (slashIndex < 0 || slashIndex == remainder.length() - 1) {
      return new LocalRoute(appId, null);
    }
    return new LocalRoute(appId, normalizeAssetPath(remainder.substring(slashIndex + 1)));
  }

  /**
   * Decodes and validates a raw asset path from the local app route.
   *
   * @param rawPath raw path suffix after {@code /apps/{appId}/}
   * @return slash-separated decoded asset path with no traversal or encoded separators
   * @throws AppDistributionException if any segment is unsafe or malformed
   */
  private static String normalizeAssetPath(String rawPath) throws AppDistributionException {
    if (rawPath.isEmpty() || rawPath.charAt(0) == '/') {
      throw new AppDistributionException("App UI asset path is unsafe.");
    }
    String[] rawSegments = rawPath.split("/", -1);
    boolean trailingSlash = rawSegments.length > 1 && rawSegments[rawSegments.length - 1].isEmpty();
    int segmentCount = trailingSlash ? rawSegments.length - 1 : rawSegments.length;
    StringBuilder builder = new StringBuilder(rawPath.length());
    for (int index = 0; index < segmentCount; index++) {
      String segment = decodePathSegment(rawSegments[index]);
      validateAssetSegment(segment);
      if (index > 0) {
        builder.append('/');
      }
      builder.append(segment);
    }
    return builder.toString();
  }

  /**
   * Validates one decoded route segment before it becomes part of a filesystem path.
   *
   * @param segment decoded route segment
   * @throws AppDistributionException if the segment is blank, traversal, separator-bearing, or
   *     control-character-bearing
   */
  private static void validateAssetSegment(String segment) throws AppDistributionException {
    if (segment.isBlank()
        || segment.equals(".")
        || segment.equals("..")
        || segment.indexOf('/') >= 0
        || segment.indexOf('\\') >= 0
        || segment.indexOf(':') >= 0
        || segment.indexOf('\0') >= 0) {
      throw new AppDistributionException("App UI asset path is unsafe.");
    }
    for (int index = 0; index < segment.length(); index++) {
      if (Character.isISOControl(segment.charAt(index))) {
        throw new AppDistributionException("App UI asset path is unsafe.");
      }
    }
  }

  /**
   * Decodes percent-encoded UTF-8 for one route segment without allowing encoded separators.
   *
   * @param rawSegment raw URL path segment with percent escapes still present
   * @return decoded UTF-8 segment
   * @throws AppDistributionException if percent encoding is malformed
   */
  private static String decodePathSegment(String rawSegment) throws AppDistributionException {
    if (rawSegment == null || rawSegment.isEmpty()) {
      throw new AppDistributionException("App UI path segment is unsafe.");
    }
    ByteArrayOutputStream bytes = new ByteArrayOutputStream(rawSegment.length());
    int index = 0;
    while (index < rawSegment.length()) {
      char character = rawSegment.charAt(index);
      if (character == PERCENT) {
        writePercentDecodedByte(bytes, rawSegment, index);
        index += 3;
      } else if (character > 0x7F) {
        bytes.writeBytes(
            Character.toString(character).getBytes(java.nio.charset.StandardCharsets.UTF_8));
        index++;
      } else {
        bytes.write((byte) character);
        index++;
      }
    }
    return bytes.toString(java.nio.charset.StandardCharsets.UTF_8);
  }

  /**
   * Decodes one percent escape into a byte buffer.
   *
   * @param bytes destination buffer for decoded bytes
   * @param rawSegment raw URL path segment containing the percent escape
   * @param percentIndex index of the percent character in {@code rawSegment}
   * @throws AppDistributionException if the escape is incomplete or non-hexadecimal
   */
  private static void writePercentDecodedByte(
      ByteArrayOutputStream bytes, String rawSegment, int percentIndex)
      throws AppDistributionException {
    if (percentIndex + 2 >= rawSegment.length()) {
      throw new AppDistributionException("App UI path contains malformed percent-encoding.");
    }
    int high = Character.digit(rawSegment.charAt(percentIndex + 1), 16);
    int low = Character.digit(rawSegment.charAt(percentIndex + 2), 16);
    if (high < 0 || low < 0) {
      throw new AppDistributionException("App UI path contains malformed percent-encoding.");
    }
    bytes.write((high << 4) + low);
  }

  /**
   * Parsed local app route.
   *
   * @param appId normalized app id from the first route segment
   * @param assetPath decoded asset path, or {@code null} when the app root was requested
   */
  private record LocalRoute(String appId, String assetPath) {}

  /**
   * Safe static file response.
   *
   * <p>The response owns a defensive copy of the file bytes because callers hand the array to the
   * HTTP response body. The file path is the resolved real file path after containment checks; it
   * is useful for tests and diagnostics but should not be printed in user-facing reports.
   */
  @SuppressWarnings({"ClassCanBeRecord", "java:S6206"})
  public static final class StaticAsset {
    /** Real resolved file path inside the staged bundle root. */
    private final Path file;

    /** Immutable response bytes copied from the resolved file. */
    private final byte[] bytes;

    /** HTTP content type selected from the app UI content type table. */
    private final String contentType;

    /**
     * Creates an immutable response.
     *
     * @param file real resolved file path inside the staged bundle root
     * @param bytes file bytes to copy into the response object
     * @param contentType HTTP content type to return for the asset
     */
    public StaticAsset(Path file, byte[] bytes, String contentType) {
      this.file = Objects.requireNonNull(file, "file");
      this.bytes = Objects.requireNonNull(bytes, "bytes").clone();
      this.contentType = Objects.requireNonNull(contentType, "contentType");
    }

    /**
     * Returns the resolved staged asset path.
     *
     * @return real file path inside the staged bundle root
     */
    public Path file() {
      return file;
    }

    /**
     * Returns the HTTP response content type.
     *
     * @return content type selected for this asset path
     */
    public String contentType() {
      return contentType;
    }

    /**
     * Returns a fresh copy of file bytes.
     *
     * @return defensive copy of the immutable response payload
     */
    public byte[] bytes() {
      return bytes.clone();
    }
  }
}

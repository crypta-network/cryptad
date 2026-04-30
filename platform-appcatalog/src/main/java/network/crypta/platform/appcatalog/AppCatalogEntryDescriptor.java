package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;

/**
 * One developer-authored descriptor used to create a catalog entry.
 *
 * <p>The descriptor file format is a deliberately small UTF-8 key/value sidecar, not a general Java
 * properties file. It sits between a local packaged bundle and the published catalog: the local
 * {@code artifact.path} lets tooling inspect ZIP bytes, while {@code bundle.uri} is the location
 * installers will later use. Blank lines and lines starting with {@code #} or {@code !} are
 * ignored; all other lines must use {@code key=value}. Unknown keys are rejected because a typo in
 * a catalog descriptor should fail before the catalog is signed.
 *
 * <p>The supported descriptor shape is:
 *
 * <pre>{@code
 * artifact.path=/abs/path/to/app.zip
 * bundle.uri=https://example.invalid/apps/app.zip
 * summary=Short operator-facing summary
 * name=Optional display name override
 * version=Optional version consistency check
 * permissions=queue.read,queue.write
 * app.id=optional app-id consistency check
 * homepage=https://example.invalid/app
 * source=https://example.invalid/repo
 * license=MIT
 * categories=productivity,network
 * minimumCryptaVersion=0.1.0
 * review.status=reviewed
 * review.note=Reviewed for local operator safety.
 * permissions.rationale.queue.read=Reads the local transfer queue.
 * screenshot.1=https://example.invalid/assets/shot-1.png
 * changelog.summary=Adds queue retry controls.
 * changelog.uri=https://example.invalid/apps/app-1.2.0-changelog.txt
 * }</pre>
 *
 * <p>{@code artifact.path}, {@code bundle.uri}, and {@code summary} are required. The local
 * artifact path is used only while authoring so the writer can read the ZIP bytes, compute {@code
 * bundle.size.bytes}, compute lowercase {@code bundle.sha256}, and inspect the root {@code
 * cryptad-app.properties}. {@code app.id} and {@code version} do not replace manifest values; when
 * present, they must match the artifact manifest so the generated catalog can install through the
 * same runtime checks used for updates. Optional store metadata is written into the public signed
 * catalog and remains advisory display input for operators.
 *
 * @param artifactPath absolute path to the local ZIP artifact inspected during catalog authoring
 * @param bundleUri public artifact URI written into the catalog entry
 * @param summary short operator-facing catalog summary for the app
 * @param appIdOverride optional app-id consistency check against the artifact manifest
 * @param nameOverride optional display name override for catalog presentation
 * @param versionOverride optional version consistency check against the artifact manifest
 * @param homepage optional operator-facing project homepage URI
 * @param source optional operator-facing source-code URI
 * @param license optional license identifier or short license name
 * @param categories normalized catalog category tags
 * @param compatibility advisory compatibility metadata
 * @param review advisory human-review metadata
 * @param changelog optional change metadata for this catalog version
 * @param screenshots optional screenshot URIs displayed as links
 * @param permissionsOverride optional permission list override; an empty list means no permissions
 * @param permissionRationales permission-keyed rationale text for install/update review
 * @see AppCatalogWriter
 */
public record AppCatalogEntryDescriptor(
    Path artifactPath,
    URI bundleUri,
    String summary,
    Optional<String> appIdOverride,
    Optional<String> nameOverride,
    Optional<String> versionOverride,
    Optional<URI> homepage,
    Optional<URI> source,
    Optional<String> license,
    List<String> categories,
    AppCatalogCompatibilityMetadata compatibility,
    AppCatalogReviewMetadata review,
    AppCatalogChangelog changelog,
    List<URI> screenshots,
    Optional<List<String>> permissionsOverride,
    Map<String, String> permissionRationales) {
  private static final String ARTIFACT_PATH = "artifact.path";
  private static final String BUNDLE_URI = "bundle.uri";
  private static final String SUMMARY_PROPERTY = "summary";
  private static final String APP_ID = "app.id";
  private static final String NAME = "name";
  private static final String VERSION = "version";
  private static final String HOMEPAGE_PROPERTY = "homepage";
  private static final String SOURCE_PROPERTY = "source";
  private static final String LICENSE_PROPERTY = "license";
  private static final String CATEGORIES_PROPERTY = "categories";
  private static final String MINIMUM_CRYPTA_VERSION = "minimumCryptaVersion";
  private static final String REVIEW_STATUS = "review.status";
  private static final String REVIEW_NOTE = "review.note";
  private static final String CHANGELOG_SUMMARY = "changelog.summary";
  private static final String CHANGELOG_URI = "changelog.uri";
  private static final String SCREENSHOT_PREFIX = "screenshot.";
  private static final String PERMISSIONS = "permissions";
  private static final String PERMISSION_RATIONALE_PREFIX = "permissions.rationale.";
  private static final int MAX_LICENSE_CHARS = 128;
  private static final int MAX_PERMISSION_RATIONALE_CHARS = 512;

  /**
   * Creates a normalized descriptor snapshot.
   *
   * <p>The constructor validates the fields that belong to the descriptor itself: absolute local
   * artifact path, safe public artifact URI, single-line summary and overrides, immutable optional
   * collections, safe display URIs, and advisory metadata. It does not read the artifact; {@link
   * AppCatalogWriter} performs that filesystem work when building a catalog. Permission rationales
   * are checked against the artifact manifest or permission override when the writer creates the
   * final {@link AppCatalogEntry}.
   *
   * @param artifactPath absolute local ZIP artifact path used only while authoring
   * @param bundleUri public artifact URI written into the generated catalog entry
   * @param summary short operator-facing summary for catalog listings
   * @param appIdOverride optional app-id consistency check against the artifact manifest
   * @param nameOverride optional display name override for catalog presentation
   * @param versionOverride optional version consistency check against the artifact manifest
   * @param homepage optional operator-facing project homepage URI
   * @param source optional operator-facing source-code URI
   * @param license optional license identifier or short license name
   * @param categories normalized catalog category tags
   * @param compatibility advisory compatibility metadata
   * @param review advisory human-review metadata
   * @param changelog optional change metadata for this catalog version
   * @param screenshots optional screenshot URIs displayed as links
   * @param permissionsOverride optional permission override list copied into immutable state
   * @param permissionRationales permission-keyed rationale text for install/update review
   * @throws AppCatalogException if descriptor metadata is malformed
   */
  public AppCatalogEntryDescriptor {
    artifactPath = normalizeArtifactPath(artifactPath);
    bundleUri = AppCatalogSidecars.requireSafeArtifactUri(Objects.requireNonNull(bundleUri));
    summary =
        AppCatalogSidecars.requireNonBlankSingleLine(
            summary, SUMMARY_PROPERTY, AppCatalogSidecars.INVALID_CATALOG_ENTRY);
    Objects.requireNonNull(appIdOverride, APP_ID);
    appIdOverride = appIdOverride.map(rawValue -> normalizeOptionalText(rawValue, APP_ID));
    Objects.requireNonNull(nameOverride, NAME);
    nameOverride = nameOverride.map(rawValue -> normalizeOptionalText(rawValue, NAME));
    Objects.requireNonNull(versionOverride, VERSION);
    versionOverride = versionOverride.map(rawValue -> normalizeOptionalText(rawValue, VERSION));
    Objects.requireNonNull(homepage, HOMEPAGE_PROPERTY);
    homepage = homepage.map(rawUri -> normalizeMetadataUri(rawUri, HOMEPAGE_PROPERTY));
    Objects.requireNonNull(source, SOURCE_PROPERTY);
    source = source.map(rawUri -> normalizeMetadataUri(rawUri, SOURCE_PROPERTY));
    Objects.requireNonNull(license, LICENSE_PROPERTY);
    license = license.map(AppCatalogEntryDescriptor::normalizeLicenseText);
    categories = normalizeCategories(categories);
    Objects.requireNonNull(compatibility, "compatibility");
    Objects.requireNonNull(review, "review");
    Objects.requireNonNull(changelog, "changelog");
    screenshots = normalizeScreenshots(screenshots);
    Objects.requireNonNull(permissionsOverride, PERMISSIONS);
    permissionsOverride = permissionsOverride.map(List::copyOf);
    permissionRationales = normalizePermissionRationales(permissionRationales);
  }

  /**
   * Parses one descriptor file.
   *
   * <p>The file is read with the same bounded, no-symlink sidecar policy used by catalog metadata.
   * Unknown keys are rejected so descriptor typos do not silently produce partial catalog entries.
   * Relative paths are rejected by the descriptor constructor; callers should resolve local
   * artifact paths before writing descriptors if they want a catalog build to be independent of the
   * current working directory.
   *
   * @param descriptorFile path to a UTF-8 catalog entry descriptor file
   * @return parsed and normalized descriptor metadata ready for catalog authoring
   * @throws IOException if the descriptor file cannot be read with the sidecar policy
   * @throws AppCatalogException if the descriptor content is malformed or incomplete
   */
  public static AppCatalogEntryDescriptor parse(Path descriptorFile) throws IOException {
    Path normalizedDescriptorFile =
        Objects.requireNonNull(descriptorFile, "descriptorFile").toAbsolutePath().normalize();
    Map<String, String> properties =
        AppCatalogSidecars.parseKeyValueSidecar(
            AppCatalogSidecars.utf8(
                AppCatalogSidecars.readRequiredBytes(
                    normalizedDescriptorFile,
                    AppCatalogSidecars.MAX_CATALOG_BYTES,
                    "catalog entry descriptor",
                    AppCatalogSidecars.INVALID_CATALOG_ENTRY)),
            "catalog entry descriptor");
    AppCatalogEntryDescriptor descriptor =
        new AppCatalogEntryDescriptor(
            parseArtifactPath(removeRequired(properties, ARTIFACT_PATH), normalizedDescriptorFile),
            parseBundleUri(removeRequired(properties, BUNDLE_URI), normalizedDescriptorFile),
            removeRequired(properties, SUMMARY_PROPERTY),
            removeOptional(properties, APP_ID),
            removeOptional(properties, NAME),
            removeOptional(properties, VERSION),
            removeOptional(properties, HOMEPAGE_PROPERTY)
                .map(value -> parseUri(value, HOMEPAGE_PROPERTY)),
            removeOptional(properties, SOURCE_PROPERTY)
                .map(value -> parseUri(value, SOURCE_PROPERTY)),
            removeOptional(properties, LICENSE_PROPERTY),
            parseCategories(removeOptional(properties, CATEGORIES_PROPERTY).orElse(null)),
            new AppCatalogCompatibilityMetadata(removeOptional(properties, MINIMUM_CRYPTA_VERSION)),
            parseReview(properties),
            new AppCatalogChangelog(
                removeOptional(properties, CHANGELOG_SUMMARY),
                removeOptional(properties, CHANGELOG_URI)
                    .map(value -> parseUri(value, CHANGELOG_URI))),
            parseScreenshots(properties),
            removeOptionalPermissions(properties),
            parsePermissionRationales(properties));
    if (!properties.isEmpty()) {
      throw AppCatalogSidecars.invalidEntry(
          "unsupported catalog entry descriptor property: "
              + properties.keySet().iterator().next());
    }
    return descriptor;
  }

  private static Path normalizeArtifactPath(Path artifactPath) {
    Path normalized = Objects.requireNonNull(artifactPath, ARTIFACT_PATH).normalize();
    if (!normalized.isAbsolute()) {
      throw AppCatalogSidecars.invalidEntry(ARTIFACT_PATH + " must be absolute");
    }
    return normalized;
  }

  private static String normalizeOptionalText(String rawValue, String fieldName) {
    return AppCatalogSidecars.requireNonBlankSingleLine(
        rawValue, fieldName, AppCatalogSidecars.INVALID_CATALOG_ENTRY);
  }

  private static URI normalizeMetadataUri(URI uri, String fieldName) {
    return AppCatalogSidecars.requireSafeMetadataUri(uri, fieldName);
  }

  private static String normalizeLicenseText(String value) {
    return AppCatalogSidecars.requireBoundedSingleLine(
        value, LICENSE_PROPERTY, AppCatalogSidecars.INVALID_CATALOG_ENTRY, MAX_LICENSE_CHARS);
  }

  private static List<String> normalizeCategories(List<String> categories) {
    Objects.requireNonNull(categories, CATEGORIES_PROPERTY);
    Set<String> normalized = new LinkedHashSet<>();
    for (String category : categories) {
      normalized.add(AppCatalogEntry.normalizeCategory(category, CATEGORIES_PROPERTY));
    }
    return List.copyOf(normalized);
  }

  private static List<URI> normalizeScreenshots(List<URI> screenshots) {
    Objects.requireNonNull(screenshots, "screenshots");
    return screenshots.stream()
        .map(uri -> AppCatalogSidecars.requireSafeMetadataUri(uri, SCREENSHOT_PREFIX))
        .toList();
  }

  private static Map<String, String> normalizePermissionRationales(
      Map<String, String> permissionRationales) {
    Objects.requireNonNull(permissionRationales, "permissionRationales");
    Map<String, String> normalized = new LinkedHashMap<>();
    for (Map.Entry<String, String> entry : permissionRationales.entrySet()) {
      String permission =
          AppCatalogEntry.normalizePermission(entry.getKey(), PERMISSION_RATIONALE_PREFIX);
      String rationale =
          AppCatalogSidecars.requireBoundedSingleLine(
              entry.getValue(),
              PERMISSION_RATIONALE_PREFIX + permission,
              AppCatalogSidecars.INVALID_CATALOG_ENTRY,
              MAX_PERMISSION_RATIONALE_CHARS);
      String previous = normalized.putIfAbsent(permission, rationale);
      if (previous != null) {
        throw AppCatalogSidecars.invalidEntry("duplicate permission rationale for " + permission);
      }
    }
    return Collections.unmodifiableMap(new LinkedHashMap<>(normalized));
  }

  private static Path parseArtifactPath(String rawPath, Path descriptorFile) {
    try {
      return Path.of(
          AppCatalogSidecars.requireNonBlankSingleLine(
              rawPath, ARTIFACT_PATH, AppCatalogSidecars.INVALID_CATALOG_ENTRY));
    } catch (InvalidPathException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_ENTRY,
          "invalid " + ARTIFACT_PATH + " in " + descriptorFile.getFileName(),
          exception);
    }
  }

  private static URI parseBundleUri(String rawUri, Path descriptorFile) {
    try {
      return parseUri(rawUri, BUNDLE_URI);
    } catch (AppCatalogException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_ENTRY,
          "invalid " + BUNDLE_URI + " in " + descriptorFile.getFileName(),
          exception);
    }
  }

  private static URI parseUri(String rawUri, String fieldName) {
    String value =
        AppCatalogSidecars.requireNonBlankSingleLine(
            rawUri, fieldName, AppCatalogSidecars.INVALID_CATALOG_ENTRY);
    try {
      return new URI(value);
    } catch (URISyntaxException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_ENTRY, "invalid " + fieldName, exception);
    }
  }

  private static List<String> parseCategories(String rawCategories) {
    if (rawCategories == null || rawCategories.isBlank()) {
      return List.of();
    }
    List<String> categories = new ArrayList<>();
    for (String category : rawCategories.split(",", -1)) {
      categories.add(category.trim());
    }
    return categories;
  }

  private static AppCatalogReviewMetadata parseReview(Map<String, String> properties) {
    Optional<String> statusText = removeOptional(properties, REVIEW_STATUS);
    AppCatalogReviewStatus status =
        statusText
            .map(value -> AppCatalogReviewStatus.parse(value, REVIEW_STATUS))
            .orElse(AppCatalogReviewStatus.UNREVIEWED);
    return new AppCatalogReviewMetadata(status, removeOptional(properties, REVIEW_NOTE));
  }

  private static List<URI> parseScreenshots(Map<String, String> properties) {
    List<String> keys =
        properties.keySet().stream().filter(key -> key.startsWith(SCREENSHOT_PREFIX)).toList();
    if (keys.isEmpty()) {
      return List.of();
    }
    SortedMap<Integer, URI> indexed = new TreeMap<>();
    for (String key : keys) {
      String indexText = key.substring(SCREENSHOT_PREFIX.length());
      if (!isPositiveDecimal(indexText)) {
        throw AppCatalogSidecars.invalidEntry("invalid screenshot index: " + key);
      }
      int index = parsePositiveIndex(indexText, key);
      URI previous = indexed.putIfAbsent(index, parseUri(properties.remove(key), key));
      if (previous != null) {
        throw AppCatalogSidecars.invalidEntry("duplicate screenshot index: " + key);
      }
    }
    List<URI> screenshots = new ArrayList<>(indexed.size());
    int expected = 1;
    for (Map.Entry<Integer, URI> entry : indexed.entrySet()) {
      if (entry.getKey() != expected) {
        throw AppCatalogSidecars.invalidEntry(
            "missing "
                + SCREENSHOT_PREFIX
                + expected
                + " before "
                + SCREENSHOT_PREFIX
                + entry.getKey());
      }
      screenshots.add(entry.getValue());
      expected++;
    }
    return List.copyOf(screenshots);
  }

  private static Optional<List<String>> removeOptionalPermissions(Map<String, String> properties) {
    String rawPermissions = properties.remove(PERMISSIONS);
    if (rawPermissions == null) {
      return Optional.empty();
    }
    if (rawPermissions.isBlank()) {
      return Optional.of(List.of());
    }
    List<String> permissions = new ArrayList<>();
    for (String permission : rawPermissions.split(",", -1)) {
      permissions.add(permission.trim());
    }
    return Optional.of(permissions);
  }

  private static Map<String, String> parsePermissionRationales(Map<String, String> properties) {
    List<String> keys =
        properties.keySet().stream()
            .filter(key -> key.startsWith(PERMISSION_RATIONALE_PREFIX))
            .toList();
    Map<String, String> rationales = new LinkedHashMap<>();
    for (String key : keys) {
      String rawPermission = key.substring(PERMISSION_RATIONALE_PREFIX.length());
      String permission = AppCatalogEntry.normalizePermission(rawPermission, key);
      String previous = rationales.putIfAbsent(permission, properties.remove(key));
      if (previous != null) {
        throw AppCatalogSidecars.invalidEntry("duplicate permission rationale for " + permission);
      }
    }
    return rationales;
  }

  private static boolean isPositiveDecimal(String value) {
    if (value.isEmpty() || value.charAt(0) == '0') {
      return false;
    }
    for (int i = 0; i < value.length(); i++) {
      char digit = value.charAt(i);
      if (digit < '0' || digit > '9') {
        return false;
      }
    }
    return true;
  }

  private static int parsePositiveIndex(String value, String key) {
    try {
      return Integer.parseInt(value);
    } catch (NumberFormatException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_ENTRY, "invalid screenshot index: " + key, exception);
    }
  }

  private static String removeRequired(Map<String, String> properties, String key) {
    String value = properties.remove(key);
    if (value == null) {
      throw AppCatalogSidecars.invalidEntry("missing catalog entry descriptor property: " + key);
    }
    return value;
  }

  private static Optional<String> removeOptional(Map<String, String> properties, String key) {
    return Optional.ofNullable(properties.remove(key));
  }
}

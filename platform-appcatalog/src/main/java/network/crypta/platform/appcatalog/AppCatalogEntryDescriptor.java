package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

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
 * <p>The supported v1 shape is:
 *
 * <pre>{@code
 * artifact.path=/abs/path/to/app.zip
 * bundle.uri=https://example.invalid/apps/app.zip
 * summary=Short operator-facing summary
 * name=Optional display name override
 * version=Optional version consistency check
 * permissions=queue.read,queue.write
 * app.id=optional app-id consistency check
 * }</pre>
 *
 * <p>{@code artifact.path}, {@code bundle.uri}, and {@code summary} are required. The local
 * artifact path is used only while authoring so the writer can read the ZIP bytes, compute {@code
 * bundle.size.bytes}, compute lowercase {@code bundle.sha256}, and inspect the root {@code
 * cryptad-app.properties}. {@code app.id} and {@code version} do not replace manifest values; when
 * present, they must match the artifact manifest so the generated catalog can install through the
 * same runtime checks used for updates. {@code bundle.uri} is the URI that will be written into the
 * public catalog for installers to fetch.
 *
 * @param artifactPath absolute path to the local ZIP artifact inspected during catalog authoring
 * @param bundleUri public artifact URI written into the catalog entry
 * @param summary short operator-facing catalog summary for the app
 * @param appIdOverride optional app-id consistency check against the artifact manifest
 * @param nameOverride optional display name override for catalog presentation
 * @param versionOverride optional version consistency check against the artifact manifest
 * @param permissionsOverride optional permission list override; an empty list means no permissions
 * @see AppCatalogWriter
 */
public record AppCatalogEntryDescriptor(
    Path artifactPath,
    URI bundleUri,
    String summary,
    Optional<String> appIdOverride,
    Optional<String> nameOverride,
    Optional<String> versionOverride,
    Optional<List<String>> permissionsOverride) {
  private static final String ARTIFACT_PATH = "artifact.path";
  private static final String BUNDLE_URI = "bundle.uri";
  private static final String SUMMARY_PROPERTY = "summary";
  private static final String APP_ID = "app.id";
  private static final String NAME = "name";
  private static final String VERSION = "version";
  private static final String PERMISSIONS = "permissions";

  /**
   * Creates a normalized descriptor snapshot.
   *
   * <p>The constructor validates the fields that belong to the descriptor itself: absolute local
   * artifact path, safe public artifact URI, single-line summary and overrides, and immutable
   * optional collections. It does not read the artifact; {@link AppCatalogWriter} performs that
   * filesystem work when building a catalog. This split keeps parse-time errors focused on
   * descriptor syntax and authoring errors focused on artifact contents.
   *
   * @param artifactPath absolute local ZIP artifact path used only while authoring
   * @param bundleUri public artifact URI written into the generated catalog entry
   * @param summary short operator-facing summary for catalog listings
   * @param appIdOverride optional app-id consistency check against the artifact manifest
   * @param nameOverride optional display name override for catalog presentation
   * @param versionOverride optional version consistency check against the artifact manifest
   * @param permissionsOverride optional permission override list copied into immutable state
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
    Objects.requireNonNull(permissionsOverride, PERMISSIONS);
    permissionsOverride = permissionsOverride.map(List::copyOf);
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
            removeOptionalPermissions(properties));
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
    String value =
        AppCatalogSidecars.requireNonBlankSingleLine(
            rawUri, BUNDLE_URI, AppCatalogSidecars.INVALID_CATALOG_ENTRY);
    try {
      return new URI(value);
    } catch (URISyntaxException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_ENTRY,
          "invalid " + BUNDLE_URI + " in " + descriptorFile.getFileName(),
          exception);
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
}

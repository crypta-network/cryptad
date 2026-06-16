package network.crypta.platform.devtools;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import network.crypta.platform.appcatalog.AppCatalogBundleExtractor;
import network.crypta.platform.appcatalog.AppCatalogWriter;
import network.crypta.platform.appcatalog.AppReviewReceipt;
import network.crypta.platform.appcatalog.AppReviewReceiptIO;
import network.crypta.platform.appdist.AppBundleManifest;
import network.crypta.platform.appdist.AppBundleManifestParser;
import network.crypta.platform.appdist.AppDistributionException;

/**
 * Writes strict catalog entry descriptors from staged bundle and artifact metadata.
 *
 * <p>This helper backs {@code crypta-app catalog entry}. It turns a signed app artifact and a local
 * staged bundle into the descriptor consumed by {@code crypta-app catalog create}. The artifact is
 * the source of publishable manifest metadata such as permissions, API compatibility, app identity,
 * and version. The staged bundle is still parsed, but only to prove that the developer is
 * generating metadata for the same manifest they just signed and packed.
 *
 * <p>The writer is intentionally conservative. It rejects unsigned artifacts through the catalog
 * bundle extractor, validates the generated descriptor before moving it into place, writes through
 * a temporary file, and preserves the order of permission rationales supplied on the CLI. It does
 * not publish bundles or catalogs; it prepares local descriptor input for the existing catalog
 * signing pipeline.
 */
final class CatalogEntryDescriptorGenerator {
  /** Directory permissions used for artifact-inspection scratch roots before ZIP extraction. */
  private static final Set<PosixFilePermission> OWNER_ONLY_DIRECTORY =
      Set.of(
          PosixFilePermission.OWNER_READ,
          PosixFilePermission.OWNER_WRITE,
          PosixFilePermission.OWNER_EXECUTE);

  /** Prevents construction of this stateless descriptor writer. */
  private CatalogEntryDescriptorGenerator() {}

  /**
   * Generates and validates one catalog entry descriptor.
   *
   * <p>The method normalizes paths, checks overwrite policy, verifies that the packed artifact is a
   * signed app bundle, compares the staged and artifact manifests, enforces strict permission
   * rationale requirements, and then writes a descriptor accepted by {@link AppCatalogWriter}. The
   * output is moved atomically where the filesystem supports it.
   *
   * @param request descriptor generation request from CLI options
   * @return generated app id, version, and any permissions that lacked rationales
   * @throws IOException if manifests, artifacts, receipts, or output files cannot be read or
   *     written
   */
  static Result write(Request request) throws IOException {
    Request checked = request.normalize();
    if (Files.exists(checked.output(), LinkOption.NOFOLLOW_LINKS) && !checked.overwrite()) {
      throw new AppDistributionException("catalog entry already exists: " + checked.output());
    }
    AppBundleManifest bundleManifest =
        AppBundleManifestParser.parse(
            checked.bundleDir().resolve(AppBundleManifestParser.MANIFEST_FILE_NAME));
    AppBundleManifest artifactManifest = inspectArtifactManifest(checked);
    requireBundleManifestMatchesArtifact(bundleManifest, artifactManifest);
    List<String> missingRationales =
        artifactManifest.permissions().stream()
            .filter(permission -> !checked.permissionRationales().containsKey(permission))
            .toList();
    if (checked.strict() && !missingRationales.isEmpty()) {
      throw new AppDistributionException(
          "missing permission rationale(s): " + String.join(", ", missingRationales));
    }
    String descriptor = descriptorContent(checked, artifactManifest);
    Path temp = temporaryDescriptor(checked.output());
    try {
      Files.writeString(
          temp,
          descriptor,
          StandardCharsets.UTF_8,
          StandardOpenOption.TRUNCATE_EXISTING,
          StandardOpenOption.WRITE);
      AppCatalogWriter.inspectEntryDescriptor(temp);
      createParent(checked.output());
      Files.move(
          temp,
          checked.output(),
          checked.overwrite()
              ? new StandardCopyOption[] {
                StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE
              }
              : new StandardCopyOption[] {StandardCopyOption.ATOMIC_MOVE});
    } catch (IOException | RuntimeException exception) {
      Files.deleteIfExists(temp);
      throw exception;
    }
    return new Result(artifactManifest.appId(), artifactManifest.appVersion(), missingRationales);
  }

  /**
   * Reads the manifest from the signed artifact using the catalog extractor's verification path.
   *
   * @param request normalized request containing the artifact ZIP path
   * @return manifest embedded in the verified signed artifact
   * @throws IOException if the artifact cannot be inspected or temporary storage cannot be created
   */
  private static AppBundleManifest inspectArtifactManifest(Request request) throws IOException {
    Path scratchRoot = createPrivateArtifactScratchRoot(request.artifact());
    try {
      return AppCatalogBundleExtractor.inspectSignedArtifact(request.artifact(), scratchRoot);
    } finally {
      Files.deleteIfExists(scratchRoot);
    }
  }

  /**
   * Creates a private scratch directory next to the artifact being inspected.
   *
   * <p>The catalog entry command expands an untrusted ZIP only through {@link
   * AppCatalogBundleExtractor}, but the extraction root itself must not live in the shared JVM
   * default temporary directory with broad permissions. Creating the directory beside the artifact
   * avoids default public temp roots, and POSIX hosts receive owner-only permissions at creation
   * time. Non-POSIX hosts are restricted immediately through the portable {@link java.io.File}
   * permission API and fail closed when the runtime reports that permissions could not be applied.
   *
   * @param artifact signed artifact path whose parent should hold inspection scratch state
   * @return owner-only temporary directory for artifact inspection
   * @throws IOException if the scratch directory cannot be created or restricted
   */
  // The directory name is generated atomically under the artifact parent, and permissions are
  // restricted to the current owner before any ZIP extraction occurs.
  @SuppressWarnings("java:S5443")
  private static Path createPrivateArtifactScratchRoot(Path artifact) throws IOException {
    Path parent = artifact.getParent();
    if (parent == null) {
      parent = Path.of("").toAbsolutePath().normalize();
    }
    try {
      return Files.createTempDirectory(
          parent,
          ".catalog-entry-artifact-",
          PosixFilePermissions.asFileAttribute(OWNER_ONLY_DIRECTORY));
    } catch (UnsupportedOperationException _) {
      Path scratchRoot = Files.createTempDirectory(parent, ".catalog-entry-artifact-");
      try {
        restrictPortableOwnerOnlyDirectory(scratchRoot);
        return scratchRoot;
      } catch (IOException | RuntimeException exception) {
        Files.deleteIfExists(scratchRoot);
        throw exception;
      }
    }
  }

  /**
   * Applies owner-only access to a scratch directory on non-POSIX filesystems.
   *
   * @param directory scratch directory that must be accessible only by the current owner
   * @throws IOException if any portable permission operation is rejected by the runtime
   */
  private static void restrictPortableOwnerOnlyDirectory(Path directory) throws IOException {
    java.io.File file = directory.toFile();
    if (!file.setReadable(false, false)
        || !file.setWritable(false, false)
        || !file.setExecutable(false, false)
        || !file.setReadable(true, true)
        || !file.setWritable(true, true)
        || !file.setExecutable(true, true)) {
      throw new IOException("failed to restrict catalog entry scratch directory: " + directory);
    }
  }

  /**
   * Ensures the mutable staged bundle and immutable artifact describe the same app bundle.
   *
   * @param bundleManifest manifest parsed from the staged bundle directory
   * @param artifactManifest manifest parsed from the signed artifact ZIP
   * @throws AppDistributionException if any manifest field differs
   */
  private static void requireBundleManifestMatchesArtifact(
      AppBundleManifest bundleManifest, AppBundleManifest artifactManifest)
      throws AppDistributionException {
    if (!bundleManifest.equals(artifactManifest)) {
      throw new AppDistributionException(
          "bundle manifest must match artifact manifest before catalog entry generation");
    }
  }

  /**
   * Renders descriptor properties in the order expected by catalog fixture tests.
   *
   * @param request normalized request containing CLI metadata and optional review receipt
   * @param manifest artifact-derived manifest that supplies app and API metadata
   * @return descriptor properties text with one {@code key=value} pair per line
   * @throws IOException if an optional review receipt cannot be read
   */
  private static String descriptorContent(Request request, AppBundleManifest manifest)
      throws IOException {
    StringBuilder builder = new StringBuilder();
    append(builder, "artifact.path", request.artifact().toString());
    append(builder, "bundle.uri", request.bundleUri().toString());
    append(builder, "summary", request.summary());
    append(builder, "app.id", manifest.appId());
    append(builder, "name", manifest.appName());
    append(builder, "version", manifest.appVersion());
    appendOptionalUri(builder, "homepage", request.homepage().orElse(null));
    appendOptionalUri(builder, "source", request.source().orElse(null));
    appendOptional(builder, "license", request.license().orElse(null));
    appendOptional(builder, "categories", request.category().orElse(null));
    appendOptional(builder, "minimumCryptaVersion", request.minimumCryptaVersion().orElse(null));
    appendOptional(builder, "maximumCryptaVersion", request.maximumCryptaVersion().orElse(null));
    appendOptional(builder, "channel", request.channel().orElse(null));
    appendOptional(builder, "support.status", request.supportStatus().orElse(null));
    appendOptional(builder, "deprecation.status", request.deprecationStatus().orElse(null));
    appendOptional(builder, "deprecation.message", request.deprecationMessage().orElse(null));
    appendOptional(builder, "replacementAppId", request.replacementAppId().orElse(null));
    appendSecurityAdvisories(builder, request.securityAdvisories());
    appendOptional(builder, "maintenance.owner", request.maintenanceOwner().orElse(null));
    appendOptionalUri(builder, "maintenance.ownerUri", request.maintenanceOwnerUri().orElse(null));
    appendOptional(
        builder, "maintenance.supportLevel", request.maintenanceSupportLevel().orElse(null));
    appendOptional(
        builder,
        "maintenance.dataSchemaPolicy",
        request.maintenanceDataSchemaPolicy().orElse(null));
    appendOptional(
        builder, "maintenance.migrationPolicy", request.maintenanceMigrationPolicy().orElse(null));
    appendOptional(
        builder, "maintenance.backupRestore", request.maintenanceBackupRestore().orElse(null));
    appendOptional(
        builder, "maintenance.securityPolicy", request.maintenanceSecurityPolicy().orElse(null));
    appendOptional(
        builder,
        "maintenance.deprecationPolicy",
        request.maintenanceDeprecationPolicy().orElse(null));
    appendOptionalUri(
        builder, "maintenance.supportUri", request.maintenanceSupportUri().orElse(null));
    if (!manifest.permissions().isEmpty()) {
      append(builder, "permissions", String.join(",", manifest.permissions()));
    }
    if (manifest.apiCompatibility().minimumVersion() != null) {
      append(
          builder, "api.minimumVersion", manifest.apiCompatibility().minimumVersion().toString());
    }
    if (manifest.apiCompatibility().maximumTestedVersion() != null) {
      append(
          builder,
          "api.maximumTestedVersion",
          manifest.apiCompatibility().maximumTestedVersion().toString());
    }
    if (!manifest.apiCompatibility().optionalCapabilities().isEmpty()) {
      append(
          builder,
          "api.optionalCapabilities",
          String.join(",", manifest.apiCompatibility().optionalCapabilities()));
    }
    if (manifest.apiCompatibility().targetStabilityDeclared()) {
      append(
          builder,
          "api.targetStability",
          manifest.apiCompatibility().targetStability().manifestValue());
    }
    if (manifest.apiCompatibility().declared()) {
      append(
          builder,
          "api.experimentalCapabilitiesAccepted",
          Boolean.toString(manifest.apiCompatibility().experimentalCapabilitiesAccepted()));
    }
    for (Map.Entry<String, String> entry : request.permissionRationales().entrySet()) {
      append(builder, "permissions.rationale." + entry.getKey(), entry.getValue());
    }
    for (int index = 0; index < request.screenshots().size(); index++) {
      append(builder, "screenshot." + (index + 1), request.screenshots().get(index).toString());
    }
    appendOptional(builder, "changelog.summary", request.changelogSummary().orElse(null));
    appendReviewReceipt(builder, request.reviewReceipt());
    return builder.toString();
  }

  /**
   * Appends a URI-valued property only when the CLI option was supplied.
   *
   * @param builder descriptor builder receiving the property
   * @param key catalog descriptor property key
   * @param value URI value supplied by the developer, or {@code null} when omitted
   * @throws AppDistributionException if the URI text contains a line break
   */
  private static void appendOptionalUri(StringBuilder builder, String key, URI value)
      throws AppDistributionException {
    if (value == null) {
      return;
    }
    append(builder, key, value.toString());
  }

  /**
   * Appends a string-valued property only when the CLI option was supplied.
   *
   * @param builder descriptor builder receiving the property
   * @param key catalog descriptor property key
   * @param value text supplied by the developer or review receipt, or {@code null} when omitted
   * @throws AppDistributionException if the value contains a line break
   */
  private static void appendOptional(StringBuilder builder, String key, String value)
      throws AppDistributionException {
    if (value == null) {
      return;
    }
    append(builder, key, value);
  }

  /**
   * Copies review metadata from an optional receipt file into the descriptor.
   *
   * @param builder descriptor builder receiving review fields
   * @param reviewReceipt optional review receipt path supplied on the CLI
   * @throws IOException if the review receipt cannot be read
   */
  private static void appendReviewReceipt(StringBuilder builder, Path reviewReceipt)
      throws IOException {
    if (reviewReceipt != null) {
      AppReviewReceipt receipt = AppReviewReceiptIO.read(reviewReceipt);
      append(builder, "review.status", receipt.payload().status().catalogValue());
      appendOptional(builder, "review.note", receipt.payload().note().orElse(null));
    }
  }

  /**
   * Appends security advisory metadata in descriptor order.
   *
   * @param builder descriptor builder receiving advisory fields
   * @param advisories insertion-ordered advisory id to URI mappings
   * @throws AppDistributionException if a generated advisory value contains a line break
   */
  private static void appendSecurityAdvisories(StringBuilder builder, Map<String, URI> advisories)
      throws AppDistributionException {
    if (advisories.isEmpty()) {
      return;
    }
    append(builder, "securityAdvisories", String.join(",", advisories.keySet()));
    for (Map.Entry<String, URI> advisory : advisories.entrySet()) {
      append(
          builder,
          "securityAdvisory." + advisory.getKey() + ".uri",
          advisory.getValue().toString());
    }
  }

  /**
   * Appends one single-line properties value.
   *
   * @param builder descriptor builder receiving the property
   * @param key catalog descriptor property key
   * @param value property value, trimmed before writing
   * @throws AppDistributionException if the value contains a line break
   */
  private static void append(StringBuilder builder, String key, String value)
      throws AppDistributionException {
    if (value.indexOf('\n') >= 0 || value.indexOf('\r') >= 0) {
      throw new AppDistributionException("catalog entry value must be a single line: " + key);
    }
    builder.append(key).append('=').append(value.trim()).append('\n');
  }

  /**
   * Creates a temporary descriptor file next to the requested output.
   *
   * @param output final descriptor path requested by the user
   * @return temporary file path in the same directory as the final output
   * @throws IOException if the parent directory or temporary file cannot be created
   */
  private static Path temporaryDescriptor(Path output) throws IOException {
    Path parent = descriptorParent(output);
    return Files.createTempFile(parent, ".catalog-entry-", ".properties");
  }

  /**
   * Resolves and creates the directory used for descriptor staging.
   *
   * @param output final descriptor path requested by the user
   * @return directory where the temporary descriptor should be created
   * @throws IOException if the directory cannot be created
   */
  private static Path descriptorParent(Path output) throws IOException {
    Path parent = output.getParent();
    if (parent == null) {
      parent = Path.of("").toAbsolutePath().normalize();
    }
    Files.createDirectories(parent);
    return parent;
  }

  /**
   * Creates the parent directory for a file when it has one.
   *
   * @param file file path whose parent should exist before a move or write
   * @throws IOException if the parent directory cannot be created
   */
  private static void createParent(Path file) throws IOException {
    Path parent = file.getParent();
    if (parent != null) {
      Files.createDirectories(parent);
    }
  }

  /**
   * Parses repeatable {@code --permission-rationale permission=text} CLI values.
   *
   * <p>The returned map preserves insertion order so repeated command runs generate byte-identical
   * descriptors when all other inputs are unchanged. Permission keys are normalized to lower case
   * to match manifest permission spelling.
   *
   * @param values raw CLI values supplied for permission rationales
   * @return immutable insertion-ordered map from permission id to rationale text
   * @throws AppDistributionException if a value is malformed or duplicates a permission
   */
  static Map<String, String> normalizeRationales(List<String> values)
      throws AppDistributionException {
    Map<String, String> rationales = new LinkedHashMap<>();
    for (String value : values) {
      int separator = value.indexOf('=');
      if (separator <= 0 || separator == value.length() - 1) {
        throw new AppDistributionException(
            "--permission-rationale must use permission=text syntax");
      }
      String permission = value.substring(0, separator).trim().toLowerCase(java.util.Locale.ROOT);
      String rationale = value.substring(separator + 1).trim();
      if (rationales.putIfAbsent(permission, rationale) != null) {
        throw new AppDistributionException("duplicate permission rationale: " + permission);
      }
    }
    return java.util.Collections.unmodifiableMap(new LinkedHashMap<>(rationales));
  }

  static Map<String, URI> normalizeSecurityAdvisories(List<String> values)
      throws AppDistributionException {
    Map<String, URI> advisories = new LinkedHashMap<>();
    for (String value : values) {
      int separator = value.indexOf('=');
      if (separator <= 0 || separator == value.length() - 1) {
        throw new AppDistributionException("--security-advisory must use id=uri syntax");
      }
      String advisoryId = value.substring(0, separator).trim();
      URI advisoryUri = URI.create(value.substring(separator + 1).trim());
      if (advisories.putIfAbsent(advisoryId, advisoryUri) != null) {
        throw new AppDistributionException("duplicate security advisory: " + advisoryId);
      }
    }
    return java.util.Collections.unmodifiableMap(new LinkedHashMap<>(advisories));
  }

  /**
   * Input for catalog entry descriptor generation.
   *
   * <p>The request combines paths for local artifacts with catalog-facing metadata supplied by the
   * developer. Only {@code artifact.path} is expected to preserve a local path in the descriptor;
   * other manifest-derived fields come from the signed artifact, and optional URI or review fields
   * are copied only after validation by the existing catalog tooling.
   *
   * @param bundleDir staged bundle directory used to confirm the local manifest matches the
   *     artifact manifest
   * @param artifact signed packed bundle artifact whose size, digest, and manifest metadata are
   *     used by the catalog
   * @param bundleUri public or local URI that catalog consumers should use to fetch the artifact
   * @param output descriptor file to write for {@code crypta-app catalog create --entry}
   * @param summary short user-facing summary required by catalog entries
   * @param homepage optional project or app homepage URI copied into the descriptor
   * @param source optional source repository URI copied into the descriptor
   * @param license optional license label or identifier copied into the descriptor
   * @param category optional catalog category value copied into the descriptor
   * @param minimumCryptaVersion optional minimum daemon version advertised by the catalog entry
   * @param maximumCryptaVersion optional maximum daemon version advertised by the catalog entry
   * @param channel optional production release channel copied into the descriptor
   * @param supportStatus optional production support status copied into the descriptor
   * @param deprecationStatus optional deprecation status copied into the descriptor
   * @param deprecationMessage optional deprecation message copied into the descriptor
   * @param replacementAppId optional replacement app id copied into the descriptor
   * @param securityAdvisories insertion-ordered advisory references keyed by advisory id
   * @param maintenanceOwner optional first-party maintenance owner copied into the descriptor
   * @param maintenanceOwnerUri optional owner information URI copied into the descriptor
   * @param maintenanceSupportLevel optional first-party support level copied into the descriptor
   * @param maintenanceDataSchemaPolicy optional app-data schema policy copied into the descriptor
   * @param maintenanceMigrationPolicy optional app-data migration policy copied into the descriptor
   * @param maintenanceBackupRestore optional backup/restore support copied into the descriptor
   * @param maintenanceSecurityPolicy optional security handling policy copied into the descriptor
   * @param maintenanceDeprecationPolicy optional deprecation policy copied into the descriptor
   * @param maintenanceSupportUri optional app-specific support URI copied into the descriptor
   * @param reviewReceipt optional trusted review receipt whose status and note are copied
   * @param changelogSummary optional short changelog text for this app release
   * @param permissionRationales insertion-ordered rationales keyed by manifest permission id
   * @param screenshots optional screenshot URIs copied as ordered descriptor entries
   * @param strict whether missing rationales for declared permissions should fail generation
   * @param overwrite whether an existing descriptor output may be replaced
   */
  record Request(
      Path bundleDir,
      Path artifact,
      URI bundleUri,
      Path output,
      String summary,
      Optional<URI> homepage,
      Optional<URI> source,
      Optional<String> license,
      Optional<String> category,
      Optional<String> minimumCryptaVersion,
      Optional<String> maximumCryptaVersion,
      Optional<String> channel,
      Optional<String> supportStatus,
      Optional<String> deprecationStatus,
      Optional<String> deprecationMessage,
      Optional<String> replacementAppId,
      Map<String, URI> securityAdvisories,
      Optional<String> maintenanceOwner,
      Optional<URI> maintenanceOwnerUri,
      Optional<String> maintenanceSupportLevel,
      Optional<String> maintenanceDataSchemaPolicy,
      Optional<String> maintenanceMigrationPolicy,
      Optional<String> maintenanceBackupRestore,
      Optional<String> maintenanceSecurityPolicy,
      Optional<String> maintenanceDeprecationPolicy,
      Optional<URI> maintenanceSupportUri,
      Path reviewReceipt,
      Optional<String> changelogSummary,
      Map<String, String> permissionRationales,
      List<URI> screenshots,
      boolean strict,
      boolean overwrite) {
    /**
     * Validates required fields and freezes collection-valued inputs.
     *
     * <p>The compact constructor accepts already-normalized or relative paths. Call {@link
     * #normalize()} before filesystem access so path handling remains consistent across CLI entry
     * points and tests.
     */
    Request {
      Objects.requireNonNull(bundleDir, "bundleDir");
      Objects.requireNonNull(artifact, "artifact");
      Objects.requireNonNull(bundleUri, "bundleUri");
      Objects.requireNonNull(output, "output");
      Objects.requireNonNull(summary, "summary");
      Objects.requireNonNull(homepage, "homepage");
      Objects.requireNonNull(source, "source");
      Objects.requireNonNull(license, "license");
      Objects.requireNonNull(category, "category");
      Objects.requireNonNull(minimumCryptaVersion, "minimumCryptaVersion");
      Objects.requireNonNull(maximumCryptaVersion, "maximumCryptaVersion");
      Objects.requireNonNull(channel, "channel");
      Objects.requireNonNull(supportStatus, "supportStatus");
      Objects.requireNonNull(deprecationStatus, "deprecationStatus");
      Objects.requireNonNull(deprecationMessage, "deprecationMessage");
      Objects.requireNonNull(replacementAppId, "replacementAppId");
      securityAdvisories =
          java.util.Collections.unmodifiableMap(new LinkedHashMap<>(securityAdvisories));
      Objects.requireNonNull(maintenanceOwner, "maintenanceOwner");
      Objects.requireNonNull(maintenanceOwnerUri, "maintenanceOwnerUri");
      Objects.requireNonNull(maintenanceSupportLevel, "maintenanceSupportLevel");
      Objects.requireNonNull(maintenanceDataSchemaPolicy, "maintenanceDataSchemaPolicy");
      Objects.requireNonNull(maintenanceMigrationPolicy, "maintenanceMigrationPolicy");
      Objects.requireNonNull(maintenanceBackupRestore, "maintenanceBackupRestore");
      Objects.requireNonNull(maintenanceSecurityPolicy, "maintenanceSecurityPolicy");
      Objects.requireNonNull(maintenanceDeprecationPolicy, "maintenanceDeprecationPolicy");
      Objects.requireNonNull(maintenanceSupportUri, "maintenanceSupportUri");
      Objects.requireNonNull(changelogSummary, "changelogSummary");
      permissionRationales =
          java.util.Collections.unmodifiableMap(new LinkedHashMap<>(permissionRationales));
      screenshots = List.copyOf(screenshots);
    }

    /**
     * Converts local paths to absolute normalized form.
     *
     * @return equivalent request with normalized filesystem paths and unchanged catalog metadata
     */
    Request normalize() {
      return new Request(
          bundleDir.toAbsolutePath().normalize(),
          artifact.toAbsolutePath().normalize(),
          bundleUri,
          output.toAbsolutePath().normalize(),
          summary.trim(),
          homepage,
          source,
          license,
          category,
          minimumCryptaVersion,
          maximumCryptaVersion,
          channel,
          supportStatus,
          deprecationStatus,
          deprecationMessage,
          replacementAppId,
          securityAdvisories,
          maintenanceOwner,
          maintenanceOwnerUri,
          maintenanceSupportLevel,
          maintenanceDataSchemaPolicy,
          maintenanceMigrationPolicy,
          maintenanceBackupRestore,
          maintenanceSecurityPolicy,
          maintenanceDeprecationPolicy,
          maintenanceSupportUri,
          reviewReceipt == null ? null : reviewReceipt.toAbsolutePath().normalize(),
          changelogSummary,
          permissionRationales,
          screenshots,
          strict,
          overwrite);
    }
  }

  /**
   * Summary of a generated descriptor.
   *
   * @param appId app id copied from the verified artifact manifest
   * @param version app version copied from the verified artifact manifest
   * @param missingRationales manifest permissions that did not have supplied rationale text
   */
  record Result(String appId, String version, List<String> missingRationales) {}
}

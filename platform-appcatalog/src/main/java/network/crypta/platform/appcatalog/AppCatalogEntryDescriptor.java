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
import network.crypta.platform.appdist.AppApiCompatibilityMetadata;

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
 * maximumCryptaVersion=0.9.99
 * channel=stable
 * support.status=supported
 * deprecation.status=none
 * deprecation.message=Use the maintained replacement.
 * replacementAppId=queue-manager
 * securityAdvisories=CRYPTA-2026-0001
 * securityAdvisory.CRYPTA-2026-0001.uri=https://example.invalid/advisories/CRYPTA-2026-0001
 * maintenance.owner=crypta-core
 * maintenance.ownerUri=https://example.invalid/crypta/owners/core
 * maintenance.supportLevel=core
 * maintenance.dataSchemaPolicy=stateless
 * maintenance.migrationPolicy=none
 * maintenance.backupRestore=not-applicable
 * maintenance.securityPolicy=catalog-advisories
 * maintenance.deprecationPolicy=none
 * maintenance.supportUri=https://example.invalid/crypta/apps/queue-manager/support
 * api.minimumVersion=1
 * api.maximumTestedVersion=1
 * api.targetStability=stable
 * api.experimentalCapabilitiesAccepted=false
 * review.status=reviewed
 * review.note=Reviewed for local operator safety.
 * permissions.rationale.queue.read=Reads the local transfer queue.
 * screenshot.1=https://example.invalid/assets/shot-1.png
 * changelog.summary=Adds queue retry controls.
 * changelog.uri=https://example.invalid/apps/app-1.2.0-changelog.txt
 * review.receipt.version=1
 * review.receipt.app.id=sample-app
 * review.receipt.signature.algorithm=Ed25519
 * review.receipt.signature.value.base64=<base64-signature-over-canonical-payload>
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
 * @param reviewReceipt optional independently signed review receipt copied into the generated
 *     catalog entry
 * @param changelog optional change metadata for this catalog version
 * @param screenshots optional screenshot URIs displayed as links
 * @param productionMetadata production channel, support, deprecation, and advisory metadata
 * @param maintenanceMetadata first-party maintenance policy metadata
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
    Optional<AppReviewReceipt> reviewReceipt,
    AppCatalogChangelog changelog,
    List<URI> screenshots,
    AppCatalogProductionMetadata productionMetadata,
    AppCatalogMaintenanceMetadata maintenanceMetadata,
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
  private static final String CHANNEL_PROPERTY = "channel";
  private static final String MINIMUM_CRYPTA_VERSION = "minimumCryptaVersion";
  private static final String MAXIMUM_CRYPTA_VERSION = "maximumCryptaVersion";
  private static final String SUPPORT_STATUS = "support.status";
  private static final String DEPRECATION_STATUS = "deprecation.status";
  private static final String DEPRECATION_MESSAGE = "deprecation.message";
  private static final String REPLACEMENT_APP_ID = "replacementAppId";
  private static final String SECURITY_ADVISORIES = "securityAdvisories";
  private static final String SECURITY_ADVISORY_PREFIX = "securityAdvisory.";
  private static final String SECURITY_ADVISORY_URI_SUFFIX = ".uri";
  private static final String MAINTENANCE_OWNER = "maintenance.owner";
  private static final String MAINTENANCE_OWNER_URI = "maintenance.ownerUri";
  private static final String MAINTENANCE_SUPPORT_LEVEL = "maintenance.supportLevel";
  private static final String MAINTENANCE_DATA_SCHEMA_POLICY = "maintenance.dataSchemaPolicy";
  private static final String MAINTENANCE_MIGRATION_POLICY = "maintenance.migrationPolicy";
  private static final String MAINTENANCE_BACKUP_RESTORE = "maintenance.backupRestore";
  private static final String MAINTENANCE_SECURITY_POLICY = "maintenance.securityPolicy";
  private static final String MAINTENANCE_DEPRECATION_POLICY = "maintenance.deprecationPolicy";
  private static final String MAINTENANCE_SUPPORT_URI = "maintenance.supportUri";
  private static final String API_MINIMUM_VERSION = "api.minimumVersion";
  private static final String API_MAXIMUM_TESTED_VERSION = "api.maximumTestedVersion";
  private static final String API_OPTIONAL_CAPABILITIES = "api.optionalCapabilities";
  private static final String API_TARGET_STABILITY = "api.targetStability";
  private static final String API_TARGET_BASELINE = "api.targetBaseline";
  private static final String API_EXPERIMENTAL_CAPABILITIES_ACCEPTED =
      "api.experimentalCapabilitiesAccepted";
  private static final String REVIEW_STATUS = "review.status";
  private static final String REVIEW_NOTE = "review.note";
  private static final String REVIEW_SUBMISSION_ID = "review.submission.id";
  private static final String REVIEW_SUBMISSION_SHA256 = "review.submission.sha256";
  private static final String REVIEW_PRE_REVIEW_STATUS = "review.preReview.status";
  private static final String REVIEW_PRE_REVIEW_SHA256 = "review.preReview.sha256";
  private static final String REVIEW_REVIEWER_KEY_ID = "review.reviewer.keyId";
  private static final String REVIEW_REVIEWER_POLICY = "review.reviewer.policy";
  private static final String REVIEW_RECEIPT_FINGERPRINT_SHA256 =
      "review.receipt.fingerprint.sha256";
  private static final String REVIEW_DECISION_REASON_SHA256 = "review.decision.reason.sha256";
  private static final String REVIEW_RESUBMISSION_OF = "review.resubmissionOf";
  private static final String REVIEW_NON_PRODUCTION = "review.nonProduction";
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
   * @param productionMetadata production channel, support, deprecation, and advisory metadata
   * @param maintenanceMetadata first-party maintenance policy metadata
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
    Objects.requireNonNull(reviewReceipt, "reviewReceipt");
    Objects.requireNonNull(changelog, "changelog");
    screenshots = normalizeScreenshots(screenshots);
    Objects.requireNonNull(productionMetadata, "productionMetadata");
    Objects.requireNonNull(maintenanceMetadata, "maintenanceMetadata");
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
            new AppCatalogCompatibilityMetadata(
                removeOptional(properties, MINIMUM_CRYPTA_VERSION).orElse(null),
                removeOptional(properties, MAXIMUM_CRYPTA_VERSION).orElse(null),
                parseApiCompatibility(properties)),
            parseReview(properties),
            parseReviewReceipt(properties),
            new AppCatalogChangelog(
                removeOptional(properties, CHANGELOG_SUMMARY),
                removeOptional(properties, CHANGELOG_URI)
                    .map(value -> parseUri(value, CHANGELOG_URI))),
            parseScreenshots(properties),
            parseProductionMetadata(properties),
            parseMaintenanceMetadata(properties),
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

  private static AppApiCompatibilityMetadata parseApiCompatibility(Map<String, String> properties) {
    Integer minimumVersion = parseOptionalPositiveInteger(properties, API_MINIMUM_VERSION);
    Integer maximumTestedVersion =
        parseOptionalPositiveInteger(properties, API_MAXIMUM_TESTED_VERSION);
    List<String> optionalCapabilities =
        parseOptionalCapabilities(
            removeOptional(properties, API_OPTIONAL_CAPABILITIES).orElse(null));
    AppApiCompatibilityMetadata.TargetStability targetStability =
        removeOptional(properties, API_TARGET_STABILITY)
            .map(AppCatalogEntryDescriptor::parseTargetStability)
            .orElse(null);
    Optional<String> targetBaseline = removeOptional(properties, API_TARGET_BASELINE);
    Optional<String> experimentalCapabilitiesAcceptedText =
        removeOptional(properties, API_EXPERIMENTAL_CAPABILITIES_ACCEPTED);
    boolean experimentalCapabilitiesAccepted =
        experimentalCapabilitiesAcceptedText
            .map(AppCatalogEntryDescriptor::parseExperimentalCapabilitiesAccepted)
            .orElse(false);
    try {
      return new AppApiCompatibilityMetadata(
          minimumVersion,
          maximumTestedVersion,
          optionalCapabilities,
          targetStability,
          targetStability != null,
          targetBaseline.orElse(null),
          targetBaseline.isPresent(),
          experimentalCapabilitiesAccepted,
          experimentalCapabilitiesAcceptedText.isPresent());
    } catch (IllegalArgumentException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_ENTRY, exception.getMessage(), exception);
    }
  }

  private static AppApiCompatibilityMetadata.TargetStability parseTargetStability(String value) {
    try {
      return AppApiCompatibilityMetadata.TargetStability.parse(value);
    } catch (IllegalArgumentException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_ENTRY, exception.getMessage(), exception);
    }
  }

  private static Integer parseOptionalPositiveInteger(Map<String, String> properties, String key) {
    Optional<String> value = removeOptional(properties, key);
    if (value.isEmpty()) {
      return null;
    }
    try {
      int parsed = Integer.parseInt(value.get());
      if (parsed <= 0) {
        throw AppCatalogSidecars.invalidEntry(key + " must be a positive integer");
      }
      return parsed;
    } catch (NumberFormatException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_ENTRY,
          "invalid " + key + ": " + value.get(),
          exception);
    }
  }

  private static boolean parseExperimentalCapabilitiesAccepted(String value) {
    String normalized = value.toLowerCase(java.util.Locale.ROOT);
    if (normalized.equals("true")) {
      return true;
    }
    if (normalized.equals("false")) {
      return false;
    }
    throw AppCatalogSidecars.invalidEntry(
        "invalid " + API_EXPERIMENTAL_CAPABILITIES_ACCEPTED + ": " + value);
  }

  private static List<String> parseOptionalCapabilities(String rawCapabilities) {
    if (rawCapabilities == null || rawCapabilities.isBlank()) {
      return List.of();
    }
    List<String> capabilities = new ArrayList<>();
    for (String capability : rawCapabilities.split(",", -1)) {
      capabilities.add(capability.trim());
    }
    return capabilities;
  }

  private static AppCatalogReviewMetadata parseReview(Map<String, String> properties) {
    Optional<String> statusText = removeOptional(properties, REVIEW_STATUS);
    AppCatalogReviewStatus status =
        statusText
            .map(value -> AppCatalogReviewStatus.parse(value, REVIEW_STATUS))
            .orElse(AppCatalogReviewStatus.UNREVIEWED);
    return new AppCatalogReviewMetadata(
        status,
        removeOptional(properties, REVIEW_NOTE),
        removeOptional(properties, REVIEW_SUBMISSION_ID),
        removeOptional(properties, REVIEW_SUBMISSION_SHA256),
        removeOptional(properties, REVIEW_PRE_REVIEW_STATUS),
        removeOptional(properties, REVIEW_PRE_REVIEW_SHA256),
        removeOptional(properties, REVIEW_REVIEWER_KEY_ID),
        removeOptional(properties, REVIEW_REVIEWER_POLICY),
        removeOptional(properties, REVIEW_RECEIPT_FINGERPRINT_SHA256),
        removeOptional(properties, REVIEW_DECISION_REASON_SHA256),
        removeOptional(properties, REVIEW_RESUBMISSION_OF),
        removeOptional(properties, REVIEW_NON_PRODUCTION)
            .map(AppCatalogEntryDescriptor::parseReviewNonProduction)
            .orElse(false));
  }

  private static Optional<AppReviewReceipt> parseReviewReceipt(Map<String, String> properties) {
    boolean present =
        properties.keySet().stream().anyMatch(key -> key.startsWith("review.receipt."));
    if (!present) {
      return Optional.empty();
    }
    return Optional.of(AppReviewReceiptIO.parseProperties(properties, ""));
  }

  private static boolean parseReviewNonProduction(String value) {
    String normalized =
        AppCatalogSidecars.requireBoundedSingleLine(
                value, REVIEW_NON_PRODUCTION, AppCatalogSidecars.INVALID_CATALOG_ENTRY, 8)
            .toLowerCase(java.util.Locale.ROOT);
    if (normalized.equals("true")) {
      return true;
    }
    if (normalized.equals("false")) {
      return false;
    }
    throw AppCatalogSidecars.invalidEntry(REVIEW_NON_PRODUCTION + " must be true or false");
  }

  private static AppCatalogProductionMetadata parseProductionMetadata(
      Map<String, String> properties) {
    Optional<String> channelText = removeOptional(properties, CHANNEL_PROPERTY);
    Optional<String> supportStatusText = removeOptional(properties, SUPPORT_STATUS);
    Optional<String> deprecationStatusText = removeOptional(properties, DEPRECATION_STATUS);
    Optional<String> deprecationMessage = removeOptional(properties, DEPRECATION_MESSAGE);
    Optional<String> replacementAppId = removeOptional(properties, REPLACEMENT_APP_ID);
    List<AppCatalogSecurityAdvisory> advisories = parseSecurityAdvisories(properties);
    boolean declared =
        channelText.isPresent()
            || supportStatusText.isPresent()
            || deprecationStatusText.isPresent()
            || deprecationMessage.isPresent()
            || replacementAppId.isPresent()
            || !advisories.isEmpty();
    return new AppCatalogProductionMetadata(
        channelText.map(value -> AppCatalogChannel.parse(value, CHANNEL_PROPERTY)).orElse(null),
        supportStatusText
            .map(value -> AppCatalogSupportStatus.parse(value, SUPPORT_STATUS))
            .orElse(null),
        deprecationStatusText
            .map(value -> AppCatalogDeprecationStatus.parse(value, DEPRECATION_STATUS))
            .orElse(null),
        deprecationMessage,
        replacementAppId,
        advisories,
        declared);
  }

  private static AppCatalogMaintenanceMetadata parseMaintenanceMetadata(
      Map<String, String> properties) {
    Optional<String> owner = removeOptional(properties, MAINTENANCE_OWNER);
    Optional<URI> ownerUri =
        removeOptional(properties, MAINTENANCE_OWNER_URI)
            .map(value -> parseUri(value, MAINTENANCE_OWNER_URI));
    Optional<String> supportLevelText = removeOptional(properties, MAINTENANCE_SUPPORT_LEVEL);
    Optional<String> dataSchemaPolicyText =
        removeOptional(properties, MAINTENANCE_DATA_SCHEMA_POLICY);
    Optional<String> migrationPolicyText = removeOptional(properties, MAINTENANCE_MIGRATION_POLICY);
    Optional<String> backupRestoreText = removeOptional(properties, MAINTENANCE_BACKUP_RESTORE);
    Optional<String> securityPolicyText = removeOptional(properties, MAINTENANCE_SECURITY_POLICY);
    Optional<String> deprecationPolicyText =
        removeOptional(properties, MAINTENANCE_DEPRECATION_POLICY);
    Optional<URI> supportUri =
        removeOptional(properties, MAINTENANCE_SUPPORT_URI)
            .map(value -> parseUri(value, MAINTENANCE_SUPPORT_URI));
    boolean declared =
        owner.isPresent()
            || ownerUri.isPresent()
            || supportLevelText.isPresent()
            || dataSchemaPolicyText.isPresent()
            || migrationPolicyText.isPresent()
            || backupRestoreText.isPresent()
            || securityPolicyText.isPresent()
            || deprecationPolicyText.isPresent()
            || supportUri.isPresent();
    return new AppCatalogMaintenanceMetadata(
        owner,
        ownerUri,
        supportLevelText.map(
            value ->
                AppCatalogMaintenanceMetadata.SupportLevel.parse(value, MAINTENANCE_SUPPORT_LEVEL)),
        dataSchemaPolicyText.map(
            value ->
                AppCatalogMaintenanceMetadata.DataSchemaPolicy.parse(
                    value, MAINTENANCE_DATA_SCHEMA_POLICY)),
        migrationPolicyText.map(
            value ->
                AppCatalogMaintenanceMetadata.MigrationPolicy.parse(
                    value, MAINTENANCE_MIGRATION_POLICY)),
        backupRestoreText.map(
            value ->
                AppCatalogMaintenanceMetadata.BackupRestoreSupport.parse(
                    value, MAINTENANCE_BACKUP_RESTORE)),
        securityPolicyText.map(
            value ->
                AppCatalogMaintenanceMetadata.SecurityPolicy.parse(
                    value, MAINTENANCE_SECURITY_POLICY)),
        deprecationPolicyText.map(
            value ->
                AppCatalogMaintenanceMetadata.DeprecationPolicy.parse(
                    value, MAINTENANCE_DEPRECATION_POLICY)),
        supportUri,
        declared);
  }

  private static List<AppCatalogSecurityAdvisory> parseSecurityAdvisories(
      Map<String, String> properties) {
    Optional<String> rawIds = removeOptional(properties, SECURITY_ADVISORIES);
    if (rawIds.isEmpty() || rawIds.orElseThrow().isBlank()) {
      return List.of();
    }
    List<AppCatalogSecurityAdvisory> advisories = new ArrayList<>();
    for (String rawId : rawIds.orElseThrow().split(",", -1)) {
      String advisoryId = AppCatalogSecurityAdvisory.normalizeId(rawId.trim(), SECURITY_ADVISORIES);
      String uriKey = SECURITY_ADVISORY_PREFIX + advisoryId + SECURITY_ADVISORY_URI_SUFFIX;
      advisories.add(
          new AppCatalogSecurityAdvisory(
              advisoryId, parseUri(removeRequired(properties, uriKey), uriKey)));
    }
    return List.copyOf(advisories);
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

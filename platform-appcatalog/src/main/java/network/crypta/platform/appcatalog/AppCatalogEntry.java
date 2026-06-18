package network.crypta.platform.appcatalog;

import java.net.URI;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;
import network.crypta.platform.appdist.AppBundleManifest;

/**
 * One app artifact advertised by a signed catalog.
 *
 * <p>The entry stores the normalized app identity, display metadata, permissions, and the exact ZIP
 * artifact contract that must be satisfied before installation. Optional store metadata such as
 * homepage links, category tags, review notes, permission rationales, compatibility hints,
 * screenshots, and changelog references is advisory display input for operators. Catalog installers
 * use the declared size and SHA-256 digest as the first artifact gate, then verify the extracted
 * signed bundle independently through {@code platform-appdist}.
 *
 * <p>Instances are immutable and safe to expose through the Platform API after the containing
 * catalog has been signature-verified. The record validates that artifact URIs use an accepted
 * local/remote scheme, that size is non-negative and below the catalog safety cap, and that only
 * ZIP artifacts are accepted for this PR. Permission strings are normalized to lower case and
 * deduplicated while preserving declaration order; they are descriptive hints until a later
 * permissions-enforcement layer consumes them.
 *
 * @param appId normalized AppHost-compatible application identifier
 * @param name human-readable application name
 * @param version application version expected in the extracted bundle manifest
 * @param summary short operator-facing description
 * @param homepage optional operator-facing project homepage URI
 * @param source optional operator-facing source-code URI
 * @param license optional license identifier or short license name
 * @param categories normalized catalog category tags
 * @param compatibility advisory compatibility metadata
 * @param review advisory human-review metadata
 * @param reviewReceipt optional independently signed review receipt
 * @param changelog optional change metadata for this catalog version
 * @param screenshots optional screenshot URIs displayed as links
 * @param productionMetadata production channel, support, deprecation, and advisory metadata
 * @param maintenanceMetadata first-party maintenance policy metadata
 * @param bundleUri absolute local or remote URI for the ZIP bundle artifact
 * @param bundleSha256 lowercase SHA-256 digest of the ZIP artifact bytes
 * @param bundleSizeBytes exact artifact size in bytes
 * @param bundleType artifact type, currently {@code zip}
 * @param permissions normalized catalog permission hints
 * @param permissionRationales permission-keyed rationale text for install/update review
 */
public record AppCatalogEntry(
    String appId,
    String name,
    String version,
    String summary,
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
    URI bundleUri,
    String bundleSha256,
    long bundleSizeBytes,
    String bundleType,
    List<String> permissions,
    Map<String, String> permissionRationales) {
  /** Artifact type supported by PR-195 catalog installs. */
  public static final String ZIP_BUNDLE_TYPE = "zip";

  private static final Pattern PERMISSION_PATTERN =
      Pattern.compile("[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?");
  private static final int MAX_LICENSE_CHARS = 128;
  private static final int MAX_CATEGORY_CHARS = 64;
  private static final int MAX_PERMISSION_RATIONALE_CHARS = 512;
  private static final int MAX_SCREENSHOT_COUNT = 8;

  /**
   * Creates a validated catalog entry.
   *
   * <p>The canonical constructor applies the same validation used when parsing a signed catalog. It
   * does not fetch or inspect the artifact; it only validates the catalog's authenticated metadata
   * so later download and extraction stages can enforce that metadata deterministically.
   *
   * @param appId normalized AppHost-compatible application identifier
   * @param name human-readable application name shown in catalog listings
   * @param version application version expected in the extracted bundle manifest
   * @param summary short operator-facing description from the catalog
   * @param homepage optional operator-facing project homepage URI
   * @param source optional operator-facing source-code URI
   * @param license optional license identifier or short license name
   * @param categories normalized catalog category tags
   * @param compatibility advisory compatibility metadata
   * @param review advisory human-review metadata
   * @param reviewReceipt optional independently signed review receipt
   * @param changelog optional change metadata for this catalog version
   * @param screenshots optional screenshot URIs displayed as links
   * @param productionMetadata production channel, support, deprecation, and advisory metadata
   * @param maintenanceMetadata first-party maintenance policy metadata
   * @param bundleUri absolute local or remote URI for the ZIP bundle artifact
   * @param bundleSha256 lowercase SHA-256 digest of the ZIP artifact bytes
   * @param bundleSizeBytes exact artifact size in bytes
   * @param bundleType artifact type, currently {@code zip}
   * @param permissions normalized catalog permission hints
   * @param permissionRationales permission-keyed rationale text for install/update review
   * @throws AppCatalogException if the entry contains unsupported or unsafe metadata
   */
  public AppCatalogEntry {
    appId = normalizeAppId(appId);
    String fieldPrefix = "app." + appId + ".";
    name = AppCatalogSidecars.requireNonBlankSingleLine(name, "app." + appId + ".name", code());
    version =
        AppCatalogSidecars.requireNonBlankSingleLine(version, "app." + appId + ".version", code());
    summary =
        AppCatalogSidecars.requireNonBlankSingleLine(summary, "app." + appId + ".summary", code());
    Objects.requireNonNull(homepage, "homepage");
    homepage = homepage.map(rawUri -> normalizeMetadataUri(rawUri, fieldPrefix + "homepage"));
    Objects.requireNonNull(source, "source");
    source = source.map(rawUri -> normalizeMetadataUri(rawUri, fieldPrefix + "source"));
    Objects.requireNonNull(license, "license");
    license =
        license.map(
            rawValue ->
                AppCatalogSidecars.requireBoundedSingleLine(
                    rawValue, fieldPrefix + "license", code(), MAX_LICENSE_CHARS));
    categories = normalizeCategories(categories, appId);
    Objects.requireNonNull(compatibility, "compatibility");
    Objects.requireNonNull(review, "review");
    Objects.requireNonNull(reviewReceipt, "reviewReceipt");
    Objects.requireNonNull(changelog, "changelog");
    screenshots = normalizeScreenshots(screenshots, appId);
    Objects.requireNonNull(productionMetadata, "productionMetadata");
    Objects.requireNonNull(maintenanceMetadata, "maintenanceMetadata");
    bundleUri = AppCatalogSidecars.requireSafeArtifactUri(Objects.requireNonNull(bundleUri));
    bundleSha256 =
        AppCatalogSidecars.requireLowercaseSha256(bundleSha256, "app." + appId + ".bundle.sha256");
    if (bundleSizeBytes < 0L) {
      throw AppCatalogSidecars.invalidEntry("app." + appId + ".bundle.size.bytes must be >= 0");
    }
    if (bundleSizeBytes > AppCatalogSidecars.MAX_ARTIFACT_BYTES) {
      throw AppCatalogSidecars.invalidEntry(
          "app." + appId + ".bundle.size.bytes exceeds the safety cap");
    }
    bundleType =
        AppCatalogSidecars.requireNonBlankSingleLine(
                bundleType, "app." + appId + ".bundle.type", code())
            .toLowerCase(Locale.ROOT);
    if (!ZIP_BUNDLE_TYPE.equals(bundleType)) {
      throw AppCatalogSidecars.invalidEntry(
          "unsupported app." + appId + ".bundle.type: " + bundleType);
    }
    permissions = normalizePermissions(permissions, appId);
    permissionRationales = normalizePermissionRationales(permissionRationales, permissions, appId);
  }

  /**
   * Creates a catalog entry with advisory store metadata and an optional review receipt.
   *
   * <p>This overload preserves existing callers that predate production-channel metadata. Entries
   * created this way use the backward-compatible {@code stable}/{@code supported} defaults.
   * Nullable store metadata parameters are converted to absent optional values before the canonical
   * constructor validates and normalizes them.
   *
   * @param appId normalized AppHost-compatible application identifier
   * @param name human-readable application name shown in catalog listings
   * @param version application version expected in the extracted bundle manifest
   * @param summary short operator-facing description from the catalog
   * @param homepage nullable operator-facing project homepage URI
   * @param source nullable operator-facing source-code URI
   * @param license nullable license identifier or short license name
   * @param categories normalized catalog category tags
   * @param compatibility advisory compatibility metadata
   * @param review advisory human-review metadata
   * @param reviewReceipt nullable independently signed review receipt
   * @param changelog optional change metadata for this catalog version
   * @param screenshots optional screenshot URIs displayed as links
   * @param bundleUri absolute local or remote URI for the ZIP bundle artifact
   * @param bundleSha256 lowercase SHA-256 digest of the ZIP artifact bytes
   * @param bundleSizeBytes exact artifact size in bytes
   * @param bundleType artifact type, currently {@code zip}
   * @param permissions normalized catalog permission hints
   * @param permissionRationales permission-keyed rationale text for install/update review
   */
  public AppCatalogEntry(
      String appId,
      String name,
      String version,
      String summary,
      URI homepage,
      URI source,
      String license,
      List<String> categories,
      AppCatalogCompatibilityMetadata compatibility,
      AppCatalogReviewMetadata review,
      AppReviewReceipt reviewReceipt,
      AppCatalogChangelog changelog,
      List<URI> screenshots,
      URI bundleUri,
      String bundleSha256,
      long bundleSizeBytes,
      String bundleType,
      List<String> permissions,
      Map<String, String> permissionRationales) {
    this(
        appId,
        name,
        version,
        summary,
        homepage,
        source,
        license,
        categories,
        compatibility,
        review,
        reviewReceipt,
        changelog,
        screenshots,
        AppCatalogProductionMetadata.DEFAULT,
        AppCatalogMaintenanceMetadata.EMPTY,
        bundleUri,
        bundleSha256,
        bundleSizeBytes,
        bundleType,
        permissions,
        permissionRationales);
  }

  /**
   * Creates a catalog entry with production and first-party maintenance metadata.
   *
   * <p>This overload is used by parser and writer code that needs to preserve v5 maintenance policy
   * fields while still accepting nullable optional display values.
   *
   * @param appId normalized AppHost-compatible application identifier
   * @param name human-readable application name shown in catalog listings
   * @param version application version expected in the extracted bundle manifest
   * @param summary short operator-facing description from the catalog
   * @param homepage nullable operator-facing project homepage URI
   * @param source nullable operator-facing source-code URI
   * @param license nullable license identifier or short license name
   * @param categories normalized catalog category tags
   * @param compatibility advisory compatibility metadata
   * @param review advisory human-review metadata
   * @param reviewReceipt nullable independently signed review receipt
   * @param changelog optional change metadata for this catalog version
   * @param screenshots optional screenshot URIs displayed as links
   * @param productionMetadata production channel, support, deprecation, and advisory metadata
   * @param maintenanceMetadata first-party maintenance policy metadata
   * @param bundleUri absolute local or remote URI for the ZIP bundle artifact
   * @param bundleSha256 lowercase SHA-256 digest of the ZIP artifact bytes
   * @param bundleSizeBytes exact artifact size in bytes
   * @param bundleType artifact type, currently {@code zip}
   * @param permissions normalized catalog permission hints
   * @param permissionRationales permission-keyed rationale text for install/update review
   */
  public AppCatalogEntry(
      String appId,
      String name,
      String version,
      String summary,
      URI homepage,
      URI source,
      String license,
      List<String> categories,
      AppCatalogCompatibilityMetadata compatibility,
      AppCatalogReviewMetadata review,
      AppReviewReceipt reviewReceipt,
      AppCatalogChangelog changelog,
      List<URI> screenshots,
      AppCatalogProductionMetadata productionMetadata,
      AppCatalogMaintenanceMetadata maintenanceMetadata,
      URI bundleUri,
      String bundleSha256,
      long bundleSizeBytes,
      String bundleType,
      List<String> permissions,
      Map<String, String> permissionRationales) {
    this(
        appId,
        name,
        version,
        summary,
        Optional.ofNullable(homepage),
        Optional.ofNullable(source),
        Optional.ofNullable(license),
        categories,
        compatibility,
        review,
        Optional.ofNullable(reviewReceipt),
        changelog,
        screenshots,
        productionMetadata,
        maintenanceMetadata,
        bundleUri,
        bundleSha256,
        bundleSizeBytes,
        bundleType,
        permissions,
        permissionRationales);
  }

  /**
   * Creates a catalog entry with advisory store metadata and an optional review receipt.
   *
   * <p>Use this overload when controlled parser or writer code has already resolved optional
   * catalog fields to nullable values and may need to attach an independently signed review
   * receipt. All nullable metadata parameters are converted to absent optional values before
   * validation.
   *
   * @param appId normalized AppHost-compatible application identifier
   * @param name human-readable application name shown in catalog listings
   * @param version application version expected in the extracted bundle manifest
   * @param summary short operator-facing description from the catalog
   * @param homepage nullable operator-facing project homepage URI
   * @param source nullable operator-facing source-code URI
   * @param license nullable license identifier or short license name
   * @param categories normalized catalog category tags
   * @param compatibility advisory compatibility metadata
   * @param review advisory human-review metadata
   * @param reviewReceipt nullable independently signed review receipt
   * @param changelog optional change metadata for this catalog version
   * @param screenshots optional screenshot URIs displayed as links
   * @param productionMetadata production channel, support, deprecation, and advisory metadata
   * @param bundleUri absolute local or remote URI for the ZIP bundle artifact
   * @param bundleSha256 lowercase SHA-256 digest of the ZIP artifact bytes
   * @param bundleSizeBytes exact artifact size in bytes
   * @param bundleType artifact type, currently {@code zip}
   * @param permissions normalized catalog permission hints
   * @param permissionRationales permission-keyed rationale text for install/update review
   */
  public AppCatalogEntry(
      String appId,
      String name,
      String version,
      String summary,
      URI homepage,
      URI source,
      String license,
      List<String> categories,
      AppCatalogCompatibilityMetadata compatibility,
      AppCatalogReviewMetadata review,
      AppReviewReceipt reviewReceipt,
      AppCatalogChangelog changelog,
      List<URI> screenshots,
      AppCatalogProductionMetadata productionMetadata,
      URI bundleUri,
      String bundleSha256,
      long bundleSizeBytes,
      String bundleType,
      List<String> permissions,
      Map<String, String> permissionRationales) {
    this(
        appId,
        name,
        version,
        summary,
        Optional.ofNullable(homepage),
        Optional.ofNullable(source),
        Optional.ofNullable(license),
        categories,
        compatibility,
        review,
        Optional.ofNullable(reviewReceipt),
        changelog,
        screenshots,
        productionMetadata,
        AppCatalogMaintenanceMetadata.EMPTY,
        bundleUri,
        bundleSha256,
        bundleSizeBytes,
        bundleType,
        permissions,
        permissionRationales);
  }

  /**
   * Creates a catalog entry with production and first-party maintenance metadata and no review
   * receipt.
   *
   * @param appId normalized AppHost-compatible application identifier
   * @param name human-readable application name shown in catalog listings
   * @param version application version expected in the extracted bundle manifest
   * @param summary short operator-facing description from the catalog
   * @param homepage nullable operator-facing project homepage URI
   * @param source nullable operator-facing source-code URI
   * @param license nullable license identifier or short license name
   * @param categories normalized catalog category tags
   * @param compatibility advisory compatibility metadata
   * @param review advisory human-review metadata
   * @param changelog optional change metadata for this catalog version
   * @param screenshots optional screenshot URIs displayed as links
   * @param productionMetadata production channel, support, deprecation, and advisory metadata
   * @param maintenanceMetadata first-party maintenance policy metadata
   * @param bundleUri absolute local or remote URI for the ZIP bundle artifact
   * @param bundleSha256 lowercase SHA-256 digest of the ZIP artifact bytes
   * @param bundleSizeBytes exact artifact size in bytes
   * @param bundleType artifact type, currently {@code zip}
   * @param permissions normalized catalog permission hints
   * @param permissionRationales permission-keyed rationale text for install/update review
   */
  public AppCatalogEntry(
      String appId,
      String name,
      String version,
      String summary,
      URI homepage,
      URI source,
      String license,
      List<String> categories,
      AppCatalogCompatibilityMetadata compatibility,
      AppCatalogReviewMetadata review,
      AppCatalogChangelog changelog,
      List<URI> screenshots,
      AppCatalogProductionMetadata productionMetadata,
      AppCatalogMaintenanceMetadata maintenanceMetadata,
      URI bundleUri,
      String bundleSha256,
      long bundleSizeBytes,
      String bundleType,
      List<String> permissions,
      Map<String, String> permissionRationales) {
    this(
        appId,
        name,
        version,
        summary,
        homepage,
        source,
        license,
        categories,
        compatibility,
        review,
        null,
        changelog,
        screenshots,
        productionMetadata,
        maintenanceMetadata,
        bundleUri,
        bundleSha256,
        bundleSizeBytes,
        bundleType,
        permissions,
        permissionRationales);
  }

  /**
   * Creates a catalog entry with advisory store metadata and no signed review receipt.
   *
   * <p>This overload preserves existing controlled callers that construct rich catalog entries
   * before independent review receipts were added. Nullable store metadata parameters are converted
   * to absent optional values before the canonical constructor validates and normalizes them.
   *
   * @param appId normalized AppHost-compatible application identifier
   * @param name human-readable application name shown in catalog listings
   * @param version application version expected in the extracted bundle manifest
   * @param summary short operator-facing description from the catalog
   * @param homepage nullable operator-facing project homepage URI
   * @param source nullable operator-facing source-code URI
   * @param license nullable license identifier or short license name
   * @param categories normalized catalog category tags
   * @param compatibility advisory compatibility metadata
   * @param review advisory human-review metadata
   * @param changelog optional change metadata for this catalog version
   * @param screenshots optional screenshot URIs displayed as links
   * @param productionMetadata production channel, support, deprecation, and advisory metadata
   * @param bundleUri absolute local or remote URI for the ZIP bundle artifact
   * @param bundleSha256 lowercase SHA-256 digest of the ZIP artifact bytes
   * @param bundleSizeBytes exact artifact size in bytes
   * @param bundleType artifact type, currently {@code zip}
   * @param permissions normalized catalog permission hints
   * @param permissionRationales permission-keyed rationale text for install/update review
   */
  public AppCatalogEntry(
      String appId,
      String name,
      String version,
      String summary,
      URI homepage,
      URI source,
      String license,
      List<String> categories,
      AppCatalogCompatibilityMetadata compatibility,
      AppCatalogReviewMetadata review,
      AppCatalogChangelog changelog,
      List<URI> screenshots,
      AppCatalogProductionMetadata productionMetadata,
      URI bundleUri,
      String bundleSha256,
      long bundleSizeBytes,
      String bundleType,
      List<String> permissions,
      Map<String, String> permissionRationales) {
    this(
        appId,
        name,
        version,
        summary,
        homepage,
        source,
        license,
        categories,
        compatibility,
        review,
        null,
        changelog,
        screenshots,
        productionMetadata,
        bundleUri,
        bundleSha256,
        bundleSizeBytes,
        bundleType,
        permissions,
        permissionRationales);
  }

  /**
   * Creates a catalog entry with advisory store metadata and no signed review receipt.
   *
   * <p>This overload preserves existing controlled callers that construct rich catalog entries
   * before production-channel metadata was added. Nullable store metadata parameters are converted
   * to absent optional values before the canonical constructor validates and normalizes them.
   *
   * @param appId normalized AppHost-compatible application identifier
   * @param name human-readable application name shown in catalog listings
   * @param version application version expected in the extracted bundle manifest
   * @param summary short operator-facing description from the catalog
   * @param homepage nullable operator-facing project homepage URI
   * @param source nullable operator-facing source-code URI
   * @param license nullable license identifier or short license name
   * @param categories normalized catalog category tags
   * @param compatibility advisory compatibility metadata
   * @param review advisory human-review metadata
   * @param changelog optional change metadata for this catalog version
   * @param screenshots optional screenshot URIs displayed as links
   * @param bundleUri absolute local or remote URI for the ZIP bundle artifact
   * @param bundleSha256 lowercase SHA-256 digest of the ZIP artifact bytes
   * @param bundleSizeBytes exact artifact size in bytes
   * @param bundleType artifact type, currently {@code zip}
   * @param permissions normalized catalog permission hints
   * @param permissionRationales permission-keyed rationale text for install/update review
   */
  public AppCatalogEntry(
      String appId,
      String name,
      String version,
      String summary,
      URI homepage,
      URI source,
      String license,
      List<String> categories,
      AppCatalogCompatibilityMetadata compatibility,
      AppCatalogReviewMetadata review,
      AppCatalogChangelog changelog,
      List<URI> screenshots,
      URI bundleUri,
      String bundleSha256,
      long bundleSizeBytes,
      String bundleType,
      List<String> permissions,
      Map<String, String> permissionRationales) {
    this(
        appId,
        name,
        version,
        summary,
        Optional.ofNullable(homepage),
        Optional.ofNullable(source),
        Optional.ofNullable(license),
        categories,
        compatibility,
        review,
        Optional.empty(),
        changelog,
        screenshots,
        AppCatalogProductionMetadata.DEFAULT,
        AppCatalogMaintenanceMetadata.EMPTY,
        bundleUri,
        bundleSha256,
        bundleSizeBytes,
        bundleType,
        permissions,
        permissionRationales);
  }

  /**
   * Creates a catalog entry using the original minimal v1 metadata shape.
   *
   * <p>This constructor keeps existing tests and controlled callers source-compatible while the
   * record grows optional store metadata. All optional fields default to absent or empty advisory
   * metadata.
   *
   * @param appId normalized AppHost-compatible application identifier
   * @param name human-readable application name shown in catalog listings
   * @param version application version expected in the extracted bundle manifest
   * @param summary short operator-facing description from the catalog
   * @param bundleUri absolute local or remote URI for the ZIP bundle artifact
   * @param bundleSha256 lowercase SHA-256 digest of the ZIP artifact bytes
   * @param bundleSizeBytes exact artifact size in bytes
   * @param bundleType artifact type, currently {@code zip}
   * @param permissions normalized catalog permission hints
   */
  public AppCatalogEntry(
      String appId,
      String name,
      String version,
      String summary,
      URI bundleUri,
      String bundleSha256,
      long bundleSizeBytes,
      String bundleType,
      List<String> permissions) {
    this(
        appId,
        name,
        version,
        summary,
        Optional.empty(),
        Optional.empty(),
        Optional.empty(),
        List.of(),
        AppCatalogCompatibilityMetadata.EMPTY,
        AppCatalogReviewMetadata.EMPTY,
        Optional.empty(),
        AppCatalogChangelog.EMPTY,
        List.of(),
        AppCatalogProductionMetadata.DEFAULT,
        AppCatalogMaintenanceMetadata.EMPTY,
        bundleUri,
        bundleSha256,
        bundleSizeBytes,
        bundleType,
        permissions,
        Map.of());
  }

  boolean hasStoreMetadata() {
    return homepage.isPresent()
        || source.isPresent()
        || license.isPresent()
        || !categories.isEmpty()
        || compatibility.minimumCryptaVersion() != null
        || compatibility.apiCompatibility().declared()
        || review.hasCatalogFields()
        || reviewReceipt.isPresent()
        || !changelog.isEmpty()
        || !screenshots.isEmpty()
        || !permissionRationales.isEmpty();
  }

  boolean hasProductionMetadata() {
    return compatibility.maximumCryptaVersion() != null || productionMetadata.hasCatalogFields();
  }

  boolean hasMaintenanceMetadata() {
    return maintenanceMetadata.hasCatalogFields();
  }

  boolean hasSubmissionReviewMetadata() {
    return review.hasSubmissionReviewFields();
  }

  /**
   * Normalizes an app id using the signed-bundle manifest rules.
   *
   * <p>Catalog entries and extracted signed-bundle manifests must agree on this normalized value
   * before AppHost receives a staged bundle. This keeps catalog routing, artifact matching, and
   * local install paths aligned on one path-safe identifier grammar.
   *
   * @param appId raw catalog app identifier from metadata or a caller
   * @return normalized AppHost-compatible identifier
   * @throws AppCatalogException if the id is not supported by AppHost
   */
  public static String normalizeAppId(String appId) throws AppCatalogException {
    try {
      return AppBundleManifest.normalizeAppId(appId);
    } catch (IllegalArgumentException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_ENTRY, exception.getMessage(), exception);
    }
  }

  private static String code() {
    return AppCatalogSidecars.INVALID_CATALOG_ENTRY;
  }

  private static URI normalizeMetadataUri(URI uri, String fieldName) {
    return AppCatalogSidecars.requireSafeMetadataUri(uri, fieldName);
  }

  private static List<String> normalizeCategories(List<String> categories, String appId)
      throws AppCatalogException {
    Objects.requireNonNull(categories, "categories");
    Set<String> normalized = new LinkedHashSet<>();
    for (String category : categories) {
      normalized.add(normalizeCategory(category, "app." + appId + ".categories"));
    }
    return List.copyOf(normalized);
  }

  static String normalizeCategory(String category, String fieldName) throws AppCatalogException {
    String value =
        AppCatalogSidecars.requireBoundedSingleLine(category, fieldName, code(), MAX_CATEGORY_CHARS)
            .toLowerCase(Locale.ROOT);
    if (!PERMISSION_PATTERN.matcher(value).matches()) {
      throw AppCatalogSidecars.invalidEntry("invalid category for " + fieldName + ": " + value);
    }
    return value;
  }

  private static List<URI> normalizeScreenshots(List<URI> screenshots, String appId)
      throws AppCatalogException {
    Objects.requireNonNull(screenshots, "screenshots");
    if (screenshots.size() > MAX_SCREENSHOT_COUNT) {
      throw AppCatalogSidecars.invalidEntry(
          "app." + appId + ".screenshot count exceeds the safety cap");
    }
    List<URI> normalized =
        screenshots.stream()
            .map(
                uri ->
                    AppCatalogSidecars.requireSafeMetadataUri(uri, "app." + appId + ".screenshot"))
            .toList();
    return List.copyOf(normalized);
  }

  private static List<String> normalizePermissions(List<String> permissions, String appId)
      throws AppCatalogException {
    Objects.requireNonNull(permissions, "permissions");
    Set<String> normalized = new LinkedHashSet<>();
    for (String permission : permissions) {
      normalized.add(normalizePermission(permission, "app." + appId + ".permissions"));
    }
    return List.copyOf(normalized);
  }

  static String normalizePermission(String permission, String fieldName)
      throws AppCatalogException {
    String value =
        AppCatalogSidecars.requireNonBlankSingleLine(permission, fieldName, code())
            .toLowerCase(Locale.ROOT);
    if (!PERMISSION_PATTERN.matcher(value).matches()) {
      throw AppCatalogSidecars.invalidEntry("invalid permission for " + fieldName + ": " + value);
    }
    return value;
  }

  private static Map<String, String> normalizePermissionRationales(
      Map<String, String> permissionRationales, List<String> permissions, String appId)
      throws AppCatalogException {
    Objects.requireNonNull(permissionRationales, "permissionRationales");
    Set<String> declaredPermissions = new LinkedHashSet<>(permissions);
    Map<String, String> byPermission = new LinkedHashMap<>();
    for (Map.Entry<String, String> entry : permissionRationales.entrySet()) {
      String permission =
          normalizePermission(entry.getKey(), "app." + appId + ".permissions.rationale permission");
      if (!declaredPermissions.contains(permission)) {
        throw AppCatalogSidecars.invalidEntry(
            "app."
                + appId
                + ".permissions.rationale."
                + permission
                + " has no declared permission");
      }
      String rationale =
          AppCatalogSidecars.requireBoundedSingleLine(
              entry.getValue(),
              "app." + appId + ".permissions.rationale." + permission,
              code(),
              MAX_PERMISSION_RATIONALE_CHARS);
      String previous = byPermission.putIfAbsent(permission, rationale);
      if (previous != null) {
        throw AppCatalogSidecars.invalidEntry("duplicate permission rationale for " + permission);
      }
    }
    Map<String, String> ordered = new LinkedHashMap<>();
    for (String permission : permissions) {
      String rationale = byPermission.get(permission);
      if (rationale != null) {
        ordered.put(permission, rationale);
      }
    }
    return Collections.unmodifiableMap(new LinkedHashMap<>(ordered));
  }
}

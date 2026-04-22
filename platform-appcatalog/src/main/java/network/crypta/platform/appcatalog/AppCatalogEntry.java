package network.crypta.platform.appcatalog;

import java.net.URI;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;
import network.crypta.platform.appdist.AppBundleManifest;

/**
 * One app artifact advertised by a signed catalog.
 *
 * <p>The entry stores the normalized app identity, display metadata, permissions, and the exact ZIP
 * artifact contract that must be satisfied before installation. Catalog installers use the declared
 * size and SHA-256 digest as the first artifact gate, then verify the extracted signed bundle
 * independently through {@code platform-appdist}.
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
 * @param bundleUri absolute local or remote URI for the ZIP bundle artifact
 * @param bundleSha256 lowercase SHA-256 digest of the ZIP artifact bytes
 * @param bundleSizeBytes exact artifact size in bytes
 * @param bundleType artifact type, currently {@code zip}
 * @param permissions normalized catalog permission hints
 */
public record AppCatalogEntry(
    String appId,
    String name,
    String version,
    String summary,
    URI bundleUri,
    String bundleSha256,
    long bundleSizeBytes,
    String bundleType,
    List<String> permissions) {
  /** Artifact type supported by PR-195 catalog installs. */
  public static final String ZIP_BUNDLE_TYPE = "zip";

  private static final Pattern PERMISSION_PATTERN =
      Pattern.compile("[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?");

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
   * @param bundleUri absolute local or remote URI for the ZIP bundle artifact
   * @param bundleSha256 lowercase SHA-256 digest of the ZIP artifact bytes
   * @param bundleSizeBytes exact artifact size in bytes
   * @param bundleType artifact type, currently {@code zip}
   * @param permissions normalized catalog permission hints
   * @throws AppCatalogException if the entry contains unsupported or unsafe metadata
   */
  public AppCatalogEntry {
    appId = normalizeAppId(appId);
    name = AppCatalogSidecars.requireNonBlankSingleLine(name, "app." + appId + ".name", code());
    version =
        AppCatalogSidecars.requireNonBlankSingleLine(version, "app." + appId + ".version", code());
    summary =
        AppCatalogSidecars.requireNonBlankSingleLine(summary, "app." + appId + ".summary", code());
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

  private static List<String> normalizePermissions(List<String> permissions, String appId)
      throws AppCatalogException {
    Objects.requireNonNull(permissions, "permissions");
    Set<String> normalized = new LinkedHashSet<>();
    for (String permission : permissions) {
      String value =
          AppCatalogSidecars.requireNonBlankSingleLine(
                  permission, "app." + appId + ".permissions", code())
              .toLowerCase(Locale.ROOT);
      if (!PERMISSION_PATTERN.matcher(value).matches()) {
        throw AppCatalogSidecars.invalidEntry("invalid permission for app." + appId + ": " + value);
      }
      normalized.add(value);
    }
    return List.copyOf(normalized);
  }
}

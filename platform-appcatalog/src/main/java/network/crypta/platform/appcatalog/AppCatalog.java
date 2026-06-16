package network.crypta.platform.appcatalog;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import network.crypta.platform.appdist.AppBundleManifest;

/**
 * Verified app catalog content.
 *
 * <p>The catalog preserves the deterministic entry order declared by {@code catalog.entries}. It is
 * immutable after construction, and every entry is keyed by the normalized AppHost app id used by
 * installation and update flows. Runtime code should treat an instance as a point-in-time view of
 * one signed catalog payload, not as a live subscription to the source URI.
 *
 * <p>The constructor performs the same validation that the parser performs after signature
 * verification, which makes the record safe for tests and controlled tooling to instantiate
 * directly. Catalog ids use the signed-bundle app-id grammar so they can also serve as on-disk
 * directory names and API path segments. Entry lists are copied, duplicate app ids are rejected,
 * and no mutable collections from callers are retained.
 *
 * @param version catalog schema version
 * @param catalogId stable catalog identifier used by API paths and local storage
 * @param name human-readable catalog name
 * @param generatedAt timestamp declared by the catalog producer
 * @param securityPolicy catalog-level security advisory and exact-version denylist policy
 * @param entries catalog entries in declared deterministic order
 */
public record AppCatalog(
    int version,
    String catalogId,
    String name,
    Instant generatedAt,
    AppCatalogSecurityPolicy securityPolicy,
    List<AppCatalogEntry> entries) {
  /** Minimal signed-catalog schema. */
  public static final int VERSION_MINIMAL = 1;

  /** Signed-catalog schema that can carry optional app-store metadata. */
  public static final int VERSION_STORE_METADATA = 2;

  /** Signed-catalog schema that can carry production channel and support metadata. */
  public static final int VERSION_PRODUCTION_CHANNELS = 3;

  /** Signed-catalog schema that can carry enforceable catalog-level security policy. */
  public static final int VERSION_SECURITY_POLICY = 4;

  /** Signed-catalog schema that can carry first-party app maintenance policy metadata. */
  public static final int VERSION_FIRST_PARTY_MAINTENANCE = 5;

  /**
   * Creates a catalog without root security policy.
   *
   * <p>This overload preserves source compatibility for tests and tooling that construct v1-v3
   * catalog models directly. New v4 policy-aware callers should use the canonical constructor.
   *
   * @param version catalog schema version
   * @param catalogId stable catalog identifier used by API paths and local storage
   * @param name human-readable catalog name shown to operators
   * @param generatedAt timestamp declared by the catalog producer
   * @param entries catalog entries in declared deterministic order
   */
  public AppCatalog(
      int version,
      String catalogId,
      String name,
      Instant generatedAt,
      List<AppCatalogEntry> entries) {
    this(version, catalogId, name, generatedAt, AppCatalogSecurityPolicy.EMPTY, entries);
  }

  /**
   * Creates a validated immutable catalog.
   *
   * <p>The canonical constructor normalizes {@code catalogId}, trims and validates the display
   * name, copies {@code entries}, and rejects duplicate normalized app ids. It does not verify
   * signatures or artifact metadata; callers must only construct instances from already
   * authenticated bytes or from trusted test/tooling fixtures.
   *
   * @param version catalog schema version
   * @param catalogId stable catalog identifier used by API paths and local storage
   * @param name human-readable catalog name shown to operators
   * @param generatedAt timestamp declared by the catalog producer
   * @param securityPolicy catalog-level security advisory and exact-version denylist policy
   * @param entries catalog entries in declared deterministic order
   * @throws AppCatalogException if the catalog header or entry set is invalid
   */
  public AppCatalog {
    if (isUnsupportedVersion(version)) {
      throw AppCatalogSidecars.invalidEntry("unsupported catalog.version: " + version);
    }
    catalogId = normalizeCatalogId(catalogId);
    name =
        AppCatalogSidecars.requireNonBlankSingleLine(
            name, "catalog.name", AppCatalogSidecars.INVALID_CATALOG_ENTRY);
    Objects.requireNonNull(generatedAt, "generatedAt");
    Objects.requireNonNull(securityPolicy, "securityPolicy");
    if (securityPolicy.hasCatalogFields() && version < VERSION_SECURITY_POLICY) {
      throw AppCatalogSidecars.invalidEntry(
          "catalog.version 4 is required when security policy metadata is present");
    }
    entries = List.copyOf(Objects.requireNonNull(entries, "entries"));
    for (AppCatalogEntry entry : entries) {
      if (entry.hasMaintenanceMetadata() && version < VERSION_FIRST_PARTY_MAINTENANCE) {
        throw AppCatalogSidecars.invalidEntry(
            "catalog.version 5 is required when maintenance metadata is present");
      }
    }
    rejectDuplicateEntries(entries);
  }

  static boolean isUnsupportedVersion(int version) {
    return version != VERSION_MINIMAL
        && version != VERSION_STORE_METADATA
        && version != VERSION_PRODUCTION_CHANNELS
        && version != VERSION_SECURITY_POLICY
        && version != VERSION_FIRST_PARTY_MAINTENANCE;
  }

  /**
   * Finds one catalog entry by normalized app id.
   *
   * <p>The lookup accepts raw caller input and normalizes it with the same rules used for catalog
   * parsing and AppHost installation. A syntactically invalid id is rejected before the entry list
   * is scanned; a valid but absent id returns {@link Optional#empty()}.
   *
   * @param appId raw or normalized app identifier from a caller
   * @return matching catalog entry, when present in the verified catalog
   * @throws AppCatalogException if {@code appId} is not a valid AppHost id
   */
  public Optional<AppCatalogEntry> entry(String appId) throws AppCatalogException {
    String normalizedAppId = AppCatalogEntry.normalizeAppId(appId);
    return entries.stream().filter(entry -> entry.appId().equals(normalizedAppId)).findFirst();
  }

  /**
   * Normalizes a catalog id using the same path-safe grammar as app ids.
   *
   * <p>Catalog ids are used as API path components and source-store directory names, so this method
   * deliberately reuses the signed-bundle id grammar instead of accepting arbitrary catalog labels.
   * The result is trimmed, lower-case, and safe to compare as a stable identifier.
   *
   * @param catalogId raw catalog identifier from a catalog or API path
   * @return normalized lower-case catalog id
   * @throws AppCatalogException if the id is not path-safe
   */
  public static String normalizeCatalogId(String catalogId) throws AppCatalogException {
    try {
      return AppBundleManifest.normalizeAppId(catalogId);
    } catch (IllegalArgumentException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_ENTRY, exception.getMessage(), exception);
    }
  }

  private static void rejectDuplicateEntries(List<AppCatalogEntry> entries)
      throws AppCatalogException {
    Map<String, AppCatalogEntry> byId = new LinkedHashMap<>();
    for (AppCatalogEntry entry : entries) {
      AppCatalogEntry previous = byId.putIfAbsent(entry.appId(), entry);
      if (previous != null) {
        throw AppCatalogSidecars.invalidEntry("duplicate catalog entry app id: " + entry.appId());
      }
    }
  }
}

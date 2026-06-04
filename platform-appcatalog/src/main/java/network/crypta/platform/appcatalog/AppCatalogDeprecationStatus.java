package network.crypta.platform.appcatalog;

import java.util.Locale;

/**
 * Deprecation lifecycle status declared by a signed app catalog entry.
 *
 * <p>This status lets a publisher distinguish an ordinary app release from an app that is still
 * visible only to explain migration, retirement, or support history. Catalog parsers and API
 * handlers expose the value alongside optional deprecation messages and replacement app ids so
 * operators can understand why an app is no longer an ordinary update target.
 *
 * <p>The status is authenticated metadata, not an artifact-verification result. Deprecated and
 * retired entries still require the same catalog signature, bundle digest, signed bundle, trusted
 * review receipt, and compatibility checks as any other entry. The app-update service also treats
 * non-{@link #NONE} statuses as policy blockers for automatic processing, which prevents a retired
 * or migration-only entry from being selected as a routine upgrade.
 *
 * <p>The enum is immutable and thread-safe. Use {@link #parse(String, String)} for catalog and
 * descriptor input, and use {@link #catalogValue()} when writing signed catalog properties or
 * Platform API summaries.
 */
public enum AppCatalogDeprecationStatus {
  /**
   * The catalog entry is not deprecated.
   *
   * <p>This is the default for legacy catalogs and for current production entries that do not need
   * migration messaging. A {@code none} status by itself does not make an entry installable; normal
   * signature, digest, review, compatibility, and update-policy checks still apply.
   */
  NONE("none"),

  /**
   * The catalog entry is deprecated but still visible for migration guidance.
   *
   * <p>Use this status when an app is being replaced or phased out but the catalog should still
   * describe the existing artifact, explain the operator-visible consequence, or point to a
   * replacement app id. Automatic update policy treats this as non-routine metadata.
   */
  DEPRECATED("deprecated"),

  /**
   * The catalog entry is retired and should be treated as historical metadata.
   *
   * <p>Use this status when the app should remain discoverable only for audit, support, or
   * migration records. Clients should present it as a retired entry rather than a candidate for
   * ordinary installation or automatic update selection.
   */
  RETIRED("retired");

  private final String catalogValue;

  AppCatalogDeprecationStatus(String catalogValue) {
    this.catalogValue = catalogValue;
  }

  /**
   * Parses a strict deprecation-status token from catalog or descriptor text.
   *
   * <p>The parser applies the same bounded single-line validation used by other catalog sidecar
   * fields before matching supported values case-insensitively. Passing the source field name keeps
   * parser and developer-tool diagnostics tied to the exact property that supplied the bad value.
   *
   * @param value catalog or descriptor text such as {@code none}, {@code deprecated}, or {@code
   *     retired}
   * @param fieldName field name used in diagnostics for malformed or unsupported input
   * @return matching normalized deprecation status for production metadata
   * @throws AppCatalogException if the token is blank, multi-line, too long, or unsupported
   */
  public static AppCatalogDeprecationStatus parse(String value, String fieldName) {
    String normalized =
        AppCatalogSidecars.requireBoundedSingleLine(
                value, fieldName, AppCatalogSidecars.INVALID_CATALOG_ENTRY, 32)
            .toLowerCase(Locale.ROOT);
    for (AppCatalogDeprecationStatus status : values()) {
      if (status.catalogValue.equals(normalized)) {
        return status;
      }
    }
    throw AppCatalogSidecars.invalidEntry("unsupported " + fieldName + ": " + value);
  }

  /**
   * Returns the lower-case catalog and API token for this deprecation status.
   *
   * <p>The returned value is the stable serialized representation used in signed catalog
   * properties, generated descriptor files, and Platform API JSON. Callers should prefer this
   * method over enum names so wire output stays independent of Java naming conventions.
   *
   * @return stable serialized deprecation status used in catalogs and API responses
   */
  public String catalogValue() {
    return catalogValue;
  }
}

package network.crypta.platform.appcatalog;

import java.util.Locale;

/**
 * Operator-facing support status carried by signed catalog metadata.
 *
 * <p>Support status describes the publisher's maintenance posture for a catalog entry. It is
 * separate from the release channel: a stable-channel app can be in maintenance mode, and a beta
 * app can still be actively supported for preview testers. Catalog APIs and the Web Shell surface
 * this value so operators can decide whether an app fits their risk tolerance.
 *
 * <p>The status is authenticated catalog metadata, but it is not an installation or trust verdict.
 * Catalog signature checks, bundle digest checks, signed bundle verification, trusted review
 * receipts, compatibility metadata, and app-update policy still control enforcement. The production
 * metadata helper treats {@link #DEPRECATED} and {@link #UNSUPPORTED} as automatic-update blockers;
 * other support states remain advisory unless a higher-level policy adds stricter handling.
 *
 * <p>The enum is immutable and thread-safe. Use {@link #parse(String, String)} for catalog and
 * descriptor input, and use {@link #catalogValue()} for signed catalog properties or Platform API
 * summaries.
 */
public enum AppCatalogSupportStatus {
  /**
   * Actively supported for production use.
   *
   * <p>This is the default for legacy catalogs and ordinary production entries. It does not bypass
   * review, compatibility, or artifact verification; it only records that the publisher presents
   * the entry as currently supported.
   */
  SUPPORTED("supported"),

  /**
   * Supported for fixes but not active feature development.
   *
   * <p>Maintenance entries remain valid catalog entries, but the status tells operators to expect
   * conservative changes such as fixes, compatibility updates, or migration support rather than
   * regular feature work.
   */
  MAINTENANCE("maintenance"),

  /**
   * Experimental and intended for operator-aware testing.
   *
   * <p>This status communicates preview risk independently of channel selection. It does not by
   * itself block automatic handling for a stable-channel entry, so publishers should pair it with
   * an appropriate release channel and review evidence when automation policy matters.
   */
  EXPERIMENTAL("experimental"),

  /**
   * Deprecated but retained to point operators at replacement metadata.
   *
   * <p>Deprecated support status means the entry should be visible for migration or compatibility
   * history, not treated as a routine automatic update target. Catalog entries can combine this
   * with a deprecation message or replacement app id for clearer operator guidance.
   */
  DEPRECATED("deprecated"),

  /**
   * Unsupported and not eligible for automatic update actions.
   *
   * <p>Unsupported entries remain signed metadata, but clients should present them as outside
   * normal maintenance. The app-update policy helper excludes this status from routine automatic
   * staging or application.
   */
  UNSUPPORTED("unsupported");

  private final String catalogValue;

  AppCatalogSupportStatus(String catalogValue) {
    this.catalogValue = catalogValue;
  }

  /**
   * Parses a strict support-status token from catalog or descriptor text.
   *
   * <p>The parser first applies bounded single-line validation, then matches the supported
   * serialized tokens case-insensitively. Passing the source field name keeps parser, writer, and
   * developer-tool diagnostics tied to the property that supplied the value.
   *
   * @param value catalog or descriptor text such as {@code supported}, {@code maintenance}, or
   *     {@code unsupported}
   * @param fieldName field name used in diagnostics for malformed or unsupported input
   * @return matching normalized support status for production metadata
   * @throws AppCatalogException if the token is blank, multi-line, too long, or unsupported
   */
  public static AppCatalogSupportStatus parse(String value, String fieldName) {
    String normalized =
        AppCatalogSidecars.requireBoundedSingleLine(
                value, fieldName, AppCatalogSidecars.INVALID_CATALOG_ENTRY, 32)
            .toLowerCase(Locale.ROOT);
    for (AppCatalogSupportStatus status : values()) {
      if (status.catalogValue.equals(normalized)) {
        return status;
      }
    }
    throw AppCatalogSidecars.invalidEntry("unsupported " + fieldName + ": " + value);
  }

  /**
   * Returns the lower-case catalog and API token for this support status.
   *
   * <p>The returned value is the stable serialized representation used in signed catalog
   * properties, generated descriptor files, and Platform API JSON. Callers should use it instead of
   * enum names when producing catalog or API output.
   *
   * @return stable serialized support status used in catalogs and API responses
   */
  public String catalogValue() {
    return catalogValue;
  }
}

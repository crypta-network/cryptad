package network.crypta.platform.appcatalog;

import java.util.Locale;

/**
 * Lifecycle status for catalog-level security advisory records.
 *
 * <p>Inactive advisory statuses remain visible for operator context, but only {@link #ACTIVE}
 * advisories can add warning or blocking decisions by themselves. Exact version denylist entries
 * remain enforceable while they are present in the signed catalog policy.
 *
 * <p>Status is part of the signed advisory record, not a local override. Catalog authors use it to
 * keep advisory history available without leaving old warning or block actions active forever.
 * Nodes still display resolved and withdrawn records in redacted policy summaries so operators can
 * understand why a catalog changed. If a catalog keeps an exact denylist entry, that denylist is
 * the active enforcement signal even when the referenced advisory record has moved out of the
 * active lifecycle.
 */
public enum AppCatalogSecurityStatus {
  /**
   * The advisory is current and contributes to security decisions.
   *
   * <p>Entry references to active advisories can produce informational, warning, block, or denylist
   * decisions depending on the advisory action.
   */
  ACTIVE("active"),

  /**
   * The advisory has been resolved but remains visible for history.
   *
   * <p>Resolved advisory records no longer gate entry references by themselves. They may still be
   * referenced by a separate exact-version denylist entry.
   */
  RESOLVED("resolved"),

  /**
   * The advisory has been withdrawn but remains visible for history.
   *
   * <p>Withdrawn records document a removed or superseded advisory. They do not create entry-level
   * gates unless a signed denylist entry remains present.
   */
  WITHDRAWN("withdrawn");

  private final String catalogValue;

  AppCatalogSecurityStatus(String catalogValue) {
    this.catalogValue = catalogValue;
  }

  /**
   * Parses an advisory status token.
   *
   * <p>The parser accepts only bounded, single-line status tokens and normalizes case before
   * matching. Unknown lifecycle values fail closed so catalog consumers do not silently treat a new
   * status as either active or inactive without an explicit code change.
   *
   * @param value status text read from a signed advisory record
   * @param fieldName field name used in bounded parser diagnostics
   * @return matching advisory lifecycle status
   */
  public static AppCatalogSecurityStatus parse(String value, String fieldName) {
    String normalized =
        AppCatalogSidecars.requireBoundedSingleLine(
                value, fieldName, AppCatalogSidecars.INVALID_CATALOG_ENTRY, 32)
            .toLowerCase(Locale.ROOT);
    for (AppCatalogSecurityStatus status : values()) {
      if (status.catalogValue.equals(normalized)) {
        return status;
      }
    }
    throw AppCatalogSidecars.invalidEntry("unsupported " + fieldName + ": " + value);
  }

  /**
   * Returns the stable catalog and JSON value.
   *
   * <p>The returned token is the canonical spelling used in catalog properties and redacted policy
   * summaries. Keep it stable for Web Shell rendering and release-certification evidence.
   *
   * @return lower-case status token used in catalog and JSON output
   */
  public String catalogValue() {
    return catalogValue;
  }
}

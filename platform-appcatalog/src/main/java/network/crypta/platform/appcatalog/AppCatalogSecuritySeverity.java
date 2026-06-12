package network.crypta.platform.appcatalog;

import java.util.Locale;

/**
 * Stable severity values for signed catalog security-policy advisories.
 *
 * <p>The values are intentionally small because they are written into signed catalog properties,
 * Platform API summaries, Web Shell warnings, and release-certification evidence. {@link #NONE} is
 * reserved for derived decisions with no matching advisory; catalog advisory records must use one
 * of the non-none severities.
 *
 * <p>Severity does not decide whether an operation is blocked. Enforcement comes from {@code
 * AppCatalogSecurityAction} and the accumulated decision booleans. The severity rank is used only
 * to choose the most serious display value when multiple advisories or denylists contribute to one
 * decision. Keeping that distinction explicit prevents a high-severity informational advisory from
 * becoming a policy block by accident.
 */
public enum AppCatalogSecuritySeverity {
  /**
   * No advisory applies to the evaluated app version.
   *
   * <p>This value is valid for derived decisions only. Signed advisory records reject it so every
   * catalog-level advisory has a visible operator severity.
   */
  NONE("none", 0),

  /**
   * Low-severity advisory metadata.
   *
   * <p>Use for minor security notes where the advisory action, not the severity, determines whether
   * any acknowledgement or gate applies.
   */
  LOW("low", 1),

  /**
   * Medium-severity advisory metadata.
   *
   * <p>Use for issues that deserve operator attention but may still be informational, warning-only,
   * or blocking depending on the advisory action.
   */
  MEDIUM("medium", 2),

  /**
   * High-severity advisory metadata.
   *
   * <p>Use for serious advisories where Web Shell and API summaries should make the risk prominent
   * while still honoring the explicit action for enforcement.
   */
  HIGH("high", 3),

  /**
   * Critical advisory metadata.
   *
   * <p>Use for the most serious advisory records, including denylist-driven responses. The rank
   * makes critical win when several advisory severities are combined.
   */
  CRITICAL("critical", 4);

  private final String catalogValue;
  private final int rank;

  AppCatalogSecuritySeverity(String catalogValue, int rank) {
    this.catalogValue = catalogValue;
    this.rank = rank;
  }

  /**
   * Parses a severity token from signed catalog text.
   *
   * <p>This parser is for catalog-level advisory records. It accepts the same bounded token syntax
   * as {@link #parse(String, String)} but rejects {@link #NONE}, because a signed advisory with no
   * severity would be ambiguous in operator summaries and release evidence.
   *
   * @param value severity text read from a signed catalog property
   * @param fieldName field name used in bounded parser diagnostics
   * @return matching catalog severity, excluding {@link #NONE}
   */
  public static AppCatalogSecuritySeverity parseCatalog(String value, String fieldName) {
    AppCatalogSecuritySeverity severity = parse(value, fieldName);
    if (severity == NONE) {
      throw AppCatalogSidecars.invalidEntry(fieldName + " must not be none");
    }
    return severity;
  }

  /**
   * Parses a severity token for catalog or derived decision use.
   *
   * <p>The method is intentionally strict: values must be bounded, single-line tokens and must
   * match one of the stable lower-case catalog values after case normalization. Unknown values fail
   * closed through catalog validation rather than being downgraded to a default severity.
   *
   * @param value severity text read from catalog or decision input
   * @param fieldName field name used in bounded parser diagnostics
   * @return matching severity for the normalized token
   */
  public static AppCatalogSecuritySeverity parse(String value, String fieldName) {
    String normalized =
        AppCatalogSidecars.requireBoundedSingleLine(
                value, fieldName, AppCatalogSidecars.INVALID_CATALOG_ENTRY, 32)
            .toLowerCase(Locale.ROOT);
    for (AppCatalogSecuritySeverity severity : values()) {
      if (severity.catalogValue.equals(normalized)) {
        return severity;
      }
    }
    throw AppCatalogSidecars.invalidEntry("unsupported " + fieldName + ": " + value);
  }

  /**
   * Returns the stable catalog and JSON value.
   *
   * <p>The value is the canonical token written by catalog output and exposed by redacted decision
   * summaries. It is stable because Web Shell, CLI inspection, and certification evidence compare
   * the string directly.
   *
   * @return lower-case severity token used in catalog and JSON output
   */
  public String catalogValue() {
    return catalogValue;
  }

  @SuppressWarnings("unused")
  int rank() {
    return rank;
  }

  static AppCatalogSecuritySeverity max(
      AppCatalogSecuritySeverity left, AppCatalogSecuritySeverity right) {
    return left.rank >= right.rank ? left : right;
  }
}

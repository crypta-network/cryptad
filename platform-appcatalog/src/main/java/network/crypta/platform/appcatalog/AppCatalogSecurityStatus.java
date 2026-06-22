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
   * Internal prepared response that should not gate production installs by itself.
   *
   * <p>Draft records are accepted so dry-run catalogs and deterministic drills can represent the
   * full production response lifecycle, but they do not create entry-level enforcement decisions.
   */
  DRAFT("draft", false),

  /**
   * Confirmed signal under triage before public publication.
   *
   * <p>Detected records are visible lifecycle metadata only. A catalog that needs production
   * containment should move the advisory to {@link #ACTIVE} or {@link #PUBLISHED} and add exact
   * denylist entries where needed.
   */
  DETECTED("detected", false),

  /**
   * The advisory is current and contributes to security decisions.
   *
   * <p>Entry references to active advisories can produce informational, warning, block, or denylist
   * decisions depending on the advisory action.
   */
  ACTIVE("active", true),

  /**
   * Public advisory that contributes to security decisions.
   *
   * <p>This is equivalent to {@link #ACTIVE} for enforcement and exists so production runbooks can
   * use the more communication-oriented lifecycle term without losing backward compatibility with
   * existing {@code active} catalogs.
   */
  PUBLISHED("published", true),

  /**
   * Advisory replaced by a later advisory.
   *
   * <p>Superseded records remain displayable for audit history but do not create entry-level gates
   * unless an exact denylist entry remains present in the signed catalog.
   */
  SUPERSEDED("superseded", false),

  /**
   * The advisory has been resolved but remains visible for history.
   *
   * <p>Resolved advisory records no longer gate entry references by themselves. They may still be
   * referenced by a separate exact-version denylist entry.
   */
  RESOLVED("resolved", false),

  /**
   * The advisory has been withdrawn but remains visible for history.
   *
   * <p>Withdrawn records document a removed or superseded advisory. They do not create entry-level
   * gates unless a signed denylist entry remains present.
   */
  WITHDRAWN("withdrawn", false),

  /**
   * Public correction that retracts an advisory.
   *
   * <p>Retracted records are equivalent to withdrawn records for enforcement and remain available
   * for release notes, operator history, and certification drills.
   */
  RETRACTED("retracted", false);

  private final String catalogValue;
  private final boolean enforcesAdvisoryAction;

  AppCatalogSecurityStatus(String catalogValue, boolean enforcesAdvisoryAction) {
    this.catalogValue = catalogValue;
    this.enforcesAdvisoryAction = enforcesAdvisoryAction;
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

  /**
   * Returns whether entry-level references to this advisory contribute enforcement decisions.
   *
   * <p>Exact denylist entries remain enforceable while present in the signed catalog regardless of
   * this value. This flag applies only to app entries that reference a catalog-level advisory
   * without an exact denylist match.
   *
   * @return true when advisory references should produce decisions
   */
  boolean enforcesAdvisoryAction() {
    return enforcesAdvisoryAction;
  }
}

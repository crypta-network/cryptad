package network.crypta.platform.appcatalog;

import java.util.Locale;

/**
 * Enforcement action declared by a catalog-level security advisory.
 *
 * <p>Catalog security policy uses these values to translate signed advisory metadata into concrete
 * install, update, and automation gates. The enum is intentionally small and exact: parser output,
 * Platform API JSON, Web Shell rendering, and release-certification evidence all use the same
 * lower-case catalog tokens. When several active advisories apply to one app version, the highest
 * ranked action becomes the display action while the individual boolean gates are still accumulated
 * by {@code AppCatalogSecurityPolicy}. That lets an advisory combination preserve, for example, a
 * warning acknowledgement and an update block at the same time.
 *
 * <p>{@link #DENYLIST} is the strongest action. It represents an exact app-version block and cannot
 * be bypassed by operator acknowledgement or automatic update policy.
 */
public enum AppCatalogSecurityAction {
  /**
   * Display-only advisory metadata.
   *
   * <p>This action keeps the advisory visible in redacted summaries without blocking install,
   * update, stage, apply, or unattended scheduler decisions.
   */
  INFORM("inform", 1),

  /**
   * Requires explicit manual acknowledgement and blocks unattended automation.
   *
   * <p>Operators can proceed with manual install or update only through the separate security
   * acknowledgement path. Automatic staging and applying to remain blocked by default.
   */
  WARN("warn", 2),

  /**
   * Blocks installing the affected app version.
   *
   * <p>This action is for releases that may remain visible for update or uninstall guidance but
   * must not be newly installed from a catalog entry.
   */
  BLOCK_INSTALL("block_install", 3),

  /**
   * Blocks updating, staging, and applying the affected app version.
   *
   * <p>The update lifecycle treats this as a hard gate for manual update, scheduler staging, staged
   * candidate validation, and apply revalidation.
   */
  BLOCK_UPDATE("block_update", 4),

  /**
   * Blocks install, update, stage, apply, and unattended automation.
   *
   * <p>Catalog denylists use this action for exact app-version matches. It is the fail-closed
   * outcome used when an advisory says the version must not be distributed further.
   */
  DENYLIST("denylist", 5);

  private final String catalogValue;
  private final int rank;

  AppCatalogSecurityAction(String catalogValue, int rank) {
    this.catalogValue = catalogValue;
    this.rank = rank;
  }

  /**
   * Parses an advisory action token.
   *
   * <p>The parser accepts only bounded, single-line catalog tokens and normalizes case before
   * lookup. Unknown values fail closed with an invalid-entry exception so signed catalogs cannot
   * smuggle unrecognized behavior into older nodes. Callers pass the field name to keep diagnostics
   * precise without exposing raw catalog bodies outside the parser boundary.
   *
   * @param value action text read from a signed catalog property
   * @param fieldName field name used in bounded parser diagnostics
   * @return matching action with stable gate semantics
   */
  public static AppCatalogSecurityAction parse(String value, String fieldName) {
    String normalized =
        AppCatalogSidecars.requireBoundedSingleLine(
                value, fieldName, AppCatalogSidecars.INVALID_CATALOG_ENTRY, 32)
            .toLowerCase(Locale.ROOT);
    for (AppCatalogSecurityAction action : values()) {
      if (action.catalogValue.equals(normalized)) {
        return action;
      }
    }
    throw AppCatalogSidecars.invalidEntry("unsupported " + fieldName + ": " + value);
  }

  /**
   * Returns the stable catalog and JSON value.
   *
   * <p>The returned token is the canonical spelling written by {@code AppCatalogWriter} and exposed
   * by {@code AppCatalogSecurityDecision.toJsonValue()}. Keep it stable because operators, Web
   * Shell, and release-certification evidence match these values directly.
   *
   * @return lower-case action token used in catalog and API output
   */
  public String catalogValue() {
    return catalogValue;
  }

  @SuppressWarnings("unused")
  int rank() {
    return rank;
  }

  boolean blocksInstall() {
    return this == BLOCK_INSTALL || this == DENYLIST;
  }

  boolean blocksUpdate() {
    return this == BLOCK_UPDATE || this == DENYLIST;
  }

  boolean blocksAutomaticApply() {
    return this == WARN || this == BLOCK_UPDATE || this == DENYLIST;
  }

  boolean requiresAcknowledgement() {
    return this == WARN;
  }

  static AppCatalogSecurityAction strongest(
      AppCatalogSecurityAction left, AppCatalogSecurityAction right) {
    return left.rank >= right.rank ? left : right;
  }
}

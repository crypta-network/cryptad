package network.crypta.platform.appcatalog;

import java.util.Objects;
import java.util.Optional;

/**
 * Exact app-version denylist entry from a signed catalog security policy.
 *
 * <p>The first enforcement implementation intentionally matches only exact {@code appId} and {@code
 * version} pairs. It does not implement semantic-version ranges. Exact matching keeps the first
 * security response layer auditable: a catalog either denies one concrete release or it does not.
 * Update candidates, direct catalog install/update routes, staged apply revalidation, and installed
 * vulnerable-version summaries can all compare the same normalized app id and literal version
 * string.
 *
 * <p>Each entry must reference a known catalog-level advisory. The advisory supplies severity,
 * title, URI, and lifecycle context; the denylist entry supplies the exact release being blocked
 * and operator-safe reason/guidance. Replacement app ids are guidance only. The platform must not
 * silently migrate or uninstall an app because this record is present.
 *
 * @param id denylist id used in signed catalog property names
 * @param appId normalized affected app id for exact matching
 * @param version exact affected app version, matched as a literal token
 * @param advisoryId known catalog-level advisory id explaining this denylist entry
 * @param reason bounded single-line reason safe for operator display
 * @param replacementAppId optional replacement guidance, not automatic migration
 * @param safeUninstallGuidance optional safe uninstall or export guidance
 */
public record AppCatalogVersionDenylistEntry(
    String id,
    String appId,
    String version,
    String advisoryId,
    String reason,
    Optional<String> replacementAppId,
    Optional<String> safeUninstallGuidance) {
  private static final String CATALOG_SECURITY_DENYLIST_PREFIX = "catalog.securityDenylist.";
  private static final String SAFE_UNINSTALL_GUIDANCE = "safeUninstallGuidance";
  private static final int MAX_VERSION_CHARS = 128;
  private static final int MAX_REASON_CHARS = 512;
  private static final int MAX_SAFE_UNINSTALL_CHARS = 512;

  /**
   * Creates a validated exact-version denylist entry.
   *
   * <p>The constructor normalizes ids, bounds all display text to one line, and leaves advisory
   * referential-integrity checks to {@link AppCatalogSecurityPolicy}. Version text is intentionally
   * preserved after bounded validation because the match is exact and catalog-defined.
   *
   * @throws AppCatalogException if any signed field is malformed or unsafe
   */
  public AppCatalogVersionDenylistEntry {
    id = AppCatalogSecurityAdvisory.normalizeId(id, "catalog security denylist id");
    String denylistId = id;
    String denylistFieldPrefix = CATALOG_SECURITY_DENYLIST_PREFIX + denylistId + ".";
    appId = AppCatalogEntry.normalizeAppId(appId);
    version =
        AppCatalogSidecars.requireBoundedSingleLine(
            version,
            denylistFieldPrefix + "version",
            AppCatalogSidecars.INVALID_CATALOG_ENTRY,
            MAX_VERSION_CHARS);
    advisoryId =
        AppCatalogSecurityAdvisory.normalizeId(advisoryId, denylistFieldPrefix + "advisoryId");
    reason =
        AppCatalogSidecars.requireBoundedSingleLine(
            reason,
            denylistFieldPrefix + "reason",
            AppCatalogSidecars.INVALID_CATALOG_ENTRY,
            MAX_REASON_CHARS);
    Objects.requireNonNull(replacementAppId, "replacementAppId");
    replacementAppId = replacementAppId.map(AppCatalogEntry::normalizeAppId);
    Objects.requireNonNull(safeUninstallGuidance, SAFE_UNINSTALL_GUIDANCE);
    safeUninstallGuidance =
        safeUninstallGuidance.map(
            value ->
                AppCatalogSidecars.requireBoundedSingleLine(
                    value,
                    denylistFieldPrefix + SAFE_UNINSTALL_GUIDANCE,
                    AppCatalogSidecars.INVALID_CATALOG_ENTRY,
                    MAX_SAFE_UNINSTALL_CHARS));
  }

  /**
   * Returns whether a candidate id and version are exactly denied by this entry.
   *
   * <p>The candidate app id is normalized with the same rules as catalog entries before comparison.
   * The version string is compared literally. Callers should pass the version from the catalog
   * candidate or installed snapshot without attempting semantic-version expansion.
   *
   * @param candidateAppId app id from a catalog candidate or installed snapshot
   * @param candidateVersion version token from the same candidate or snapshot
   * @return true when both normalized app id and literal version match
   */
  boolean matches(String candidateAppId, String candidateVersion) {
    return appId.equals(AppCatalogEntry.normalizeAppId(candidateAppId))
        && version.equals(candidateVersion);
  }

  /**
   * Converts this denylist entry to redacted JSON-compatible values.
   *
   * <p>The returned map is safe for operator-facing policy summaries and release evidence. It
   * contains identifiers, exact version metadata, reason text, and optional guidance, but not raw
   * catalog payloads, signatures, source paths, staged bundle paths, or fetched content.
   *
   * @return safe denylist metadata without catalog paths or raw payloads
   */
  public java.util.Map<String, Object> toJsonValue() {
    java.util.LinkedHashMap<String, Object> json = java.util.LinkedHashMap.newLinkedHashMap(7);
    json.put("id", id);
    json.put("appId", appId);
    json.put("version", version);
    json.put("advisoryId", advisoryId);
    json.put("reason", reason);
    json.put("replacementAppId", replacementAppId.orElse(null));
    json.put(SAFE_UNINSTALL_GUIDANCE, safeUninstallGuidance.orElse(null));
    return json;
  }
}

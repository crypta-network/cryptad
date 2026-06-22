package network.crypta.platform.appcatalog;

import java.net.URI;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * Catalog-level signed security advisory metadata.
 *
 * <p>This record is policy input, unlike the legacy entry-level {@link AppCatalogSecurityAdvisory}
 * reference. Advisory records describe severity, lifecycle status, and the action that applies when
 * an app entry references the advisory. Exact app-version denylist entries can also point at these
 * records for operator context. The parser validates each field before the record reaches install
 * or update policy so malformed signed metadata fails closed instead of becoming display-only
 * advisory text.
 *
 * <p>Instances are immutable and safe to expose after conversion through {@link #toJsonValue()}.
 * They do not carry catalog signatures, raw catalog payloads, local file paths, or fetched bundle
 * content. Active records can produce enforcement decisions through {@code
 * AppCatalogSecurityPolicy} when an entry references the advisory. Resolved or withdrawn records
 * remain useful as operator history, while exact denylist entries can still cite them for context
 * if the denylist itself is present in the signed catalog.
 *
 * @param id advisory id used in property names and denylist references
 * @param uri safe metadata URI for operator-facing advisory details
 * @param title bounded single-line advisory title shown to operators
 * @param severity deterministic severity used for sorting and display
 * @param status lifecycle status controlling entry-advisory enforcement
 * @param action strongest advisory action while the record is active
 * @param summary bounded single-line advisory summary safe for UI text
 * @param publishedAt advisory publication timestamp from the signed catalog
 * @param updatedAt advisory update timestamp, never before publication time
 * @param replacementAppId optional replacement app guidance, not an automatic migration
 * @param safeUninstallGuidance optional safe uninstall or export-before-delete guidance
 */
public record AppCatalogSecurityAdvisoryRecord(
    String id,
    URI uri,
    String title,
    AppCatalogSecuritySeverity severity,
    AppCatalogSecurityStatus status,
    AppCatalogSecurityAction action,
    String summary,
    Instant publishedAt,
    Instant updatedAt,
    Optional<String> replacementAppId,
    Optional<String> safeUninstallGuidance) {
  private static final String CATALOG_SECURITY_ADVISORY_PREFIX = "catalog.securityAdvisory.";
  private static final String SAFE_UNINSTALL_GUIDANCE = "safeUninstallGuidance";
  private static final int MAX_TITLE_CHARS = 160;
  private static final int MAX_SUMMARY_CHARS = 512;
  private static final int MAX_SAFE_UNINSTALL_CHARS = 512;

  /**
   * Creates a validated catalog-level advisory record.
   *
   * <p>The compact constructor enforces the same bounded-token and bounded-text rules used by the
   * catalog parser. It also rejects {@code none} severity and timestamps where the update time
   * precedes the publication time. Replacement app ids are normalized with the catalog app-id rules
   * so downstream policy and Web Shell guidance compare stable identifiers.
   *
   * @throws AppCatalogException if signed metadata is unsafe, unsupported, or inconsistent
   */
  public AppCatalogSecurityAdvisoryRecord {
    id = AppCatalogSecurityAdvisory.normalizeId(id, "catalog security advisory id");
    String advisoryId = id;
    String advisoryFieldPrefix = CATALOG_SECURITY_ADVISORY_PREFIX + advisoryId + ".";
    uri =
        AppCatalogSidecars.requireSafeMetadataUri(
            Objects.requireNonNull(uri, "uri"), advisoryFieldPrefix + "uri");
    title =
        AppCatalogSidecars.requireBoundedSingleLine(
            title,
            advisoryFieldPrefix + "title",
            AppCatalogSidecars.INVALID_CATALOG_ENTRY,
            MAX_TITLE_CHARS);
    Objects.requireNonNull(severity, "severity");
    if (severity == AppCatalogSecuritySeverity.NONE) {
      throw AppCatalogSidecars.invalidEntry(advisoryFieldPrefix + "severity must not be none");
    }
    Objects.requireNonNull(status, "status");
    Objects.requireNonNull(action, "action");
    summary =
        AppCatalogSidecars.requireBoundedSingleLine(
            summary,
            advisoryFieldPrefix + "summary",
            AppCatalogSidecars.INVALID_CATALOG_ENTRY,
            MAX_SUMMARY_CHARS);
    Objects.requireNonNull(publishedAt, "publishedAt");
    Objects.requireNonNull(updatedAt, "updatedAt");
    if (updatedAt.isBefore(publishedAt)) {
      throw AppCatalogSidecars.invalidEntry(
          advisoryFieldPrefix + "updatedAt must not be before publishedAt");
    }
    Objects.requireNonNull(replacementAppId, "replacementAppId");
    replacementAppId = replacementAppId.map(AppCatalogEntry::normalizeAppId);
    Objects.requireNonNull(safeUninstallGuidance, SAFE_UNINSTALL_GUIDANCE);
    safeUninstallGuidance =
        safeUninstallGuidance.map(
            value ->
                AppCatalogSidecars.requireBoundedSingleLine(
                    value,
                    advisoryFieldPrefix + SAFE_UNINSTALL_GUIDANCE,
                    AppCatalogSidecars.INVALID_CATALOG_ENTRY,
                    MAX_SAFE_UNINSTALL_CHARS));
  }

  boolean active() {
    return status.enforcesAdvisoryAction();
  }

  /**
   * Converts this advisory to redacted JSON-compatible values.
   *
   * <p>The returned map contains only bounded advisory metadata that is safe for Platform API, Web
   * Shell, CLI inspection, and release-certification evidence. Optional values are represented as
   * {@code null} so consumers can distinguish missing guidance from an empty string. The method
   * preserves insertion order to keep generated JSON deterministic.
   *
   * @return safe advisory metadata without raw signatures, payloads, or local paths
   */
  public java.util.Map<String, Object> toJsonValue() {
    java.util.LinkedHashMap<String, Object> json = java.util.LinkedHashMap.newLinkedHashMap(11);
    json.put("id", id);
    json.put("uri", uri.toString());
    json.put("title", title);
    json.put("severity", severity.catalogValue());
    json.put("status", status.catalogValue());
    json.put("action", action.catalogValue());
    json.put("summary", summary);
    json.put("publishedAt", publishedAt.toString());
    json.put("updatedAt", updatedAt.toString());
    json.put("replacementAppId", replacementAppId.orElse(null));
    json.put(SAFE_UNINSTALL_GUIDANCE, safeUninstallGuidance.orElse(null));
    return json;
  }
}

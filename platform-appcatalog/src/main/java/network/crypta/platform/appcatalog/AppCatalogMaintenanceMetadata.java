package network.crypta.platform.appcatalog;

import java.net.URI;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;

/**
 * First-party maintenance policy metadata carried by a signed catalog entry.
 *
 * <p>This record is the signed catalog block that turns a first-party app from a reference artifact
 * into an explicit maintenance commitment. Catalog parsers attach it to {@link AppCatalogEntry}
 * instances, writers use it to decide when v5 catalog properties are required, Platform API
 * summaries expose it to operator UIs, and release-certification tooling checks it for every
 * first-party app. The block deliberately does not repeat release channel, support status,
 * deprecation status, replacement app id, security advisory references, or Crypta daemon version
 * bounds; those fields already live on the catalog entry and remain authoritative.
 *
 * <p>Instances are immutable after construction. Enum values serialize through stable lower-case
 * catalog tokens, optional text is bounded to one line, and optional URIs pass the same display
 * metadata URI policy used elsewhere in app catalogs. Legacy catalogs may omit the entire block.
 * Once any maintenance field appears, the required policy fields must be complete so signed
 * catalogs cannot publish a partial maintenance promise.
 *
 * @param owner maintenance owner responsible for triage, updates, and operator-facing support
 *     posture
 * @param ownerUri optional HTTPS owner information URI that can be shown as catalog metadata
 * @param supportLevel first-party maintenance support level for this app commitment
 * @param dataSchemaPolicy app-data schema policy that describes durable-state expectations
 * @param migrationPolicy app-data migration policy operators should expect during updates
 * @param backupRestore backup/restore support posture for app-owned durable state
 * @param securityPolicy security advisory handling policy for this first-party app
 * @param deprecationPolicy deprecation handling policy for future retirement or replacement
 * @param supportUri optional HTTPS app-specific support URI that can be shown to operators
 * @param declared whether catalog or descriptor input explicitly declared maintenance metadata
 * @see AppCatalogProductionMetadata
 */
public record AppCatalogMaintenanceMetadata(
    Optional<String> owner,
    Optional<URI> ownerUri,
    Optional<SupportLevel> supportLevel,
    Optional<DataSchemaPolicy> dataSchemaPolicy,
    Optional<MigrationPolicy> migrationPolicy,
    Optional<BackupRestoreSupport> backupRestore,
    Optional<SecurityPolicy> securityPolicy,
    Optional<DeprecationPolicy> deprecationPolicy,
    Optional<URI> supportUri,
    boolean declared) {
  private static final int MAX_OWNER_CHARS = 128;
  private static final String TOKEN_NOT_APPLICABLE = "not-applicable";
  private static final String TOKEN_UNSUPPORTED = "unsupported";
  private static final String UNSUPPORTED_FIELD_PREFIX = "unsupported ";

  /**
   * Empty metadata used for legacy catalogs and descriptors without a maintenance block.
   *
   * <p>The instance has no catalog fields and therefore does not force v5 serialization. Parsers
   * use it for old signed catalogs so older app entries can continue to round-trip without
   * inventing a first-party maintenance policy.
   */
  public static final AppCatalogMaintenanceMetadata EMPTY =
      new AppCatalogMaintenanceMetadata(
          Optional.empty(),
          Optional.empty(),
          Optional.empty(),
          Optional.empty(),
          Optional.empty(),
          Optional.empty(),
          Optional.empty(),
          Optional.empty(),
          Optional.empty(),
          false);

  /**
   * Creates validated immutable maintenance metadata.
   *
   * <p>All optional components are normalized before the record is stored. The owner is trimmed and
   * bounded as single-line text, optional owner and support URIs are checked with catalog metadata
   * URI rules, and enum components are expected to have been parsed through their nested {@code
   * parse} helpers. If any component is present, the block becomes declared even when the caller
   * passed {@code declared=false}; all required policy fields must then be present. That
   * fail-closed behavior protects signed catalogs from publishing only an owner URI, support URI,
   * or one enum token without the rest of the policy.
   *
   * @throws NullPointerException if any optional component wrapper is {@code null}
   * @throws AppCatalogException if declared metadata is incomplete, multi-line, too long, or uses
   *     an unsafe URI
   */
  public AppCatalogMaintenanceMetadata {
    Objects.requireNonNull(owner, "owner");
    owner =
        owner.map(
            value ->
                AppCatalogSidecars.requireBoundedSingleLine(
                    value,
                    "maintenance.owner",
                    AppCatalogSidecars.INVALID_CATALOG_ENTRY,
                    MAX_OWNER_CHARS));
    Objects.requireNonNull(ownerUri, "ownerUri");
    ownerUri =
        ownerUri.map(uri -> AppCatalogSidecars.requireSafeMetadataUri(uri, "maintenance.ownerUri"));
    Objects.requireNonNull(supportLevel, "supportLevel");
    Objects.requireNonNull(dataSchemaPolicy, "dataSchemaPolicy");
    Objects.requireNonNull(migrationPolicy, "migrationPolicy");
    Objects.requireNonNull(backupRestore, "backupRestore");
    Objects.requireNonNull(securityPolicy, "securityPolicy");
    Objects.requireNonNull(deprecationPolicy, "deprecationPolicy");
    Objects.requireNonNull(supportUri, "supportUri");
    supportUri =
        supportUri.map(
            uri -> AppCatalogSidecars.requireSafeMetadataUri(uri, "maintenance.supportUri"));

    declared =
        declared
            || owner.isPresent()
            || ownerUri.isPresent()
            || supportLevel.isPresent()
            || dataSchemaPolicy.isPresent()
            || migrationPolicy.isPresent()
            || backupRestore.isPresent()
            || securityPolicy.isPresent()
            || deprecationPolicy.isPresent()
            || supportUri.isPresent();
    if (declared) {
      requirePresent(owner.isPresent(), "maintenance.owner");
      requirePresent(supportLevel.isPresent(), "maintenance.supportLevel");
      requirePresent(dataSchemaPolicy.isPresent(), "maintenance.dataSchemaPolicy");
      requirePresent(migrationPolicy.isPresent(), "maintenance.migrationPolicy");
      requirePresent(backupRestore.isPresent(), "maintenance.backupRestore");
      requirePresent(securityPolicy.isPresent(), "maintenance.securityPolicy");
      requirePresent(deprecationPolicy.isPresent(), "maintenance.deprecationPolicy");
    }
  }

  /**
   * Returns whether this metadata should force catalog schema v5 serialization.
   *
   * <p>A value of {@code false} means the metadata is equivalent to a legacy entry with no
   * first-party maintenance block. A value of {@code true} means parsers or descriptor input
   * explicitly supplied maintenance metadata, or the canonical constructor inferred that a field
   * was present and completed the block.
   *
   * @return {@code true} when a complete maintenance policy block must be emitted
   */
  public boolean hasCatalogFields() {
    return declared;
  }

  private static void requirePresent(boolean present, String fieldName) {
    if (!present) {
      throw AppCatalogSidecars.invalidEntry(
          fieldName + " is required when maintenance metadata is declared");
    }
  }

  private static String normalizeEnumToken(String value, String fieldName) {
    return AppCatalogSidecars.requireBoundedSingleLine(
            value, fieldName, AppCatalogSidecars.INVALID_CATALOG_ENTRY, 64)
        .toLowerCase(Locale.ROOT);
  }

  private static AppCatalogException unsupportedEnumToken(String fieldName, String value) {
    return AppCatalogSidecars.invalidEntry(UNSUPPORTED_FIELD_PREFIX + fieldName + ": " + value);
  }

  /**
   * First-party maintenance support level.
   *
   * <p>The support level describes the project's maintenance commitment for the app itself. It is
   * separate from the production support status on {@link AppCatalogProductionMetadata}: for
   * example, a beta-channel app can still be a local release-candidate commitment, and a stable app
   * can be maintained only for migration support.
   */
  public enum SupportLevel {
    /**
     * Core app maintained as part of the reference daemon operator workflow.
     *
     * <p>Use this for first-party apps that are part of ordinary daemon operation rather than only
     * a platform example or migration aid.
     */
    CORE("core"),
    /**
     * Actively maintained first-party app outside the core operator workflow.
     *
     * <p>This level records an ongoing project commitment without implying that the app is part of
     * the minimal operator surface.
     */
    MAINTAINED("maintained"),
    /**
     * Reference app maintained to document platform behavior.
     *
     * <p>Reference apps are expected to stay useful for developers and operators, but their main
     * purpose is to demonstrate supported app-platform behavior.
     */
    REFERENCE("reference"),
    /**
     * Local release-candidate app with explicit preview scope.
     *
     * <p>This is for first-party apps such as local RC social or trust tooling where the catalog
     * should be clear that the scope is bounded to the local app platform.
     */
    LOCAL_RC("local-rc"),
    /**
     * Preview app that is visible for operator-aware testing.
     *
     * <p>Preview entries can be useful for feedback, but callers should not present them as stable
     * production commitments.
     */
    PREVIEW("preview"),
    /**
     * Maintained only for fixes, compatibility, or migration support.
     *
     * <p>This level is narrower than {@link #MAINTAINED}; it tells operators to expect conservative
     * changes rather than feature development.
     */
    MAINTENANCE("maintenance"),
    /**
     * Deprecated first-party entry retained for migration guidance.
     *
     * <p>Deprecated entries should pair this level with the catalog deprecation metadata that
     * explains replacement or retirement handling.
     */
    DEPRECATED("deprecated"),
    /**
     * Unsupported entry retained only as signed historical metadata.
     *
     * <p>Unsupported first-party entries remain authenticated catalog records, but clients should
     * not present them as maintained or eligible for routine update flows.
     */
    UNSUPPORTED(TOKEN_UNSUPPORTED);

    private final String catalogValue;

    SupportLevel(String catalogValue) {
      this.catalogValue = catalogValue;
    }

    /**
     * Parses a strict maintenance support-level token.
     *
     * <p>The parser applies the shared bounded single-line catalog validation and then matches the
     * lower-case wire token case-insensitively. Callers should pass the exact catalog or descriptor
     * property name so validation failures identify the bad input field.
     *
     * @param value catalog or descriptor token supplied by signed metadata or CLI input
     * @param fieldName field name used in diagnostics for malformed or unsupported tokens
     * @return matching support level used by model objects and API summaries
     * @throws AppCatalogException if the token is blank, multi-line, too long, or unsupported
     */
    public static SupportLevel parse(String value, String fieldName) {
      String normalized = normalizeEnumToken(value, fieldName);
      for (SupportLevel level : values()) {
        if (level.catalogValue.equals(normalized)) {
          return level;
        }
      }
      throw unsupportedEnumToken(fieldName, value);
    }

    /**
     * Returns the stable signed-catalog token.
     *
     * @return lower-case catalog and API value for deterministic serialization
     */
    public String catalogValue() {
      return catalogValue;
    }
  }

  /**
   * First-party app-data schema policy.
   *
   * <p>This policy records how the app relates to durable app-data schema management. It does not
   * store the schema itself; app bundle manifests and app-data migration metadata remain the source
   * for concrete schema versions and migration steps.
   */
  public enum DataSchemaPolicy {
    /** The app stores no durable app-data schema that needs catalog maintenance. */
    STATELESS("stateless"),
    /** The app declares schema metadata but does not require migration handling yet. */
    DECLARED("declared"),
    /** The app declares schema metadata and supported migration behavior. */
    MIGRATABLE("migratable"),
    /** Durable state lives in an external system outside app-data schema migration. */
    EXTERNAL("external"),
    /** The policy is not relevant for this app. */
    NOT_APPLICABLE(TOKEN_NOT_APPLICABLE);

    private final String catalogValue;

    DataSchemaPolicy(String catalogValue) {
      this.catalogValue = catalogValue;
    }

    /**
     * Parses a strict app-data schema policy token.
     *
     * <p>Tokens are normalized to lower case after shared single-line validation. The returned enum
     * is the canonical in-memory value; writers should use {@link #catalogValue()} rather than enum
     * names when producing signed catalog text.
     *
     * @param value catalog or descriptor token supplied by signed metadata or CLI input
     * @param fieldName field name used in diagnostics for malformed or unsupported tokens
     * @return matching data schema policy used by catalog entries
     * @throws AppCatalogException if the token is blank, multi-line, too long, or unsupported
     */
    public static DataSchemaPolicy parse(String value, String fieldName) {
      String normalized = normalizeEnumToken(value, fieldName);
      for (DataSchemaPolicy policy : values()) {
        if (policy.catalogValue.equals(normalized)) {
          return policy;
        }
      }
      throw unsupportedEnumToken(fieldName, value);
    }

    /**
     * Returns the stable signed-catalog token.
     *
     * @return lower-case catalog and API value for deterministic serialization
     */
    public String catalogValue() {
      return catalogValue;
    }
  }

  /**
   * First-party app-data migration policy.
   *
   * <p>The migration policy tells operators what kind of update-time data handling to expect. It is
   * deliberately high-level: concrete migration command metadata and dry-run output stay in the app
   * bundle and update lifecycle evidence, not in this catalog policy block.
   */
  public enum MigrationPolicy {
    /** The app has no migration behavior to run. */
    NONE("none"),
    /** Migration behavior is declared by the app metadata. */
    DECLARED("declared"),
    /** Migration requires dry-run evidence before update apply. */
    DRY_RUN_REQUIRED("dry-run-required"),
    /** Migration requires explicit operator approval. */
    OPERATOR_APPROVED("operator-approved"),
    /** The policy is not relevant for this app. */
    NOT_APPLICABLE(TOKEN_NOT_APPLICABLE);

    private final String catalogValue;

    MigrationPolicy(String catalogValue) {
      this.catalogValue = catalogValue;
    }

    /**
     * Parses a strict migration policy token.
     *
     * <p>The accepted token set is intentionally small so release certification can compare catalog
     * metadata with app-data migration declarations without free-form interpretation.
     *
     * @param value catalog or descriptor token supplied by signed metadata or CLI input
     * @param fieldName field name used in diagnostics for malformed or unsupported tokens
     * @return matching migration policy used by catalog entries
     * @throws AppCatalogException if the token is blank, multi-line, too long, or unsupported
     */
    public static MigrationPolicy parse(String value, String fieldName) {
      String normalized = normalizeEnumToken(value, fieldName);
      for (MigrationPolicy policy : values()) {
        if (policy.catalogValue.equals(normalized)) {
          return policy;
        }
      }
      throw unsupportedEnumToken(fieldName, value);
    }

    /**
     * Returns the stable signed-catalog token.
     *
     * @return lower-case catalog and API value for deterministic serialization
     */
    public String catalogValue() {
      return catalogValue;
    }
  }

  /**
   * First-party app-data backup and restore support policy.
   *
   * <p>This policy describes support expectations for operator-managed app-data backup and restore.
   * It is metadata only; it does not grant an app access to backup payloads and does not expose raw
   * app data through catalog or API responses.
   */
  public enum BackupRestoreSupport {
    /** Backup/restore is not relevant because the app has no durable app data. */
    NOT_APPLICABLE(TOKEN_NOT_APPLICABLE),
    /** The app supports export evidence, but not an import promise. */
    EXPORT_ONLY("export-only"),
    /** The app supports export and import through app-data backup/restore tooling. */
    EXPORT_IMPORT("export-import"),
    /** Backup/restore is supported through operator-mediated workflows. */
    OPERATOR_SUPPORTED("operator-supported"),
    /** Backup/restore is explicitly unsupported. */
    UNSUPPORTED(TOKEN_UNSUPPORTED);

    private final String catalogValue;

    BackupRestoreSupport(String catalogValue) {
      this.catalogValue = catalogValue;
    }

    /**
     * Parses a strict backup/restore support token.
     *
     * <p>Parsing follows the same bounded token rules as other maintenance enums. Keeping the value
     * normalized here avoids separate string handling in descriptor generation, catalog parsing,
     * and Platform API summaries.
     *
     * @param value catalog or descriptor token supplied by signed metadata or CLI input
     * @param fieldName field name used in diagnostics for malformed or unsupported tokens
     * @return matching backup/restore support value used by catalog entries
     * @throws AppCatalogException if the token is blank, multi-line, too long, or unsupported
     */
    public static BackupRestoreSupport parse(String value, String fieldName) {
      String normalized = normalizeEnumToken(value, fieldName);
      for (BackupRestoreSupport support : values()) {
        if (support.catalogValue.equals(normalized)) {
          return support;
        }
      }
      throw unsupportedEnumToken(fieldName, value);
    }

    /**
     * Returns the stable signed-catalog token.
     *
     * @return lower-case catalog and API value for deterministic serialization
     */
    public String catalogValue() {
      return catalogValue;
    }
  }

  /**
   * First-party security advisory handling policy.
   *
   * <p>The security policy records how maintainers expect vulnerability information for the app to
   * be surfaced. Catalog-level advisory references remain separate so individual advisories can be
   * added, updated, or revoked without changing this high-level maintenance classification.
   */
  public enum SecurityPolicy {
    /** Security state is handled by signed catalog advisory references. */
    CATALOG_ADVISORIES("catalog-advisories"),
    /** Security state follows the project-wide security policy. */
    PROJECT_SECURITY_POLICY("project-security-policy"),
    /** Security advisory handling is explicitly unsupported. */
    UNSUPPORTED(TOKEN_UNSUPPORTED);

    private final String catalogValue;

    SecurityPolicy(String catalogValue) {
      this.catalogValue = catalogValue;
    }

    /**
     * Parses a strict security policy token.
     *
     * <p>The returned value is suitable for signed catalog metadata and API output. Unsupported
     * tokens fail with the catalog invalid-entry error so release tooling cannot silently accept a
     * private or ad hoc security-process label.
     *
     * @param value catalog or descriptor token supplied by signed metadata or CLI input
     * @param fieldName field name used in diagnostics for malformed or unsupported tokens
     * @return matching security policy used by catalog entries
     * @throws AppCatalogException if the token is blank, multi-line, too long, or unsupported
     */
    public static SecurityPolicy parse(String value, String fieldName) {
      String normalized = normalizeEnumToken(value, fieldName);
      for (SecurityPolicy policy : values()) {
        if (policy.catalogValue.equals(normalized)) {
          return policy;
        }
      }
      throw unsupportedEnumToken(fieldName, value);
    }

    /**
     * Returns the stable signed-catalog token.
     *
     * @return lower-case catalog and API value for deterministic serialization
     */
    public String catalogValue() {
      return catalogValue;
    }
  }

  /**
   * First-party deprecation handling policy.
   *
   * <p>This policy records the expected handling model if the app later moves out of normal
   * maintenance. It complements, but does not replace, catalog deprecation status, deprecation
   * messages, and replacement app ids.
   */
  public enum DeprecationPolicy {
    /** No deprecation path is declared for the current app. */
    NONE("none"),
    /** Operators receive notice before a future retirement. */
    NOTICE_ONLY("notice-only"),
    /** Deprecated entries must identify a replacement app id. */
    REPLACEMENT_REQUIRED("replacement-required"),
    /** The app receives only security-relevant fixes while deprecated. */
    SECURITY_ONLY("security-only");

    private final String catalogValue;

    DeprecationPolicy(String catalogValue) {
      this.catalogValue = catalogValue;
    }

    /**
     * Parses a strict deprecation policy token.
     *
     * <p>Use this parser for catalog and descriptor input so policy tokens are normalized before
     * writers or API handlers see them. The method rejects unknown values rather than preserving
     * free-form labels in signed metadata.
     *
     * @param value catalog or descriptor token supplied by signed metadata or CLI input
     * @param fieldName field name used in diagnostics for malformed or unsupported tokens
     * @return matching deprecation policy used by catalog entries
     * @throws AppCatalogException if the token is blank, multi-line, too long, or unsupported
     */
    public static DeprecationPolicy parse(String value, String fieldName) {
      String normalized = normalizeEnumToken(value, fieldName);
      for (DeprecationPolicy policy : values()) {
        if (policy.catalogValue.equals(normalized)) {
          return policy;
        }
      }
      throw unsupportedEnumToken(fieldName, value);
    }

    /**
     * Returns the stable signed-catalog token.
     *
     * @return lower-case catalog and API value for deterministic serialization
     */
    public String catalogValue() {
      return catalogValue;
    }
  }
}

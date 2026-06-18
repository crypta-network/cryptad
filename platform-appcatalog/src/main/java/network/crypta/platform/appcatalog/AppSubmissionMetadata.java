package network.crypta.platform.appcatalog;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import network.crypta.platform.appdist.AppApiCompatibilityMetadata;
import network.crypta.platform.appdist.AppBundleManifest;

/**
 * Deterministic top-level metadata for a third-party app submission package.
 *
 * <p>The JSON form is stored as {@code crypta-app-submission.json} at the root of every submission
 * ZIP. The metadata binds the package to the staged bundle manifest, the packaged bundle artifact
 * digest, API-stability declarations, rationale digests, maintainer/source metadata, and the
 * non-production marker used by fixture and local test submissions.
 *
 * <p>This record is the author-facing summary of the submitted app. It is not trusted by itself:
 * {@link AppSubmissionPackageVerifier} compares the fields against the embedded manifest, rationale
 * documents, artifact bytes, and redaction scan before a reviewer can rely on it. Keeping the model
 * immutable and deterministic lets CLI tools, review receipts, catalog candidates, and
 * release-certification evidence all refer to the same submission identity without copying raw
 * package contents into logs or operator-facing JSON.
 *
 * <p>Optional fields are present only when corresponding artifacts exist. For example, a bundle
 * signature key id is copied from the bundle signature sidecar, and a catalog-entry digest is
 * included only when a candidate descriptor was generated at submission time.
 *
 * @param schemaVersion submission metadata schema version understood by this parser
 * @param submissionId deterministic id generated from app identity, version, and bundle digest
 * @param submissionCreatedAt timestamp supplied by the creating tool for audit ordering
 * @param submissionType whether this package is new, an update, or a resubmission
 * @param resubmissionOf prior submission id when this package is a resubmission
 * @param appId normalized app id copied from the submitted bundle manifest
 * @param appVersion bounded app version copied from the submitted bundle manifest
 * @param bundleDigest lowercase SHA-256 digest of the submitted app bundle artifact
 * @param bundleSignatureKeyId optional signing-key id from the bundle signature sidecar
 * @param catalogEntryDigest optional lowercase SHA-256 digest of generated catalog metadata
 * @param apiTargetStability manifest-declared API target stability
 * @param experimentalCapabilitiesAccepted whether manifest experimental API use is acknowledged
 * @param requestedPermissions permission capabilities requested by the submitted manifest
 * @param permissionRationaleDigest optional lowercase SHA-256 digest of permission rationale text
 * @param sandboxRequirement normalized sandbox mode and required marker from the manifest
 * @param appDataSchemaDeclared whether the manifest declares durable app-data schema metadata
 * @param appDataMigrationDeclared whether the manifest declares app-data migration steps
 * @param backupRestoreDeclared whether the submission includes backup/restore review evidence
 * @param maintainer public maintainer contact metadata for reviewer follow-up
 * @param sourceReference public source-code reference metadata for reviewer inspection
 * @param redactionScanDigest optional lowercase SHA-256 digest of redaction evidence
 * @param nonProduction whether the package was created for local tests or fixture use
 */
public record AppSubmissionMetadata(
    int schemaVersion,
    String submissionId,
    Instant submissionCreatedAt,
    AppSubmissionType submissionType,
    Optional<String> resubmissionOf,
    String appId,
    String appVersion,
    String bundleDigest,
    Optional<String> bundleSignatureKeyId,
    Optional<String> catalogEntryDigest,
    String apiTargetStability,
    boolean experimentalCapabilitiesAccepted,
    List<String> requestedPermissions,
    Optional<String> permissionRationaleDigest,
    String sandboxRequirement,
    boolean appDataSchemaDeclared,
    boolean appDataMigrationDeclared,
    boolean backupRestoreDeclared,
    AppSubmissionMaintainer maintainer,
    AppSubmissionSourceReference sourceReference,
    Optional<String> redactionScanDigest,
    boolean nonProduction) {
  /**
   * Current submission metadata schema version.
   *
   * <p>Version changes are format changes for {@code crypta-app-submission.json}. Review tools
   * reject unsupported versions instead of trying to infer compatibility from field names.
   */
  public static final int SCHEMA_VERSION = 1;

  private static final int MAX_SUBMISSION_ID_CHARS = 96;
  private static final int MAX_APP_VERSION_CHARS = 128;
  private static final int MAX_KEY_ID_CHARS = 128;
  private static final int MAX_SANDBOX_REQUIREMENT_CHARS = 64;
  private static final String API_TARGET_STABILITY_FIELD = "apiTargetStability";
  private static final String APP_DATA_MIGRATION_DECLARED_FIELD = "appDataMigrationDeclared";
  private static final String APP_DATA_SCHEMA_DECLARED_FIELD = "appDataSchemaDeclared";
  private static final String APP_ID_FIELD = "appId";
  private static final String APP_VERSION_FIELD = "appVersion";
  private static final String BACKUP_RESTORE_DECLARED_FIELD = "backupRestoreDeclared";
  private static final String BUNDLE_DIGEST_FIELD = "bundleDigest";
  private static final String BUNDLE_SIGNATURE_KEY_ID_FIELD = "bundleSignatureKeyId";
  private static final String CATALOG_ENTRY_DIGEST_FIELD = "catalogEntryDigest";
  private static final String EXPERIMENTAL_CAPABILITIES_ACCEPTED_FIELD =
      "experimentalCapabilitiesAccepted";
  private static final String MAINTAINER_FIELD = "maintainer";
  private static final String NON_PRODUCTION_FIELD = "nonProduction";
  private static final String PERMISSION_RATIONALE_DIGEST_FIELD = "permissionRationaleDigest";
  private static final String REDACTION_SCAN_DIGEST_FIELD = "redactionScanDigest";
  private static final String REQUESTED_PERMISSIONS_FIELD = "requestedPermissions";
  private static final String RESUBMISSION_OF_FIELD = "resubmissionOf";
  private static final String SANDBOX_REQUIREMENT_FIELD = "sandboxRequirement";
  private static final String SCHEMA_VERSION_FIELD = "schemaVersion";
  private static final String SOURCE_REFERENCE_FIELD = "sourceReference";
  private static final String SUBMISSION_CREATED_AT_FIELD = "submissionCreatedAt";
  private static final String SUBMISSION_ID_FIELD = "submissionId";
  private static final String SUBMISSION_TYPE_FIELD = "submissionType";

  /**
   * Creates validated submission metadata.
   *
   * <p>The constructor normalizes app id and API stability text, validates all digest fields,
   * bounds all public single-line strings, and enforces the resubmission link invariant. It does
   * not prove that metadata matches the bundle; that binding is performed by package verification
   * so malformed or edited submission JSON fails with structured findings.
   */
  public AppSubmissionMetadata {
    if (schemaVersion != SCHEMA_VERSION) {
      throw AppCatalogSidecars.invalidEntry(
          "unsupported submission " + SCHEMA_VERSION_FIELD + ": " + schemaVersion);
    }
    submissionId =
        AppCatalogSidecars.requireBoundedSingleLine(
            submissionId,
            SUBMISSION_ID_FIELD,
            AppCatalogSidecars.INVALID_CATALOG_ENTRY,
            MAX_SUBMISSION_ID_CHARS);
    Objects.requireNonNull(submissionCreatedAt, SUBMISSION_CREATED_AT_FIELD);
    Objects.requireNonNull(submissionType, SUBMISSION_TYPE_FIELD);
    Objects.requireNonNull(resubmissionOf, RESUBMISSION_OF_FIELD);
    resubmissionOf =
        resubmissionOf.map(
            value ->
                AppCatalogSidecars.requireBoundedSingleLine(
                    value,
                    RESUBMISSION_OF_FIELD,
                    AppCatalogSidecars.INVALID_CATALOG_ENTRY,
                    MAX_SUBMISSION_ID_CHARS));
    if (submissionType == AppSubmissionType.RESUBMISSION && resubmissionOf.isEmpty()) {
      throw AppCatalogSidecars.invalidEntry(
          "resubmission submissions require " + RESUBMISSION_OF_FIELD);
    }
    if (submissionType != AppSubmissionType.RESUBMISSION && resubmissionOf.isPresent()) {
      throw AppCatalogSidecars.invalidEntry(
          RESUBMISSION_OF_FIELD + " is only valid for resubmissions");
    }
    appId = AppCatalogEntry.normalizeAppId(appId);
    appVersion =
        AppCatalogSidecars.requireBoundedSingleLine(
            appVersion,
            APP_VERSION_FIELD,
            AppCatalogSidecars.INVALID_CATALOG_ENTRY,
            MAX_APP_VERSION_CHARS);
    bundleDigest = AppCatalogSidecars.requireLowercaseSha256(bundleDigest, BUNDLE_DIGEST_FIELD);
    Objects.requireNonNull(bundleSignatureKeyId, BUNDLE_SIGNATURE_KEY_ID_FIELD);
    bundleSignatureKeyId =
        bundleSignatureKeyId.map(
            value ->
                AppCatalogSidecars.requireBoundedSingleLine(
                    value,
                    BUNDLE_SIGNATURE_KEY_ID_FIELD,
                    AppCatalogSidecars.INVALID_CATALOG_ENTRY,
                    MAX_KEY_ID_CHARS));
    Objects.requireNonNull(catalogEntryDigest, CATALOG_ENTRY_DIGEST_FIELD);
    catalogEntryDigest =
        catalogEntryDigest.map(
            value -> AppCatalogSidecars.requireLowercaseSha256(value, CATALOG_ENTRY_DIGEST_FIELD));
    apiTargetStability =
        AppApiCompatibilityMetadata.TargetStability.parse(apiTargetStability).manifestValue();
    requestedPermissions = normalizePermissions(requestedPermissions);
    Objects.requireNonNull(permissionRationaleDigest, PERMISSION_RATIONALE_DIGEST_FIELD);
    permissionRationaleDigest =
        permissionRationaleDigest.map(
            value ->
                AppCatalogSidecars.requireLowercaseSha256(
                    value, PERMISSION_RATIONALE_DIGEST_FIELD));
    sandboxRequirement =
        AppCatalogSidecars.requireBoundedSingleLine(
            sandboxRequirement,
            SANDBOX_REQUIREMENT_FIELD,
            AppCatalogSidecars.INVALID_CATALOG_ENTRY,
            MAX_SANDBOX_REQUIREMENT_CHARS);
    Objects.requireNonNull(maintainer, MAINTAINER_FIELD);
    Objects.requireNonNull(sourceReference, SOURCE_REFERENCE_FIELD);
    Objects.requireNonNull(redactionScanDigest, REDACTION_SCAN_DIGEST_FIELD);
    redactionScanDigest =
        redactionScanDigest.map(
            value -> AppCatalogSidecars.requireLowercaseSha256(value, REDACTION_SCAN_DIGEST_FIELD));
  }

  /**
   * Creates metadata from a staged bundle manifest and computed package inputs.
   *
   * <p>This factory is used by submission package creation after the staged bundle has been
   * validated and packaged. Manifest-derived fields are copied from the parsed manifest, while
   * artifact digests and review-document digests come from the deterministic package writer. The
   * resulting object is ready to serialize as the root metadata document.
   *
   * @param submissionId deterministic id assigned to the submission package
   * @param createdAt creation instant written to submission metadata
   * @param submissionType whether the package is a new app, update, or resubmission
   * @param resubmissionOf prior submission id for resubmission packages, or {@code null}
   * @param manifest parsed staged-bundle manifest used as the source of app metadata
   * @param bundleDigest lowercase SHA-256 digest of the packaged bundle artifact
   * @param bundleSignatureKeyId signing-key id from the signature sidecar, or {@code null}
   * @param catalogEntryDigest digest for a generated catalog-entry sidecar, or {@code null}
   * @param permissionRationaleDigest digest for the permission rationale document, or {@code null}
   * @param backupRestoreDeclared whether backup/restore review evidence was supplied
   * @param maintainer public maintainer contact metadata
   * @param sourceReference public source-code reference metadata
   * @param redactionScanDigest digest for redaction scan evidence, or {@code null}
   * @param nonProduction whether the package is visibly marked as test-only
   * @return validated metadata snapshot derived from the manifest and computed artifacts
   */
  public static AppSubmissionMetadata fromManifest(
      String submissionId,
      Instant createdAt,
      AppSubmissionType submissionType,
      String resubmissionOf,
      AppBundleManifest manifest,
      String bundleDigest,
      String bundleSignatureKeyId,
      String catalogEntryDigest,
      String permissionRationaleDigest,
      boolean backupRestoreDeclared,
      AppSubmissionMaintainer maintainer,
      AppSubmissionSourceReference sourceReference,
      String redactionScanDigest,
      boolean nonProduction) {
    AppApiCompatibilityMetadata api = manifest.apiCompatibility();
    return new AppSubmissionMetadata(
        SCHEMA_VERSION,
        submissionId,
        createdAt,
        submissionType,
        Optional.ofNullable(resubmissionOf),
        manifest.appId(),
        manifest.appVersion(),
        bundleDigest,
        Optional.ofNullable(bundleSignatureKeyId),
        Optional.ofNullable(catalogEntryDigest),
        api.targetStability().manifestValue(),
        api.experimentalCapabilitiesAccepted(),
        manifest.permissions(),
        Optional.ofNullable(permissionRationaleDigest),
        manifest.sandboxRequired()
            ? manifest.sandboxMode().manifestValue() + ":required"
            : manifest.sandboxMode().manifestValue(),
        manifest.dataSchemaContract().declared(),
        !manifest.dataSchemaContract().migrations().isEmpty(),
        backupRestoreDeclared,
        maintainer,
        sourceReference,
        Optional.ofNullable(redactionScanDigest),
        nonProduction);
  }

  /**
   * Serializes this metadata to deterministic JSON.
   *
   * <p>Fields are emitted in schema order with optional fields omitted when absent. The output ends
   * with a newline so package creation and digest calculation are stable across repeated CLI runs.
   *
   * @return metadata JSON document ending with a newline
   */
  public String toJson() {
    return AppSubmissionJson.write(toJsonValue());
  }

  /**
   * Parses submission metadata from deterministic JSON.
   *
   * <p>Parsing validates the JSON shape and then applies the same constructor invariants used by
   * freshly created metadata. Callers still need to verify the parsed metadata against the package
   * contents before treating it as reviewer evidence.
   *
   * @param json metadata document read from {@code crypta-app-submission.json}
   * @return parsed and normalized metadata snapshot
   */
  public static AppSubmissionMetadata parse(String json) {
    Map<String, Object> object = AppSubmissionJson.parseObject(json, "submission metadata");
    return fromJsonObject(object);
  }

  Map<String, Object> toJsonValue() {
    LinkedHashMap<String, Object> value = new LinkedHashMap<>();
    value.put(SCHEMA_VERSION_FIELD, schemaVersion);
    value.put(SUBMISSION_ID_FIELD, submissionId);
    value.put(SUBMISSION_CREATED_AT_FIELD, submissionCreatedAt.toString());
    value.put(SUBMISSION_TYPE_FIELD, submissionType.jsonValue());
    resubmissionOf.ifPresent(text -> value.put(RESUBMISSION_OF_FIELD, text));
    value.put(APP_ID_FIELD, appId);
    value.put(APP_VERSION_FIELD, appVersion);
    value.put(BUNDLE_DIGEST_FIELD, bundleDigest);
    bundleSignatureKeyId.ifPresent(text -> value.put(BUNDLE_SIGNATURE_KEY_ID_FIELD, text));
    catalogEntryDigest.ifPresent(text -> value.put(CATALOG_ENTRY_DIGEST_FIELD, text));
    value.put(API_TARGET_STABILITY_FIELD, apiTargetStability);
    value.put(EXPERIMENTAL_CAPABILITIES_ACCEPTED_FIELD, experimentalCapabilitiesAccepted);
    value.put(REQUESTED_PERMISSIONS_FIELD, requestedPermissions);
    permissionRationaleDigest.ifPresent(text -> value.put(PERMISSION_RATIONALE_DIGEST_FIELD, text));
    value.put(SANDBOX_REQUIREMENT_FIELD, sandboxRequirement);
    value.put(APP_DATA_SCHEMA_DECLARED_FIELD, appDataSchemaDeclared);
    value.put(APP_DATA_MIGRATION_DECLARED_FIELD, appDataMigrationDeclared);
    value.put(BACKUP_RESTORE_DECLARED_FIELD, backupRestoreDeclared);
    value.put(MAINTAINER_FIELD, maintainer.toJsonValue());
    value.put(SOURCE_REFERENCE_FIELD, sourceReference.toJsonValue());
    redactionScanDigest.ifPresent(text -> value.put(REDACTION_SCAN_DIGEST_FIELD, text));
    value.put(NON_PRODUCTION_FIELD, nonProduction);
    return value;
  }

  private static AppSubmissionMetadata fromJsonObject(Map<String, Object> object) {
    return new AppSubmissionMetadata(
        AppSubmissionJson.requireSchemaVersion(object),
        AppSubmissionJson.requireString(object, SUBMISSION_ID_FIELD, SUBMISSION_ID_FIELD),
        parseInstant(
            AppSubmissionJson.requireString(
                object, SUBMISSION_CREATED_AT_FIELD, SUBMISSION_CREATED_AT_FIELD)),
        AppSubmissionType.parse(
            AppSubmissionJson.requireString(object, SUBMISSION_TYPE_FIELD, SUBMISSION_TYPE_FIELD)),
        AppSubmissionJson.optionalString(object, RESUBMISSION_OF_FIELD, RESUBMISSION_OF_FIELD),
        AppSubmissionJson.requireString(object, APP_ID_FIELD, APP_ID_FIELD),
        AppSubmissionJson.requireString(object, APP_VERSION_FIELD, APP_VERSION_FIELD),
        AppSubmissionJson.requireString(object, BUNDLE_DIGEST_FIELD, BUNDLE_DIGEST_FIELD),
        AppSubmissionJson.optionalString(
            object, BUNDLE_SIGNATURE_KEY_ID_FIELD, BUNDLE_SIGNATURE_KEY_ID_FIELD),
        AppSubmissionJson.optionalString(
            object, CATALOG_ENTRY_DIGEST_FIELD, CATALOG_ENTRY_DIGEST_FIELD),
        AppSubmissionJson.requireString(
            object, API_TARGET_STABILITY_FIELD, API_TARGET_STABILITY_FIELD),
        AppSubmissionJson.requireBoolean(
            object,
            EXPERIMENTAL_CAPABILITIES_ACCEPTED_FIELD,
            EXPERIMENTAL_CAPABILITIES_ACCEPTED_FIELD),
        AppSubmissionJson.requireRequestedPermissions(object),
        AppSubmissionJson.optionalString(
            object, PERMISSION_RATIONALE_DIGEST_FIELD, PERMISSION_RATIONALE_DIGEST_FIELD),
        AppSubmissionJson.requireString(
            object, SANDBOX_REQUIREMENT_FIELD, SANDBOX_REQUIREMENT_FIELD),
        AppSubmissionJson.requireBoolean(
            object, APP_DATA_SCHEMA_DECLARED_FIELD, APP_DATA_SCHEMA_DECLARED_FIELD),
        AppSubmissionJson.requireBoolean(
            object, APP_DATA_MIGRATION_DECLARED_FIELD, APP_DATA_MIGRATION_DECLARED_FIELD),
        AppSubmissionJson.requireBoolean(
            object, BACKUP_RESTORE_DECLARED_FIELD, BACKUP_RESTORE_DECLARED_FIELD),
        AppSubmissionMaintainer.fromJsonValue(object.get(MAINTAINER_FIELD)),
        AppSubmissionSourceReference.fromJsonValue(object.get(SOURCE_REFERENCE_FIELD)),
        AppSubmissionJson.optionalString(
            object, REDACTION_SCAN_DIGEST_FIELD, REDACTION_SCAN_DIGEST_FIELD),
        AppSubmissionJson.requireBoolean(object, NON_PRODUCTION_FIELD, NON_PRODUCTION_FIELD));
  }

  private static Instant parseInstant(String value) {
    try {
      return Instant.parse(value);
    } catch (DateTimeParseException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_ENTRY,
          SUBMISSION_CREATED_AT_FIELD + " must be an ISO-8601 instant",
          exception);
    }
  }

  private static List<String> normalizePermissions(List<String> permissions) {
    ArrayList<String> normalized = new ArrayList<>();
    for (String permission : List.copyOf(Objects.requireNonNull(permissions, "permissions"))) {
      normalized.add(
          AppCatalogSidecars.requireBoundedSingleLine(
              permission,
              REQUESTED_PERMISSIONS_FIELD,
              AppCatalogSidecars.INVALID_CATALOG_ENTRY,
              128));
    }
    return List.copyOf(normalized);
  }
}

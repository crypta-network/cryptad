package network.crypta.platform.appcatalog;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Durable metadata record for one local public-beta third-party submission intake item.
 *
 * <p>The record is the on-disk queue schema used by reviewer tooling. It contains only safe
 * metadata, digests, timestamps, reviewer ids, decision summaries, warning codes, and redacted
 * candidate references. It deliberately excludes raw submission ZIP contents, rationale bodies,
 * private reviewer keys, trusted-registry file paths, local absolute staging paths, browser/app
 * tokens, raw app data, raw fetched content, and private insert URIs.
 */
public record AppSubmissionIntakeRecord(
    int schemaVersion,
    AppSubmissionIntakeStatus status,
    String submissionId,
    String submissionDigest,
    String submissionType,
    Optional<String> resubmissionOf,
    String appId,
    String appVersion,
    String bundleDigest,
    String manifestDigest,
    String apiTargetStability,
    Optional<String> apiTargetBaseline,
    List<String> requestedPermissions,
    String maintainerName,
    String maintainerContactPublic,
    String sourceUrl,
    Optional<String> sourceRevision,
    Instant submittedAt,
    Optional<Instant> triagedAt,
    Optional<AppSubmissionReviewerAssignment> reviewerAssignment,
    Optional<String> preReviewReportDigest,
    Optional<String> preReviewStatus,
    Optional<AppSubmissionReviewDecisionRecord> decision,
    Optional<AppSubmissionCatalogCandidateRecord> catalogCandidate,
    Optional<String> transparencyLogDigest,
    boolean nonProduction,
    String redactionStatus,
    List<String> warnings,
    List<AppSubmissionIntakeAuditEvent> auditEvents) {
  /** Current intake record schema version. */
  public static final int SCHEMA_VERSION = 1;

  private static final String SCHEMA_VERSION_FIELD = "schemaVersion";
  private static final String STATUS_FIELD = "status";
  private static final String SUBMISSION_ID_FIELD = "submissionId";
  private static final String SUBMISSION_DIGEST_FIELD = "submissionDigest";
  private static final String SUBMISSION_TYPE_FIELD = "submissionType";
  private static final String RESUBMISSION_OF_FIELD = "resubmissionOf";
  private static final String APP_ID_FIELD = "appId";
  private static final String APP_VERSION_FIELD = "appVersion";
  private static final String BUNDLE_DIGEST_FIELD = "bundleDigest";
  private static final String MANIFEST_DIGEST_FIELD = "manifestDigest";
  private static final String API_TARGET_STABILITY_FIELD = "apiTargetStability";
  private static final String API_TARGET_BASELINE_FIELD = "apiTargetBaseline";
  private static final String REQUESTED_PERMISSIONS_FIELD = "requestedPermissions";
  private static final String MAINTAINER_NAME_FIELD = "maintainerName";
  private static final String MAINTAINER_CONTACT_PUBLIC_FIELD = "maintainerContactPublic";
  private static final String SOURCE_URL_FIELD = "sourceUrl";
  private static final String SOURCE_REVISION_FIELD = "sourceRevision";
  private static final String SUBMITTED_AT_FIELD = "submittedAt";
  private static final String TRIAGED_AT_FIELD = "triagedAt";
  private static final String REVIEWER_ASSIGNMENT_FIELD = "reviewerAssignment";
  private static final String PRE_REVIEW_REPORT_DIGEST_FIELD = "preReviewReportDigest";
  private static final String PRE_REVIEW_STATUS_FIELD = "preReviewStatus";
  private static final String DECISION_FIELD = "decision";
  private static final String CATALOG_CANDIDATE_FIELD = "catalogCandidate";
  private static final String TRANSPARENCY_LOG_DIGEST_FIELD = "transparencyLogDigest";
  private static final String NON_PRODUCTION_FIELD = "nonProduction";
  private static final String REDACTION_STATUS_FIELD = "redactionStatus";
  private static final String WARNINGS_FIELD = "warnings";
  private static final String AUDIT_EVENTS_FIELD = "auditEvents";

  /** Creates a validated intake record. */
  public AppSubmissionIntakeRecord {
    if (schemaVersion != SCHEMA_VERSION) {
      throw AppCatalogSidecars.invalidEntry("unsupported intake schemaVersion: " + schemaVersion);
    }
    Objects.requireNonNull(status, STATUS_FIELD);
    submissionId = bounded(submissionId, SUBMISSION_ID_FIELD, 96);
    submissionDigest =
        AppCatalogSidecars.requireLowercaseSha256(submissionDigest, SUBMISSION_DIGEST_FIELD);
    submissionType = AppSubmissionType.parse(submissionType).jsonValue();
    Objects.requireNonNull(resubmissionOf, RESUBMISSION_OF_FIELD);
    resubmissionOf = resubmissionOf.map(value -> bounded(value, RESUBMISSION_OF_FIELD, 96));
    appId = AppCatalogEntry.normalizeAppId(appId);
    appVersion = bounded(appVersion, APP_VERSION_FIELD, 128);
    bundleDigest = AppCatalogSidecars.requireLowercaseSha256(bundleDigest, BUNDLE_DIGEST_FIELD);
    manifestDigest =
        AppCatalogSidecars.requireLowercaseSha256(manifestDigest, MANIFEST_DIGEST_FIELD);
    network.crypta.platform.appdist.AppApiCompatibilityMetadata.TargetStability
        normalizedTargetStability =
            network.crypta.platform.appdist.AppApiCompatibilityMetadata.TargetStability.parse(
                apiTargetStability);
    apiTargetStability = normalizedTargetStability.manifestValue();
    Objects.requireNonNull(apiTargetBaseline, API_TARGET_BASELINE_FIELD);
    apiTargetBaseline =
        apiTargetBaseline.map(
            value ->
                new network.crypta.platform.appdist.AppApiCompatibilityMetadata(
                        null,
                        null,
                        List.of(),
                        normalizedTargetStability,
                        true,
                        value,
                        true,
                        false,
                        false)
                    .targetBaseline());
    requestedPermissions =
        List.copyOf(Objects.requireNonNull(requestedPermissions, REQUESTED_PERMISSIONS_FIELD))
            .stream()
            .map(value -> bounded(value, REQUESTED_PERMISSIONS_FIELD, 128))
            .toList();
    maintainerName = bounded(maintainerName, MAINTAINER_NAME_FIELD, 128);
    maintainerContactPublic =
        bounded(maintainerContactPublic, MAINTAINER_CONTACT_PUBLIC_FIELD, 512);
    sourceUrl = bounded(sourceUrl, SOURCE_URL_FIELD, 1024);
    Objects.requireNonNull(sourceRevision, SOURCE_REVISION_FIELD);
    sourceRevision = sourceRevision.map(value -> bounded(value, SOURCE_REVISION_FIELD, 160));
    Objects.requireNonNull(submittedAt, SUBMITTED_AT_FIELD);
    Objects.requireNonNull(triagedAt, TRIAGED_AT_FIELD);
    Objects.requireNonNull(reviewerAssignment, REVIEWER_ASSIGNMENT_FIELD);
    Objects.requireNonNull(preReviewReportDigest, PRE_REVIEW_REPORT_DIGEST_FIELD);
    preReviewReportDigest =
        preReviewReportDigest.map(
            value ->
                AppCatalogSidecars.requireLowercaseSha256(value, PRE_REVIEW_REPORT_DIGEST_FIELD));
    Objects.requireNonNull(preReviewStatus, PRE_REVIEW_STATUS_FIELD);
    preReviewStatus =
        preReviewStatus.map(value -> AppSubmissionPreReviewStatus.parse(value).jsonValue());
    Objects.requireNonNull(decision, DECISION_FIELD);
    Objects.requireNonNull(catalogCandidate, CATALOG_CANDIDATE_FIELD);
    Objects.requireNonNull(transparencyLogDigest, TRANSPARENCY_LOG_DIGEST_FIELD);
    transparencyLogDigest =
        transparencyLogDigest.map(
            value ->
                AppCatalogSidecars.requireLowercaseSha256(value, TRANSPARENCY_LOG_DIGEST_FIELD));
    redactionStatus = bounded(redactionStatus, REDACTION_STATUS_FIELD, 32);
    warnings =
        List.copyOf(Objects.requireNonNull(warnings, WARNINGS_FIELD)).stream()
            .map(value -> bounded(value, "intake.warning", 256))
            .toList();
    auditEvents = List.copyOf(Objects.requireNonNull(auditEvents, AUDIT_EVENTS_FIELD));
    validateConsistentState(
        status,
        reviewerAssignment.orElse(null),
        preReviewReportDigest.orElse(null),
        decision.orElse(null),
        catalogCandidate.orElse(null));
  }

  /**
   * Creates a new intake record from a verified submission package.
   *
   * @param submission verified submission package metadata
   * @param submittedAt local import timestamp
   * @return submitted intake record with one audit event
   */
  public static AppSubmissionIntakeRecord fromSubmission(
      AppSubmissionPackage submission, Instant submittedAt) {
    AppSubmissionMetadata metadata = submission.metadata();
    AppSubmissionIntakeRecord draft =
        new AppSubmissionIntakeRecord(
            SCHEMA_VERSION,
            AppSubmissionIntakeStatus.SUBMITTED,
            metadata.submissionId(),
            submission.submissionDigest(),
            metadata.submissionType().jsonValue(),
            metadata.resubmissionOf(),
            metadata.appId(),
            metadata.appVersion(),
            metadata.bundleDigest(),
            submission.manifestDigest(),
            metadata.apiTargetStability(),
            metadata.apiTargetBaseline(),
            metadata.requestedPermissions(),
            metadata.maintainer().name(),
            metadata.maintainer().contact(),
            metadata.sourceReference().url().toString(),
            metadata.sourceReference().revision(),
            submittedAt,
            Optional.empty(),
            Optional.empty(),
            Optional.empty(),
            Optional.empty(),
            Optional.empty(),
            Optional.empty(),
            Optional.empty(),
            metadata.nonProduction(),
            "pass",
            metadata.nonProduction() ? List.of("nonProduction=true") : List.of(),
            List.of());
    return draft.withAudit(
        "submission_imported",
        null,
        submittedAt,
        null,
        submission.submissionDigest(),
        metadata.nonProduction() ? List.of("nonProduction=true") : List.of());
  }

  /** Serializes this record as deterministic JSON. */
  public String toJson() {
    return AppSubmissionJson.write(toJsonValue());
  }

  /** Parses a record from deterministic JSON. */
  public static AppSubmissionIntakeRecord parse(String json) {
    Map<String, Object> object = AppSubmissionJson.parseObject(json, "submission intake record");
    return fromJsonObject(object);
  }

  /** Returns a compact operator-safe summary. */
  public AppSubmissionIntakeSummary toSummary() {
    AppSubmissionReviewerAssignment assignment = reviewerAssignment.orElse(null);
    AppSubmissionReviewDecisionRecord decisionRecord = decision.orElse(null);
    AppSubmissionCatalogCandidateRecord candidate = catalogCandidate.orElse(null);
    return new AppSubmissionIntakeSummary(
        submissionId,
        appId,
        appVersion,
        apiTargetStability,
        apiTargetBaseline.orElse(null),
        status,
        assignment == null ? null : assignment.reviewerKeyId(),
        assignment == null ? null : assignment.reviewerDisplayName(),
        preReviewStatus.orElse(null),
        decisionRecord == null ? null : decisionRecord.decision().jsonValue(),
        candidate != null,
        candidate == null ? null : candidate.betaCatalogChannel(),
        candidate == null ? null : candidate.installSmokeStatus(),
        transparencyLogDigest.orElse(null),
        nonProduction,
        redactionStatus,
        warnings);
  }

  /** Returns a copy with reviewer assignment recorded. */
  public AppSubmissionIntakeRecord assignReviewer(
      AppSubmissionReviewerAssignment assignment, Instant assignedAt) {
    ensureTransitionAllowed(AppSubmissionIntakeStatus.REVIEWER_ASSIGNED);
    AppSubmissionIntakeStatus updatedStatus =
        status == AppSubmissionIntakeStatus.PRE_REVIEW_PASSED
                || status == AppSubmissionIntakeStatus.PRE_REVIEW_FAILED
            ? status
            : AppSubmissionIntakeStatus.REVIEWER_ASSIGNED;
    AppSubmissionIntakeRecord updated =
        new AppSubmissionIntakeRecord(
            schemaVersion,
            updatedStatus,
            submissionId,
            submissionDigest,
            submissionType,
            resubmissionOf,
            appId,
            appVersion,
            bundleDigest,
            manifestDigest,
            apiTargetStability,
            apiTargetBaseline,
            requestedPermissions,
            maintainerName,
            maintainerContactPublic,
            sourceUrl,
            sourceRevision,
            submittedAt,
            Optional.ofNullable(triagedAt.orElse(assignedAt)),
            Optional.of(assignment),
            preReviewReportDigest,
            preReviewStatus,
            decision,
            catalogCandidate,
            transparencyLogDigest,
            nonProduction,
            redactionStatus,
            addWarningIfMissing(warnings, "reviewerAssigned=true"),
            auditEvents);
    return updated.withAudit(
        "reviewer_assigned",
        status,
        assignedAt,
        assignment.reviewerKeyId(),
        assignment.assignmentReasonDigest(),
        List.of(
            assignment.previousReviewerKeyId().isPresent() ? "reassigned=true" : "assigned=true"));
  }

  /** Returns a copy that records pre-review as running. */
  public AppSubmissionIntakeRecord preReviewRunning(Instant startedAt) {
    ensureTransitionAllowed(AppSubmissionIntakeStatus.PRE_REVIEW_RUNNING);
    return withStatus(AppSubmissionIntakeStatus.PRE_REVIEW_RUNNING)
        .withAudit(
            "pre_review_started",
            status,
            startedAt,
            reviewerAssignment.map(AppSubmissionReviewerAssignment::reviewerKeyId).orElse(null),
            null,
            List.of("preReviewStatus=running"));
  }

  /** Returns a copy with automated pre-review result metadata recorded. */
  public AppSubmissionIntakeRecord recordPreReview(
      String preReviewDigest, AppSubmissionPreReviewStatus statusValue, Instant completedAt) {
    return recordPreReview(preReviewDigest, statusValue, completedAt, redactionStatus, List.of());
  }

  /**
   * Returns a copy with automated pre-review result metadata and redaction summary recorded.
   *
   * @param preReviewDigest SHA-256 digest of the pre-review report JSON
   * @param statusValue aggregate automated pre-review status
   * @param completedAt completion timestamp
   * @param redactionStatusValue aggregate redaction scan status
   * @param additionalWarnings extra bounded warning labels to retain in the queue record
   * @return updated immutable intake record
   */
  public AppSubmissionIntakeRecord recordPreReview(
      String preReviewDigest,
      AppSubmissionPreReviewStatus statusValue,
      Instant completedAt,
      String redactionStatusValue,
      List<String> additionalWarnings) {
    AppSubmissionIntakeStatus nextStatus =
        statusValue == AppSubmissionPreReviewStatus.FAIL
            ? AppSubmissionIntakeStatus.PRE_REVIEW_FAILED
            : AppSubmissionIntakeStatus.PRE_REVIEW_PASSED;
    ensureTransitionAllowed(nextStatus);
    List<String> updatedWarnings =
        addWarnings(
            addWarningIfMissing(warnings, "preReviewStatus=" + statusValue.jsonValue()),
            additionalWarnings);
    AppSubmissionIntakeRecord updated =
        new AppSubmissionIntakeRecord(
            schemaVersion,
            nextStatus,
            submissionId,
            submissionDigest,
            submissionType,
            resubmissionOf,
            appId,
            appVersion,
            bundleDigest,
            manifestDigest,
            apiTargetStability,
            apiTargetBaseline,
            requestedPermissions,
            maintainerName,
            maintainerContactPublic,
            sourceUrl,
            sourceRevision,
            submittedAt,
            triagedAt,
            reviewerAssignment,
            Optional.of(preReviewDigest),
            Optional.of(statusValue.jsonValue()),
            decision,
            catalogCandidate,
            transparencyLogDigest,
            nonProduction,
            redactionStatusValue,
            updatedWarnings,
            auditEvents);
    return updated.withAudit(
        "pre_review_completed",
        status,
        completedAt,
        reviewerAssignment.map(AppSubmissionReviewerAssignment::reviewerKeyId).orElse(null),
        preReviewDigest,
        List.of("preReviewStatus=" + statusValue.jsonValue()));
  }

  /** Returns a copy with final reviewer decision metadata recorded. */
  public AppSubmissionIntakeRecord recordDecision(
      AppSubmissionReviewDecisionRecord decisionRecord, Instant decidedAt) {
    Objects.requireNonNull(decisionRecord, "decisionRecord");
    AppSubmissionIntakeStatus nextStatus =
        switch (decisionRecord.decision()) {
          case REVIEWED -> AppSubmissionIntakeStatus.REVIEWED;
          case CAUTION -> AppSubmissionIntakeStatus.CAUTION;
          case REJECTED -> AppSubmissionIntakeStatus.REJECTED;
          case RESUBMISSION_REQUESTED -> AppSubmissionIntakeStatus.RESUBMISSION_REQUESTED;
        };
    ensureTransitionAllowed(nextStatus);
    AppSubmissionIntakeRecord updated =
        new AppSubmissionIntakeRecord(
            schemaVersion,
            nextStatus,
            submissionId,
            submissionDigest,
            submissionType,
            resubmissionOf,
            appId,
            appVersion,
            bundleDigest,
            manifestDigest,
            apiTargetStability,
            apiTargetBaseline,
            requestedPermissions,
            maintainerName,
            maintainerContactPublic,
            sourceUrl,
            sourceRevision,
            submittedAt,
            triagedAt,
            reviewerAssignment,
            preReviewReportDigest,
            preReviewStatus,
            Optional.of(decisionRecord),
            catalogCandidate,
            transparencyLogDigest,
            nonProduction,
            redactionStatus,
            addWarningIfMissing(warnings, "decision=" + decisionRecord.decision().jsonValue()),
            auditEvents);
    return updated.withAudit(
        "review_decision_recorded",
        status,
        decidedAt,
        decisionRecord.reviewerKeyId(),
        decisionRecord.decisionReasonDigest(),
        List.of("decision=" + decisionRecord.decision().jsonValue()));
  }

  /** Returns a copy with beta catalog candidate staging metadata recorded. */
  public AppSubmissionIntakeRecord recordCatalogCandidate(
      AppSubmissionCatalogCandidateRecord candidateRecord, Instant stagedAt) {
    Objects.requireNonNull(candidateRecord, "candidateRecord");
    AppSubmissionReviewDecision decisionValue =
        decision
            .map(AppSubmissionReviewDecisionRecord::decision)
            .orElseThrow(
                () ->
                    AppCatalogSidecars.invalidEntry(
                        "catalog candidate staging requires reviewer decision"));
    if (decisionValue.blocksCatalogCandidateStaging()) {
      throw AppCatalogSidecars.invalidEntry(
          "only reviewed or caution submissions can stage catalog candidates");
    }
    if (decisionValue == AppSubmissionReviewDecision.CAUTION && !candidateRecord.cautionAllowed()) {
      throw AppCatalogSidecars.invalidEntry("caution candidates require explicit allowance");
    }
    if (decisionValue == AppSubmissionReviewDecision.REVIEWED && candidateRecord.cautionAllowed()) {
      throw AppCatalogSidecars.invalidEntry(
          "reviewed candidates must not be marked as caution-allowed");
    }
    String decisionReceiptFingerprint =
        decision
            .flatMap(AppSubmissionReviewDecisionRecord::reviewReceiptFingerprintSha256)
            .orElseThrow(
                () ->
                    AppCatalogSidecars.invalidEntry(
                        "catalog candidate staging requires recorded review receipt"));
    if (!decisionReceiptFingerprint.equals(candidateRecord.reviewReceiptFingerprintSha256())) {
      throw AppCatalogSidecars.invalidEntry(
          "catalog candidate receipt does not match reviewer decision receipt");
    }
    ensureTransitionAllowed(AppSubmissionIntakeStatus.CATALOG_CANDIDATE_CREATED);
    AppSubmissionIntakeRecord candidateCreated =
        new AppSubmissionIntakeRecord(
            schemaVersion,
            AppSubmissionIntakeStatus.CATALOG_CANDIDATE_CREATED,
            submissionId,
            submissionDigest,
            submissionType,
            resubmissionOf,
            appId,
            appVersion,
            bundleDigest,
            manifestDigest,
            apiTargetStability,
            apiTargetBaseline,
            requestedPermissions,
            maintainerName,
            maintainerContactPublic,
            sourceUrl,
            sourceRevision,
            submittedAt,
            triagedAt,
            reviewerAssignment,
            preReviewReportDigest,
            preReviewStatus,
            decision,
            Optional.of(candidateRecord),
            transparencyLogDigest,
            nonProduction,
            redactionStatus,
            addWarningIfMissing(warnings, "catalogCandidateCreated=true"),
            auditEvents);
    AppSubmissionIntakeRecord staged =
        candidateCreated.withStatus(AppSubmissionIntakeStatus.STAGED_TO_BETA_CATALOG);
    return staged.withAudit(
        "catalog_candidate_staged",
        status,
        stagedAt,
        reviewerAssignment.map(AppSubmissionReviewerAssignment::reviewerKeyId).orElse(null),
        candidateRecord.catalogCandidateDigest(),
        candidateRecord.cautionAllowed()
            ? List.of("candidateReview=caution", "allowCaution=true")
            : List.of("candidateReview=reviewed"));
  }

  /** Returns a copy with install-from-beta-catalog smoke evidence recorded. */
  public AppSubmissionIntakeRecord recordInstallSmokePassed(
      String transparencyDigest, Instant smokeAt) {
    ensureTransitionAllowed(AppSubmissionIntakeStatus.BETA_INSTALL_SMOKE_PASSED);
    AppSubmissionCatalogCandidateRecord candidateRecord =
        catalogCandidate.orElseThrow(
            () -> AppCatalogSidecars.invalidEntry("catalog candidate is required for smoke"));
    AppSubmissionCatalogCandidateRecord updatedCandidate =
        candidateWithInstallSmokePassed(candidateRecord);
    AppSubmissionIntakeRecord updated =
        new AppSubmissionIntakeRecord(
            schemaVersion,
            AppSubmissionIntakeStatus.BETA_INSTALL_SMOKE_PASSED,
            submissionId,
            submissionDigest,
            submissionType,
            resubmissionOf,
            appId,
            appVersion,
            bundleDigest,
            manifestDigest,
            apiTargetStability,
            apiTargetBaseline,
            requestedPermissions,
            maintainerName,
            maintainerContactPublic,
            sourceUrl,
            sourceRevision,
            submittedAt,
            triagedAt,
            reviewerAssignment,
            preReviewReportDigest,
            preReviewStatus,
            decision,
            Optional.of(updatedCandidate),
            Optional.ofNullable(transparencyDigest),
            nonProduction,
            redactionStatus,
            addWarningIfMissing(warnings, "betaInstallSmoke=pass"),
            auditEvents);
    return updated.withAudit(
        "beta_install_smoke_passed",
        status,
        smokeAt,
        reviewerAssignment.map(AppSubmissionReviewerAssignment::reviewerKeyId).orElse(null),
        transparencyDigest,
        List.of("installSmokeStatus=pass"));
  }

  private static AppSubmissionCatalogCandidateRecord candidateWithInstallSmokePassed(
      AppSubmissionCatalogCandidateRecord candidateRecord) {
    return new AppSubmissionCatalogCandidateRecord(
        candidateRecord.catalogCandidateDigest(),
        candidateRecord.betaCatalogChannel(),
        candidateRecord.betaCatalogCandidateReference(),
        candidateRecord.reviewReceiptFingerprintSha256(),
        candidateRecord.createdAt(),
        candidateRecord.cautionAllowed(),
        "pass");
  }

  public Map<String, Object> toJsonValue() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(31);
    json.put(SCHEMA_VERSION_FIELD, schemaVersion);
    json.put(STATUS_FIELD, status.jsonValue());
    json.put(SUBMISSION_ID_FIELD, submissionId);
    json.put(SUBMISSION_DIGEST_FIELD, submissionDigest);
    json.put(SUBMISSION_TYPE_FIELD, submissionType);
    resubmissionOf.ifPresent(value -> json.put(RESUBMISSION_OF_FIELD, value));
    json.put(APP_ID_FIELD, appId);
    json.put(APP_VERSION_FIELD, appVersion);
    json.put(BUNDLE_DIGEST_FIELD, bundleDigest);
    json.put(MANIFEST_DIGEST_FIELD, manifestDigest);
    json.put(API_TARGET_STABILITY_FIELD, apiTargetStability);
    apiTargetBaseline.ifPresent(value -> json.put(API_TARGET_BASELINE_FIELD, value));
    json.put(REQUESTED_PERMISSIONS_FIELD, requestedPermissions);
    json.put(MAINTAINER_NAME_FIELD, maintainerName);
    json.put(MAINTAINER_CONTACT_PUBLIC_FIELD, maintainerContactPublic);
    json.put(SOURCE_URL_FIELD, sourceUrl);
    sourceRevision.ifPresent(value -> json.put(SOURCE_REVISION_FIELD, value));
    json.put(SUBMITTED_AT_FIELD, submittedAt.toString());
    triagedAt.ifPresent(value -> json.put(TRIAGED_AT_FIELD, value.toString()));
    reviewerAssignment.ifPresent(value -> json.put(REVIEWER_ASSIGNMENT_FIELD, value.toJsonValue()));
    preReviewReportDigest.ifPresent(value -> json.put(PRE_REVIEW_REPORT_DIGEST_FIELD, value));
    preReviewStatus.ifPresent(value -> json.put(PRE_REVIEW_STATUS_FIELD, value));
    decision.ifPresent(value -> json.put(DECISION_FIELD, value.toJsonValue()));
    catalogCandidate.ifPresent(value -> json.put(CATALOG_CANDIDATE_FIELD, value.toJsonValue()));
    transparencyLogDigest.ifPresent(value -> json.put(TRANSPARENCY_LOG_DIGEST_FIELD, value));
    json.put(NON_PRODUCTION_FIELD, nonProduction);
    json.put(REDACTION_STATUS_FIELD, redactionStatus);
    json.put(WARNINGS_FIELD, warnings);
    json.put(
        AUDIT_EVENTS_FIELD,
        auditEvents.stream().map(AppSubmissionIntakeAuditEvent::toJsonValue).toList());
    return json;
  }

  private static AppSubmissionIntakeRecord fromJsonObject(Map<String, Object> object) {
    return new AppSubmissionIntakeRecord(
        AppSubmissionJson.requireSchemaVersion(object),
        AppSubmissionIntakeStatus.parse(
            AppSubmissionJson.requireString(object, STATUS_FIELD, STATUS_FIELD)),
        AppSubmissionJson.requireString(object, SUBMISSION_ID_FIELD, SUBMISSION_ID_FIELD),
        AppSubmissionJson.requireString(object, SUBMISSION_DIGEST_FIELD, SUBMISSION_DIGEST_FIELD),
        AppSubmissionJson.requireString(object, SUBMISSION_TYPE_FIELD, SUBMISSION_TYPE_FIELD),
        AppSubmissionJson.optionalString(object, RESUBMISSION_OF_FIELD, RESUBMISSION_OF_FIELD),
        AppSubmissionJson.requireString(object, APP_ID_FIELD, APP_ID_FIELD),
        AppSubmissionJson.requireString(object, APP_VERSION_FIELD, APP_VERSION_FIELD),
        AppSubmissionJson.requireString(object, BUNDLE_DIGEST_FIELD, BUNDLE_DIGEST_FIELD),
        AppSubmissionJson.requireString(object, MANIFEST_DIGEST_FIELD, MANIFEST_DIGEST_FIELD),
        AppSubmissionJson.requireString(
            object, API_TARGET_STABILITY_FIELD, API_TARGET_STABILITY_FIELD),
        AppSubmissionJson.optionalString(
            object, API_TARGET_BASELINE_FIELD, API_TARGET_BASELINE_FIELD),
        stringList(object.get(REQUESTED_PERMISSIONS_FIELD), REQUESTED_PERMISSIONS_FIELD),
        AppSubmissionJson.requireString(object, MAINTAINER_NAME_FIELD, MAINTAINER_NAME_FIELD),
        AppSubmissionJson.requireString(
            object, MAINTAINER_CONTACT_PUBLIC_FIELD, MAINTAINER_CONTACT_PUBLIC_FIELD),
        AppSubmissionJson.requireString(object, SOURCE_URL_FIELD, SOURCE_URL_FIELD),
        AppSubmissionJson.optionalString(object, SOURCE_REVISION_FIELD, SOURCE_REVISION_FIELD),
        parseInstant(
            AppSubmissionJson.requireString(object, SUBMITTED_AT_FIELD, SUBMITTED_AT_FIELD),
            SUBMITTED_AT_FIELD),
        AppSubmissionJson.optionalString(object, TRIAGED_AT_FIELD, TRIAGED_AT_FIELD)
            .map(value -> parseInstant(value, TRIAGED_AT_FIELD)),
        Optional.ofNullable(object.get(REVIEWER_ASSIGNMENT_FIELD))
            .map(AppSubmissionReviewerAssignment::fromJsonValue),
        AppSubmissionJson.optionalString(
            object, PRE_REVIEW_REPORT_DIGEST_FIELD, PRE_REVIEW_REPORT_DIGEST_FIELD),
        AppSubmissionJson.optionalString(object, PRE_REVIEW_STATUS_FIELD, PRE_REVIEW_STATUS_FIELD),
        Optional.ofNullable(object.get(DECISION_FIELD))
            .map(AppSubmissionReviewDecisionRecord::fromJsonValue),
        Optional.ofNullable(object.get(CATALOG_CANDIDATE_FIELD))
            .map(AppSubmissionCatalogCandidateRecord::fromJsonValue),
        AppSubmissionJson.optionalString(
            object, TRANSPARENCY_LOG_DIGEST_FIELD, TRANSPARENCY_LOG_DIGEST_FIELD),
        AppSubmissionJson.requireBoolean(object, NON_PRODUCTION_FIELD, NON_PRODUCTION_FIELD),
        AppSubmissionJson.requireString(object, REDACTION_STATUS_FIELD, REDACTION_STATUS_FIELD),
        stringList(object.get(WARNINGS_FIELD), WARNINGS_FIELD),
        auditEvents(object.get(AUDIT_EVENTS_FIELD)));
  }

  private AppSubmissionIntakeRecord withStatus(AppSubmissionIntakeStatus nextStatus) {
    return new AppSubmissionIntakeRecord(
        schemaVersion,
        nextStatus,
        submissionId,
        submissionDigest,
        submissionType,
        resubmissionOf,
        appId,
        appVersion,
        bundleDigest,
        manifestDigest,
        apiTargetStability,
        apiTargetBaseline,
        requestedPermissions,
        maintainerName,
        maintainerContactPublic,
        sourceUrl,
        sourceRevision,
        submittedAt,
        triagedAt,
        reviewerAssignment,
        preReviewReportDigest,
        preReviewStatus,
        decision,
        catalogCandidate,
        transparencyLogDigest,
        nonProduction,
        redactionStatus,
        warnings,
        auditEvents);
  }

  private AppSubmissionIntakeRecord withAudit(
      String eventKind,
      AppSubmissionIntakeStatus fromStatus,
      Instant createdAt,
      String reviewerKeyId,
      String evidenceSha256,
      List<String> eventWarnings) {
    ArrayList<AppSubmissionIntakeAuditEvent> updatedEvents = new ArrayList<>(auditEvents);
    updatedEvents.add(
        new AppSubmissionIntakeAuditEvent(
            eventKind,
            createdAt,
            Optional.ofNullable(fromStatus),
            status,
            Optional.ofNullable(reviewerKeyId),
            Optional.ofNullable(evidenceSha256),
            eventWarnings));
    return new AppSubmissionIntakeRecord(
        schemaVersion,
        status,
        submissionId,
        submissionDigest,
        submissionType,
        resubmissionOf,
        appId,
        appVersion,
        bundleDigest,
        manifestDigest,
        apiTargetStability,
        apiTargetBaseline,
        requestedPermissions,
        maintainerName,
        maintainerContactPublic,
        sourceUrl,
        sourceRevision,
        submittedAt,
        triagedAt,
        reviewerAssignment,
        preReviewReportDigest,
        preReviewStatus,
        decision,
        catalogCandidate,
        transparencyLogDigest,
        nonProduction,
        redactionStatus,
        warnings,
        updatedEvents);
  }

  private void ensureTransitionAllowed(AppSubmissionIntakeStatus nextStatus) {
    EnumSet<AppSubmissionIntakeStatus> allowed =
        switch (status) {
          case SUBMITTED ->
              EnumSet.of(
                  AppSubmissionIntakeStatus.TRIAGED,
                  AppSubmissionIntakeStatus.REVIEWER_ASSIGNED,
                  AppSubmissionIntakeStatus.PRE_REVIEW_RUNNING);
          case TRIAGED ->
              EnumSet.of(
                  AppSubmissionIntakeStatus.REVIEWER_ASSIGNED,
                  AppSubmissionIntakeStatus.PRE_REVIEW_RUNNING);
          case REVIEWER_ASSIGNED ->
              EnumSet.of(
                  AppSubmissionIntakeStatus.REVIEWER_ASSIGNED,
                  AppSubmissionIntakeStatus.PRE_REVIEW_RUNNING,
                  AppSubmissionIntakeStatus.PRE_REVIEW_PASSED,
                  AppSubmissionIntakeStatus.PRE_REVIEW_FAILED);
          case PRE_REVIEW_RUNNING ->
              EnumSet.of(
                  AppSubmissionIntakeStatus.PRE_REVIEW_RUNNING,
                  AppSubmissionIntakeStatus.PRE_REVIEW_PASSED,
                  AppSubmissionIntakeStatus.PRE_REVIEW_FAILED);
          case PRE_REVIEW_PASSED ->
              EnumSet.of(
                  AppSubmissionIntakeStatus.REVIEWER_ASSIGNED,
                  AppSubmissionIntakeStatus.REVIEW_IN_PROGRESS,
                  AppSubmissionIntakeStatus.REVIEWED,
                  AppSubmissionIntakeStatus.CAUTION,
                  AppSubmissionIntakeStatus.REJECTED,
                  AppSubmissionIntakeStatus.RESUBMISSION_REQUESTED);
          case PRE_REVIEW_FAILED ->
              EnumSet.of(
                  AppSubmissionIntakeStatus.REVIEWER_ASSIGNED,
                  AppSubmissionIntakeStatus.REJECTED,
                  AppSubmissionIntakeStatus.RESUBMISSION_REQUESTED);
          case REVIEW_IN_PROGRESS ->
              EnumSet.of(
                  AppSubmissionIntakeStatus.REVIEWED,
                  AppSubmissionIntakeStatus.CAUTION,
                  AppSubmissionIntakeStatus.REJECTED,
                  AppSubmissionIntakeStatus.RESUBMISSION_REQUESTED);
          case REVIEWED, CAUTION ->
              EnumSet.of(
                  AppSubmissionIntakeStatus.CATALOG_CANDIDATE_CREATED,
                  AppSubmissionIntakeStatus.STAGED_TO_BETA_CATALOG);
          case CATALOG_CANDIDATE_CREATED ->
              EnumSet.of(
                  AppSubmissionIntakeStatus.STAGED_TO_BETA_CATALOG,
                  AppSubmissionIntakeStatus.BETA_INSTALL_SMOKE_PASSED);
          case STAGED_TO_BETA_CATALOG ->
              EnumSet.of(
                  AppSubmissionIntakeStatus.BETA_INSTALL_SMOKE_PASSED,
                  AppSubmissionIntakeStatus.CLOSED);
          case BETA_INSTALL_SMOKE_PASSED, REJECTED, RESUBMISSION_REQUESTED ->
              EnumSet.of(AppSubmissionIntakeStatus.CLOSED);
          case CLOSED -> EnumSet.noneOf(AppSubmissionIntakeStatus.class);
        };
    if (!allowed.contains(nextStatus)) {
      throw AppCatalogSidecars.invalidEntry(
          "invalid intake status transition: "
              + status.jsonValue()
              + " -> "
              + nextStatus.jsonValue());
    }
  }

  private static void validateConsistentState(
      AppSubmissionIntakeStatus status,
      AppSubmissionReviewerAssignment reviewerAssignment,
      String preReviewReportDigest,
      AppSubmissionReviewDecisionRecord decision,
      AppSubmissionCatalogCandidateRecord catalogCandidate) {
    requireReviewerAssignment(status, reviewerAssignment);
    requirePreReviewReportDigest(status, preReviewReportDigest);
    requireDecisionMetadata(status, decision);
    requireCatalogCandidateMetadata(status, catalogCandidate);
    validateCatalogCandidateDecision(decision, catalogCandidate);
  }

  private static void requireReviewerAssignment(
      AppSubmissionIntakeStatus status, AppSubmissionReviewerAssignment reviewerAssignment) {
    if (requiresReviewerAssignment(status) && reviewerAssignment == null) {
      throw AppCatalogSidecars.invalidEntry("review decision states require reviewer assignment");
    }
  }

  private static void requirePreReviewReportDigest(
      AppSubmissionIntakeStatus status, String preReviewReportDigest) {
    if (isPreReviewResultStatus(status) && preReviewReportDigest == null) {
      throw AppCatalogSidecars.invalidEntry("pre-review states require report digest");
    }
  }

  private static void requireDecisionMetadata(
      AppSubmissionIntakeStatus status, AppSubmissionReviewDecisionRecord decision) {
    if (requiresDecisionMetadata(status) && decision == null) {
      throw AppCatalogSidecars.invalidEntry("decision states require decision metadata");
    }
  }

  private static void requireCatalogCandidateMetadata(
      AppSubmissionIntakeStatus status, AppSubmissionCatalogCandidateRecord catalogCandidate) {
    if (requiresCatalogCandidateMetadata(status) && catalogCandidate == null) {
      throw AppCatalogSidecars.invalidEntry("candidate states require catalog candidate metadata");
    }
  }

  private static void validateCatalogCandidateDecision(
      AppSubmissionReviewDecisionRecord decision,
      AppSubmissionCatalogCandidateRecord catalogCandidate) {
    if (catalogCandidate == null || decision == null) {
      return;
    }
    AppSubmissionReviewDecision decisionValue = decision.decision();
    if (decisionValue.blocksCatalogCandidateStaging()) {
      throw AppCatalogSidecars.invalidEntry(
          "only reviewed or caution submissions can have catalog candidates");
    }
    if (decisionValue == AppSubmissionReviewDecision.CAUTION
        && !catalogCandidate.cautionAllowed()) {
      throw AppCatalogSidecars.invalidEntry("caution candidates require explicit allowance");
    }
    if (decisionValue == AppSubmissionReviewDecision.REVIEWED
        && catalogCandidate.cautionAllowed()) {
      throw AppCatalogSidecars.invalidEntry(
          "reviewed candidates must not be marked as caution-allowed");
    }
  }

  private static boolean isPreReviewResultStatus(AppSubmissionIntakeStatus status) {
    return status == AppSubmissionIntakeStatus.PRE_REVIEW_PASSED
        || status == AppSubmissionIntakeStatus.PRE_REVIEW_FAILED;
  }

  private static boolean requiresDecisionMetadata(AppSubmissionIntakeStatus status) {
    return switch (status) {
      case REVIEWED,
          CAUTION,
          REJECTED,
          RESUBMISSION_REQUESTED,
          CATALOG_CANDIDATE_CREATED,
          STAGED_TO_BETA_CATALOG,
          BETA_INSTALL_SMOKE_PASSED ->
          true;
      case SUBMITTED,
          TRIAGED,
          REVIEWER_ASSIGNED,
          PRE_REVIEW_RUNNING,
          PRE_REVIEW_PASSED,
          PRE_REVIEW_FAILED,
          REVIEW_IN_PROGRESS,
          CLOSED ->
          false;
    };
  }

  private static boolean requiresCatalogCandidateMetadata(AppSubmissionIntakeStatus status) {
    return switch (status) {
      case CATALOG_CANDIDATE_CREATED, STAGED_TO_BETA_CATALOG, BETA_INSTALL_SMOKE_PASSED -> true;
      case SUBMITTED,
          TRIAGED,
          REVIEWER_ASSIGNED,
          PRE_REVIEW_RUNNING,
          PRE_REVIEW_PASSED,
          PRE_REVIEW_FAILED,
          REVIEW_IN_PROGRESS,
          REVIEWED,
          CAUTION,
          REJECTED,
          RESUBMISSION_REQUESTED,
          CLOSED ->
          false;
    };
  }

  private static List<String> addWarningIfMissing(List<String> existing, String warning) {
    if (existing.contains(warning)) {
      return existing;
    }
    ArrayList<String> copy = new ArrayList<>(existing);
    copy.add(warning);
    return List.copyOf(copy);
  }

  private static List<String> addWarnings(List<String> existing, List<String> additions) {
    ArrayList<String> copy = new ArrayList<>(existing);
    for (String warning : additions) {
      if (!copy.contains(warning)) {
        copy.add(warning);
      }
    }
    return List.copyOf(copy);
  }

  private static boolean requiresReviewerAssignment(AppSubmissionIntakeStatus status) {
    return switch (status) {
      case REVIEWED,
          CAUTION,
          REJECTED,
          RESUBMISSION_REQUESTED,
          CATALOG_CANDIDATE_CREATED,
          STAGED_TO_BETA_CATALOG,
          BETA_INSTALL_SMOKE_PASSED,
          CLOSED ->
          true;
      case SUBMITTED,
          TRIAGED,
          REVIEWER_ASSIGNED,
          PRE_REVIEW_RUNNING,
          PRE_REVIEW_PASSED,
          PRE_REVIEW_FAILED,
          REVIEW_IN_PROGRESS ->
          false;
    };
  }

  private static Instant parseInstant(String value, String fieldName) {
    try {
      return Instant.parse(value);
    } catch (DateTimeParseException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_ENTRY,
          fieldName + " must be an ISO-8601 instant",
          exception);
    }
  }

  private static List<String> stringList(Object value, String fieldName) {
    if (!(value instanceof List<?> list)) {
      throw AppCatalogSidecars.invalidEntry(fieldName + " must be an array");
    }
    return list.stream()
        .map(
            element -> {
              if (element instanceof String text) {
                return text;
              }
              throw AppCatalogSidecars.invalidEntry(fieldName + " must contain only strings");
            })
        .toList();
  }

  private static List<AppSubmissionIntakeAuditEvent> auditEvents(Object value) {
    if (!(value instanceof List<?> list)) {
      throw AppCatalogSidecars.invalidEntry(AUDIT_EVENTS_FIELD + " must be an array");
    }
    return list.stream().map(AppSubmissionIntakeAuditEvent::fromJsonValue).toList();
  }

  private static String bounded(String value, String fieldName, int maxChars) {
    return AppCatalogSidecars.requireBoundedSingleLine(
        value, fieldName, AppCatalogSidecars.INVALID_CATALOG_ENTRY, maxChars);
  }
}

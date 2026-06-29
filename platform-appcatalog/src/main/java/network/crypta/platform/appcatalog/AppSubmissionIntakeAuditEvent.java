package network.crypta.platform.appcatalog;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Redacted audit event stored inside a local submission intake record.
 *
 * <p>The event vocabulary is local to the file-backed intake queue. It records workflow milestones,
 * reviewer assignment, pre-review results, decisions, staging, and smoke evidence without storing
 * raw submission content, reason bodies, private key material, local paths, or tokens.
 *
 * @param eventKind stable local event kind
 * @param createdAt event timestamp
 * @param fromStatus previous intake status when this event records a state transition
 * @param toStatus resulting intake status when this event records a state transition
 * @param reviewerKeyId reviewer key id associated with the event
 * @param evidenceSha256 digest of external evidence, report, receipt, descriptor, or transparency
 *     log state
 * @param warnings bounded display-safe warnings
 */
public record AppSubmissionIntakeAuditEvent(
    String eventKind,
    Instant createdAt,
    Optional<AppSubmissionIntakeStatus> fromStatus,
    AppSubmissionIntakeStatus toStatus,
    Optional<String> reviewerKeyId,
    Optional<String> evidenceSha256,
    List<String> warnings) {
  private static final String EVENT_KIND_FIELD = "eventKind";
  private static final String CREATED_AT_FIELD = "createdAt";
  private static final String FROM_STATUS_FIELD = "fromStatus";
  private static final String TO_STATUS_FIELD = "toStatus";
  private static final String REVIEWER_KEY_ID_FIELD = "reviewerKeyId";
  private static final String EVIDENCE_SHA256_FIELD = "evidenceSha256";
  private static final String WARNINGS_FIELD = "warnings";

  /** Creates a validated audit event. */
  public AppSubmissionIntakeAuditEvent {
    eventKind = bounded(eventKind, EVENT_KIND_FIELD, 96);
    Objects.requireNonNull(createdAt, CREATED_AT_FIELD);
    Objects.requireNonNull(fromStatus, FROM_STATUS_FIELD);
    Objects.requireNonNull(toStatus, TO_STATUS_FIELD);
    Objects.requireNonNull(reviewerKeyId, REVIEWER_KEY_ID_FIELD);
    reviewerKeyId = reviewerKeyId.map(value -> bounded(value, REVIEWER_KEY_ID_FIELD, 128));
    Objects.requireNonNull(evidenceSha256, EVIDENCE_SHA256_FIELD);
    evidenceSha256 =
        evidenceSha256.map(
            value -> AppCatalogSidecars.requireLowercaseSha256(value, EVIDENCE_SHA256_FIELD));
    warnings =
        List.copyOf(Objects.requireNonNull(warnings, WARNINGS_FIELD)).stream()
            .map(value -> bounded(value, "intake.audit.warning", 256))
            .toList();
  }

  Map<String, Object> toJsonValue() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(7);
    json.put(EVENT_KIND_FIELD, eventKind);
    json.put(CREATED_AT_FIELD, createdAt.toString());
    fromStatus.ifPresent(value -> json.put(FROM_STATUS_FIELD, value.jsonValue()));
    json.put(TO_STATUS_FIELD, toStatus.jsonValue());
    reviewerKeyId.ifPresent(value -> json.put(REVIEWER_KEY_ID_FIELD, value));
    evidenceSha256.ifPresent(value -> json.put(EVIDENCE_SHA256_FIELD, value));
    json.put(WARNINGS_FIELD, warnings);
    return json;
  }

  static AppSubmissionIntakeAuditEvent fromJsonValue(Object value) {
    Map<String, Object> json = AppSubmissionJson.requireObject(value, "auditEvent");
    return new AppSubmissionIntakeAuditEvent(
        AppSubmissionJson.requireString(json, EVENT_KIND_FIELD, EVENT_KIND_FIELD),
        parseInstant(AppSubmissionJson.requireString(json, CREATED_AT_FIELD, CREATED_AT_FIELD)),
        AppSubmissionJson.optionalString(json, FROM_STATUS_FIELD, FROM_STATUS_FIELD)
            .map(AppSubmissionIntakeStatus::parse),
        AppSubmissionIntakeStatus.parse(
            AppSubmissionJson.requireString(json, TO_STATUS_FIELD, TO_STATUS_FIELD)),
        AppSubmissionJson.optionalString(json, REVIEWER_KEY_ID_FIELD, REVIEWER_KEY_ID_FIELD),
        AppSubmissionJson.optionalString(json, EVIDENCE_SHA256_FIELD, EVIDENCE_SHA256_FIELD),
        stringList(json.get(WARNINGS_FIELD)));
  }

  private static List<String> stringList(Object value) {
    if (!(value instanceof List<?> list)) {
      throw AppCatalogSidecars.invalidEntry(WARNINGS_FIELD + " must be an array");
    }
    return list.stream()
        .map(
            element -> {
              if (element instanceof String text) {
                return text;
              }
              throw AppCatalogSidecars.invalidEntry(WARNINGS_FIELD + " must contain only strings");
            })
        .toList();
  }

  private static Instant parseInstant(String value) {
    try {
      return Instant.parse(value);
    } catch (DateTimeParseException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_ENTRY,
          CREATED_AT_FIELD + " must be an ISO-8601 instant",
          exception);
    }
  }

  private static String bounded(String value, String fieldName, int maxChars) {
    return AppCatalogSidecars.requireBoundedSingleLine(
        value, fieldName, AppCatalogSidecars.INVALID_CATALOG_ENTRY, maxChars);
  }
}

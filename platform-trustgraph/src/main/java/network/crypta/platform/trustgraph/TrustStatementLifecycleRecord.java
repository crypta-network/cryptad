package network.crypta.platform.trustgraph;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Durable local lifecycle record for one imported trust statement fingerprint.
 *
 * <p>A lifecycle record is local operator policy attached to an already imported public statement.
 * It tells this node whether the statement may be used by local scoring, should remain visible only
 * as deprecated evidence, or has been locally revoked. The record is not a network-wide revocation
 * protocol, not a moderation signal, and not a compatibility layer for legacy Web-of-Trust plugins.
 * Stores key records by the canonical document fingerprint so re-importing the same statement
 * cannot erase a local deprecated or revoked decision.
 *
 * <p>The record carries only bounded public metadata. Notes and reason codes are trimmed and
 * capped, replacement URIs are redacted before storage, and actor/source fields are short labels.
 * Raw statement documents, signatures, fetched content, private insert URIs, tokens, private keys,
 * and local paths do not belong in this model.
 *
 * <p>Typical callers do not construct this record directly. Store implementations use {@link
 * #active(String, Instant)} when a statement has no stored lifecycle entry and {@link
 * #updated(String, TrustStatementLifecycleStatus, String, String, String, Instant, Instant, String,
 * String)} when a local operator or authorized app changes lifecycle state.
 *
 * @param statementFingerprint canonical statement document fingerprint used as the store key
 * @param status local lifecycle status consulted by scoring contribution gates
 * @param reasonCode short stable reason code, such as {@code operator-revoked}
 * @param note optional bounded operator or app note for local display only
 * @param replacementUri optional redacted replacement statement URI summary, never the raw URI
 * @param createdAt first time this local lifecycle record was created
 * @param updatedAt latest time this local lifecycle record was updated
 * @param actorAppId optional bounded app id that requested the local lifecycle change
 * @param source local source label such as {@code operator}, {@code app}, or {@code
 *     imported-metadata}
 * @see TrustGraphStore#lifecycle(String)
 * @see TrustGraphStore#updateLifecycle(String, TrustStatementLifecycleStatus, String, String,
 *     String, String, String)
 */
public record TrustStatementLifecycleRecord(
    String statementFingerprint,
    TrustStatementLifecycleStatus status,
    String reasonCode,
    String note,
    String replacementUri,
    Instant createdAt,
    Instant updatedAt,
    String actorAppId,
    String source) {
  private static final int MAX_FINGERPRINT_LENGTH = 128;
  private static final int MAX_REASON_CODE_LENGTH = 48;
  private static final int MAX_NOTE_LENGTH = 240;
  private static final int MAX_REPLACEMENT_URI_LENGTH = 80;
  private static final int MAX_ACTOR_APP_ID_LENGTH = 128;
  private static final int MAX_SOURCE_LENGTH = 32;
  private static final String SOURCE_OPERATOR = "operator";

  /**
   * Creates a validated lifecycle record.
   *
   * <p>Callers normally use {@link #updated(String, TrustStatementLifecycleStatus, String, String,
   * String, Instant, Instant, String, String)} so replacement URI redaction and default
   * reason/source labels happen in one place. The canonical constructor still validates loaded
   * durable records and test fixtures before the record reaches score evidence, statement
   * summaries, or audit-adjacent support output.
   *
   * <p>Validation is intentionally strict at this boundary. Fingerprints, notes, source labels, and
   * actor ids are bounded; unknown lifecycle sources collapse to {@code operator}; and {@code
   * updatedAt} must not precede {@code createdAt}. Replacement URI values passed to this
   * constructor are expected to already be summaries, so mutation code should prefer {@link
   * #updated(String, TrustStatementLifecycleStatus, String, String, String, Instant, Instant,
   * String, String)} when it receives a raw app-facing URI.
   *
   * @throws TrustGraphException when bounded text, reason-code, or timestamp validation fails
   * @throws NullPointerException when {@code status}, {@code createdAt}, or {@code updatedAt} is
   *     omitted
   */
  public TrustStatementLifecycleRecord {
    statementFingerprint =
        TrustStatementValidator.requiredText(
            "statementFingerprint", statementFingerprint, MAX_FINGERPRINT_LENGTH);
    java.util.Objects.requireNonNull(status, "status");
    reasonCode = normalizeReasonCode(reasonCode, defaultReason(status));
    note = TrustStatementValidator.optionalText("note", note, MAX_NOTE_LENGTH);
    replacementUri =
        TrustGraphStoreSanitizer.optionalAuditText(
            "replacementUri", replacementUri, MAX_REPLACEMENT_URI_LENGTH);
    Instant checkedCreatedAt = java.util.Objects.requireNonNull(createdAt, "createdAt");
    Instant checkedUpdatedAt = java.util.Objects.requireNonNull(updatedAt, "updatedAt");
    if (checkedUpdatedAt.isBefore(checkedCreatedAt)) {
      throw new TrustGraphException(
          "invalid_trust_statement_lifecycle",
          "Lifecycle field 'updatedAt' must not be before 'createdAt'.");
    }
    actorAppId =
        TrustGraphStoreSanitizer.optionalAuditText(
            "actorAppId", actorAppId, MAX_ACTOR_APP_ID_LENGTH);
    source = normalizeSource(source);
  }

  /**
   * Builds a default active lifecycle view for a statement without a stored local record.
   *
   * <p>The returned map-facing object uses the supplied timestamp for both record times. Store
   * implementations do not persist this value unless a caller explicitly reactivates a statement;
   * it exists so summaries and evidence can consistently report {@code active}. Because the value
   * is synthetic, its reason code is {@code default-active} and its source is {@code default}
   * rather than {@code operator} or {@code app}.
   *
   * @param statementFingerprint canonical document fingerprint for the imported statement being
   *     summarized
   * @param timestamp statement import time or store clock time used for the synthetic active view
   * @return active lifecycle view that does not represent a persisted mutation by itself
   * @throws TrustGraphException when the statement fingerprint is missing, too long, or unsafe
   * @throws NullPointerException when {@code timestamp} is omitted
   */
  public static TrustStatementLifecycleRecord active(
      String statementFingerprint, Instant timestamp) {
    return new TrustStatementLifecycleRecord(
        statementFingerprint,
        TrustStatementLifecycleStatus.ACTIVE,
        "default-active",
        null,
        null,
        timestamp,
        timestamp,
        null,
        "default");
  }

  /**
   * Builds a lifecycle record for a local mutation.
   *
   * <p>The method preserves the original creation time when a previous record exists, updates the
   * modification timestamp, normalizes the reason code and source, and converts a replacement URI
   * into a redacted summary. A blank replacement URI is omitted. The result is ready for memory or
   * file-backed storage and can be returned through Platform API summaries without exposing raw
   * statement bodies, raw signatures, fetched content, private insert URIs, tokens, or local paths.
   *
   * <p>This method does not verify the replacement URI, fetch the replacement statement, or publish
   * any lifecycle state to the network. It only records the local policy decision that scoring and
   * explanation code must honor for the supplied statement fingerprint.
   *
   * @param statementFingerprint canonical document fingerprint for the imported statement being
   *     changed
   * @param status lifecycle status to store locally for later scoring decisions
   * @param reasonCode optional bounded reason code, or a status-specific default when omitted
   * @param note optional bounded human note for local operator or app display
   * @param replacementUri optional Crypta content URI for a replacement statement, redacted if set
   * @param createdAt first lifecycle record timestamp to preserve across later mutations
   * @param updatedAt mutation timestamp for this local lifecycle change
   * @param actorAppId optional app id that requested the local lifecycle mutation
   * @param source local source label for the mutation workflow
   * @return validated lifecycle record ready for memory or file-backed storage
   * @throws TrustGraphException when lifecycle metadata is malformed or a replacement URI is unsafe
   * @throws NullPointerException when {@code status}, {@code createdAt}, or {@code updatedAt} is
   *     omitted
   */
  public static TrustStatementLifecycleRecord updated(
      String statementFingerprint,
      TrustStatementLifecycleStatus status,
      String reasonCode,
      String note,
      String replacementUri,
      Instant createdAt,
      Instant updatedAt,
      String actorAppId,
      String source) {
    return new TrustStatementLifecycleRecord(
        statementFingerprint,
        status,
        normalizeReasonCode(reasonCode, defaultReason(status)),
        note,
        replacementUri == null || replacementUri.isBlank()
            ? null
            : TrustGraphStoreSanitizer.redactedUriSummary(replacementUri),
        createdAt,
        updatedAt,
        actorAppId,
        source);
  }

  /**
   * Returns a deterministic JSON-compatible lifecycle summary.
   *
   * <p>The map preserves field order for stable API and test output. Optional fields are included
   * only when present after normalization. The returned summary contains the statement fingerprint,
   * lifecycle status, reason code, timestamps, source, and bounded optional metadata; it never
   * includes the raw statement document, signature value, fetched content, or an unredacted
   * replacement URI.
   *
   * @return bounded lifecycle metadata without raw statement bodies or raw replacement URIs
   */
  public Map<String, Object> toJson() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(9);
    json.put("statementFingerprint", statementFingerprint);
    json.put("status", status.jsonValue());
    json.put("reasonCode", reasonCode);
    if (note != null) {
      json.put("note", note);
    }
    if (replacementUri != null) {
      json.put("replacementUri", replacementUri);
    }
    json.put("createdAt", createdAt.toString());
    json.put("updatedAt", updatedAt.toString());
    if (actorAppId != null) {
      json.put("actorAppId", actorAppId);
    }
    json.put("source", source);
    return json;
  }

  static String normalizeReasonCode(String reasonCode, String fallback) {
    String normalized =
        TrustStatementValidator.optionalText("reasonCode", reasonCode, MAX_REASON_CODE_LENGTH);
    if (normalized == null) {
      return fallback;
    }
    String lower = normalized.toLowerCase(java.util.Locale.ROOT);
    if (!lower.matches("[a-z0-9][a-z0-9._-]{0,47}")) {
      throw new TrustGraphException(
          "invalid_trust_statement_lifecycle", "Field 'reasonCode' must be a short stable token.");
    }
    return lower;
  }

  private static String normalizeSource(String source) {
    String normalized = TrustStatementValidator.optionalText("source", source, MAX_SOURCE_LENGTH);
    if (normalized == null) {
      return SOURCE_OPERATOR;
    }
    return switch (normalized) {
      case SOURCE_OPERATOR, "app", "imported-metadata", "default" -> normalized;
      default -> SOURCE_OPERATOR;
    };
  }

  private static String defaultReason(TrustStatementLifecycleStatus status) {
    return switch (status) {
      case ACTIVE -> "operator-reactivated";
      case DEPRECATED -> "operator-deprecated";
      case REVOKED -> "operator-revoked";
    };
  }
}

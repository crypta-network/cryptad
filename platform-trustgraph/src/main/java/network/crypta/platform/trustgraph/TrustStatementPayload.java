package network.crypta.platform.trustgraph;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.jetbrains.annotations.NotNull;

/**
 * Canonical signed payload for a Trust Graph Preview statement.
 *
 * <p>The payload is deliberately bounded and shallow. It identifies an issuer, one subject, a
 * narrow context, score/confidence values, optional human-readable explanation fields, and the
 * issue/expiry timestamps used by the deterministic preview scorer. This is the only part of a
 * statement that AppVault signs: the root document wrapper and signature envelope are transport
 * metadata and are not included in the canonical payload JSON.
 *
 * <p>Payload construction enforces the same limits used by import and app-facing signing routes, so
 * callers cannot accidentally publish statements that would later fail local validation. Unknown
 * JSON fields are rejected by {@link TrustStatementParser} before a payload is constructed.
 *
 * @param issuer public issuer metadata
 * @param subject bounded trust subject
 * @param context trust context such as {@code profile} or {@code feed-source}
 * @param score integer score from -100 to 100
 * @param confidence integer confidence from 0 to 100
 * @param reason optional bounded human-readable reason
 * @param tags bounded immutable tag list
 * @param issuedAt issue instant in UTC
 * @param expiresAt optional expiry instant; when present it is later than {@code issuedAt}
 */
public record TrustStatementPayload(
    TrustIssuer issuer,
    TrustSubject subject,
    String context,
    int score,
    int confidence,
    String reason,
    List<String> tags,
    Instant issuedAt,
    Instant expiresAt) {
  /**
   * Public context labels supported by version 1 of the preview statement format.
   *
   * <p>Contexts are intentionally broad enough for the reference app scenarios but narrow enough to
   * keep scoring queries deterministic. A score only contributes to a query with the same subject
   * and context.
   */
  public static final List<String> ALLOWED_CONTEXTS =
      List.of("general", "profile", "feed-source", "app-review", "message-author");

  /**
   * Creates a validated payload in canonical field order.
   *
   * <p>The constructor normalizes optional text, freezes tags, rejects out-of-range score and
   * confidence values, and requires the expiry time to be later than the issue time. It never
   * stores private issuer material or app/session tokens.
   */
  public TrustStatementPayload {
    java.util.Objects.requireNonNull(issuer, "issuer");
    java.util.Objects.requireNonNull(subject, "subject");
    context = TrustStatementValidator.requiredContext(context);
    TrustStatementValidator.requireScore(score);
    TrustStatementValidator.requireConfidence(confidence);
    reason = TrustStatementValidator.optionalText("reason", reason, 280);
    tags = TrustStatementValidator.tags(tags);
    java.util.Objects.requireNonNull(issuedAt, "issuedAt");
    if (expiresAt != null && !expiresAt.isAfter(issuedAt)) {
      throw new TrustGraphException(
          "invalid_trust_statement", "Field 'expiresAt' must be later than 'issuedAt'.");
    }
  }

  /**
   * Returns whether this statement is expired at the supplied instant.
   *
   * <p>Expired statements remain useful as displayed evidence, but the preview scorer excludes them
   * from contributing evidence.
   *
   * @param now instant used for the expiry comparison
   * @return {@code true} when {@code expiresAt} is present and not after {@code now}
   */
  public boolean expiredAt(Instant now) {
    return expiresAt != null && !expiresAt.isAfter(now);
  }

  /**
   * Returns the payload as an insertion-ordered JSON object in canonical field order.
   *
   * @return JSON-ready payload map used by canonical signing, publication, and summaries
   */
  public Map<String, Object> toJson() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(9);
    json.put("issuer", issuer.toJson());
    json.put("subject", subject.toJson());
    json.put("context", context);
    json.put("score", score);
    json.put("confidence", confidence);
    if (reason != null) {
      json.put("reason", reason);
    }
    if (!tags.isEmpty()) {
      json.put("tags", tags);
    }
    json.put("issuedAt", issuedAt.toString());
    if (expiresAt != null) {
      json.put("expiresAt", expiresAt.toString());
    }
    return json;
  }

  @Override
  public @NotNull String toString() {
    return "TrustStatementPayload[issuerFingerprint="
        + issuer.publicKeyFingerprint()
        + ", subject="
        + subject.kind().jsonValue()
        + ", context="
        + context
        + ", score="
        + score
        + ", confidence="
        + confidence
        + ", issuedAt="
        + issuedAt
        + ", expiresAt="
        + expiresAt
        + "]";
  }
}

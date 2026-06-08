package network.crypta.platform.trustgraph;

import java.util.Locale;

/**
 * Local lifecycle state applied to an imported trust statement.
 *
 * <p>The lifecycle state is operator-local policy, not a network-verifiable revocation protocol. It
 * lets the local Trust Graph release-candidate service keep a durable decision beside a statement
 * fingerprint so scoring cannot silently use evidence that the operator or an authorized app has
 * deprecated or revoked. The state is intentionally small because it is serialized through Platform
 * API responses, file-backed store records, score evidence, and audit summaries.
 *
 * <p>The enum is deliberately not a moderation vocabulary. It only answers whether one imported
 * statement is eligible for local score contribution after every other scoring gate passes.
 * Routing, peer selection, content filtering, global trust propagation, and legacy plugin
 * compatibility remain outside this model.
 *
 * @see TrustStatementLifecycleRecord
 * @see TrustGraphEvidence
 */
public enum TrustStatementLifecycleStatus {
  /**
   * The statement is locally eligible for scoring when every other contribution gate passes.
   *
   * <p>Active is the default view for imported statements that do not have a stored lifecycle
   * mutation. It does not make the statement trusted by itself; the issuer must still be a local
   * anchor, the signature must verify, the statement must be unexpired, and confidence must be
   * non-zero.
   */
  ACTIVE("active"),

  /**
   * The statement remains visible for explanation but is locally excluded from scoring.
   *
   * <p>Deprecated is useful when an operator wants to retain history, show why older evidence did
   * not contribute, or point to a replacement statement without treating the old statement as
   * usable local trust evidence.
   */
  DEPRECATED("deprecated"),

  /**
   * The statement remains visible for explanation but is locally revoked and excluded.
   *
   * <p>Revoked is a local safety decision for this node. It blocks contribution in the Trust Graph
   * scorer, but it does not publish a global revocation, delete the public statement, or instruct
   * other subsystems to block content.
   */
  REVOKED("revoked");

  private final String jsonValue;

  TrustStatementLifecycleStatus(String jsonValue) {
    this.jsonValue = jsonValue;
  }

  /**
   * Parses a lifecycle status from app-facing text.
   *
   * <p>The parser accepts the lowercase JSON tokens and enum names. It rejects unknown values with
   * the Trust Graph validation error code so route handlers can return a bounded client error
   * without exposing implementation details. The accepted vocabulary is intentionally closed:
   * callers cannot smuggle routing, moderation, or legacy compatibility states through this field.
   *
   * @param value candidate lifecycle status supplied by a local API workflow or persisted record
   * @return parsed lifecycle status ready for store updates or evidence rendering
   * @throws TrustGraphException when the value is missing, too long, or not one of the supported
   *     statuses
   */
  public static TrustStatementLifecycleStatus parse(String value) {
    String normalized = TrustStatementValidator.requiredText("lifecycleStatus", value, 32);
    for (TrustStatementLifecycleStatus status : values()) {
      if (status.jsonValue.equalsIgnoreCase(normalized)
          || status.name().equalsIgnoreCase(normalized)) {
        return status;
      }
    }
    throw new TrustGraphException(
        "invalid_trust_statement_lifecycle",
        "Field 'lifecycleStatus' must be active, deprecated, or revoked.");
  }

  /**
   * Returns the stable lowercase JSON token for this lifecycle status.
   *
   * <p>The token is the wire/storage spelling used by Platform API summaries, file-backed lifecycle
   * records, and score evidence. It is stable across enum-name capitalization and should be used
   * instead of {@link #name()} for app-facing output.
   *
   * @return app-facing status value used in summaries and score evidence
   */
  public String jsonValue() {
    return jsonValue;
  }

  /**
   * Returns whether this local state allows a statement to contribute to a score.
   *
   * <p>This helper only reflects the lifecycle gate. A {@code true} result still leaves all other
   * Trust Graph scorer checks in force, including local anchor status, signature verification,
   * expiry, and confidence.
   *
   * @return {@code true} only for {@link #ACTIVE}
   */
  @SuppressWarnings("unused")
  public boolean contributes() {
    return this == ACTIVE;
  }

  /**
   * Returns the lowercase app-facing token for logs, diagnostics, and compact summaries.
   *
   * <p>The implementation mirrors {@link #jsonValue()} so accidental string interpolation uses the
   * same bounded vocabulary as API responses. Callers that build structured output should still
   * prefer {@link #jsonValue()} for clarity.
   *
   * @return lowercase lifecycle token for this status
   */
  @Override
  public String toString() {
    return jsonValue.toLowerCase(Locale.ROOT);
  }
}

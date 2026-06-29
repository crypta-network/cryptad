package network.crypta.platform.appcatalog;

import java.util.Locale;

/**
 * Stable event kinds for the local review transparency log.
 *
 * <p>These values form the on-disk and JSON vocabulary for host-owned review governance events.
 * They are deliberately narrower than the catalog model: an event records that this node observed a
 * receipt, evaluated local trust, applied an installation or update gate, or loaded reviewer
 * governance state. The values do not imply that a catalog, bundle, or reviewer is trusted by
 * itself; callers must read the associated trust-status fields on each record.
 *
 * <p>The lowercase strings returned by {@link #jsonValue()} are stable API values. They are used in
 * JSONL log records, Platform API filters, Web Shell views, developer tooling, and release
 * certification evidence. Add new values only when older readers can safely reject or ignore them.
 */
public enum AppReviewTransparencyEventKind {
  /**
   * A signed independent review receipt was observed locally.
   *
   * <p>The record is de-duplicated by receipt fingerprint so the same receipt is not appended for
   * every catalog listing. The subject fields come from the receipt payload rather than publisher
   * advisory metadata, which keeps malformed catalog entries from rewriting receipt history.
   */
  REVIEW_RECEIPT_OBSERVED("review_receipt_observed"),

  /**
   * A deterministic third-party submission package was created or received locally.
   *
   * <p>The record should reference submission and bundle digests only, never raw package contents.
   */
  SUBMISSION_CREATED("submission_created"),

  /**
   * A reviewer key was assigned to a third-party submission in the local beta intake queue.
   *
   * <p>The record should contain the reviewer key id and reason digest only, never reviewer private
   * key material, registry file paths, or raw assignment rationale text.
   */
  REVIEWER_ASSIGNED("reviewer_assigned"),

  /**
   * Automated pre-review completed for a submission package.
   *
   * <p>The record may reference the pre-review report digest and status in redacted warning fields.
   */
  PRE_REVIEW_COMPLETED("pre_review_completed"),

  /**
   * A reviewer recorded a final decision for a submission package.
   *
   * <p>Reviewed and caution decisions may be followed by receipt issuance; rejected decisions must
   * not create installable catalog candidates.
   */
  REVIEW_DECISION_RECORDED("review_decision_recorded"),

  /** A review receipt was issued for an accepted or caution submission decision. */
  REVIEW_RECEIPT_ISSUED("review_receipt_issued"),

  /** A reviewer rejected a submission package. */
  SUBMISSION_REJECTED("submission_rejected"),

  /** A resubmission package linked to an earlier submission id. */
  SUBMISSION_RESUBMITTED("submission_resubmitted"),

  /** A reviewed or caution submission was converted into a catalog candidate descriptor. */
  CATALOG_CANDIDATE_CREATED("catalog_candidate_created"),

  /**
   * A catalog app review receipt or publisher advisory state was evaluated against local policy.
   *
   * <p>This event captures the computed trust status, reviewer lifecycle status, policy id/version,
   * acknowledgement flags, and redacted evidence fields for an operator-visible evaluation.
   */
  REVIEW_TRUST_EVALUATED("review_trust_evaluated"),

  /**
   * The installation path applied the local app-review gate to a candidate catalog entry.
   *
   * <p>The event records the final gate status and warning flags after the candidate has been
   * rechecked. It is audit evidence for the local decision, not authorization to skip bundle or
   * catalog signature validation.
   */
  REVIEW_GATE_INSTALL("review_gate_install"),

  /**
   * The update path applied the local app-review gate to a candidate replacement version.
   *
   * <p>Records with this kind let operators compare installed state with update-candidate review
   * state and explain review deltas such as policy changes, reviewer rotation, or rejection.
   */
  REVIEW_GATE_UPDATE("review_gate_update"),

  /**
   * A policy-driven apply operation evaluated local app-review trust before continuing.
   *
   * <p>This kind is used for scheduler or policy surfaces that can apply updates when an app is
   * stopped. The record documents the local policy decision without exposing scheduler internals.
   */
  REVIEW_GATE_POLICY_APPLY("review_gate_policy_apply"),

  /**
   * A trusted-reviewer registry was loaded by the local node.
   *
   * <p>The associated record should contain only registry counts and warnings, never the registry
   * path or raw public key bytes. It gives operators an audit point for governance configuration.
   */
  REVIEWER_REGISTRY_LOADED("reviewer_registry_loaded"),

  /**
   * Local governance identified a reviewer key as active.
   *
   * <p>Active status means the key may authenticate receipts within its configured policy and
   * validity constraints. It does not bypass receipt signature, artifact, or app-id checks.
   */
  REVIEWER_KEY_ACTIVE("reviewer_key_active"),

  /**
   * Local governance identified a reviewer key as retired.
   *
   * <p>Retired keys can explain historical trust only inside an explicit validity window. The
   * status should be rendered separately from active trust in operator-facing views.
   */
  REVIEWER_KEY_RETIRED("reviewer_key_retired"),

  /**
   * Local governance identified a reviewer key as revoked.
   *
   * <p>Revoked keys fail closed for every receipt from that key id. Records of this kind help an
   * operator see why a previously trusted review no longer verifies locally.
   */
  REVIEWER_KEY_REVOKED("reviewer_key_revoked"),

  /**
   * Local governance observed or configured a reviewer-key rotation relationship.
   *
   * <p>The record may mention predecessor or successor key ids, but it must not include public key
   * bytes. Rotation metadata is explanatory and does not create transitive trust.
   */
  REVIEWER_KEY_ROTATED("reviewer_key_rotated"),

  /**
   * The local transparency log hash chain was verified.
   *
   * <p>This event is audit evidence for a verification action. The verification result still lives
   * on the record fields and can indicate either success or a redacted failure reason.
   */
  TRANSPARENCY_LOG_VERIFIED("transparency_log_verified");

  private final String jsonValue;

  AppReviewTransparencyEventKind(String jsonValue) {
    this.jsonValue = jsonValue;
  }

  /**
   * Parses a stable event-kind value.
   *
   * <p>Input is trimmed through the shared sidecar validator and compared case-insensitively to the
   * stable lowercase values. Unsupported text fails closed with the same catalog-entry error family
   * used by other governance sidecar parsers, which lets API query parsing and file verification
   * report malformed values without accepting partial data.
   *
   * @param raw configured, persisted, or query-string event kind text
   * @return matching event kind for the stable JSON value
   */
  public static AppReviewTransparencyEventKind parse(String raw) {
    String value =
        AppCatalogSidecars.requireNonBlankSingleLine(
                raw, "review transparency event kind", AppCatalogSidecars.INVALID_CATALOG_ENTRY)
            .toLowerCase(Locale.ROOT);
    for (AppReviewTransparencyEventKind kind : values()) {
      if (kind.jsonValue.equals(value)) {
        return kind;
      }
    }
    throw AppCatalogSidecars.invalidEntry("unsupported review transparency event kind: " + raw);
  }

  /**
   * Returns the stable lowercase JSON value.
   *
   * <p>The returned value is the only representation that should be written to JSONL transparency
   * records or exposed through Platform API responses. Enum names are implementation details and
   * should not be used as external contract values.
   *
   * @return lowercase event kind used by JSON, CLI, and UI surfaces
   */
  public String jsonValue() {
    return jsonValue;
  }
}

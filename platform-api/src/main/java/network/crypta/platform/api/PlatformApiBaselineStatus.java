package network.crypta.platform.api;

import java.util.Objects;

/**
 * Defines the closed lifecycle states for a named Platform API stable-baseline definition.
 *
 * <p>States advance through proposal, review, documentation, operational support, deprecation, and
 * end-of-support under registry transition rules. A definition's membership remains immutable
 * throughout those transitions. In particular, candidate or fixture-backed states do not create a
 * stable runtime promise, and rejection is terminal. Canonical JSON spellings are deliberately
 * strict so persisted history cannot introduce aliases or unknown lifecycle behavior.
 *
 * <p>The enum describes state only; {@link PlatformApiBaselineRegistry} owns allowed transitions,
 * predecessor continuity, and monotonic compatibility checks. Evidence authentication remains a
 * protected release-certification responsibility rather than a property inferred from a status
 * label.
 */
public enum PlatformApiBaselineStatus {
  /**
   * The definition has entered lifecycle review but is not a complete compatibility candidate.
   * Membership and supporting evidence may still be incomplete, so this state carries no runtime
   * support promise.
   */
  PROPOSED("proposed"),
  /**
   * The definition is complete enough for compatibility evaluation but is not supported. Its
   * membership can be tested as preview evidence without becoming an admission guarantee.
   */
  CANDIDATE("candidate"),
  /**
   * Required review has accepted the definition, pending stable documentation. Review alone does
   * not activate the baseline or authorize any descriptor.
   */
  REVIEWED("reviewed"),
  /**
   * Stable documentation is bound, pending authenticated operational activation. The complete
   * proposal remains non-production until protected release evidence advances it.
   */
  DOCUMENTED("documented"),
  /**
   * The baseline carries an active runtime compatibility promise. Apps may target it for admission,
   * subject to contract-range, capability, principal, consent, and sandbox policy.
   */
  ACTIVE("active"),
  /**
   * The baseline remains supported while its published end-of-support transition approaches. Newer
   * baselines must continue preserving its membership and endpoint semantics during this period.
   */
  DEPRECATED("deprecated"),
  /**
   * The baseline no longer carries a runtime compatibility promise. Its immutable definition and
   * lineage remain in history even though admission no longer treats it as supported.
   */
  END_OF_SUPPORT("end-of-support"),
  /**
   * The proposal was rejected and cannot advance further. The retained terminal record documents
   * the decision but never contributes supported baseline membership.
   */
  REJECTED("rejected");

  private final String jsonValue;

  PlatformApiBaselineStatus(String jsonValue) {
    this.jsonValue = jsonValue;
  }

  /**
   * Returns the canonical JSON spelling used by registry artifacts.
   *
   * <p>The value is stable, lowercase, and included in lifecycle digests. It is intended for
   * deterministic persistence and exact comparisons rather than localized operator display text.
   *
   * @return the stable, lowercase serialized lifecycle state
   */
  public String jsonValue() {
    return jsonValue;
  }

  /**
   * Returns whether this state still carries a runtime compatibility promise.
   *
   * <p>Both active and deprecated baselines remain admissible because deprecation precedes end of
   * support. Proposal, review, documentation, rejection, and terminal history states return {@code
   * false}; this classification does not grant app permissions.
   *
   * @return {@code true} only for active or deprecated-but-supported baselines
   */
  public boolean isSupported() {
    return this == ACTIVE || this == DEPRECATED;
  }

  /**
   * Parses the exact canonical JSON spelling without accepting aliases.
   *
   * <p>The parser is case-sensitive and does not trim whitespace. Unknown values fail closed so a
   * newer lifecycle state cannot be interpreted by an older reader without an explicit schema and
   * enum update.
   *
   * @param value the serialized lifecycle value to parse
   * @return the matching closed lifecycle state
   * @throws IllegalArgumentException if the value is not canonical and supported
   */
  public static PlatformApiBaselineStatus parse(String value) {
    String text = Objects.requireNonNull(value, "value");
    for (PlatformApiBaselineStatus status : values()) {
      if (status.jsonValue.equals(text)) {
        return status;
      }
    }
    throw new IllegalArgumentException("unsupported Platform API baseline status: " + text);
  }
}

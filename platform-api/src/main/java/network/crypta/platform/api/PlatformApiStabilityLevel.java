package network.crypta.platform.api;

import java.util.Locale;

/**
 * Stability classification for Platform API contract capabilities and endpoints.
 *
 * <p>Stability levels are public review metadata. They tell app authors and release reviewers how
 * much compatibility confidence to attach to a capability or route descriptor, but they do not
 * change endpoint behavior by themselves. Authorization, request semantics, and response semantics
 * remain defined by the actual Platform API handlers.
 *
 * <p>The verifier uses these levels to produce compatibility findings. Stable entries do not create
 * findings, experimental entries require explicit app opt-in, deprecated and scheduled entries are
 * release risks, and internal or operator-only entries are never valid manifest capabilities for
 * third-party apps. JSON values are lowercase and stable so catalog metadata, CLI output, and
 * release evidence can be compared deterministically.
 */
public enum PlatformApiStabilityLevel {
  /**
   * Stable app-facing API surface covered by the Platform API compatibility contract.
   *
   * <p>Stable entries are expected to remain available for the current contract line and are the
   * normal state for third-party app capabilities and endpoints.
   */
  STABLE("stable"),

  /**
   * Experimental app-facing API surface that may change across contract versions.
   *
   * <p>Apps can declare that they accept experimental capabilities through manifest metadata.
   * Without that opt-in, compatibility verification reports experimental use as a review risk.
   */
  EXPERIMENTAL("experimental"),

  /**
   * API surface that remains callable but should be migrated away from.
   *
   * <p>Deprecated entries are still part of the descriptor set so old apps can be reviewed
   * accurately, but tooling should encourage app authors to move to a replacement when one exists.
   */
  DEPRECATED("deprecated"),

  /**
   * API surface that remains callable now but has a planned removal contract version.
   *
   * <p>Scheduled entries carry stronger migration pressure than deprecated entries because
   * deprecation metadata can name a future compatibility contract where removal is expected.
   */
  SCHEDULED_FOR_REMOVAL("scheduled-for-removal"),

  /**
   * Host/operator local-management surface that is not third-party app-facing API.
   *
   * <p>Operator-only entries may be exposed over localhost routes for Web Shell or local management
   * workflows, but they are outside the Platform API 1.0 stable app baseline. The verifier treats
   * app declarations against these capabilities as errors even when the app targets experimental
   * APIs.
   */
  OPERATOR_ONLY("operator-only"),

  /**
   * Host/internal surface that is intentionally not part of the public app contract.
   *
   * <p>Internal entries must not be requested by app manifests. The verifier treats internal
   * capability use as an error even in non-strict mode.
   */
  INTERNAL("internal");

  private final String jsonValue;

  PlatformApiStabilityLevel(String jsonValue) {
    this.jsonValue = jsonValue;
  }

  /**
   * Returns the stable JSON value used in contract snapshots and release reports.
   *
   * <p>The returned value is the canonical wire/reporting form. It should be used instead of {@link
   * #name()} when writing contract JSON, CLI output, or release evidence.
   *
   * @return lowercase hyphenated stability label used by public metadata
   */
  public String jsonValue() {
    return jsonValue;
  }

  /**
   * Returns whether this level describes app-facing stable API.
   *
   * @return {@code true} only for stable entries
   */
  @SuppressWarnings("unused")
  public boolean isStableAppFacing() {
    return this == STABLE;
  }

  /**
   * Returns whether this level is still covered by the stable compatibility-window policy.
   *
   * <p>Deprecated and scheduled-for-removal entries remain in the stable baseline while they are
   * still present, but they require deprecation-window metadata and produce verifier findings.
   *
   * @return {@code true} for stable, deprecated, and scheduled-for-removal entries
   */
  public boolean isStableCompatibilityCovered() {
    return this == STABLE || this == DEPRECATED || this == SCHEDULED_FOR_REMOVAL;
  }

  /**
   * Returns whether this level describes app-facing experimental API.
   *
   * @return {@code true} only for experimental entries
   */
  @SuppressWarnings("unused")
  public boolean isExperimentalAppFacing() {
    return this == EXPERIMENTAL;
  }

  /**
   * Returns whether this level is outside third-party app compatibility declarations.
   *
   * @return {@code true} for internal and operator-only entries
   */
  public boolean isRestrictedAudience() {
    return this == INTERNAL || this == OPERATOR_ONLY;
  }

  /**
   * Parses a contract stability label.
   *
   * <p>Parsing is case-insensitive for valid labels after trimming surrounding whitespace. Unknown
   * labels are rejected so malformed or future contract snapshots fail loudly in tooling instead of
   * being silently interpreted as stable.
   *
   * @param value stability label from JSON or metadata
   * @return matching stability level represented by the label
   * @throws IllegalArgumentException if the value is unsupported
   */
  public static PlatformApiStabilityLevel parse(String value) {
    String normalized = value.trim().toLowerCase(Locale.ROOT);
    for (PlatformApiStabilityLevel level : values()) {
      if (level.jsonValue.equals(normalized)) {
        return level;
      }
    }
    throw new IllegalArgumentException("unsupported Platform API stability level: " + value);
  }
}

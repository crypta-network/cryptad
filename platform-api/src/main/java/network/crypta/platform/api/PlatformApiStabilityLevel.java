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
 * release risks, and internal entries are never valid manifest capabilities for third-party apps.
 * JSON values are lowercase and stable so catalog metadata, CLI output, and release evidence can be
 * compared deterministically.
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

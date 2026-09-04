package network.crypta.platform.api;

import java.util.Objects;

/**
 * Identifies the closed provenance boundary for baseline lifecycle evidence.
 *
 * <p>The kind is part of each lifecycle record's self-digest and determines which state transitions
 * can carry an operational compatibility promise. Fixture evidence remains useful for proposals,
 * preview, and self-tests but can never activate or end support for a baseline. Protected-release
 * evidence represents authenticated release coordinates; importing the frozen artifact is a
 * narrowly scoped bootstrap exception for the already completed Platform API {@code 1.0} freeze.
 * Parsing is exact and case-sensitive so persisted artifacts cannot introduce aliases that hash or
 * display differently.
 */
public enum PlatformApiBaselineEvidenceKind {
  /**
   * The immutable Platform API 1.0 bootstrap artifact retained from the completed freeze.
   *
   * <p>This kind is valid only for the exact frozen {@code 1.0} definition and its genesis lineage
   * entry; it is not a general-purpose import mechanism.
   */
  IMPORTED_FROZEN_BASELINE("imported-frozen-baseline"),
  /**
   * Developer-only or self-test evidence that can never activate runtime support.
   *
   * <p>Fixture records may exercise proposal and preview validation, but cannot establish active,
   * deprecated, or end-of-support lifecycle states.
   */
  FIXTURE("fixture"),
  /**
   * Authenticated evidence from a protected release operation.
   *
   * <p>The kind identifies the required trust boundary; registry validation still requires the
   * corresponding release coordinates and external receipt authentication.
   */
  PROTECTED_RELEASE("protected-release");

  private final String jsonValue;

  PlatformApiBaselineEvidenceKind(String jsonValue) {
    this.jsonValue = jsonValue;
  }

  /**
   * Returns the canonical JSON spelling used by registry artifacts.
   *
   * <p>The value is stable, lowercase, and included in the lineage self-digest. It is intended for
   * deterministic persistence and comparisons rather than operator-facing display localization.
   *
   * @return the stable, lowercase serialized value for this evidence kind
   */
  public String jsonValue() {
    return jsonValue;
  }

  /**
   * Parses the exact canonical JSON spelling without accepting aliases.
   *
   * <p>The comparison is case-sensitive and does not trim whitespace. This strict behavior keeps
   * lifecycle artifacts canonical and causes unknown future values to fail closed until this closed
   * enum and its readers are deliberately updated.
   *
   * @param value the serialized evidence kind to parse
   * @return the matching closed evidence kind
   * @throws IllegalArgumentException if the value is not canonical and supported
   */
  public static PlatformApiBaselineEvidenceKind parse(String value) {
    String text = Objects.requireNonNull(value, "value");
    for (PlatformApiBaselineEvidenceKind kind : values()) {
      if (kind.jsonValue.equals(text)) {
        return kind;
      }
    }
    throw new IllegalArgumentException("unsupported Platform API baseline evidence kind: " + text);
  }
}

package network.crypta.platform.api;

/**
 * Optional deprecation and removal metadata for a Platform API contract item.
 *
 * <p>This record is attached to capability and endpoint descriptors when the contract needs to tell
 * app authors that an item is deprecated or has a planned removal window. The metadata is advisory
 * by itself; the presence of a deprecation record does not change endpoint behavior, authorization,
 * or response payload semantics.
 *
 * <p>Version fields refer to Platform API compatibility contract versions, not Cryptad build
 * numbers and not URL API versions. A {@code null} value means the contract has no published value
 * for that part of the deprecation schedule. Notes are trimmed and blank notes collapse to {@code
 * null} so generated contract JSON stays concise.
 *
 * @param deprecatedSinceContractVersion first contract version where the item was deprecated, or
 *     {@code null}
 * @param removalContractVersion planned removal contract version, or {@code null}
 * @param note short operator/developer-facing migration note, or {@code null}
 */
public record PlatformApiDeprecation(
    Integer deprecatedSinceContractVersion, Integer removalContractVersion, String note) {
  /**
   * Validates optional contract version metadata.
   *
   * <p>Present version values must be positive because compatibility contract versions are
   * one-based integers. The constructor does not require a removal version to be present when a
   * deprecation version exists; early deprecation notices may not have a scheduled removal yet.
   */
  public PlatformApiDeprecation {
    deprecatedSinceContractVersion =
        normalizeVersion(deprecatedSinceContractVersion, "deprecatedSinceContractVersion");
    removalContractVersion = normalizeVersion(removalContractVersion, "removalContractVersion");
    note = normalizeOptional(note);
  }

  private static Integer normalizeVersion(Integer value, String fieldName) {
    if (value == null) {
      return null;
    }
    if (value <= 0) {
      throw new IllegalArgumentException(fieldName + " must be a positive integer");
    }
    return value;
  }

  private static String normalizeOptional(String value) {
    if (value == null) {
      return null;
    }
    String trimmed = value.trim();
    return trimmed.isEmpty() ? null : trimmed;
  }
}

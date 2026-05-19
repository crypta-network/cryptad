package network.crypta.platform.appcatalog;

import java.util.Locale;

/**
 * Local lifecycle status for a trusted reviewer key.
 *
 * <p>The status is operator-controlled local governance state. It is not read from catalogs or
 * receipt payloads, and it never grants trust by itself; receipt signatures, policy constraints,
 * artifact binding, and receipt expiry still have to verify.
 *
 * <p>The three states describe how the verifier should treat receipts that name a configured key
 * id. Active keys may verify current receipts inside their validity window. Retired keys can only
 * verify historical receipts inside an explicit window. Revoked keys fail closed for every receipt
 * and remain visible as governance evidence instead of being downgraded to unknown reviewers.
 *
 * <p>The lowercase values returned by {@link #jsonValue()} are stable across registry files, API
 * responses, Web Shell badges, CLI output, and release-certification reports.
 */
public enum TrustedReviewerKeyStatus {
  /**
   * Key may sign current receipts within its configured validity window.
   *
   * <p>An active key still has to match the receipt policy constraint and verify the receipt
   * signature. Active status alone does not trust catalog publishers or app bundles.
   */
  ACTIVE("active"),

  /**
   * Key is no longer current, but may authenticate historical receipts inside its window.
   *
   * <p>A retired key without an explicit validity end is not accepted for positive trust because
   * the verifier cannot determine the historical boundary safely.
   */
  RETIRED("retired"),

  /**
   * Key is revoked and must fail closed for every receipt.
   *
   * <p>Revocation is distinct from an unknown key. Operator surfaces should show that the key is
   * known locally but rejected by governance policy.
   */
  REVOKED("revoked");

  private final String jsonValue;

  TrustedReviewerKeyStatus(String jsonValue) {
    this.jsonValue = jsonValue;
  }

  /**
   * Parses a registry status value.
   *
   * <p>Registry parsing accepts the stable lowercase values case-insensitively after validating
   * that the input is a bounded single line. Unsupported values fail closed so a malformed trust
   * registry cannot silently create active reviewer keys.
   *
   * @param raw configured status text from a trusted-reviewer registry
   * @return matching local lifecycle status
   */
  public static TrustedReviewerKeyStatus parse(String raw) {
    String value =
        AppCatalogSidecars.requireNonBlankSingleLine(
                raw, "reviewer key status", AppCatalogSidecars.INVALID_CATALOG_ENTRY)
            .toLowerCase(Locale.ROOT);
    for (TrustedReviewerKeyStatus status : values()) {
      if (status.jsonValue.equals(value)) {
        return status;
      }
    }
    throw AppCatalogSidecars.invalidEntry("unsupported reviewer key status: " + raw);
  }

  /**
   * Returns the stable lowercase value used in API, CLI, docs, and audit summaries.
   *
   * <p>Use this value for persisted registry summaries and JSON responses. Enum names are not part
   * of the external review-governance contract.
   *
   * @return stable lowercase JSON-facing status value
   */
  public String jsonValue() {
    return jsonValue;
  }
}

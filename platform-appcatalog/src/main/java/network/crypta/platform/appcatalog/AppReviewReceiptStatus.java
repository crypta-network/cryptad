package network.crypta.platform.appcatalog;

import java.util.Locale;

/**
 * Policy outcome asserted by an independently signed app review receipt.
 *
 * <p>This vocabulary intentionally mirrors the legacy catalog review words without reusing {@link
 * AppCatalogReviewStatus}. Catalog review metadata is a publisher advisory claim carried by the
 * catalog signature. A receipt status is reviewer evidence carried by an independent reviewer
 * signature and interpreted through local reviewer-key policy.
 *
 * <p>The enum describes what the reviewer said, not whether the local node trusts that statement.
 * Trust is established only after signature verification, reviewer-key lookup, expiry checks, and
 * receipt-to-artifact binding. A trusted {@link #REJECTED} receipt is therefore strong negative
 * evidence, not an error in the receipt format.
 */
public enum AppReviewReceiptStatus {
  /**
   * The reviewer accepted the app version for the named review policy.
   *
   * <p>After a valid signature and trusted reviewer-key lookup, this becomes the positive {@code
   * trusted_reviewed} decision used by stricter install and update policies.
   */
  REVIEWED("reviewed"),

  /**
   * The reviewer accepted the app version only with operator-visible caution.
   *
   * <p>This status preserves reviewer evidence and display metadata, but it is not a trusted
   * positive review for policies that require {@code trusted_reviewed}.
   */
  CAUTION("caution"),

  /**
   * The reviewer rejected the app version for the named review policy.
   *
   * <p>When the receipt verifies, this is trusted negative evidence. UI and API callers should not
   * render it as a successful review.
   */
  REJECTED("rejected");

  private final String catalogValue;

  AppReviewReceiptStatus(String catalogValue) {
    this.catalogValue = catalogValue;
  }

  /**
   * Parses a receipt status from sidecar text.
   *
   * <p>The parser accepts only stable lower-case values, with case folded for operator-authored
   * sidecars. The input is bounded and single-line so malformed catalog data cannot create
   * multi-line diagnostics or unstable serialized output.
   *
   * @param value raw sidecar value from receipt properties
   * @param fieldName field name used in validation diagnostics
   * @return parsed receipt status represented by the supplied text
   * @throws AppCatalogException if the value is blank, multi-line, too long, or unsupported
   */
  public static AppReviewReceiptStatus parse(String value, String fieldName) {
    String normalized =
        AppCatalogSidecars.requireBoundedSingleLine(
                value, fieldName, AppCatalogSidecars.INVALID_CATALOG_ENTRY, 32)
            .toLowerCase(Locale.ROOT);
    for (AppReviewReceiptStatus status : values()) {
      if (status.catalogValue.equals(normalized)) {
        return status;
      }
    }
    throw AppCatalogSidecars.invalidEntry(fieldName + " is not a supported review receipt status");
  }

  /**
   * Returns the stable sidecar/API spelling for this receipt status.
   *
   * <p>The returned value is serialized into receipt properties and compared with legacy publisher
   * review metadata when producing mismatch warnings. It is stable API surface for catalog tools
   * and Platform API clients.
   *
   * @return lower-case receipt status value used in properties and JSON
   */
  public String catalogValue() {
    return catalogValue;
  }
}

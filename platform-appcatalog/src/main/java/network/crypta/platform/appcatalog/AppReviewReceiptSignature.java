package network.crypta.platform.appcatalog;

import java.util.Base64;
import java.util.Objects;

/**
 * Signature value attached to an app review receipt.
 *
 * <p>The signature authenticates {@link AppReviewReceiptPayload#canonicalPayloadBytes()}; it does
 * not sign the signature value itself.
 *
 * <p>The value is intentionally just the public signature sidecar: algorithm name and base64
 * signature bytes. It carries no reviewer public key, private key, trust decision, local key-file
 * path, or catalog signer information. Verification happens in {@link AppReviewReceiptVerifier},
 * where the reviewer key id from the payload is resolved through the node-local {@link
 * TrustedReviewerKeys} registry.
 *
 * <p>Instances validate base64 structure at construction time so malformed receipts fail before any
 * policy decision is derived. Decoding remains cheap and deterministic; callers receive a fresh
 * byte array on each access.
 *
 * @param algorithm signature algorithm, currently {@value #SIGNATURE_ALGORITHM}
 * @param valueBase64 base64-encoded signature bytes over canonical payload bytes
 */
public record AppReviewReceiptSignature(String algorithm, String valueBase64) {
  /**
   * Supported receipt signature algorithm.
   *
   * <p>Review receipts currently use the same Ed25519 algorithm identifier as signed app bundles,
   * but reviewer key trust remains separate from bundle-signing trust.
   */
  public static final String SIGNATURE_ALGORITHM = TrustedReviewerKey.SIGNATURE_ALGORITHM;

  /**
   * Creates a structurally validated signature value.
   *
   * <p>The constructor confirms the algorithm is supported and the signature text is non-blank,
   * single-line base64. It does not verify the signature because verification requires the payload
   * bytes and a locally trusted reviewer public key.
   *
   * @param algorithm signature algorithm declared by the receipt
   * @param valueBase64 base64-encoded signature bytes supplied with the receipt
   */
  public AppReviewReceiptSignature {
    if (!SIGNATURE_ALGORITHM.equals(Objects.requireNonNull(algorithm, "algorithm"))) {
      throw AppCatalogSidecars.invalidEntry(
          "unsupported review.receipt.signature.algorithm: " + algorithm);
    }
    valueBase64 =
        AppCatalogSidecars.requireNonBlankSingleLine(
            valueBase64,
            "review.receipt.signature.value.base64",
            AppCatalogSidecars.INVALID_CATALOG_ENTRY);
    try {
      Base64.getDecoder().decode(valueBase64);
    } catch (IllegalArgumentException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_ENTRY,
          "invalid review.receipt.signature.value.base64",
          exception);
    }
  }

  /**
   * Decodes signature bytes.
   *
   * <p>The returned array is newly decoded for the caller. Mutating it cannot affect this immutable
   * record or future verification attempts.
   *
   * @return fresh byte array containing the detached signature bytes
   */
  public byte[] signatureBytes() {
    return Base64.getDecoder().decode(valueBase64);
  }
}

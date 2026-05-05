package network.crypta.platform.appcatalog;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.Base64;
import java.util.Objects;

/**
 * Signs review receipt payloads with Ed25519.
 *
 * <p>This helper is used by developer tooling and deterministic tests that need to produce an
 * independent review receipt before embedding it in a catalog. It signs only {@link
 * AppReviewReceiptPayload#canonicalPayloadBytes()} and returns an {@link AppReviewReceipt} that
 * pairs the original payload with a detached base64 signature.
 *
 * <p>The class does not load private keys, choose reviewer ids, or persist receipts. Those
 * responsibilities remain in callers such as the developer CLI so private key material stays out of
 * catalog parsing, catalog writing, Platform API summaries, and release-certification output.
 * Verification uses {@link AppReviewReceiptVerifier}; a freshly signed receipt is not trusted until
 * a node resolves the reviewer key id through its local registry.
 */
public final class AppReviewReceiptSigner {
  private AppReviewReceiptSigner() {}

  /**
   * Signs a review receipt payload.
   *
   * <p>The payload is not copied or mutated. The returned receipt references the same immutable
   * payload and a new signature value. If the supplied key cannot sign with the configured Ed25519
   * algorithm, the method fails closed with an {@link AppCatalogException}.
   *
   * @param payload canonical payload whose deterministic bytes should be signed
   * @param privateKey Ed25519 private key controlled by the reviewer
   * @return signed receipt containing the original payload and detached signature
   */
  public static AppReviewReceipt sign(AppReviewReceiptPayload payload, PrivateKey privateKey) {
    Objects.requireNonNull(payload, "payload");
    Objects.requireNonNull(privateKey, "privateKey");
    return new AppReviewReceipt(
        payload,
        new AppReviewReceiptSignature(
            AppReviewReceiptSignature.SIGNATURE_ALGORITHM,
            Base64.getEncoder()
                .encodeToString(signBytes(payload.canonicalPayloadBytes(), privateKey))));
  }

  private static byte[] signBytes(byte[] payloadBytes, PrivateKey privateKey) {
    try {
      Signature signer = Signature.getInstance(AppReviewReceiptSignature.SIGNATURE_ALGORITHM);
      signer.initSign(privateKey);
      signer.update(payloadBytes);
      return signer.sign();
    } catch (GeneralSecurityException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_ENTRY, "failed to sign review receipt", exception);
    }
  }
}

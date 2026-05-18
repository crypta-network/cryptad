package network.crypta.platform.trustgraph;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Verifies preview trust-statement signatures when issuer public key material is present.
 *
 * <p>The Trust Graph Preview stores imported statements even when they cannot be verified, but the
 * scorer only allows verified, locally anchored statements with positive confidence to contribute.
 * This keeps pasted or fetched documents visible as evidence without letting a forged issuer
 * fingerprint influence a score.
 *
 * <p>The verifier implements the preview AppVault contract only. It does not discover issuer keys,
 * build recursive trust chains, contact the network, or provide legacy WebOfTrust compatibility.
 */
public final class TrustStatementVerifier {
  private static final String ALGORITHM_ED25519 = "Ed25519";

  private TrustStatementVerifier() {}

  /**
   * Returns whether a statement has a valid AppVault preview signature.
   *
   * <p>The preview document format can include the issuer's X.509-encoded public key in {@code
   * payload.issuer.publicKeyBase64}. When present, this method checks that the key hashes to {@code
   * payload.issuer.publicKeyFingerprint} and verifies {@code signature.value} over the documented
   * domain-separated canonical payload bytes. Statements without an inline public key, a matching
   * fingerprint, or a valid signature are retained as unverified evidence.
   *
   * <p>Verification failures are reported as {@code false} instead of exceptions because callers
   * treat malformed signatures as an evidence attribute, not as an import failure after shape
   * validation has succeeded.
   *
   * @param document parsed trust statement
   * @return {@code true} when the signature verifies against the issuer public key
   */
  public static boolean isSignatureVerified(TrustStatementDocument document) {
    java.util.Objects.requireNonNull(document, "document");
    String publicKeyBase64 = document.payload().issuer().publicKeyBase64();
    if (publicKeyBase64 == null) {
      return false;
    }
    try {
      byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyBase64);
      if (!TrustStatementFingerprint.sha256Hex(publicKeyBytes)
          .equals(document.payload().issuer().publicKeyFingerprint())) {
        return false;
      }
      PublicKey publicKey =
          KeyFactory.getInstance(ALGORITHM_ED25519)
              .generatePublic(new X509EncodedKeySpec(publicKeyBytes));
      Signature verifier = Signature.getInstance(ALGORITHM_ED25519);
      verifier.initVerify(publicKey);
      verifier.update(TrustStatementCanonicalizer.canonicalPayloadBytes(document.payload()));
      return verifier.verify(Base64.getDecoder().decode(document.signature().value()));
    } catch (IllegalArgumentException | GeneralSecurityException _) {
      return false;
    }
  }
}

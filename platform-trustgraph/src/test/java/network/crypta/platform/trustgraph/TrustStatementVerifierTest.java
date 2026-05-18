package network.crypta.platform.trustgraph;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class TrustStatementVerifierTest {
  @Test
  void isSignatureVerified_whenStatementIsSignedByIssuerKey_expectTrue()
      throws GeneralSecurityException {
    SignedFixture fixture = signedFixture();

    boolean verified = TrustStatementVerifier.isSignatureVerified(fixture.document());

    assertTrue(verified);
  }

  @Test
  void isSignatureVerified_whenIssuerPublicKeyMissing_expectFalse()
      throws GeneralSecurityException {
    SignedFixture fixture = signedFixture();
    TrustStatementDocument withoutPublicKey =
        documentWithIssuer(fixture.document(), issuerWithoutPublicKey(fixture.document()));

    boolean verified = TrustStatementVerifier.isSignatureVerified(withoutPublicKey);

    assertFalse(verified);
  }

  @Test
  void isSignatureVerified_whenIssuerFingerprintDoesNotMatchKey_expectFalse()
      throws GeneralSecurityException {
    SignedFixture fixture = signedFixture();
    TrustStatementDocument wrongFingerprint =
        documentWithIssuer(
            fixture.document(),
            new TrustIssuer(
                "issuer-1",
                "wrong-fingerprint",
                fixture.document().payload().issuer().publicKeyBase64(),
                null));

    boolean verified = TrustStatementVerifier.isSignatureVerified(wrongFingerprint);

    assertFalse(verified);
  }

  @Test
  void isSignatureVerified_whenPayloadChangesAfterSigning_expectFalse()
      throws GeneralSecurityException {
    SignedFixture fixture = signedFixture();
    TrustStatementPayload payload = fixture.document().payload();
    TrustStatementDocument tampered =
        new TrustStatementDocument(
            fixture.document().type(),
            new TrustStatementPayload(
                payload.issuer(),
                payload.subject(),
                payload.context(),
                payload.score() + 1,
                payload.confidence(),
                payload.reason(),
                payload.tags(),
                payload.issuedAt(),
                payload.expiresAt()),
            fixture.document().signature());

    boolean verified = TrustStatementVerifier.isSignatureVerified(tampered);

    assertFalse(verified);
  }

  @Test
  void isSignatureVerified_whenSignatureIsMalformedBase64_expectFalse()
      throws GeneralSecurityException {
    SignedFixture fixture = signedFixture();
    TrustStatementDocument malformedSignature =
        new TrustStatementDocument(
            fixture.document().type(),
            fixture.document().payload(),
            new TrustSignatureEnvelope(
                TrustDocumentTypes.APP_VAULT_ED25519_PREVIEW_ALGORITHM,
                TrustDocumentTypes.TRUST_STATEMENT_V1,
                "not-base64!"));

    boolean verified = TrustStatementVerifier.isSignatureVerified(malformedSignature);

    assertFalse(verified);
  }

  private static SignedFixture signedFixture() throws GeneralSecurityException {
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    String publicKeyBase64 = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
    String fingerprint = TrustStatementFingerprint.sha256Hex(keyPair.getPublic().getEncoded());
    TrustStatementPayload payload =
        new TrustStatementPayload(
            new TrustIssuer("issuer-1", fingerprint, publicKeyBase64, null),
            new TrustSubject(TrustSubjectKind.PROFILE, "USK@example/profile.json", null),
            "profile",
            50,
            80,
            "known publisher",
            List.of("local"),
            Instant.parse("2026-05-16T00:00:00Z"),
            Instant.parse("2026-11-16T00:00:00Z"));
    Signature signer = Signature.getInstance("Ed25519");
    signer.initSign(keyPair.getPrivate());
    signer.update(TrustStatementCanonicalizer.canonicalPayloadBytes(payload));
    TrustStatementDocument document =
        new TrustStatementDocument(
            TrustDocumentTypes.TRUST_STATEMENT_V1,
            payload,
            new TrustSignatureEnvelope(
                TrustDocumentTypes.APP_VAULT_ED25519_PREVIEW_ALGORITHM,
                TrustDocumentTypes.TRUST_STATEMENT_V1,
                Base64.getEncoder().encodeToString(signer.sign())));
    return new SignedFixture(document);
  }

  private static TrustStatementDocument documentWithIssuer(
      TrustStatementDocument source, TrustIssuer issuer) {
    TrustStatementPayload payload = source.payload();
    return new TrustStatementDocument(
        source.type(),
        new TrustStatementPayload(
            issuer,
            payload.subject(),
            payload.context(),
            payload.score(),
            payload.confidence(),
            payload.reason(),
            payload.tags(),
            payload.issuedAt(),
            payload.expiresAt()),
        source.signature());
  }

  private static TrustIssuer issuerWithoutPublicKey(TrustStatementDocument document) {
    TrustIssuer issuer = document.payload().issuer();
    return new TrustIssuer(issuer.identityId(), issuer.publicKeyFingerprint(), null);
  }

  private record SignedFixture(TrustStatementDocument document) {}
}

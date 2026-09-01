package network.crypta.platform.appcatalog;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import network.crypta.platform.appdist.TrustedAppKeyLifecycle;
import network.crypta.platform.appdist.TrustedAppKeyPolicy;
import network.crypta.platform.appdist.TrustedAppKeys;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class CatalogEndorsementTest {
  @Test
  void verifyDirect_whenEndorsementIsAuthentic_expectDirectActiveEvidenceWithoutTrust()
      throws Exception {
    KeyPair keyPair = CatalogSignedDocumentTestSupport.keyPair();
    CatalogEndorsement endorsement = CatalogSignedDocumentTestSupport.signedEndorsement(keyPair);

    CatalogEndorsementVerification result =
        CatalogEndorsementVerifier.verifyDirect(
            endorsement.canonicalDocumentBytes(),
            TrustedAppKeys.of(CatalogSignedDocumentTestSupport.trustedKey(keyPair)),
            CatalogSignedDocumentTestSupport.NOW);

    assertEquals(CatalogEndorsementVerification.Status.ACTIVE, result.status());
    assertTrue(CatalogEndorsementVerification.DIRECT);
    assertTrue(result.activeContribution());
    assertFalse(CatalogEndorsementVerification.TRANSITIVE);
    assertFalse(CatalogEndorsementVerification.TRUST_GRANTED);
  }

  @Test
  void verifyDirect_whenIssuerIsRevoked_expectOnlyItsContributionBecomesInactive()
      throws Exception {
    KeyPair keyPair = CatalogSignedDocumentTestSupport.keyPair();
    CatalogEndorsement endorsement = CatalogSignedDocumentTestSupport.signedEndorsement(keyPair);
    TrustedAppKeyPolicy revokedPolicy =
        new TrustedAppKeyPolicy(
            CatalogSignedDocumentTestSupport.trustedKey(keyPair),
            TrustedAppKeyLifecycle.REVOKED,
            Instant.MIN,
            Instant.MAX);

    CatalogEndorsementVerification result =
        CatalogEndorsementVerifier.verifyDirect(
            endorsement,
            TrustedAppKeys.ofPolicies(revokedPolicy),
            CatalogSignedDocumentTestSupport.NOW);

    assertEquals(CatalogEndorsementVerification.Status.INACTIVE_ISSUER, result.status());
    assertFalse(result.activeContribution());
    assertFalse(CatalogEndorsementVerification.TRUST_GRANTED);
  }

  @Test
  void verifyDirect_whenEndorsementIsExpired_expectRetainedEvidenceIsInactive() throws Exception {
    KeyPair keyPair = CatalogSignedDocumentTestSupport.keyPair();
    CatalogEndorsement endorsement = CatalogSignedDocumentTestSupport.signedEndorsement(keyPair);

    CatalogEndorsementVerification result =
        CatalogEndorsementVerifier.verifyDirect(
            endorsement,
            TrustedAppKeys.of(CatalogSignedDocumentTestSupport.trustedKey(keyPair)),
            CatalogSignedDocumentTestSupport.NOW.plusSeconds(7200));

    assertEquals(CatalogEndorsementVerification.Status.EXPIRED, result.status());
    assertFalse(result.activeContribution());
  }

  @Test
  void verifyDirect_whenSelfDigestIsSubstituted_expectFailsClosed() throws Exception {
    KeyPair keyPair = CatalogSignedDocumentTestSupport.keyPair();
    CatalogEndorsement endorsement = CatalogSignedDocumentTestSupport.signedEndorsement(keyPair);
    CatalogEndorsement substituted =
        new CatalogEndorsement(
            endorsement.content(),
            new CatalogEndorsement.Authentication(
                "f".repeat(64),
                endorsement.authentication().signatureAlgorithm(),
                endorsement.authentication().signatureValueBase64()));
    TrustedAppKeys trustedKeys =
        TrustedAppKeys.of(CatalogSignedDocumentTestSupport.trustedKey(keyPair));

    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class,
            () ->
                CatalogEndorsementVerifier.verifyDirect(
                    substituted, trustedKeys, CatalogSignedDocumentTestSupport.NOW));

    assertEquals(CatalogSignedDocumentSupport.INVALID_ENDORSEMENT, exception.errorCode());
  }

  @Test
  void evidence_whenLabelsOrReasonExceedBounds_expectRejectsInput() {
    Optional<String> noDigest = Optional.empty();
    Optional<String> noReason = Optional.empty();
    List<String> oversizedLabels = List.of("label".repeat(20));
    List<String> noLabels = List.of();
    Optional<String> oversizedReason = Optional.of("reason".repeat(100));

    assertThrows(
        AppCatalogException.class,
        () -> new CatalogEndorsement.Evidence(noDigest, noDigest, oversizedLabels, noReason));
    assertThrows(
        AppCatalogException.class,
        () -> new CatalogEndorsement.Evidence(noDigest, noDigest, noLabels, oversizedReason));
  }

  @Test
  void parse_whenDocumentContainsUnknownField_expectRejectsClosedInput() throws Exception {
    CatalogEndorsement endorsement =
        CatalogSignedDocumentTestSupport.signedEndorsement(
            CatalogSignedDocumentTestSupport.keyPair());
    String document = new String(endorsement.canonicalDocumentBytes(), StandardCharsets.UTF_8);
    byte[] unknownField =
        document.replaceFirst("\\{", "{\"transitive\":true,").getBytes(StandardCharsets.UTF_8);

    assertThrows(AppCatalogException.class, () -> CatalogEndorsement.parse(unknownField));
  }
}

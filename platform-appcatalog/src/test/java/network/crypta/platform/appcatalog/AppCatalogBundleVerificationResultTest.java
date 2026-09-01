package network.crypta.platform.appcatalog;

import network.crypta.platform.appdist.AppBundleDigest;
import network.crypta.platform.appdist.AppBundleSignature;
import network.crypta.platform.appdist.AppBundleVerification;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class AppCatalogBundleVerificationResultTest {
  private static final String DIGEST = "1".repeat(64);
  private static final String PUBLISHER_KEY_ID = "publisher-key";
  private static final String PUBLISHER_BINDING_ID = "publisher-binding";

  @Test
  void constructor_whenScopedIdentityIsComplete_expectRecordedAuthorization() {
    AppCatalogBundleVerificationResult result =
        new AppCatalogBundleVerificationResult(
            PUBLISHER_KEY_ID, DIGEST, PUBLISHER_BINDING_ID, DIGEST, true, DIGEST);

    assertEquals(PUBLISHER_KEY_ID, result.publisherKeyId());
    assertEquals(DIGEST, result.publisherKeyFingerprintSha256());
    assertEquals(PUBLISHER_BINDING_ID, result.authorizationPolicyId());
    assertEquals(DIGEST, result.authorizationPolicyDigestSha256());
    assertEquals(DIGEST, result.signedContentDigestSha256());
    assertTrue(result.catalogScoped());
  }

  @Test
  void constructor_whenScopedIdentityIsIncomplete_expectRejection() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new AppCatalogBundleVerificationResult(
                PUBLISHER_KEY_ID, "", PUBLISHER_BINDING_ID, DIGEST, true, DIGEST));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new AppCatalogBundleVerificationResult(
                PUBLISHER_KEY_ID, DIGEST, PUBLISHER_BINDING_ID, "", true, DIGEST));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new AppCatalogBundleVerificationResult(
                PUBLISHER_KEY_ID, DIGEST, PUBLISHER_BINDING_ID, DIGEST, true, ""));
  }

  @Test
  void constructor_whenCompatibilityOverloadIsUsed_expectUnscopedResult() {
    AppCatalogBundleVerificationResult result =
        new AppCatalogBundleVerificationResult(
            PUBLISHER_KEY_ID, DIGEST, "global-policy", "", false);

    assertFalse(result.catalogScoped());
    assertEquals("", result.signedContentDigestSha256());
  }

  @Test
  void legacyCompatibility_whenSignatureIsPresent_expectKeyIdentityOnly() {
    AppBundleSignature signature =
        new AppBundleSignature(
            AppBundleSignature.SIGNATURE_VERSION,
            AppBundleSignature.SIGNATURE_ALGORITHM,
            PUBLISHER_KEY_ID,
            AppBundleDigest.DIGEST_FILE_NAME,
            "AA==");

    AppCatalogBundleVerificationResult result =
        AppCatalogBundleVerificationResult.legacyCompatibility(signature);

    assertEquals(PUBLISHER_KEY_ID, result.publisherKeyId());
    assertFalse(result.catalogScoped());
    assertEquals("", result.publisherKeyFingerprintSha256());
    assertThrows(
        NullPointerException.class,
        () -> AppCatalogBundleVerificationResult.legacyCompatibility(null));
  }

  @Test
  void unsignedDevelopmentCompatibility_whenRequested_expectExplicitUnscopedMarker() {
    AppCatalogBundleVerificationResult result =
        AppCatalogBundleVerificationResult.unsignedDevelopmentCompatibility();

    assertEquals("unsigned-development", result.publisherKeyId());
    assertFalse(result.catalogScoped());
    assertEquals("", result.signedContentDigestSha256());
  }

  @Test
  void trustedAppKeys_whenVerificationIsComplete_expectGlobalIdentity() {
    AppBundleVerification verification =
        AppBundleVerification.signed(
            PUBLISHER_KEY_ID, AppBundleSignature.SIGNATURE_ALGORITHM, DIGEST, DIGEST);

    AppCatalogBundleVerificationResult result =
        AppCatalogBundleVerificationResult.trustedAppKeys(verification);

    assertEquals(PUBLISHER_KEY_ID, result.publisherKeyId());
    assertEquals(DIGEST, result.publisherKeyFingerprintSha256());
    assertEquals(DIGEST, result.signedContentDigestSha256());
    assertFalse(result.catalogScoped());
  }

  @Test
  void trustedAppKeys_whenVerificationIdentityIsIncomplete_expectRejection() {
    AppBundleVerification unsigned = AppBundleVerification.unsigned();
    AppBundleVerification missingFingerprints =
        AppBundleVerification.signed(PUBLISHER_KEY_ID, AppBundleSignature.SIGNATURE_ALGORITHM);

    assertThrows(
        IllegalArgumentException.class,
        () -> AppCatalogBundleVerificationResult.trustedAppKeys(unsigned));
    assertThrows(
        IllegalArgumentException.class,
        () -> AppCatalogBundleVerificationResult.trustedAppKeys(missingFingerprints));
    assertThrows(
        NullPointerException.class, () -> AppCatalogBundleVerificationResult.trustedAppKeys(null));
  }

  @Test
  void constructor_whenIdentityOrDigestIsMalformed_expectRejection() {
    assertThrows(
        IllegalArgumentException.class,
        () -> new AppCatalogBundleVerificationResult(" ", "", "legacy-policy", "", false, ""));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new AppCatalogBundleVerificationResult(
                PUBLISHER_KEY_ID, "invalid", "legacy-policy", "", false, ""));
  }
}

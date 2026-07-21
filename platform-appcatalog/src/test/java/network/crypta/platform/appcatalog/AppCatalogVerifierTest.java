package network.crypta.platform.appcatalog;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import network.crypta.platform.appdist.TrustedAppKey;
import network.crypta.platform.appdist.TrustedAppKeys;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class AppCatalogVerifierTest {
  private static final String EXPECTED_KEY_ID = "stable-catalog-production";
  private static final String OTHER_TRUSTED_KEY_ID = "stable-catalog-other";

  @TempDir private Path tempDir;

  @Test
  void verify_whenDetachedSignatureAndExpectedKeyMatch_expectAuthenticatesExactCatalog()
      throws Exception {
    KeyPair expectedKey = keyPair();
    KeyPair otherTrustedKey = keyPair();
    Path catalog = writeCatalog();
    AppCatalogSigner.sign(catalog, EXPECTED_KEY_ID, expectedKey.getPrivate());
    Path detachedSignature = tempDir.resolve("candidate-catalog.detached-signature");
    Files.move(catalog.resolveSibling(AppCatalogSignature.SIGNATURE_FILE_NAME), detachedSignature);
    TrustedAppKeys trustedKeys = trustedKeys(expectedKey, otherTrustedKey);

    AppCatalog verified =
        AppCatalogVerifier.verify(catalog, detachedSignature, trustedKeys, EXPECTED_KEY_ID);

    assertEquals("stable", verified.catalogId());
  }

  @Test
  void verify_whenSignatureUsesDifferentTrustedKeyThanDeclared_expectRejectsSignerSubstitution()
      throws Exception {
    KeyPair expectedKey = keyPair();
    KeyPair otherTrustedKey = keyPair();
    Path catalog = writeCatalog();
    AppCatalogSigner.sign(catalog, OTHER_TRUSTED_KEY_ID, otherTrustedKey.getPrivate());
    Path signature = catalog.resolveSibling(AppCatalogSignature.SIGNATURE_FILE_NAME);
    TrustedAppKeys trustedKeys = trustedKeys(expectedKey, otherTrustedKey);

    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class,
            () -> AppCatalogVerifier.verify(catalog, signature, trustedKeys, EXPECTED_KEY_ID));

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_SIGNATURE, exception.errorCode());
    assertEquals("catalog signature key id does not match expected key id", exception.getMessage());
  }

  @Test
  void verify_whenCatalogBytesChangeAfterSigning_expectRejectsDetachedSignature() throws Exception {
    KeyPair expectedKey = keyPair();
    KeyPair otherTrustedKey = keyPair();
    Path catalog = writeCatalog();
    AppCatalogSigner.sign(catalog, EXPECTED_KEY_ID, expectedKey.getPrivate());
    Path signature = catalog.resolveSibling(AppCatalogSignature.SIGNATURE_FILE_NAME);
    Files.writeString(
        catalog,
        "catalog.name=Mutated Stable catalog\n",
        StandardCharsets.UTF_8,
        java.nio.file.StandardOpenOption.APPEND);
    TrustedAppKeys trustedKeys = trustedKeys(expectedKey, otherTrustedKey);

    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class,
            () -> AppCatalogVerifier.verify(catalog, signature, trustedKeys, EXPECTED_KEY_ID));

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_SIGNATURE, exception.errorCode());
  }

  @Test
  void verify_whenRegistryReplacesPublicKeyUnderExpectedId_expectRejectsSignature()
      throws Exception {
    KeyPair signingKey = keyPair();
    KeyPair substitutedKey = keyPair();
    Path catalog = writeCatalog();
    AppCatalogSigner.sign(catalog, EXPECTED_KEY_ID, signingKey.getPrivate());
    Path signature = catalog.resolveSibling(AppCatalogSignature.SIGNATURE_FILE_NAME);
    TrustedAppKeys substitutedRegistry =
        TrustedAppKeys.of(
            new TrustedAppKey(
                EXPECTED_KEY_ID,
                AppCatalogSignature.SIGNATURE_ALGORITHM,
                substitutedKey.getPublic()));

    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class,
            () ->
                AppCatalogVerifier.verify(
                    catalog, signature, substitutedRegistry, EXPECTED_KEY_ID));

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_SIGNATURE, exception.errorCode());
  }

  private Path writeCatalog() throws Exception {
    Path catalog = tempDir.resolve(AppCatalogSignature.CATALOG_FILE_NAME);
    Files.writeString(
        catalog,
        """
        catalog.version=1
        catalog.id=stable
        catalog.name=Stable catalog
        catalog.generatedAt=2026-07-20T00:00:00Z
        catalog.entries=
        """,
        StandardCharsets.UTF_8);
    return catalog;
  }

  private static KeyPair keyPair() throws Exception {
    return KeyPairGenerator.getInstance(AppCatalogSignature.SIGNATURE_ALGORITHM).generateKeyPair();
  }

  private static TrustedAppKeys trustedKeys(KeyPair expectedKey, KeyPair otherTrustedKey) {
    return TrustedAppKeys.of(
        new TrustedAppKey(
            EXPECTED_KEY_ID, AppCatalogSignature.SIGNATURE_ALGORITHM, expectedKey.getPublic()),
        new TrustedAppKey(
            OTHER_TRUSTED_KEY_ID,
            AppCatalogSignature.SIGNATURE_ALGORITHM,
            otherTrustedKey.getPublic()));
  }
}

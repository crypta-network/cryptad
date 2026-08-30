package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import network.crypta.platform.appdist.PublicKeyFingerprint;
import network.crypta.platform.appdist.TrustedAppKey;
import network.crypta.platform.appdist.TrustedAppKeys;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class FederatedCatalogVerifierTest {
  private static final String CATALOG_A = "catalog-a";
  private static final String KEY_ID = "federated-catalog-key";

  @TempDir Path temporaryDirectory;

  @Test
  void verifyRoutine_whenCatalogAndSignerMatchActiveBinding_expectAccepted() throws Exception {
    KeyPair keyPair = keyPair();
    Path catalog = writeAndSign(CATALOG_A, keyPair);

    AppCatalog verified =
        FederatedCatalogVerifier.verifyRoutine(
            Files.readAllBytes(catalog),
            Files.readAllBytes(catalog.resolveSibling(AppCatalogSignature.SIGNATURE_FILE_NAME)),
            trustedKeys(keyPair),
            binding(keyPair, FederatedCatalogTrustBinding.Status.ACTIVE));

    assertEquals(CATALOG_A, verified.catalogId());
  }

  @Test
  void verifyRoutine_whenSignerForCatalogATriesCatalogB_expectRejected() throws Exception {
    KeyPair keyPair = keyPair();
    Path catalog = writeAndSign("catalog-b", keyPair);
    byte[] catalogBytes = Files.readAllBytes(catalog);
    byte[] signatureBytes =
        Files.readAllBytes(catalog.resolveSibling(AppCatalogSignature.SIGNATURE_FILE_NAME));
    TrustedAppKeys trustedKeys = trustedKeys(keyPair);
    FederatedCatalogTrustBinding binding =
        binding(keyPair, FederatedCatalogTrustBinding.Status.ACTIVE);

    assertThrows(
        AppCatalogException.class,
        () ->
            FederatedCatalogVerifier.verifyRoutine(
                catalogBytes, signatureBytes, trustedKeys, binding));
  }

  @Test
  void verifyRoutine_whenBindingIsSuspended_expectRejectedButHistoricalInspectionAllowed()
      throws Exception {
    KeyPair keyPair = keyPair();
    Path catalog = writeAndSign(CATALOG_A, keyPair);
    byte[] catalogBytes = Files.readAllBytes(catalog);
    byte[] signatureBytes =
        Files.readAllBytes(catalog.resolveSibling(AppCatalogSignature.SIGNATURE_FILE_NAME));
    TrustedAppKeys trustedKeys = trustedKeys(keyPair);
    FederatedCatalogTrustBinding binding =
        binding(keyPair, FederatedCatalogTrustBinding.Status.SUSPENDED);

    assertThrows(
        AppCatalogException.class,
        () ->
            FederatedCatalogVerifier.verifyRoutine(
                catalogBytes, signatureBytes, trustedKeys, binding));
    assertEquals(
        CATALOG_A,
        FederatedCatalogVerifier.verifyHistorical(
                catalogBytes, signatureBytes, trustedKeys, binding)
            .catalogId());
  }

  private Path writeAndSign(String catalogId, KeyPair keyPair) throws IOException {
    Path catalog = temporaryDirectory.resolve(catalogId + ".properties");
    Files.writeString(
        catalog,
        "catalog.version=1\n"
            + "catalog.id="
            + catalogId
            + "\ncatalog.name=Federated catalog\n"
            + "catalog.generatedAt=2026-08-25T00:00:00Z\ncatalog.entries=\n",
        StandardCharsets.UTF_8);
    AppCatalogSigner.sign(catalog, KEY_ID, keyPair.getPrivate());
    return catalog;
  }

  private static FederatedCatalogTrustBinding binding(
      KeyPair keyPair, FederatedCatalogTrustBinding.Status status) {
    return FederatedCatalogTrustBinding.create(
        "binding-" + CATALOG_A,
        CATALOG_A,
        Map.of(KEY_ID, PublicKeyFingerprint.sha256(keyPair.getPublic())),
        status,
        Set.of(AppCatalogChannel.STABLE),
        100,
        null,
        null,
        null,
        Instant.EPOCH,
        Instant.EPOCH,
        "operator approval",
        "operator");
  }

  private static TrustedAppKeys trustedKeys(KeyPair keyPair) {
    return TrustedAppKeys.of(
        new TrustedAppKey(KEY_ID, AppCatalogSignature.SIGNATURE_ALGORITHM, keyPair.getPublic()));
  }

  private static KeyPair keyPair() throws NoSuchAlgorithmException {
    return KeyPairGenerator.getInstance(AppCatalogSignature.SIGNATURE_ALGORITHM).generateKeyPair();
  }
}

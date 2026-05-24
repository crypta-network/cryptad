package network.crypta.platform.devtools;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import network.crypta.platform.appcatalog.AppCatalogSignature;
import network.crypta.platform.appdist.AppDistributionException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

@SuppressWarnings("java:S100")
class PublicationInputValidatorTest {
  private static final String SHA256 = "0".repeat(64);
  private static final String PUBLIC_SOURCE =
      "  crypta:USK@PUBLIC/catalog/42/" + AppCatalogSignature.CATALOG_FILE_NAME + "  ";

  @TempDir private Path tempDir;

  @Test
  void validate_whenInputsAreCanonical_expectParsedInputsAndDigests() throws Exception {
    Path catalogFile = writeCatalog(AppCatalogSignature.CATALOG_FILE_NAME);
    Path signatureFile = writeSignature();
    Path output = tempDir.resolve("reports").resolve("summary.json");

    ValidatedPublicationInputs inputs =
        PublicationInputValidator.validate(catalogFile, signatureFile, PUBLIC_SOURCE, output);

    assertEquals("dev", inputs.catalog().catalogId());
    assertEquals(1, inputs.catalog().entries().size());
    assertEquals("dev-local", inputs.signature().keyId());
    assertEquals(PUBLIC_SOURCE.trim(), inputs.catalogSource());
    assertEquals(catalogFile.toAbsolutePath().normalize(), inputs.catalogFile());
    assertEquals(signatureFile.toAbsolutePath().normalize(), inputs.catalogSignatureFile());
    assertEquals(output.toAbsolutePath().normalize(), inputs.output());
    assertEquals(sha256(Files.readAllBytes(catalogFile)), inputs.catalogSha256());
    assertEquals(sha256(Files.readAllBytes(signatureFile)), inputs.signatureSha256());
    assertRetainsValidatedBytes(inputs, catalogFile, signatureFile);
  }

  @Test
  void validate_whenCatalogSourceHasQuery_expectFailure() throws Exception {
    Path catalogFile = writeCatalog(AppCatalogSignature.CATALOG_FILE_NAME);
    Path signatureFile = writeSignature();

    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class,
            () ->
                PublicationInputValidator.validate(
                    catalogFile,
                    signatureFile,
                    "crypta:USK@PUBLIC/catalog/42/"
                        + AppCatalogSignature.CATALOG_FILE_NAME
                        + "?edition=42",
                    tempDir.resolve("summary.json")));

    assertEquals(
        "publish-usk requires --catalog-source crypta:USK@.../cryptad-app-catalog.properties",
        exception.getMessage());
  }

  @Test
  void validate_whenCatalogFileNameIsNotCanonical_expectFailure() throws Exception {
    Path catalogFile = writeCatalog("catalog.properties");
    Path signatureFile = writeSignature();

    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class,
            () ->
                PublicationInputValidator.validate(
                    catalogFile, signatureFile, PUBLIC_SOURCE, tempDir.resolve("summary.json")));

    assertEquals(
        "catalog file must be " + AppCatalogSignature.CATALOG_FILE_NAME, exception.getMessage());
  }

  @Test
  void validate_whenSignatureSidecarIsMissing_expectFailure() throws Exception {
    Path catalogFile = writeCatalog(AppCatalogSignature.CATALOG_FILE_NAME);
    Path missingSignature = tempDir.resolve(AppCatalogSignature.SIGNATURE_FILE_NAME);

    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class,
            () ->
                PublicationInputValidator.validate(
                    catalogFile, missingSignature, PUBLIC_SOURCE, tempDir.resolve("summary.json")));

    assertEquals("catalog signature file must be a regular file", exception.getMessage());
  }

  @Test
  void validate_whenOutputIsCatalogFile_expectFailureWithoutChangingCatalog() throws Exception {
    Path catalogFile = writeCatalog(AppCatalogSignature.CATALOG_FILE_NAME);
    Path signatureFile = writeSignature();
    String catalogBefore = Files.readString(catalogFile, StandardCharsets.UTF_8);

    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class,
            () ->
                PublicationInputValidator.validate(
                    catalogFile, signatureFile, PUBLIC_SOURCE, catalogFile));

    assertOutputAliasFailure(exception);
    assertEquals(catalogBefore, Files.readString(catalogFile, StandardCharsets.UTF_8));
  }

  @Test
  void validate_whenOutputIsSignatureSidecar_expectFailureWithoutChangingSignature()
      throws Exception {
    Path catalogFile = writeCatalog(AppCatalogSignature.CATALOG_FILE_NAME);
    Path signatureFile = writeSignature();
    String signatureBefore = Files.readString(signatureFile, StandardCharsets.UTF_8);

    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class,
            () ->
                PublicationInputValidator.validate(
                    catalogFile, signatureFile, PUBLIC_SOURCE, signatureFile));

    assertOutputAliasFailure(exception);
    assertEquals(signatureBefore, Files.readString(signatureFile, StandardCharsets.UTF_8));
  }

  @Test
  void validate_whenOutputHardLinksCatalogFile_expectFailure() throws Exception {
    Path catalogFile = writeCatalog(AppCatalogSignature.CATALOG_FILE_NAME);
    Path signatureFile = writeSignature();
    Path outputAlias = createHardLinkOrSkip(catalogFile);

    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class,
            () ->
                PublicationInputValidator.validate(
                    catalogFile, signatureFile, PUBLIC_SOURCE, outputAlias));

    assertOutputAliasFailure(exception);
  }

  private Path writeCatalog(String fileName) throws Exception {
    Path catalogFile = tempDir.resolve(fileName);
    Files.writeString(
        catalogFile,
        """
        catalog.version=1
        catalog.id=dev
        catalog.name=Development Apps
        catalog.generatedAt=2026-05-14T00:00:00Z
        catalog.entries=queue-app
        app.queue-app.id=queue-app
        app.queue-app.name=Queue App
        app.queue-app.version=0.1.0
        app.queue-app.summary=Queue dashboard.
        app.queue-app.bundle.uri=crypta:CHK@public-bundle-key
        app.queue-app.bundle.sha256=%s
        app.queue-app.bundle.size.bytes=0
        app.queue-app.bundle.type=zip
        app.queue-app.permissions=queue.read
        """
            .formatted(SHA256),
        StandardCharsets.UTF_8);
    return catalogFile;
  }

  private Path writeSignature() throws Exception {
    Path signatureFile = tempDir.resolve(AppCatalogSignature.SIGNATURE_FILE_NAME);
    Files.writeString(
        signatureFile,
        """
        catalog.signature.version=1
        catalog.signature.algorithm=Ed25519
        catalog.signature.key.id=dev-local
        catalog.signature.payload=cryptad-app-catalog.properties
        catalog.signature.value.base64=AQID
        """,
        StandardCharsets.UTF_8);
    return signatureFile;
  }

  private Path createHardLinkOrSkip(Path target) throws Exception {
    Path alias = tempDir.resolve("catalog-plan.json");
    try {
      Files.createLink(alias, target);
    } catch (UnsupportedOperationException | IOException | SecurityException _) {
      assumeTrue(false, "hard links are not supported by this filesystem");
    }
    return alias;
  }

  private static void assertOutputAliasFailure(AppDistributionException exception) {
    assertEquals(
        "publication output must be separate from catalog file and signature sidecar",
        exception.getMessage());
  }

  private static void assertRetainsValidatedBytes(
      ValidatedPublicationInputs inputs, Path catalogFile, Path signatureFile) throws Exception {
    byte[] catalogBytes = inputs.catalogBytes();
    byte[] signatureBytes = inputs.signatureBytes();

    catalogBytes[0] = (byte) (catalogBytes[0] + 1);
    signatureBytes[0] = (byte) (signatureBytes[0] + 1);

    assertArrayEquals(Files.readAllBytes(catalogFile), inputs.catalogBytes());
    assertArrayEquals(Files.readAllBytes(signatureFile), inputs.signatureBytes());
  }

  private static String sha256(byte[] bytes) throws Exception {
    return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
  }
}

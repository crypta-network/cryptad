package network.crypta.platform.devtools;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import network.crypta.platform.appcatalog.AppCatalogSignature;
import network.crypta.platform.appdist.AppDistributionException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class PublicationPlanWriterTest {
  private static final String SHA256 = "0".repeat(64);

  @TempDir private Path tempDir;

  @Test
  void write_whenJsonOutputRequested_expectRedactedPlanAndResult() throws Exception {
    Path catalogFile = writeCatalog();
    Path signatureFile = writeSignature(AppCatalogSignature.SIGNATURE_FILE_NAME);
    Path output = tempDir.resolve("plan.json");

    PublicationPlanWriter.Result result =
        PublicationPlanWriter.write(
            new PublicationPlanWriter.Request(
                catalogFile,
                signatureFile,
                "crypta:USK@private-insert-material/catalog/"
                    + AppCatalogSignature.CATALOG_FILE_NAME,
                output));

    String json = Files.readString(output, StandardCharsets.UTF_8);
    assertEquals("dev", result.catalogId());
    assertEquals(1, result.entryCount());
    assertEquals(output.toAbsolutePath().normalize(), result.output());
    assertTrue(json.contains("\"schemaVersion\": 1"));
    assertTrue(json.contains("\"catalogSource\": \"crypta:USK@[REDACTED]/catalog/"));
    assertTrue(json.contains("\"bundleUri\":\"crypta:CHK@[REDACTED]\""));
    assertTrue(json.contains(AppCatalogSignature.CATALOG_FILE_NAME));
    assertTrue(json.contains(AppCatalogSignature.SIGNATURE_FILE_NAME));
    assertFalse(json.contains("private-insert-material"));
    assertFalse(json.contains("private-bundle-key"));
    assertFalse(json.contains(tempDir.toString()));
  }

  @Test
  void write_whenCatalogSourceIsNotUskCatalogProperties_expectFailure() throws Exception {
    Path catalogFile = writeCatalog();
    Path signatureFile = writeSignature(AppCatalogSignature.SIGNATURE_FILE_NAME);

    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class,
            () ->
                PublicationPlanWriter.write(
                    new PublicationPlanWriter.Request(
                        catalogFile,
                        signatureFile,
                        "crypta:CHK@catalog/" + AppCatalogSignature.CATALOG_FILE_NAME,
                        tempDir.resolve("plan.md"))));

    assertTrue(exception.getMessage().contains("publish-usk requires --catalog-source"));
  }

  @Test
  void write_whenSignatureSidecarNameIsNotCanonical_expectFailure() throws Exception {
    Path catalogFile = writeCatalog();
    Path signatureFile = writeSignature("catalog.sig");

    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class,
            () ->
                PublicationPlanWriter.write(
                    new PublicationPlanWriter.Request(
                        catalogFile,
                        signatureFile,
                        "crypta:USK@private/catalog/" + AppCatalogSignature.CATALOG_FILE_NAME,
                        tempDir.resolve("plan.md"))));

    assertEquals(
        "catalog signature sidecar must be cryptad-app-catalog.signature", exception.getMessage());
  }

  private Path writeCatalog() throws Exception {
    Path catalogFile = tempDir.resolve(AppCatalogSignature.CATALOG_FILE_NAME);
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
        app.queue-app.bundle.uri=crypta:CHK@private-bundle-key
        app.queue-app.bundle.sha256=%s
        app.queue-app.bundle.size.bytes=0
        app.queue-app.bundle.type=zip
        app.queue-app.permissions=queue.read
        """
            .formatted(SHA256),
        StandardCharsets.UTF_8);
    return catalogFile;
  }

  private Path writeSignature(String fileName) throws Exception {
    Path signatureFile = tempDir.resolve(fileName);
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
}

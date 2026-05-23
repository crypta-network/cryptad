package network.crypta.platform.devtools;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import network.crypta.platform.appcatalog.AppCatalogException;
import network.crypta.platform.appcatalog.AppCatalogSignature;
import network.crypta.platform.appcatalog.AppCatalogSigner;
import network.crypta.platform.appdist.AppDistributionException;
import network.crypta.platform.appdist.TrustedAppKey;
import network.crypta.platform.appdist.TrustedAppKeys;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class LiveUskPublicationServiceTest {
  private static final String SHA256 = "0".repeat(64);
  private static final String PUBLIC_USK_PREFIX =
      "USK@sdFxM0Z4zx4-gXhGwzXAVYvOUi6NRfdGbyJa797bNAg,"
          + "ZP4aASnyZax8nYOvCOlUebegsmbGQIXfVzw7iyOsXEc,AQACAAE";
  private static final String PRIVATE_USK_PREFIX =
      "USK@ZTeIa1g4T3OYCdUFfHrFSlRnt5coeFFDCIZxWSb7abs,"
          + "ZP4aASnyZax8nYOvCOlUebegsmbGQIXfVzw7iyOsXEc,AQECAAE";
  private static final String PUBLIC_SOURCE =
      "crypta:" + PUBLIC_USK_PREFIX + "/catalog/42/" + AppCatalogSignature.CATALOG_FILE_NAME;
  private static final String PRIVATE_INSERT_URI = PRIVATE_USK_PREFIX + "/catalog/42";
  private static final String FORM_PASSWORD = "form-password-secret";

  @TempDir private Path tempDir;

  @Test
  void publish_whenFakePublisherSucceeds_expectSanitizedSummaryAndRetainedStaging()
      throws Exception {
    KeyPair keyPair = keyPair();
    Path catalogFile = writeSignedCatalog(keyPair);
    Path output = tempDir.resolve("live-summary.json");
    RecordingPublisher publisher =
        new RecordingPublisher(
            new LiveUskPublishResponse(
                "queued",
                "queued",
                Optional.of(PUBLIC_SOURCE),
                "verified",
                "not_run",
                List.of("safe_warning")));

    try {
      LiveUskPublicationResult result =
          LiveUskPublicationService.publish(
              request(catalogFile, output, true), trustedKeys(keyPair), publisher);

      String summary = Files.readString(output, StandardCharsets.UTF_8);
      assertEquals("dev", result.catalogId());
      assertEquals(1, result.entryCount());
      assertEquals("dev-local", result.catalogSigningKeyId());
      assertEquals("42", result.edition().orElseThrow());
      assertTrue(summary.contains("\"mode\": \"live\""));
      assertTrue(summary.contains("\"catalogInsertStatus\": \"queued\""));
      assertTrue(summary.contains("\"signatureInsertStatus\": \"queued\""));
      assertTrue(summary.contains("\"postPublishVerificationStatus\": \"verified\""));
      assertTrue(summary.contains("\"catalogSha256\""));
      assertTrue(summary.contains("\"signatureSha256\""));
      assertTrue(summary.contains(PUBLIC_SOURCE));
      assertTrue(summary.contains(publicSignatureSource()));
      assertTrue(summary.contains("staging_sidecars_retained_until_live_insert_completion"));
      assertFalse(summary.contains(PRIVATE_INSERT_URI));
      assertFalse(summary.contains("ZTeIa1g4T3OYCdUFfHrFSlRnt5coeFFDCIZxWSb7abs"));
      assertFalse(summary.contains(FORM_PASSWORD));
      assertFalse(summary.contains(tempDir.toString()));
      assertFalse(summary.contains(publisher.stagingDirectory.toString()));
      assertTrue(Files.exists(publisher.stagingDirectory));
      assertOwnerOnlyStagingDirectory(publisher.stagingDirectory);
      assertArrayEquals(Files.readAllBytes(catalogFile), publisher.catalogBytes);
      assertArrayEquals(
          Files.readAllBytes(catalogFile.resolveSibling(AppCatalogSignature.SIGNATURE_FILE_NAME)),
          publisher.signatureBytes);
    } finally {
      if (publisher.stagingDirectory != null) {
        deleteRecursively(publisher.stagingDirectory);
      }
    }
  }

  @Test
  void publish_whenInsertIsOnlyQueued_expectStagingRetainedWithoutPathInSummary() throws Exception {
    KeyPair keyPair = keyPair();
    Path catalogFile = writeSignedCatalog(keyPair);
    Path output = tempDir.resolve("live-summary.json");
    RecordingPublisher publisher =
        new RecordingPublisher(
            new LiveUskPublishResponse(
                "queued", "queued", Optional.empty(), "not_requested", "not_run", List.of()));

    try {
      LiveUskPublicationResult result =
          LiveUskPublicationService.publish(
              request(catalogFile, output, false), trustedKeys(keyPair), publisher);

      String summary = Files.readString(output, StandardCharsets.UTF_8);
      assertEquals("not_requested", result.postPublishVerificationStatus());
      assertTrue(
          Files.isRegularFile(
              publisher.stagingDirectory.resolve(AppCatalogSignature.CATALOG_FILE_NAME)));
      assertTrue(
          Files.isRegularFile(
              publisher.stagingDirectory.resolve(AppCatalogSignature.SIGNATURE_FILE_NAME)));
      assertOwnerOnlyStagingDirectory(publisher.stagingDirectory);
      assertTrue(summary.contains("staging_sidecars_retained_until_live_insert_completion"));
      assertFalse(summary.contains(publisher.stagingDirectory.toString()));
      assertFalse(summary.contains(tempDir.toString()));
    } finally {
      if (publisher.stagingDirectory != null) {
        deleteRecursively(publisher.stagingDirectory);
      }
    }
  }

  @Test
  void publish_whenPrivateInsertUriUsesPublicScheme_expectFailureWithoutPublisherOrSummary()
      throws Exception {
    KeyPair keyPair = keyPair();
    Path catalogFile = writeSignedCatalog(keyPair);
    Path output = tempDir.resolve("live-summary.json");
    RecordingPublisher publisher =
        new RecordingPublisher(
            new LiveUskPublishResponse(
                "queued", "queued", Optional.empty(), "not_requested", "not_run", List.of()));

    assertThrows(
        AppDistributionException.class,
        () ->
            LiveUskPublicationService.publish(
                new LiveUskPublicationService.Request(
                    catalogFile,
                    catalogFile.resolveSibling(AppCatalogSignature.SIGNATURE_FILE_NAME),
                    PUBLIC_SOURCE,
                    output,
                    "crypta:USK@PUBLIC/catalog/42",
                    "http://127.0.0.1:8888/api/v1",
                    FORM_PASSWORD,
                    false),
                trustedKeys(keyPair),
                publisher));

    assertFalse(publisher.invoked);
    assertFalse(Files.exists(output));
  }

  @Test
  void publish_whenPrivateInsertUriDoesNotMatchPublicSource_expectFailureWithoutPublisherOrSummary()
      throws Exception {
    KeyPair keyPair = keyPair();
    Path catalogFile = writeSignedCatalog(keyPair);
    Path output = tempDir.resolve("live-summary.json");
    RecordingPublisher publisher =
        new RecordingPublisher(
            new LiveUskPublishResponse(
                "queued", "queued", Optional.empty(), "not_requested", "not_run", List.of()));

    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class,
            () ->
                LiveUskPublicationService.publish(
                    new LiveUskPublicationService.Request(
                        catalogFile,
                        catalogFile.resolveSibling(AppCatalogSignature.SIGNATURE_FILE_NAME),
                        PUBLIC_SOURCE,
                        output,
                        PRIVATE_USK_PREFIX + "/wrong-catalog/42",
                        "http://127.0.0.1:8888/api/v1",
                        FORM_PASSWORD,
                        false),
                    trustedKeys(keyPair),
                    publisher));

    assertTrue(exception.getMessage().contains("does not match public catalog source"));
    assertFalse(exception.getMessage().contains(PRIVATE_USK_PREFIX));
    assertFalse(exception.getMessage().contains(FORM_PASSWORD));
    assertFalse(publisher.invoked);
    assertFalse(Files.exists(output));
  }

  @Test
  void publish_whenNodeHostOnlyStartsWithLoopbackPrefix_expectFailureWithoutPublisherOrSummary()
      throws Exception {
    KeyPair keyPair = keyPair();
    Path catalogFile = writeSignedCatalog(keyPair);
    Path output = tempDir.resolve("live-summary.json");
    RecordingPublisher publisher =
        new RecordingPublisher(
            new LiveUskPublishResponse(
                "queued", "queued", Optional.empty(), "not_requested", "not_run", List.of()));

    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class,
            () ->
                LiveUskPublicationService.publish(
                    new LiveUskPublicationService.Request(
                        catalogFile,
                        catalogFile.resolveSibling(AppCatalogSignature.SIGNATURE_FILE_NAME),
                        PUBLIC_SOURCE,
                        output,
                        PRIVATE_INSERT_URI,
                        "http://127.0.0.1.attacker.example:8888/api/v1",
                        FORM_PASSWORD,
                        false),
                    trustedKeys(keyPair),
                    publisher));

    assertTrue(exception.getMessage().contains("localhost host"));
    assertFalse(exception.getMessage().contains(PRIVATE_INSERT_URI));
    assertFalse(exception.getMessage().contains(FORM_PASSWORD));
    assertFalse(publisher.invoked);
    assertFalse(Files.exists(output));
  }

  @Test
  void publish_whenTrustedKeyIsMissing_expectFailureBeforeLiveInsert() throws Exception {
    KeyPair keyPair = keyPair();
    Path catalogFile = writeSignedCatalog(keyPair);
    Path output = tempDir.resolve("live-summary.json");
    RecordingPublisher publisher =
        new RecordingPublisher(
            new LiveUskPublishResponse(
                "queued", "queued", Optional.empty(), "not_requested", "not_run", List.of()));
    LiveUskPublicationService.Request request = request(catalogFile, output, false);
    TrustedAppKeys trustedKeys = TrustedAppKeys.empty();

    assertThrows(
        AppCatalogException.class,
        () -> LiveUskPublicationService.publish(request, trustedKeys, publisher));

    assertFalse(publisher.invoked);
    assertFalse(Files.exists(output));
  }

  private LiveUskPublicationService.Request request(
      Path catalogFile, Path output, boolean verifyLiveFetch) {
    return new LiveUskPublicationService.Request(
        catalogFile,
        catalogFile.resolveSibling(AppCatalogSignature.SIGNATURE_FILE_NAME),
        PUBLIC_SOURCE,
        output,
        PRIVATE_INSERT_URI,
        "http://127.0.0.1:8888/api/v1",
        FORM_PASSWORD,
        verifyLiveFetch);
  }

  private static String publicSignatureSource() {
    return "crypta:" + PUBLIC_USK_PREFIX + "/catalog/42/" + AppCatalogSignature.SIGNATURE_FILE_NAME;
  }

  private Path writeSignedCatalog(KeyPair keyPair) throws Exception {
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
        app.queue-app.bundle.uri=crypta:CHK@public-bundle-key
        app.queue-app.bundle.sha256=%s
        app.queue-app.bundle.size.bytes=0
        app.queue-app.bundle.type=zip
        app.queue-app.permissions=queue.read
        """
            .formatted(SHA256),
        StandardCharsets.UTF_8);
    AppCatalogSigner.sign(catalogFile, "dev-local", keyPair.getPrivate());
    return catalogFile;
  }

  private static KeyPair keyPair() throws Exception {
    return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
  }

  private static TrustedAppKeys trustedKeys(KeyPair keyPair) throws AppDistributionException {
    return TrustedAppKeys.of(TrustedAppKey.ed25519("dev-local", keyPair.getPublic().getEncoded()));
  }

  private static void deleteRecursively(Path root) throws Exception {
    if (!Files.exists(root)) {
      return;
    }
    try (var stream = Files.walk(root)) {
      for (Path path : stream.sorted(Comparator.reverseOrder()).toList()) {
        Files.deleteIfExists(path);
      }
    }
  }

  private static void assertOwnerOnlyStagingDirectory(Path stagingDirectory) throws Exception {
    if (!Files.getFileStore(stagingDirectory).supportsFileAttributeView("posix")) {
      return;
    }
    assertEquals(
        Set.of(
            PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE,
            PosixFilePermission.OWNER_EXECUTE),
        Files.getPosixFilePermissions(stagingDirectory));
  }

  private static final class RecordingPublisher implements LiveUskPublisher {
    private final LiveUskPublishResponse response;
    private boolean invoked;
    private Path stagingDirectory;
    private byte[] catalogBytes;
    private byte[] signatureBytes;

    private RecordingPublisher(LiveUskPublishResponse response) {
      this.response = response;
    }

    @Override
    public LiveUskPublishResponse publish(LiveUskPublishRequest request) {
      invoked = true;
      stagingDirectory = request.stagingDirectory();
      catalogBytes = request.catalogBytes();
      signatureBytes = request.signatureBytes();
      assertEquals(PRIVATE_INSERT_URI, request.privateInsertUri());
      assertEquals(FORM_PASSWORD, request.formPassword());
      assertTrue(
          Files.isRegularFile(stagingDirectory.resolve(AppCatalogSignature.CATALOG_FILE_NAME)));
      assertTrue(
          Files.isRegularFile(stagingDirectory.resolve(AppCatalogSignature.SIGNATURE_FILE_NAME)));
      return response;
    }
  }
}

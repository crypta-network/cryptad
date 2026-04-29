package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import network.crypta.platform.appdist.AppBundleManifestParser;
import network.crypta.platform.appdist.AppBundlePackager;
import network.crypta.platform.appdist.TrustedAppKey;
import network.crypta.platform.appdist.TrustedAppKeys;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class AppCatalogWriterTest {
  private static final String KEY_ID = "catalog-writer-test";
  private static final String CATALOG_ID = "core";
  private static final String CATALOG_NAME = "Crypta Core Apps";
  private static final String QUEUE_APP_ID = "queue-manager";
  private static final String PUBLISHER_APP_ID = "publisher";
  private static final Instant GENERATED_AT = Instant.parse("2026-04-21T18:22:40Z");

  @TempDir private Path tempDir;

  @Test
  void write_whenDescriptorUsesManifestAndDisplayOverrides_expectDeterministicCatalogProperties()
      throws Exception {
    Path artifact = appZip(QUEUE_APP_ID, "Queue Manager", "1.0.0", "queue.read,queue.write");
    String bundleUri = "https://example.invalid/apps/queue-manager.zip";
    Path descriptor =
        descriptor(
            "queue.properties",
            artifact,
            bundleUri,
            "Manage local Crypta transfer queues.",
            """
            app.id=Queue-Manager
            name=Catalog Queue Manager
            version=1.0.0
            permissions=queue.inspect,QUEUE.READ,queue.inspect
            """);
    Path outputFile = tempDir.resolve("catalog").resolve(AppCatalogSignature.CATALOG_FILE_NAME);

    AppCatalogWriter.WriteResult result =
        AppCatalogWriter.write(request(List.of(descriptor)).withOutputFile(outputFile));

    String expected =
        lines(
            "catalog.version=1",
            "catalog.id=core",
            "catalog.name=Crypta Core Apps",
            "catalog.generatedAt=2026-04-21T18:22:40Z",
            "catalog.entries=queue-manager",
            "app.queue-manager.id=queue-manager",
            "app.queue-manager.name=Catalog Queue Manager",
            "app.queue-manager.version=1.0.0",
            "app.queue-manager.summary=Manage local Crypta transfer queues.",
            "app.queue-manager.bundle.uri=" + bundleUri,
            "app.queue-manager.bundle.sha256=" + sha256(artifact),
            "app.queue-manager.bundle.size.bytes=" + Files.size(artifact),
            "app.queue-manager.bundle.type=zip",
            "app.queue-manager.permissions=queue.inspect,queue.read");

    assertEquals(expected, new String(result.catalogBytes(), StandardCharsets.UTF_8));
    assertEquals(expected, Files.readString(outputFile));
    assertEquals(outputFile.toAbsolutePath().normalize(), result.catalogFile().orElseThrow());
    assertEquals(
        expected, new String(AppCatalogWriter.serialize(result.catalog()), StandardCharsets.UTF_8));
  }

  @Test
  void write_whenMultipleDescriptorFiles_expectEntriesInRequestOrder() throws Exception {
    Path publisherArtifact = appZip(PUBLISHER_APP_ID, "Publisher", "2.0.0", "publish.write");
    Path queueArtifact = appZip(QUEUE_APP_ID, "Queue Manager", "1.0.0", "queue.read");
    Path publisherDescriptor =
        descriptor(
            "publisher.properties",
            publisherArtifact,
            "https://example.invalid/apps/publisher.zip",
            "Publish local files.",
            "");
    Path queueDescriptor =
        descriptor(
            "queue.properties",
            queueArtifact,
            "https://example.invalid/apps/queue-manager.zip",
            "Manage local queues.",
            "");

    AppCatalogWriter.WriteResult result =
        AppCatalogWriter.write(request(List.of(publisherDescriptor, queueDescriptor)));

    assertEquals(
        List.of(PUBLISHER_APP_ID, QUEUE_APP_ID),
        result.catalog().entries().stream().map(AppCatalogEntry::appId).toList());
    assertTrue(
        new String(result.catalogBytes(), StandardCharsets.UTF_8)
            .contains("catalog.entries=publisher,queue-manager\n"));
  }

  @Test
  void write_whenArtifactBytesAreRead_expectDigestAndSizeFromZip() throws Exception {
    Path artifact = appZip(QUEUE_APP_ID, "Queue Manager", "1.0.0", "queue.read,queue.write");
    Path descriptor =
        descriptor(
            "queue.properties", artifact, artifact.toUri().toString(), "Manage local queues.", "");

    AppCatalogWriter.WriteResult result = AppCatalogWriter.write(request(List.of(descriptor)));
    AppCatalogEntry entry = result.catalog().entries().getFirst();

    assertEquals(Files.size(artifact), entry.bundleSizeBytes());
    assertEquals(sha256(artifact), entry.bundleSha256());
    assertTrue(entry.bundleSha256().matches("[0-9a-f]{64}"));
  }

  @Test
  void write_whenDescriptorAppIdDiffersFromArtifactManifest_expectInvalidCatalogEntry()
      throws Exception {
    Path artifact = appZip(QUEUE_APP_ID, "Queue Manager", "1.0.0", "queue.read");
    Path descriptor =
        descriptor(
            "queue.properties",
            artifact,
            "https://example.invalid/apps/queue-manager.zip",
            "Manage local queues.",
            "app.id=other-app");

    AppCatalogException exception =
        captureInvalidEntry(() -> AppCatalogWriter.write(request(List.of(descriptor))));

    assertTrue(exception.getMessage().contains("app.id must match artifact manifest app.id"));
  }

  @Test
  void write_whenDescriptorVersionDiffersFromArtifactManifest_expectInvalidCatalogEntry()
      throws Exception {
    Path artifact = appZip(QUEUE_APP_ID, "Queue Manager", "1.0.0", "queue.read");
    Path descriptor =
        descriptor(
            "queue.properties",
            artifact,
            "https://example.invalid/apps/queue-manager.zip",
            "Manage local queues.",
            "version=1.0.1");

    AppCatalogException exception =
        captureInvalidEntry(() -> AppCatalogWriter.write(request(List.of(descriptor))));

    assertTrue(exception.getMessage().contains("version must match artifact manifest app.version"));
  }

  @Test
  void write_whenDescriptorIsMalformed_expectInvalidCatalogEntry() throws Exception {
    Path descriptor =
        Files.writeString(
            tempDir.resolve("missing-summary.properties"),
            lines(
                "artifact.path=" + tempDir.resolve("missing.zip"),
                "bundle.uri=https://example.invalid/apps/queue-manager.zip"),
            StandardCharsets.UTF_8);

    assertInvalidEntry(() -> AppCatalogWriter.write(request(List.of(descriptor))));
  }

  @Test
  void write_whenArtifactIsMalformed_expectInvalidCatalogEntry() throws Exception {
    Path artifact = Files.writeString(tempDir.resolve("not-a-zip.zip"), "not a zip");
    Path descriptor =
        descriptor(
            "queue.properties",
            artifact,
            "https://example.invalid/apps/queue-manager.zip",
            "Manage local queues.",
            "");

    assertInvalidEntry(() -> AppCatalogWriter.write(request(List.of(descriptor))));
  }

  @Test
  void write_whenArtifactExceedsCatalogEntryCap_expectInvalidCatalogEntry() throws Exception {
    Path artifact = appZipExceedingCatalogEntryCap();
    Path descriptor =
        descriptor(
            "queue.properties",
            artifact,
            "https://example.invalid/apps/queue-manager.zip",
            "Manage local queues.",
            "");

    AppCatalogException exception =
        captureInvalidEntry(() -> AppCatalogWriter.write(request(List.of(descriptor))));

    assertTrue(exception.getMessage().contains("too many entries for catalog installation"));
  }

  @Test
  void write_whenOutputFileIsSymbolicLink_expectRejectsWithoutWritingThroughLink()
      throws Exception {
    Path artifact = appZip(QUEUE_APP_ID, "Queue Manager", "1.0.0", "queue.read");
    Path descriptor =
        descriptor(
            "queue.properties",
            artifact,
            "https://example.invalid/apps/queue-manager.zip",
            "Manage local queues.",
            "");
    Path realCatalog = tempDir.resolve("external-catalog.properties");
    Path linkedCatalog = tempDir.resolve("linked-catalog.properties");
    Files.writeString(realCatalog, "unchanged", StandardCharsets.UTF_8);
    Assumptions.assumeTrue(canCreateSymlink(linkedCatalog));
    Files.createSymbolicLink(linkedCatalog, realCatalog);

    IOException exception =
        assertThrows(
            IOException.class,
            () ->
                AppCatalogWriter.write(request(List.of(descriptor)).withOutputFile(linkedCatalog)));

    assertTrue(exception.getMessage().contains("catalog output path must not be a symbolic link"));
    assertEquals("unchanged", Files.readString(realCatalog, StandardCharsets.UTF_8));
  }

  @Test
  void verify_whenWrittenCatalogIsSigned_expectRoundTrip() throws Exception {
    KeyPair keyPair =
        KeyPairGenerator.getInstance(AppCatalogSignature.SIGNATURE_ALGORITHM).generateKeyPair();
    Path artifact = appZip(QUEUE_APP_ID, "Queue Manager", "1.0.0", "queue.read");
    Path descriptor =
        descriptor(
            "queue.properties",
            artifact,
            "https://example.invalid/apps/queue-manager.zip",
            "Manage local queues.",
            "");
    Path catalogFile = tempDir.resolve(AppCatalogSignature.CATALOG_FILE_NAME);
    AppCatalogWriter.WriteResult result =
        AppCatalogWriter.write(request(List.of(descriptor)).withOutputFile(catalogFile));

    AppCatalogSigner.sign(catalogFile, KEY_ID, keyPair.getPrivate());
    AppCatalog verifiedCatalog = AppCatalogVerifier.verify(catalogFile, trustedKeys(keyPair));

    assertEquals(result.catalog(), verifiedCatalog);
  }

  private AppCatalogBuildRequest request(List<Path> descriptors) {
    return new AppCatalogBuildRequest(CATALOG_ID, CATALOG_NAME, GENERATED_AT, descriptors);
  }

  private Path descriptor(
      String fileName, Path artifact, String bundleUri, String summary, String extraProperties)
      throws IOException {
    return Files.writeString(
        tempDir.resolve(fileName),
        lines(
            "artifact.path=" + artifact,
            "bundle.uri=" + bundleUri,
            "summary=" + summary,
            extraProperties),
        StandardCharsets.UTF_8);
  }

  private Path appZip(String appId, String appName, String appVersion, String permissions)
      throws IOException {
    Path artifact = tempDir.resolve(appId + ".zip");
    try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(artifact))) {
      writeZipEntry(
          zip,
          AppBundleManifestParser.MANIFEST_FILE_NAME,
          lines(
              "manifest.version=1",
              "app.id=" + appId,
              "app.name=" + appName,
              "app.version=" + appVersion,
              "app.exec=bin/launch.sh",
              "app.permissions=" + permissions));
      writeZipEntry(zip, "bin/launch.sh", "#!/bin/sh\nexit 0\n");
    }
    return artifact;
  }

  private Path appZipExceedingCatalogEntryCap() throws IOException {
    Path artifact = tempDir.resolve("entry-cap.zip");
    try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(artifact))) {
      writeZipEntry(
          zip,
          AppBundleManifestParser.MANIFEST_FILE_NAME,
          lines(
              "manifest.version=1",
              "app.id=" + QUEUE_APP_ID,
              "app.name=Queue Manager",
              "app.version=1.0.0",
              "app.exec=bin/launch.sh"));
      for (int index = 0; index < AppBundlePackager.MAX_CATALOG_ZIP_ENTRIES; index++) {
        writeZipEntry(zip, "assets/file-" + index + ".txt", "asset " + index);
      }
    }
    return artifact;
  }

  private static String lines(String... values) {
    return String.join("\n", values) + "\n";
  }

  private static void writeZipEntry(ZipOutputStream zip, String name, String content)
      throws IOException {
    ZipEntry entry = new ZipEntry(name);
    entry.setTime(0L);
    zip.putNextEntry(entry);
    zip.write(content.getBytes(StandardCharsets.UTF_8));
    zip.closeEntry();
  }

  private static String sha256(Path file) throws Exception {
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    digest.update(Files.readAllBytes(file));
    return HexFormat.of().formatHex(digest.digest());
  }

  private static TrustedAppKeys trustedKeys(KeyPair keyPair) {
    return TrustedAppKeys.of(
        new TrustedAppKey(KEY_ID, AppCatalogSignature.SIGNATURE_ALGORITHM, keyPair.getPublic()));
  }

  private static boolean canCreateSymlink(Path symlink) {
    try {
      Files.createSymbolicLink(symlink, Path.of("missing-target"));
      Files.deleteIfExists(symlink);
      return true;
    } catch (UnsupportedOperationException | IOException | SecurityException _) {
      return false;
    }
  }

  private static void assertInvalidEntry(Executable executable) {
    AppCatalogException exception = assertThrows(AppCatalogException.class, executable);

    assertInvalidCatalogEntryErrorCode(exception);
  }

  private static AppCatalogException captureInvalidEntry(Executable executable) {
    AppCatalogException exception = assertThrows(AppCatalogException.class, executable);

    assertInvalidCatalogEntryErrorCode(exception);
    return exception;
  }

  private static void assertInvalidCatalogEntryErrorCode(AppCatalogException exception) {
    assertEquals(AppCatalogSidecars.INVALID_CATALOG_ENTRY, exception.errorCode());
  }
}

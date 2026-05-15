package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import network.crypta.platform.appdist.AppBundleManifest;
import network.crypta.platform.appdist.AppBundlePackager;
import network.crypta.platform.appdist.AppBundleSignature;
import network.crypta.platform.appdist.AppBundleSigner;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class AppCatalogBundleExtractorTest {
  private static final int IGNORED_METADATA_BYTES = 32;

  @TempDir private Path tempDir;

  @Test
  void inspectSignedArtifact_whenArtifactHasSignedSidecars_expectManifest() throws Exception {
    Path bundleRoot = createBundle("signed-artifact-app");
    AppBundleSigner.sign(bundleRoot, "dev-local", generateEd25519KeyPair().getPrivate());
    Path artifact = tempDir.resolve("signed-artifact.zip");
    AppBundlePackager.packageBundle(bundleRoot, artifact);

    AppBundleManifest manifest =
        AppCatalogBundleExtractor.inspectSignedArtifact(artifact, tempDir.resolve("scratch"));

    assertEquals("signed-artifact-app", manifest.appId());
    assertEquals("1.0.0", manifest.appVersion());
  }

  @Test
  void inspectSignedArtifact_whenArtifactIsUnsigned_expectInvalidAppBundle() throws Exception {
    Path bundleRoot = createBundle("unsigned-artifact-app");
    Path artifact = tempDir.resolve("unsigned-artifact.zip");
    AppBundlePackager.packageBundle(bundleRoot, artifact);

    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class,
            () -> AppCatalogBundleExtractor.inspectSignedArtifact(artifact, tempDir));

    assertEquals(AppCatalogSidecars.INVALID_APP_BUNDLE, exception.errorCode());
    assertTrue(exception.getMessage().contains("signed bundle sidecars"));
  }

  @Test
  void inspectSignedArtifact_whenSignatureSidecarCaseVariant_expectInvalidAppBundle()
      throws Exception {
    Path bundleRoot = createBundle("case-sidecar-app");
    AppBundleSigner.sign(bundleRoot, "dev-local", generateEd25519KeyPair().getPrivate());
    Path artifact = tempDir.resolve("case-sidecar.zip");
    AppBundlePackager.packageBundle(bundleRoot, artifact);
    Path tampered = zipWithCaseVariantSignatureSidecar(artifact);

    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class,
            () -> AppCatalogBundleExtractor.inspectSignedArtifact(tampered, tempDir));

    assertEquals(AppCatalogSidecars.INVALID_APP_BUNDLE, exception.errorCode());
    assertTrue(exception.getMessage().contains("non-canonical distribution sidecar name"));
  }

  @Test
  void inspectSignedArtifact_whenCatalogSidecarsAreSignedPayload_expectInvalidAppBundle()
      throws Exception {
    Path bundleRoot = createBundle("catalog-sidecar-app");
    Files.writeString(
        bundleRoot.resolve(AppCatalogSignature.CATALOG_FILE_NAME),
        "catalog.version=1\n",
        StandardCharsets.UTF_8);
    Files.writeString(
        bundleRoot.resolve(AppCatalogSignature.SIGNATURE_FILE_NAME),
        "catalog.signature.version=1\n",
        StandardCharsets.UTF_8);
    AppBundleSigner.sign(bundleRoot, "dev-local", generateEd25519KeyPair().getPrivate());
    Path artifact = tempDir.resolve("catalog-sidecar.zip");
    AppBundlePackager.packageBundle(bundleRoot, artifact);

    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class,
            () -> AppCatalogBundleExtractor.inspectSignedArtifact(artifact, tempDir));

    assertEquals(AppCatalogSidecars.INVALID_APP_BUNDLE, exception.errorCode());
    assertEquals("zip artifact must not contain catalog sidecars", exception.getMessage());
  }

  @Test
  void extractZip_whenIgnoredAppleDoubleEntryExceedsExtractedCap_expectInvalidAppBundle()
      throws Exception {
    Path artifact = ignoredAppleDoubleZip(tempDir.resolve("appledouble-large.zip"));
    Path stagedRoot = Files.createDirectory(tempDir.resolve("staged"));

    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class,
            () -> AppCatalogBundleExtractor.extractZip(artifact, stagedRoot, 16L));

    assertEquals(AppCatalogSidecars.INVALID_APP_BUNDLE, exception.errorCode());
    assertEquals("zip artifact exceeds extracted size cap", exception.getMessage());
    assertFalse(Files.exists(stagedRoot.resolve("._cryptad-app.properties")));
  }

  private Path createBundle(String appId) throws IOException {
    Path bundleRoot = Files.createTempDirectory(tempDir, appId + "-");
    Files.createDirectories(bundleRoot.resolve("bin"));
    Files.writeString(
        bundleRoot.resolve("cryptad-app.properties"),
        """
        manifest.version=1
        app.id=%s
        app.name=Signed Artifact App
        app.version=1.0.0
        app.exec=bin/start.sh
        app.ui.mode=none
        """
            .formatted(appId),
        StandardCharsets.UTF_8);
    Files.writeString(
        bundleRoot.resolve("bin").resolve("start.sh"),
        "#!/bin/sh\nexit 0\n",
        StandardCharsets.UTF_8);
    return bundleRoot;
  }

  private static KeyPair generateEd25519KeyPair() throws Exception {
    return KeyPairGenerator.getInstance(AppBundleSignature.SIGNATURE_ALGORITHM).generateKeyPair();
  }

  private Path zipWithCaseVariantSignatureSidecar(Path sourceZip) throws IOException {
    Path targetZip = tempDir.resolve("renamed-sidecar.zip");
    try (var input = new java.util.zip.ZipInputStream(Files.newInputStream(sourceZip));
        var output = new ZipOutputStream(Files.newOutputStream(targetZip))) {
      ZipEntry entry;
      while ((entry = input.getNextEntry()) != null) {
        String name =
            AppBundleSignature.SIGNATURE_FILE_NAME.equals(entry.getName())
                ? entry.getName().toUpperCase(java.util.Locale.ROOT)
                : entry.getName();
        output.putNextEntry(new ZipEntry(name));
        input.transferTo(output);
        output.closeEntry();
        input.closeEntry();
      }
    }
    return targetZip;
  }

  private static Path ignoredAppleDoubleZip(Path targetZip) throws IOException {
    byte[] payload = "x".repeat(IGNORED_METADATA_BYTES).getBytes(StandardCharsets.UTF_8);
    try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(targetZip))) {
      zip.putNextEntry(new ZipEntry("._cryptad-app.properties"));
      zip.write(payload);
      zip.closeEntry();
    }
    return targetZip;
  }
}

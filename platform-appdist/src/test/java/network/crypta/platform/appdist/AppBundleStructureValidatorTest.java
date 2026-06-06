package network.crypta.platform.appdist;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AppBundleStructureValidatorTest {
  private static final int PE_HEADER_OFFSET_FIELD = 0x3C;
  private static final int PE_HEADER_OFFSET = 0x80;
  private static final int COFF_CHARACTERISTICS_OFFSET = PE_HEADER_OFFSET + 22;
  private static final short IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002;
  private static final short IMAGE_FILE_DLL = 0x2000;

  @TempDir Path tempDir;

  @Test
  void validate_whenWindowsBatchLauncherDeclared_expectWindowsBatchLaunchMode() throws Exception {
    Path bundleRoot = createBundle("bin/start.cmd", "echo sample\r\n");

    AppBundleStructureValidator.ValidatedBundle validated =
        AppBundleStructureValidator.validate(bundleRoot);

    assertEquals(AppBundleStructureValidator.LaunchMode.WINDOWS_BATCH, validated.launchMode());
    assertNull(validated.authenticatedExecutableBit());
  }

  @Test
  void validate_whenShellScriptSuffixHasNoShebang_expectPosixInterpretedLaunchMode()
      throws Exception {
    Path bundleRoot = createBundle("bin/start.sh", "echo sample\n");

    AppBundleStructureValidator.ValidatedBundle validated =
        AppBundleStructureValidator.validate(bundleRoot);

    assertEquals(AppBundleStructureValidator.LaunchMode.POSIX_INTERPRETED, validated.launchMode());
    assertNull(validated.authenticatedExecutableBit());
  }

  @Test
  void validate_whenEnvSplitShellShebangDeclared_expectPosixInterpretedLaunchMode()
      throws Exception {
    Path bundleRoot = createBundle("bin/start", "#!/usr/bin/env -S sh -eu\necho sample\n");

    AppBundleStructureValidator.ValidatedBundle validated =
        AppBundleStructureValidator.validate(bundleRoot);

    assertEquals(AppBundleStructureValidator.LaunchMode.POSIX_INTERPRETED, validated.launchMode());
    assertNull(validated.authenticatedExecutableBit());
  }

  @Test
  void validate_whenValidPortableExecutableDeclared_expectWindowsPeLaunchMode() throws Exception {
    Path bundleRoot = createBundle("bin/start.exe", "");
    Files.write(bundleRoot.resolve("bin/start.exe"), portableExecutableBytes(false));

    AppBundleStructureValidator.ValidatedBundle validated =
        AppBundleStructureValidator.validate(bundleRoot);

    assertEquals(AppBundleStructureValidator.LaunchMode.WINDOWS_PE, validated.launchMode());
    assertNull(validated.authenticatedExecutableBit());
  }

  @Test
  void validate_whenPortableExecutableIsDll_expectNotLaunchableFailure() throws Exception {
    Path bundleRoot = createBundle("bin/plugin.exe", "");
    Files.write(bundleRoot.resolve("bin/plugin.exe"), portableExecutableBytes(true));

    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class, () -> AppBundleStructureValidator.validate(bundleRoot));

    assertEquals(
        "app.exec is not launchable on any supported platform: bin/plugin.exe",
        exception.getMessage());
  }

  @Test
  void validate_whenPlainExtensionlessFileHasNoLaunchMetadata_expectNotLaunchableFailure()
      throws Exception {
    Path bundleRoot = createBundle("bin/start", "echo sample\n");

    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class, () -> AppBundleStructureValidator.validate(bundleRoot));

    assertEquals(
        "app.exec is not launchable on any supported platform: bin/start", exception.getMessage());
  }

  @Test
  void validate_whenStaticUiEntryExists_expectValidatedBundle() throws Exception {
    Path bundleRoot =
        createBundle(
            "bin/start.sh",
            "echo sample\n",
            "app.ui.mode=static\napp.ui.entry=static/index.html\n");
    Files.createDirectories(bundleRoot.resolve("static"));
    Files.writeString(bundleRoot.resolve("static/index.html"), "<html></html>");

    AppBundleStructureValidator.ValidatedBundle validated =
        AppBundleStructureValidator.validate(bundleRoot);

    assertEquals(AppUiMode.STATIC, validated.manifest().uiMode());
  }

  @Test
  void validate_whenStaticUiEntryIsMissing_expectFailure() throws Exception {
    Path bundleRoot =
        createBundle(
            "bin/start.sh",
            "echo sample\n",
            "app.ui.mode=static\napp.ui.entry=static/index.html\n");

    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class, () -> AppBundleStructureValidator.validate(bundleRoot));

    assertEquals(
        "app.ui.entry does not resolve to a file in bundle: static/index.html",
        exception.getMessage());
  }

  @Test
  void validate_whenMigrationCommandIsRegularNonExecutableFile_expectAccepted() throws Exception {
    Path bundleRoot =
        createBundle(
            "bin/start.sh",
            "echo sample\n",
            """
            app.data.schema.current=2
            app.data.schema.namespaces=feeds
            app.data.schema.namespace.feeds.current=2
            app.data.migrations=feeds-v1-v2
            app.data.migration.feeds-v1-v2.namespace=feeds
            app.data.migration.feeds-v1-v2.from=1
            app.data.migration.feeds-v1-v2.to=2
            app.data.migration.feeds-v1-v2.command=bin/migrate.sh
            app.data.migration.feeds-v1-v2.rollbackCompatible=true
            app.data.migration.feeds-v1-v2.requiresStopped=true
            app.data.migration.feeds-v1-v2.description=Upgrade feed data.
            """);
    Files.writeString(bundleRoot.resolve("bin/migrate.sh"), "echo migrate\n");

    AppBundleStructureValidator.ValidatedBundle validated =
        AppBundleStructureValidator.validate(bundleRoot);

    assertEquals("sample-app", validated.manifest().appId());
  }

  private Path createBundle(String execPath, String executableContent) throws Exception {
    return createBundle(execPath, executableContent, "");
  }

  private Path createBundle(String execPath, String executableContent, String uiProperties)
      throws Exception {
    Path bundleRoot = Files.createTempDirectory(tempDir, "bundle-");
    Path executable = bundleRoot.resolve(execPath);
    Files.createDirectories(executable.getParent());
    Files.writeString(
        bundleRoot.resolve(AppBundleDigest.MANIFEST_FILE_NAME),
        """
        manifest.version=1
        app.id=sample-app
        app.name=Sample App
        app.version=1.0.0
        app.exec=%s
        """
                .formatted(execPath)
            + uiProperties,
        StandardCharsets.UTF_8);
    Files.writeString(executable, executableContent, StandardCharsets.UTF_8);
    return bundleRoot;
  }

  private static byte[] portableExecutableBytes(boolean dll) {
    byte[] bytes = new byte[PE_HEADER_OFFSET + 24];
    bytes[0] = 'M';
    bytes[1] = 'Z';
    ByteBuffer.wrap(bytes)
        .order(ByteOrder.LITTLE_ENDIAN)
        .putInt(PE_HEADER_OFFSET_FIELD, PE_HEADER_OFFSET);
    bytes[PE_HEADER_OFFSET] = 'P';
    bytes[PE_HEADER_OFFSET + 1] = 'E';
    short characteristics = IMAGE_FILE_EXECUTABLE_IMAGE;
    if (dll) {
      characteristics |= IMAGE_FILE_DLL;
    }
    ByteBuffer.wrap(bytes)
        .order(ByteOrder.LITTLE_ENDIAN)
        .putShort(COFF_CHARACTERISTICS_OFFSET, characteristics);
    return bytes;
  }
}

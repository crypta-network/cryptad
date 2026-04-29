package network.crypta.platform.devtools;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class CryptaAppCliTest {
  @TempDir private Path tempDir;

  @Test
  void init_whenStaticAppRequested_expectStandaloneBundleSkeleton() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    CliResult result =
        runCli(
            "init",
            "--dir",
            appDir.toString(),
            "--app-id",
            "sample-app",
            "--name",
            "Sample App",
            "--version",
            "0.1.0");

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(Files.isRegularFile(appDir.resolve("cryptad-app.properties")));
    assertTrue(Files.isRegularFile(appDir.resolve("bin").resolve("start.sh")));
    assertTrue(Files.isRegularFile(appDir.resolve("static").resolve("index.html")));
    assertTrue(Files.isRegularFile(appDir.resolve("static").resolve("app.js")));
    assertTrue(Files.isRegularFile(appDir.resolve("static").resolve("app.css")));
    assertTrue(Files.isRegularFile(appDir.resolve("static").resolve("crypta-platform.js")));
    assertTrue(Files.isRegularFile(appDir.resolve("README.md")));
    assertTrue(result.out().contains("Initialized app bundle"));
    assertTrue(
        Files.readString(appDir.resolve("static").resolve("crypta-platform.js"))
            .contains("window.CryptaPlatform"));
  }

  @Test
  void init_whenNoPermissionsRequested_expectManifestOmitsBlankPermissions() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");

    String manifest =
        Files.readString(appDir.resolve("cryptad-app.properties"), StandardCharsets.UTF_8);

    assertFalse(manifest.contains("app.permissions="));
  }

  @Test
  void init_whenShellPanelRequested_expectManifestUsesShellPanelWithoutStaticTemplate()
      throws Exception {
    Path appDir = tempDir.resolve("sample-app");

    CliResult result =
        runCli(
            "init",
            "--dir",
            appDir.toString(),
            "--app-id",
            "sample-app",
            "--name",
            "Sample App",
            "--version",
            "0.1.0",
            "--ui-mode",
            "shell-panel");
    String manifest =
        Files.readString(appDir.resolve("cryptad-app.properties"), StandardCharsets.UTF_8);

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(manifest.contains("app.ui.mode=shell-panel\n"));
    assertTrue(manifest.contains("app.ui.entry=/app/node/#sample-app\n"));
    assertFalse(Files.exists(appDir.resolve("static")));
  }

  @Test
  void init_whenTargetDirectoryIsNotEmptyWithoutOverwrite_expectFailure() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    Files.createDirectories(appDir);
    Files.writeString(appDir.resolve("existing.txt"), "existing", StandardCharsets.UTF_8);

    CliResult result =
        runCli(
            "init",
            "--dir",
            appDir.toString(),
            "--app-id",
            "sample-app",
            "--name",
            "Sample App",
            "--version",
            "0.1.0");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("target directory is not empty"));
  }

  @Test
  void init_whenTargetDirectoryIsSymbolicLink_expectFailureWithoutWritingThroughLink()
      throws Exception {
    Path externalTarget = tempDir.resolve("external-target");
    Path appDir = tempDir.resolve("linked-app");
    Files.createDirectories(externalTarget);
    Assumptions.assumeTrue(canCreateSymlink(appDir));
    Files.createSymbolicLink(appDir, externalTarget);

    CliResult result =
        runCli(
            "init",
            "--dir",
            appDir.toString(),
            "--app-id",
            "sample-app",
            "--name",
            "Sample App",
            "--version",
            "0.1.0",
            "--overwrite");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("target directory must not be a symbolic link"));
    assertFalse(Files.exists(externalTarget.resolve("cryptad-app.properties")));
  }

  @Test
  void validate_whenScaffoldIsMinimal_expectSuccess() {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");

    CliResult result = runCli("validate", "--bundle-dir", appDir.toString());

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(result.out().contains("Bundle is valid: sample-app 0.1.0"));
    assertEquals("", result.err());
  }

  @Test
  void validate_whenBundleIsBroken_expectFailureMessage() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Files.delete(appDir.resolve("bin").resolve("start.sh"));

    CliResult result = runCli("validate", "--bundle-dir", appDir.toString());

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("app.exec does not resolve to a file"));
  }

  @Test
  void validate_whenUnknownPermissionAndStrict_expectFailure() {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0",
        "--permission",
        "future.read");

    CliResult result = runCli("validate", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("unknown app permission(s): future.read"));
  }

  @Test
  void validate_whenUnknownPermissionAndNotStrict_expectWarningAndSuccess() {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0",
        "--permission",
        "future.read");

    CliResult result = runCli("validate", "--bundle-dir", appDir.toString());

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(result.err().contains("Warning: unknown app permission(s): future.read"));
    assertTrue(result.out().contains("Bundle is valid: sample-app 0.1.0"));
  }

  @Test
  void signAndVerify_whenBundleCliRoundTrips_expectSuccess() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Path privateKey = tempDir.resolve("private.der");
    Path publicKey = tempDir.resolve("public.der");
    Files.write(privateKey, keyPair.getPrivate().getEncoded());
    Files.write(publicKey, keyPair.getPublic().getEncoded());
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");

    CliResult signResult =
        runCli(
            "sign",
            "--bundle-dir",
            appDir.toString(),
            "--key-id",
            "dev-local",
            "--private-key-file",
            privateKey.toString());
    CliResult verifyResult =
        runCli(
            "verify",
            "--bundle-dir",
            appDir.toString(),
            "--trusted-key-id",
            "dev-local",
            "--trusted-public-key-file",
            publicKey.toString());

    assertEquals(CommandLine.ExitCode.OK, signResult.exitCode());
    assertTrue(signResult.out().contains("Signed bundle:"));
    assertEquals(CommandLine.ExitCode.OK, verifyResult.exitCode());
    assertTrue(verifyResult.out().contains("Verified bundle:"));
  }

  @Test
  void pack_whenScaffoldIsValid_expectZipArtifact() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    Path outputZip = tempDir.resolve("sample-app.zip");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");

    CliResult result =
        runCli("pack", "--bundle-dir", appDir.toString(), "--output", outputZip.toString());

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(Files.isRegularFile(outputZip));
    assertTrue(result.out().contains("Packaged bundle:"));
    assertTrue(result.out().contains(sha256Hex(outputZip)));
  }

  @Test
  void pack_whenOutputExistsWithoutOverwrite_expectFailure() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    Path outputZip = tempDir.resolve("sample-app.zip");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Files.writeString(outputZip, "existing");

    CliResult result =
        runCli("pack", "--bundle-dir", appDir.toString(), "--output", outputZip.toString());

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("output ZIP already exists"));
  }

  @Test
  void catalogCreate_whenDescriptorPointsAtBundleZip_expectCatalogWithComputedArtifactMetadata()
      throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    Path outputZip = tempDir.resolve("sample-app.zip");
    Path descriptor = tempDir.resolve("entry.properties");
    Path catalogFile = tempDir.resolve("cryptad-app-catalog.properties");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0",
        "--permission",
        "queue.read");
    runCli("pack", "--bundle-dir", appDir.toString(), "--output", outputZip.toString());
    Files.writeString(
        descriptor,
        lines(
            "artifact.path=" + outputZip.toAbsolutePath().normalize(),
            "bundle.uri=" + outputZip.toUri(),
            "summary=Sample catalog entry."),
        StandardCharsets.UTF_8);

    CliResult result =
        runCli(
            "catalog",
            "create",
            "--catalog-file",
            catalogFile.toString(),
            "--catalog-id",
            "dev",
            "--name",
            "Development Apps",
            "--generated-at",
            "2026-04-29T00:00:00Z",
            "--entry",
            descriptor.toString());

    String catalog = Files.readString(catalogFile, StandardCharsets.UTF_8);
    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(result.out().contains("Created catalog: dev with 1 entry"));
    assertTrue(catalog.contains("catalog.generatedAt=2026-04-29T00:00:00Z\n"));
    assertTrue(catalog.contains("app.sample-app.id=sample-app\n"));
    assertTrue(catalog.contains("app.sample-app.permissions=queue.read\n"));
    assertTrue(catalog.contains("app.sample-app.bundle.size.bytes=" + Files.size(outputZip)));
    assertTrue(catalog.contains("app.sample-app.bundle.sha256=" + sha256Hex(outputZip)));
  }

  @Test
  void catalogSignAndVerify_whenCatalogCliRoundTrips_expectSuccess() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    Path outputZip = tempDir.resolve("sample-app.zip");
    Path descriptor = tempDir.resolve("entry.properties");
    Path catalogFile = tempDir.resolve("cryptad-app-catalog.properties");
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Path privateKey = tempDir.resolve("catalog-private.der");
    Path publicKey = tempDir.resolve("catalog-public.der");
    Files.write(privateKey, keyPair.getPrivate().getEncoded());
    Files.write(publicKey, keyPair.getPublic().getEncoded());
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    runCli("pack", "--bundle-dir", appDir.toString(), "--output", outputZip.toString());
    Files.writeString(
        descriptor,
        lines(
            "artifact.path=" + outputZip.toAbsolutePath().normalize(),
            "bundle.uri=" + outputZip.toUri(),
            "summary=Sample catalog entry."),
        StandardCharsets.UTF_8);
    runCli(
        "catalog",
        "create",
        "--catalog-file",
        catalogFile.toString(),
        "--catalog-id",
        "dev",
        "--name",
        "Development Apps",
        "--entry",
        descriptor.toString());

    CliResult signResult =
        runCli(
            "catalog",
            "sign",
            "--catalog-file",
            catalogFile.toString(),
            "--key-id",
            "dev-local",
            "--private-key-file",
            privateKey.toString());
    CliResult verifyResult =
        runCli(
            "catalog",
            "verify",
            "--catalog-file",
            catalogFile.toString(),
            "--trusted-key-id",
            "dev-local",
            "--trusted-public-key-file",
            publicKey.toString());

    assertEquals(CommandLine.ExitCode.OK, signResult.exitCode());
    assertTrue(signResult.out().contains("Signed catalog with key: dev-local"));
    assertEquals(CommandLine.ExitCode.OK, verifyResult.exitCode());
    assertTrue(verifyResult.out().contains("Verified catalog: dev"));
  }

  @Test
  void help_whenRequested_expectUsage() {
    CliResult result = runCli("--help");

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(result.out().contains("Usage: crypta-app"));
    assertTrue(result.out().contains("init"));
    assertTrue(result.out().contains("validate"));
    assertTrue(result.out().contains("pack"));
    assertTrue(result.out().contains("catalog"));
  }

  private static String sha256Hex(Path file) throws Exception {
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    byte[] bytes = Files.readAllBytes(file);
    digest.update(bytes);
    StringBuilder builder = new StringBuilder(64);
    for (byte value : digest.digest()) {
      builder.append(Character.forDigit((value >>> 4) & 0x0F, 16));
      builder.append(Character.forDigit(value & 0x0F, 16));
    }
    return builder.toString();
  }

  private static String lines(String... values) {
    return String.join("\n", values) + "\n";
  }

  private static boolean canCreateSymlink(Path symlink) {
    try {
      Files.createSymbolicLink(symlink, Path.of("missing-target"));
      Files.deleteIfExists(symlink);
      return true;
    } catch (UnsupportedOperationException | java.io.IOException | SecurityException _) {
      return false;
    }
  }

  private static CliResult runCli(String... arguments) {
    StringWriter out = new StringWriter();
    StringWriter err = new StringWriter();
    int exitCode =
        CryptaAppCli.execute(new PrintWriter(out, true), new PrintWriter(err, true), arguments);
    return new CliResult(exitCode, out.toString(), err.toString());
  }

  private record CliResult(int exitCode, String out, String err) {}
}

package network.crypta.platform.appdist;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AppBundleDigestWriterTest {
  @TempDir Path tempDir;

  @Test
  void write_whenBundleContainsManifestAndFiles_expectDeterministicSortedDigest() throws Exception {
    Path bundleRoot = createBundle();
    Files.writeString(bundleRoot.resolve(AppBundleDigest.DIGEST_FILE_NAME), "stale-digest");
    Files.writeString(
        bundleRoot.resolve(AppBundleSignature.SIGNATURE_FILE_NAME), "stale-signature");
    Files.createDirectories(bundleRoot.resolve("assets"));
    Files.writeString(bundleRoot.resolve("assets/logo.txt"), "logo");
    Files.writeString(bundleRoot.resolve("z-last.txt"), "tail");

    AppBundleDigest firstDigest = AppBundleDigestWriter.write(bundleRoot);
    String firstSidecar =
        Files.readString(
            bundleRoot.resolve(AppBundleDigest.DIGEST_FILE_NAME), StandardCharsets.UTF_8);
    AppBundleDigest secondDigest = AppBundleDigestWriter.write(bundleRoot);
    String secondSidecar =
        Files.readString(
            bundleRoot.resolve(AppBundleDigest.DIGEST_FILE_NAME), StandardCharsets.UTF_8);

    assertEquals(firstDigest, secondDigest);
    assertEquals(firstSidecar, secondSidecar);
    assertEquals(
        List.of(
            "assets/logo.txt", "bin/start.sh", AppBundleDigest.MANIFEST_FILE_NAME, "z-last.txt"),
        secondDigest.entries().stream().map(AppBundleDigestEntry::path).toList());
    assertTrue(
        secondDigest.entries().stream()
            .anyMatch(entry -> entry.path().equals(AppBundleDigest.MANIFEST_FILE_NAME)));
    assertFalse(secondSidecar.contains(".executable="));
    assertFalse(secondSidecar.contains(AppBundleSignature.SIGNATURE_FILE_NAME));
    assertFalse(secondSidecar.contains("stale-signature"));
  }

  @Test
  void write_whenBundleContainsCaseVariantSidecars_expectDigestExcludesThem() throws Exception {
    Path bundleRoot = createBundle();
    Files.writeString(bundleRoot.resolve("CRYPTAD-APP.DIGESTS"), "case-variant-digest");
    Files.writeString(bundleRoot.resolve("CRYPTAD-APP.SIGNATURE"), "case-variant-signature");
    Files.writeString(bundleRoot.resolve("CRYPTAD-APP.CATALOG"), "case-variant-catalog");

    AppBundleDigest digest = AppBundleDigestWriter.write(bundleRoot);

    assertFalse(
        digest.entries().stream()
            .map(AppBundleDigestEntry::path)
            .anyMatch(path -> path.startsWith("CRYPTAD-APP.")));
  }

  @Test
  void write_whenPosixExecutableRequiresExecBit_expectDigestIncludesExecutableFlag()
      throws Exception {
    Path bundleRoot = createPosixExecutableBundle();

    AppBundleDigest digest = AppBundleDigestWriter.write(bundleRoot);
    String sidecar =
        Files.readString(
            bundleRoot.resolve(AppBundleDigest.DIGEST_FILE_NAME), StandardCharsets.UTF_8);

    assertTrue(
        digest.entries().stream()
            .anyMatch(
                entry ->
                    entry.path().equals("bin/tool") && Boolean.TRUE.equals(entry.executable())));
    assertTrue(sidecar.contains(".executable=true"));
  }

  @Test
  void verify_whenDigestSidecarContainsTraversalPath_expectFailure() throws Exception {
    Path bundleRoot = createBundle();
    String manifestSha = sha256Hex(bundleRoot.resolve(AppBundleDigest.MANIFEST_FILE_NAME));
    Files.writeString(
        bundleRoot.resolve(AppBundleDigest.DIGEST_FILE_NAME),
        """
        digest.version=1
        digest.algorithm=SHA-256
        file.0.path=../escape.txt
        file.0.sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
        file.1.path=cryptad-app.properties
        file.1.sha256=%s
        """
            .formatted(manifestSha),
        StandardCharsets.UTF_8);

    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class, () -> AppBundleDigestVerifier.verify(bundleRoot));

    assertTrue(exception.getMessage().contains("invalid digest entry 0"));
  }

  @Test
  void write_whenBundleContainsSymlink_expectFailure() throws Exception {
    Path bundleRoot = createBundle();
    Path symlink = bundleRoot.resolve("linked.txt");
    Assumptions.assumeTrue(canCreateSymlink(symlink));
    Path target = tempDir.resolve("target.txt");
    Files.writeString(target, "linked");
    Files.createSymbolicLink(symlink, target);

    AppDistributionException exception =
        assertThrows(AppDistributionException.class, () -> AppBundleDigestWriter.write(bundleRoot));

    assertTrue(exception.getMessage().contains("symlink"));
  }

  @Test
  void write_whenWindowsJunctionEscapesBundleRoot_expectFailure() throws Exception {
    Assumptions.assumeTrue(isWindows());
    Path bundleRoot = createBundle();
    Path externalRoot = Files.createDirectories(tempDir.resolve("outside-root"));
    Path junction = bundleRoot.resolve("outside-junction");

    Process mklink =
        new ProcessBuilder(
                windowsCommandInterpreter(),
                "/c",
                "mklink",
                "/J",
                junction.toString(),
                externalRoot.toString())
            .start();
    assertEquals(0, waitForExit(mklink));

    AppDistributionException exception =
        assertThrows(AppDistributionException.class, () -> AppBundleDigestWriter.write(bundleRoot));

    assertTrue(exception.getMessage().contains("links or reparse points"));
  }

  private Path createBundle() throws IOException {
    Path bundleRoot = tempDir.resolve("bundle");
    Files.createDirectories(bundleRoot.resolve("bin"));
    Files.writeString(
        bundleRoot.resolve(AppBundleDigest.MANIFEST_FILE_NAME),
        """
        manifest.version=1
        app.id=sample-app
        app.name=Sample App
        app.version=1.0.0
        app.exec=bin/start.sh
        """,
        StandardCharsets.UTF_8);
    Files.writeString(
        bundleRoot.resolve("bin/start.sh"), "#!/bin/sh\necho sample\n", StandardCharsets.UTF_8);
    return bundleRoot;
  }

  private Path createPosixExecutableBundle() throws IOException {
    Assumptions.assumeTrue(
        Files.getFileStore(tempDir).supportsFileAttributeView("posix"),
        "POSIX execute-bit authentication requires POSIX file attributes");
    Path bundleRoot = tempDir.resolve("posix-bundle");
    Path binDir = Files.createDirectories(bundleRoot.resolve("bin"));
    Path executable = binDir.resolve("tool");
    Files.writeString(
        bundleRoot.resolve(AppBundleDigest.MANIFEST_FILE_NAME),
        """
        manifest.version=1
        app.id=sample-app
        app.name=Sample App
        app.version=1.0.0
        app.exec=bin/tool
        """,
        StandardCharsets.UTF_8);
    Files.writeString(executable, "echo sample\n", StandardCharsets.UTF_8);
    Files.setPosixFilePermissions(
        executable, java.nio.file.attribute.PosixFilePermissions.fromString("rwxr-xr-x"));
    return bundleRoot;
  }

  private static boolean canCreateSymlink(Path symlink) {
    try {
      Files.createSymbolicLink(symlink, Path.of("missing-target"));
      Files.deleteIfExists(symlink);
      return true;
    } catch (IOException | SecurityException | UnsupportedOperationException _) {
      return false;
    }
  }

  private static boolean isWindows() {
    return System.getProperty("os.name").toLowerCase(Locale.ROOT).contains("win");
  }

  private static String windowsCommandInterpreter() {
    String comSpec = System.getenv("ComSpec");
    return comSpec != null && !comSpec.isBlank() ? comSpec : "cmd.exe";
  }

  private static int waitForExit(Process process) throws Exception {
    if (!process.waitFor(5, TimeUnit.SECONDS)) {
      process.destroyForcibly();
      throw new java.io.IOException("timed out waiting for process to exit: " + process.pid());
    }
    return process.exitValue();
  }

  private static String sha256Hex(Path file) throws Exception {
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    return AppDistributionSidecars.lowercaseHex(digest.digest(Files.readAllBytes(file)));
  }
}

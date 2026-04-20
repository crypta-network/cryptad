package network.crypta.platform.appdist;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AppDistributionToolTest {
  @TempDir Path tempDir;

  @Test
  void verify_whenAllowUnsignedAndBundleHasNoSidecars_expectTrustInputsIgnored() throws Exception {
    Path bundleRoot = createBundle();
    Path missingTrustedKeysFile = tempDir.resolve("missing-trusted-keys.properties");

    assertDoesNotThrow(
        () ->
            AppDistributionTool.main(
                new String[] {
                  "verify",
                  "--bundle-dir",
                  bundleRoot.toString(),
                  "--allow-unsigned",
                  "--trusted-keys-file",
                  missingTrustedKeysFile.toString()
                }));
  }

  @Test
  void verify_whenAllowUnsignedAndExecutableMissing_expectBundleFailure() throws Exception {
    Path bundleRoot = createBundle();
    Files.delete(bundleRoot.resolve("bin/start.sh"));

    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class,
            () ->
                AppDistributionTool.main(
                    new String[] {
                      "verify", "--bundle-dir", bundleRoot.toString(), "--allow-unsigned"
                    }));

    assertEquals(
        "app.exec does not resolve to a file in bundle: bin/start.sh", exception.getMessage());
  }

  @Test
  void verify_whenAllowUnsignedAndCaseVariantSidecarPresent_expectSignedPathFailure()
      throws Exception {
    Path bundleRoot = createBundle();
    Files.writeString(bundleRoot.resolve("CRYPTAD-APP.DIGESTS"), "stale-digest");

    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class,
            () ->
                AppDistributionTool.main(
                    new String[] {
                      "verify", "--bundle-dir", bundleRoot.toString(), "--allow-unsigned"
                    }));

    assertEquals("missing signature sidecar", exception.getMessage());
  }

  @Test
  void verify_whenAllowUnsignedAndBundleContainsSymlink_expectFailure() throws Exception {
    Path bundleRoot = createBundle();
    Path symlink = bundleRoot.resolve("linked.txt");
    Assumptions.assumeTrue(canCreateSymlink(symlink));
    Files.createSymbolicLink(symlink, tempDir.resolve("outside.txt"));

    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class,
            () ->
                AppDistributionTool.main(
                    new String[] {
                      "verify", "--bundle-dir", bundleRoot.toString(), "--allow-unsigned"
                    }));

    assertEquals("bundle must not contain symlinks: " + symlink, exception.getMessage());
  }

  @Test
  void verify_whenConflictingTrustedPublicKeyInputsProvided_expectFailure() throws Exception {
    Path bundleRoot = createBundle();
    Files.writeString(bundleRoot.resolve(AppBundleDigest.DIGEST_FILE_NAME), "stub-digest");

    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class,
            () ->
                AppDistributionTool.main(
                    new String[] {
                      "verify",
                      "--bundle-dir",
                      bundleRoot.toString(),
                      "--allow-unsigned",
                      "--trusted-key-id",
                      "local-dev",
                      "--trusted-public-key-base64",
                      "ZmFrZQ==",
                      "--trusted-public-key-file",
                      tempDir.resolve("public.pem").toString()
                    }));

    assertEquals(
        "Trusted app public key material must be configured by base64 or file, not both.",
        exception.getMessage());
  }

  @Test
  void verify_whenSignedBundleExecutableMissing_expectBundleFailureAfterSignatureCheck()
      throws Exception {
    Path bundleRoot = createBundle();
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    AppBundleSigner.sign(bundleRoot, "local-dev", keyPair.getPrivate());
    Files.delete(bundleRoot.resolve("bin/start.sh"));

    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class,
            () ->
                AppDistributionTool.main(
                    new String[] {
                      "verify",
                      "--bundle-dir",
                      bundleRoot.toString(),
                      "--trusted-key-id",
                      "local-dev",
                      "--trusted-public-key-base64",
                      java.util.Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded())
                    }));

    assertEquals(
        "app.exec does not resolve to a file in bundle: bin/start.sh", exception.getMessage());
  }

  private Path createBundle() throws Exception {
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

  private static boolean canCreateSymlink(Path symlink) {
    try {
      Files.createSymbolicLink(symlink, Path.of("missing-target"));
      Files.deleteIfExists(symlink);
      return true;
    } catch (Exception _) {
      return false;
    }
  }
}

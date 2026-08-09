package network.crypta.platform.appdist;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AppDistributionToolTest {
  @TempDir Path tempDir;

  @Test
  void packageBundle_whenCliPackagesSameSignedInputTwice_expectByteIdenticalArchives()
      throws Exception {
    Path bundleRoot = createBundle();
    Path first = tempDir.resolve("first.zip");
    Path second = tempDir.resolve("second.zip");

    AppDistributionTool.main(
        new String[] {
          "package", "--bundle-dir", bundleRoot.toString(), "--output-zip", first.toString()
        });
    AppDistributionTool.main(
        new String[] {
          "package", "--bundle-dir", bundleRoot.toString(), "--output-zip", second.toString()
        });

    assertArrayEquals(Files.readAllBytes(first), Files.readAllBytes(second));
  }

  @Test
  void signAndVerify_whenCliRoundTripsSignedBundle_expectSuccess() throws Exception {
    Path bundleRoot = createBundle();
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();

    AppDistributionTool.main(
        new String[] {
          "sign",
          "--bundle-dir",
          bundleRoot.toString(),
          "--key-id",
          "local-dev",
          "--private-key-base64",
          Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded())
        });
    assertTrue(Files.exists(bundleRoot.resolve(AppBundleDigest.DIGEST_FILE_NAME)));
    assertTrue(Files.exists(bundleRoot.resolve(AppBundleSignature.SIGNATURE_FILE_NAME)));
    AppDistributionTool.main(
        new String[] {
          "verify",
          "--bundle-dir",
          bundleRoot.toString(),
          "--trusted-key-id",
          "local-dev",
          "--trusted-public-key-base64",
          Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded())
        });
  }

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

package network.crypta.platform.appdist;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AppBundleVerifierTest {
  private static final String TEST_KEY_ID = "test-ed25519";

  @TempDir Path tempDir;

  @Test
  void verify_whenBundleIsSignedAndUntouched_expectSuccess() throws Exception {
    Path bundleRoot = createBundle();
    KeyPair keyPair = generateEd25519KeyPair();
    AppBundleSignature writtenSignature =
        AppBundleSigner.sign(bundleRoot, TEST_KEY_ID, keyPair.getPrivate());

    AppBundleSignature verifiedSignature =
        AppBundleVerifier.verify(bundleRoot, trustedKeys(keyPair, TEST_KEY_ID));

    assertEquals(writtenSignature, verifiedSignature);
    assertEquals(TEST_KEY_ID, verifiedSignature.keyId());
    assertEquals(AppBundleSignature.SIGNATURE_ALGORITHM, verifiedSignature.algorithm());
  }

  @Test
  void verify_whenBundleFileChangesAfterSigning_expectFailure() throws Exception {
    Path bundleRoot = createBundle();
    KeyPair keyPair = generateEd25519KeyPair();
    AppBundleSigner.sign(bundleRoot, TEST_KEY_ID, keyPair.getPrivate());
    Files.writeString(bundleRoot.resolve("README.txt"), "mutated", StandardCharsets.UTF_8);

    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class,
            () -> AppBundleVerifier.verify(bundleRoot, trustedKeys(keyPair, TEST_KEY_ID)));

    assertEquals("digest sidecar does not match bundle contents", exception.getMessage());
  }

  @Test
  void verify_whenManifestChangesAfterSigning_expectFailure() throws Exception {
    Path bundleRoot = createBundle();
    KeyPair keyPair = generateEd25519KeyPair();
    AppBundleSigner.sign(bundleRoot, TEST_KEY_ID, keyPair.getPrivate());
    Files.writeString(
        bundleRoot.resolve(AppBundleDigest.MANIFEST_FILE_NAME),
        """
        manifest.version=1
        app.id=sample-app
        app.name=Tampered App
        app.version=1.0.0
        app.exec=bin/start.sh
        """,
        StandardCharsets.UTF_8);

    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class,
            () -> AppBundleVerifier.verify(bundleRoot, trustedKeys(keyPair, TEST_KEY_ID)));

    assertEquals("digest sidecar does not match bundle contents", exception.getMessage());
  }

  @Test
  void verify_whenExecutableBitChangesAfterSigning_expectFailure() throws Exception {
    Path bundleRoot = createPosixExecutableBundle();
    Path executable = bundleRoot.resolve("bin/tool");
    Assumptions.assumeTrue(Files.getFileStore(executable).supportsFileAttributeView("posix"));
    KeyPair keyPair = generateEd25519KeyPair();
    AppBundleSigner.sign(bundleRoot, TEST_KEY_ID, keyPair.getPrivate());
    Files.setPosixFilePermissions(executable, PosixFilePermissions.fromString("rw-r--r--"));

    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class,
            () -> AppBundleVerifier.verify(bundleRoot, trustedKeys(keyPair, TEST_KEY_ID)));

    assertEquals(
        "app.exec is not launchable on any supported platform: bin/tool", exception.getMessage());
  }

  @Test
  void verify_whenDigestSidecarBytesChangeAfterSigning_expectFailure() throws Exception {
    Path bundleRoot = createBundle();
    KeyPair keyPair = generateEd25519KeyPair();
    AppBundleSigner.sign(bundleRoot, TEST_KEY_ID, keyPair.getPrivate());
    Path digestSidecar = bundleRoot.resolve(AppBundleDigest.DIGEST_FILE_NAME);
    Files.writeString(
        digestSidecar,
        Files.readString(digestSidecar, StandardCharsets.UTF_8).replace("SHA-256", "SHA-256 "),
        StandardCharsets.UTF_8);

    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class,
            () -> AppBundleVerifier.verify(bundleRoot, trustedKeys(keyPair, TEST_KEY_ID)));

    assertEquals("signature sidecar does not match digest sidecar", exception.getMessage());
  }

  @Test
  void verify_whenKeyIdIsUnknown_expectFailure() throws Exception {
    Path bundleRoot = createBundle();
    KeyPair signingKeyPair = generateEd25519KeyPair();
    AppBundleSigner.sign(bundleRoot, TEST_KEY_ID, signingKeyPair.getPrivate());
    KeyPair unrelatedKeyPair = generateEd25519KeyPair();

    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class,
            () -> AppBundleVerifier.verify(bundleRoot, trustedKeys(unrelatedKeyPair, "other-key")));

    assertEquals("unknown trusted key id: " + TEST_KEY_ID, exception.getMessage());
  }

  @Test
  void verify_whenSignatureAlgorithmUnsupported_expectFailure() throws Exception {
    Path bundleRoot = createBundle();
    KeyPair keyPair = generateEd25519KeyPair();
    AppBundleSignature signature =
        AppBundleSigner.sign(bundleRoot, TEST_KEY_ID, keyPair.getPrivate());
    Files.writeString(
        bundleRoot.resolve(AppBundleSignature.SIGNATURE_FILE_NAME),
        AppBundleSigner.serialize(
                new AppBundleSignature(
                    signature.version(),
                    signature.algorithm(),
                    signature.keyId(),
                    signature.payload(),
                    signature.valueBase64()))
            .replace("signature.algorithm=Ed25519", "signature.algorithm=RSA"),
        StandardCharsets.UTF_8);

    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class,
            () -> AppBundleVerifier.verify(bundleRoot, trustedKeys(keyPair, TEST_KEY_ID)));

    assertEquals("unsupported signature.algorithm: RSA", exception.getMessage());
  }

  @Test
  void verify_whenSignatureSidecarIsMissing_expectFailure() throws Exception {
    Path bundleRoot = createBundle();
    KeyPair keyPair = generateEd25519KeyPair();
    AppBundleSigner.sign(bundleRoot, TEST_KEY_ID, keyPair.getPrivate());
    Files.delete(bundleRoot.resolve(AppBundleSignature.SIGNATURE_FILE_NAME));

    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class,
            () -> AppBundleVerifier.verify(bundleRoot, trustedKeys(keyPair, TEST_KEY_ID)));

    assertEquals("missing signature sidecar", exception.getMessage());
  }

  @Test
  void verify_whenUnsignedAllowedAndNoSidecarsPresent_expectUnsignedSuccess() throws Exception {
    Path bundleRoot = createBundle();

    AppBundleVerification verification =
        AppBundleVerifier.allowUnsignedForDevelopmentOnly(TrustedAppKeys.empty())
            .verify(bundleRoot);

    assertFalse(verification.signed());
    assertNull(verification.keyId());
    assertNull(verification.algorithm());
  }

  @Test
  void verify_whenUnsignedAllowedAndCaseVariantSidecarPresent_expectSignedPathFailure()
      throws Exception {
    Path bundleRoot = createBundle();
    Files.writeString(bundleRoot.resolve("CRYPTAD-APP.DIGESTS"), "stale-digest");

    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class,
            () ->
                AppBundleVerifier.allowUnsignedForDevelopmentOnly(TrustedAppKeys.empty())
                    .verify(bundleRoot));

    assertEquals("missing signature sidecar", exception.getMessage());
  }

  @Test
  void verify_whenDigestSidecarIsMissing_expectFailure() throws Exception {
    Path bundleRoot = createBundle();
    KeyPair keyPair = generateEd25519KeyPair();
    AppBundleSigner.sign(bundleRoot, TEST_KEY_ID, keyPair.getPrivate());
    Files.delete(bundleRoot.resolve(AppBundleDigest.DIGEST_FILE_NAME));

    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class,
            () -> AppBundleVerifier.verify(bundleRoot, trustedKeys(keyPair, TEST_KEY_ID)));

    assertEquals("missing digest sidecar", exception.getMessage());
  }

  @Test
  void digestVerifier_whenDigestAlgorithmUnsupported_expectFailure() throws Exception {
    Path bundleRoot = createBundle();
    KeyPair keyPair = generateEd25519KeyPair();
    AppBundleSigner.sign(bundleRoot, TEST_KEY_ID, keyPair.getPrivate());
    Path digestSidecar = bundleRoot.resolve(AppBundleDigest.DIGEST_FILE_NAME);
    Files.writeString(
        digestSidecar,
        Files.readString(digestSidecar, StandardCharsets.UTF_8)
            .replace("digest.algorithm=SHA-256", "digest.algorithm=SHA-1"),
        StandardCharsets.UTF_8);

    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class, () -> AppBundleDigestVerifier.verify(bundleRoot));

    assertEquals("unsupported digest.algorithm: SHA-1", exception.getMessage());
  }

  @Test
  void digestVerifier_whenSidecarIsRewrittenAfterDigestRead_expectSuppliedDigestStillEnforced()
      throws Exception {
    Path bundleRoot = createBundle();
    AppBundleDigestWriter.write(bundleRoot);
    AppBundleDigest signedDigest =
        AppBundleDigestVerifier.read(
            Files.readAllBytes(bundleRoot.resolve(AppBundleDigest.DIGEST_FILE_NAME)));
    Files.writeString(bundleRoot.resolve("README.txt"), "mutated", StandardCharsets.UTF_8);
    AppBundleDigest rewrittenDigest = AppBundleDigestWriter.write(bundleRoot);

    AppBundleDigest rereadDigest = AppBundleDigestVerifier.verify(bundleRoot);
    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class,
            () -> AppBundleDigestVerifier.verify(bundleRoot, signedDigest));

    assertEquals(rewrittenDigest, rereadDigest);
    assertEquals("digest sidecar does not match bundle contents", exception.getMessage());
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
    Files.writeString(bundleRoot.resolve("README.txt"), "bundle-readme", StandardCharsets.UTF_8);
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
    Files.setPosixFilePermissions(executable, PosixFilePermissions.fromString("rwxr-xr-x"));
    Files.writeString(bundleRoot.resolve("README.txt"), "bundle-readme", StandardCharsets.UTF_8);
    return bundleRoot;
  }

  private static KeyPair generateEd25519KeyPair() throws Exception {
    return KeyPairGenerator.getInstance(AppBundleSignature.SIGNATURE_ALGORITHM).generateKeyPair();
  }

  private static TrustedAppKeys trustedKeys(KeyPair keyPair, String keyId) {
    return TrustedAppKeys.of(
        new TrustedAppKey(keyId, AppBundleSignature.SIGNATURE_ALGORITHM, keyPair.getPublic()));
  }
}

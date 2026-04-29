package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class AppCatalogSignerTest {
  private static final String KEY_ID = "catalog-signer-test";

  @TempDir private Path tempDir;

  @Test
  void sign_whenSignatureSidecarIsSymbolicLink_expectRejectsWithoutWritingThroughLink()
      throws IOException, NoSuchAlgorithmException {
    Path catalogFile = tempDir.resolve(AppCatalogSignature.CATALOG_FILE_NAME);
    Path realSignatureTarget = tempDir.resolve("external-signature.properties");
    Path signatureSidecar = tempDir.resolve(AppCatalogSignature.SIGNATURE_FILE_NAME);
    Files.writeString(catalogFile, "catalog.version=1\n", StandardCharsets.UTF_8);
    Files.writeString(realSignatureTarget, "unchanged", StandardCharsets.UTF_8);
    Assumptions.assumeTrue(canCreateSymlink(signatureSidecar));
    Files.createSymbolicLink(signatureSidecar, realSignatureTarget);
    PrivateKey privateKey = privateKey();

    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class,
            () -> AppCatalogSigner.sign(catalogFile, KEY_ID, privateKey));

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_SIGNATURE, exception.errorCode());
    assertTrue(exception.getMessage().contains("must not be a symbolic link"));
    assertEquals("unchanged", Files.readString(realSignatureTarget, StandardCharsets.UTF_8));
  }

  private static PrivateKey privateKey() throws NoSuchAlgorithmException {
    KeyPair keyPair =
        KeyPairGenerator.getInstance(AppCatalogSignature.SIGNATURE_ALGORITHM).generateKeyPair();
    return keyPair.getPrivate();
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
}

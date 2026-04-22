package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.Base64;
import java.util.Objects;

/**
 * Writes deterministic Ed25519 catalog signature sidecars for tests and tooling.
 *
 * <p>The signer reads the catalog properties file as exact bytes and signs those bytes without
 * reparsing or normalizing the catalog. Runtime verification uses the same byte-for-byte payload,
 * so build tooling can create catalog fixtures that exercise the production trust path.
 *
 * <p>This class is intentionally small and does not manage key storage. Callers provide the private
 * key and trusted-key id that operators will configure separately as a public trusted key. The
 * generated sidecar uses the canonical file names and schema fields consumed by {@link
 * AppCatalogVerifier}.
 */
public final class AppCatalogSigner {
  private AppCatalogSigner() {}

  /**
   * Signs a catalog properties file and writes its sibling signature sidecar.
   *
   * <p>The catalog file must already contain the final bytes to authenticate. The method enforces
   * the catalog sidecar size cap, signs the exact bytes, serializes signature metadata, and writes
   * {@code cryptad-app-catalog.signature} beside the catalog file. Existing signature files are
   * replaced by the write operation.
   *
   * @param catalogFile path to {@code cryptad-app-catalog.properties}
   * @param keyId stable trusted-key identifier written into the sidecar
   * @param privateKey Ed25519 private key used to sign the exact catalog bytes
   * @return signature metadata written to disk
   * @throws IOException if the catalog file cannot be read or the sidecar cannot be written
   */
  public static AppCatalogSignature sign(Path catalogFile, String keyId, PrivateKey privateKey)
      throws IOException {
    Path normalizedCatalogFile = Objects.requireNonNull(catalogFile).toAbsolutePath().normalize();
    byte[] catalogBytes =
        AppCatalogSidecars.readRequiredBytes(
            normalizedCatalogFile,
            AppCatalogSidecars.MAX_CATALOG_BYTES,
            "catalog properties",
            AppCatalogSidecars.INVALID_CATALOG_ENTRY);
    AppCatalogSignature signature =
        new AppCatalogSignature(
            AppCatalogSignature.SIGNATURE_VERSION,
            AppCatalogSignature.SIGNATURE_ALGORITHM,
            keyId,
            AppCatalogSignature.CATALOG_FILE_NAME,
            Base64.getEncoder().encodeToString(signBytes(catalogBytes, privateKey)));
    Files.writeString(
        normalizedCatalogFile.resolveSibling(AppCatalogSignature.SIGNATURE_FILE_NAME),
        serialize(signature));
    return signature;
  }

  static String serialize(AppCatalogSignature signature) {
    return "catalog.signature.version="
        + signature.version()
        + '\n'
        + "catalog.signature.algorithm="
        + signature.algorithm()
        + '\n'
        + "catalog.signature.key.id="
        + signature.keyId()
        + '\n'
        + "catalog.signature.payload="
        + signature.payload()
        + '\n'
        + "catalog.signature.value.base64="
        + signature.valueBase64()
        + '\n';
  }

  private static byte[] signBytes(byte[] catalogBytes, PrivateKey privateKey) {
    try {
      Signature signer = Signature.getInstance(AppCatalogSignature.SIGNATURE_ALGORITHM);
      signer.initSign(Objects.requireNonNull(privateKey, "privateKey"));
      signer.update(catalogBytes);
      return signer.sign();
    } catch (GeneralSecurityException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_SIGNATURE,
          "failed to sign catalog sidecar",
          exception);
    }
  }
}

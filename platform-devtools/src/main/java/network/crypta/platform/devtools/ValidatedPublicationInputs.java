package network.crypta.platform.devtools;

import java.nio.file.Path;
import network.crypta.platform.appcatalog.AppCatalog;
import network.crypta.platform.appcatalog.AppCatalogSignature;

/**
 * Immutable snapshot of validated catalog publication inputs.
 *
 * <p>The record is intentionally package-scoped because it is a coordination type between the
 * developer CLI's dry-run writer and live publication service. It keeps the exact bytes needed for
 * signature verification and live staging, plus only derived report-safe metadata such as digests
 * and file basenames. Callers should use {@link AppTestRedactor#fileName(Path)} when rendering any
 * of the local paths held here.
 *
 * @param catalogFile normalized local catalog file path
 * @param catalogSignatureFile normalized local signature sidecar path
 * @param catalogSource public {@code crypta:USK@.../cryptad-app-catalog.properties} source
 * @param output normalized report output path
 * @param catalogBytes exact catalog properties bytes
 * @param signatureBytes exact signature sidecar bytes
 * @param catalog parsed catalog metadata
 * @param signature parsed signature metadata
 * @param catalogSha256 SHA-256 digest of {@code catalogBytes}
 * @param signatureSha256 SHA-256 digest of {@code signatureBytes}
 */
@SuppressWarnings("ArrayRecordComponent")
record ValidatedPublicationInputs(
    Path catalogFile,
    Path catalogSignatureFile,
    String catalogSource,
    Path output,
    byte[] catalogBytes,
    byte[] signatureBytes,
    AppCatalog catalog,
    AppCatalogSignature signature,
    String catalogSha256,
    String signatureSha256) {
  /**
   * Defensively copies mutable sidecar byte arrays at the validation boundary.
   *
   * <p>The validator passes this record to both dry-run and live publication paths. Copying here
   * keeps later caller mutations from changing the bytes that are verified, staged, and digested
   * for evidence.
   */
  ValidatedPublicationInputs {
    catalogBytes = catalogBytes.clone();
    signatureBytes = signatureBytes.clone();
  }

  /**
   * Returns the exact catalog properties bytes captured during validation.
   *
   * @return defensive copy of the validated catalog bytes
   */
  @Override
  public byte[] catalogBytes() {
    return catalogBytes.clone();
  }

  /**
   * Returns the exact detached signature sidecar bytes captured during validation.
   *
   * @return defensive copy of the validated signature bytes
   */
  @Override
  public byte[] signatureBytes() {
    return signatureBytes.clone();
  }
}

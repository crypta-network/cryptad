package network.crypta.platform.devtools;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import network.crypta.platform.appcatalog.AppCatalog;
import network.crypta.platform.appcatalog.AppCatalogParser;
import network.crypta.platform.appcatalog.AppCatalogSignature;
import network.crypta.platform.appcatalog.AppCatalogVerifier;
import network.crypta.platform.appdist.AppDistributionException;

/**
 * Validates the shared local inputs for offline and live catalog publication.
 *
 * <p>The publication commands deliberately treat local validation as a single reusable step:
 * normalize paths, reject symlinked or missing sidecars, require the canonical catalog and
 * signature filenames ({@code cryptad-app-catalog.properties} and {@code
 * cryptad-app-catalog.signature}), parse the catalog, structurally read the signature sidecar,
 * validate the public {@code crypta:USK@.../cryptad-app-catalog.properties} source, and compute
 * stable digests before any plan or live insertion summary is written. The returned snapshot
 * contains exact sidecar bytes for later signature verification, but never exposes local absolute
 * paths through report-rendering helpers.
 */
final class PublicationInputValidator {
  /** Utility class; validation is performed through static methods. */
  private PublicationInputValidator() {}

  /**
   * Validates one catalog publication request.
   *
   * @param catalogFile local catalog properties file
   * @param catalogSignatureFile local catalog signature sidecar
   * @param catalogSource public catalog source URI expected after publication
   * @param output report output path
   * @return normalized and parsed publication inputs
   * @throws IOException if catalog or signature bytes cannot be read
   */
  static ValidatedPublicationInputs validate(
      Path catalogFile, Path catalogSignatureFile, String catalogSource, Path output)
      throws IOException {
    Path normalizedCatalogFile = catalogFile.toAbsolutePath().normalize();
    Path normalizedSignatureFile = catalogSignatureFile.toAbsolutePath().normalize();
    Path normalizedOutput = output.toAbsolutePath().normalize();
    requireUskSource(catalogSource);
    requireReadable(normalizedCatalogFile, "catalog file");
    requireReadable(normalizedSignatureFile, "catalog signature file");
    requireCanonicalFileName(
        normalizedCatalogFile, AppCatalogSignature.CATALOG_FILE_NAME, "catalog file");
    requireCanonicalFileName(
        normalizedSignatureFile,
        AppCatalogSignature.SIGNATURE_FILE_NAME,
        "catalog signature sidecar");
    byte[] catalogBytes = Files.readAllBytes(normalizedCatalogFile);
    byte[] signatureBytes = Files.readAllBytes(normalizedSignatureFile);
    AppCatalog catalog = AppCatalogParser.parse(catalogBytes);
    AppCatalogSignature signature = AppCatalogVerifier.readSignature(signatureBytes);
    return ValidatedPublicationInputs.builder()
        .catalogFile(normalizedCatalogFile)
        .catalogSignatureFile(normalizedSignatureFile)
        .catalogSource(catalogSource.trim())
        .output(normalizedOutput)
        .catalogBytes(catalogBytes)
        .signatureBytes(signatureBytes)
        .catalog(catalog)
        .signature(signature)
        .catalogSha256(sha256Hex(catalogBytes))
        .signatureSha256(sha256Hex(signatureBytes))
        .build();
  }

  /**
   * Requires a concrete local file without following symlink indirection.
   *
   * <p>Publication evidence must describe the sidecar filenames only, but the live publisher still
   * reads bytes from local disk. Rejecting symlinks keeps the command tied to the operator-selected
   * sidecars and avoids surprising path traversal through a staging location.
   *
   * @param file normalized path to validate
   * @param label human-readable sidecar label for sanitized error messages
   * @throws AppDistributionException if the path is not a regular file
   */
  private static void requireReadable(Path file, String label) throws AppDistributionException {
    if (Files.isSymbolicLink(file) || !Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
      throw new AppDistributionException(label + " must be a regular file");
    }
  }

  /**
   * Enforces the catalog sidecar filenames expected by public USK consumers.
   *
   * @param file normalized path whose basename is checked
   * @param expected required basename
   * @param label human-readable sidecar label for sanitized error messages
   * @throws AppDistributionException if the basename would publish at a non-standard sibling path
   */
  private static void requireCanonicalFileName(Path file, String expected, String label)
      throws AppDistributionException {
    if (!expected.equals(file.getFileName().toString())) {
      throw new AppDistributionException(label + " must be " + expected);
    }
  }

  /**
   * Validates the public catalog source shape used by first-party live publication.
   *
   * <p>The signed catalog trust path expects a public {@code crypta:USK@...} source ending in the
   * catalog properties filename. Query strings and fragments are rejected so a companion signature
   * sidecar can be derived as a plain sibling file at the same USK path and edition.
   *
   * @param source operator-supplied public catalog source
   * @throws AppDistributionException if the source is not the canonical live USK catalog source
   */
  private static void requireUskSource(String source) throws AppDistributionException {
    String value = source == null ? "" : source.trim();
    if (!value.startsWith("crypta:USK@")
        || value.contains("?")
        || value.contains("#")
        || !value.endsWith("/" + AppCatalogSignature.CATALOG_FILE_NAME)) {
      throw new AppDistributionException(
          "publish-usk requires --catalog-source crypta:USK@.../cryptad-app-catalog.properties");
    }
  }

  /**
   * Computes the stable digest recorded in dry-run plans and live publication summaries.
   *
   * @param bytes sidecar bytes to digest
   * @return lowercase SHA-256 hex digest
   */
  private static String sha256Hex(byte[] bytes) {
    try {
      return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    } catch (NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 digest is unavailable", exception);
    }
  }
}

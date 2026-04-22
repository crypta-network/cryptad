package network.crypta.platform.appcatalog;

import java.util.Base64;
import java.util.Objects;
import network.crypta.platform.appdist.AppBundleSignature;

/**
 * Parsed or generated signature sidecar for a signed app catalog.
 *
 * <p>The signature authenticates the exact bytes of {@code cryptad-app-catalog.properties}. The
 * catalog verifier checks this sidecar before parsing catalog entries, so a rewrite of either the
 * entry metadata or the signer metadata fails before any artifact URL is trusted.
 *
 * <p>The sidecar format is intentionally small and deterministic. Version {@value
 * #SIGNATURE_VERSION} supports Ed25519 only, identifies the trusted public key by {@code keyId},
 * and requires the payload field to name the canonical catalog properties file. The record
 * validates base64 syntax but does not verify the signature value; {@link AppCatalogVerifier}
 * performs trust lookup and cryptographic verification against the exact catalog bytes.
 *
 * @param version signature schema version, currently {@code 1}
 * @param algorithm signature algorithm, currently JDK {@code Ed25519}
 * @param keyId stable trusted-key identifier used to select the public key
 * @param payload payload filename authenticated by the signature
 * @param valueBase64 base64-encoded signature bytes
 */
public record AppCatalogSignature(
    int version, String algorithm, String keyId, String payload, String valueBase64) {
  /**
   * Canonical catalog properties filename.
   *
   * <p>The signature sidecar must name this file as its payload so verifiers never need to infer or
   * accept alternate payload names.
   */
  public static final String CATALOG_FILE_NAME = "cryptad-app-catalog.properties";

  /**
   * Canonical catalog signature filename.
   *
   * <p>Catalog sources resolve this file as the sibling of {@link #CATALOG_FILE_NAME}.
   */
  public static final String SIGNATURE_FILE_NAME = "cryptad-app-catalog.signature";

  /**
   * Current catalog signature sidecar schema version.
   *
   * <p>Unsupported versions are rejected before key lookup or signature verification.
   */
  public static final int SIGNATURE_VERSION = 1;

  /**
   * Supported signature algorithm for catalog sidecars.
   *
   * <p>This matches signed app bundles so operators can reuse the same trusted-key configuration
   * for catalog and bundle verification.
   */
  public static final String SIGNATURE_ALGORITHM = AppBundleSignature.SIGNATURE_ALGORITHM;

  /**
   * Creates a validated catalog signature snapshot.
   *
   * <p>Validation is structural. It checks the sidecar schema version, supported algorithm,
   * non-blank key id, canonical payload filename, and base64 syntax. It intentionally does not
   * consult trusted keys or verify the signature bytes so parsing can remain separate from policy.
   *
   * @param version signature schema version, currently {@code 1}
   * @param algorithm signature algorithm, currently JDK {@code Ed25519}
   * @param keyId stable trusted-key identifier used to select the public key
   * @param payload payload filename authenticated by the signature
   * @param valueBase64 base64-encoded signature bytes
   * @throws AppCatalogException if the fields cannot describe a supported catalog signature
   */
  public AppCatalogSignature {
    if (version != SIGNATURE_VERSION) {
      throw AppCatalogSidecars.invalidSignature(
          "unsupported catalog.signature.version: " + version);
    }
    if (!SIGNATURE_ALGORITHM.equals(Objects.requireNonNull(algorithm, "algorithm"))) {
      throw AppCatalogSidecars.invalidSignature(
          "unsupported catalog.signature.algorithm: " + algorithm);
    }
    keyId =
        AppCatalogSidecars.requireNonBlankSingleLine(
            keyId, "catalog.signature.key.id", AppCatalogSidecars.INVALID_CATALOG_SIGNATURE);
    payload =
        AppCatalogSidecars.requireNonBlankSingleLine(
            payload, "catalog.signature.payload", AppCatalogSidecars.INVALID_CATALOG_SIGNATURE);
    if (!CATALOG_FILE_NAME.equals(payload)) {
      throw AppCatalogSidecars.invalidSignature(
          "unsupported catalog.signature.payload: " + payload);
    }
    valueBase64 =
        AppCatalogSidecars.requireNonBlankSingleLine(
            valueBase64,
            "catalog.signature.value.base64",
            AppCatalogSidecars.INVALID_CATALOG_SIGNATURE);
    try {
      Base64.getDecoder().decode(valueBase64);
    } catch (IllegalArgumentException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_SIGNATURE,
          "invalid catalog.signature.value.base64",
          exception);
    }
  }

  /**
   * Decodes the immutable base64 signature text.
   *
   * <p>A new array is returned on every call so verification code can pass the bytes to JDK crypto
   * APIs without exposing mutable state from the record.
   *
   * @return fresh byte array containing the signature value
   */
  public byte[] signatureBytes() {
    return Base64.getDecoder().decode(valueBase64);
  }
}

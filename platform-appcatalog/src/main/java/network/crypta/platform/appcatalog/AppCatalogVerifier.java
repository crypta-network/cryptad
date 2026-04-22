package network.crypta.platform.appcatalog;

import java.security.GeneralSecurityException;
import java.security.Signature;
import java.util.Map;
import java.util.Objects;
import network.crypta.platform.appdist.TrustedAppKey;
import network.crypta.platform.appdist.TrustedAppKeys;

/**
 * Verifies signed catalog sidecars against explicit trusted keys.
 *
 * <p>Verification deliberately follows the same order as signed app bundles: first the signature
 * over the exact catalog-properties bytes is checked, then the authenticated bytes are parsed into
 * a catalog model. This prevents a normalized or reparsed catalog from becoming the signed payload
 * and keeps remote catalog metadata fail-closed when sidecars are stale or tampered.
 *
 * <p>The verifier does not read files or fetch remote data. Callers pass the exact bytes retrieved
 * by {@link AppCatalogFetcher} or loaded from {@link AppCatalogSourceStore}. Trusted keys are
 * explicit inputs so runtime composition can choose whether catalog and bundle trust share the same
 * key set without introducing global mutable state.
 */
public final class AppCatalogVerifier {
  private AppCatalogVerifier() {}

  /**
   * Parses one catalog signature sidecar.
   *
   * <p>This method validates sidecar structure and supported signature metadata but does not verify
   * the signature value against catalog bytes. Malformed signature sidecars are always classified
   * as {@code invalid_catalog_signature}, even when the shared key/value parser detects the
   * low-level line-format problem.
   *
   * @param signatureBytes exact UTF-8 bytes read from {@code cryptad-app-catalog.signature}
   * @return parsed signature metadata
   * @throws AppCatalogException if the sidecar is malformed or unsupported
   */
  public static AppCatalogSignature readSignature(byte[] signatureBytes)
      throws AppCatalogException {
    Map<String, String> properties = parseSignatureSidecar(signatureBytes);
    String versionText = removeRequired(properties, "catalog.signature.version");
    String algorithm = removeRequired(properties, "catalog.signature.algorithm");
    String keyId = removeRequired(properties, "catalog.signature.key.id");
    String payload = removeRequired(properties, "catalog.signature.payload");
    String signatureValue = removeRequired(properties, "catalog.signature.value.base64");
    if (!properties.isEmpty()) {
      throw AppCatalogSidecars.invalidSignature(
          "unsupported catalog signature property: " + properties.keySet().iterator().next());
    }
    try {
      return new AppCatalogSignature(
          Integer.parseInt(versionText), algorithm, keyId, payload, signatureValue);
    } catch (NumberFormatException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_SIGNATURE,
          "invalid catalog.signature.version: " + versionText,
          exception);
    }
  }

  private static Map<String, String> parseSignatureSidecar(byte[] signatureBytes) {
    try {
      return AppCatalogSidecars.parseKeyValueSidecar(
          AppCatalogSidecars.utf8(signatureBytes), "catalog signature");
    } catch (AppCatalogException exception) {
      if (AppCatalogSidecars.INVALID_CATALOG_ENTRY.equals(exception.errorCode())) {
        throw new AppCatalogException(
            AppCatalogSidecars.INVALID_CATALOG_SIGNATURE, exception.getMessage(), exception);
      }
      throw exception;
    }
  }

  /**
   * Verifies a catalog and returns the authenticated parsed content.
   *
   * <p>The verifier reads the signature sidecar, selects the trusted public key by key id, checks
   * the algorithm match, verifies Ed25519 over {@code catalogBytes}, and only then parses catalog
   * entries. Unknown key ids, algorithm mismatches, and cryptographic failures all use the
   * signature error code because no catalog entry should be trusted until this method returns.
   *
   * @param catalogBytes exact bytes from {@code cryptad-app-catalog.properties}
   * @param signatureBytes exact bytes from {@code cryptad-app-catalog.signature}
   * @param trustedKeys explicit trusted Ed25519 public keys
   * @return authenticated catalog content in declared entry order
   * @throws AppCatalogException if signature, trust, or catalog parsing fails
   */
  public static AppCatalog verify(
      byte[] catalogBytes, byte[] signatureBytes, TrustedAppKeys trustedKeys)
      throws AppCatalogException {
    Objects.requireNonNull(catalogBytes, "catalogBytes");
    Objects.requireNonNull(signatureBytes, "signatureBytes");
    Objects.requireNonNull(trustedKeys, "trustedKeys");
    AppCatalogSignature signature = readSignature(signatureBytes);
    TrustedAppKey trustedKey =
        trustedKeys
            .find(signature.keyId())
            .orElseThrow(
                () ->
                    new AppCatalogException(
                        AppCatalogSidecars.INVALID_CATALOG_SIGNATURE,
                        "unknown trusted catalog key id: " + signature.keyId()));
    if (!signature.algorithm().equals(trustedKey.algorithm())) {
      throw AppCatalogSidecars.invalidSignature(
          "trusted key algorithm does not match catalog signature: " + signature.keyId());
    }
    verifySignature(catalogBytes, signature, trustedKey);
    return AppCatalogParser.parse(catalogBytes);
  }

  private static void verifySignature(
      byte[] catalogBytes, AppCatalogSignature signature, TrustedAppKey trustedKey) {
    try {
      Signature verifier = Signature.getInstance(signature.algorithm());
      verifier.initVerify(trustedKey.publicKey());
      verifier.update(catalogBytes);
      if (!verifier.verify(signature.signatureBytes())) {
        throw AppCatalogSidecars.invalidSignature("catalog signature does not match catalog bytes");
      }
    } catch (GeneralSecurityException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_SIGNATURE,
          "failed to verify catalog signature",
          exception);
    }
  }

  private static String removeRequired(Map<String, String> properties, String key) {
    String value = properties.remove(key);
    if (value == null) {
      throw AppCatalogSidecars.invalidSignature("missing " + key);
    }
    return value;
  }
}

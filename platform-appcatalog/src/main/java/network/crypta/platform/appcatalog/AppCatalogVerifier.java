package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import network.crypta.platform.appdist.TrustedAppKey;
import network.crypta.platform.appdist.TrustedAppKeyPolicy;
import network.crypta.platform.appdist.TrustedAppKeys;

/**
 * Verifies signed catalog sidecars against explicit trusted keys.
 *
 * <p>Verification deliberately follows the same order as signed app bundles: first the signature
 * over the exact catalog-properties bytes is checked, then the authenticated bytes are parsed into
 * a catalog model. This prevents a normalized or reparsed catalog from becoming the signed payload
 * and keeps remote catalog metadata fail-closed when sidecars are stale or tampered.
 *
 * <p>The primary verifier accepts exact bytes retrieved by {@link AppCatalogFetcher} or loaded from
 * {@link AppCatalogSourceStore}. A small path-based overload exists for CLI tooling that signs and
 * verifies local sidecars. Trusted keys are explicit inputs so runtime composition can choose
 * whether catalog and bundle trust share the same key set without introducing global mutable state.
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
    return verify(catalogBytes, signatureBytes, trustedKeys, null);
  }

  /**
   * Verifies an exact retained catalog under historical signing-key policy.
   *
   * <p>This path is restricted to stored catalog state, retained revision inspection, and explicit
   * rollback. Active, retiring, and retired keys may authenticate the exact retained bytes during
   * their declared support window; revoked or expired keys fail. Newly fetched catalog admission
   * must use {@link #verify(byte[], byte[], TrustedAppKeys)}.
   *
   * @param catalogBytes exact retained catalog-properties bytes
   * @param signatureBytes exact retained detached-signature bytes
   * @param trustedKeys explicit trusted Ed25519 public keys
   * @return authenticated retained catalog content
   * @throws AppCatalogException if signature, historical trust, or catalog parsing fails
   */
  public static AppCatalog verifyHistorical(
      byte[] catalogBytes, byte[] signatureBytes, TrustedAppKeys trustedKeys)
      throws AppCatalogException {
    return verify(catalogBytes, signatureBytes, trustedKeys, null, VerificationPurpose.HISTORICAL);
  }

  /** Verifies retained catalog bytes under an exact historical signer identity. */
  public static AppCatalog verifyHistorical(
      byte[] catalogBytes, byte[] signatureBytes, TrustedAppKeys trustedKeys, String expectedKeyId)
      throws AppCatalogException {
    return verify(
        catalogBytes, signatureBytes, trustedKeys, expectedKeyId, VerificationPurpose.HISTORICAL);
  }

  /**
   * Verifies a catalog under one explicitly declared trusted signing-key identity.
   *
   * <p>This overload is intended for release boundaries that have already frozen the expected key
   * id separately from the detached signature. It rejects a structurally valid signature made by
   * any other trusted key before checking the signature bytes, preventing a broad trusted-key
   * registry from weakening the release's exact signer binding.
   *
   * @param catalogBytes exact bytes from {@code cryptad-app-catalog.properties}
   * @param signatureBytes exact bytes from {@code cryptad-app-catalog.signature}
   * @param trustedKeys explicit trusted Ed25519 public keys
   * @param expectedKeyId exact key id declared by the release candidate
   * @return authenticated catalog content in declared entry order
   * @throws AppCatalogException if the signer identity, signature, trust, or catalog parsing fails
   */
  public static AppCatalog verify(
      byte[] catalogBytes, byte[] signatureBytes, TrustedAppKeys trustedKeys, String expectedKeyId)
      throws AppCatalogException {
    return verify(
        catalogBytes, signatureBytes, trustedKeys, expectedKeyId, VerificationPurpose.ROUTINE);
  }

  private static AppCatalog verify(
      byte[] catalogBytes,
      byte[] signatureBytes,
      TrustedAppKeys trustedKeys,
      String expectedKeyId,
      VerificationPurpose purpose)
      throws AppCatalogException {
    Objects.requireNonNull(catalogBytes, "catalogBytes");
    Objects.requireNonNull(signatureBytes, "signatureBytes");
    Objects.requireNonNull(trustedKeys, "trustedKeys");
    AppCatalogSignature signature = readSignature(signatureBytes);
    if (expectedKeyId != null && !signature.keyId().equals(expectedKeyId)) {
      throw AppCatalogSidecars.invalidSignature(
          "catalog signature key id does not match expected key id");
    }
    TrustedAppKeyPolicy trustedKeyPolicy =
        trustedKeys
            .findPolicy(signature.keyId())
            .orElseThrow(
                () ->
                    new AppCatalogException(
                        AppCatalogSidecars.INVALID_CATALOG_SIGNATURE,
                        "unknown trusted catalog key id: " + signature.keyId()));
    if (!allowsVerification(trustedKeyPolicy, purpose, Instant.now())) {
      throw AppCatalogSidecars.invalidSignature(
          "trusted catalog key is not authorized for "
              + purpose.label
              + " verification: "
              + signature.keyId());
    }
    TrustedAppKey trustedKey = trustedKeyPolicy.key();
    if (!signature.algorithm().equals(trustedKey.algorithm())) {
      throw AppCatalogSidecars.invalidSignature(
          "trusted key algorithm does not match catalog signature: " + signature.keyId());
    }
    verifySignature(catalogBytes, signature, trustedKey);
    return AppCatalogParser.parse(catalogBytes);
  }

  /**
   * Verifies a catalog properties file with its sibling signature sidecar.
   *
   * <p>This overload is intended for CLI and developer-tooling paths that already operate on local
   * files. It reads {@code catalogFile} as exact catalog bytes, reads {@code
   * cryptad-app-catalog.signature} from the same directory, and then delegates to {@link
   * #verify(byte[], byte[], TrustedAppKeys)} for signature and parser validation.
   *
   * @param catalogFile path to {@code cryptad-app-catalog.properties}
   * @param trustedKeys explicit trusted Ed25519 public keys
   * @return authenticated parsed catalog content
   * @throws IOException if either sidecar cannot be read
   * @throws AppCatalogException if signature, trust, or catalog parsing fails
   */
  public static AppCatalog verify(Path catalogFile, TrustedAppKeys trustedKeys) throws IOException {
    Path normalizedCatalogFile =
        Objects.requireNonNull(catalogFile, "catalogFile").toAbsolutePath().normalize();
    return verify(
        normalizedCatalogFile,
        normalizedCatalogFile.resolveSibling(AppCatalogSignature.SIGNATURE_FILE_NAME),
        trustedKeys,
        null);
  }

  /**
   * Verifies exact catalog and detached-signature files under a declared signing-key identity.
   *
   * <p>Release workflows use this overload because their authenticated candidate can give the
   * detached sidecar a public artifact filename that differs from the runtime source filename. Both
   * files are read as exact bounded byte sequences and the signature sidecar's key id must equal
   * {@code expectedKeyId}.
   *
   * @param catalogFile exact catalog-properties file
   * @param signatureFile exact detached signature sidecar
   * @param trustedKeys explicit trusted Ed25519 public keys
   * @param expectedKeyId exact key id declared by the release candidate
   * @return authenticated catalog content in declared entry order
   * @throws IOException if either sidecar cannot be read
   * @throws AppCatalogException if the signer identity, signature, trust, or catalog parsing fails
   */
  public static AppCatalog verify(
      Path catalogFile, Path signatureFile, TrustedAppKeys trustedKeys, String expectedKeyId)
      throws IOException {
    Path normalizedCatalogFile =
        Objects.requireNonNull(catalogFile, "catalogFile").toAbsolutePath().normalize();
    Path normalizedSignatureFile =
        Objects.requireNonNull(signatureFile, "signatureFile").toAbsolutePath().normalize();
    byte[] catalogBytes =
        AppCatalogSidecars.readRequiredBytes(
            normalizedCatalogFile,
            AppCatalogSidecars.MAX_CATALOG_BYTES,
            "catalog properties",
            AppCatalogSidecars.INVALID_CATALOG_ENTRY);
    byte[] signatureBytes =
        AppCatalogSidecars.readRequiredBytes(
            normalizedSignatureFile,
            AppCatalogSidecars.MAX_SIGNATURE_BYTES,
            "catalog signature",
            AppCatalogSidecars.INVALID_CATALOG_SIGNATURE);
    return verify(catalogBytes, signatureBytes, trustedKeys, expectedKeyId);
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

  private static boolean allowsVerification(
      TrustedAppKeyPolicy policy, VerificationPurpose purpose, Instant verifiedAt) {
    return purpose == VerificationPurpose.ROUTINE
        ? policy.allowsRoutineVerification(verifiedAt)
        : policy.allowsHistoricalVerification(verifiedAt);
  }

  private enum VerificationPurpose {
    ROUTINE("routine catalog"),
    HISTORICAL("historical catalog");

    private final String label;

    VerificationPurpose(String label) {
      this.label = label;
    }
  }
}

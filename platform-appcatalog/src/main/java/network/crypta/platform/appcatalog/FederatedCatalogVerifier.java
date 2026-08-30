package network.crypta.platform.appcatalog;

import java.util.Objects;
import network.crypta.platform.appdist.PublicKeyFingerprint;
import network.crypta.platform.appdist.TrustedAppKeyPolicy;
import network.crypta.platform.appdist.TrustedAppKeys;

/**
 * Verifies signed catalog bytes against an exact host-owned catalog trust binding.
 *
 * <p>This utility composes the existing catalog signature verifier with the node's local
 * catalog-ID, signer-fingerprint, lifecycle, and channel constraints. Routine verification accepts
 * only active bindings, while the historical path also permits suspended bindings for bounded
 * inspection and rollback. Neither path changes the trusted-key registry or derives trust from
 * catalog content.
 */
public final class FederatedCatalogVerifier {
  /** Prevents construction of this stateless verification utility. */
  private FederatedCatalogVerifier() {}

  /**
   * Verifies newly fetched bytes for refresh, install, or update.
   *
   * @param catalogBytes canonical signed catalog bytes
   * @param signatureBytes detached catalog signature sidecar
   * @param trustedKeys locally configured catalog public-key material
   * @param binding exact active local catalog authorization
   * @return parsed catalog after signature and local-scope verification
   */
  public static AppCatalog verifyRoutine(
      byte[] catalogBytes,
      byte[] signatureBytes,
      TrustedAppKeys trustedKeys,
      FederatedCatalogTrustBinding binding) {
    FederatedCatalogTrustBinding checkedBinding = Objects.requireNonNull(binding, "binding");
    if (checkedBinding.status() != FederatedCatalogTrustBinding.Status.ACTIVE) {
      throw invalid("catalog trust binding is not active");
    }
    return verify(catalogBytes, signatureBytes, trustedKeys, checkedBinding, false);
  }

  /**
   * Verifies exact retained bytes for local inspection or explicit rollback.
   *
   * <p>Suspension preserves bounded historical inspection. Revoked, removed, and pending bindings
   * fail closed even when the underlying key registry would otherwise allow historical use.
   *
   * @param catalogBytes exact retained catalog bytes
   * @param signatureBytes detached signature for the retained revision
   * @param trustedKeys locally configured catalog public-key material
   * @param binding exact local catalog authorization for the retained identity
   * @return parsed retained catalog after historical verification
   */
  public static AppCatalog verifyHistorical(
      byte[] catalogBytes,
      byte[] signatureBytes,
      TrustedAppKeys trustedKeys,
      FederatedCatalogTrustBinding binding) {
    FederatedCatalogTrustBinding checkedBinding = Objects.requireNonNull(binding, "binding");
    if (checkedBinding.status() != FederatedCatalogTrustBinding.Status.ACTIVE
        && checkedBinding.status() != FederatedCatalogTrustBinding.Status.SUSPENDED) {
      throw invalid("catalog trust binding does not permit historical verification");
    }
    return verify(catalogBytes, signatureBytes, trustedKeys, checkedBinding, true);
  }

  /**
   * Applies signer, catalog identity, signature, lifecycle, and channel authorization.
   *
   * @param catalogBytes canonical catalog bytes
   * @param signatureBytes detached catalog signature sidecar
   * @param trustedKeys locally configured catalog public-key material
   * @param binding exact local catalog authorization
   * @param historical whether to use bounded historical key verification
   * @return parsed and locally authorized catalog
   */
  private static AppCatalog verify(
      byte[] catalogBytes,
      byte[] signatureBytes,
      TrustedAppKeys trustedKeys,
      FederatedCatalogTrustBinding binding,
      boolean historical) {
    Objects.requireNonNull(trustedKeys, "trustedKeys");
    AppCatalogSignature signature = AppCatalogVerifier.readSignature(signatureBytes);
    String expectedFingerprint = binding.signerFingerprints().get(signature.keyId());
    if (expectedFingerprint == null) {
      throw invalid("catalog signer is not allowed by the local catalog binding");
    }
    TrustedAppKeyPolicy keyPolicy =
        trustedKeys
            .findPolicy(signature.keyId())
            .orElseThrow(() -> invalid("catalog signer key material is not locally available"));
    if (!expectedFingerprint.equals(PublicKeyFingerprint.sha256(keyPolicy.key().publicKey()))) {
      throw invalid("catalog signer fingerprint does not match the local catalog binding");
    }
    AppCatalog catalog =
        historical
            ? AppCatalogVerifier.verifyHistorical(
                catalogBytes, signatureBytes, trustedKeys, signature.keyId())
            : AppCatalogVerifier.verify(
                catalogBytes, signatureBytes, trustedKeys, signature.keyId());
    if (!catalog.catalogId().equals(binding.catalogId())) {
      throw invalid("authenticated catalog id does not match the local catalog binding");
    }
    boolean disallowedChannel =
        catalog.entries().stream()
            .map(entry -> entry.productionMetadata().channel())
            .anyMatch(channel -> !binding.allowedChannels().contains(channel));
    if (disallowedChannel) {
      throw invalid("catalog contains an app channel not allowed by the local catalog binding");
    }
    return catalog;
  }

  /**
   * Creates the stable signature-boundary failure used by federated verification.
   *
   * @param message bounded validation explanation
   * @return catalog exception carrying the stable invalid-signature code
   */
  private static AppCatalogException invalid(String message) {
    return new AppCatalogException(AppCatalogSidecars.INVALID_CATALOG_SIGNATURE, message);
  }
}

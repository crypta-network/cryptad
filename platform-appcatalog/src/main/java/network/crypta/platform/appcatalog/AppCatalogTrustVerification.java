package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.util.regex.Pattern;
import network.crypta.platform.appdist.TrustedAppKeys;

/**
 * Adapts catalog verification to legacy-compatible and federation-scoped trust modes.
 *
 * <p>Routine verification always authenticates the catalog signature and expected catalog ID. In
 * federation mode it additionally resolves the explicit local trust binding and requires its
 * current active signer and channel policy. Historical verification uses the corresponding bounded
 * lifecycle rules for retained revisions.
 *
 * <p>Stored-source checks keep a catalog tied to the stable binding identity recorded at admission.
 * Routine work also requires the current binding digest, while historical work permits policy
 * evolution without permitting the binding ID to move to another catalog. The adapter is stateless
 * and does not mutate trust policy, install keys, or infer authorization from catalog content.
 */
final class AppCatalogTrustVerification {
  /** Closed lowercase SHA-256 grammar used for stored policy digests. */
  private static final Pattern SHA256 = Pattern.compile("[0-9a-f]{64}");

  /** Prevents construction of this stateless verification utility. */
  private AppCatalogTrustVerification() {}

  /**
   * Verifies a catalog for routine refresh, install, or update work.
   *
   * @param catalogBytes exact catalog content bytes
   * @param signatureBytes detached catalog signature bytes
   * @param trustedKeys current catalog-signing key registry
   * @param expectedCatalogId expected authenticated catalog identity
   * @param trustStore optional local federated trust-binding store
   * @return authenticated catalog authorized for routine work
   * @throws IOException if local trust state cannot be read safely
   */
  static AppCatalog verifyRoutine(
      byte[] catalogBytes,
      byte[] signatureBytes,
      TrustedAppKeys trustedKeys,
      String expectedCatalogId,
      FileFederatedCatalogTrustStore trustStore)
      throws IOException {
    if (trustStore == null) {
      AppCatalog catalog = AppCatalogVerifier.verify(catalogBytes, signatureBytes, trustedKeys);
      requireExpectedCatalogId(catalog, expectedCatalogId);
      return catalog;
    }
    if (expectedCatalogId == null) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_SOURCE,
          "federated catalog admission requires an expected catalog id");
    }
    FederatedCatalogTrustBinding binding =
        trustStore
            .findByCatalogId(expectedCatalogId)
            .orElseThrow(
                () ->
                    new AppCatalogException(
                        AppCatalogSidecars.INVALID_CATALOG_SIGNATURE,
                        "no local trust binding exists for the expected catalog id"));
    return FederatedCatalogVerifier.verifyRoutine(
        catalogBytes, signatureBytes, trustedKeys, binding);
  }

  /**
   * Verifies a retained catalog revision under historical trust policy.
   *
   * @param catalogBytes exact retained catalog content bytes
   * @param signatureBytes detached retained signature bytes
   * @param trustedKeys current catalog-signing key registry
   * @param expectedCatalogId expected authenticated catalog identity
   * @param trustStore optional local federated trust-binding store
   * @return authenticated catalog authorized for historical inspection or rollback
   * @throws IOException if local trust state cannot be read safely
   */
  static AppCatalog verifyHistorical(
      byte[] catalogBytes,
      byte[] signatureBytes,
      TrustedAppKeys trustedKeys,
      String expectedCatalogId,
      FileFederatedCatalogTrustStore trustStore)
      throws IOException {
    if (trustStore == null) {
      AppCatalog catalog =
          AppCatalogVerifier.verifyHistorical(catalogBytes, signatureBytes, trustedKeys);
      requireExpectedCatalogId(catalog, expectedCatalogId);
      return catalog;
    }
    FederatedCatalogTrustBinding binding =
        trustStore
            .findByCatalogId(expectedCatalogId)
            .orElseThrow(
                () ->
                    new AppCatalogException(
                        AppCatalogSidecars.INVALID_CATALOG_SIGNATURE,
                        "no local trust binding exists for the stored catalog id"));
    return FederatedCatalogVerifier.verifyHistorical(
        catalogBytes, signatureBytes, trustedKeys, binding);
  }

  /**
   * Requires a stored source to match the exact current routine trust binding.
   *
   * @param stored stored catalog source being used for routine work
   * @param trustStore optional local federated trust-binding store
   * @throws IOException if local trust state cannot be read safely
   */
  static void requireStoredBinding(
      StoredCatalogSource stored, FileFederatedCatalogTrustStore trustStore) throws IOException {
    if (trustStore == null) {
      return;
    }
    String bindingId =
        stored
            .trustBindingId()
            .orElseThrow(
                () ->
                    new AppCatalogException(
                        AppCatalogSidecars.INVALID_CATALOG_SIGNATURE,
                        "stored catalog has no federated trust binding identity"));
    String bindingDigest =
        stored
            .trustBindingDigest()
            .orElseThrow(
                () ->
                    new AppCatalogException(
                        AppCatalogSidecars.INVALID_CATALOG_SIGNATURE,
                        "stored catalog has no federated trust binding digest"));
    FederatedCatalogTrustBinding current =
        trustStore
            .findByCatalogId(stored.catalogId())
            .orElseThrow(
                () ->
                    new AppCatalogException(
                        AppCatalogSidecars.INVALID_CATALOG_SIGNATURE,
                        "stored catalog local trust binding is unavailable"));
    if (!bindingId.equals(current.bindingId()) || !bindingDigest.equals(current.selfDigest())) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_SIGNATURE,
          "stored catalog local trust policy changed; explicit source re-approval is required");
    }
  }

  /**
   * Requires a stored source to retain its stable historical binding identity.
   *
   * @param stored stored catalog source containing admission provenance
   * @param trustStore optional local federated trust-binding store
   * @throws IOException if local trust state cannot be read safely
   */
  static void requireHistoricalStoredBinding(
      StoredCatalogSource stored, FileFederatedCatalogTrustStore trustStore) throws IOException {
    if (trustStore == null) {
      return;
    }
    String bindingId =
        stored
            .trustBindingId()
            .orElseThrow(
                () ->
                    new AppCatalogException(
                        AppCatalogSidecars.INVALID_CATALOG_SIGNATURE,
                        "stored catalog has no federated trust binding identity"));
    String bindingDigest =
        stored
            .trustBindingDigest()
            .orElseThrow(
                () ->
                    new AppCatalogException(
                        AppCatalogSidecars.INVALID_CATALOG_SIGNATURE,
                        "stored catalog has no federated trust binding digest"));
    if (!SHA256.matcher(bindingDigest).matches()) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_SIGNATURE,
          "stored catalog federated trust binding digest is malformed");
    }
    FederatedCatalogTrustBinding current =
        trustStore
            .findByCatalogId(stored.catalogId())
            .orElseThrow(
                () ->
                    new AppCatalogException(
                        AppCatalogSidecars.INVALID_CATALOG_SIGNATURE,
                        "stored catalog local trust binding is unavailable"));
    if (!bindingId.equals(current.bindingId())) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_SIGNATURE,
          "stored catalog local trust binding identity changed");
    }
  }

  /**
   * Requires the authenticated catalog identity to match an optional expected identity.
   *
   * @param catalog authenticated catalog returned by signature verification
   * @param expectedCatalogId optional expected catalog identifier
   */
  private static void requireExpectedCatalogId(AppCatalog catalog, String expectedCatalogId) {
    if (expectedCatalogId != null
        && !catalog.catalogId().equals(AppCatalog.normalizeCatalogId(expectedCatalogId))) {
      throw new AppCatalogException(
          AppCatalogSidecars.CATALOG_ID_MISMATCH,
          "authenticated catalog id does not match the expected catalog id");
    }
  }
}

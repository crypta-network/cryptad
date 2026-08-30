package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import network.crypta.platform.appdist.PublicKeyFingerprint;
import network.crypta.platform.appdist.TrustedAppKeys;

/**
 * Resolves and reauthorizes the exact catalog identity stored with an installed app.
 *
 * <p>This component separates provenance-specific work from catalog source orchestration. It
 * authenticates the current source before creating an origin, derives the catalog signer
 * fingerprint from the role-specific key registry, and searches current plus retained revisions
 * when an explicit rollback needs historical authorization. Historical matching remains exact: the
 * stable local binding identity, catalog revision, signer key and fingerprint, app version, and
 * bundle digest must all agree before a catalog entry is returned.
 *
 * <p>Instances are immutable. Callers provide synchronization around source and trust-store access
 * so a retained authorization can be held through the subsequent AppHost mutation.
 */
final class AppCatalogOriginAuthority {
  /** Stable sentinel used when an origin was created through legacy global catalog trust. */
  private static final String LEGACY_TRUST_BINDING_ID = "legacy-global-catalog-trust";

  /** Persists current and retained authenticated catalog revisions. */
  private final AppCatalogSourceStore sourceStore;

  /** Supplies the current catalog-signing key registry for each authorization. */
  private final AppCatalogManager.TrustedKeyProvider trustedCatalogKeyProvider;

  /** Optional local federation binding authority; {@code null} retains legacy behavior. */
  private final FileFederatedCatalogTrustStore federatedTrustStore;

  /**
   * Creates an origin authority over one catalog store and signing-key provider.
   *
   * @param sourceStore source and retained-revision persistence to inspect
   * @param trustedCatalogKeyProvider current catalog-signing key provider
   * @param federatedTrustStore optional local catalog binding authority
   */
  AppCatalogOriginAuthority(
      AppCatalogSourceStore sourceStore,
      AppCatalogManager.TrustedKeyProvider trustedCatalogKeyProvider,
      FileFederatedCatalogTrustStore federatedTrustStore) {
    this.sourceStore = Objects.requireNonNull(sourceStore, "sourceStore");
    this.trustedCatalogKeyProvider =
        Objects.requireNonNull(trustedCatalogKeyProvider, "trustedCatalogKeyProvider");
    this.federatedTrustStore = federatedTrustStore;
  }

  /**
   * Authenticates one current source and builds its exact origin context.
   *
   * @param normalizedCatalogId normalized catalog identity to read
   * @return exact signer, revision, and local-policy provenance
   * @throws IOException if the source, keys, or local trust policy cannot be read
   */
  AppCatalogOriginContext originContext(String normalizedCatalogId) throws IOException {
    StoredCatalogSource stored = sourceStore.read(normalizedCatalogId);
    AppCatalogTrustVerification.requireStoredBinding(stored, federatedTrustStore);
    TrustedAppKeys trustedKeys = trustedCatalogKeyProvider.trustedKeys();
    AppCatalogTrustVerification.verifyRoutine(
        stored.fetchedCatalog().catalogBytes(),
        stored.fetchedCatalog().signatureBytes(),
        trustedKeys,
        normalizedCatalogId,
        federatedTrustStore);
    return originContext(stored, trustedKeys);
  }

  /**
   * Builds an origin from an already authenticated stored source and key snapshot.
   *
   * @param stored exact stored source used by the caller's catalog verification
   * @param trustedKeys catalog-signing keys used for that verification
   * @return exact legacy or federation-scoped origin context
   * @throws IOException if the local federation binding cannot be read
   */
  AppCatalogOriginContext originContext(StoredCatalogSource stored, TrustedAppKeys trustedKeys)
      throws IOException {
    String catalogId = stored.catalogId();
    String keyId =
        AppCatalogVerifier.readSignature(stored.fetchedCatalog().signatureBytes()).keyId();
    String keyFingerprint = signerFingerprint(trustedKeys, keyId);
    String revisionDigest =
        AppCatalogRevisions.digestDirectoryName(
            AppCatalogRevisions.catalogContentDigest(stored.fetchedCatalog()));
    if (federatedTrustStore == null) {
      return legacyOrigin(catalogId, keyId, keyFingerprint, revisionDigest);
    }
    return federatedOrigin(catalogId, keyId, keyFingerprint, revisionDigest);
  }

  /**
   * Reauthorizes an exact installed origin against current historical catalog policy.
   *
   * @param captured origin retained with the installed rollback slot
   * @param appId exact app namespace to locate
   * @param appVersion exact retained app version
   * @param bundleSha256 exact retained bundle digest
   * @return authenticated historical catalog entry matching every retained identity
   * @throws IOException if source, revision, key, or trust-policy data cannot be read
   */
  AppCatalogEntry authorizeHistoricalAppOrigin(
      AppCatalogOriginContext captured, String appId, String appVersion, String bundleSha256)
      throws IOException {
    AppCatalogOriginContext checked = Objects.requireNonNull(captured, "captured");
    requireFederatedOrigin(checked);
    String catalogId = AppCatalogManager.normalizeCatalogIdForLookup(checked.catalogId());
    StoredCatalogSource stored = sourceStore.read(catalogId);
    AppCatalogTrustVerification.requireHistoricalStoredBinding(stored, federatedTrustStore);
    requireMatchingBinding(checked, stored);

    TrustedAppKeys trustedKeys = trustedCatalogKeyProvider.trustedKeys();
    for (FetchedCatalog fetched : revisions(stored, catalogId)) {
      AppCatalogEntry entry =
          matchingHistoricalEntry(
              checked, fetched, trustedKeys, catalogId, appId, appVersion, bundleSha256);
      if (entry != null) {
        return entry;
      }
    }
    throw invalidOrigin(
        "no authenticated retained catalog revision matches the installed rollback origin");
  }

  /**
   * Builds the explicitly unscoped provenance used by compatible legacy catalog paths.
   *
   * @param catalogId normalized authenticated catalog identifier
   * @param keyId verified catalog-signature key identifier
   * @param keyFingerprint canonical catalog signer fingerprint
   * @param revisionDigest exact authenticated catalog revision digest
   * @return unscoped legacy origin context
   */
  private AppCatalogOriginContext legacyOrigin(
      String catalogId, String keyId, String keyFingerprint, String revisionDigest) {
    return new AppCatalogOriginContext(
        catalogId,
        keyId,
        keyFingerprint,
        revisionDigest,
        LEGACY_TRUST_BINDING_ID,
        "",
        "",
        "",
        false);
  }

  /**
   * Builds provenance bound to the current exact local catalog trust record.
   *
   * @param catalogId normalized authenticated catalog identifier
   * @param keyId verified catalog-signature key identifier
   * @param keyFingerprint canonical catalog signer fingerprint
   * @param revisionDigest exact authenticated catalog revision digest
   * @return federation-scoped origin context bound to current policy
   * @throws IOException if the local trust binding cannot be read
   */
  private AppCatalogOriginContext federatedOrigin(
      String catalogId, String keyId, String keyFingerprint, String revisionDigest)
      throws IOException {
    FederatedCatalogTrustBinding binding =
        federatedTrustStore.findByCatalogId(catalogId).orElseThrow();
    return new AppCatalogOriginContext(
        catalogId,
        keyId,
        keyFingerprint,
        revisionDigest,
        binding.bindingId(),
        binding.selfDigest(),
        binding.publisherPolicyDigest().orElse(""),
        binding.reviewerPolicyDigest().orElse(""),
        true);
  }

  /**
   * Rejects historical authorization when no federation-scoped origin can be enforced.
   *
   * @param captured installed origin presented for historical authorization
   */
  private void requireFederatedOrigin(AppCatalogOriginContext captured) {
    if (!captured.federationScoped() || federatedTrustStore == null) {
      throw invalidOrigin("historical app origin is not federation scoped");
    }
  }

  /**
   * Requires the stored source to retain the origin's stable local binding identity.
   *
   * @param captured installed origin presented for historical authorization
   * @param stored current stored source for the same catalog
   */
  private static void requireMatchingBinding(
      AppCatalogOriginContext captured, StoredCatalogSource stored) {
    if (stored.trustBindingId().filter(captured.trustBindingId()::equals).isEmpty()) {
      throw invalidOrigin(
          "installed origin does not match the stable catalog trust binding identity");
    }
  }

  /**
   * Returns the current revision followed by every separately retained historical revision.
   *
   * @param stored current authenticated stored source
   * @param catalogId normalized catalog identifier
   * @return current and retained revisions in deterministic storage order
   * @throws IOException if retained revision metadata or bytes cannot be read
   */
  private List<FetchedCatalog> revisions(StoredCatalogSource stored, String catalogId)
      throws IOException {
    List<FetchedCatalog> revisions = new ArrayList<>();
    revisions.add(stored.fetchedCatalog());
    String currentDigest = AppCatalogRevisions.catalogDigest(stored.fetchedCatalog());
    for (AppCatalogVerifiedRevision revision :
        sourceStore.listRevisions(catalogId, currentDigest)) {
      if (!revision.current()) {
        revisions.add(sourceStore.readRevision(catalogId, revision.revisionDigest()));
      }
    }
    return revisions;
  }

  /**
   * Returns the exact matching app entry, or {@code null} when this revision is not the origin.
   *
   * @param captured exact installed origin being authorized
   * @param fetched retained signed catalog revision to inspect
   * @param trustedKeys current catalog-signing key registry
   * @param catalogId normalized catalog identifier
   * @param appId exact application identifier to locate
   * @param appVersion exact retained application version
   * @param bundleSha256 exact retained bundle digest
   * @return matching authenticated entry, or {@code null} for a different revision
   * @throws IOException if historical local trust policy cannot be read
   */
  private AppCatalogEntry matchingHistoricalEntry(
      AppCatalogOriginContext captured,
      FetchedCatalog fetched,
      TrustedAppKeys trustedKeys,
      String catalogId,
      String appId,
      String appVersion,
      String bundleSha256)
      throws IOException {
    AppCatalogSignature signature = AppCatalogVerifier.readSignature(fetched.signatureBytes());
    if (!matchesCapturedAuthority(captured, fetched, trustedKeys, signature)) {
      return null;
    }
    AppCatalog catalog =
        AppCatalogTrustVerification.verifyHistorical(
            fetched.catalogBytes(),
            fetched.signatureBytes(),
            trustedKeys,
            catalogId,
            federatedTrustStore);
    return catalog
        .entry(appId)
        .filter(entry -> entry.version().equals(appVersion))
        .filter(entry -> entry.bundleSha256().equals(bundleSha256))
        .orElse(null);
  }

  /**
   * Compares one fetched revision with the captured revision and catalog signer identities.
   *
   * @param captured exact installed origin being authorized
   * @param fetched retained signed catalog revision
   * @param trustedKeys current catalog-signing key registry
   * @param signature parsed signature sidecar for the retained revision
   * @return {@code true} when revision and signer identities match exactly
   */
  private static boolean matchesCapturedAuthority(
      AppCatalogOriginContext captured,
      FetchedCatalog fetched,
      TrustedAppKeys trustedKeys,
      AppCatalogSignature signature) {
    String contentDigest =
        AppCatalogRevisions.digestDirectoryName(AppCatalogRevisions.catalogContentDigest(fetched));
    return captured.catalogRevisionDigestSha256().equals(contentDigest)
        && captured.catalogSignerKeyId().equals(signature.keyId())
        && captured
            .catalogSignerFingerprintSha256()
            .equals(signerFingerprint(trustedKeys, signature.keyId()));
  }

  /**
   * Returns the canonical fingerprint for a known key ID, or an empty value when unknown.
   *
   * @param trustedKeys current catalog-signing key registry
   * @param keyId exact signing-key identifier to resolve
   * @return canonical public-key fingerprint, or an empty value when unknown
   */
  private static String signerFingerprint(TrustedAppKeys trustedKeys, String keyId) {
    return trustedKeys
        .findPolicy(keyId)
        .map(policy -> PublicKeyFingerprint.sha256(policy.key().publicKey()))
        .orElse("");
  }

  /**
   * Creates the stable catalog-signature failure used for origin authorization errors.
   *
   * @param message bounded origin-validation failure message
   * @return catalog exception with the stable invalid-signature code
   */
  private static AppCatalogException invalidOrigin(String message) {
    return new AppCatalogException(AppCatalogSidecars.INVALID_CATALOG_SIGNATURE, message);
  }
}

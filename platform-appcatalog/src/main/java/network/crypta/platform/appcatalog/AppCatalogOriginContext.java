package network.crypta.platform.appcatalog;

/**
 * Public, path-free catalog authority fields used for host-owned install provenance.
 *
 * <p>The installation planner captures this context only after catalog signature and local binding
 * verification. It contains public identities and digests rather than source URIs, paths, catalog
 * bodies, credentials, or other discovery state.
 *
 * <p>Callers carry the immutable value from plan preparation through retained-plan revalidation and
 * into {@code InstalledAppOrigin}. A federation-scoped context commits to the exact local catalog,
 * publisher, and reviewer policies that authorized the bundle. Compatibility contexts are
 * explicitly marked unscoped and cannot satisfy federation completion. The record performs no key
 * lookup or policy evaluation itself; {@link AppCatalogManager} creates it from already
 * authenticated state. Its components are immutable strings and a flag, so sharing the value across
 * lifecycle operations does not require additional synchronization.
 *
 * @param catalogId exact authenticated catalog identifier
 * @param catalogSignerKeyId catalog signature key identifier used for verification
 * @param catalogSignerFingerprintSha256 canonical catalog signing-key fingerprint
 * @param catalogRevisionDigestSha256 authenticated catalog revision subject digest
 * @param trustBindingId local trust binding that authorized the catalog
 * @param trustBindingDigestSha256 exact digest of the authorizing trust binding
 * @param publisherPolicyDigestSha256 exact scoped publisher-policy digest
 * @param reviewerPolicyDigestSha256 exact scoped reviewer-policy digest
 * @param federationScoped whether all fields came from explicit federated policy
 */
public record AppCatalogOriginContext(
    String catalogId,
    String catalogSignerKeyId,
    String catalogSignerFingerprintSha256,
    String catalogRevisionDigestSha256,
    String trustBindingId,
    String trustBindingDigestSha256,
    String publisherPolicyDigestSha256,
    String reviewerPolicyDigestSha256,
    boolean federationScoped) {}

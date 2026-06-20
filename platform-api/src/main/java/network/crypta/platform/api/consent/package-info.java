/**
 * Operator consent previews, decisions, and audit records for material app-platform mutations.
 *
 * <p>The consent package keeps install, update, service-grant, migration, and catalog-risk review
 * data as path-free JSON-compatible snapshots. Mutation routes approve a specific snapshot digest
 * instead of accepting open-ended acknowledgement flags, while existing app-platform services keep
 * ownership of catalog verification, app replacement, app-data migration, and service-grant
 * persistence.
 *
 * <p>The package is deliberately small and policy focused. Snapshot builders normalize catalog,
 * update, review-receipt, security-advisory, permission-delta, API-stability, service-dependency,
 * and migration-plan details into redacted {@link
 * network.crypta.platform.api.consent.ConsentSection} values. {@link
 * network.crypta.platform.api.consent.ConsentSnapshotDigest} then canonicalizes those sections so
 * approvals are invalidated by material drift, including changed advisories, review evidence,
 * bundle fingerprints, grant dependencies, or schema migration details.
 *
 * <p>Consent requests and decisions are host-local coordination records, not durable app-platform
 * authority. They expire quickly, approvals are consumed by the protected mutation path, and
 * blocking snapshots cannot be approved. The audit store records redacted decisions and expiry
 * events for operator accountability without exposing raw app data, local filesystem paths, service
 * secrets, private catalog URIs, or full catalog payloads.
 */
package network.crypta.platform.api.consent;

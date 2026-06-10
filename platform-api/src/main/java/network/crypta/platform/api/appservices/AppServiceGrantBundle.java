package network.crypta.platform.api.appservices;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;

/**
 * Durable operator-review object grouping declared service dependencies for one consumer app.
 *
 * <p>A bundle captures the set of dependency aliases that an operator reviewed together. It stores
 * a safe fingerprint of each dependency's signed manifest metadata so approval and renewal can
 * reject manifest drift instead of silently granting a different provider, service, scope, context,
 * purpose, feature label, or expiry policy. The record also keeps the grant ids created or reused
 * by approval so effective bundle status can follow later revocation, expiry, or descriptor
 * revalidation.
 *
 * <p>Bundle ids are stable record identifiers, not bearer secrets. Public JSON contains normalized
 * app ids, aliases, timestamps, dependency summaries, and grant ids only. It does not include raw
 * service request bodies, subject URIs, provider process state, tokens, local paths, private insert
 * URIs, or raw Trust Graph data.
 *
 * @param bundleId stable local bundle record id, never a service credential
 * @param consumerAppId normalized app id for the consumer whose dependencies are reviewed
 * @param bundleAlias optional manifest bundle alias used to select dependency groups
 * @param dependencyAliases normalized request aliases included in this review object
 * @param dependencyFingerprints safe SHA-256 fingerprints of reviewed dependency metadata
 * @param includeOptional whether optional dependencies were included when the bundle was requested
 * @param purpose bounded operator-facing review purpose shown with the bundle
 * @param status persisted lifecycle status before effective-status revalidation
 * @param createdAt instant when the bundle record was first created
 * @param updatedAt instant when the bundle record was last changed
 * @param approvedAt instant when the operator last approved the bundle, if any
 * @param rejectedAt instant when the operator rejected the bundle, if any
 * @param expiresAt earliest expiry time among grants approved through this bundle
 * @param renewedAt instant when the operator last renewed or revalidated the bundle
 * @param grantIds normalized grant ids created or reused by bundle approval
 */
public record AppServiceGrantBundle(
    String bundleId,
    String consumerAppId,
    String bundleAlias,
    List<String> dependencyAliases,
    List<String> dependencyFingerprints,
    boolean includeOptional,
    String purpose,
    AppServiceGrantBundleStatus status,
    Instant createdAt,
    Instant updatedAt,
    Instant approvedAt,
    Instant rejectedAt,
    Instant expiresAt,
    Instant renewedAt,
    List<String> grantIds) {
  /**
   * Creates a normalized grant-bundle record.
   *
   * <p>The constructor normalizes ids and aliases, validates optional dependency fingerprints, and
   * redacts unsafe purpose text before the bundle can be written to disk or returned through the
   * Platform API. Fingerprints may be absent for legacy records; when present, the count must match
   * dependency aliases so approval can compare one reviewed snapshot per dependency.
   *
   * @throws IllegalArgumentException when ids, aliases, fingerprints, or purpose text are malformed
   * @throws NullPointerException when required timestamps, status, or grant id lists are absent
   */
  public AppServiceGrantBundle {
    bundleId = AppServiceManifestParser.normalizeBundleId(bundleId);
    consumerAppId = AppServiceManifestParser.normalizeAppId(consumerAppId);
    bundleAlias = bundleAlias == null ? null : AppServiceManifestParser.normalizeAlias(bundleAlias);
    dependencyAliases =
        AppServiceManifestParser.normalizeAliases("dependencyAliases", dependencyAliases);
    dependencyFingerprints = normalizeDependencyFingerprints(dependencyFingerprints);
    if (!dependencyFingerprints.isEmpty()
        && dependencyFingerprints.size() != dependencyAliases.size()) {
      throw new IllegalArgumentException("dependency fingerprint count must match aliases");
    }
    purpose = AppServiceManifestParser.requiredPurposeText(purpose);
    java.util.Objects.requireNonNull(status, "status");
    java.util.Objects.requireNonNull(createdAt, "createdAt");
    java.util.Objects.requireNonNull(updatedAt, "updatedAt");
    grantIds =
        grantIds.stream().map(AppServiceManifestParser::normalizeGrantId).distinct().toList();
  }

  /**
   * Returns a status-updated bundle with preserved dependency metadata.
   *
   * <p>The coordinator uses this helper for approval, rejection, renewal, and test fixtures. It
   * does not recalculate dependency fingerprints or mutate this record. Callers pass the new grant
   * id membership explicitly so failed approval paths can avoid partially activating grants.
   *
   * @param newStatus persisted lifecycle status to store on the returned bundle
   * @param now timestamp to use as the returned bundle's updated time
   * @param newApprovedAt approval timestamp to expose, or {@code null} when not approved
   * @param newRejectedAt rejection timestamp to expose, or {@code null} when not rejected
   * @param newExpiresAt effective bundle expiry derived from approved grants
   * @param newRenewedAt renewal timestamp to expose, or {@code null} when not renewed
   * @param newGrantIds grant ids that belong to the updated bundle status
   * @return new immutable bundle record with updated lifecycle fields
   */
  AppServiceGrantBundle withStatus(
      AppServiceGrantBundleStatus newStatus,
      Instant now,
      Instant newApprovedAt,
      Instant newRejectedAt,
      Instant newExpiresAt,
      Instant newRenewedAt,
      List<String> newGrantIds) {
    return new AppServiceGrantBundle(
        bundleId,
        consumerAppId,
        bundleAlias,
        dependencyAliases,
        dependencyFingerprints,
        includeOptional,
        purpose,
        newStatus,
        createdAt,
        now,
        newApprovedAt,
        newRejectedAt,
        newExpiresAt,
        newRenewedAt,
        newGrantIds);
  }

  /**
   * Returns deterministic public JSON using this bundle's persisted status.
   *
   * <p>Use this overload when the stored status is already the correct caller-visible value, such
   * as for pending or rejected bundles. Approved bundles usually go through the effective-status
   * overload so expired grants or descriptor drift can be shown without rewriting the record.
   *
   * @param dependencies already resolved dependency summaries safe for public API output
   * @return ordered JSON-compatible map for Web Shell, SDK, and release evidence
   */
  public java.util.Map<String, Object> toJson(List<java.util.Map<String, Object>> dependencies) {
    return toJson(status, dependencies);
  }

  /**
   * Returns deterministic public JSON with an effective status override.
   *
   * <p>The coordinator supplies the effective status after checking grant ids, grant expiry, grant
   * revalidation state, and current dependency fingerprints. The serialized body keeps persisted
   * lifecycle timestamps alongside that computed status so operators can see when approval happened
   * and why renewal may be needed.
   *
   * @param effectiveStatus caller-visible status after current grant and descriptor checks
   * @param dependencies already resolved dependency summaries safe for public API output
   * @return ordered JSON-compatible map with no raw request bodies or provider-private data
   */
  public java.util.Map<String, Object> toJson(
      AppServiceGrantBundleStatus effectiveStatus,
      List<java.util.Map<String, Object>> dependencies) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(14);
    json.put("bundleId", bundleId);
    json.put("consumerAppId", consumerAppId);
    json.put("bundleAlias", bundleAlias);
    json.put("status", effectiveStatus.jsonValue());
    json.put("createdAt", createdAt.toString());
    json.put("updatedAt", updatedAt.toString());
    json.put("approvedAt", approvedAt == null ? null : approvedAt.toString());
    json.put("rejectedAt", rejectedAt == null ? null : rejectedAt.toString());
    json.put("expiresAt", expiresAt == null ? null : expiresAt.toString());
    json.put("renewedAt", renewedAt == null ? null : renewedAt.toString());
    json.put("purpose", purpose);
    json.put("includeOptional", includeOptional);
    json.put("dependencies", dependencies);
    json.put("grantIds", grantIds);
    return json;
  }

  /**
   * Normalizes the dependency snapshot fingerprints stored with a bundle review.
   *
   * <p>The coordinator uses these values to reject approval or renewal when the consumer manifest
   * changed after the operator reviewed the bundle. Returning a normalized immutable list keeps the
   * durable bundle record deterministic and prevents a caller from mutating the review snapshot
   * after construction.
   *
   * @param fingerprints approval-time dependency fingerprints, or {@code null} for legacy records
   * @return immutable ordered list of normalized fingerprint tokens
   */
  private static List<String> normalizeDependencyFingerprints(List<String> fingerprints) {
    if (fingerprints == null || fingerprints.isEmpty()) {
      return List.of();
    }
    return fingerprints.stream()
        .map(AppServiceGrantBundle::normalizeDependencyFingerprint)
        .toList();
  }

  /**
   * Validates and normalizes one dependency snapshot fingerprint.
   *
   * <p>Only the safe {@code sha256:} digest token is persisted. The fingerprint never contains raw
   * request bodies, paths, provider runtime data, or Trust Graph statements, which keeps bundle
   * records safe to serialize in operator-facing API responses.
   *
   * @param value raw fingerprint token from bundle construction or durable storage
   * @return lower-case SHA-256 fingerprint token
   * @throws IllegalArgumentException when the value is missing or malformed
   */
  private static String normalizeDependencyFingerprint(String value) {
    String normalized =
        AppServiceManifestParser.requiredText("dependencyFingerprint", value, 71)
            .toLowerCase(Locale.ROOT);
    if (!normalized.matches("sha256:[0-9a-f]{64}")) {
      throw new IllegalArgumentException("dependency fingerprint is malformed");
    }
    return normalized;
  }
}

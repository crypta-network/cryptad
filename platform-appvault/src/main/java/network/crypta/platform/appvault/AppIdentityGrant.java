package network.crypta.platform.appvault;

import java.time.Instant;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import org.jetbrains.annotations.NotNull;

/**
 * App-id-bound grant that authorizes one app to see or use one vault identity.
 *
 * <p>Grant records are the durable authorization layer between an identity and an app. The vault
 * never treats possession of an identity id as permission to use it; callers must have an active
 * grant whose app id matches the authenticated principal and whose scope matches the requested
 * operation. Revocation and app-update cleanup therefore work by changing or narrowing these
 * records rather than by changing app manifests alone.
 *
 * <p>The record stores only management metadata. It does not contain private key bytes, secret
 * values, process tokens, browser-session tokens, or local vault paths. The grant id is redacted
 * from {@link #toString()} because it is a durable management handle.
 *
 * @param grantId durable grant identifier used by operator management routes
 * @param identityId identity authorized by this grant
 * @param appId app id that may exercise the grant
 * @param scopes non-empty set of operations covered by the grant
 * @param status lifecycle state used by authorization and management views
 * @param createdAt creation timestamp for audit and retention decisions
 * @param updatedAt most recent grant metadata transition timestamp
 * @param expiresAt optional instant after which the grant no longer authorizes use
 * @param grantedBy optional operator or automation label that created the grant
 * @param reason optional operator-visible reason for the grant
 * @param sourceReviewReceiptId optional trusted review receipt associated with the grant
 */
public record AppIdentityGrant(
    String grantId,
    String identityId,
    String appId,
    Set<AppIdentityGrantScope> scopes,
    AppIdentityGrantStatus status,
    Instant createdAt,
    Instant updatedAt,
    Instant expiresAt,
    String grantedBy,
    String reason,
    String sourceReviewReceiptId) {
  /**
   * Creates a validated identity grant.
   *
   * <p>Identifiers are normalized to path-safe vault ids, scopes are copied into sorted immutable
   * form, and blank operator metadata is normalized to {@code null}. The constructor rejects empty
   * scope sets because a grant with no scopes cannot express an auditable authorization decision.
   */
  public AppIdentityGrant {
    grantId = AppVaultPaths.normalizeGrantId(grantId);
    identityId = AppVaultPaths.normalizeIdentityId(identityId);
    appId = AppVaultPaths.normalizeAppId(appId);
    scopes = Set.copyOf(new TreeSet<>(Objects.requireNonNull(scopes, "scopes")));
    if (scopes.isEmpty()) {
      throw new IllegalArgumentException("grant scopes must not be empty");
    }
    Objects.requireNonNull(status, "status");
    Objects.requireNonNull(createdAt, "createdAt");
    Objects.requireNonNull(updatedAt, "updatedAt");
    grantedBy = blankToNull(grantedBy);
    reason = blankToNull(reason);
    sourceReviewReceiptId = blankToNull(sourceReviewReceiptId);
  }

  /**
   * Returns whether this grant can authorize use at the supplied instant.
   *
   * <p>A grant is usable only while its status is {@link AppIdentityGrantStatus#ACTIVE} and its
   * optional expiry is still in the future. Callers pass a single timestamp into a batch of grant
   * checks so all candidates are evaluated against the same view of time.
   *
   * @param now current time used for the expiry comparison
   * @return {@code true} when the grant is active and not expired
   */
  public boolean activeAt(Instant now) {
    Objects.requireNonNull(now, "now");
    return status == AppIdentityGrantStatus.ACTIVE && (expiresAt == null || expiresAt.isAfter(now));
  }

  /**
   * Returns this grant with a different status and updated timestamp.
   *
   * <p>The method preserves identity id, app id, scopes, expiry, and operator metadata. It is used
   * for operator revocation, update-driven inactivation, and explicit status changes while keeping
   * the record immutable.
   *
   * @param nextStatus new grant status to persist
   * @param updatedAt timestamp for the status transition
   * @return updated immutable grant record with the requested status
   */
  public AppIdentityGrant withStatus(AppIdentityGrantStatus nextStatus, Instant updatedAt) {
    return new AppIdentityGrant(
        grantId,
        identityId,
        appId,
        scopes,
        nextStatus,
        createdAt,
        updatedAt,
        expiresAt,
        grantedBy,
        reason,
        sourceReviewReceiptId);
  }

  /**
   * Returns this grant with a narrowed scope set and updated timestamp.
   *
   * <p>Scope narrowing is used when an app update keeps some vault permissions but drops others.
   * The grant remains active for scopes that the new manifest still declares instead of becoming
   * entirely inactive.
   *
   * @param nextScopes replacement non-empty grant scopes
   * @param updatedAt timestamp for the scope transition
   * @return updated immutable grant record with the replacement scopes
   */
  public AppIdentityGrant withScopes(Set<AppIdentityGrantScope> nextScopes, Instant updatedAt) {
    return new AppIdentityGrant(
        grantId,
        identityId,
        appId,
        nextScopes,
        status,
        createdAt,
        updatedAt,
        expiresAt,
        grantedBy,
        reason,
        sourceReviewReceiptId);
  }

  @Override
  public @NotNull String toString() {
    return "AppIdentityGrant[grantId=<redacted>, identityId="
        + identityId
        + ", appId="
        + appId
        + ", scopes="
        + scopes
        + ", status="
        + status.jsonValue()
        + ", expiresAt="
        + expiresAt
        + "]";
  }

  private static String blankToNull(String value) {
    if (value == null || value.isBlank()) {
      return null;
    }
    return value.trim();
  }
}

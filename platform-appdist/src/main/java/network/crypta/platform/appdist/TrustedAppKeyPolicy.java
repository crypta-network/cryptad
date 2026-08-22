package network.crypta.platform.appdist;

import java.time.Instant;
import java.util.Objects;

/**
 * Lifecycle and validity policy for one trusted app-signing public key.
 *
 * <p>The validity interval is half-open: {@code validFrom} is inclusive and {@code validUntil} is
 * exclusive. Active keys may authorize newly staged bundles during that interval. Active, retiring,
 * and retired keys may verify historical installed bundles during the interval, while a revoked key
 * is rejected for both purposes regardless of its dates.
 *
 * <p>Instances are immutable and contain public verification material only. Callers select the
 * verification purpose explicitly through the query methods instead of treating registry membership
 * as authorization. Version 1 registries are represented by an active compatibility policy with an
 * unbounded interval; version 2 registries retain the operator-declared lifecycle and support
 * window. This keeps existing deployments readable while allowing planned retirement to preserve
 * installed-app verification without permitting another install or update.
 *
 * @param key unchanged public-key identity used by existing bundle signature sidecars
 * @param lifecycle closed lifecycle state for the key
 * @param validFrom first instant at which the key may be used for verification
 * @param validUntil first instant at which the key may no longer be used for verification
 */
public record TrustedAppKeyPolicy(
    TrustedAppKey key, TrustedAppKeyLifecycle lifecycle, Instant validFrom, Instant validUntil) {

  /**
   * Validates a trusted app-key policy.
   *
   * <p>Construction is side-effect free. It retains the immutable key reference and normalized
   * {@link Instant} values supplied by the caller. The interval is half-open and must contain at
   * least one representable instant; lifecycle-specific authorization is evaluated later for the
   * requested verification purpose.
   *
   * @throws NullPointerException if any component is {@code null}
   * @throws IllegalArgumentException if the validity interval is empty or reversed
   */
  public TrustedAppKeyPolicy {
    Objects.requireNonNull(key, "key");
    Objects.requireNonNull(lifecycle, "lifecycle");
    Objects.requireNonNull(validFrom, "validFrom");
    Objects.requireNonNull(validUntil, "validUntil");
    if (!validFrom.isBefore(validUntil)) {
      throw new IllegalArgumentException("trusted app key validFrom must precede validUntil");
    }
  }

  /**
   * Creates the compatibility policy used by v1 registries and direct trusted-key configuration.
   *
   * <p>The returned policy preserves historical behavior by treating the explicit key as active for
   * the complete {@link Instant} range. It should be used only when lifecycle metadata is absent; a
   * version 2 registry should construct a bounded policy from its declared fields.
   *
   * @param key trusted public key retained as the compatibility policy identity
   * @return active policy spanning the full representable verification timeline
   */
  public static TrustedAppKeyPolicy activeCompatibilityKey(TrustedAppKey key) {
    return new TrustedAppKeyPolicy(
        Objects.requireNonNull(key, "key"),
        TrustedAppKeyLifecycle.ACTIVE,
        Instant.MIN,
        Instant.MAX);
  }

  /**
   * Returns whether this policy permits verification of a newly staged bundle.
   *
   * <p>Registry membership alone is insufficient. The key must be active, and the supplied instant
   * must fall within the half-open validity interval. Retiring, retired, and revoked keys therefore
   * fail this query even when their cryptographic signature would otherwise verify.
   *
   * @param verifiedAt instant at which the staged-bundle decision is evaluated
   * @return {@code true} only for an active key within its validity interval
   */
  public boolean allowsNewBundleVerification(Instant verifiedAt) {
    return allowsRoutineVerification(verifiedAt);
  }

  /**
   * Returns whether this policy permits routine verification under the active signing authority.
   *
   * <p>This generic predicate is used by non-bundle signed subjects, such as app catalogs, that
   * must reject retiring, retired, revoked, not-yet-valid, and expired keys. Bundle callers may use
   * {@link #allowsNewBundleVerification(Instant)} for purpose-specific readability.
   *
   * @param verifiedAt instant at which the routine verification decision is evaluated
   * @return {@code true} only for an active key within its validity interval
   */
  public boolean allowsRoutineVerification(Instant verifiedAt) {
    return lifecycle == TrustedAppKeyLifecycle.ACTIVE && isValidAt(verifiedAt);
  }

  /**
   * Returns whether this policy permits verification of a historical installed bundle.
   *
   * <p>This purpose preserves supported installations during planned retirement. Active, retiring,
   * and retired keys may pass while their declared support interval contains the supplied instant;
   * revoked keys always fail. The method verifies lifecycle authorization only and does not verify
   * bundle bytes or signatures.
   *
   * @param verifiedAt instant at which historical support is evaluated
   * @return {@code true} for a non-revoked key within its validity interval
   */
  public boolean allowsHistoricalBundleVerification(Instant verifiedAt) {
    return allowsHistoricalVerification(verifiedAt);
  }

  /**
   * Returns whether this policy permits verification of an exact retained historical subject.
   *
   * <p>Active, retiring, and retired keys may authenticate already retained content while their
   * declared support window remains valid. Revoked keys always fail. Bundle callers may use {@link
   * #allowsHistoricalBundleVerification(Instant)} for purpose-specific readability.
   *
   * @param verifiedAt instant at which historical support is evaluated
   * @return {@code true} for a non-revoked key within its validity interval
   */
  public boolean allowsHistoricalVerification(Instant verifiedAt) {
    return lifecycle != TrustedAppKeyLifecycle.REVOKED && isValidAt(verifiedAt);
  }

  /**
   * Tests whether an instant belongs to this policy's half-open validity interval.
   *
   * <p>The lower boundary is inclusive and the upper boundary is exclusive. This helper performs
   * only the temporal check; callers remain responsible for applying the lifecycle rule appropriate
   * to routine or historical verification.
   *
   * @param verifiedAt instant to compare with the declared validity boundaries
   * @return {@code true} when the instant is not before {@link #validFrom()} and is before {@link
   *     #validUntil()}
   * @throws NullPointerException if {@code verifiedAt} is {@code null}
   */
  private boolean isValidAt(Instant verifiedAt) {
    Instant checkedInstant = Objects.requireNonNull(verifiedAt, "verifiedAt");
    return !checkedInstant.isBefore(validFrom) && checkedInstant.isBefore(validUntil);
  }
}

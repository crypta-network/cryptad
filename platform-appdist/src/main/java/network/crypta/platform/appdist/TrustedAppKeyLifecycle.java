package network.crypta.platform.appdist;

/**
 * Lifecycle state controlling how a trusted app-signing key may verify bundles.
 *
 * <p>The state separates authorization for a newly staged app from historical verification of an
 * already installed or otherwise retained app. Planned rotation moves a key from {@link #ACTIVE}
 * through {@link #RETIRING} to {@link #RETIRED}; those later states preserve bounded historical
 * verification without authorizing another release. {@link #REVOKED} is the fail-closed state used
 * when policy no longer permits either verification purpose.
 *
 * <p>This enum carries no key material and does not make a trust decision by itself. {@link
 * TrustedAppKeyPolicy} combines it with a public key and a validity interval, and {@link
 * AppBundleVerifier} selects the appropriate new-bundle or historical verification purpose.
 * Registry parsing accepts only these closed values so an unknown state cannot silently become
 * active.
 */
public enum TrustedAppKeyLifecycle {
  /**
   * The key may verify newly staged bundles and historical installed bundles while its declared
   * validity interval contains the verification instant.
   */
  ACTIVE,

  /**
   * The key remains usable for historical bundles during a planned overlap, but it cannot authorize
   * a newly staged install or update.
   */
  RETIRING,

  /**
   * The key verifies only historical installed or retained bundles, and only during its declared
   * support window; it cannot authorize new bundle acceptance.
   */
  RETIRED,

  /**
   * The key may not verify new or historical bundles, regardless of its validity dates or prior
   * lifecycle state.
   */
  REVOKED
}

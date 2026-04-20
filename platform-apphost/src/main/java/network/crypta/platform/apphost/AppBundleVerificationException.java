package network.crypta.platform.apphost;

/**
 * Signals that a staged app bundle failed signed-distribution verification.
 *
 * <p>{@code AppBundleVerificationException} is the AppHost-facing failure type for bundle digest,
 * signature, trust-policy, or other signed-distribution checks that reject a copied staged bundle
 * before installation or update proceeds. Platform API callers treat this as a client-fixable
 * staged-bundle problem rather than an internal host-layout failure.
 *
 * <p>The exception is thrown after AppHost has copied the caller-owned staging directory into its
 * managed temporary tree and a verifier determines that the bundle is unsigned, partially signed,
 * tampered, or signed by an untrusted key. Raw filesystem failures in the managed tree should
 * remain plain {@link java.io.IOException} cases so the API can report host-side problems
 * separately.
 */
public final class AppBundleVerificationException extends AppHostException {
  /**
   * Creates a verification failure with a message.
   *
   * @param message human-readable verification failure detail safe for logs or API mapping
   */
  public AppBundleVerificationException(String message) {
    super(message);
  }

  /**
   * Creates a verification failure with a message and cause.
   *
   * @param message human-readable verification failure detail safe for logs or API mapping
   * @param cause underlying distribution verifier failure cause
   */
  public AppBundleVerificationException(String message, Throwable cause) {
    super(message, cause);
  }
}

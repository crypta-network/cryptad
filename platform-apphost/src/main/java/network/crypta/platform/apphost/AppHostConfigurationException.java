package network.crypta.platform.apphost;

/**
 * Signals AppHost-side configuration failures rather than staged-bundle input problems.
 *
 * <p>{@code AppHostConfigurationException} is the checked failure type for invalid operator or node
 * configuration that prevents AppHost work from proceeding before bundle validation can even start.
 * Platform API callers treat this as a server-side internal error rather than a client-fixable
 * {@code invalid_app_bundle} problem.
 *
 * <p>Typical examples include missing or malformed trusted-key files, duplicate trusted key ids
 * between file-backed and direct configuration, unsupported public key material, or partial direct
 * key setup where key material is configured without a key id. These cases require operator action
 * on the node configuration, not changes to the staged app bundle.
 */
public final class AppHostConfigurationException extends AppHostException {
  /**
   * Creates a configuration failure with a message.
   *
   * @param message human-readable configuration failure detail for logs and server-side reporting
   */
  public AppHostConfigurationException(String message) {
    super(message);
  }

  /**
   * Creates a configuration failure with a message and cause.
   *
   * @param message human-readable configuration failure detail for logs and server-side reporting
   * @param cause underlying configuration, path, or key parsing failure
   */
  public AppHostConfigurationException(String message, Throwable cause) {
    super(message, cause);
  }
}

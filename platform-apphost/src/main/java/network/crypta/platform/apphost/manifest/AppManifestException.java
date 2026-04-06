package network.crypta.platform.apphost.manifest;

import network.crypta.platform.apphost.AppHostException;

/**
 * Signals manifest parsing or validation failures.
 *
 * <p>This checked exception specializes {@link network.crypta.platform.apphost.AppHostException}
 * for problems in {@code cryptad-app.properties}. Typical causes include missing required keys,
 * malformed numeric values, unsupported manifest versions, invalid path syntax, or permission and
 * quota metadata that fails normalization.
 *
 * <p>Using a dedicated subtype lets callers distinguish bundle-shape problems from later runtime
 * failures such as launch errors or shutdown timeouts.
 */
public class AppManifestException extends AppHostException {
  /**
   * Creates an exception with a message.
   *
   * @param message human-readable detail about the invalid manifest content or missing property
   */
  public AppManifestException(String message) {
    super(message);
  }

  /**
   * Creates an exception with a message and cause.
   *
   * @param message human-readable detail about the invalid manifest content or missing property
   * @param cause underlying parsing or validation cause
   */
  public AppManifestException(String message, Throwable cause) {
    super(message, cause);
  }
}

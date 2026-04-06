package network.crypta.platform.apphost.manifest;

import network.crypta.platform.apphost.AppHostException;

/** Signals manifest parsing or validation failures. */
public class AppManifestException extends AppHostException {
  /**
   * Creates an exception with a message.
   *
   * @param message failure detail
   */
  public AppManifestException(String message) {
    super(message);
  }

  /**
   * Creates an exception with a message and cause.
   *
   * @param message failure detail
   * @param cause underlying cause
   */
  public AppManifestException(String message, Throwable cause) {
    super(message, cause);
  }
}

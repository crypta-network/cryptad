package network.crypta.platform.apphost;

import java.io.IOException;

/** Signals application-host validation or lifecycle failures. */
public class AppHostException extends IOException {
  /**
   * Creates an exception with a message.
   *
   * @param message failure detail
   */
  public AppHostException(String message) {
    super(message);
  }

  /**
   * Creates an exception with a message and cause.
   *
   * @param message failure detail
   * @param cause underlying cause
   */
  public AppHostException(String message, Throwable cause) {
    super(message, cause);
  }
}

package network.crypta.platform.apphost;

import java.io.IOException;

/**
 * Signals AppHost validation or lifecycle failures.
 *
 * <p>{@code AppHostException} is the checked failure type used for host-specific problems such as
 * invalid manifests, unsafe filesystem layouts, startup failures, and shutdown timeouts.
 * Implementations throw this exception when the failure is part of the AppHost contract rather than
 * an unexpected unchecked programming error.
 *
 * <p>The type extends {@link IOException} so callers that already treat filesystem and process
 * lifecycle work as checked I/O can handle AppHost failures in the same control flow while still
 * distinguishing them by concrete type when needed.
 */
public class AppHostException extends IOException {
  /**
   * Creates an exception with a message.
   *
   * @param message human-readable failure detail that explains the rejected operation or invalid
   *     state
   */
  public AppHostException(String message) {
    super(message);
  }

  /**
   * Creates an exception with a message and cause.
   *
   * @param message human-readable failure detail that explains the rejected operation or invalid
   *     state
   * @param cause underlying cause that triggered this host-level failure classification
   */
  public AppHostException(String message, Throwable cause) {
    super(message, cause);
  }
}

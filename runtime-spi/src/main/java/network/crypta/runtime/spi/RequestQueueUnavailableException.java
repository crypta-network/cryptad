package network.crypta.runtime.spi;

/**
 * Signals that the runtime request queue cannot accept new persistent-request work.
 *
 * <p>This checked exception lets infrastructure code preserve its existing protocol-level mapping
 * when persistence has been disabled, the database has been killed, shutdown has advanced too far,
 * or the queue is otherwise unavailable. Keeping this failure as a checked exception makes the
 * queue boundary explicit and avoids forcing runtime-spi callers to know about daemon-specific
 * exception types.
 */
public class RequestQueueUnavailableException extends Exception {
  /**
   * Creates an exception with the supplied detail message.
   *
   * <p>Use this constructor when the queue rejection has no more specific underlying cause that is
   * worth exposing to the caller.
   *
   * @param message human-readable explanation of the queue failure for logs or protocol mapping
   */
  public RequestQueueUnavailableException(String message) {
    super(message);
  }

  /**
   * Creates an exception with the supplied detail message and cause.
   *
   * <p>Use this constructor when adapting a daemon-specific queue failure into the JDK-only SPI
   * boundary while still preserving the original exception for diagnostics.
   *
   * @param message human-readable explanation of the queue failure for logs or protocol mapping
   * @param cause underlying daemon exception that caused the queue submission failure
   */
  public RequestQueueUnavailableException(String message, Throwable cause) {
    super(message, cause);
  }
}

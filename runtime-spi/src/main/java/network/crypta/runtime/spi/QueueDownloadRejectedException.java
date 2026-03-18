package network.crypta.runtime.spi;

/**
 * Signals that runtime policy rejected creation of a new queue download.
 *
 * <p>This checked exception separates access-control-style rejections from broader queue
 * availability failures. Typical callers keep user-facing mapping in the HTTP layer, where single
 * downloads and bulk downloads may render the rejection differently while still treating the cause
 * as a non-retriable policy failure.
 *
 * <p>Use this exception when the runtime decided that the requested operation is not allowed, not
 * when the queue subsystem is missing or temporarily unavailable. That distinction lets callers
 * preserve existing queue-page behavior such as rendering a disk-configuration error for a single
 * download while still recording per-key failures during bulk submission.
 */
public class QueueDownloadRejectedException extends Exception {
  /**
   * Creates an exception with the supplied detail message.
   *
   * <p>The message should describe the policy rejection at a level suitable for logs and debugging.
   * Callers typically map this exception type to a user-facing page or aggregate failure list
   * rather than exposing the raw message directly.
   *
   * @param message human-readable explanation of the rejection
   */
  public QueueDownloadRejectedException(String message) {
    super(message);
  }

  /**
   * Creates an exception with the supplied detail message and cause.
   *
   * <p>Use this constructor when adapting a runtime-specific exception into the detached SPI so the
   * original failure remains available for diagnostics without leaking daemon-only exception types
   * across the boundary.
   *
   * @param message human-readable explanation of the rejection
   * @param cause underlying runtime-specific rejection cause retained for diagnostics
   */
  public QueueDownloadRejectedException(String message, Throwable cause) {
    super(message, cause);
  }
}

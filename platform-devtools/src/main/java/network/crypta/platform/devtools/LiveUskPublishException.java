package network.crypta.platform.devtools;

import java.io.IOException;
import network.crypta.platform.appdist.AppDistributionException;

/**
 * Reports a live USK publication failure with staging-retention guidance.
 *
 * <p>The production live publisher queues a persistent, disk-backed directory insert and may then
 * do optional public-source verification. Once the queue accepts the insert, staged sidecar files
 * must remain available even if later verification fails, because the daemon may still be reading
 * the source directory. Failures before queue acceptance can safely remove staging.
 *
 * <p>This exception keeps that distinction inside the devtools implementation boundary without
 * adding private insert URIs, form passwords, request bodies, or local staging paths to error text.
 */
final class LiveUskPublishException extends AppDistributionException {
  private LiveUskPublishException(String message, IOException cause) {
    super(message, cause);
  }

  /**
   * Wraps a failure that happened after the live queue accepted the directory insert.
   *
   * @param cause sanitized failure raised after queue acceptance
   * @return publication exception that tells the service to retain staged sidecars
   */
  static LiveUskPublishException afterQueueAccepted(IOException cause) {
    return new LiveUskPublishException(sanitizedMessage(cause), cause);
  }

  private static String sanitizedMessage(IOException cause) {
    String message = cause.getMessage();
    return message == null || message.isBlank() ? "live_publish_failed" : message;
  }
}

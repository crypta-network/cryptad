package network.crypta.runtime.spi;

import java.io.IOException;

/**
 * Runtime capability for creating new persistent download requests from the queue UI.
 *
 * <p>This port isolates the remaining live-daemon work involved in registering new persistent
 * downloads while keeping HTTP request parsing, URI validation, path selection, and user-facing
 * response mapping outside the runtime boundary. Callers submit one detached {@link
 * QueueDownloadRequest} at a time after they have already decided whether the request should go to
 * disk or return directly to the browser.
 *
 * <p>The contract is intentionally narrow. It does not expose daemon-only URI types, queue page
 * models, or any bulk helper. Higher layers keep those concerns so queue toadlets can preserve
 * their current success and failure rendering while still moving the actual enqueue operation
 * behind a JDK-only runtime SPI.
 *
 * <ul>
 *   <li>Creates only new persistent downloads; it does not mutate existing requests.
 *   <li>Uses JDK-only request data so the SPI stays independent of daemon-only URI types.
 *   <li>Surfaces policy rejections separately from queue-unavailable failures.
 * </ul>
 *
 * @see QueueDownloadRequest
 * @see QueueDownloadRejectedException
 * @see RequestQueueUnavailableException
 */
public interface QueueDownloadPort {
  /**
   * Returns whether runtime policy currently disables disk-backed downloads.
   *
   * <p>Callers use this flag to preserve the existing queue-page behavior that falls back to
   * direct-return downloads when disk targets are not permitted. The result reports the current
   * runtime policy only; callers still keep HTTP-layer access checks such as public-gateway
   * restrictions and any per-request path validation. The value is a point-in-time snapshot, so
   * callers should use it only to choose the immediate handling path for the current request.
   *
   * @return {@code true} when disk downloads are disabled by the runtime; otherwise {@code false}
   */
  boolean isDiskDownloadDisabled();

  /**
   * Registers one new persistent download request with the runtime.
   *
   * <p>The runtime adapter is responsible only for bridging the detached request into the legacy
   * queueing implementation. Callers retain any URI parsing, bulk text splitting, path creation,
   * redirects, and user-facing error-page selection in their own layer. Each invocation handles
   * exactly one request, so bulk callers should loop explicitly and decide for themselves whether
   * to stop on the first failure or accumulate partial results.
   *
   * @param request detached download request describing the fetch, return mode, and optional disk
   *     target chosen by the caller
   * @throws QueueDownloadRejectedException if runtime policy rejects the requested download target
   *     or other not-allowed queue operation
   * @throws RequestQueueUnavailableException if the persistent queue is unavailable for new
   *     requests, such as when persistence support is disabled
   * @throws IOException if request creation fails for another I/O reason while bridging to the
   *     legacy queueing implementation
   */
  void enqueueDownload(QueueDownloadRequest request)
      throws QueueDownloadRejectedException, RequestQueueUnavailableException, IOException;
}

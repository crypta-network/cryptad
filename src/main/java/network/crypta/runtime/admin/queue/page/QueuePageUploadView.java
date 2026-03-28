package network.crypta.runtime.admin.queue.page;

import network.crypta.keys.FreenetURI;

/**
 * Marks a queue-page view representing an upload request.
 *
 * <p>The queue page still treats the finalized URI specially for uploads. It uses that value when
 * rendering hidden form fields and key columns.
 *
 * <p>This subtype exposes the finalized URI explicitly. Callers do not need to infer it from the
 * generic request URI. That keeps upload-specific rendering concerns out of generic queue-page code
 * while still avoiding a broad dependency on the upstream upload status model.
 */
public interface QueuePageUploadView extends QueuePageRequestView {
  /**
   * Returns the finalized insert URI associated with the upload request.
   *
   * @return finalized upload URI for queue-page key rendering, or {@code null} when not available
   */
  FreenetURI getFinalUri();
}

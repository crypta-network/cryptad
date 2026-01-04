package network.crypta.client;

import network.crypta.client.async.ClientContext;

/**
 * Describes a single archive element of interest and its callback.
 *
 * <p>The element name may be {@code null} to indicate that no specific entry is requested. The
 * callback and client context are passed through to the extraction pipeline as provided.
 */
final class ArchiveElementRequest {
  final String element;
  final ArchiveExtractCallback callback;
  final ClientContext clientContext;

  /**
   * Creates a new element request.
   *
   * @param element optional element name to prioritize; may be {@code null}
   * @param callback callback notified when the element is found or missing; may be {@code null}
   * @param clientContext client execution context for callbacks and background work
   */
  ArchiveElementRequest(
      String element, ArchiveExtractCallback callback, ClientContext clientContext) {
    this.element = element;
    this.callback = callback;
    this.clientContext = clientContext;
  }
}

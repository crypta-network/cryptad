package network.crypta.runtime.spi;

import java.io.File;
import java.io.IOException;
import java.util.List;

/**
 * Exposes the legacy node-to-node message compose/send capability.
 *
 * <p>This port is the detached boundary used by the HTTP compose/send page. It lets the web layer
 * identify target peers by stable runtime snapshots, offer optional attachments, and render the
 * existing sent or delayed or queued result buckets without reaching into live daemon objects.
 * Implementations are responsible for resolving detached peer identities on demand and delegating
 * to the daemon's current sending APIs.
 *
 * <p>The interface is intentionally small. It models only the behaviors that the N2NTM UI currently
 * needs, preserves the legacy selection-token flow, and avoids bringing HTTP request abstractions
 * into {@code runtime-spi}. Callers should assume that peer identity resolution is request-scoped
 * and may fail if the peer roster changes before the sending occurs.
 */
public interface DarknetMessagingPort {
  /**
   * Sends one text message to the selected detached darknet peer.
   *
   * <p>The implementation resolves the supplied detached identity against the current runtime peer
   * roster, sends the text through the daemon's existing N2NTM path, and maps the daemon result to
   * a UI-level delivery category. Callers typically pass the full message body shown on the
   * "compose" page; this method implies no truncation.
   *
   * @param nodeIdentifier detached peer identity selected from the legacy friends page and used for
   *     request-scoped peer lookup
   * @param message UTF-8 text to send to the resolved darknet peer without additional UI formatting
   * @return UI-level delivery category that the compose/send page can render directly
   * @throws UnknownPeerException if the detached peer identity no longer resolves at sending time
   * @throws DarknetPeerRequiredException if the resolved peer exists but is not a darknet peer
   */
  DarknetMessageSendStatus sendText(String nodeIdentifier, String message)
      throws UnknownPeerException, DarknetPeerRequiredException;

  /**
   * Sends one local-file offer to the selected detached darknet peer.
   *
   * <p>This is the detached equivalent of the legacy file-offer path for files that already exist
   * on the node's local filesystem. The implementation resolves the target peer on demand and
   * delegates to the daemon's existing file-offer API without changing the caller-provided note.
   *
   * @param nodeIdentifier detached peer identity selected from the legacy friends page and used for
   *     request-scoped peer lookup
   * @param file local file on disk that the daemon should offer to the selected peer
   * @param messageHead optional short human-readable note that comes with the file offer
   * @throws UnknownPeerException if the detached peer identity no longer resolves at sending time
   * @throws DarknetPeerRequiredException if the resolved peer exists but is not a darknet peer
   * @throws IOException if the local file cannot be opened or read by the daemon adapter
   */
  void sendFileOffer(String nodeIdentifier, File file, String messageHead)
      throws UnknownPeerException, DarknetPeerRequiredException, IOException;

  /**
   * Sends one uploaded-file offer to the selected detached darknet peer.
   *
   * <p>This variant handles uploads that arrived through the HTTP request rather than through a
   * local filesystem path. The detached payload must be adaptable to the daemon's file-offer API
   * without depending on HTTP-layer bucket types inside the SPI surface.
   *
   * @param nodeIdentifier detached peer identity selected from the legacy friends page and used for
   *     request-scoped peer lookup
   * @param upload detached uploaded-file payload, including metadata and a reopenable content
   *     stream
   * @param messageHead optional short human-readable note that comes with the file offer
   * @throws UnknownPeerException if the detached peer identity no longer resolves at sending time
   * @throws DarknetPeerRequiredException if the resolved peer exists but is not a darknet peer
   * @throws IOException if the detached upload cannot be adapted or reopened for sending
   */
  void sendUploadedFileOffer(String nodeIdentifier, DarknetUploadedFile upload, String messageHead)
      throws UnknownPeerException, DarknetPeerRequiredException, IOException;

  /**
   * Sends one or more download recommendations to the selected detached darknet peer.
   *
   * <p>This is the detached equivalent of the legacy queue "recommend to friends" path. Callers
   * keep request parsing, URI validation, checkbox selection, and user-facing error handling in the
   * HTTP layer. They then pass the validated URI strings in encounter order. The implementation
   * resolves the detached peer identity on demand, converts the strings into daemon URI objects,
   * and delegates to the existing download-feed send API.
   *
   * <p>The implementation should preserve the caller-provided URI order and description value
   * exactly for the selected peer. As with the other methods on this port, detached identity
   * resolution is request-scoped and may fail if the peer roster changes between form render and
   * submit.
   *
   * @param nodeIdentifier detached peer identity selected from the legacy friends page and used for
   *     request-scoped peer lookup
   * @param uris validated URI strings to recommend to the resolved peer, in encounter order
   * @param description optional human-readable description sent with each recommendation
   * @throws UnknownPeerException if the detached peer identity no longer resolves at sending time
   * @throws DarknetPeerRequiredException if the resolved peer exists but is not a darknet peer
   */
  void recommendDownloads(String nodeIdentifier, List<String> uris, String description)
      throws UnknownPeerException, DarknetPeerRequiredException;

  /**
   * Sends one composed N2NTM to the selected detached darknet peer.
   *
   * <p>Implementations must resolve the peer once for the whole operation, then send the optional
   * file offer and text message through that same bound peer instance. At most one of {@code file}
   * or {@code upload} should be non-{@code null}; when both are {@code null}, this behaves like a
   * plain text sending.
   *
   * <p>This method preserves the original page semantics where one selected peer maps to one
   * logical send operation. The implementation must keep the whole sequence bound to one peer
   * resolution so that the optional file-offer step and the text-send step succeed or fail against
   * the same peer object. Callers should pass either {@code file} or {@code upload}; supplying both
   * is invalid caller behavior and is not normalized here.
   *
   * @param nodeIdentifier detached peer identity selected from the legacy friends page and used for
   *     request-scoped peer lookup
   * @param message UTF-8 text to send after any requested file-offer step has completed
   * @param file local file on disk to offer before sending the text message; may be {@code null}
   * @param upload detached uploaded-file payload to offer before sending the text message; may be
   *     {@code null}
   * @param messageHead optional short human-readable note that comes with the file offer
   * @return UI-level delivery category for the text-send result that follows any file-offer step
   * @throws UnknownPeerException if the detached peer identity no longer resolves at sending time
   * @throws DarknetPeerRequiredException if the resolved peer exists but is not a darknet peer
   * @throws IOException if the requested file or detached, upload cannot be opened or read
   */
  DarknetMessageSendStatus sendComposedMessage(
      String nodeIdentifier,
      String message,
      File file,
      DarknetUploadedFile upload,
      String messageHead)
      throws UnknownPeerException, DarknetPeerRequiredException, IOException;
}

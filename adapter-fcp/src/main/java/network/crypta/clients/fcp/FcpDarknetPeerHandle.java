package network.crypta.clients.fcp;

import network.crypta.keys.FreenetURI;

/**
 * Adapter-owned handle for delivering feed items to a resolved darknet peer.
 *
 * <p>This interface is the narrow peer-facing contract that remains visible inside the {@code
 * :adapter-fcp} leaf after peer lookup succeeds. FCP message handlers need to send only three kinds
 * of feed items: plain text announcements, download suggestions, and bookmark suggestions. They do
 * not need the broader {@code DarknetPeerNode} surface, nor should they know how the runtime
 * locates, validates, or retains the backing peer object. Restricting the contract to these methods
 * keeps the message package protocol-focused while still preserving the existing delivery flow and
 * reply semantics.
 *
 * <p>Implementations are expected to be thin adapters around a live runtime peer. Calls should
 * delegate immediately, should not reinterpret validated FCP data, and should return the same node
 * status integers that the pre-seam direct calls returned so that {@link SentPeerMessage} remains
 * wire-compatible. Implementations may be shared by concurrent connection handlers, so they should
 * treat the backing peer reference as a live runtime state and preserve the daemon's thread-safety
 * guarantees rather than layering their own caching or retry policy on top.
 *
 * <ul>
 *   <li>Represents only peers that already passed the darknet-only eligibility check.
 *   <li>Exposes only the feed operations needed by the residual FCP message handlers.
 *   <li>Leaves peer discovery, authorization, and protocol branching outside the handle.
 * </ul>
 *
 * @see FcpPeerLookupResult
 * @see SentPeerMessage
 */
public interface FcpDarknetPeerHandle {

  /**
   * Sends a text feed item to the resolved darknet peer.
   *
   * <p>The supplied text is already decoded from the inbound FCP payload and has passed any
   * protocol-level validation performed by the calling message handler. Implementations should
   * enqueue or forward the text using the runtime peer's existing delivery path, preserve its
   * current back-pressure and status behavior, and avoid performing additional protocol
   * interpretation beyond what the peer runtime already does internally. The returned integer is an
   * opaque node-status value that the adapter forwards back to the client unchanged.
   *
   * @param message UTF-8 text payload that should be queued for the peer feed, already validated by
   *     the message layer and never {@code null}.
   * @return peer status integer that remains suitable for the eventual {@link SentPeerMessage}
   *     reply emitted on the FCP connection.
   */
  int sendTextFeed(String message);

  /**
   * Sends a download suggestion to the resolved darknet peer.
   *
   * <p>The message layer has already parsed the URI into canonical form and decoded the optional
   * description bucket, so this method receives only runtime-ready values. Implementations should
   * preserve the runtime peer's existing scheduling, queueing, and status reporting semantics for
   * download feed items. A {@code null} description means the client intentionally omitted that
   * field rather than supplying an empty string, so implementations should pass the distinction
   * through unchanged.
   *
   * @param uri parsed URI to suggest to the peer, already accepted by FCP parsing and never {@code
   *     null}.
   * @param description optional human-readable description to attach to the suggestion; {@code
   *     null} when the request carried no description payload.
   * @return peer status integer that the adapter can return to the caller without translation in
   *     the resulting {@link SentPeerMessage}.
   */
  int sendDownloadFeed(FreenetURI uri, String description);

  /**
   * Sends a bookmark suggestion to the resolved darknet peer.
   *
   * <p>The calling FCP message has already validated the bookmark title, parsed the URI, decoded
   * the optional description, and interpreted the active-link flag. Implementations should pass
   * those values through to the runtime peer without rewriting client intent, changing defaulting
   * behavior, or collapsing the distinction between omitted and present description text. As with
   * the other feed methods, the integer result is a runtime-defined status code that must remain
   * stable enough for the FCP adapter to echo back to the client.
   *
   * @param uri parsed bookmark URI to share with the peer, already validated by the FCP request and
   *     never {@code null}.
   * @param name bookmark title supplied by the FCP client, already validated as present and never
   *     {@code null}.
   * @param description optional decoded description text; {@code null} when the request did not
   *     carry a description bucket.
   * @param hasActiveLink whether the bookmark should be marked as having an active link in the
   *     downstream peer-visible feed item.
   * @return peer status integer suitable for direct reuse in the eventual {@link SentPeerMessage}
   *     response sent back over FCP.
   */
  int sendBookmarkFeed(FreenetURI uri, String name, String description, boolean hasActiveLink);
}

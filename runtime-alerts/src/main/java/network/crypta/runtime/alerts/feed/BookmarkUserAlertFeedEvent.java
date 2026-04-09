package network.crypta.runtime.alerts.feed;

import java.util.Objects;
import network.crypta.keys.FreenetURI;

/**
 * Immutable runtime-side feed event for bookmark recommendations.
 *
 * <p>This variant extends the common alert text fields with the data needed to preserve existing
 * bookmark feed behavior when the FCP bridge later encodes the event. It carries the bookmark
 * title, target URI, optional descriptive text, and the node-to-node provenance metadata that tells
 * clients which darknet peer produced the recommendation and when the message moved through the
 * system.
 *
 * <p>The record does not perform URI normalization or text transformation. Callers are expected to
 * provide values that already reflect current alert behavior so the downstream bridge can recreate
 * the exact message layout it used before the seam was introduced.
 *
 * @param header short one-line title shown most prominently when clients render the alert
 * @param shortText secondary summary line that gives clients a concise preview of the alert
 * @param text full alert body text that downstream bridges encode into the feed payload
 * @param priorityClass numeric severity or priority class preserved from the originating alert
 * @param updatedTime epoch-millisecond timestamp describing when the originating alert last changed
 * @param metadata source-node name and compose/send/receive timestamps for the recommendation
 * @param bookmarkTitle display title for the recommended bookmark entry
 * @param uri target {@link FreenetURI} for the bookmark suggestion
 * @param description optional human-readable description associated with the bookmark
 * @param hasActiveLink whether the originating alert exposed the bookmark as an active link
 * @see NodeToNodeFeedMetadata
 */
public record BookmarkUserAlertFeedEvent(
    String header,
    String shortText,
    String text,
    short priorityClass,
    long updatedTime,
    NodeToNodeFeedMetadata metadata,
    String bookmarkTitle,
    FreenetURI uri,
    String description,
    boolean hasActiveLink)
    implements UserAlertFeedEvent {

  /**
   * Creates a runtime-owned bookmark feed event snapshot.
   *
   * <p>The constructor keeps validation narrow so that it mirrors the existing alert behavior
   * closely. Provenance metadata and the target URI are required because downstream FCP message
   * types always rely on them, while the descriptive text may be absent when the originating alert
   * did not include any additional explanation.
   *
   * @param header short one-line title shown most prominently when clients render the alert
   * @param shortText secondary summary line that gives clients a concise preview of the alert
   * @param text full alert body text that downstream bridges encode into the feed payload
   * @param priorityClass numeric severity or priority class preserved from the originating alert
   * @param updatedTime epoch-millisecond timestamp describing when the originating alert last
   *     changed
   * @param metadata source-node name and compose/send/receive timestamps for the recommendation
   * @param bookmarkTitle display title for the recommended bookmark entry
   * @param uri target {@link FreenetURI} for the bookmark suggestion
   * @param description optional human-readable description associated with the bookmark
   * @param hasActiveLink whether the originating alert exposed the bookmark as an active link
   * @throws NullPointerException if {@code metadata} or {@code uri} is {@code null}
   */
  public BookmarkUserAlertFeedEvent {
    Objects.requireNonNull(metadata, "metadata");
    uri = new FreenetURI(Objects.requireNonNull(uri, "uri"));
  }

  @Override
  public FreenetURI uri() {
    return new FreenetURI(uri);
  }
}

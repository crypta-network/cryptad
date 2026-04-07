package network.crypta.runtime.alerts.feed;

import java.util.Objects;
import network.crypta.keys.FreenetURI;

/**
 * Immutable runtime-side feed event for URI and download announcements.
 *
 * <p>This variant models alerts that recommend or announce a specific {@link FreenetURI}. It keeps
 * the common alert presentation fields together with the announced URI, optional descriptive text,
 * and the node-to-node provenance metadata required by the existing FCP feed protocol. Runtime
 * alerts use it when they want to remain transport-neutral but still preserve the exact data shape
 * that downstream FCP clients expect.
 *
 * <p>The record is intentionally descriptive rather than behavioral. It does not attempt to fetch,
 * validate, or rewrite the URI, and it leaves any sentinel handling for unknown timestamps to the
 * transport bridge that converts it into a protocol message.
 *
 * @param header short one-line title shown most prominently when clients render the alert
 * @param shortText secondary summary line that gives clients a concise preview of the alert
 * @param text full alert body text that downstream bridges encode into the feed payload
 * @param priorityClass numeric severity or priority class preserved from the originating alert
 * @param updatedTime epoch-millisecond timestamp describing when the originating alert last changed
 * @param metadata source-node name and compose/send/receive timestamps for the announcement
 * @param uri announced {@link FreenetURI} that clients may display or follow
 * @param description optional human-readable description paired with the announced URI
 * @see NodeToNodeFeedMetadata
 */
public record UriUserAlertFeedEvent(
    String header,
    String shortText,
    String text,
    short priorityClass,
    long updatedTime,
    NodeToNodeFeedMetadata metadata,
    FreenetURI uri,
    String description)
    implements UserAlertFeedEvent {

  /**
   * Creates a runtime-owned URI feed event snapshot.
   *
   * <p>The constructor validates only the fields that downstream protocol encoding always requires.
   * The provenance metadata and URI must be present, while the description may be omitted when the
   * originating alert had no separate descriptive text to send.
   *
   * @param header short one-line title shown most prominently when clients render the alert
   * @param shortText secondary summary line that gives clients a concise preview of the alert
   * @param text full alert body text that downstream bridges encode into the feed payload
   * @param priorityClass numeric severity or priority class preserved from the originating alert
   * @param updatedTime epoch-millisecond timestamp describing when the originating alert last
   *     changed
   * @param metadata source-node name and compose/send/receive timestamps for the announcement
   * @param uri announced {@link FreenetURI} that clients may display or follow
   * @param description optional human-readable description paired with the announced URI
   * @throws NullPointerException if {@code metadata} or {@code uri} is {@code null}
   */
  public UriUserAlertFeedEvent {
    Objects.requireNonNull(metadata, "metadata");
    uri = new FreenetURI(Objects.requireNonNull(uri, "uri"));
  }

  @Override
  public FreenetURI uri() {
    return new FreenetURI(uri);
  }
}

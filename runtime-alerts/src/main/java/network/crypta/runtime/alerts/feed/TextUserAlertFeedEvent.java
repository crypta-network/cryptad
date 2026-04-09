package network.crypta.runtime.alerts.feed;

import java.util.Objects;

/**
 * Immutable runtime-side feed event for node-to-node text messages.
 *
 * <p>This variant is used for alerts that expose a normal rendered alert body and also need to keep
 * the original text-message payload available for downstream transport encoding. The common fields
 * describe what operators see in the alert UI, while {@code messageText} preserves the raw
 * node-to-node message content that FCP clients have historically received in a dedicated payload
 * bucket.
 *
 * <p>The raw message text may be {@code null}. That behavior is deliberate because the legacy alert
 * path already allowed empty or absent node-to-node text payloads, and the seam keeps that contract
 * intact so the FCP bridge can continue emitting the same zero-length bucket behavior.
 *
 * @param header short one-line title shown most prominently when clients render the alert
 * @param shortText secondary summary line that gives clients a concise preview of the alert
 * @param text full alert body text that downstream bridges encode into the feed payload
 * @param priorityClass numeric severity or priority class preserved from the originating alert
 * @param updatedTime epoch-millisecond timestamp describing when the originating alert last changed
 * @param metadata source-node name and compose/send/receive timestamps for the text message
 * @param messageText raw text payload carried by the node-to-node message, which may be {@code
 *     null}
 * @see NodeToNodeFeedMetadata
 */
public record TextUserAlertFeedEvent(
    String header,
    String shortText,
    String text,
    short priorityClass,
    long updatedTime,
    NodeToNodeFeedMetadata metadata,
    String messageText)
    implements UserAlertFeedEvent {

  /**
   * Creates a runtime-owned text-message feed event snapshot.
   *
   * <p>The constructor requires provenance metadata because downstream node-to-node feed encoders
   * always emit those fields. It does not require a non-null {@code messageText}; callers may pass
   * {@code null} when the originating alert had no raw node-to-node message body beyond the main
   * rendered text.
   *
   * @param header short one-line title shown most prominently when clients render the alert
   * @param shortText secondary summary line that gives clients a concise preview of the alert
   * @param text full alert body text that downstream bridges encode into the feed payload
   * @param priorityClass numeric severity or priority class preserved from the originating alert
   * @param updatedTime epoch-millisecond timestamp describing when the originating alert last
   *     changed
   * @param metadata source-node name and compose/send/receive timestamps for the text message
   * @param messageText raw text payload carried by the node-to-node message, which may be {@code
   *     null}
   * @throws NullPointerException if {@code metadata} is {@code null}
   */
  public TextUserAlertFeedEvent {
    Objects.requireNonNull(metadata, "metadata");
  }
}

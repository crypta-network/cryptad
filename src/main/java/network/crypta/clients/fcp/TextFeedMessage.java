package network.crypta.clients.fcp;

import java.nio.charset.StandardCharsets;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.ArrayBucket;
import network.crypta.support.io.NullBucket;

/**
 * Feed message that carries a textual node‑to‑node notification with an optional extra body.
 *
 * <p>This class extends {@link N2NFeedMessage} and therefore behaves like a regular {@link
 * FeedMessage} enriched with information about the originating node and transmission timestamps. In
 * addition to the standard {@code "Text"} payload created by the superclass, it attaches a second
 * payload bucket named {@code "MessageText"}, which can be used to transport an auxiliary textual
 * fragment such as a detailed description, log excerpt, or peer‑specific note.
 *
 * <p>The primary constructor accepts all fields at once, so instances are fully initialized and
 * effectively immutable after construction. Callers typically create a {@code TextFeedMessage} on a
 * single thread shortly before sending it over an FCP connection. The bucket map is populated
 * eagerly using either an {@link ArrayBucket} containing UTF‑8 encoded bytes of the supplied
 * message text, or a {@link NullBucket} when no additional text is provided, so read‑only methods
 * such as {@link #getFieldSet()} and {@link #dataLength()} can be called without further I/O.
 *
 * <p>Thread‑safety: instances are not designed for concurrent mutation but are safe for read‑only
 * access from a single thread once constructed.
 *
 * @see N2NFeedMessage
 * @see FeedMessage
 * @see network.crypta.support.SimpleFieldSet
 */
public class TextFeedMessage extends N2NFeedMessage {

  /**
   * Protocol name of this message type used on the FCP wire.
   *
   * <p>The value of this constant is returned by {@link #getName()} and is written as the leading
   * line of the serialized message when the FCP connection sends a {@code TextFeedMessage}. Client
   * implementations can compare incoming message names against this literal to detect node‑to‑node
   * text feed entries with the extra {@code "MessageText"} payload segment attached.
   */
  public static final String NAME = "TextFeed";

  /**
   * Create a new node‑to‑node feed message that carries textual content and an optional extra body.
   *
   * <p>The parameters that describe the header, short summary, and main body are forwarded
   * unchanged to the {@link N2NFeedMessage} constructor, which in turn populates the {@code "Text"}
   * bucket and base header fields. This constructor additionally creates a {@link Bucket} for the
   * {@code messageText} argument and stores it under the key {@code "MessageText"} in the internal
   * bucket map. When {@code messageText} is {@code null}, a {@link NullBucket} of zero length is
   * used so that the field set still exposes a {@code MessageTextLength} entry consistent with the
   * data‑carrying contract.
   *
   * <p>The resulting instance is ready to be serialized and sent to an FCP client. No further
   * mutation of bucket contents is expected once construction completes.
   *
   * @param header short human‑readable title for the feed entry; may be {@code null} when no
   *     dedicated header line is required by the caller.
   * @param shortText secondary summary line providing compact context beyond {@code header}; may be
   *     {@code null} if the feed entry does not use a short description.
   * @param text full body text for the main feed payload; converted to UTF‑8 bytes and stored in a
   *     {@code "Text"} bucket, and therefore must not be {@code null}.
   * @param priorityClass numeric priority hint used by the surrounding FCP infrastructure when
   *     ordering outgoing messages; higher values generally indicate more urgent notifications.
   * @param updatedTime timestamp in milliseconds since the Unix epoch indicating when the feed
   *     entry was last updated from the perspective of the producer.
   * @param sourceNodeName descriptive name of the remote node that originated this message; written
   *     to the {@code "SourceNodeName"} header field and may be {@code null} or empty.
   * @param composed time at which the sender composed the message body, expressed in epoch
   *     milliseconds; use {@code -1} when the composition time is unknown or not tracked.
   * @param sent time at which the message was transmitted towards this node, in epoch milliseconds;
   *     use {@code -1} when a precise send time is unavailable or intentionally omitted.
   * @param received time at which this node received the message, in epoch milliseconds; use {@code
   *     -1} when the receipt time could not be recorded or is not meaningful.
   * @param messageText optional additional textual payload carried in the {@code "MessageText"}
   *     bucket; when {@code null}, an empty {@link NullBucket} is used instead of an {@link
   *     ArrayBucket}.
   */
  public TextFeedMessage(
      String header,
      String shortText,
      String text,
      short priorityClass,
      long updatedTime,
      String sourceNodeName,
      long composed,
      long sent,
      long received,
      String messageText) {
    super(
        header,
        shortText,
        text,
        priorityClass,
        updatedTime,
        sourceNodeName,
        composed,
        sent,
        received);
    final Bucket messageTextBucket;
    if (messageText != null) {
      messageTextBucket = new ArrayBucket(messageText.getBytes(StandardCharsets.UTF_8));
    } else {
      messageTextBucket = new NullBucket();
    }
    buckets.put("MessageText", messageTextBucket);
  }

  /**
   * Return the symbolic protocol name identifying this message type.
   *
   * <p>The value is the constant {@link #NAME}, which is used by the FCP layer when serializing the
   * message and by clients that need to distinguish {@code TextFeedMessage} instances from other
   * feed or control messages. The returned string is immutable and may be compared directly against
   * the literal {@code "TextFeed"} in client code.
   *
   * @return the literal protocol name {@code "TextFeed"} associated with this class.
   */
  @Override
  public String getName() {
    return NAME;
  }
}

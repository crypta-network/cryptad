package network.crypta.clients.fcp;

import java.nio.charset.StandardCharsets;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.ArrayBucket;

/**
 * Freenet Client Protocol (FCP) message that represents a single feed entry sent from the node to
 * an external client.
 *
 * <p>Instances of this class carry two short textual descriptors ({@code header} and {@code
 * shortText}) and a potentially larger UTF&#8209;8 encoded body, which is stored as a {@link
 * Bucket} entry named {@code "Text"}. The binary body is handled through the multipart payload
 * support of {@link MultipleDataCarryingMessage}, so the message appears on the wire as a regular
 * FCP header followed by a sequence of payload bytes whose size is derived from the bucket
 * contents.
 *
 * <p>The feed mechanism is typically used to surface human‑readable notifications to clients, such
 * as status information or user alerts, while keeping the protocol framing consistent with other
 * data‑carrying messages. A {@code FeedMessage} is constructed on the server side shortly before it
 * is written to an output stream and is not intended to be instantiated or executed in response to
 * client input.
 *
 * <p>Thread‑safety: instances are mutable only during construction. After the constructor has
 * populated the internal bucket map the object is effectively read‑only and should be confined to a
 * single thread, typically the FCP connection handler that sends the message.
 *
 * @see MultipleDataCarryingMessage
 * @see TextFeedMessage
 * @see URIFeedMessage
 */
public class FeedMessage extends MultipleDataCarryingMessage {
  /**
   * Protocol message name used on the FCP wire for feed notifications.
   *
   * <p>This constant is returned by {@link #getName()} and is used by the {@link FCPMessage}
   * factory logic when routing decoded messages. The value is stable across releases so that
   * existing clients can register interest in feed messages by comparing against the literal {@code
   * "Feed"} string.
   */
  public static final String NAME = "Feed";

  // We assume that the header and shortText doesn't contain any newlines
  private final String header;
  private final String shortText;

  private final short priorityClass;
  private final long updatedTime;

  /**
   * Create a new feed message with the given metadata and body text.
   *
   * <p>The {@code text} argument is converted to UTF&#8209;8 bytes and stored in an {@link
   * ArrayBucket} under the key {@code "Text"}, which participates in the multipart payload managed
   * by the superclass. The {@code header} and {@code shortText} values are copied verbatim and are
   * expected not to contain newline characters so that they can be embedded safely into the textual
   * {@link SimpleFieldSet} header.
   *
   * @param header short one‑line summary displayed most prominently to the user; should not contain
   *     newline characters and may be {@code null} when no header is required.
   * @param shortText secondary summary that provides brief context; like {@code header}, this is
   *     expected to be a single line of text without embedded newlines and may be {@code null}.
   * @param text full body of the feed entry that will be sent as binary payload bytes; must be
   *     non‑{@code null} and may contain arbitrary characters, including newlines.
   * @param priorityClass numeric priority hint used by the surrounding FCP infrastructure; higher
   *     values typically indicate messages that should be delivered before lower priority entries.
   * @param updatedTime timestamp in milliseconds since the epoch indicating when the feed entry was
   *     last updated; the semantics of this value are defined by the producer of the message.
   */
  public FeedMessage(
      String header, String shortText, String text, short priorityClass, long updatedTime) {
    this.header = header;
    this.shortText = shortText;
    this.priorityClass = priorityClass;
    this.updatedTime = updatedTime;

    // The text may contain newlines
    Bucket textBucket = new ArrayBucket(text.getBytes(StandardCharsets.UTF_8));
    buckets.put("Text", textBucket);
  }

  /**
   * Build the {@link SimpleFieldSet} header that describes this feed message and its payload.
   *
   * <p>This implementation starts with the multipart payload metadata provided by {@link
   * MultipleDataCarryingMessage#getFieldSet()}, which includes individual length fields for each
   * bucket and the aggregated {@code DataLength}. It then appends feed‑specific fields such as
   * {@code Header}, {@code ShortText}, {@code PriorityClass}, and {@code UpdatedTime}. If either
   * {@code header} or {@code shortText} is {@code null}, the corresponding key is omitted from the
   * returned structure.
   *
   * @return a newly created field set describing both the multipart payload lengths and the
   *     feed‑specific metadata; callers are free to modify this instance without affecting the
   *     internal state of the message.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet fs = super.getFieldSet();
    fs.putSingle("Header", header);
    fs.putSingle("ShortText", shortText);
    fs.put("PriorityClass", priorityClass);
    fs.put("UpdatedTime", updatedTime);
    return fs;
  }

  /**
   * {@inheritDoc}
   *
   * <p>For {@code FeedMessage} this method always signals a protocol error. Feed messages are
   * designed to flow from server to client only, so receiving such a message from a client is
   * treated as invalid input. The implementation therefore throws a {@link MessageInvalidException}
   * with the {@link ProtocolErrorMessage#INVALID_MESSAGE} code and does not inspect its arguments.
   *
   * @param handler connection handler associated with the FCP session; ignored by this
   *     implementation because feed messages are not processed on the server side when received
   *     from clients.
   * @throws MessageInvalidException always thrown to indicate that {@code FeedMessage} instances
   *     must not be sent from client to server in this direction.
   */
  @Override
  public void run(FCPConnectionHandler handler) throws MessageInvalidException {
    throw new MessageInvalidException(
        ProtocolErrorMessage.INVALID_MESSAGE,
        getName() + " goes from server to client not the other way around",
        null,
        false);
  }

  /**
   * Return the FCP wire name of this message type.
   *
   * <p>The implementation simply returns the constant {@link #NAME}, allowing callers that only
   * depend on the {@link FCPMessage} abstraction to discover the concrete message identifier used
   * when serializing this instance. This value is typically written as the first line of the FCP
   * message on the connection.
   *
   * @return the literal string {@code "Feed"}, identifying this message type in FCP exchanges.
   */
  @Override
  public String getName() {
    return NAME;
  }
}

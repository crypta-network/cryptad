package network.crypta.clients.fcp;

import network.crypta.support.SimpleFieldSet;

/**
 * Abstract base class for feed messages that carry node&#8209;to&#8209;node metadata in addition to
 * the textual payload defined by {@link FeedMessage}.
 *
 * <p>The core feed infrastructure represents each entry as a {@link FeedMessage}, which provides
 * the human‑readable header, short summary, and body text transported over the Freenet Client
 * Protocol (FCP). {@code N2NFeedMessage} extends this model for notifications that originate from
 * another node in the network, attaching details about the sending peer and timestamps describing
 * how the message moved through the system.
 *
 * <p>Subclasses such as {@link TextFeedMessage}, {@link URIFeedMessage}, and {@link BookmarkFeed}
 * specialize the payload while relying on this class to keep track of when the message was
 * composed, transmitted, and received. All metadata is supplied at construction time and exposed
 * indirectly through {@link #getFieldSet()}, which encodes the node information into the outgoing
 * FCP header. Instances are effectively immutable after construction and are typically created on a
 * single thread that prepares messages for delivery to FCP clients.
 *
 * @see FeedMessage
 * @see TextFeedMessage
 * @see URIFeedMessage
 * @see BookmarkFeed
 */
public abstract class N2NFeedMessage extends FeedMessage {

  /**
   * Descriptive name of the node that sent the underlying message.
   *
   * <p>The value is written to the FCP header field {@code "SourceNodeName"} and is usually a
   * human‑readable label chosen by the remote peer. It is treated purely as display text; callers
   * should not assume uniqueness or attempt to parse structured identifiers from it.
   */
  protected final String sourceNodeName;

  /**
   * Time at which the sender composed the message, expressed in epoch milliseconds.
   *
   * <p>When this value is non‑negative it is exported in the {@code "TimeComposed"} field of the
   * {@link SimpleFieldSet} returned by {@link #getFieldSet()}. A value of {@code -1} indicates that
   * the composition time is unknown or was not supplied by the originating node.
   */
  protected final long composed;

  /**
   * Time at which the sender transmitted the message towards this node, in epoch milliseconds.
   *
   * <p>If this value is non‑negative it is written to the FCP header under the key {@code
   * "TimeSent"}. A value of {@code -1} signals that no explicit send time is available, either
   * because the sender did not provide one or because the transport layer does not expose it.
   */
  protected final long sent;

  /**
   * Time at which this node received the message, in epoch milliseconds.
   *
   * <p>When non‑negative this timestamp is exported in the {@code "TimeReceived"} field of the
   * header built by {@link #getFieldSet()}. A value of {@code -1} means that the receipt time is
   * not known, for example when older data is reconstructed without precise timing information.
   */
  protected final long received;

  /**
   * Create a new node‑to‑node feed message with timing metadata and textual content.
   *
   * <p>The textual arguments mirror those of {@link FeedMessage}: a short {@code header}, a
   * secondary {@code shortText}, and a full {@code text} body that is stored as a binary payload.
   * The {@code priorityClass} and {@code updatedTime} parameters are passed through to the
   * superclass unchanged, while {@code sourceNodeName} and the three timestamp values are retained
   * to describe the origin and life‑cycle of the message as it flows between nodes.
   *
   * @param header short one‑line summary describing the message; callers should avoid embedding
   *     newline characters because the value is placed directly into the textual FCP header and may
   *     be {@code null} when no separate title is required.
   * @param shortText secondary summary that gives additional context beyond {@code header}; like
   *     the header it is expected to be a single logical line of text and may be {@code null} if
   *     there is no distinct short description.
   * @param text full body of the feed entry that will be sent as payload bytes; this string is
   *     converted to UTF‑8 and may contain arbitrary characters, including newlines, but must not
   *     be {@code null} when constructing an instance.
   * @param priorityClass numeric priority hint used by the surrounding FCP infrastructure to order
   *     outgoing messages; higher values typically indicate entries that should be delivered before
   *     lower‑priority ones on the same connection.
   * @param updatedTime timestamp representing the last update time of the feed entry from the
   *     perspective of the sender or alerting subsystem; the concrete semantics are defined by the
   *     code that constructs the message and are not interpreted further here.
   * @param sourceNodeName human‑readable name of the node that originated the message; this value
   *     is exported in the {@code "SourceNodeName"} header field and may be {@code null} or empty
   *     when no friendly identifier is available for the peer.
   * @param composed time at which the sender composed the message content, expressed in
   *     milliseconds since the Unix epoch; use {@code -1} when the composition time is unknown or
   *     not tracked by the upstream component.
   * @param sent time at which the sender transmitted the message towards this node, also in epoch
   *     milliseconds; use {@code -1} if the transport does not expose a precise send time or if it
   *     is otherwise unavailable.
   * @param received time at which this node received the message from the network, in epoch
   *     milliseconds; a value of {@code -1} indicates that the receipt time could not be recorded
   *     or is intentionally left unspecified.
   */
  protected N2NFeedMessage(
      String header,
      String shortText,
      String text,
      short priorityClass,
      long updatedTime,
      String sourceNodeName,
      long composed,
      long sent,
      long received) {
    super(header, shortText, text, priorityClass, updatedTime);
    this.sourceNodeName = sourceNodeName;
    this.composed = composed;
    this.sent = sent;
    this.received = received;
  }

  /**
   * Build a {@link SimpleFieldSet} that describes this feed entry, including node metadata.
   *
   * <p>This implementation starts with the header produced by {@link FeedMessage#getFieldSet()},
   * which contains the textual fields and multipart payload information, then adds node‑specific
   * keys. The {@code "SourceNodeName"} entry is always included, while the {@code "TimeComposed"},
   * {@code "TimeSent"}, and {@code "TimeReceived"} fields are present only when their corresponding
   * timestamps are non‑negative.
   *
   * @return a newly created field set combining the base feed metadata with node‑to‑node timing
   *     information ready to be serialized onto the FCP connection.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet fs = super.getFieldSet();
    fs.putSingle("SourceNodeName", sourceNodeName);
    if (composed != -1) fs.put("TimeComposed", composed);
    if (sent != -1) fs.put("TimeSent", sent);
    if (received != -1) fs.put("TimeReceived", received);
    return fs;
  }
}

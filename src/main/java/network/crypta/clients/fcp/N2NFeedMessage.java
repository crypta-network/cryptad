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
   * <p>The supplied {@link N2NFeedMessageParams} bundles the base feed text fields, priority and
   * update timestamps, and the node timing metadata. The values are forwarded unchanged to the
   * superclass and stored for later serialization.
   *
   * @param params bundled feed metadata describing the text fields, priority, update time, source
   *     node name, and lifecycle timestamps for this message.
   */
  protected N2NFeedMessage(N2NFeedMessageParams params) {
    super(
        params.header(),
        params.shortText(),
        params.text(),
        params.priorityClass(),
        params.updatedTime());
    this.sourceNodeName = params.sourceNodeName();
    this.composed = params.composed();
    this.sent = params.sent();
    this.received = params.received();
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

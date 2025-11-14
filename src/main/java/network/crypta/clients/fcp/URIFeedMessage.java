package network.crypta.clients.fcp;

import java.nio.charset.StandardCharsets;
import java.util.Objects;
import network.crypta.keys.FreenetURI;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.ArrayBucket;
import network.crypta.support.io.NullBucket;

/**
 * Freenet Client Protocol (FCP) feed message that advertises a resource identified by a {@link
 * FreenetURI}.
 *
 * <p>Instances of this class are created on the server side when a peer announces content on the
 * node-to-node download feed. The message combines the generic header, short text, and body text
 * handled by {@link FeedMessage} with additional metadata describing the origin node, timestamps
 * for when the announcement was composed, sent, and received, and an optional human-readable
 * description stored as a separate payload bucket named {@code "Description"}.
 *
 * <p>The resulting feed entry is serialized as a multipart FCP message. Timing and node metadata
 * are exported through {@link #getFieldSet()}, while the URI and description are exposed as
 * standard header and payload fields that downstream FCP clients can display or process further.
 * Instances are effectively immutable after construction and are typically used on a single thread
 * responsible for writing messages to an FCP connection.
 *
 * <ul>
 *   <li>Wire name is {@link #NAME} and is returned by {@link #getName()}.
 *   <li>The {@link FreenetURI} is sent as the {@code "URI"} header value.
 *   <li>The optional description contributes to the overall {@code DataLength} alongside the main
 *       text body.
 * </ul>
 *
 * @see FeedMessage
 * @see FreenetURI
 * @see network.crypta.node.useralerts.DownloadFeedUserAlert
 */
public class URIFeedMessage extends N2NFeedMessage {
  /**
   * Protocol message name used on the FCP wire for URI feed notifications.
   *
   * <p>This literal appears as the first line of the serialized FCP message and allows clients to
   * recognize URI feed entries without depending on the concrete Java type. It is also returned by
   * {@link #getName()} so components that work with the generic {@link FCPMessage} abstraction can
   * still distinguish {@code URIFeedMessage} instances by their protocol name.
   */
  public static final String NAME = "URIFeed";

  private final FreenetURI uri;

  /**
   * Create a new URI-based feed message with node metadata and optional description text.
   *
   * <p>The textual parameters mirror those of {@link FeedMessage}. The URI is stored verbatim and
   * must be non-{@code null}; a {@link NullPointerException} is thrown if it is missing. A
   * non-{@code null} description is converted to UTF-8 bytes and stored in an {@link ArrayBucket}
   * under the key {@code "Description"}, while a {@code null} description results in a {@link
   * NullBucket} that contributes zero bytes to the overall data length.
   *
   * <p>Timestamps and source node name are exported into the {@link SimpleFieldSet} built by {@link
   * #getFieldSet()}. A value of {@code -1} for any timestamp suppresses the corresponding {@code
   * "TimeComposed"}, {@code "TimeSent"}, or {@code "TimeReceived"} field so callers can signal
   * unknown times without inventing placeholder values.
   *
   * @param header short, user-visible title shown most prominently; may be {@code null} and should
   *     not contain embedded newlines because it is copied into the textual FCP header.
   * @param shortText secondary summary providing additional context; may be {@code null} and is
   *     likewise expected to be a single logical line of text without newlines.
   * @param text full body of the feed entry to be delivered as the primary payload; must be
   *     non-{@code null} and may contain arbitrary characters, including Unicode and line breaks.
   * @param priorityClass numeric priority hint used by the FCP infrastructure when ordering
   *     outgoing messages; higher values typically indicate more urgent notifications.
   * @param updatedTime timestamp in milliseconds since the Unix epoch representing when the entry
   *     was last updated from the server's perspective; the value is forwarded unchanged.
   * @param sourceNodeName human-readable name of the peer that announced the URI; may be {@code
   *     null} or empty when no friendly identifier is available, and is exported as the {@code
   *     "SourceNodeName"} header field.
   * @param composed time at which the remote peer composed the announcement, expressed in epoch
   *     milliseconds; use {@code -1} to indicate that this information is not known.
   * @param sent time when the remote peer sent the announcement towards this node, in epoch
   *     milliseconds; {@code -1} again indicates an unknown or unavailable value.
   * @param received time when this node received the announcement from the network, in epoch
   *     milliseconds; {@code -1} suppresses the corresponding header field in {@link
   *     #getFieldSet()}.
   * @param uri target {@link FreenetURI} that identifies the advertised content; must not be {@code
   *     null} and is neither normalized nor modified by this constructor.
   * @param description optional textual description associated with the URI; when non-{@code null}
   *     it is encoded as UTF-8 bytes into a {@link Bucket} named {@code "Description"}, otherwise a
   *     {@link NullBucket} is used to represent the absence of description data.
   */
  public URIFeedMessage(
      String header,
      String shortText,
      String text,
      short priorityClass,
      long updatedTime,
      String sourceNodeName,
      long composed,
      long sent,
      long received,
      FreenetURI uri,
      String description) {
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
    this.uri = Objects.requireNonNull(uri, "uri");
    final Bucket descriptionBucket;
    if (description != null) {
      descriptionBucket = new ArrayBucket(description.getBytes(StandardCharsets.UTF_8));
    } else {
      descriptionBucket = new NullBucket();
    }
    buckets.put("Description", descriptionBucket);
  }

  /**
   * Build the FCP header for this URI feed entry.
   *
   * <p>This implementation starts with the base header produced by {@link FeedMessage#getFieldSet}
   * and then appends node and URI-specific fields. The {@code "SourceNodeName"} entry is always
   * present. The {@code "TimeComposed"}, {@code "TimeSent"}, and {@code "TimeReceived"} keys are
   * only included when their corresponding timestamps are non-negative, allowing callers to
   * distinguish between known and unknown timing information. Finally, the target URI is exported
   * as a string in the {@code "URI"} field so clients can display or follow it.
   *
   * @return a new {@link SimpleFieldSet} combining generic feed metadata, any available timing
   *     information, and the URI; callers may freely modify the returned instance without affecting
   *     the internal state of this message.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet fs = super.getFieldSet();
    fs.putSingle("URI", uri.toString());
    return fs;
  }

  /**
   * Return the protocol name for this message type.
   *
   * <p>The value matches {@link #NAME} and is used on the FCP wire as the identifier on the first
   * line of the serialized message. Keeping the name constant allows clients to reliably recognize
   * URI feed notifications even when they interact only with the abstract {@link FCPMessage}
   * hierarchy instead of this concrete class.
   *
   * @return the literal {@link #NAME} value, currently {@code "URIFeed"}.
   */
  @Override
  public String getName() {
    return NAME;
  }
}

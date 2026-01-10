package network.crypta.clients.fcp;

import java.nio.charset.StandardCharsets;
import network.crypta.keys.FreenetURI;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.ArrayBucket;
import network.crypta.support.io.NullBucket;

/**
 * Node-to-node feed message that advertises a bookmark recommendation to external FCP clients.
 *
 * <p>Instances encapsulate the full textual body exposed through {@link FeedMessage} alongside the
 * originating peer metadata and a structured bookmark payload. Typical producers are darknet peers
 * forwarding bookmark suggestions and UI alerts that render them; consumers are FCP clients that
 * monitor feed streams to mirror remote peers' bookmarks. Each object is immutable after
 * construction—the constructor computes all derived fields and the backing {@link Bucket} instances
 * remain read-only, so callers may safely hand the instance to serialization routines without
 * defensive copying.
 *
 * <p>The class focuses on accurately reporting provenance information. It stores the sending node
 * name and the timestamps describing when the recommendation was composed, sent, and received.
 * Downstream processing can therefore sort or filter entries based on message latency or recency
 * before presenting them to users. Because {@code BookmarkFeed} extends {@link FeedMessage}, it
 * participates in the same multipart payload semantics and inherits guarantees such as stable
 * bucket iteration order and deterministic data lengths.
 *
 * <ul>
 *   <li>Encapsulates bookmark metadata and peer timing data for FCP serialization.
 *   <li>Stores optional free-form descriptions as dedicated multipart buckets.
 *   <li>Produces {@link SimpleFieldSet} headers compatible with existing feed consumers.
 * </ul>
 *
 * <p>Thread-safety: construction and population are single-threaded, but the resulting object is
 * effectively immutable and may be shared between threads as long as no thread mutates the
 * inherited bucket map. All fields are final except the map inherited from {@link FeedMessage},
 * which is populated once in the constructor and then treated as read-only.
 */
public class BookmarkFeed extends N2NFeedMessage {

  /**
   * Public FCP message identifier for bookmark notifications, emitted by {@link #getName()} and
   * used by consumers to filter feed entries originating from this class. Clients monitoring {@code
   * Feed} traffic compare against this constant to decide whether to render bookmark decoration, so
   * the literal value must remain stable across protocol revisions.
   */
  public static final String NAME = "BookmarkFeed";

  private final String bookmarkTitle;
  private final FreenetURI bookmarkUri;
  private final boolean hasAnActivelink;

  /**
   * Create a bookmark feed entry populated with peer metadata, descriptive text, and bookmark
   * details ready to serialize over FCP.
   *
   * <p>The textual arguments describe what the peer recommends, while the timing parameters record
   * when the peer composed, transmitted, and delivered the message. {@code description} becomes a
   * dedicated {@link Bucket} named {@code "Description"}; if {@code null}, the bucket is replaced
   * with a {@link NullBucket} placeholder to keep payload structure stable. All supplied strings
   * are treated as display text, so callers should pre-sanitize any user-provided content.
   *
   * @param params bundled feed metadata describing the header, body text, priority, update time,
   *     source node name, and timing information for this entry.
   * @param bookmarkTitle short label for the bookmark being recommended; appears as {@code "Name"}
   *     in the outgoing field set and should not contain newlines.
   * @param bookmarkUri parsed Freenet URI pointing to the recommended resource; the constructor
   *     stores the reference and later serializes it with {@link FreenetURI#toString()}.
   * @param description optional textual description of the bookmark; when non-{@code null} it is
   *     encoded as UTF-8 bytes and shipped as the {@code "Description"} bucket.
   * @param hasAnActivelink flag signaling whether the recommendation includes a clickable link or
   *     merely informational content.
   */
  public BookmarkFeed(
      N2NFeedMessageParams params,
      String bookmarkTitle,
      FreenetURI bookmarkUri,
      String description,
      boolean hasAnActivelink) {
    super(params);
    this.bookmarkTitle = bookmarkTitle;
    this.bookmarkUri = bookmarkUri;
    this.hasAnActivelink = hasAnActivelink;
    final Bucket descriptionBucket;
    if (description != null) {
      descriptionBucket = new ArrayBucket(description.getBytes(StandardCharsets.UTF_8));
    } else {
      descriptionBucket = new NullBucket();
    }
    buckets.put("Description", descriptionBucket);
  }

  /**
   * Build the structured representation of this bookmark entry, combining inherited feed metadata
   * with node provenance and bookmark-specific fields.
   *
   * <p>The returned {@link SimpleFieldSet} is a fresh copy per invocation. It always contains the
   * base feed keys from {@link FeedMessage#getFieldSet()} plus {@code SourceNodeName}. The
   * timestamp trio is included only when their corresponding fields are non-negative, preserving
   * backward compatibility with peers that never supplied such data. Finally, the bookmark title,
   * URI, and active-link flag are appended for client consumption.
   *
   * @return mutable field set describing the entire message; callers may modify it without
   *     affecting this instance, and bucket payloads remain owned by the message.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet fs = super.getFieldSet();
    fs.putSingle("Name", bookmarkTitle);
    fs.putSingle("URI", bookmarkUri.toString());
    fs.put("HasAnActivelink", hasAnActivelink);
    return fs;
  }

  /**
   * Return the wire-level identifier for this message type, enabling FCP code to route the entry or
   * label serialized output.
   *
   * @return the constant {@link #NAME} string {@code "BookmarkFeed"}; callers must not modify the
   *     returned reference.
   */
  @Override
  public String getName() {
    return NAME;
  }
}

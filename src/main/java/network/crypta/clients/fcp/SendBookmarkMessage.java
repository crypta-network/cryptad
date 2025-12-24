package network.crypta.clients.fcp;

import java.io.IOException;
import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;
import network.crypta.keys.FreenetURI;
import network.crypta.node.DarknetPeerNode;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.io.BucketTools;

/**
 * Encapsulates the FCP message that forwards a bookmark suggestion to a darknet peer.
 *
 * <p>Instances parse a {@link SimpleFieldSet} payload received from a client connection and hold
 * the resolved {@link FreenetURI}, bookmark title, and the caller's intention about exposing an
 * active link to peers. After construction the object becomes immutable and can be safely handed to
 * the dispatch thread that interacts with {@link DarknetPeerNode} instances. Subclasses of {@link
 * SendPeerMessage} are short-lived, so this implementation avoids retaining unnecessary references
 * and directly reuses the bucket created by {@link #readFrom} in the base class. The class is not
 * thread-safe; each instance should be used by at most one handler thread.
 *
 * <p>Typical usage occurs when an FCP client requests that a bookmark be shared. The connection
 * handler creates this message with the parsed field set, invokes {@link #run} on the parent class,
 * and lets {@link #handleFeed(DarknetPeerNode)} stream the optional description to the peer. The
 * response status returned by the peer is forwarded to the client through {@link SentPeerMessage}.
 *
 * <ul>
 *   <li><strong>Responsibilities:</strong> validate inputs, prepare serialization fields, and
 *       delegate the bookmark feed to the darknet peer.
 *   <li><strong>Notable behaviors:</strong> handles both metadata-only and data-carrying requests
 *       and ensures UTF-8 decoding for human-readable descriptions.
 * </ul>
 */
public class SendBookmarkMessage extends SendPeerMessage {
  /**
   * Protocol literal clients use when emitting or filtering {@code SendBookmark} traffic, ensuring
   * that GUI tools and scripting clients consistently map the same string to this feature without
   * inspecting other metadata.
   */
  public static final String NAME = "SendBookmark";

  private final FreenetURI uri;
  private final String bookmarkName;
  private final boolean hasAnAnActiveLink;

  /**
   * Creates a bookmark message by extracting required fields from an incoming payload.
   *
   * <p>The constructor validates that a bookmark name exists, parses the {@code URI} field using
   * {@link FreenetURI}, and records whether the caller advertises an active link. The instance does
   * not read any associated bucket data here, so callers may defer payload streaming until the
   * message reaches {@link #handleFeed(DarknetPeerNode)}.
   *
   * @param fs parsed field set describing the bookmark request; must contain at least {@code Name}
   *     and {@code URI} entries in addition to the identifiers handled by {@link SendPeerMessage}.
   * @throws MessageInvalidException if the bookmark name is absent or if the URI cannot be parsed
   *     by {@link FreenetURI}, in which case the constructor propagates a descriptive protocol
   *     error.
   */
  public SendBookmarkMessage(SimpleFieldSet fs) throws MessageInvalidException {
    super(fs);
    try {
      bookmarkName = fs.get("Name");
      if (bookmarkName == null)
        throw new MessageInvalidException(
            ProtocolErrorMessage.MISSING_FIELD, "No name", identifier, false);
      uri = new FreenetURI(fs.get("URI"));
      hasAnAnActiveLink = fs.getBoolean("HasAnActivelink", false);
    } catch (MalformedURLException e) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.FREENET_URI_PARSE_ERROR, e.getMessage(), identifier, false);
    }
  }

  /**
   * Builds the outbound field set sent to the peer or echoed to clients.
   *
   * <p>The returned instance is a fresh {@link SimpleFieldSet} containing the identifier inherited
   * from {@link SendPeerMessage}, the peer reference, the bookmark name, its stringified URI, and
   * the caller's {@code HasAnActivelink} flag. Callers may freely mutate the result before it is
   * serialized back to the client connection. Because {@link SimpleFieldSet} is mutable, downstream
   * code can add debugging keys or transport hints without touching this class, which keeps
   * construction costs low and avoids additional allocations.
   *
   * @return mutable field set describing the bookmark send request, ready for serialization or
   *     further augmentation by the caller.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet fs = super.getFieldSet();
    fs.putSingle("Name", bookmarkName);
    fs.putSingle("URI", uri.toString());
    fs.put("HasAnActivelink", hasAnAnActiveLink);
    return fs;
  }

  /**
   * Returns the protocol-level name announced to clients issuing this message type.
   *
   * <p>The value allows routing logic to compare requested operations against the supported set and
   * is also used when serializing {@link SentPeerMessage} responses so clients can correlate
   * asynchronous messages with their originating command. Because the name never changes at
   * runtime, callers are free to cache it or compare it using reference equality when optimizing
   * dispatch paths.
   *
   * @return constant {@value #NAME}, enabling handlers to match requests with supported
   *     capabilities.
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Streams the bookmark details to the resolved darknet peer node.
   *
   * <p>If a payload bucket is present, the method reads it entirely, interprets it as UTF-8 text,
   * and delivers the description along with the metadata. When no payload is attached, the peer is
   * informed with a {@code null} description. The returned integer mirrors the peer status provided
   * by {@link DarknetPeerNode#sendBookmarkFeed(FreenetURI, String, String, boolean)}.
   *
   * @param pn validated darknet peer that should receive the bookmark information; never null when
   *     invoked by {@link SendPeerMessage#run}.
   * @return peer-reported status integer that will be relayed to the originating client once the
   *     send operation completes.
   * @throws MessageInvalidException if reading the payload fails with {@link IOException}, allowing
   *     the caller to surface a protocol error back to the client.
   */
  @Override
  protected int handleFeed(DarknetPeerNode pn) throws MessageInvalidException {
    try {
      if (dataLength() > 0) {
        byte[] description = BucketTools.toByteArray(bucket);
        return pn.sendBookmarkFeed(
            uri, bookmarkName, new String(description, StandardCharsets.UTF_8), hasAnAnActiveLink);
      } else return pn.sendBookmarkFeed(uri, bookmarkName, null, hasAnAnActiveLink);
    } catch (IOException _) {
      throw new MessageInvalidException(ProtocolErrorMessage.INVALID_MESSAGE, "", null, false);
    }
  }
}

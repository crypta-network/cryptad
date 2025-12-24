package network.crypta.clients.fcp;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import network.crypta.node.DarknetPeerNode;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.io.BucketTools;

/**
 * Handles text-only FCP peer messages flowing from a remote client into a {@link DarknetPeerNode}.
 *
 * <p>Instances wrap the parsed {@link SimpleFieldSet} supplied by the FCP dispatcher and translate
 * the attached data bucket into a UTF-8 string before handing it to {@link
 * DarknetPeerNode#sendTextFeed(String)}. The class is stateless and short-lived; each instance
 * processes a single inbound payload and is expected to be discarded afterward. Although the
 * transport can theoretically carry arbitrary binary blobs, this implementation enforces a text
 * contract and therefore validates that some payload bytes were provided before forwarding the
 * request.
 *
 * <p>Because the surrounding infrastructure can submit feeds from multiple threads, callers should
 * ensure they provide thread-safe {@link DarknetPeerNode} implementations. The message itself does
 * not maintain mutable state and can therefore be reused only if the caller guarantees sequential
 * access.
 *
 * <ul>
 *   <li>Responsibility: convert bucket data to text and delegate to the peer.
 *   <li>Error handling: raises {@link MessageInvalidException} when the payload is missing or when
 *       the bucket cannot be read.
 *   <li>Lifecycle: constructed, handled once via {@link #handleFeed(DarknetPeerNode)}, then
 *       eligible for garbage collection.
 * </ul>
 *
 * @see SendPeerMessage
 * @see DarknetPeerNode#sendTextFeed(String)
 */
public class SendTextMessage extends SendPeerMessage {

  /**
   * Canonical FCP message name advertised to peers when composing or dispatching SendText requests.
   */
  public static final String NAME = "SendText";

  /**
   * Creates a new handler bound to the provided field set and associated payload descriptors.
   *
   * @param fs structured fields describing the message; must include routing metadata and bucket
   *     identifiers as defined by the FCP SendText specification.
   * @throws MessageInvalidException if required fields are absent or cannot be parsed by the base
   *     {@link SendPeerMessage} constructor.
   */
  public SendTextMessage(SimpleFieldSet fs) throws MessageInvalidException {
    super(fs);
  }

  /**
   * Returns the symbolic message name used across transport negotiations and logging.
   *
   * <p>The value is constant and can be compared against {@link SimpleFieldSet} entries to quickly
   * decide whether an inbound frame should be handled by this class. Consumers must not mutate the
   * returned string and should treat it as a read-only identifier.
   *
   * @return immutable {@link String} literal {@code "SendText"} describing the supported command.
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Reads the message payload, converts it to UTF-8 text, and forwards it to the supplied peer.
   *
   * <p>The method expects that {@link #dataLength()} is strictly positive; otherwise it fails fast
   * with a {@link MessageInvalidException} to ensure empty writes are never persisted. The payload
   * is loaded fully into memory via {@link BucketTools#toByteArray} before invoking {@link
   * DarknetPeerNode#sendTextFeed(String)}, so upstream callers should avoid attaching unbounded
   * data streams. Any {@link IOException} raised while reading the bucket is translated into {@link
   * ProtocolErrorMessage#INVALID_MESSAGE} to keep protocol semantics consistent.
   *
   * @param pn peer connection that ultimately transmits the text; must support concurrent feed
   *     delivery if used by multiple SendTextMessage instances.
   * @return the status code returned from {@link DarknetPeerNode#sendTextFeed(String)}, preserving
   *     the peer's decision about success, retries, or throttling.
   * @throws MessageInvalidException if the payload is empty, unreadable, or otherwise violates the
   *     SendText contract defined by the protocol.
   */
  @Override
  protected int handleFeed(DarknetPeerNode pn) throws MessageInvalidException {
    try {
      if (dataLength() > 0) {
        byte[] text = BucketTools.toByteArray(bucket);
        return pn.sendTextFeed(new String(text, StandardCharsets.UTF_8));
      } else {
        throw new MessageInvalidException(
            ProtocolErrorMessage.INVALID_FIELD, "Invalid data length", null, false);
      }
    } catch (IOException _) {
      throw new MessageInvalidException(ProtocolErrorMessage.INVALID_MESSAGE, "", null, false);
    }
  }
}

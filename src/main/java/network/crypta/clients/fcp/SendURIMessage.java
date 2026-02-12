package network.crypta.clients.fcp;

import java.io.IOException;
import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;
import network.crypta.keys.FreenetURI;
import network.crypta.node.DarknetPeerNode;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.io.BucketTools;

/**
 * Represents the FCP message used to stream a {@link FreenetURI} request toward a darknet peer.
 *
 * <p>The message encapsulates immutable URI metadata along with an optional textual description
 * drawn from the inherited payload bucket. Callers typically construct it from a {@link
 * SimpleFieldSet} received over the wire or populate it manually before invoking outbound
 * transmission helpers on {@link SendPeerMessage}. Once created, the instance retains the parsed
 * URI and ensures that serialization back to a {@code SimpleFieldSet} reproduces the original
 * semantics so peers can authenticate and queue downloads consistently.
 *
 * <p>Senders should create a new instance per outgoing transaction, enqueue it on the peer
 * scheduler, and rely on {@link #handleFeed(DarknetPeerNode)} to forward optional descriptive text
 * while honoring UTF-8 encoding. The type performs no retries or throttling; upstream code must
 * handle pacing, persistence, and error logging. Instances are thread-safe because they expose only
 * effectively final state once construction completes.
 *
 * <ul>
 *   <li>Parses and validates URIs supplied via {@code SimpleFieldSet} structures.
 *   <li>Serializes the URI back to peers using canonical textual form.
 *   <li>Bridges optional descriptions from the inherited bucket into download feeds.
 * </ul>
 *
 * @see SendPeerMessage
 * @see DarknetPeerNode#sendDownloadFeed(FreenetURI, String)
 */
public final class SendURIMessage extends SendPeerMessage {

  /**
   * Canonical FCP command name advertised through {@link #getName()} and dispatcher lookups; must
   * remain stable for wire compatibility.
   */
  public static final String NAME = "SendURI";

  private final FreenetURI uri;

  /**
   * Constructs a message instance by extracting the target URI from an incoming field set.
   *
   * <p>The constructor performs immediate validation so malformed URIs are rejected close to the
   * network boundary. Callers should already have verified the surrounding message type, but they
   * do not need to sanitize whitespace because {@link FreenetURI#FreenetURI(String)} handles
   * canonical parsing. The underlying bucket remains untouched until {@link
   * #handleFeed(DarknetPeerNode)} is invoked, so large payloads stay in-place.
   *
   * @param fs field set containing at least one {@code URI} entry with canonical string form.
   * @throws MessageInvalidException if the {@code URI} entry is missing or fails to parse cleanly.
   */
  public SendURIMessage(SimpleFieldSet fs) throws MessageInvalidException {
    super(fs);
    try {
      uri = new FreenetURI(fs.get("URI"));
    } catch (MalformedURLException e) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.FREENET_URI_PARSE_ERROR, e.getMessage(), identifier, false);
    }
  }

  /**
   * Recreates the serialized representation for downstream transport to a remote peer.
   *
   * <p>The field set mirrors {@link SendPeerMessage}'s base values and injects the stored URI in
   * canonical text form so receiving peers can rehydrate it without ambiguity. No transient fields
   * are included, therefore the result is deterministic for identical inputs and safe to reuse as a
   * cached snapshot while preparing multiple sends.
   *
   * @return mutable {@link SimpleFieldSet} populated with basic headers plus the {@code URI} entry.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet fs = super.getFieldSet();
    fs.putSingle("URI", uri.toString());
    return fs;
  }

  /**
   * Exposes the protocol-level message identifier string shared across SendURI transmissions.
   *
   * <p>The constant name is used by dispatch tables and logging so the value must remain stable and
   * uppercase. Callers can rely on it for switch statements or to allocate queues dedicated to
   * specific FCP verbs without re-validating the payload contents.
   *
   * @return literal {@link #NAME} constant describing the SendURI protocol verb.
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Streams the URI (and optional description) to the provided peer's download feed.
   *
   * <p>The method reads the inherited payload bucket only when {@link #dataLength()} reports a
   * positive size, converts the bytes to UTF-8 text, and instructs the peer to enqueue the download
   * request. When no descriptive text is present it passes {@code null}, which the peer interprets
   * as an absence of supplementary metadata. Any {@link IOException} emitted during bucket
   * extraction is translated into {@link MessageInvalidException} to keep protocol error handling
   * uniform.
   *
   * <p>This method is not idempotent with respect to peer state; callers should invoke it exactly
   * once per outbound transaction and rely on higher layers for retries or deduplication.
   *
   * @param pn darknet peer that ultimately receives the URI and optional description, never null.
   * @return opaque code from {@link DarknetPeerNode#sendDownloadFeed(FreenetURI, String)} conveying
   *     scheduling outcomes.
   * @throws MessageInvalidException if payload bytes cannot be decoded or the peer rejects input.
   */
  @Override
  protected int handleFeed(DarknetPeerNode pn) throws MessageInvalidException {
    try {
      if (dataLength() > 0) {
        byte[] description = BucketTools.toByteArray(bucket);
        return pn.sendDownloadFeed(uri, new String(description, StandardCharsets.UTF_8));
      } else return pn.sendDownloadFeed(uri, null);
    } catch (IOException _) {
      throw new MessageInvalidException(ProtocolErrorMessage.INVALID_MESSAGE, "", null, false);
    }
  }
}

package network.crypta.clients.fcp;

import network.crypta.client.FetchResult;
import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;

/**
 * Message emitted by the node when a requested piece of data has been located and is ready for
 * delivery over FCP.
 *
 * <p>The node sends this message to whichever client issued the originating request (identified by
 * {@code Identifier}) to convey metadata about the result before the payload itself is streamed.
 * Clients typically receive {@code DataFound} followed by {@code AllData} and can use the metadata
 * to allocate buffers, update progress bars, or decline the transfer if the MIME type or size is
 * unsuitable. The message is read-only after construction and can safely be shared across threads
 * as long as the surrounding FCP infrastructure treats {@link SimpleFieldSet} instances immutably.
 *
 * <p>Lifecycle wise, this object is created on the server (node) side and never sent from a client.
 * The {@link #run(FCPConnectionHandler, Node)} method therefore always rejects inbound invocations,
 * which protects the server against malformed or malicious transmissions that attempt to mimic
 * server messages. Consumers normally only call {@link #getFieldSet()} and {@link #getName()} when
 * serializing the message to the wire. Concurrency guarantees are limited to constructor-time
 * publication; callers should not mutate returned field-set instances without copying them first.
 *
 * <ul>
 *   <li>Represents metadata about located data chunks, not the data payload itself.
 *   <li>Enforces protocol directionality by throwing whenever a client attempts to execute it.
 *   <li>Encapsulates both MIME type and timing information so UI layers can display latency stats.
 * </ul>
 *
 * @see AllDataMessage
 */
public class DataFoundMessage extends FCPMessage {
  final String requestIdentifier;
  final boolean global;
  final String mimeType;
  final long dataLength;
  final long startupTime;
  final long completionTime;

  /**
   * Creates a metadata announcement from a {@link FetchResult} produced by the node-side fetch
   * pipeline.
   *
   * <p>Use this form when a {@link FetchResult} is already available; the constructor copies only
   * the MIME type and content length because those are the pieces required by the FCP protocol. All
   * arguments are stored verbatim without validation so that upstream components remain responsible
   * for enforcing consistency. The resulting instance can be enqueued on an {@link
   * FCPConnectionHandler} immediately after construction.
   *
   * @param fr non-null {@link FetchResult} describing the located data and providing MIME metadata.
   * @param identifier stable request identifier supplied by the client when issuing the fetch.
   * @param global {@code true} when the request originated from the global pool instead of
   *     per-user.
   * @param startupTime milliseconds elapsed between request submission and lookup start.
   * @param completionTime milliseconds elapsed between lookup completion and message creation.
   */
  public DataFoundMessage(
      FetchResult fr, String identifier, boolean global, long startupTime, long completionTime) {
    this.requestIdentifier = identifier;
    this.global = global;
    this.mimeType = fr.getMimeType();
    this.dataLength = fr.size();
    this.startupTime = startupTime;
    this.completionTime = completionTime;
  }

  /**
   * Creates a metadata announcement using explicit MIME type and length values rather than a full
   * {@link FetchResult}.
   *
   * <p>This overload avoids the need to instantiate {@link FetchResult} for cases where the caller
   * already possesses normalized metadata, such as during synthetic tests or when relaying cached
   * directory entries. It mirrors the first constructor field-for-field, allowing callers to choose
   * whichever entry path better matches their data source. Timing arguments should follow the same
   * units as the primary constructor so latency statistics remain consistent across message flows.
   *
   * @param foundDataLength byte length of the located payload; must be zero or positive.
   * @param foundDataMimeType MIME type describing the payload; {@code null} means unknown/opaque.
   * @param identifier stable request identifier supplied by the client when issuing the fetch.
   * @param global {@code true} when the request originated from the global pool instead of
   *     per-user.
   * @param startupTime milliseconds elapsed between request submission and lookup start.
   * @param completionTime milliseconds elapsed between lookup completion and message creation.
   */
  public DataFoundMessage(
      long foundDataLength,
      String foundDataMimeType,
      String identifier,
      boolean global,
      long startupTime,
      long completionTime) {
    this.mimeType = foundDataMimeType;
    this.requestIdentifier = identifier;
    this.global = global;
    this.dataLength = foundDataLength;
    this.startupTime = startupTime;
    this.completionTime = completionTime;
  }

  /**
   * Builds the serialized representation delivered to clients.
   *
   * <p>The returned {@link SimpleFieldSet} contains the identifier, global flag, MIME type, data
   * length, and timing fields expected by the FCP specification. Callers should treat the returned
   * instance as immutable because it is shared directly with downstream encoders. The field names
   * intentionally match the legacy naming scheme to preserve backward compatibility with older
   * tooling.
   *
   * @return field set describing the located content; callers must not mutate it in place.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", requestIdentifier);
    fs.put("Global", global);
    fs.putSingle("Metadata.ContentType", mimeType);
    fs.put("DataLength", dataLength);
    fs.put("StartupTime", startupTime);
    fs.put("CompletionTime", completionTime);
    return fs;
  }

  /**
   * Returns the static wire identifier for this message type.
   *
   * <p>The value is always {@code DataFound}, matching the token clients expect before receiving
   * any metadata payload. Keeping this string centralized ensures that protocol writers do not
   * drift in casing or spelling, which would otherwise break client parsers relying on exact
   * matches.
   *
   * @return constant literal {@code DataFound} required by the FCP control channel.
   */
  @Override
  public String getName() {
    return "DataFound";
  }

  /**
   * Rejects attempts to process this message from the client side.
   *
   * <p>The FCP protocol defines {@code DataFound} as a server-to-client event, so any invocation of
   * this method necessarily indicates that a client tried to send the message upstream. The handler
   * therefore raises {@link MessageInvalidException} to signal a protocol violation and includes
   * the identifier plus scope flag for logging and diagnostics. There are no side effects beyond
   * the exception, and callers should expect the connection handler to close or isolate the
   * offending client.
   *
   * @param handler active connection handler attempting to execute the inbound message frame.
   * @param node node instance receiving the message; unused because execution is forbidden.
   * @throws MessageInvalidException always thrown to preserve protocol directionality semantics.
   */
  @Override
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    throw new MessageInvalidException(
        ProtocolErrorMessage.INVALID_MESSAGE,
        "DataFound goes from server to client not the other way around",
        requestIdentifier,
        global);
  }
}

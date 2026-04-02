package network.crypta.clients.fcp;

import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.Bucket;

/**
 * FCP message that transports an entire retrieved payload to a waiting client in a single transfer.
 *
 * <p>AllDataMessage is emitted by the node whenever a {@link ClientGet} succeeds with {@link
 * ClientGet.ReturnType#DIRECT} and the payload already resides in memory or temporary disk storage.
 * The message couples a fully populated {@link Bucket} with the request identifier, timestamps,
 * MIME metadata, and the {@code global} scope indicator required to resume persisted requests or
 * feed {@code ListPersistentRequests} responses.
 *
 * <p>By extending {@link DataCarryingMessage}, the class inherits streaming semantics that write
 * the bucket verbatim after its {@link #getFieldSet()} header is queued. Instances are short-lived,
 * mutable only during construction, and are not thread-safe; callers must build, send, and
 * optionally invoke {@link DataCarryingMessage#setFreeOnSent()} from a single connection-handling
 * thread while ensuring the bucket remains readable until transmission completes.
 *
 * <p>Typical responsibilities include:
 *
 * <ul>
 *   <li>Declaring the byte length so output handlers can enforce bandwidth quotas.
 *   <li>Reporting {@code startupTime} and {@code completionTime} so clients can compute latency and
 *       display progress history.
 *   <li>Providing optional {@code Metadata.ContentType} for downstream caches or UI previews that
 *       respect MIME information.
 * </ul>
 *
 * @see DataCarryingMessage
 * @see ClientGet
 */
public class AllDataMessage extends DataCarryingMessage {

  final long dataLength;
  final boolean global;
  final String identifier;
  final long startupTime;
  final long completionTime;
  final String mimeType;

  /**
   * Create an {@code AllData} response wrapper for a payload that has already been fetched and
   * buffered.
   *
   * <p>The constructor captures immutable metadata alongside the supplied {@link Bucket}. The
   * bucket is not copied; the caller retains ownership but must keep it readable until the message
   * has been serialized and optionally freed through {@link DataCarryingMessage#setFreeOnSent()}.
   * Timestamps typically mirror {@link ClientRequest#startupTime} and {@link
   * ClientRequest#completionTime}, enabling FCP clients to present stable latency metrics even when
   * responses are replayed from persistence queues.
   *
   * <pre>{@code
   * AllDataMessage msg =
   *     new AllDataMessage(bucket, identifier, global, startupTime, completionTime, mimeType);
   * msg.setFreeOnSent(); // optional: reclaim the bucket after send
   * }</pre>
   *
   * @param bucket payload bucket holding the complete bytes; must remain readable
   * @param identifier client-supplied identifier echoed in every response frame for correlation
   * @param global whether the originating request was marked global, influencing persistence
   *     routing rules
   * @param startupTime epoch milliseconds recorded when the request began processing on the node
   * @param completionTime epoch milliseconds recorded when fetching finished; zero denotes pending
   *     completion
   * @param mimeType optional MIME type string; {@code null} omits metadata header
   */
  public AllDataMessage(
      Bucket bucket,
      String identifier,
      boolean global,
      long startupTime,
      long completionTime,
      String mimeType) {
    this.bucket = bucket;
    this.dataLength = bucket.size();
    this.identifier = identifier;
    this.global = global;
    this.startupTime = startupTime;
    this.completionTime = completionTime;
    this.mimeType = mimeType;
  }

  @Override
  long dataLength() {
    return dataLength;
  }

  /**
   * Build the {@link SimpleFieldSet} header that precedes the binary payload on the wire.
   *
   * <p>The returned field set mirrors the canonical {@code AllData} header layout expected by FCP
   * clients: {@code DataLength}, {@code Identifier}, {@code Global}, {@code StartupTime}, {@code
   * CompletionTime}, and the optional {@code Metadata.ContentType}. Each invocation produces a
   * fresh instance so that callers may add list identifiers or persistence annotations without
   * mutating shared state. All numeric values are copied verbatim, leaving interpretation (for
   * example clock skew or quota enforcement) to the consumer.
   *
   * @return newly created {@link SimpleFieldSet} describing payload size, identity, and metadata
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.put("DataLength", dataLength);
    fs.putSingle("Identifier", identifier);
    fs.put("Global", global);
    fs.put("StartupTime", startupTime);
    fs.put("CompletionTime", completionTime);
    if (mimeType != null) fs.putSingle("Metadata.ContentType", mimeType);
    return fs;
  }

  /**
   * Return the FCP message name associated with this payload-bearing frame.
   *
   * <p>The {@code AllData} label is defined by the wire protocol and allows {@link
   * FCPConnectionHandler} implementations to route the message to the data streaming logic instead
   * of treating it as a purely informational response. Because this class always represents the
   * same protocol concept, the method never varies its answer and contains no side effects.
   *
   * @return constant string {@code AllData} so receiving parsers treat the payload as inline data
   */
  @Override
  public String getName() {
    return "AllData";
  }

  /**
   * Reject attempts to process an {@code AllData} message as if it had originated from a client.
   *
   * <p>This method exists because {@link FCPMessage} enforces a uniform interface for both inbound
   * and outbound frames. In practice, {@code AllData} is generated exclusively by the node, so any
   * invocation of {@code run} indicates a malformed or malicious client. The implementation
   * therefore throws {@link MessageInvalidException} with {@link
   * ProtocolErrorMessage#INVALID_MESSAGE} to ensure the request is aborted and the caller receives
   * an explicit error.
   *
   * @param handler connection handler that attempted execution; recorded only for diagnostics
   * @throws MessageInvalidException always thrown to indicate the directionality violation
   */
  @Override
  public void run(FCPConnectionHandler handler) throws MessageInvalidException {
    throw new MessageInvalidException(
        ProtocolErrorMessage.INVALID_MESSAGE,
        "AllData goes from server to client not the other way around",
        identifier,
        global);
  }

  @Override
  String getIdentifier() {
    return identifier;
  }

  @Override
  boolean isGlobal() {
    return global;
  }
}

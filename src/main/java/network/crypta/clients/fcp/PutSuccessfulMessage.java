package network.crypta.clients.fcp;

import network.crypta.keys.FreenetURI;
import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;

/**
 * Server-to-client notification indicating that an insert request completed successfully.
 *
 * <p>The message bundles the client-supplied identifier, whether the request belonged to the global
 * queue, the resulting {@link FreenetURI}, and coarse-grained timing metrics. Instances are
 * immutable and safe to reuse across threads once constructed, which allows connection handlers to
 * serialize them without additional synchronization. Downstream FCP encoders rely on the exact
 * field names produced by {@link #getFieldSet()} for compatibility with existing clients, so this
 * class focuses on faithfully mirroring the wire format rather than enforcing business logic. In
 * typical flows, the node constructs the message immediately after verifying storage and announces
 * it to the originating client before any further cleanup. Attempted execution from a client is
 * rejected by {@link #run(FCPConnectionHandler, Node)} to preserve protocol directionality and
 * protect the server from spoofed success messages.
 *
 * <ul>
 *   <li>Encapsulates the success path for FCP insert operations.
 *   <li>Provides timing hints clients can surface as latency or throughput statistics.
 *   <li>Enforces immutable state to simplify sharing between worker threads and encoders.
 * </ul>
 *
 * @see PutFailedMessage
 * @see DataFoundMessage
 */
public class PutSuccessfulMessage extends FCPMessage {

  /**
   * Stable identifier chosen by the client to correlate this success with the originating insert
   * request; retained verbatim for logging, deduplication, and UI progress tracking across
   * connection restarts.
   */
  public final String requestIdentifier;

  /**
   * Scope flag indicating whether the request belonged to the shared global queue as opposed to a
   * per-connection or per-user queue; consumers may surface it when displaying multi-tenant
   * activity or deciding where to route subsequent acknowledgements.
   */
  public final boolean global;

  /**
   * Final {@link FreenetURI} that clients can use to retrieve the inserted content; may be {@code
   * null} if the server cannot construct a stable URI, in which case the field is omitted from the
   * serialized representation.
   */
  public final FreenetURI uri;

  /**
   * Millisecond timestamp recorded near the start of the insert workflow, typically derived from
   * the node's internal clock; useful for estimating queueing or preparation latency without
   * requiring synchronized wall-clock time between peers.
   */
  public final long startupTime;

  /**
   * Millisecond timestamp captured when the insert finished and this message was prepared; clients
   * can subtract {@link #startupTime} to estimate total duration, or combine it with other metrics
   * when presenting performance summaries.
   */
  public final long completionTime;

  /**
   * Creates an immutable success notification with caller-provided identifiers, scope, URI, and
   * timing metrics.
   *
   * <p>The constructor stores every argument exactly as provided so upstream components retain full
   * control over validation, rounding, or redaction policies. Callers typically invoke it on the
   * node side once an insert finishes, then hand the instance to an {@link FCPConnectionHandler}
   * for serialization. Because the object is read-only after construction, multiple threads can
   * safely reuse it when broadcasting to mirrored clients, provided the returned {@link
   * SimpleFieldSet} from {@link #getFieldSet()} is also treated as immutable.
   *
   * @param requestIdentifier client-chosen token correlating response with originating insert
   *     request.
   * @param global {@code true} when insert used the shared global queue rather than a
   *     connection-specific channel.
   * @param uri resulting URI for stored data; may be null when unavailable.
   * @param startupTime milliseconds marking when insert processing began on the node.
   * @param completionTime milliseconds captured when insert finished and message assembled.
   */
  public PutSuccessfulMessage(
      String requestIdentifier,
      boolean global,
      FreenetURI uri,
      long startupTime,
      long completionTime) {
    this.requestIdentifier = requestIdentifier;
    this.global = global;
    this.uri = uri;
    this.startupTime = startupTime;
    this.completionTime = completionTime;
  }

  /**
   * Builds the serialized field set describing this successful insert.
   *
   * <p>The method emits a {@link SimpleFieldSet} using the canonical keys required by FCP clients:
   * {@code Identifier}, {@code Global}, optional {@code URI}, {@code StartupTime}, and {@code
   * CompletionTime}. The URI is only present when supplied at construction so that downstream
   * parsers do not encounter empty placeholders. Callers should treat the returned object as
   * immutable because it may be shared with encoder pipelines; perform a defensive copy before
   * altering any fields. No normalization occurs here, keeping responsibility for validation with
   * upstream components that know the broader request context.
   *
   * @return field set containing protocol keys for this insert success message instance.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", requestIdentifier);
    fs.put("Global", global);
    // This is useful for simple clients.
    if (uri != null) fs.putSingle("URI", uri.toString(false, false));
    fs.put("StartupTime", startupTime);
    fs.put("CompletionTime", completionTime);
    return fs;
  }

  /**
   * Returns the wire token that identifies this message type.
   *
   * <p>The literal value is fixed to {@code PutSuccessful} so encoders and decoders can rely on a
   * stable string when framing or routing FCP messages. Keeping the token centralized prevents
   * accidental drift in capitalization or spelling that might occur if callers inlined the value in
   * multiple places. The method performs no computation and is safe to invoke from any thread.
   *
   * @return constant literal {@code PutSuccessful} used on the FCP control channel.
   */
  @Override
  public String getName() {
    return "PutSuccessful";
  }

  /**
   * Rejects client-to-server execution because this message is outbound-only from the node.
   *
   * <p>By contract, {@code PutSuccessful} is produced solely by the server after completing an
   * insert. If a client attempts to send or run it, the handler raises {@link
   * MessageInvalidException} with the embedded identifier and scope for diagnostic logging. No node
   * state is mutated, and callers should expect the surrounding connection logic to handle the
   * exception, often by closing the session that originated the invalid frame. The node argument is
   * unused because the method always throws.
   *
   * @param handler active connection handler that attempted to process the inbound message frame.
   * @param node node receiving the message; present for API symmetry but not used during handling.
   * @throws MessageInvalidException always thrown to enforce protocol directionality.
   */
  @Override
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    throw new MessageInvalidException(
        ProtocolErrorMessage.INVALID_MESSAGE,
        "InsertSuccessful goes from server to client not the other way around",
        requestIdentifier,
        global);
  }
}

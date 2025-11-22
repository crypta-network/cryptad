package network.crypta.clients.fcp;

import java.io.File;
import network.crypta.clients.fcp.ClientGet.ReturnType;
import network.crypta.clients.fcp.ClientRequest.Persistence;
import network.crypta.keys.FreenetURI;
import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;

/**
 * Represents the server-to-client {@code PersistentGet} FCP message that describes a tracked
 * retrieval request. The node emits this immutable container while answering persistent-request
 * listings so a client can reconcile local state with the node table. Fields mirror the arguments
 * supplied in a {@link ClientGet} command but flow back to the client to resume monitoring or
 * decide whether to cancel stalled work.
 *
 * <p>Instances carry the request identifier, target {@link FreenetURI}, persistence setting, return
 * policy, disk target, size bounds, retry budget, binary flag, and state flags such as {@code
 * started}, {@code global}, and {@code realTime}. Values are captured at construction in {@code
 * final} fields, making the object thread-safe without additional locking.
 *
 * <p>Typical usage: the node builds one per request when replying to a listing. Clients call {@link
 * #getFieldSet()} to emit FCP wire fields or hydrate UI-facing models. Inbound execution is
 * rejected by {@link #run(FCPConnectionHandler, Node)} to enforce directionality.
 *
 * @see ClientGet
 * @see ClientRequest
 * @see FCPMessage
 */
public class PersistentGet extends FCPMessage {

  static final String NAME = "PersistentGet";

  final String messageIdentifier;
  final FreenetURI uri;
  final int verbosity;
  final short priorityClass;
  final ReturnType returnType;
  final Persistence persistence;
  final File targetFile;
  final String clientToken;
  final boolean global;
  final boolean started;
  final int maxRetries;
  final boolean binaryBlob;
  final long maxSize;
  final boolean realTime;

  /**
   * Creates a description of an existing persistent get so it can be transmitted back to a client
   * as part of a listing or resume flow. The constructor simply captures the provided values; it
   * does not perform validation beyond rejecting a {@code null} URI. Callers should therefore pass
   * values already vetted by the request scheduler. All fields become immutable snapshots that can
   * be safely shared across threads that only read request metadata.
   *
   * <pre>{@code
   * PersistentGet msg = new PersistentGet(
   *     "req-1", uri, 1, priority, ReturnType.DISK, Persistence.PERMANENT,
   *     file, "token", true, true, 5, false, 1_000_000L, false);
   * SimpleFieldSet fs = msg.getFieldSet();
   * }</pre>
   *
   * @param identifier unique message identifier that correlates responses for the requesting client
   *     session; must not be empty.
   * @param uri target {@link FreenetURI} being fetched; required and validated for non-null.
   * @param verbosity verbosity hint used by the client to tune progress or log detail levels.
   * @param priorityClass priority class applied by the scheduler; lower values typically win
   *     earlier timeslices.
   * @param returnType desired content delivery mode; may be memory or {@link ReturnType#DISK}.
   * @param persistence persistence level indicating lifetime across restarts or session ends.
   * @param targetFile absolute file path for {@link ReturnType#DISK} deliveries; ignored otherwise.
   * @param clientToken optional opaque token used by clients to correlate application-level state.
   * @param global whether the request is visible to other client connections sharing the node.
   * @param started whether the request has already been scheduled or begun transferring data.
   * @param maxRetries maximum automatic retries allowed before the node abandons the request.
   * @param binaryBlob true when binary data handling is requested instead of decoded metadata.
   * @param maxSize upper bound in bytes for the payload the client is willing to accept.
   * @param realTime whether the request participates in real-time prioritization queues.
   */
  public PersistentGet(
      String identifier,
      FreenetURI uri,
      int verbosity,
      short priorityClass,
      ReturnType returnType,
      Persistence persistence,
      File targetFile,
      String clientToken,
      boolean global,
      boolean started,
      int maxRetries,
      boolean binaryBlob,
      long maxSize,
      boolean realTime) {
    this.messageIdentifier = identifier;
    this.uri = uri;
    // This has been seen in practice (bug #3606), lets try to get an earlier stack trace...
    if (uri == null) throw new NullPointerException();
    this.verbosity = verbosity;
    this.priorityClass = priorityClass;
    this.returnType = returnType;
    this.persistence = persistence;
    this.targetFile = targetFile;
    this.clientToken = clientToken;
    this.global = global;
    this.started = started;
    this.maxRetries = maxRetries;
    this.binaryBlob = binaryBlob;
    this.maxSize = maxSize;
    this.realTime = realTime;
  }

  /**
   * Serializes this persistent get descriptor into an {@link SimpleFieldSet} suitable for
   * transmission over the FCP wire protocol. The resulting structure includes identifiers, URI,
   * verbosity, persistence, and priority metadata. When the return type is {@link ReturnType#DISK},
   * the absolute filename is also inserted so the recipient can store incoming data. Optional
   * fields such as client tokens are omitted when {@code null}, mirroring existing client parsing
   * expectations. No additional validation is performed at this stage.
   *
   * @return a newly allocated {@link SimpleFieldSet} containing the serialized message fields in
   *     node-to-client format, ready to hand to an {@link FCPConnectionHandler} for sending.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", messageIdentifier);
    fs.putSingle("URI", uri.toString(false, false));
    fs.put("Verbosity", verbosity);
    fs.putSingle("ReturnType", returnType.toString().toLowerCase());
    fs.putSingle("Persistence", persistence.toString().toLowerCase());
    if (returnType == ReturnType.DISK) {
      fs.putSingle("Filename", targetFile.getAbsolutePath());
    }
    fs.put("PriorityClass", priorityClass);
    if (clientToken != null) fs.putSingle("ClientToken", clientToken);
    fs.put("Global", global);
    fs.put("Started", started);
    fs.put("MaxRetries", maxRetries);
    fs.put("BinaryBlob", binaryBlob);
    fs.put("MaxSize", maxSize);
    fs.put("RealTime", realTime);
    return fs;
  }

  /**
   * Returns the protocol-level name of this message so connection handlers can route or log it
   * consistently. The value is constant ({@code "PersistentGet"}) and is expected to match the name
   * used when the node sends this message to clients. Keeping this method trivial ensures reliable
   * equality checks against incoming or outgoing messages without requiring additional allocations
   * or lookup tables.
   *
   * @return the invariant FCP message name string identifying a persistent get listing entry.
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Rejects attempts to run this message on the server side, because {@code PersistentGet} is
   * intended only for server-to-client flow. If a client tries to submit it, the connection handler
   * throws a {@link MessageInvalidException} explaining the directionality violation, preventing
   * accidental misuse from bypassing validation or clogging the scheduler. The error uses the
   * original identifier and global flag so the client can map the failure to its request context.
   *
   * @param handler connection handler that attempted to process the message; not used beyond error
   *     reporting.
   * @param node node instance receiving the message; present to satisfy the {@link FCPMessage}
   *     contract but unused here.
   * @throws MessageInvalidException always thrown to signal that this message must not be sent from
   *     client to server in normal operation.
   */
  @Override
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    throw new MessageInvalidException(
        ProtocolErrorMessage.INVALID_MESSAGE,
        "PersistentGet goes from server to client not the other way around",
        messageIdentifier,
        global);
  }
}

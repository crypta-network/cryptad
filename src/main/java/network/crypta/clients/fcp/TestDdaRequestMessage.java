package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;

/**
 * TestDdaRequestMessage represents the client request used to validate direct disk access (DDA)
 * permissions on a directory.
 *
 * <p>This message is parsed from the client's {@link SimpleFieldSet} and instructs the node to
 * probe whether the supplied directory can be used for read and/or write transfers. The constructor
 * ensures the directory field is present and non-empty and that at least one of the {@value
 * #WANT_READ} or {@value #WANT_WRITE} flags is true. During execution the message hands control to
 * the {@link FCPConnectionHandler}, which creates a {@link DdaCheckJob} describing the test and
 * returns a {@link TestDdaReplyMessage} so the client can confirm capabilities before requesting
 * persistent DDA sessions.
 *
 * <p>Instances are immutable after construction and are expected to be short-lived; they are not
 * reused across multiple checks. The class performs no I/O itself and is thread-confined to the
 * handler thread that calls {@link #run(FCPConnectionHandler, Node)}. Incoming field values are
 * used exactly as provided; callers should avoid reusing paths that may change between checks.
 *
 * <ul>
 *   <li>Validates client intent and basic safety assumptions.
 *   <li>Delegates the actual filesystem access probe to the connection handler.
 *   <li>Produces a deterministic reply describing allowed operations for the directory.
 * </ul>
 *
 * @see TestDdaReplyMessage
 * @see DdaCheckJob
 * @see FCPConnectionHandler
 * @author Florent Daigni&egrave;re &lt;nextgens@freenetproject.org&gt;
 */
public class TestDdaRequestMessage extends FCPMessage {

  /**
   * Message name used by the FCP router and protocol logging to recognize a client-issued DDA test
   * request; immutable constant shared by parsers and serializers to avoid drift in the wire
   * format.
   */
  public static final String NAME = "TestDDARequest";

  /**
   * Field key representing the directory path the node will probe for DDA read/write operations;
   * used consistently when parsing and when crafting replies to maintain stable wire names.
   */
  public static final String DIRECTORY = "Directory";

  /**
   * Field key signaling that the client wants to verify read access to the supplied directory
   * during the DDA probe; paired with {@link #WANT_WRITE} when both permissions are requested.
   */
  public static final String WANT_READ = "WantReadDirectory";

  /**
   * Field key signaling that the client wants to verify write access to the supplied directory
   * during the DDA probe; retained in replies so callers can correlate granted permissions.
   */
  public static final String WANT_WRITE = "WantWriteDirectory";

  final String requestedDirectory;
  final boolean wantRead;
  final boolean wantWrite;

  /**
   * Builds an instance from the incoming {@link SimpleFieldSet} provided by the FCP parser and
   * performs minimal validation before queuing the DDA check.
   *
   * <p>The constructor copies the directory path and requested access flags so the instance remains
   * immutable during processing. It rejects missing or empty {@value #DIRECTORY} values and
   * enforces that at least one of {@value #WANT_READ} or {@value #WANT_WRITE} is true, ensuring the
   * handler does not receive nonsensical work items.
   *
   * @param fs field set containing Directory, WantReadDirectory, and WantWriteDirectory entries
   *     from client.
   * @throws MessageInvalidException If required directory is missing, empty, or both access flags
   *     false.
   */
  public TestDdaRequestMessage(SimpleFieldSet fs) throws MessageInvalidException {
    requestedDirectory = fs.get(DIRECTORY);
    if (requestedDirectory == null)
      throw new MessageInvalidException(
          ProtocolErrorMessage.MISSING_FIELD, "No Directory given!", null, false);
    if (requestedDirectory.isEmpty())
      throw new MessageInvalidException(
          ProtocolErrorMessage.MISSING_FIELD,
          "The specified Directory can't be empty!",
          null,
          false);

    wantRead = fs.getBoolean(WANT_READ, false);
    wantWrite = fs.getBoolean(WANT_WRITE, false);
    if (!wantRead && !wantWrite)
      throw new MessageInvalidException(
          ProtocolErrorMessage.INVALID_MESSAGE,
          "Both "
              + WANT_READ
              + " and "
              + WANT_WRITE
              + " are set to false: what's the point of sending a message?",
          requestedDirectory,
          false);
  }

  /**
   * Returns a serialized representation of this message or {@code null} when no serialization is
   * needed.
   *
   * <p>This request type exists only in the client-to-node direction and is never emitted by the
   * node, so the implementation returns {@code null} to signal that no outbound field set should be
   * generated. Callers that log or forward messages should expect the absence of a payload and rely
   * on {@link #getName()} alone when routing or auditing.
   *
   * @return Always returns null because this request is never serialized outbound.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    return null;
  }

  /**
   * Supplies the protocol-level message identifier used to route this instance through FCP
   * handlers.
   *
   * <p>The value is constant for every instance and matches {@link #NAME}, allowing dispatchers or
   * tests to compare names without constructing additional field sets. The method is side effect
   * free and threads can call it repeatedly without synchronization because the value is immutable.
   *
   * @return Message name constant identifying a TestDDARequest on the wire protocol.
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Enqueues a directory-access check with the connection handler and emits a reply to the client.
   *
   * <p>The method delegates to {@link FCPConnectionHandler#enqueueDDACheck(String, boolean,
   * boolean)} to perform path validation and spawn a {@link DdaCheckJob}. It then wraps the job in
   * a {@link TestDdaReplyMessage} and sends it back over the same connection. The {@link Node}
   * argument is accepted for interface compatibility but is not used directly. Callers should pass
   * a handler that can manage filesystem permissions; this method does not retry and will propagate
   * validation errors as {@link MessageInvalidException}.
   *
   * @param handler connection-scoped handler responsible for scheduling DDA checks and sending
   *     replies synchronously.
   * @param node owning node instance for contextual compatibility; not dereferenced by this method.
   * @throws MessageInvalidException if handler rejects the directory or if validation fails during
   *     enqueueing.
   */
  @Override
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    DdaCheckJob job;
    try {
      job = handler.enqueueDDACheck(requestedDirectory, wantRead, wantWrite);
    } catch (IllegalArgumentException e) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.INVALID_FIELD, e.getMessage(), requestedDirectory, false);
    }
    TestDdaReplyMessage reply = new TestDdaReplyMessage(job);
    handler.send(reply);
  }
}

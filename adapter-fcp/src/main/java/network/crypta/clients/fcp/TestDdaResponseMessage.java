package network.crypta.clients.fcp;

import network.crypta.support.SimpleFieldSet;

/**
 * Handles the client-to-node {@code TestDDAResponse} FCP message that finalizes a temporary
 * direct-disk-access (DDA) capability check.
 *
 * <p>This message participates in a probe that verifies whether the client can read or write within
 * a node-provided directory. Typical flow:
 *
 * <ul>
 *   <li>Client sends {@link TestDdaRequestMessage} with desired permissions and a directory hint.
 *   <li>Node replies with file names and optional content to write.
 *   <li>Client responds with this message containing the directory and any data read back.
 *   <li>Node returns {@link TestDdaCompleteMessage} summarizing what succeeded.
 * </ul>
 *
 * <p>The class performs minimal validation of the supplied directory and read payload before
 * delegating to the handler. It remains immutable after construction, carries only the request
 * parameters, and typically runs on the connection handler thread. Use it to drive DDA diagnostics
 * or integration tests verifying directory access without mutating node state.
 *
 * @author Florent Daigni&egrave;re &lt;nextgens@freenetproject.org&gt;
 * @see TestDdaRequestMessage
 * @see TestDdaCompleteMessage
 */
public final class TestDdaResponseMessage extends FCPMessage {

  /**
   * Protocol identifier that labels this message on the wire and inside routing tables. Immutable
   * and shared across all instances, it should match the {@code Name} field observed in FCP
   * exchanges initiated by clients performing DDA tests.
   */
  public static final String NAME = "TestDDAResponse";

  /**
   * Field name carrying the data read from the temporary file created by the node during the DDA
   * probe. The value is expected to mirror the content the node placed in the file when {@link
   * TestDdaRequestMessage#WANT_READ} was set, allowing the node to confirm read access.
   */
  public static final String READ_CONTENT = "ReadContent";

  final String directory;
  final String readContent;

  /**
   * Creates the response from an incoming field set provided by the client-side parser.
   *
   * <p>The constructor performs structural validation: it requires a non-empty directory path and
   * optionally accepts the payload read from the node-provided test file. It does not touch the
   * filesystem and leaves permission evaluation to {@link #run(FCPConnectionHandler)}. The instance
   * is fully initialized after construction and can be executed immediately or queued for later
   * handling.
   *
   * @param sfs parsed fields from the FCP layer, expected to contain directory and optional read
   *     content values; must not be {@code null}.
   * @throws MessageInvalidException if required fields are missing or the directory field is an
   *     empty string after parsing.
   */
  public TestDdaResponseMessage(SimpleFieldSet sfs) throws MessageInvalidException {
    directory = sfs.get(TestDdaRequestMessage.DIRECTORY);
    if (directory == null)
      throw new MessageInvalidException(
          ProtocolErrorMessage.MISSING_FIELD, "No Directory given!", null, false);
    if (directory.isEmpty())
      throw new MessageInvalidException(
          ProtocolErrorMessage.MISSING_FIELD,
          "The specified Directory can't be empty!",
          null,
          false);

    readContent = sfs.get(READ_CONTENT);
  }

  /**
   * Returns the field set representation for outbound use.
   *
   * <p>This message is only accepted inbound during testing flows, so the outbound rendering is
   * intentionally not implemented and returns {@code null}. Callers should not attempt to resend or
   * serialize this instance directly.
   *
   * @return always {@code null} because this message is not serialized for outbound transport.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    return null;
  }

  /**
   * Reports the protocol name used to identify this message type.
   *
   * @return constant value {@link #NAME}, suitable for routing through the FCP dispatcher.
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Executes validation of the test response and triggers completion reporting to the client.
   *
   * <p>The handler is asked to look up the pending {@link DdaCheckJob} using the directory token
   * supplied at construction time. Missing or mismatched jobs raise a protocol error. When a read
   * was requested, the caller must have supplied {@link #READ_CONTENT}; otherwise a missing-field
   * error is surfaced. On success a {@link TestDdaCompleteMessage} is assembled and sent back to
   * the client to convey which operations were allowed.
   *
   * @param handler active connection handler coordinating DDA checks for this client; must not be
   *     {@code null} and must have a pending check entry for the directory.
   * @throws MessageInvalidException if the directory is unknown, required content is absent, or the
   *     handler rejects the lookup parameters.
   */
  @Override
  public void run(FCPConnectionHandler handler) throws MessageInvalidException {
    DdaCheckJob job;
    try {
      job = handler.popDDACheck(directory);
    } catch (IllegalArgumentException e) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.INVALID_FIELD, e.getMessage(), directory, false);
    }
    if (job == null)
      throw new MessageInvalidException(
          ProtocolErrorMessage.INVALID_MESSAGE,
          "The node doesn't know that testDDA identifier! double check it! (" + directory + ").",
          directory,
          false);
    else if ((job.readFilename != null) && (readContent == null))
      throw new MessageInvalidException(
          ProtocolErrorMessage.MISSING_FIELD,
          "You need to send "
              + READ_CONTENT
              + " back to the node if you specify "
              + TestDdaRequestMessage.WANT_READ
              + " in "
              + TestDdaRequestMessage.NAME
              + '.',
          directory,
          false);

    TestDdaCompleteMessage reply = new TestDdaCompleteMessage(handler, job, readContent);
    handler.send(reply);
  }
}

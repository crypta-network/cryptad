package network.crypta.clients.fcp;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.io.LegacyFileSupport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Completes a deterministic direct disk access (DDA) probe by reporting whether the node could read
 * from and write to the directory proposed by a client.
 *
 * <p>This message is sent by the node after the DDA handshake sequence finishes. During the
 * exchange the client first asks for temporary filenames, writes test content, and echoes back
 * values so the node can validate both directions of access. This class encapsulates the outcome
 * and conveys it in a compact {@link SimpleFieldSet} that the client parses before unblocking
 * further DDA usage. The instance is immutable after construction; the referenced {@link
 * DdaCheckJob} must therefore be fully populated up front. Side effects, such as deleting temporary
 * files and registering the result with the connection handler, are performed when the field set is
 * built, mirroring historical behavior.
 *
 * <p>Key characteristics:
 *
 * <ul>
 *   <li>Read/write checks are kept independent so partial success is detectable.
 *   <li>Temporary files are eagerly cleaned on the node side to avoid filesystem litter.
 *   <li>No threading guarantees are provided; callers must ensure single-threaded access per
 *       handler.
 * </ul>
 *
 * @author Florent Daigni&egrave;re &lt;nextgens@freenetproject.org&gt;
 * @see TestDdaRequestMessage
 * @see DdaCheckJob
 */
public class TestDdaCompleteMessage extends FCPMessage {
  private static final Logger LOG = LoggerFactory.getLogger(TestDdaCompleteMessage.class);

  /**
   * Canonical FCP name for the DDA completion notification, used during message registration and
   * routing. This value is stable across protocol revisions and should be reused by any new
   * implementations that interoperate with legacy clients.
   */
  public static final String NAME = "TestDDAComplete";

  /**
   * Field name set to {@code true} or {@code false} indicating whether the node successfully read
   * the client-provided test file from the negotiated directory. Callers rely on this key to decide
   * whether later DDA reads are permitted.
   */
  public static final String READ_ALLOWED = "ReadDirectoryAllowed";

  /**
   * Field name set to {@code true} or {@code false} indicating whether the node successfully
   * observed the content written by the client in the negotiated directory. A {@code true} value
   * allows future DDA writes for the same directory.
   */
  public static final String WRITE_ALLOWED = "WriteDirectoryAllowed";

  final DdaCheckJob checkJob;
  final String readContentFromClient;
  private final FCPConnectionHandler handler;

  /**
   * Creates a completion message bound to the supplied handler and DDA verification job while
   * retaining the client's echoed read content for comparison.
   *
   * <p>The constructor does not perform any validation; it merely captures the references needed
   * when the message is later serialized. Callers should ensure that {@code job.directory}, {@code
   * job.readFilename}, and {@code job.writeFilename} (when present) remain valid until {@link
   * #getFieldSet()} is invoked. The message is intended for a single use and should not be reused
   * across multiple connections.
   *
   * @param handler connection handler responsible for registering the final DDA result and routing
   *     the message; must not be {@code null}.
   * @param job prepared verification job containing the directory and temporary filenames derived
   *     from the initial request; must describe one DDA probe only.
   * @param readContent client-provided content that the node expects to read back from the
   *     temporary file; empty string indicates no read comparison is available.
   */
  public TestDdaCompleteMessage(FCPConnectionHandler handler, DdaCheckJob job, String readContent) {
    this.checkJob = job;
    this.readContentFromClient = readContent;
    this.handler = handler;
  }

  /**
   * Builds the {@link SimpleFieldSet} representation of the message, computing read/write success
   * flags and performing cleanup of temporary artifacts.
   *
   * <p>When a read filename is present, the method compares the client's echoed content with the
   * original expectation, records the boolean outcome, and deletes the temporary read file. For
   * writing checks it reads back the node-side file, compares it to the staged content, and infers
   * whether the client possessed write access. After both checks, the handler is notified so higher
   * layers can update DDA capability caches. The returned field set contains directory information
   * plus {@link #READ_ALLOWED} and {@link #WRITE_ALLOWED} keys when applicable.
   *
   * @return immutable field set containing the computed DDA verdict and directory identifier, ready
   *     for serialization to the client.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet sfs = new SimpleFieldSet(true);

    sfs.putSingle(TestDdaRequestMessage.DIRECTORY, checkJob.directory.toString());

    boolean isReadAllowed = false;
    boolean isWriteAllowed = false;

    if (checkJob.readFilename != null) {
      isReadAllowed = checkJob.readContent.equals(readContentFromClient);
      // cleanup in any case: we created it!... let's hope the client will do the same on its side.
      try {
        Files.deleteIfExists(checkJob.readFilename.toPath());
      } catch (IOException e) {
        LOG.warn("Failed to delete temporary DDA read file {}", checkJob.readFilename, e);
      }
      sfs.putSingle(READ_ALLOWED, String.valueOf(isReadAllowed));
    }

    if (checkJob.writeFilename != null) {
      File maybeWrittenFile = checkJob.writeFilename;
      if (maybeWrittenFile.exists() && maybeWrittenFile.isFile() && maybeWrittenFile.canRead()) {
        try {
          String existingContent = LegacyFileSupport.readUTF(maybeWrittenFile).toString().trim();
          isWriteAllowed = checkJob.writeContent.equals(existingContent);
        } catch (IOException e) {
          LOG.error(
              "Caught an IOE trying to read the file ({})! {}", maybeWrittenFile, e.getMessage());
        }
      }
      sfs.putSingle(WRITE_ALLOWED, String.valueOf(isWriteAllowed));
    }

    // Side effect kept for compatibility with existing DDA result propagation.
    handler.registerTestDDAResult(checkJob.directory.toString(), isReadAllowed, isWriteAllowed);

    return sfs;
  }

  /**
   * Returns the canonical name for this message type so it can be routed through the FCP dispatch
   * machinery.
   *
   * <p>The value is constant and suitable for direct comparisons or switch dispatch. Because the
   * message represents a server-to-client response, callers typically invoke this after
   * constructing the field set and before writing the frame onto the connection.
   *
   * @return message identifier string {@value #NAME} used by the FCP protocol.
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Throws unconditionally because this message is only valid in the server-to-client direction and
   * should never be executed as a client-originated command.
   *
   * <p>Any attempt to process this message via the generic execution path signals a protocol
   * misuse. The exception includes the message name, so upstream logging and diagnostics can
   * pinpoint the source frame that violated the flow. No side effects occur before throwing the
   * exception.
   *
   * @param handler connection handler that attempted to execute the message; ignored because the
   *     method always fails fast.
   * @throws MessageInvalidException always thrown to indicate the message direction is invalid.
   */
  @Override
  public void run(FCPConnectionHandler handler) throws MessageInvalidException {
    throw new MessageInvalidException(
        ProtocolErrorMessage.INVALID_MESSAGE,
        NAME + " goes from server to client not the other way around",
        NAME,
        false);
  }
}

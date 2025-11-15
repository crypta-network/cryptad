package network.crypta.clients.fcp;

import java.io.File;
import java.util.Random;
import network.crypta.support.HexUtil;

/**
 * Represents a directory access test initiated via the DDA handshake.
 *
 * <p>This job bundles the directory under scrutiny with the randomly generated filenames and
 * hexadecimal challenges that a client must echo back through the {@code TestDDA*} request/response
 * sequence. The surrounding {@link FCPConnectionHandler} enqueues the job immediately after a
 * {@link TestDdaRequestMessage} arrives and hands it to the node side of the FCP session so that
 * the handler can validate whether the peer really controls the requested filesystem subtree. Each
 * job therefore captures the server's expectation for one verification round before being retired.
 *
 * <p>The job is immutable after construction, which avoids concurrency hazards when multiple DDA
 * exchanges occur in parallel. All random data is 128 bytes long prior to hexadecimal encoding, so
 * the derived strings have deterministic size and can be logged for debugging without truncation.
 * The read filename and read content must already exist when the client is asked to fetch them,
 * while the write filename and content are only validated after the peer claims to have stored the
 * data.
 *
 * <ul>
 *   <li>Encapsulates per-request secrets so the higher levels do not re-derive entropy.
 *   <li>Provides a durable record that the {@link TestDdaReplyMessage} can include verbatim.
 * </ul>
 *
 * @see TestDdaRequestMessage
 * @see TestDdaReplyMessage
 */
public class DdaCheckJob {
  final File directory;
  final File readFilename;
  final File writeFilename;
  final String readContent;
  final String writeContent;

  DdaCheckJob(Random random, File directory, File readFilename, File writeFilename) {
    this.directory = directory;
    this.readFilename = readFilename;
    this.writeFilename = writeFilename;

    byte[] data = new byte[128];
    random.nextBytes(data);
    this.readContent = HexUtil.bytesToHex(data);

    random.nextBytes(data);
    this.writeContent = HexUtil.bytesToHex(data);
  }
}

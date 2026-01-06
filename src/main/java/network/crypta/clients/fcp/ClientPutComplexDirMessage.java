package network.crypta.clients.fcp;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;
import network.crypta.client.Metadata;
import network.crypta.clients.fcp.ClientRequest.Persistence;
import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.ManifestElement;
import network.crypta.support.io.PersistentTempBucketFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Handles the {@code ClientPutComplexDir} FCP command, enabling a client to stage and upload a
 * directory tree composed of files, nested folders, and redirect targets from multiple sources.
 *
 * <p>The message aggregates {@link DirPutFile} entries keyed by their hierarchical name, tracks
 * data that must still be read from the network connection, and ultimately produces the manifest
 * expected by {@link ClientPutDirMessage}. A single instance encapsulates one client request and is
 * therefore not thread-safe; callers construct it, stream any pending data in lexical order, and
 * hand it to {@link FCPConnectionHandler} for execution on the node.
 *
 * <p>Larger directory puts benefit from this class because it keeps metadata, MIME hints, and
 * {@link ManifestElement ManifestElements} adjacent to their payloads while enforcing sequential
 * numbering and ordering rules. Error reporting distinguishes between malformed hierarchies, access
 * restrictions, and I/O problems so the client can retry selectively.
 *
 * <ul>
 *   <li>Builds a nested {@code Map} structure that mirrors directory layout before dispatch.
 *   <li>Streams {@code UploadFrom=direct} payloads in alphabetical order to avoid buffering.
 *   <li>Validates disk-sourced files against {@link Node#getClientCore()} upload policy.
 * </ul>
 *
 * <p>Example payload:
 *
 * <pre>{@code
 * ClientPutComplexDir
 * Files.0.Name=hello.txt
 * Files.0.UploadFrom=direct
 * Files.0.DataLength=6
 * End
 * <binary payload here>
 * }</pre>
 *
 * @see ClientPutDirMessage
 * @see DirPutFile
 */
public class ClientPutComplexDirMessage extends ClientPutDirMessage {
  private static final Logger LOG = LoggerFactory.getLogger(ClientPutComplexDirMessage.class);

  /** The files attached to this message, in a directory hierarchy */
  private final HashMap<String, Object /* <HashMap || DirPutFile> */> filesByName;

  /** Any files we want to read data from */
  private final LinkedList<DirPutFile> filesToRead;

  /** Total number of bytes of attached data */
  private final long attachedBytes;

  /**
   * Creates a new message by parsing the supplied {@link SimpleFieldSet} and provisioning bucket
   * storage for any pending direct uploads.
   *
   * <p>The constructor performs all structural validation eagerly: it enforces sequential {@code
   * Files.x} numbering, builds the hierarchical lookup map used later by {@link #run}, and queues
   * {@link DirectDirPutFile} instances whose payload bytes are expected to follow the message body.
   * Bucket factories are selected according to persistence so that temporary uploads stay in fast
   * scratch storage while forever requests use disk-backed buckets.
   *
   * <pre>{@code
   * ClientPutComplexDirMessage msg =
   *     new ClientPutComplexDirMessage(fields, tempFactory, persistentFactory);
   * }</pre>
   *
   * @param fs structured field set describing {@code Files.*} entries plus metadata
   * @param bfTemp transient bucket factory for non-forever uploads and streaming buffers
   * @param bfPersistent persistent bucket factory keeping FOREVER payloads durably available
   * @throws MessageInvalidException if mandatory headers are missing or hierarchy rules break
   */
  public ClientPutComplexDirMessage(
      SimpleFieldSet fs, BucketFactory bfTemp, PersistentTempBucketFactory bfPersistent)
      throws MessageInvalidException {
    // Parse the standard ClientPutDir headers - URI, etc.
    super(fs);

    filesByName = new HashMap<>();
    filesToRead = new LinkedList<>();
    long totalBytes = 0;
    // Now parse the meat
    SimpleFieldSet files = fs.subset("Files");
    if (files == null)
      throw new MessageInvalidException(
          ProtocolErrorMessage.MISSING_FIELD, "Missing Files section", identifier, global);
    for (int i = 0; ; i++) {
      SimpleFieldSet subset = files.subset(Integer.toString(i));
      if (subset == null) break;
      DirPutFile f =
          DirPutFile.create(
              subset,
              identifier,
              global,
              (persistence == Persistence.FOREVER) ? bfPersistent : bfTemp);
      addFile(f);
      if (LOG.isDebugEnabled()) LOG.debug("Adding {}", f);
      if (f instanceof DirectDirPutFile file) {
        totalBytes += file.bytesToRead();
        filesToRead.addLast(f);
        if (LOG.isDebugEnabled()) LOG.debug("totalBytes now {}", totalBytes);
      }
    }
    attachedBytes = totalBytes;
  }

  /**
   * Add a file to the filesByName.
   *
   * @throws MessageInvalidException if the provided path collides with an existing directory entry
   */
  private void addFile(DirPutFile f) throws MessageInvalidException {
    addFile(filesByName, f.getName(), f);
  }

  private void addFile(Map<String, Object> byName, String name, DirPutFile f)
      throws MessageInvalidException {
    int idx = name.indexOf('/');
    if (idx == -1) {
      byName.put(name, f);
    } else {
      String before = name.substring(0, idx);
      String after = name.substring(idx + 1);
      Object o = byName.get(before);
      if (o != null) {
        if (o instanceof Map) {
          addFile(Metadata.forceMap(o), after, f);
        } else {
          throw new MessageInvalidException(
              ProtocolErrorMessage.INVALID_MESSAGE,
              "Cannot be both a file and a directory: " + before,
              identifier,
              global);
        }
      } else {
        HashMap<String, Object> newDir = new HashMap<>();
        byName.put(before, newDir);
        addFile(newDir, after, f);
      }
    }
  }

  static final String NAME = "ClientPutComplexDir";

  /**
   * Returns the canonical command name advertised to the FCP layer and logging facilities.
   *
   * <p>The identifier is a constant shared by every instance so routers can compare it cheaply
   * against incoming tokens and dispatch without additional allocations. It is also used by unit
   * tests to assert protocol compatibility when future versions add optional fields.
   *
   * @return constant name string that downstream {@link ClientRequest} classifiers understand
   */
  @Override
  public String getName() {
    return NAME;
  }

  @Override
  long dataLength() {
    return attachedBytes;
  }

  @SuppressWarnings("unused")
  String getIdentifier() {
    return identifier;
  }

  /**
   * Reads any {@code UploadFrom=direct} payloads from the provided stream and persists them through
   * the chosen bucket factory.
   *
   * <p>The order of reads must remain alphabetical by filename so that the streamlined sender can
   * write a single concatenated blob. Each {@link DirectDirPutFile} tracks its expected byte count,
   * and {@link MessageInvalidException} is raised if the stream ends prematurely or provides excess
   * data. The {@link FCPServer} parameter allows policy hooks to be triggered if future versions
   * need to enforce throttling or audit logging.
   *
   * @param is decoded message continuation stream containing the concatenated direct payload bytes
   * @param bf bucket factory already selected for this request, reused for direct attachments
   * @param server FCP server orchestrating the client session, never {@code null}
   * @throws IOException if the socket or bucket write fails while copying payload bytes
   * @throws MessageInvalidException if read sizes mismatch declarations or validation rejects input
   */
  @Override
  public void readFrom(InputStream is, BucketFactory bf, FCPServer server)
      throws IOException, MessageInvalidException {
    for (DirPutFile f : filesToRead) {
      ((DirectDirPutFile) f).read(is);
    }
  }

  /**
   * Writes pending {@code UploadFrom=direct} payloads to the supplied output stream in strict
   * lexical order.
   *
   * <p>This method mirrors {@link #readFrom(InputStream, BucketFactory, FCPServer)} but targets a
   * caller-supplied stream, such as a socket or bucket. It assumes that each {@link DirPutFile} has
   * already staged its data and therefore only delegates to {@link DirectDirPutFile#write} without
   * buffering. Implementations must ensure the stream honors blocking semantics because large
   * directories may emit megabytes of data per invocation.
   *
   * @param os destination stream that receives previously buffered direct-upload payloads
   * @throws IOException if writing any buffered payload fails or the stream closes unexpectedly
   */
  @Override
  protected void writeData(OutputStream os) throws IOException {
    for (DirPutFile f : filesToRead) {
      ((DirectDirPutFile) f).write(os);
    }
  }

  /**
   * Converts parsed files into {@link ManifestElement} trees and instructs the handler to start the
   * directory insert.
   *
   * <p>During execution the method validates disk-backed files through {@link Node#getClientCore()}
   * before constructing the manifest, thereby ensuring policy compliance without touching the
   * network. The resulting map mirrors the original hierarchy so downstream components can process
   * nested directories without recomputing paths. The insert begins immediately afterward, and any
   * {@link MessageInvalidException} bubbles up to the caller so the FCP client receives actionable
   * feedback.
   *
   * @param handler active connection handler responsible for initiating the put job
   * @param node node instance that supplies policy checks and storage context for the request
   * @throws MessageInvalidException if conversion detects disallowed files or inconsistent input
   */
  @Override
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    // Convert the hierarchical hashmap's of DirPutFile's to hierarchical hashmap's
    // of ManifestElement's.
    // Then simply create the ClientPutDir.
    HashMap<String, Object> manifestElements = new HashMap<>();
    convertFilesByNameToManifestElements(filesByName, manifestElements, node);
    handler.startClientPutDir(this, manifestElements, false);
  }

  /**
   * Convert a hierarchy of HashMap's containing DirPutFile's into a hierarchy of HashMap's
   * containing ManifestElement's.
   */
  private void convertFilesByNameToManifestElements(
      Map<String, Object> filesByName, HashMap<String, Object> manifestElements, Node node)
      throws MessageInvalidException {

    for (Map.Entry<String, Object> entry : filesByName.entrySet()) {
      String tempName = entry.getKey();
      Object val = entry.getValue();
      if (val instanceof HashMap) {
        Map<String, Object> h = Metadata.forceMap(val);
        HashMap<String, Object> manifests = new HashMap<>();
        manifestElements.put(tempName, manifests);
        convertFilesByNameToManifestElements(h, manifests, node);
      } else {
        DirPutFile f = (DirPutFile) val;
        if (f instanceof DiskDirPutFile file
            && !node.services().clientCore().allowUploadFrom(file.getFile()))
          throw new MessageInvalidException(
              ProtocolErrorMessage.ACCESS_DENIED,
              "Not allowed to upload " + file.getFile(),
              identifier,
              global);
        ManifestElement e = f.getElement();
        manifestElements.put(tempName, e);
      }
    }
  }
}

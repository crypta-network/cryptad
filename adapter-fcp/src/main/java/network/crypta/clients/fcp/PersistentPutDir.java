package network.crypta.clients.fcp;

import java.util.List;
import java.util.Locale;
import network.crypta.clients.fcp.ClientRequest.Persistence;
import network.crypta.keys.FreenetURI;
import network.crypta.support.HexUtil;
import network.crypta.support.SimpleFieldSet;

/**
 * Builds the wire representation of a persistent directory insert request for the FCP layer.
 *
 * <p>This helper gathers detached manifest-entry snapshots, default name, compression hints,
 * persistence expectations, and encryption material required to serialize a {@code
 * PersistentPutDir} message that the server sends back to clients. The instance is immutable after
 * construction; all data is pre-flattened into a {@link SimpleFieldSet} so callers can transmit the
 * message repeatedly without re-walking the manifest tree. Use this class when the node needs to
 * mirror a client's persistent directory insertion, for example, during reconnections or
 * resumptions where the node must restate the pending request.
 *
 * <p>Concurrency: the object contains only final fields and is thread-safe for read-only access.
 * Large manifests are supported by avoiding eager string copies where possible; however, the
 * resulting field set can still be sizable, so callers should reuse instances rather than building
 * them per sending. The class does not perform I/O beyond serializing the supplied detached entry
 * data.
 *
 * <ul>
 *   <li><strong>Responsibilities:</strong> emit stable message fields from detached manifest-entry
 *       data and attach optional metadata such as compression, retry limits, and crypto keys.
 *   <li><strong>Notable behaviors:</strong> treats redirected targets as lightweight entries and
 *       preserves the established {@code Files.N} wire layout.
 * </ul>
 */
public final class PersistentPutDir extends FCPMessage {
  private static final String NAME = "PersistentPutDir";
  private static final String UPLOAD_FROM = "UploadFrom";

  final String clientIdentifier;
  final FreenetURI uri;
  final FreenetURI privateURI;
  final int verbosity;
  final short priorityClass;
  final Persistence persistence;
  final boolean global;
  final String defaultName;
  final String token;
  final boolean started;
  final int maxRetries;
  final boolean wasDiskPut;
  private final SimpleFieldSet cached;
  final boolean dontCompress;
  final String compressorDescriptor;
  final boolean realTime;
  final byte[] splitfileCryptoKey;
  final FcpCompatibilityMode compatMode;

  /**
   * Creates a persistent directory insert message snapshot with all supporting metadata.
   *
   * <p>The constructor consumes already-detached manifest-entry snapshots and caches the resulting
   * field set so repeated invocations of {@link #getFieldSet()} are cheap. Callers should pass the
   * URIs exactly as issued by the node; no additional validation or escaping is performed here.
   *
   * @param requestParams core request identifiers, scheduling flags, and persistence settings
   * @param metadata shared persistent insert metadata such as retries and compression flags
   * @param defaultName the default filename applied to manifest entries lacking an explicit name;
   *     also used by UI layers when constructing links.
   * @param manifestEntries detached manifest-entry snapshots in the order expected by the FCP wire
   *     format
   * @param wasDiskPut whether the original request streamed from disk; affects how the node
   *     represents the upload source within the field set.
   */
  public PersistentPutDir(
      ClientRequestParams requestParams,
      PersistentPutRequestMetadata metadata,
      String defaultName,
      List<PersistentPutDirEntrySnapshot> manifestEntries,
      boolean wasDiskPut) {
    this.clientIdentifier = requestParams.identifier();
    this.uri = requestParams.uri();
    this.privateURI = metadata.privateURI();
    this.verbosity = requestParams.verbosity();
    this.priorityClass = requestParams.priorityClass();
    this.persistence = requestParams.persistence();
    this.global = requestParams.global();
    this.defaultName = defaultName;
    this.token = requestParams.clientToken();
    this.started = metadata.started();
    this.maxRetries = metadata.maxRetries();
    this.wasDiskPut = wasDiskPut;
    this.dontCompress = metadata.dontCompress();
    this.compressorDescriptor = metadata.compressorDescriptor();
    this.realTime = requestParams.realTime();
    this.splitfileCryptoKey = metadata.splitfileCryptoKey();
    this.compatMode = metadata.compatMode();
    cached = generateFieldSet(manifestEntries == null ? List.of() : manifestEntries);
  }

  private SimpleFieldSet generateFieldSet(List<PersistentPutDirEntrySnapshot> manifestEntries) {
    SimpleFieldSet fs = createBaseFieldSet();
    fs.putSingle("DefaultName", defaultName);
    fs.put("Files", createFilesFieldSet(manifestEntries));
    addOptionalFields(fs);
    return fs;
  }

  private SimpleFieldSet createBaseFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(false); // false because this can get HUGE
    fs.putSingle(IDENTIFIER, clientIdentifier);
    fs.putSingle("URI", uri.toString(false, false));
    if (privateURI != null) fs.putSingle("PrivateURI", privateURI.toString(false, false));
    fs.put("Verbosity", verbosity);
    fs.putSingle("Persistence", persistence.toString().toLowerCase(Locale.ROOT));
    fs.put("PriorityClass", priorityClass);
    fs.put("Global", global);
    fs.putSingle("PutDirType", wasDiskPut ? "disk" : "complex");
    fs.putOverwrite("CompatibilityMode", compatMode.name());
    return fs;
  }

  private SimpleFieldSet createFilesFieldSet(List<PersistentPutDirEntrySnapshot> manifestEntries) {
    SimpleFieldSet files = new SimpleFieldSet(false);
    for (int i = 0; i < manifestEntries.size(); i++) {
      files.put(Integer.toString(i), createElementFieldSet(manifestEntries.get(i)));
    }
    files.put("Count", manifestEntries.size());
    return files;
  }

  private SimpleFieldSet createElementFieldSet(PersistentPutDirEntrySnapshot entry) {
    SimpleFieldSet subset = new SimpleFieldSet(false);
    subset.putSingle("Name", entry.name());
    if (entry.uploadFrom() == ClientPutBase.UploadFrom.REDIRECT && entry.targetUri() != null) {
      subset.putSingle(UPLOAD_FROM, "redirect");
      subset.putSingle("TargetURI", entry.targetUri().toString());
      return subset;
    }
    subset.put("DataLength", entry.dataLength());
    String mimeOverride = entry.mimeTypeOverride();
    if (mimeOverride != null) {
      subset.putSingle("Metadata.ContentType", mimeOverride);
    }
    if (entry.uploadFrom() == ClientPutBase.UploadFrom.DISK) {
      subset.putSingle(UPLOAD_FROM, "disk");
      if (entry.filename() != null) {
        subset.putSingle("Filename", entry.filename());
      }
    } else if (entry.uploadFrom() == ClientPutBase.UploadFrom.DIRECT) {
      subset.putSingle(UPLOAD_FROM, "direct");
    }
    return subset;
  }

  private void addOptionalFields(SimpleFieldSet fs) {
    if (token != null) fs.putSingle("ClientToken", token);
    fs.put("Started", started);
    fs.put("MaxRetries", maxRetries);
    fs.put("DontCompress", dontCompress);
    if (compressorDescriptor != null) fs.putSingle("Codecs", compressorDescriptor);
    fs.put("RealTime", realTime);
    if (splitfileCryptoKey != null) {
      fs.putSingle("SplitfileCryptoKey", HexUtil.bytesToHex(splitfileCryptoKey));
    }
  }

  /**
   * Returns the precomputed field set representing this persistent directory insert request.
   *
   * <p>The returned {@link SimpleFieldSet} is built once during construction and reused; callers
   * must not mutate it. The structure contains a flattened manifest, upload sources, and all
   * optional control flags so it can be sent directly over FCP. Because the field set is cached, it
   * is safe to reuse this instance across reconnections or retransmissions without re-walking the
   * manifest. The object is read-only after construction, making it suitable for sharing across
   * threads that only need to serialize the data.
   *
   * @return immutable field set ready for serialization; ownership remains with this instance and
   *     should not be modified by callers.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    return cached;
  }

  /**
   * Reports the protocol name for this FCP message type.
   *
   * <p>The name is a constant required by the FCP framing layer when routing responses. It never
   * changes across instances and should match the token understood by clients listening for
   * directory insert status messages. Use this identifier when registering handlers or when logging
   * message flow so downstream consumers can correlate traffic without inspecting payloads.
   *
   * @return stable message type identifier {@code "PersistentPutDir"} for FCP exchanges.
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Rejects inbound execution because {@code PersistentPutDir} is a server-to-client message only.
   *
   * <p>If this method is invoked, the node received an invalid client request. The handler is not
   * modified; instead a {@link MessageInvalidException} is raised to signal protocol misuse. This
   * method is intentionally non-idempotent because it always throws.
   *
   * @param handler connection handler associated with the client session; not used beyond error
   *     reporting in this implementation.
   * @throws MessageInvalidException always thrown to indicate the message direction is incorrect
   *     when arriving from a client.
   */
  @Override
  public void run(FCPConnectionHandler handler) throws MessageInvalidException {
    throw new MessageInvalidException(
        ProtocolErrorMessage.INVALID_MESSAGE,
        "PersistentPut goes from server to client not the other way around",
        clientIdentifier,
        global);
  }
}

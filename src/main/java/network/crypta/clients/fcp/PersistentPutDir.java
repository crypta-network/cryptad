package network.crypta.clients.fcp;

import java.util.Map;
import network.crypta.client.InsertContext;
import network.crypta.client.async.BaseManifestPutter;
import network.crypta.clients.fcp.ClientRequest.Persistence;
import network.crypta.crypt.EncryptedRandomAccessBucket;
import network.crypta.keys.FreenetURI;
import network.crypta.node.Node;
import network.crypta.support.HexUtil;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.ManifestElement;
import network.crypta.support.io.DelayedFreeBucket;
import network.crypta.support.io.DelayedFreeRandomAccessBucket;
import network.crypta.support.io.FileBucket;
import network.crypta.support.io.NullBucket;
import network.crypta.support.io.PaddedEphemerallyEncryptedBucket;
import network.crypta.support.io.PersistentTempFileBucket;
import network.crypta.support.io.TempBucketFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Builds the wire representation of a persistent directory insert request for the FCP layer.
 *
 * <p>This helper gathers the manifest entries, default name, compression hints, persistence
 * expectations, and encryption material required to serialize a {@code PersistentPutDir} message
 * that the server sends back to clients. The instance is immutable after construction; all data is
 * pre-flattened into a {@link SimpleFieldSet} so callers can transmit the message repeatedly
 * without re-walking the manifest tree. Use this class when the node needs to mirror a client's
 * persistent directory insertion, for example during reconnects or resumptions where the node must
 * restate the pending request.
 *
 * <p>Concurrency: the object contains only final fields and is thread-safe for read-only access.
 * Large manifests are supported by avoiding eager string copies where possible; however, the
 * resulting field set can still be sizeable, so callers should reuse instances rather than building
 * them per send. The class does not perform I/O beyond inspecting the supplied buckets.
 *
 * <ul>
 *   <li><strong>Responsibilities:</strong> normalize manifest elements, emit stable message fields,
 *       attach optional metadata such as compression, retry limits, and crypto keys.
 *   <li><strong>Notable behaviors:</strong> treats redirected targets as lightweight entries and
 *       rejects unknown bucket types with a clear {@link IllegalStateException}.
 * </ul>
 *
 * @see BaseManifestPutter#flatten(Map)
 */
public class PersistentPutDir extends FCPMessage {
  private static final Logger LOG = LoggerFactory.getLogger(PersistentPutDir.class);
  private static final String NAME = "PersistentPutDir";
  private static final String UPLOAD_FROM = "UploadFrom";

  final String clientIdentifier;
  final FreenetURI uri;
  final FreenetURI privateURI;
  final int verbosity;
  final short priorityClass;
  final Persistence persistence;
  final boolean global;
  private final Map<String, Object> manifestElements;
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
  final InsertContext.CompatibilityMode compatMode;

  /**
   * Creates a persistent directory insert message snapshot with all supporting metadata.
   *
   * <p>The constructor performs the manifest flattening immediately and caches the resulting field
   * set so repeated invocations of {@link #getFieldSet()} are cheap. Callers should pass the URIs
   * exactly as issued by the node; no additional validation or escaping is performed here.
   *
   * @param clientIdentifier unique identifier that ties the message to the originating client
   *     session; may be any non-null token the client previously registered.
   * @param publicURI public {@link FreenetURI} that names the target insert; used when announcing
   *     the put to peers and to reconstruct state after restarts.
   * @param privateURI optional private {@link FreenetURI} that enables resume or cancellation for
   *     the same request; may be {@code null} when none was issued.
   * @param verbosity server verbosity level requested by the client; higher values surface more
   *     progress updates and diagnostics through FCP callbacks.
   * @param priorityClass priority band for queueing; lower numbers generally represent faster
   *     scheduling according to node policy.
   * @param persistence persistence scope chosen by the client; defines whether the request survives
   *     restarts or disconnects and maps directly to {@link Persistence} values.
   * @param global whether the request is globally scoped across the node; {@code true} keeps it
   *     active even if the originating client disconnects.
   * @param defaultName default filename applied to manifest entries lacking an explicit name; also
   *     used by UI layers when constructing links.
   * @param manifestElements flattened or hierarchical manifest elements supplied by the client; any
   *     redirect entries must include a target URI while file entries must carry data buckets.
   * @param token optional opaque token returned in progress callbacks; callers can use it to
   *     correlate asynchronous updates without inspecting request identifiers.
   * @param started whether the node should treat the request as already started, typically used
   *     during resume flows to avoid requeuing work that was previously underway.
   * @param maxRetries maximum retry attempts the node should perform for transient failures; zero
   *     disables retries while positive values cap retry loops.
   * @param dontCompress flag indicating the client disabled compression for the insert; honored as
   *     a hint when constructing splitfiles.
   * @param compressorDescriptor optional compressor descriptor string when compression is allowed;
   *     may be {@code null} to use node defaults.
   * @param wasDiskPut whether the original request streamed from disk; affects how the node
   *     represents the upload source within the field set.
   * @param realTime whether the insert participates in real-time scheduling, prioritizing latency
   *     over throughput while consuming more bandwidth headroom.
   * @param splitfileCryptoKey optional raw splitfile encryption key bytes; when provided, they are
   *     hex-encoded into the outgoing message for client consumption.
   * @param cmode compatibility mode derived from {@link InsertContext}; governs how manifests are
   *     serialized for different protocol expectations.
   */
  public PersistentPutDir(
      String clientIdentifier,
      FreenetURI publicURI,
      FreenetURI privateURI,
      int verbosity,
      short priorityClass,
      Persistence persistence,
      boolean global,
      String defaultName,
      Map<String, Object> manifestElements,
      String token,
      boolean started,
      int maxRetries,
      boolean dontCompress,
      String compressorDescriptor,
      boolean wasDiskPut,
      boolean realTime,
      byte[] splitfileCryptoKey,
      InsertContext.CompatibilityMode cmode) {
    this.clientIdentifier = clientIdentifier;
    this.uri = publicURI;
    this.privateURI = privateURI;
    this.verbosity = verbosity;
    this.priorityClass = priorityClass;
    this.persistence = persistence;
    this.global = global;
    this.defaultName = defaultName;
    this.manifestElements = manifestElements;
    this.token = token;
    this.started = started;
    this.maxRetries = maxRetries;
    this.wasDiskPut = wasDiskPut;
    this.dontCompress = dontCompress;
    this.compressorDescriptor = compressorDescriptor;
    this.realTime = realTime;
    this.splitfileCryptoKey = splitfileCryptoKey;
    this.compatMode = cmode;
    cached = generateFieldSet();
  }

  private SimpleFieldSet generateFieldSet() {
    SimpleFieldSet fs = createBaseFieldSet();
    ManifestElement[] elements = BaseManifestPutter.flatten(manifestElements);
    fs.putSingle("DefaultName", defaultName);
    fs.put("Files", createFilesFieldSet(elements));
    addOptionalFields(fs);
    return fs;
  }

  private SimpleFieldSet createBaseFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(false); // false because this can get HUGE
    fs.putSingle(IDENTIFIER, clientIdentifier);
    fs.putSingle("URI", uri.toString(false, false));
    if (privateURI != null) fs.putSingle("PrivateURI", privateURI.toString(false, false));
    fs.put("Verbosity", verbosity);
    fs.putSingle("Persistence", persistence.toString().toLowerCase());
    fs.put("PriorityClass", priorityClass);
    fs.put("Global", global);
    fs.putSingle("PutDirType", wasDiskPut ? "disk" : "complex");
    fs.putOverwrite("CompatibilityMode", compatMode.name());
    return fs;
  }

  private SimpleFieldSet createFilesFieldSet(ManifestElement[] elements) {
    SimpleFieldSet files = new SimpleFieldSet(false);
    for (int i = 0; i < elements.length; i++) {
      files.put(Integer.toString(i), createElementFieldSet(elements[i]));
    }
    files.put("Count", elements.length);
    return files;
  }

  private SimpleFieldSet createElementFieldSet(ManifestElement element) {
    SimpleFieldSet subset = new SimpleFieldSet(false);
    subset.putSingle("Name", element.getName());
    FreenetURI targetURI = element.getTargetURI();
    if (targetURI != null) {
      subset.putSingle(UPLOAD_FROM, "redirect");
      subset.putSingle("TargetURI", targetURI.toString());
      return subset;
    }
    Bucket data = unwrapBucket(element.getData());
    subset.put("DataLength", element.getSize());
    String mimeOverride = element.getMimeTypeOverride();
    if (mimeOverride != null) {
      subset.putSingle("Metadata.ContentType", mimeOverride);
    }
    populateUploadSource(subset, data, element);
    return subset;
  }

  private void populateUploadSource(SimpleFieldSet subset, Bucket data, ManifestElement element) {
    if (data == null) {
      LOG.error(
          "Bucket already freed: {} for {} for {} for {}",
          element.getData(),
          element,
          element.getName(),
          clientIdentifier);
      return;
    }
    if (data instanceof FileBucket bucket) {
      subset.putSingle(UPLOAD_FROM, "disk");
      subset.putSingle("Filename", bucket.getFile().getPath());
      return;
    }
    if (isDirectUploadBucket(data)) {
      subset.putSingle(UPLOAD_FROM, "direct");
      return;
    }
    throw new IllegalStateException("Don't know what to do with bucket: " + data);
  }

  private boolean isDirectUploadBucket(Bucket data) {
    return data instanceof PaddedEphemerallyEncryptedBucket
        || data instanceof NullBucket
        || data instanceof PersistentTempFileBucket
        || data instanceof TempBucketFactory.TempBucket
        || data instanceof EncryptedRandomAccessBucket;
  }

  private Bucket unwrapBucket(Bucket data) {
    if (data instanceof DelayedFreeBucket bucket) {
      return bucket.getUnderlying();
    }
    if (data instanceof DelayedFreeRandomAccessBucket bucket) {
      return bucket.getUnderlying();
    }
    return data;
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
   * is safe to reuse this instance across reconnects or retransmissions without re-walking the
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
   * @param node node instance that received the message; supplied for interface completeness and
   *     unchanged here.
   * @throws MessageInvalidException always thrown to indicate the message direction is incorrect
   *     when arriving from a client.
   */
  @Override
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    throw new MessageInvalidException(
        ProtocolErrorMessage.INVALID_MESSAGE,
        "PersistentPut goes from server to client not the other way around",
        clientIdentifier,
        global);
  }
}

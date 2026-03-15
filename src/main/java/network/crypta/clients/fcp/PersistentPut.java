package network.crypta.clients.fcp;

import java.io.File;
import java.util.Locale;
import network.crypta.client.InsertContext;
import network.crypta.clients.fcp.ClientPutBase.UploadFrom;
import network.crypta.clients.fcp.ClientRequest.Persistence;
import network.crypta.keys.FreenetURI;
import network.crypta.support.HexUtil;
import network.crypta.support.SimpleFieldSet;

/**
 * Represents a persistent insert description sent over the FCP channel.
 *
 * <p>This immutable message wrapper bundles the parameters describing a long-lived insert request,
 * including URIs, compression preferences, and retry behavior, so they can be serialized into a
 * {@link SimpleFieldSet} for transmission. Instances are constructed on the server side when
 * enumerating or mirroring client requests and are never executed in the inbound direction, as
 * {@link #run(FCPConnectionHandler)} always rejects client-sourced messages.
 *
 * <p>Use this type when a caller needs to:
 *
 * <ul>
 *   <li>Report the state of an insert back to an FCP client.
 *   <li>Preserve the identifiers and upload the source used during request creation.
 *   <li>Emit metadata such as MIME type, compression codecs, and crypto keys alongside persistence
 *       settings.
 * </ul>
 *
 * <p>All fields are final, making the instances thread-safe to publish and reuse across handlers.
 * Optional attributes accept {@code null} values to keep the serialized payload compact when data
 * is unavailable.
 */
public class PersistentPut extends FCPMessage {

  static final String NAME = "PersistentPut";

  final String requestIdentifier;
  final FreenetURI uri;
  final FreenetURI privateURI;
  final int verbosity;
  final short priorityClass;
  final UploadFrom uploadFrom;
  final Persistence persistence;
  final File origFilename;
  final String mimeType;
  final boolean global;
  final FreenetURI targetURI;
  final long size;
  final String token;
  final boolean started;
  final int maxRetries;
  final String targetFilename;
  final boolean binaryBlob;
  final InsertContext.CompatibilityMode compatMode;
  final boolean dontCompress;
  final boolean realTime;
  final byte[] splitfileCryptoKey;
  final String compressorDescriptor;

  /**
   * Creates a {@code PersistentPut} message populated with the supplied insert parameters.
   *
   * <p>The constructor performs no additional validation beyond assigning the provided values, so
   * callers must ensure that the public and private URIs, upload source, and persistence level are
   * consistent with the originating request. Optional properties such as filenames, MIME type, and
   * compression descriptor may be {@code null} and will be omitted when {@link #getFieldSet()}
   * serializes the message. The splitfile crypto key and compatibility mode are stored verbatim so
   * downstream components can honor the client's encryption and codec expectations.
   *
   * @param requestParams core request identifiers, scheduling flags, and persistence settings
   * @param upload upload metadata describing the payload source and MIME hints
   * @param metadata shared persistent insert metadata such as retry and compression flags
   * @param size content length in bytes, or {@code -1} when unspecified
   */
  public PersistentPut(
      ClientRequestParams requestParams,
      ClientPutUpload upload,
      PersistentPutRequestMetadata metadata,
      long size) {
    this.requestIdentifier = requestParams.identifier();
    this.uri = requestParams.uri();
    this.privateURI = metadata.privateURI();
    this.verbosity = requestParams.verbosity();
    this.priorityClass = requestParams.priorityClass();
    this.uploadFrom = upload.uploadFromType();
    this.targetURI = upload.redirectTarget();
    this.persistence = requestParams.persistence();
    this.origFilename = upload.origFilename();
    this.mimeType = upload.contentType();
    this.global = requestParams.global();
    this.size = size;
    this.token = requestParams.clientToken();
    this.started = metadata.started();
    this.maxRetries = metadata.maxRetries();
    this.targetFilename = upload.targetFilename();
    this.binaryBlob = upload.binaryBlob();
    this.compatMode = metadata.compatMode();
    this.dontCompress = metadata.dontCompress();
    this.compressorDescriptor = metadata.compressorDescriptor();
    this.realTime = requestParams.realTime();
    this.splitfileCryptoKey = metadata.splitfileCryptoKey();
  }

  /**
   * Serializes the persistent insert description into an {@link SimpleFieldSet}.
   *
   * <p>The resulting structure contains only the populated attributes, preserving optional fields
   * such as private URIs, filenames, and codec descriptors when present while omitting them when
   * null. Boolean flags mirror the constructor values verbatim, allowing downstream consumers to
   * reconstruct the original request intent without altering defaults or applying extra policy. Any
   * provided splitfile crypto key is hex-encoded to ensure safe transport in the textual field-set
   * representation used by the FCP wire format.
   *
   * @return immutable {@code SimpleFieldSet} snapshot ready for transmission to clients
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", requestIdentifier);
    fs.putSingle("URI", uri.toString(false, false));
    if (privateURI != null) fs.putSingle("PrivateURI", privateURI.toString(false, false));
    fs.put("Verbosity", verbosity);
    fs.put("PriorityClass", priorityClass);
    fs.putSingle("UploadFrom", uploadFrom.toString().toLowerCase(Locale.ROOT));
    fs.putSingle("Persistence", persistence.toString().toLowerCase(Locale.ROOT));
    if (origFilename != null) fs.putSingle("Filename", origFilename.getAbsolutePath());
    if (targetURI != null) fs.putSingle("TargetURI", targetURI.toString());
    if (mimeType != null) fs.putSingle("Metadata.ContentType", mimeType);
    fs.put("Global", global);
    if (size != -1) fs.put("DataLength", size);
    if (token != null) fs.putSingle("ClientToken", token);
    fs.put("Started", started);
    fs.put("MaxRetries", maxRetries);
    if (targetFilename != null) fs.putSingle("TargetFilename", targetFilename);
    if (binaryBlob) fs.put("BinaryBlob", true);
    fs.putOverwrite("CompatibilityMode", compatMode.name());
    fs.put("DontCompress", dontCompress);
    if (compressorDescriptor != null) fs.putSingle("Codecs", compressorDescriptor);
    fs.put("RealTime", realTime);
    if (splitfileCryptoKey != null)
      fs.putSingle("SplitfileCryptoKey", HexUtil.bytesToHex(splitfileCryptoKey));
    return fs;
  }

  /**
   * Returns the protocol-level name for this FCP message type.
   *
   * <p>The value is constant ({@code "PersistentPut"}) and is used when encoding the message onto
   * the wire or when matching inbound message types. It does not vary with request parameters and
   * can be safely cached by protocol dispatchers.
   *
   * @return stable message type identifier expected by the FCP protocol
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Rejects inbound attempts to execute a {@code PersistentPut} from a client.
   *
   * <p>This message is intended to flow from the server to the client when describing existing
   * persistent insert requests; executing it in the opposite direction would represent a protocol
   * error. Consequently, this method always throws {@link MessageInvalidException} to signal the
   * invalid direction while preserving the identifier and global flag for diagnostics.
   *
   * @param handler connection handler that attempted to process the message
   * @throws MessageInvalidException always thrown to indicate the invalid message direction
   */
  @Override
  public void run(FCPConnectionHandler handler) throws MessageInvalidException {
    throw new MessageInvalidException(
        ProtocolErrorMessage.INVALID_MESSAGE,
        "PersistentPut goes from server to client not the other way around",
        requestIdentifier,
        global);
  }
}

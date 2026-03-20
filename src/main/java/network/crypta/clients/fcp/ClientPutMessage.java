package network.crypta.clients.fcp;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.util.Locale;
import network.crypta.client.HighLevelSimpleClientImpl;
import network.crypta.client.InsertContext;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.clients.fcp.ClientPutBase.UploadFrom;
import network.crypta.clients.fcp.ClientRequest.Persistence;
import network.crypta.keys.FreenetURI;
import network.crypta.node.Node;
import network.crypta.node.RequestStarter;
import network.crypta.support.HexUtil;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.compress.Compressor.COMPRESSOR_TYPE;
import network.crypta.support.compress.InvalidCompressionCodecException;
import network.crypta.support.io.FileBucket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents a fully parsed ClientPut request flowing over the FCP control connection.
 *
 * <p>Each instance is constructed once the peer's {@link SimpleFieldSet} payload passes validation,
 * capturing the destination {@link FreenetURI}, persistence policy, upload mode, and optional hints
 * such as compressor descriptors or redirect targets. The parsed structure is passed to the server
 * pipeline, so payload streaming, request accounting, and insert scheduling can start immediately
 * without repeatedly decoding textual headers.
 *
 * <p>The object is effectively immutable after construction because all exposed fields are final
 * and the payload bucket reference is managed by {@link DataCarryingMessage}. This design makes it
 * safe for worker threads to hand the message between parser, queueing, and insert components
 * without additional locking beyond the bucket lifecycle hooks.
 *
 * <ul>
 *   <li>Validates metadata (URI, identifiers, persistence, compression, and file hints).
 *   <li>Describes how payload bytes will be supplied (inline, disk file, or redirect).
 *   <li>Exposes helper accessors for handler code invoked by {@link FCPConnectionHandler}.
 * </ul>
 *
 * @see ClientPutBase
 * @see ClientRequest
 * @see HighLevelSimpleClientImpl
 */
public final class ClientPutMessage extends DataCarryingMessage {
  private static final Logger LOG = LoggerFactory.getLogger(ClientPutMessage.class);

  /**
   * Canonical FCP verb string for this message, reused by {@link #getName()} and server routing so
   * that client responses, logging, and protocol negotiation remain stable across releases.
   */
  public static final String NAME = "ClientPut";

  private static final String FIELD_UPLOAD_FROM = "UploadFrom";
  private static final String FIELD_DATA_LENGTH = "DataLength";
  private static final String FIELD_VERBOSITY = "Verbosity";

  final FreenetURI uri;
  final String contentType;
  final long payloadLength;
  final String identifier;
  final int verbosity;
  final int maxRetries;
  final boolean getCHKOnly;
  final short priorityClass;
  final Persistence persistence;
  final UploadFrom uploadFromType;

  /**
   * The hash of the file you want the node to deal with. It is MANDATORY to do DDA operations and
   * should be computed like that:
   *
   * <p>Base64Encode(SHA256( Handler.connectionIdentifer + ClientPutMessage.identifier + content))
   */
  final String fileHash;

  final boolean dontCompress;
  final String clientToken;
  final File origFilename;
  final boolean global;
  final FreenetURI redirectTarget;

  /** Filename (hint for the final filename) */
  final String targetFilename;

  final boolean earlyEncode;
  final boolean binaryBlob;
  final boolean canWriteClientCache;
  final String compressorDescriptor;
  final boolean forkOnCacheable;
  final int extraInsertsSingleBlock;
  final int extraInsertsSplitfileHeaderBlock;
  final InsertContext.CompatibilityMode compatibilityMode;
  final byte[] overrideSplitfileCryptoKey;
  final boolean localRequestOnly;
  final boolean realTimeFlag;
  final long metadataThreshold;
  final boolean ignoreUSKDatehints;

  /**
   * Parses a raw {@link SimpleFieldSet} describing a ClientPut request and builds an immutable
   * representation.
   *
   * <p>This constructor validates every user-supplied field, normalizes defaults, and eagerly
   * derives helper information such as upload source, compressor descriptors, and inferred
   * filenames. It accepts inserts ranging from small inline payloads to multi-gigabyte redirected
   * streams, and throws {@link MessageInvalidException} as soon as a constraint violation surfaces
   * so the caller can reply with the appropriate protocol error. Callers should invoke it once per
   * inbound message on the parsing thread before handing the resulting instance to worker queues.
   *
   * @param fs parsed field set containing client-provided headers and numeric properties for the
   *     insert request
   * @throws MessageInvalidException if any required field is missing, contradictory, malformed, or
   *     violates node policy choices
   */
  public ClientPutMessage(SimpleFieldSet fs) throws MessageInvalidException {
    identifier = fs.get("Identifier");
    binaryBlob = fs.getBoolean("BinaryBlob", false);
    global = fs.getBoolean("Global", false);
    localRequestOnly = fs.getBoolean("LocalRequestOnly", false);
    compatibilityMode = parseCompatibilityMode(fs, identifier, global);
    String overrideKeyRaw = fs.get("OverrideSplitfileCryptoKey");
    overrideSplitfileCryptoKey =
        overrideKeyRaw == null
            ? null
            : decodeOverrideSplitfileCryptoKey(overrideKeyRaw, identifier, global);
    if (identifier == null)
      throw new MessageInvalidException(
          ProtocolErrorMessage.MISSING_FIELD, "No Identifier", null, global);
    UriParseResult uriParseResult = parseUri(fs, binaryBlob, identifier, global);
    uri = uriParseResult.uri();
    String filenameHint = uriParseResult.filenameHint();

    verbosity =
        parseOptionalIntOrZero(fs.get(FIELD_VERBOSITY), FIELD_VERBOSITY, identifier, global);
    contentType = fs.get("Metadata.ContentType");
    maxRetries = parseOptionalIntOrZero(fs.get("MaxRetries"), "MaxSize", identifier, global);
    getCHKOnly = fs.getBoolean("GetCHKOnly", false);
    priorityClass = parsePriorityClass(fs.get("PriorityClass"), identifier, global);

    fileHash = fs.get(ClientPutBase.FILE_HASH);

    UploadConfig uploadConfig = parseUploadSource(fs, identifier, global, filenameHint, uri);
    payloadLength = uploadConfig.length();
    uploadFromType = uploadConfig.type();
    origFilename = uploadConfig.originalFile();
    redirectTarget = uploadConfig.redirectTarget();
    filenameHint = uploadConfig.filenameHint();

    dontCompress = fs.getBoolean("DontCompress", false);
    persistence = Persistence.parseOrThrow(fs.get("Persistence"), identifier, global);
    canWriteClientCache = fs.getBoolean("WriteToClientCache", false);
    clientToken = fs.get("ClientToken");
    targetFilename =
        resolveTargetFilename(fs.get("TargetFilename"), filenameHint, uri, identifier, global);
    earlyEncode = fs.getBoolean("EarlyEncode", false);
    compressorDescriptor = parseCompressorDescriptor(fs.get("Codecs"), identifier, global);
    if (fs.get("ForkOnCacheable") != null)
      forkOnCacheable = fs.getBoolean("ForkOnCacheable", false);
    else forkOnCacheable = Node.FORK_ON_CACHEABLE_DEFAULT;
    extraInsertsSingleBlock =
        fs.getInt("ExtraInsertsSingleBlock", HighLevelSimpleClientImpl.EXTRA_INSERTS_SINGLE_BLOCK);
    extraInsertsSplitfileHeaderBlock =
        fs.getInt(
            "ExtraInsertsSplitfileHeaderBlock",
            HighLevelSimpleClientImpl.EXTRA_INSERTS_SPLITFILE_HEADER);
    realTimeFlag = fs.getBoolean("RealTimeFlag", false);
    metadataThreshold = fs.getLong("MetadataThreshold", -1);
    ignoreUSKDatehints = fs.getBoolean("IgnoreUSKDatehints", false);
  }

  private static InsertContext.CompatibilityMode parseCompatibilityMode(
      SimpleFieldSet fs, String identifier, boolean global) throws MessageInvalidException {
    String s = fs.get("CompatibilityMode");
    InsertContext.CompatibilityMode cmode;
    if (s == null) {
      cmode = InsertContext.CompatibilityMode.COMPAT_DEFAULT;
    } else {
      try {
        cmode = InsertContext.CompatibilityMode.valueOf(s);
      } catch (IllegalArgumentException _) {
        try {
          cmode = InsertContext.CompatibilityMode.byCode((short) Integer.parseInt(s));
        } catch (NumberFormatException _) {
          throw new MessageInvalidException(
              ProtocolErrorMessage.INVALID_FIELD,
              "Invalid CompatibilityMode (not a name and not a number)",
              identifier,
              global);
        } catch (IllegalArgumentException _) {
          throw new MessageInvalidException(
              ProtocolErrorMessage.INVALID_FIELD,
              "Invalid CompatibilityMode (not a valid number)",
              identifier,
              global);
        }
      }
    }
    return cmode.intern();
  }

  private static byte[] decodeOverrideSplitfileCryptoKey(
      String rawKey, String identifier, boolean global) throws MessageInvalidException {
    try {
      return HexUtil.hexToBytes(rawKey);
    } catch (NumberFormatException _) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.INVALID_FIELD,
          "Invalid splitfile crypto key (not hex)",
          identifier,
          global);
    } catch (IndexOutOfBoundsException _) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.INVALID_FIELD,
          "Invalid splitfile crypto key (too short)",
          identifier,
          global);
    }
  }

  private static UriParseResult parseUri(
      SimpleFieldSet fs, boolean binaryBlob, String identifier, boolean global)
      throws MessageInvalidException {
    if (binaryBlob) {
      try {
        return new UriParseResult(new FreenetURI("CHK@"), null);
      } catch (MalformedURLException e) {
        throw new MessageInvalidException(
            ProtocolErrorMessage.FREENET_URI_PARSE_ERROR, e.getMessage(), identifier, global);
      }
    }
    String u = fs.get("URI");
    if (u == null)
      throw new MessageInvalidException(
          ProtocolErrorMessage.MISSING_FIELD, "No URI", identifier, global);
    try {
      FreenetURI parsed = new FreenetURI(u);
      String[] metas = parsed.getAllMetaStrings();
      if (metas != null && metas.length == 1) {
        String fnam = metas[0];
        parsed = parsed.setMetaString(null);
        return new UriParseResult(parsed, fnam);
      }
      return new UriParseResult(parsed, null);
    } catch (MalformedURLException e) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.FREENET_URI_PARSE_ERROR, e.getMessage(), identifier, global);
    }
  }

  private static int parseOptionalIntOrZero(
      String rawValue, String errorFieldName, String identifier, boolean global)
      throws MessageInvalidException {
    if (rawValue == null) {
      return 0;
    }
    try {
      return Integer.parseInt(rawValue, 10);
    } catch (NumberFormatException e) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.ERROR_PARSING_NUMBER,
          "Error parsing " + errorFieldName + " field: " + e.getMessage(),
          identifier,
          global);
    }
  }

  private static short parsePriorityClass(String priorityString, String identifier, boolean global)
      throws MessageInvalidException {
    if (priorityString == null) {
      return RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS;
    }
    try {
      short parsed = Short.parseShort(priorityString);
      if (!RequestStarter.isValidPriorityClass(parsed)) {
        throw new MessageInvalidException(
            ProtocolErrorMessage.INVALID_FIELD,
            "Invalid priority class "
                + parsed
                + " - range is "
                + RequestStarter.PAUSED_PRIORITY_CLASS
                + " to "
                + RequestStarter.MAXIMUM_PRIORITY_CLASS,
            identifier,
            global);
      }
      return parsed;
    } catch (NumberFormatException e) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.ERROR_PARSING_NUMBER,
          "Error parsing PriorityClass field: " + e.getMessage(),
          identifier,
          global);
    }
  }

  private UploadConfig parseUploadSource(
      SimpleFieldSet fs,
      String identifier,
      boolean global,
      String filenameHint,
      FreenetURI parsedUri)
      throws MessageInvalidException {
    String uploadFrom = fs.get(FIELD_UPLOAD_FROM);
    if (uploadFrom == null || uploadFrom.equalsIgnoreCase("direct")) {
      long length = parseDataLength(fs, identifier, global);
      return new UploadConfig(length, UploadFrom.DIRECT, null, null, filenameHint);
    }
    if (uploadFrom.equalsIgnoreCase("disk")) {
      String filename = fs.get("Filename");
      if (filename == null)
        throw new MessageInvalidException(
            ProtocolErrorMessage.MISSING_FIELD, "Missing field Filename", identifier, global);
      File f = new File(filename);
      if (!(f.exists() && f.isFile() && f.canRead()))
        throw new MessageInvalidException(
            ProtocolErrorMessage.FILE_NOT_FOUND, null, identifier, global);
      bucket = new FileBucket(f, true, false, false, false);
      String resolvedName = filenameHint;
      if (resolvedName == null && shouldInferDiskFilenameHint(parsedUri)) {
        resolvedName = f.getName();
      }
      return new UploadConfig(f.length(), UploadFrom.DISK, f, null, resolvedName);
    }
    if (uploadFrom.equalsIgnoreCase("redirect")) {
      FreenetURI target = parseRedirectTarget(fs.get("TargetURI"), identifier, global);
      bucket = null;
      return new UploadConfig(0, UploadFrom.REDIRECT, null, target, filenameHint);
    }
    throw new MessageInvalidException(
        ProtocolErrorMessage.INVALID_FIELD,
        "UploadFrom invalid or unrecognized: " + uploadFrom,
        identifier,
        global);
  }

  private static long parseDataLength(SimpleFieldSet fs, String identifier, boolean global)
      throws MessageInvalidException {
    String dataLengthString = fs.get(FIELD_DATA_LENGTH);
    if (dataLengthString == null)
      throw new MessageInvalidException(
          ProtocolErrorMessage.MISSING_FIELD, "Need DataLength on a ClientPut", identifier, global);
    try {
      return Long.parseLong(dataLengthString, 10);
    } catch (NumberFormatException e) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.ERROR_PARSING_NUMBER,
          "Error parsing DataLength field: " + e.getMessage(),
          identifier,
          global);
    }
  }

  private static FreenetURI parseRedirectTarget(String rawTarget, String identifier, boolean global)
      throws MessageInvalidException {
    if (rawTarget == null)
      throw new MessageInvalidException(
          ProtocolErrorMessage.MISSING_FIELD,
          "TargetURI missing but UploadFrom=redirect",
          identifier,
          global);
    try {
      return new FreenetURI(rawTarget);
    } catch (MalformedURLException e) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.INVALID_FIELD, "Invalid TargetURI: " + e, identifier, global);
    }
  }

  private String resolveTargetFilename(
      String targetOverride,
      String inferredName,
      FreenetURI parsedUri,
      String identifier,
      boolean global)
      throws MessageInvalidException {
    String candidate = targetOverride != null ? targetOverride : inferredName;
    if (candidate != null && candidate.indexOf('/') > -1) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.INVALID_FIELD,
          "TargetFilename must not contain slashes",
          identifier,
          global);
    }
    if (candidate != null && candidate.isEmpty()) {
      candidate = null;
    }
    if (parsedUri.getRoutingKey() == null && !parsedUri.isKSK()) {
      return candidate;
    }
    return null;
  }

  private static String parseCompressorDescriptor(String codecs, String identifier, boolean global)
      throws MessageInvalidException {
    if (codecs == null) {
      return null;
    }
    try {
      COMPRESSOR_TYPE[] ca = COMPRESSOR_TYPE.getCompressorsArrayNoDefault(codecs);
      if (ca.length == 0) {
        return null;
      }
      return codecs;
    } catch (InvalidCompressionCodecException e) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.INVALID_FIELD, e.getMessage(), identifier, global);
    }
  }

  private static boolean shouldInferDiskFilenameHint(FreenetURI uri) {
    // For bare CHK inserts we do not infer a target filename from the local disk path.
    // Preserving a null filename keeps semantics aligned with direct payload uploads and avoids
    // forcing a metadata wrapper when the client did not explicitly request one.
    return !(uri.getRoutingKey() == null
        && uri.getDocName() == null
        && "CHK".equals(uri.getKeyType()));
  }

  private record UriParseResult(FreenetURI uri, String filenameHint) {}

  private record UploadConfig(
      long length,
      UploadFrom type,
      File originalFile,
      FreenetURI redirectTarget,
      String filenameHint) {}

  /**
   * Serializes this request back into the canonical {@link SimpleFieldSet} wire representation.
   *
   * <p>The returned structure mirrors the current in-memory state, including normalized upload
   * configuration, persistence flags, metadata hints, and codec descriptors. Callers typically pass
   * the snapshot to downstream protocol layers whenever the request must be echoed, logged, or
   * forwarded for auditing or deferred processing.
   *
   * <pre>{@code
   * SimpleFieldSet snapshot = message.getFieldSet();
   * server.getConnection().send(snapshot);
   * }</pre>
   *
   * @return freshly allocated field set carrying canonicalized headers describing this insert
   *     request instance
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    sfs.putSingle("URI", uri.toString());
    sfs.putSingle("Identifier", identifier);
    sfs.put(FIELD_VERBOSITY, verbosity);
    sfs.put("MaxRetries", maxRetries);
    sfs.putSingle("Metadata.ContentType", contentType);
    sfs.putSingle("ClientToken", clientToken);
    switch (uploadFromType) {
      case DIRECT -> {
        sfs.putSingle(FIELD_UPLOAD_FROM, "direct");
        sfs.put(FIELD_DATA_LENGTH, payloadLength);
      }
      case DISK -> {
        sfs.putSingle(FIELD_UPLOAD_FROM, "disk");
        sfs.putSingle("Filename", origFilename.getAbsolutePath());
        sfs.put(FIELD_DATA_LENGTH, payloadLength);
      }
      case REDIRECT -> {
        sfs.putSingle(FIELD_UPLOAD_FROM, "redirect");
        sfs.putSingle("TargetURI", redirectTarget.toString());
      }
    }
    sfs.put("GetCHKOnly", getCHKOnly);
    sfs.put("PriorityClass", priorityClass);
    sfs.putSingle("Persistence", persistence.toString().toLowerCase(Locale.ROOT));
    sfs.put("DontCompress", dontCompress);
    if (compressorDescriptor != null) sfs.putSingle("Codecs", compressorDescriptor);
    sfs.put("Global", global);
    sfs.put("BinaryBlob", binaryBlob);
    return sfs;
  }

  /**
   * Returns the FCP message verb that identifies this structure to routers and serializers.
   *
   * <p>Client and server code rely on this value when populating response headers, wiring message
   * dispatch tables, and recording telemetry grouped by verb. The implementation always returns
   * {@link #NAME}, preserving the stable mapping between the Java type and the textual verb even if
   * future refactors adjust construction details.
   *
   * @return constant verb that protocol dispatch tables expect for ClientPut traffic
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Initiates processing of this insert request by delegating to the connection handler.
   *
   * <p>The method is invoked on the handler thread after any payload bucket has been populated so
   * that {@link DataCarryingMessage} invariants already hold. It forwards this instance, together
   * with the owning {@link Node}, to {@link FCPConnectionHandler#startClientPut(ClientPutMessage)}
   * so the handler can enforce quotas, schedule insert workers, or emit late validation errors to
   * the client.
   *
   * @param handler connection handler that accepted the message and coordinates streaming
   *     back-pressure
   * @throws MessageInvalidException if the handler detects inconsistency during late validation
   */
  @Override
  public void run(FCPConnectionHandler handler) throws MessageInvalidException {
    handler.startClientPut(this);
  }

  /** Get the length of the trailing field. */
  @Override
  long dataLength() {
    if (uploadFromType == UploadFrom.DIRECT) return payloadLength;
    else return -1;
  }

  @Override
  String getIdentifier() {
    return identifier;
  }

  @Override
  RandomAccessBucket createBucket(BucketFactory bf, long length, FCPServer server)
      throws IOException, PersistenceDisabledException {
    if (persistence == Persistence.FOREVER) {
      return server.insertRuntimeSupport().allocatePersistentUploadBucket(length);
    } else {
      return super.createBucket(bf, length, server);
    }
  }

  @Override
  boolean isGlobal() {
    return global;
  }

  /**
   * Releases any bucket resources associated with the payload of this message.
   *
   * <p>This hook lets handlers clean up deterministically after streaming completes or aborts
   * prematurely. It frees the bucket exactly once, logging a warning when multiple invocations
   * occur so ordering issues can be diagnosed. Callers should prefer invoking it from {@code
   * finally} blocks to keep transient storage usage bounded even when inserts spawn long-running
   * retries elsewhere.
   */
  public void freeData() {
    if (bucket == null) {
      if (dataLength() <= 0) return; // Okay.
      LOG.warn("bucket is null on {} - freed twice?", this);
      return;
    }
    bucket.free();
  }
}

package network.crypta.clients.fcp;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.nio.file.Files;
import network.crypta.clients.fcp.ClientGet.ReturnType;
import network.crypta.clients.fcp.ClientRequest.Persistence;
import network.crypta.keys.FreenetURI;
import network.crypta.node.Node;
import network.crypta.node.RequestStarter;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.io.BucketTools;
import network.crypta.support.io.FileUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents the on-wire {@code ClientGet} message exchanged between FCP clients and the node.
 *
 * <p>The message aggregates every option a requester can provide, including routing hints, return
 * channels, persistence, local caching policies, bandwidth priorities, and optional checksum or
 * metadata payloads. Construction eagerly validates each field, so invalid identifiers, URIs, retry
 * counts, or disk targets trigger a {@link MessageInvalidException} before the network stack
 * attempts to start work. That early failure path protects downstream components from dealing with
 * partially initialized state.
 *
 * <p>Instances are effectively immutable after parsing, making them safe to reuse across handler
 * callbacks even when multiple threads deliver status updates. The class also centralizes
 * serialization logic so that only a curated subset of the original fields is echoed back to the
 * client, preventing accidental leakage of local-only attributes such as disk paths.
 *
 * <ul>
 *   <li>Parses and validates user-supplied {@link SimpleFieldSet} parameters.
 *   <li>Tracks how the requested data should be returned (direct, disk, or none).
 *   <li>Holds derived metadata such as cache policy and allowable MIME types.
 * </ul>
 *
 * <p>Example usage:
 *
 * <pre>{@code
 * SimpleFieldSet fields = ...; // obtained from the FCP socket
 * ClientGetMessage message = new ClientGetMessage(fields);
 * handler.startClientGet(message);
 * }</pre>
 *
 * @see ClientGet
 * @see FCPConnectionHandler
 */
public class ClientGetMessage extends BaseDataCarryingMessage {
  private static final Logger LOG = LoggerFactory.getLogger(ClientGetMessage.class);

  /**
   * Constant message name advertised to the FCP dispatcher so that inbound field sets are routed to
   * this type; the value never changes because the wire protocol expects {@code ClientGet}
   * literally.
   */
  public static final String NAME = "ClientGet";

  private static final String FIELD_MAX_SIZE = "MaxSize";
  private static final String FIELD_MAX_TEMP_SIZE = "MaxTempSize";
  final boolean ignoreDS;
  final boolean dsOnly;
  final FreenetURI uri;
  final String identifier;
  final int verbosity;
  final ReturnType returnType;
  final Persistence persistence;
  final long maxSize;
  final long maxTempSize;
  final int maxRetries;
  final short priorityClass;
  final File diskFile;
  final String clientToken;
  final boolean global;
  final boolean binaryBlob;
  final String[] allowedMIMETypes;
  private final boolean writeToClientCache;
  final String charset;
  final boolean filterData;
  final boolean realTimeFlag;
  final boolean ignoreUSKDatehints;
  private Bucket initialMetadata;
  private final long initialMetadataLength;

  // Legacy threshold callback removed.

  /**
   * Creates a message by parsing and validating the user-supplied field set.
   *
   * <p>The constructor inspects every supported parameter, applies sensible defaults, and ensures
   * that file paths, URIs, numeric bounds, and persistence modes meet protocol rules. The resulting
   * instance carries both raw and derived fields (such as {@link #returnType}) so routing and
   * handler code can react without re-reading the original {@link SimpleFieldSet}. Because parsing
   * is strict, callers should be prepared to relay validation errors back to the remote client.
   *
   * @param fs field set from the remote peer containing ClientGet parameters and defaults.
   * @throws MessageInvalidException if identifiers, numeric ranges, return type, or disk targets
   *     are invalid.
   */
  public ClientGetMessage(SimpleFieldSet fs) throws MessageInvalidException {
    clientToken = fs.get("ClientToken");
    global = fs.getBoolean("Global", false);
    ignoreDS = fs.getBoolean("IgnoreDS", false);
    dsOnly = fs.getBoolean("DSOnly", false);
    identifier = requireIdentifier(fs);
    allowedMIMETypes = fs.getAll("AllowedMIMETypes");
    filterData = fs.getBoolean("FilterData", false);
    charset = fs.get("Charset");
    uri = parseUri(fs);
    verbosity = parseVerbosity(fs);
    ReturnTypeConfig returnTypeConfig = resolveReturnType(fs);
    returnType = returnTypeConfig.type();
    diskFile = returnTypeConfig.diskFile();
    maxSize =
        parsePositiveLong(fs.get(FIELD_MAX_SIZE), FIELD_MAX_SIZE, "Maximum size must be positive");
    maxTempSize =
        parsePositiveLong(
            fs.get(FIELD_MAX_TEMP_SIZE), FIELD_MAX_TEMP_SIZE, "Maximum temp size must be positive");
    maxRetries = parseMaxRetries(fs.get("MaxRetries"));
    priorityClass = parsePriorityClass(fs.get("PriorityClass"), returnTypeConfig.defaultPriority());
    persistence = parsePersistence(fs);
    writeToClientCache = fs.getBoolean("WriteToClientCache", persistence == Persistence.CONNECTION);
    binaryBlob = fs.getBoolean("BinaryBlob", false);
    realTimeFlag = fs.getBoolean("RealTimeFlag", false);
    initialMetadataLength =
        validateInitialMetadataLength(fs.getLong("InitialMetadata.DataLength", 0));
    ignoreUSKDatehints = fs.getBoolean("IgnoreUSKDatehints", false);
  }

  private String requireIdentifier(SimpleFieldSet fs) throws MessageInvalidException {
    String value = fs.get("Identifier");
    if (value == null) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.MISSING_FIELD, "No Identifier", null, global);
    }
    return value;
  }

  private FreenetURI parseUri(SimpleFieldSet fs) throws MessageInvalidException {
    try {
      return new FreenetURI(fs.get("URI"));
    } catch (MalformedURLException e) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.FREENET_URI_PARSE_ERROR, e.getMessage(), identifier, global);
    }
  }

  private int parseVerbosity(SimpleFieldSet fs) throws MessageInvalidException {
    String verbosityString = fs.get("Verbosity");
    if (verbosityString == null) {
      return 0;
    }
    try {
      return Integer.parseInt(verbosityString, 10);
    } catch (NumberFormatException e) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.ERROR_PARSING_NUMBER,
          "Error parsing Verbosity field: " + e.getMessage(),
          identifier,
          global);
    }
  }

  private ReturnTypeConfig resolveReturnType(SimpleFieldSet fs) throws MessageInvalidException {
    ReturnType parsedType = parseReturnTypeFCP(fs.get("ReturnType"));
    return switch (parsedType) {
      case DIRECT ->
          new ReturnTypeConfig(parsedType, null, RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS);
      case NONE -> new ReturnTypeConfig(parsedType, null, RequestStarter.PREFETCH_PRIORITY_CLASS);
      case DISK ->
          new ReturnTypeConfig(
              parsedType, initDiskFile(fs), RequestStarter.BULK_SPLITFILE_PRIORITY_CLASS);
      default ->
          throw new MessageInvalidException(
              ProtocolErrorMessage.MESSAGE_PARSE_ERROR, "Unknown return-type", identifier, global);
    };
  }

  private File initDiskFile(SimpleFieldSet fs) throws MessageInvalidException {
    String filename = fs.get("Filename");
    if (filename == null) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.MISSING_FIELD, "Missing Filename", identifier, global);
    }
    File target = new File(filename);
    if (target.exists()) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.DISK_TARGET_EXISTS, null, identifier, global);
    }
    try {
      File temp = FileUtil.createTempFile(target.getName(), ".freenet-tmp", target.getParentFile());
      Files.delete(temp.toPath());
    } catch (IOException e) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.COULD_NOT_CREATE_FILE, e.getMessage(), identifier, global);
    }
    return target;
  }

  private long parsePositiveLong(String value, String fieldName, String invalidValueMessage)
      throws MessageInvalidException {
    if (value == null) {
      return Long.MAX_VALUE;
    }
    try {
      long parsed = Long.parseLong(value, 10);
      if (parsed < 0) {
        throw new MessageInvalidException(
            ProtocolErrorMessage.INVALID_FIELD, invalidValueMessage, identifier, global);
      }
      return parsed;
    } catch (NumberFormatException e) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.ERROR_PARSING_NUMBER,
          "Error parsing " + fieldName + " field: " + e.getMessage(),
          identifier,
          global);
    }
  }

  private int parseMaxRetries(String value) throws MessageInvalidException {
    if (value == null) {
      logMaxRetries(0);
      return 0;
    }
    try {
      int parsed = Integer.parseInt(value, 10);
      if (parsed < -1) {
        throw new MessageInvalidException(
            ProtocolErrorMessage.INVALID_FIELD,
            "Max retries must be -1 or larger",
            identifier,
            global);
      }
      logMaxRetries(parsed);
      return parsed;
    } catch (NumberFormatException e) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.ERROR_PARSING_NUMBER,
          "Error parsing MaxRetries field: " + e.getMessage(),
          identifier,
          global);
    }
  }

  private void logMaxRetries(int value) {
    if (LOG.isDebugEnabled()) {
      LOG.debug("max retries={}", value);
    }
  }

  private short parsePriorityClass(String priorityString, short defaultPriority)
      throws MessageInvalidException {
    if (priorityString == null) {
      return defaultPriority;
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

  private Persistence parsePersistence(SimpleFieldSet fs) throws MessageInvalidException {
    String persistenceString = fs.get("Persistence");
    Persistence parsed = Persistence.parseOrThrow(persistenceString, identifier, global);
    if (global && (parsed == Persistence.CONNECTION)) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.NOT_SUPPORTED,
          "Global requests must be persistent",
          identifier,
          true);
    }
    return parsed;
  }

  private long validateInitialMetadataLength(long length) throws MessageInvalidException {
    if (length < 0) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.INVALID_FIELD,
          "Invalid data length for initial metadata",
          identifier,
          global);
    }
    return length;
  }

  private record ReturnTypeConfig(ReturnType type, File diskFile, short defaultPriority) {}

  /**
   * Returns a sanitized {@link SimpleFieldSet} snapshot suitable for forwarding to peer nodes or
   * echoing back to the requesting client.
   *
   * <p>The returned structure includes only the commonly shared ClientGet arguments (identifiers,
   * URI, verbosity, return type, and size limits). Sensitive local-only values such as filenames or
   * cached metadata are intentionally omitted to avoid revealing operator information. The snapshot
   * is rebuilt on every invocation so that downstream consumers cannot mutate the internal state of
   * this message instance.
   *
   * @return field set containing ClientGet options safe for serialization without leakage.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.put("IgnoreDS", ignoreDS);
    fs.putSingle("URI", uri.toString(false, false));
    fs.put("FilterData", filterData);
    fs.putSingle("Charset", charset);
    fs.putSingle("Identifier", identifier);
    fs.put("Verbosity", verbosity);
    fs.putSingle("ReturnType", getReturnTypeString());
    fs.put(FIELD_MAX_SIZE, maxSize);
    fs.put(FIELD_MAX_TEMP_SIZE, maxTempSize);
    fs.put("MaxRetries", maxRetries);
    fs.put("BinaryBlob", binaryBlob);
    return fs;
  }

  private String getReturnTypeString() {
    return returnType.toString();
  }

  /**
   * Supplies the canonical name advertised to the FCP dispatch layer.
   *
   * <p>Even though the value is always {@link #NAME}, this indirection keeps the {@link
   * BaseDataCarryingMessage} contract satisfied and enables instrumentation hooks that inspect
   * names before executing a handler. The method is pure and side effect free, allowing it to be
   * invoked repeatedly when tracing or metrics systems need to tag outgoing responses.
   *
   * @return literal {@code ClientGet} so dispatchers map field sets consistently.
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Delegates processing to the provided connection handler for execution on the node.
   *
   * <p>The handler typically schedules the request with {@link RequestStarter}, causing the node to
   * retrieve or stream data according to the persistence and return type captured inside this
   * message. Callers should only invoke this method once per instance; repeated calls would enqueue
   * redundant work and potentially exceed resource quotas because the message carries immutable
   * identifiers and client tokens.
   *
   * @param handler active connection handler orchestrating ClientGet lifecycle and status relays.
   * @param node node instance whose datastore, routing, and scheduler components execute the
   *     request.
   */
  @Override
  public void run(FCPConnectionHandler handler, Node node) {
    handler.startClientGet(this);
  }

  /**
   * Indicates whether fetched data should be written to the client cache when returned.
   *
   * <p>The flag is derived from the requested persistence: ephemeral {@code CONNECTION} requests
   * write by default so reconnections resume quickly, whereas reboot- or forever-persistent ones
   * rely on datastore durability instead. External callers can consult this helper when determining
   * whether to materialize temporary buckets or bypass caching for highly transient transfers.
   *
   * @return true to mirror into client cache, false to stream directly.
   */
  public boolean shouldWriteToClientCache() {
    return writeToClientCache;
  }

  ReturnType parseReturnTypeFCP(String string) throws MessageInvalidException {
    try {
      if (string == null) return ReturnType.DIRECT;
      return ReturnType.valueOf(string.toUpperCase());
    } catch (IllegalArgumentException e) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.INVALID_FIELD,
          "Unable to parse ReturnType " + string + " : " + e,
          identifier,
          global);
    }
  }

  @Override
  long dataLength() {
    return initialMetadataLength;
  }

  /**
   * Reads optional initial metadata that may accompany the literal message body.
   *
   * <p>The implementation allocates a {@link Bucket} sized exactly to {@link
   * #initialMetadataLength} and streams bytes from the provided {@link InputStream}. Because the
   * metadata block is small compared to the requested payload, the entire block is buffered before
   * processing continues. Callers should provide a {@link BucketFactory} capable of producing
   * in-memory or temporary-disk buckets appropriate for the configured node environment.
   *
   * @param is input stream positioned at the pending metadata payload.
   * @param bf factory allocating metadata buckets that honor memory or disk caps.
   * @param server owning FCP server reference retained for interface symmetry and logging.
   * @throws IOException if streaming bytes or writing into the bucket triggers I/O failures.
   * @throws MessageInvalidException if metadata length bookkeeping contradicts earlier validation
   *     expectations.
   */
  @Override
  public void readFrom(InputStream is, BucketFactory bf, FCPServer server)
      throws IOException, MessageInvalidException {
    if (initialMetadataLength == 0) return;
    Bucket data;
    data = bf.makeBucket(initialMetadataLength);
    BucketTools.copyFrom(data, is, initialMetadataLength);
    // No need for synchronization here.
    initialMetadata = data;
  }

  /**
   * ClientGet never writes auxiliary data back to the wire through this hook and therefore always
   * signals unsupported behavior.
   *
   * <p>The FCP control channel expects responses to be produced by {@link FCPConnectionHandler}
   * callbacks instead of this streaming method; keeping the implementation as a hard failure avoids
   * subtle bugs where large payloads might be double-buffered. Subclasses of {@link
   * BaseDataCarryingMessage} that do emit data override this method, but ClientGet acts only as a
   * request envelope.
   *
   * @param os ignored output stream placeholder satisfying the superclass signature contract.
   * @throws IOException never thrown because the method raises {@link
   *     UnsupportedOperationException} first.
   */
  @Override
  protected void writeData(OutputStream os) throws IOException {
    throw new UnsupportedOperationException();
  }

  /**
   * Returns the metadata bucket captured during {@link #readFrom(InputStream, BucketFactory,
   * FCPServer)}.
   *
   * <p>The bucket may be {@code null} when no metadata was supplied or zero-length when the client
   * specified a size but streamed no data. Callers should treat the bucket as read-only and release
   * or recycle it via the owning {@link BucketFactory} once the node has interpreted the contained
   * hints. The bucket remains identical between invocations; the method simply exposes the stored
   * reference without copying.
   *
   * @return metadata bucket supplied by the client, or {@code null} when absent.
   */
  public Bucket getInitialMetadata() {
    return initialMetadata;
  }
}

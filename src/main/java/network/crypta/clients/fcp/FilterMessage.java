package network.crypta.clients.fcp;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.URISyntaxException;
import network.crypta.client.DefaultMIMETypes;
import network.crypta.client.async.ClientContext;
import network.crypta.client.filter.ContentFilter;
import network.crypta.client.filter.ContentFilter.FilterStatus;
import network.crypta.client.filter.FilterOperation;
import network.crypta.client.filter.UnsafeContentTypeException;
import network.crypta.node.FSParseException;
import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.io.FileBucket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Encapsulates a single FCP message that exercises the node's content filter pipeline and reports
 * whether a payload would be accepted for publication.
 *
 * <p>The instance mediates between untrusted client input and the {@link ContentFilter} subsystem:
 * it parses the {@link SimpleFieldSet}, determines whether the payload is streamed directly or read
 * from disk, infers MIME metadata when absent, and stages data inside a {@link Bucket} so the
 * filter can treat the request identically to production traffic. Each message is short-lived and
 * is designed to be instantiated, validated, and consumed entirely on a single thread while the
 * caller holds the relevant protocol connection locks; no shared mutable state escapes the object.
 *
 * <p>Typical callers build a {@code Filter} FCP message prior to uploading content that might trip
 * safety policies. The reply, {@link FilterResultMessage}, lets the client decide whether to redact
 * data or retry with a safer MIME type before performing irreversible operations such as
 * persistence. Large inputs are streamed through temporary buckets, so the filtering cost is
 * proportional to payload size but avoids buffering everything into memory.
 *
 * <p><b>Notable behaviors:</b>
 *
 * <ul>
 *   <li>Supports {@code DIRECT} and {@code DISK} payload sources with identical downstream flow.
 *   <li>Propagates precise {@link ProtocolErrorMessage} codes whenever validation fails.
 *   <li>Produces a deterministic loopback URI so filters that need location context remain stable.
 * </ul>
 *
 * @see FilterResultMessage
 * @see ContentFilter
 */
public class FilterMessage extends DataCarryingMessage {
  private static final Logger LOG = LoggerFactory.getLogger(FilterMessage.class);

  /**
   * Public protocol name announced in {@code FCP} exchanges so peers can recognize filter probes;
   * constant to keep server/client command tables in sync and safe to reuse across requests.
   */
  public static final String NAME = "Filter";

  private static final String DATA_LENGTH_FIELD = "DataLength";
  private static final String FILTER_URI_PROPERTY =
      "network.crypta.clients.fcp.FilterMessage.loopbackUri";
  private static final URI DEFAULT_FILTER_URI = URI.create("http://127.0.0.1:8888/");

  private final String identifier;
  private final FilterOperation operation;
  private final DataSource dataSource;
  private final String mimeType;
  private final long dataLength;
  private final String filename;

  private final BucketFactory bf;

  /**
   * Builds a message from a parsed {@link SimpleFieldSet} and a {@link BucketFactory}, validating
   * that the caller supplied every field required for the chosen data source before executing any
   * disk or network operations.
   *
   * <p>The constructor consumes lightweight identifiers immediately so that subsequent failures
   * reference the client-provided ID. For {@code DIRECT} payloads it copies length metadata; for
   * {@code DISK} payloads it verifies paths, sets up {@link FileBucket} staging, and derives MIME
   * hints. Callers typically chain this constructor directly from {@code FCPMessage.create} without
   * retaining references because the new instance owns the temporary bucket lifecycle.
   *
   * <pre>{@code
   * FilterMessage message = new FilterMessage(fieldSet, bucketFactory);
   * handler.register(message);
   * }</pre>
   *
   * @param fs parsed field set containing identifier, MIME metadata, and source-specific inputs;
   *     must not be {@code null}.
   * @param bf factory used to allocate transient buckets for forwarding the payload to the filter;
   *     reused for both outputs and auto-cleanup.
   * @throws MessageInvalidException if any required field is missing, malformed, or references an
   *     unreadable file; error codes align with {@link ProtocolErrorMessage}.
   */
  public FilterMessage(SimpleFieldSet fs, BucketFactory bf) throws MessageInvalidException {
    identifier = parseIdentifier(fs);
    operation = parseOperation(fs);
    dataSource = parseDataSource(fs);
    filename = fs.get("Filename");

    PayloadMetadata payloadMetadata = preparePayload(fs, fs.get("MimeType"));
    mimeType = payloadMetadata.mimeType;
    dataLength = payloadMetadata.dataLength;
    this.bf = bf;
  }

  @Override
  String getIdentifier() {
    return identifier;
  }

  private String parseIdentifier(SimpleFieldSet fs) throws MessageInvalidException {
    try {
      return fs.getString(IDENTIFIER);
    } catch (FSParseException _) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.MISSING_FIELD,
          "Must contain an " + IDENTIFIER + " field",
          null,
          false);
    }
  }

  private FilterOperation parseOperation(SimpleFieldSet fs) throws MessageInvalidException {
    String op = readRequiredString(fs, "Operation", "Must contain an Operation field");
    try {
      return FilterOperation.valueOf(op);
    } catch (IllegalArgumentException _) {
      throw invalidField("Illegal Operation value");
    }
  }

  private DataSource parseDataSource(SimpleFieldSet fs) throws MessageInvalidException {
    String ds = readRequiredString(fs, "DataSource", "Must contain a DataSource field");
    try {
      return DataSource.valueOf(ds);
    } catch (IllegalArgumentException _) {
      throw invalidField("Illegal DataSource value");
    }
  }

  private PayloadMetadata preparePayload(SimpleFieldSet fs, String inputMimeType)
      throws MessageInvalidException {
    return switch (dataSource) {
      case DIRECT -> handleDirectPayload(fs, inputMimeType);
      case DISK -> handleDiskPayload(inputMimeType);
    };
  }

  private PayloadMetadata handleDirectPayload(SimpleFieldSet fs, String inputMimeType)
      throws MessageInvalidException {
    String resolvedMimeType = requireMimeType(inputMimeType);
    long length = parseDataLength(fs);
    return new PayloadMetadata(resolvedMimeType, length);
  }

  private PayloadMetadata handleDiskPayload(String inputMimeType) throws MessageInvalidException {
    if (filename == null) {
      throw missingField("Must contain a Filename field");
    }
    File file = new File(filename);
    validateDiskFile(file);
    String resolvedMimeType = inputMimeType != null ? inputMimeType : bestGuessMimeType(filename);
    if (resolvedMimeType == null) {
      throw invalidMimeType();
    }
    this.bucket = new FileBucket(file, true, false, false, false);
    return new PayloadMetadata(resolvedMimeType, -1);
  }

  private long parseDataLength(SimpleFieldSet fs) throws MessageInvalidException {
    if (fs.get(DATA_LENGTH_FIELD) == null) {
      throw missingField("Must contain a DataLength field");
    }
    try {
      return fs.getLong(DATA_LENGTH_FIELD);
    } catch (FSParseException _) {
      throw dataLengthParsingError();
    }
  }

  private String requireMimeType(String inputMimeType) throws MessageInvalidException {
    if (inputMimeType == null) {
      throw missingField("Must contain a MimeType field");
    }
    return inputMimeType;
  }

  private void validateDiskFile(File file) throws MessageInvalidException {
    if (!file.exists()) {
      throw fileError(ProtocolErrorMessage.FILE_NOT_FOUND);
    }
    if (!file.isFile()) {
      throw fileError(ProtocolErrorMessage.NOT_A_FILE_ERROR);
    }
    if (!file.canRead()) {
      throw fileError(ProtocolErrorMessage.COULD_NOT_READ_FILE);
    }
  }

  private String readRequiredString(SimpleFieldSet fs, String fieldName, String missingMessage)
      throws MessageInvalidException {
    try {
      return fs.getString(fieldName);
    } catch (FSParseException _) {
      throw missingField(missingMessage);
    }
  }

  private MessageInvalidException missingField(String message) {
    return new MessageInvalidException(
        ProtocolErrorMessage.MISSING_FIELD, message, identifier, false);
  }

  private MessageInvalidException invalidField(String message) {
    return new MessageInvalidException(
        ProtocolErrorMessage.INVALID_FIELD, message, identifier, false);
  }

  private MessageInvalidException dataLengthParsingError() {
    return new MessageInvalidException(
        ProtocolErrorMessage.ERROR_PARSING_NUMBER,
        "DataLength field must be a long",
        identifier,
        false);
  }

  private MessageInvalidException invalidMimeType() {
    return new MessageInvalidException(
        ProtocolErrorMessage.BAD_MIME_TYPE,
        "Could not determine MIME type from filename",
        identifier,
        false);
  }

  private MessageInvalidException fileError(int protocolCode) {
    return new MessageInvalidException(protocolCode, null, identifier, false);
  }

  private MessageInvalidException internalError(String message, Throwable cause) {
    MessageInvalidException exception =
        new MessageInvalidException(
            ProtocolErrorMessage.INTERNAL_ERROR, message, identifier, false);
    exception.initCause(cause);
    return exception;
  }

  @Override
  boolean isGlobal() {
    return false;
  }

  @Override
  long dataLength() {
    return dataLength;
  }

  /**
   * Creates a fresh {@link SimpleFieldSet} mirroring the outbound message so other protocol layers
   * can log or relay the request without re-interpreting internal state.
   *
   * <p>The returned structure always contains the identifier, declared operation, data source,
   * advertised MIME type, filename (which may be {@code null} for {@code DIRECT} payloads), and an
   * explicit {@code DataLength}. Mutations to the resulting object are not reflected back into this
   * message, so callers should treat it as a snapshot.
   *
   * @return new mutable {@link SimpleFieldSet} instance containing only protocol-visible fields,
   *     safe for serialization or inspection by higher FCP layers.
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle(IDENTIFIER, identifier);
    fs.putOverwrite("Operation", operation.name());
    fs.putOverwrite("DataSource", dataSource.name());
    fs.putOverwrite("MimeType", mimeType);
    fs.putOverwrite("Filename", filename);
    fs.put(DATA_LENGTH_FIELD, dataLength);
    return fs;
  }

  /**
   * Reports the protocol command name so dispatchers can map the object back to FCP wire commands
   * without assuming concrete types.
   *
   * <p>The value is always {@link #NAME} and therefore suitable for hashing, metrics labeling, or
   * routing tables that operate purely on canonical command strings rather than concrete classes.
   *
   * @return constant {@code Filter} string describing the command associated with this message.
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Executes the content filter by streaming the prepared payload through {@link ContentFilter} and
   * returning a {@link FilterResultMessage} to the caller.
   *
   * <p>The method allocates a result bucket, relays bytes through the filtering pipeline, captures
   * MIME or charset adjustments, and records whether the content was rejected as unsafe. It is
   * expected to run within the {@link FCPConnectionHandler}'s thread confinement so no external
   * synchronization is required. The message must already own a populated {@link #bucket};
   * otherwise a {@link MessageInvalidException} is raised before any filtering occurs.
   *
   * @param handler connection handler responsible for sending replies back over the client's FCP
   *     socket and exposing the server core; must remain valid for the call duration.
   * @param node node instance containing the wider runtime context; used indirectly when retrieving
   *     the {@link ClientContext} from the server.
   * @throws MessageInvalidException if the payload bucket is absent or a transient allocation error
   *     prevents preparing buckets for the filtering process.
   */
  @Override
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    if (bucket == null) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.MISSING_FIELD, "Must contain data", identifier, false);
    }
    Bucket resultBucket;
    try {
      resultBucket = bf.makeBucket(-1);
    } catch (IOException e) {
      throw internalError("Failed to create temporary bucket", e);
    }
    String resultCharset = null;
    String resultMimeType = null;
    boolean unsafe = false;
    try (InputStream input = bucket.getInputStream();
        OutputStream output = resultBucket.getOutputStream()) {
      FilterStatus status =
          applyFilter(input, output, handler.getServer().getCore().getClientContext());
      resultCharset = status.charset;
      resultMimeType = status.mimeType;
    } catch (UnsafeContentTypeException _) {
      unsafe = true;
    } catch (IOException e) {
      throw internalError("IO error running content filter", e);
    }
    FilterResultMessage response =
        new FilterResultMessage(identifier, resultCharset, resultMimeType, unsafe, resultBucket);
    handler.send(response);
  }

  private FilterStatus applyFilter(
      InputStream input, OutputStream output, ClientContext clientContext) throws IOException {
    URI fakeUri = resolveFilterUri();
    // ContentFilter currently only supports read filtering; update once write filtering is
    // available.
    return ContentFilter.filter(
        input,
        output,
        mimeType,
        fakeUri,
        null,
        null,
        null,
        null,
        clientContext.linkFilterExceptionProvider);
  }

  private URI resolveFilterUri() {
    String configuredUri = System.getProperty(FILTER_URI_PROPERTY);
    if (configuredUri == null || configuredUri.isBlank()) {
      return DEFAULT_FILTER_URI;
    }
    try {
      return new URI(configuredUri);
    } catch (URISyntaxException e) {
      LOG.warn(
          "Invalid value for {}: {}. Falling back to {}",
          FILTER_URI_PROPERTY,
          configuredUri,
          DEFAULT_FILTER_URI,
          e);
      return DEFAULT_FILTER_URI;
    }
  }

  private record PayloadMetadata(String mimeType, long dataLength) {}

  private String bestGuessMimeType(String filename) {
    String guessedMimeType = null;
    if (filename != null) {
      guessedMimeType = DefaultMIMETypes.guessMIMEType(filename, true);
    }
    return guessedMimeType;
  }
}

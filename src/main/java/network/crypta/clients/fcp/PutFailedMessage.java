package network.crypta.clients.fcp;

import java.io.IOException;
import java.io.InvalidObjectException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serial;
import java.io.Serializable;
import java.net.MalformedURLException;
import network.crypta.client.FailureCodeTracker;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.client.InsertException;
import network.crypta.keys.FreenetURI;
import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;

/**
 * Message sent from the node when a client-initiated {@code ClientPut} fails.
 *
 * <p>Instances capture the precise {@link InsertExceptionMode}, human-readable code descriptions,
 * any extended text provided by the node, and the optional {@link FreenetURI} that had been
 * expected. The message can be serialized to and from {@link SimpleFieldSet} so it can travel
 * across FCP, be logged, or be preserved with a persistent request. Most fields are immutable after
 * construction, allowing callers to safely cache or forward the object without further
 * synchronization.
 *
 * <p>Typical consumers are FCP clients that need to render meaningful diagnostics or decide whether
 * to retry a failed insert. The class does not attempt recovery itself; it only relays state
 * reported by the server. When created from field sets, callers may choose between consuming
 * verbose descriptions or recomputing them from the numeric error code, which can help reduce wire
 * size. Thread-safety is achieved through immutability; multiple threads may read the same instance
 * concurrently.
 *
 * <ul>
 *   <li>Encapsulates server-side insert failure metadata.
 *   <li>Supports compact and verbose FCP serialization forms.
 *   <li>Provides short and long failure message helpers for UI display.
 * </ul>
 *
 * @see InsertException
 * @see FailureCodeTracker
 * @see FreenetURI
 */
public final class PutFailedMessage extends FCPMessage implements Serializable {

  @Serial private static final long serialVersionUID = 1L;

  private static final String FIELD_FAILURE_MODE = "failureMode";
  private static final String FIELD_CODE_DESCRIPTION = "codeDescription";
  private static final String FIELD_EXTRA_DESCRIPTION = "extraDescription";
  private static final String FIELD_SHORT_CODE_DESCRIPTION = "shortCodeDescription";
  private static final String FIELD_TRACKER = "tracker";
  private static final String FIELD_EXPECTED_URI = "expectedURI";
  private static final String FIELD_REQUEST_IDENTIFIER = "requestIdentifier";
  private static final String FIELD_LEGACY_CODE = "code";
  private static final String FIELD_LEGACY_IDENTIFIER = "identifier";
  private static final String FIELD_GLOBAL = "global";
  private static final String FIELD_IS_FATAL = "isFatal";

  /**
   * Failure mode that categorizes the insert error and drives fatality and retry semantics. The
   * value maps directly to {@link InsertExceptionMode} so clients can branch on protocol-defined
   * codes without parsing free-form strings.
   */
  InsertExceptionMode failureMode;

  /**
   * Human-readable description of the failure code, either read from verbose message fields or
   * reconstructed from the numeric code. Intended for log output or UI labels where structured
   * codes are insufficient.
   */
  String codeDescription;

  /**
   * Optional extended diagnostic details supplied by the node; may be {@code null} when absent.
   * Contents often include specific reasons such as checksum mismatches or connectivity problems
   * that are not conveyed by the main code description.
   */
  String extraDescription;

  /**
   * Concise description intended for compact displays or log summaries of the failure condition.
   * This string is shorter than {@link #codeDescription} and suited to status tables or progress
   * indicators.
   */
  String shortCodeDescription;

  /**
   * Optional tracker containing structured error counts and codes gathered during the insert
   * attempt. When present it allows clients to render detailed diagnostics or aggregate failure
   * statistics without parsing textual messages.
   */
  FailureCodeTracker tracker;

  /**
   * Expected URI for the inserted content when provided by the node; can be {@code null}. Clients
   * may use the value to confirm addressing expectations or to annotate user-facing error reports.
   */
  FreenetURI expectedURI;

  /**
   * Identifier used by the client to correlate this message with the original request. The same
   * token is echoed back to the server in follow-up interactions and is required by the protocol.
   */
  String requestIdentifier;

  /**
   * Whether the originating request was submitted as a global request across peers. This flag
   * informs clients about scope so they can decide whether retries should remain global or fall
   * back to a local insert.
   */
  boolean global;

  /**
   * Indicates whether the node treats this failure as fatal for subsequent retries. Fatal errors
   * normally halt automated retry loops, while non-fatal ones may be retried after backoff.
   */
  boolean isFatal;

  /**
   * Builds a failure message directly from an {@link InsertException} raised by the node.
   *
   * <p>This constructor is used on the server side before sending the failure to an FCP client. It
   * copies the detailed error context, short/long descriptions, and request identifier. All copied
   * values are treated as immutable snapshots of the original exception so later changes to the
   * source exception do not affect the message.
   *
   * @param e insert exception describing why the put failed; never {@code null}.
   * @param identifier client-supplied identifier that correlates responses to requests.
   * @param global whether the failing request was global (affects broadcast semantics).
   */
  public PutFailedMessage(InsertException e, String identifier, boolean global) {
    this.failureMode = e.getMode();
    this.codeDescription = InsertException.getMessage(failureMode);
    this.shortCodeDescription = InsertException.getShortMessage(failureMode);
    this.extraDescription = e.extra;
    this.tracker = e.getErrorCodes();
    this.expectedURI = e.getUri();
    this.requestIdentifier = identifier;
    this.global = global;
    this.isFatal = InsertException.isFatal(failureMode);
  }

  /**
   * Reconstructs a failure message from a {@link SimpleFieldSet} representation.
   *
   * <p>Used when loading persistent requests or consuming messages from external sources. When
   * {@code useVerboseFields} is {@code true}, the method reads human-readable descriptions directly
   * from the field set; otherwise it regenerates them from the numeric {@code Code} value to reduce
   * storage overhead. The identifier must be present; callers are expected to validate the source
   * before constructing. URI parsing follows the same rules as {@link FreenetURI} and may raise a
   * malformed URL error.
   *
   * @param fs field set containing the serialized failure fields, including {@code Identifier}.
   * @param useVerboseFields whether to consume descriptive fields or recompute them from the code.
   * @throws MalformedURLException when {@code ExpectedURI} is present but cannot be parsed.
   */
  public PutFailedMessage(SimpleFieldSet fs, boolean useVerboseFields)
      throws MalformedURLException {
    requestIdentifier = fs.get("Identifier");
    if (requestIdentifier == null) throw new NullPointerException();
    global = fs.getBoolean("Global", false);
    failureMode = InsertExceptionMode.getByCode(Integer.parseInt(fs.get("Code")));

    if (useVerboseFields) {
      codeDescription = fs.get("CodeDescription");
      isFatal = fs.getBoolean("Fatal", false);
      shortCodeDescription = fs.get("ShortCodeDescription");
    } else {
      codeDescription = InsertException.getMessage(failureMode);
      isFatal = InsertException.isFatal(failureMode);
      shortCodeDescription = InsertException.getShortMessage(failureMode);
    }

    extraDescription = fs.get("ExtraDescription");
    String euri = fs.get("ExpectedURI");
    if (euri != null && !euri.isEmpty()) expectedURI = new FreenetURI(euri);
    else expectedURI = null;
    SimpleFieldSet trackerSubset = fs.subset("Errors");
    if (trackerSubset != null) {
      tracker = new FailureCodeTracker(true, trackerSubset);
    } else {
      tracker = null;
    }
  }

  @Serial
  private void writeObject(ObjectOutputStream out) throws IOException {
    ObjectOutputStream.PutField fields = out.putFields();
    fields.put(FIELD_FAILURE_MODE, failureMode);
    fields.put(FIELD_LEGACY_CODE, null); // legacy field left blank for forward streams
    fields.put(FIELD_CODE_DESCRIPTION, codeDescription);
    fields.put(FIELD_EXTRA_DESCRIPTION, extraDescription);
    fields.put(FIELD_SHORT_CODE_DESCRIPTION, shortCodeDescription);
    fields.put(FIELD_TRACKER, tracker);
    fields.put(FIELD_EXPECTED_URI, expectedURI);
    fields.put(FIELD_REQUEST_IDENTIFIER, requestIdentifier);
    fields.put(FIELD_LEGACY_IDENTIFIER, null); // legacy field left blank for forward streams
    fields.put(FIELD_GLOBAL, global);
    fields.put(FIELD_IS_FATAL, isFatal);
    out.writeFields();
  }

  @Serial
  private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    ObjectInputStream.GetField fields = in.readFields();

    InsertExceptionMode mode = (InsertExceptionMode) fields.get(FIELD_FAILURE_MODE, null);
    if (mode == null) {
      mode = (InsertExceptionMode) fields.get(FIELD_LEGACY_CODE, null);
    }
    failureMode = mode;

    String identifier = (String) fields.get(FIELD_REQUEST_IDENTIFIER, null);
    if (identifier == null) {
      identifier = (String) fields.get(FIELD_LEGACY_IDENTIFIER, null);
    }
    requestIdentifier = identifier;

    codeDescription = (String) fields.get(FIELD_CODE_DESCRIPTION, null);
    extraDescription = (String) fields.get(FIELD_EXTRA_DESCRIPTION, null);
    shortCodeDescription = (String) fields.get(FIELD_SHORT_CODE_DESCRIPTION, null);
    tracker = (FailureCodeTracker) fields.get(FIELD_TRACKER, null);
    expectedURI = (FreenetURI) fields.get(FIELD_EXPECTED_URI, null);
    global = fields.get(FIELD_GLOBAL, false);

    boolean fatal = fields.get(FIELD_IS_FATAL, false);
    if (fields.defaulted(FIELD_IS_FATAL) && mode != null) {
      fatal = InsertException.isFatal(mode);
    }
    isFatal = fatal;

    if (failureMode == null || requestIdentifier == null) {
      throw new InvalidObjectException("Missing required fields for PutFailedMessage");
    }
  }

  @Override
  public SimpleFieldSet getFieldSet() {
    return getFieldSet(true);
  }

  /**
   * Serializes this failure message into an {@link SimpleFieldSet} suitable for FCP transport.
   *
   * <p>When {@code verbose} is {@code true}, descriptive strings and fatality flags are emitted to
   * aid diagnostics. In compact mode only the essential codes are included, allowing callers to
   * minimize payload size while still reconstructing messages on the other side.
   *
   * @param verbose whether to include descriptive text fields alongside numeric codes.
   * @return mutable field set populated with message data ready for wire transmission.
   */
  public SimpleFieldSet getFieldSet(boolean verbose) {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    if (requestIdentifier == null) throw new NullPointerException();
    fs.putSingle("Identifier", requestIdentifier);
    fs.put("Global", global);
    fs.put("Code", failureMode.code);
    if (verbose) fs.putSingle("CodeDescription", codeDescription);
    if (extraDescription != null) fs.putSingle("ExtraDescription", extraDescription);
    if (tracker != null) {
      fs.tput("Errors", tracker.toFieldSet(verbose));
    }
    if (verbose) fs.put("Fatal", isFatal);
    if (verbose) fs.putSingle("ShortCodeDescription", shortCodeDescription);
    if (expectedURI != null) fs.putSingle("ExpectedURI", expectedURI.toString());
    return fs;
  }

  @Override
  public String getName() {
    return "PutFailed";
  }

  /**
   * Rejects attempts to send {@code PutFailed} from a client back to the server.
   *
   * <p>The FCP protocol defines this message as server-to-client only. Invoking this method on the
   * client side therefore always results in an exception that includes the offending identifier and
   * global flag for logging. The method is intentionally non-idempotent because it always throws.
   *
   * @param handler connection handler that attempted to process the outbound message.
   * @param node node instance associated with the connection; unused but required by signature.
   * @throws MessageInvalidException always thrown to signal protocol misuse by the client.
   */
  @Override
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    throw new MessageInvalidException(
        ProtocolErrorMessage.INVALID_MESSAGE,
        "PutFailed goes from server to client not the other way around",
        requestIdentifier,
        global);
  }

  /**
   * Returns a concise description of the failure suitable for compact displays.
   *
   * @return short, human-readable message derived from the insert failure mode.
   */
  public String getShortFailedMessage() {
    return shortCodeDescription;
  }

  /**
   * Returns an expanded failure description that includes any extra diagnostic text.
   *
   * @return short description optionally suffixed with the extra error context text.
   */
  public String getLongFailedMessage() {
    if (extraDescription != null) return shortCodeDescription + ": " + extraDescription;
    else return shortCodeDescription;
  }
}

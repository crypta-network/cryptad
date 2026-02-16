package network.crypta.clients.fcp;

import java.io.Serial;
import java.io.Serializable;
import java.util.Map;
import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents an FCP {@code ProtocolError} message produced when a peer cannot process a command
 * cleanly.
 *
 * <p>This immutable value object bundles the numeric protocol error code, the fatality flag, an
 * optional free-form explanation, and the identifier of the request that triggered the failure.
 * Instances are typically created immediately after a parser detects malformed input or an
 * unsupported operation, and the data they carry is serialized back to the remote peer without
 * alteration. The internal code-to-description map keeps the canonical protocol text so callers do
 * not need to reimplement it.
 *
 * <p>The message is safe to share across threads because all fields are final and exposed only
 * through accessors or a {@link SimpleFieldSet} representation. Callers remain responsible for
 * closing the connection when {@code fatal} is {@code true} and for deciding whether a {@code
 * global} error should cancel outstanding requests. This class does not attempt retries or
 * translation; it merely preserves what the protocol already communicated.
 *
 * <ul>
 *   <li>Encodes a single protocol error with optional human-readable context.
 *   <li>Supports construction from parsed field sets or explicit parameter values.
 *   <li>Maintains the official descriptions for all known FCP error codes.
 * </ul>
 */
public final class ProtocolErrorMessage extends FCPMessage implements Serializable {
  private static final Logger LOG = LoggerFactory.getLogger(ProtocolErrorMessage.class);

  @Serial private static final long serialVersionUID = 1L;
  static final int CLIENT_HELLO_MUST_BE_FIRST_MESSAGE = 1;
  static final int NO_LATE_CLIENT_HELLOS = 2;
  static final int MESSAGE_PARSE_ERROR = 3;
  static final int FREENET_URI_PARSE_ERROR = 4;
  static final int MISSING_FIELD = 5;
  static final int ERROR_PARSING_NUMBER = 6;

  /** Numeric code indicating the peer sent a message type the node cannot process. */
  public static final int INVALID_MESSAGE = 7;

  static final int INVALID_FIELD = 8;
  static final int FILE_NOT_FOUND = 9;
  static final int DISK_TARGET_EXISTS = 10;
  static final int COULD_NOT_CREATE_FILE = 12;
  static final int COULD_NOT_WRITE_FILE = 13;
  static final int COULD_NOT_RENAME_FILE = 14;
  static final int NO_SUCH_IDENTIFIER = 15;
  static final int NOT_SUPPORTED = 16;
  static final int INTERNAL_ERROR = 17;
  static final int SHUTTING_DOWN = 18;
  static final int NO_SUCH_NODE_IDENTIFIER = 19; // Unused
  static final int URL_PARSE_ERROR = 20;
  static final int REF_PARSE_ERROR = 21;
  static final int FILE_PARSE_ERROR = 22;
  static final int NOT_A_FILE_ERROR = 23;
  static final int ACCESS_DENIED = 24;
  static final int DIRECT_DISK_ACCESS_DENIED = 25;
  static final int COULD_NOT_READ_FILE = 26;
  static final int REF_SIGNATURE_INVALID = 27;
  static final int CANNOT_PEER_WITH_SELF = 28;
  static final int DUPLICATE_PEER_REF = 29;
  static final int OPENNET_DISABLED = 30;
  static final int DARKNET_ONLY = 31;
  static final int NO_SUCH_PLUGIN = 32;
  static final int PERSISTENCE_DISABLED = 33;
  static final int TOO_MANY_FILES_IN_INSERT = 34;
  static final int BAD_MIME_TYPE = 35;
  static final int WRONG_RETURN_TYPE = 36;
  static final int IO_ERROR = 37;
  static final int PLUGINS_DISABLED = 38;

  private static final Map<Integer, String> CODE_DESCRIPTIONS =
      Map.ofEntries(
          Map.entry(CLIENT_HELLO_MUST_BE_FIRST_MESSAGE, "ClientHello must be first message"),
          Map.entry(NO_LATE_CLIENT_HELLOS, "No late ClientHello's accepted"),
          Map.entry(MESSAGE_PARSE_ERROR, "Unknown message parsing error"),
          Map.entry(FREENET_URI_PARSE_ERROR, "Error parsing freenet URI"),
          Map.entry(MISSING_FIELD, "Missing field"),
          Map.entry(ERROR_PARSING_NUMBER, "Error parsing a numeric field"),
          Map.entry(INVALID_MESSAGE, "Don't know what to do with message"),
          Map.entry(INVALID_FIELD, "Invalid field value"),
          Map.entry(FILE_NOT_FOUND, "File not found, not a file or not readable"),
          Map.entry(
              DISK_TARGET_EXISTS, "Disk target exists, refusing to overwrite for security reasons"),
          Map.entry(COULD_NOT_CREATE_FILE, "Could not create file"),
          Map.entry(COULD_NOT_WRITE_FILE, "Could not write file"),
          Map.entry(COULD_NOT_RENAME_FILE, "Could not rename file"),
          Map.entry(NO_SUCH_IDENTIFIER, "No such identifier"),
          Map.entry(NOT_SUPPORTED, "Not supported"),
          Map.entry(INTERNAL_ERROR, "Internal error"),
          Map.entry(SHUTTING_DOWN, "Shutting down"),
          Map.entry(NO_SUCH_NODE_IDENTIFIER, "No such nodeIdentifier"),
          Map.entry(URL_PARSE_ERROR, "Error parsing URL"),
          Map.entry(REF_PARSE_ERROR, "Reference could not be parsed"),
          Map.entry(FILE_PARSE_ERROR, "File could not be read"),
          Map.entry(NOT_A_FILE_ERROR, "Filepath is not a file"),
          Map.entry(ACCESS_DENIED, "Access denied"),
          Map.entry(
              DIRECT_DISK_ACCESS_DENIED,
              "Direct Disk Access operation denied: did you send a FileHash field ? Did you use"
                  + " TestDDA?"),
          Map.entry(COULD_NOT_READ_FILE, "Could not read file"),
          Map.entry(REF_SIGNATURE_INVALID, "Reference signature failed to verify"),
          Map.entry(CANNOT_PEER_WITH_SELF, "Node cannot peer with itself"),
          Map.entry(DUPLICATE_PEER_REF, "Node already has a peer with that ref"),
          Map.entry(OPENNET_DISABLED, "Opennet is currently disabled in the node's configuration"),
          Map.entry(DARKNET_ONLY, "Operation only available on a darknet peer"),
          Map.entry(NO_SUCH_PLUGIN, "No such plugin"),
          Map.entry(
              PERSISTENCE_DISABLED,
              "Persistence disabled (e.g. encrypted queue waiting for password?)"),
          Map.entry(
              TOO_MANY_FILES_IN_INSERT, "Too many files in a single folder on a freesite insert"),
          Map.entry(BAD_MIME_TYPE, "Bad MIME type"),
          Map.entry(WRONG_RETURN_TYPE, "Not supported for that return type"),
          Map.entry(IO_ERROR, "Disk I/O error"),
          Map.entry(PLUGINS_DISABLED, "Plugins are disabled"));

  /** Numeric protocol error code preserved exactly as received or specified. */
  private final int protocolCode;

  /** Optional explanatory text supplied by the remote peer; may be {@code null}. */
  final String extra;

  /**
   * Indicates whether the sending peer regards the error as connection-fatal; callers should close
   * if {@code true}.
   */
  final boolean fatal;

  /** Identifier of the request that triggered the error, or {@code null} if unavailable. */
  final String ident;

  /**
   * Marks the error as affecting the entire connection or session rather than a single request
   * only.
   */
  final boolean global;

  private String codeDescription() {
    String description = CODE_DESCRIPTIONS.get(protocolCode);
    if (description != null) {
      return description;
    }
    LOG.warn("Unknown error code: {}", protocolCode);
    return "(Unknown)";
  }

  /**
   * Creates a protocol error message with explicitly supplied values for every field.
   *
   * <p>Use this when emitting a new {@code ProtocolError} in response to a parsing or validation
   * failure you just detected. The parameters are stored verbatim, allowing the instance to be
   * serialized, logged, and reused without further normalization. Unknown codes are accepted; when
   * serialized, they receive the generic {@code (Unknown)} description so downstream peers can
   * still understand that an error occurred even if they do not recognize the code. The object is
   * immutable and safe for concurrent reads after construction.
   *
   * @param code numeric protocol error code matching one of the defined constants
   * @param fatal true when the sender regards the error as connection-terminating
   * @param extra optional human-readable explanation; may be {@code null} or empty
   * @param ident identifier linked to the failing request; {@code null} if parsing failed early
   * @param global true when the error should be treated as affecting the whole connection state
   */
  public ProtocolErrorMessage(int code, boolean fatal, String extra, String ident, boolean global) {
    this.protocolCode = code;
    this.extra = extra;
    this.fatal = fatal;
    this.ident = ident;
    this.global = global;
  }

  /**
   * Reconstructs a protocol error from a parsed {@link SimpleFieldSet} received over FCP.
   *
   * <p>This constructor pulls the canonical field names ({@code Identifier}, {@code Code}, {@code
   * ExtraDescription}, {@code Fatal}, and {@code Global}) from the supplied structure. It mirrors
   * the serialization format produced by {@link #getFieldSet()}, enabling round-trip tests and
   * bridge components to treat messages uniformly. The caller is responsible for ensuring the field
   * set originates from a trusted parser; missing or malformed numeric values will trigger a {@link
   * NumberFormatException}. All extracted values are stored exactly as provided.
   *
   * @param fs parsed field set containing the protocol error fields; must not be {@code null}
   * @throws NumberFormatException if the {@code Code} field cannot be parsed as an integer
   */
  public ProtocolErrorMessage(SimpleFieldSet fs) {
    ident = fs.get("Identifier");
    protocolCode = Integer.parseInt(fs.get("Code"));
    extra = fs.get("ExtraDescription");
    fatal = fs.getBoolean("Fatal", false);
    global = fs.getBoolean("Global", false);
  }

  /**
   * Initializes an empty protocol error suitable for serialization frameworks that require a
   * no-argument constructor.
   *
   * <p>The fields are set to harmless defaults and should be overwritten by the deserializer before
   * the instance is used. This constructor is not intended for direct application use; prefer the
   * parameterized constructors when constructing real messages. The resulting object is mutable
   * only during deserialization because the fields are final once the constructor completes.
   */
  ProtocolErrorMessage() {
    // For serialization.
    protocolCode = 0;
    extra = null;
    fatal = false;
    ident = null;
    global = false;
  }

  /**
   * Serializes this message into a {@link SimpleFieldSet} using the canonical FCP field names.
   *
   * <p>The returned structure always contains {@code Code}, {@code CodeDescription}, {@code Fatal},
   * and {@code Global}; optional fields are included only when present. Descriptions are resolved
   * from the static code map so that downstream components receive protocol-approved text even when
   * they were constructed with only a numeric code. The method performs no network I/O and can be
   * invoked repeatedly without side effects.
   *
   * @return immutable field set representation appropriate for immediate transmission to a peer
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    if (ident != null) sfs.putSingle("Identifier", ident);
    sfs.put("Code", protocolCode);
    sfs.putSingle("CodeDescription", codeDescription());
    if (extra != null) sfs.putSingle("ExtraDescription", extra);
    sfs.put("Fatal", fatal);
    sfs.put("Global", global);
    return sfs;
  }

  /**
   * Notifies the local handler that the client reported a protocol error.
   *
   * <p>This implementation simply logs the occurrence because protocol errors are already fully
   * represented in the object. It does not attempt automatic recovery or connection management; the
   * caller should decide whether to close the session based on the {@code fatal} flag or higher
   * level policies. The method is safe to call multiple times and does not mutate state.
   *
   * @param handler active FCP connection handler receiving the message; never {@code null} during
   *     normal operation
   * @param node current node instance that owns the connection; used by higher-level handlers
   */
  @Override
  public void run(FCPConnectionHandler handler, Node node) {
    LOG.error("Client reported protocol error");
  }

  /**
   * Returns the protocol message name used when serializing this object over FCP.
   *
   * <p>The value is constant for all instances because the class models only the {@code
   * ProtocolError} message type. Callers commonly use it when dispatching or logging outbound
   * messages so the receiving side can match on well-known names. The string does not include any
   * additional qualifiers or formatting.
   *
   * @return constant message name {@code ProtocolError} suitable for FCP framing
   */
  @Override
  public String getName() {
    return "ProtocolError";
  }

  /**
   * Exposes the raw numeric error code preserved within this message.
   *
   * <p>The value corresponds to one of the constants defined in this class when the sender adhered
   * to the protocol, but arbitrary numbers are allowed for forward compatibility. The method
   * performs no translation and never returns {@code null}. Callers may use it to map to localized
   * descriptions or to branch logic without reparsing the field set.
   *
   * @return integer code representing the specific protocol error condition
   */
  public int getCode() {
    return protocolCode;
  }

  /**
   * Builds a human-readable representation containing the superclass string plus key fields.
   *
   * <p>The output concatenates the superclass value, numeric code, extra description, fatal flag,
   * request identifier, and global flag, separated by colons. It is intended for diagnostics and
   * should not be parsed back into a message. The format remains stable to ease log search but is
   * not part of the wire protocol.
   *
   * @return string summary of the error content for logging or debugging purposes
   */
  @Override
  public String toString() {
    return super.toString()
        + ":"
        + protocolCode
        + ":"
        + extra
        + ":"
        + fatal
        + ":"
        + ident
        + ":"
        + global;
  }
}

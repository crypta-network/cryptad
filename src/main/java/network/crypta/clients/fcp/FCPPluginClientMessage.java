package network.crypta.clients.fcp;

import java.io.IOException;
import network.crypta.clients.fcp.FCPPluginConnection.SendDirection;
import network.crypta.node.FSParseException;
import network.crypta.node.Node;
import network.crypta.pluginmanager.PluginManager;
import network.crypta.pluginmanager.PluginNotFoundException;
import network.crypta.support.SimpleFieldSet;
import org.jetbrains.annotations.Nullable;

/**
 * Parses client-to-server FCP plugin messages from their {@link SimpleFieldSet}-based wire format
 * into the richer structures expected by the node.
 *
 * <p>The class consumes raw field sets emitted by remote plugin clients, validates invariants such
 * as {@code Identifier}, {@code PluginName}, and optional payload metadata, and then materializes
 * {@link FCPPluginMessage} instances that downstream handlers can treat uniformly regardless of
 * transport direction. In practice, it is constructed by the FCP request stack after a message
 * arrives at the socket and before the runtime attempts to route it to a plugin-specific handler.
 *
 * <p>Unlike {@link FCPPluginMessage}, which is the public container shared between servers and
 * plugins, this type is intentionally narrower. It focuses solely on the inbound path, translating
 * field-set conventions (such as {@link #PARAM_PREFIX}) into canonical state and exposing helper
 * logic for building a {@link FCPPluginConnection}-ready message. Instances are immutable and can
 * therefore be safely passed between threads once constructed, although typical usage confines them
 * to a single handler thread that subsequently queues the message for plugin execution.
 *
 * <p>The legacy on-network message name remains {@value #NAME} to avoid breaking compatibility with
 * deployed nodes. Renaming only the Java class allows the runtime to distinguish between the
 * internal parser and the external representation without modifying the wire protocol. Future
 * revisions may introduce an alternate label, but this class deliberately preserves the original
 * constant until peers universally upgrade.
 *
 * <ul>
 *   <li>Validates structural requirements before reaching plugin code.
 *   <li>Tracks optional metadata such as success flags and error payload details.
 *   <li>Bridges bucket-backed payloads to {@link FCPPluginConnection} delivery.
 * </ul>
 *
 * @author saces
 * @author xor (xor@freenetproject.org)
 * @see FCPPluginMessage
 * @see FCPPluginServerMessage
 * @see FCPPluginConnection
 * @see FCPPluginConnectionImpl
 */
public class FCPPluginClientMessage extends DataCarryingMessage {

  /**
   * On-network format name of the message.
   *
   * <p>ATTENTION: This one is different to the class name. For an explanation, see the class-level
   * JavaDoc {@link FCPPluginClientMessage}.
   */
  public static final String NAME = "FCPPluginMessage";

  /**
   * Prefix applied to every plugin parameter stored in the {@link SimpleFieldSet} payload so that
   * keys such as {@code Param.Foo} can be isolated from required top-level headers without risk of
   * collision or misinterpretation.
   */
  public static final String PARAM_PREFIX = "Param";

  /**
   * @see FCPPluginMessage#identifier
   */
  private final String identifier;

  /**
   * @see PluginManager#getPluginFCPServer(String)
   */
  private final String pluginname;

  /**
   * @see FCPPluginMessage#data
   */
  private final long dataLength;

  /**
   * @see FCPPluginMessage#params
   */
  private final SimpleFieldSet plugparams;

  /**
   * @see FCPPluginMessage#success
   */
  private final Boolean success;

  /**
   * @see FCPPluginMessage#errorCode
   */
  private final String errorCode;

  /**
   * @see FCPPluginMessage#errorMessage
   */
  private final String errorMessage;

  FCPPluginClientMessage(SimpleFieldSet fs) throws MessageInvalidException {
    identifier =
        getRequiredField(fs, "Identifier", NAME + " must contain a Identifier field", null);
    pluginname =
        getRequiredField(fs, "PluginName", NAME + " must contain a PluginName field", identifier);

    boolean hasData = "Data".equals(fs.getEndMarker());
    dataLength = resolveDataLength(fs, hasData, identifier);

    plugparams = extractPluginParams(fs);
    success = parseSuccess(fs, identifier);

    if (Boolean.FALSE.equals(success)) {
      errorCode = fs.get("ErrorCode");
      errorMessage = errorCode != null ? fs.get("ErrorMessage") : null;
    } else {
      errorCode = errorMessage = null;
    }
  }

  @Override
  String getIdentifier() {
    return identifier;
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
   * Returns the {@link SimpleFieldSet} backing this message, or {@code null} when the intermediary
   * representation has already been normalized into {@link FCPPluginMessage} form.
   *
   * <p>Client messages immediately extract their mandatory headers and plugin parameters during
   * construction, so exposing the parsed field set would invite accidental mutation or double
   * reading. Returning {@code null} signals that the canonical structure is the {@link
   * #constructFCPPluginMessage()} output rather than the transient parsing buffer.
   *
   * @return {@code null} because downstream callers must use {@link FCPPluginMessage} instead of
   *     the intermediate {@link SimpleFieldSet}
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    return null;
  }

  /**
   * Reports the wire-format identifier for this message so protocol stacks can emit or compare the
   * canonical tag irrespective of Java type names.
   *
   * <p>The value is fixed to {@link #NAME}, allowing loggers, metrics, and compatibility shims to
   * reason about legacy peers without embedding additional lookup tables. Retaining this mapping is
   * critical while new builds coexist with deployments that only understand {@code
   * FCPPluginMessage} as the discriminator inside multiplexed plugin channels.
   *
   * @return the literal {@link #NAME} constant advertised in on-network exchanges
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Builds a transport-neutral {@link FCPPluginMessage} so {@link FCPPluginConnection} can forward
   * this request without understanding how the {@link SimpleFieldSet} was parsed.
   *
   * <p>The returned message preserves the parsed identifier, parameter set, success indicator, and
   * optional error metadata while retaining the same bucket that stores binary payload data. Treat
   * the return value as a single-use view because plugin code may consume the bucket's stream once
   * and close it afterward.
   *
   * @return a newly constructed {@link FCPPluginMessage} sharing this instance's bucket and state
   */
  protected FCPPluginMessage constructFCPPluginMessage() {
    return FCPPluginMessage.constructRawMessage(
        null, identifier, plugparams, this.bucket, success, errorCode, errorMessage);
  }

  /**
   * Resolves the target {@link FCPPluginConnection} and delivers the message using {@link
   * SendDirection#TO_SERVER}, translating lookup or transport failures into protocol-friendly
   * exceptions.
   *
   * <p>The handler grants access to plugin-scoped connections; if the desired plugin cannot be
   * located or its connection disappears, the method throws {@link MessageInvalidException} so the
   * remote peer receives a deterministic error. Once a connection is available, the method creates
   * a {@link FCPPluginMessage} view and delegates sending, letting plugins stream payload buckets
   * as needed. The {@code node} parameter is passed for parity with other message types even though
   * this implementation currently interacts solely with the handler.
   *
   * <pre>{@code
   * FCPPluginClientMessage message = new FCPPluginClientMessage(fs);
   * message.run(handler, node);
   * }</pre>
   *
   * @param handler connection provider tied to the requesting client; must already manage plugin
   *     lifetimes and transport policies
   * @param node owning node instance for contextual logging or metrics; may be unused but must not
   *     be {@code null}
   * @throws MessageInvalidException if the plugin cannot be found or an I/O error occurs while
   *     forwarding the message to the server side implementation
   */
  @Override
  public void run(final FCPConnectionHandler handler, final Node node)
      throws MessageInvalidException {
    // Plugin messaging now requires the FCPPluginConnection interface provided by
    // FredPluginFCPMessageHandler.ServerSideFCPMessageHandler. Legacy PluginTalker delivery has
    // been removed, so lack of a connection means the plugin is unavailable.

    final FCPPluginConnection serverConnection;
    try {
      serverConnection = handler.getFCPPluginConnection(pluginname);
    } catch (PluginNotFoundException e) {
      throw pluginUnavailable();
    }

    if (serverConnection == null) {
      throw pluginUnavailable();
    }

    FCPPluginMessage message = constructFCPPluginMessage();

    try {
      serverConnection.send(SendDirection.TO_SERVER, message);
    } catch (IOException e) {
      throw pluginUnavailable();
    }
  }

  private MessageInvalidException pluginUnavailable() {
    return new MessageInvalidException(
        ProtocolErrorMessage.NO_SUCH_PLUGIN,
        pluginname + " not found or is not a FCPPlugin",
        identifier,
        false);
  }

  private static String getRequiredField(
      SimpleFieldSet fs, String fieldName, String errorMessage, String identifier)
      throws MessageInvalidException {
    String value = fs.get(fieldName);
    if (value == null) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.MISSING_FIELD, errorMessage, identifier, false);
    }
    return value;
  }

  private static long resolveDataLength(SimpleFieldSet fs, boolean hasData, String identifier)
      throws MessageInvalidException {
    String dataLengthString = fs.get("DataLength");

    if (!hasData) {
      if (dataLengthString != null) {
        throw new MessageInvalidException(
            ProtocolErrorMessage.INVALID_FIELD,
            "A nondata message can't have a DataLength field",
            identifier,
            false);
      }
      return -1;
    }

    if (dataLengthString == null) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.MISSING_FIELD,
          "Need DataLength on a Datamessage",
          identifier,
          false);
    }

    try {
      return Long.parseLong(dataLengthString, 10);
    } catch (NumberFormatException e) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.ERROR_PARSING_NUMBER,
          "Error parsing DataLength field: " + e.getMessage(),
          identifier,
          false);
    }
  }

  private static SimpleFieldSet extractPluginParams(SimpleFieldSet fs) {
    SimpleFieldSet maybePlugparams = fs.subset(PARAM_PREFIX);
    // subset() will return null if the subset is empty. To make server code more robust, we
    // hand out an empty mock SimpleFieldSet in that case.
    return maybePlugparams != null ? maybePlugparams : new SimpleFieldSet(true);
  }

  @Nullable
  private static Boolean parseSuccess(SimpleFieldSet fs, String identifier)
      throws MessageInvalidException {
    if (fs.get("Success") == null) {
      return null;
    }

    try {
      return fs.getBoolean("Success");
    } catch (FSParseException e) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.INVALID_FIELD,
          "Success must be a boolean (yes, no, true or false)",
          identifier,
          false);
    }
  }
}

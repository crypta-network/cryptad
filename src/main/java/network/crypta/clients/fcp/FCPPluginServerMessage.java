package network.crypta.clients.fcp;

import java.util.Objects;
import network.crypta.node.Node;
import network.crypta.pluginmanager.PluginManager;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.Bucket;

/**
 * Represents a server-to-client FCP plugin message in the on-wire format used by the node.
 *
 * <p>This class converts the high-level {@link FCPPluginMessage} representation produced by server
 * plugins into the serialized form that is sent to a remote FCP client. It is the logical inverse
 * of {@link FCPPluginClientMessage}, which parses client-to-server plugin messages. Instances of
 * this type are typically created shortly before transmission and then treated as immutable
 * containers for the identifier, parameters, optional data bucket, and success or error metadata.
 *
 * <p>The on-network name of this message is intentionally different from the class name: the
 * protocol identifier is {@value #NAME}. Historically, messages of this kind were used only as
 * direct replies from server to client. Asynchronous, unsolicited server messages are now allowed,
 * so the class was renamed to {@code FCPPluginServerMessage} to emphasize the direction rather than
 * the reply semantics, while the wire-level name was kept unchanged for backward compatibility. Any
 * future changes to the message name must preserve the ability to read old traffic.
 *
 * <ul>
 *   <li>Encodes plugin replies as {@link SimpleFieldSet} plus optional {@link Bucket} payload.
 *   <li>Supports both successful results and structured error reports.
 *   <li>Is used only for messages flowing from server to client, never the reverse.
 * </ul>
 *
 * @see FCPPluginConnection
 * @see FCPPluginConnectionImpl
 * @author saces
 * @author xor (xor@freenetproject.org)
 */
public class FCPPluginServerMessage extends DataCarryingMessage {

  /**
   * On-network format name of the message.
   *
   * <p>ATTENTION: This one is different to the class name. For an explanation, see the class-level
   * JavaDoc {@link FCPPluginServerMessage}.
   */
  private static final String NAME = "FCPPluginReply";

  /**
   * Field-set key under which reply parameters from plugins are stored.
   *
   * <p>The server nests the {@link #plugparams} field set under this prefix when serializing the
   * message so that reply-specific parameters remain grouped inside the surrounding {@link
   * SimpleFieldSet}. The exact string value is part of the on-wire protocol and must remain stable
   * to ensure interoperability with existing clients.
   */
  public static final String PARAM_PREFIX = "Replies";

  /**
   * @see FCPPluginMessage#data
   */
  private final long dataLength;

  /**
   * @see PluginManager#getPluginFCPServer(String)
   */
  private final String plugname;

  /**
   * @see FCPPluginMessage#identifier
   */
  private final String identifier;

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

  /**
   * Creates a server-to-client message by copying data from an existing {@link FCPPluginMessage}.
   *
   * <p>This convenience constructor is suitable when a plugin already built a complete {@link
   * FCPPluginMessage} instance and only needs to wrap it for transmission to the client. All
   * relevant fields are copied from the supplied message, and the original instance is not retained
   * after construction. The {@code pluginname} is stored verbatim and later emitted as the {@code
   * PluginName} field in the serialized {@link SimpleFieldSet}.
   *
   * @param pluginname the class name of the plugin sending the message; must not be {@code null};
   *     see {@link PluginManager#getPluginInfoByClassName(String)} for the expected naming
   *     convention.
   * @param message the source {@link FCPPluginMessage} providing identifier, parameters, payload,
   *     and success or error metadata; must not be {@code null}.
   */
  public FCPPluginServerMessage(String pluginname, FCPPluginMessage message) {

    this(
        Objects.requireNonNull(pluginname, "pluginname"),
        message.identifier,
        message.params,
        message.data,
        message.success,
        message.errorCode,
        message.errorMessage);
  }

  /**
   * Creates a server-to-client message from the individual plugin message components.
   *
   * <p>This constructor is useful when the caller maintains the identifier, parameter set, binary
   * payload, and success or error information separately instead of in a single {@link
   * FCPPluginMessage}. The supplied bucket is marked read-only and its size is cached as the
   * payload length. Callers may pass {@code null} for parameters, payload, or error fields when the
   * message does not require those aspects.
   *
   * @param pluginname the class name of the sending plugin as placed into the {@code PluginName}
   *     field; may be {@code null} when the plugin does not expose a name.
   * @param identifier2 identifier chosen by the plugin or client to correlate this reply with
   *     earlier requests; may be {@code null} when no correlation is required.
   * @param fs additional reply parameters to be nested under {@link #PARAM_PREFIX}; may be {@code
   *     null} or empty when the message carries no structured parameters.
   * @param bucket2 optional binary payload that is streamed to the client; may be {@code null} for
   *     messages without data; is marked read-only during construction.
   * @param success indicates whether the operation succeeded; {@code null} omits the field, {@code
   *     Boolean.TRUE} records success, and {@code Boolean.FALSE} usually pairs with error details.
   * @param errorCode machine-readable error code that is serialized only when {@code success} is
   *     {@code Boolean.FALSE}; ignored for successful messages.
   * @param errorMessage human-readable explanation of the failure, included only when an error code
   *     is present; primarily intended for logging or diagnostic display on the client side.
   */
  public FCPPluginServerMessage(
      String pluginname,
      String identifier2,
      SimpleFieldSet fs,
      Bucket bucket2,
      Boolean success,
      String errorCode,
      String errorMessage) {

    bucket = bucket2;
    if (bucket == null) dataLength = -1;
    else {
      bucket.setReadOnly();
      dataLength = bucket.size();
    }
    plugname = pluginname;
    identifier = identifier2;
    plugparams = fs;
    this.success = success;
    this.errorCode = errorCode;
    this.errorMessage = errorMessage;
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

  @Override
  String getEndString() {
    if (dataLength() > 0) return "Data";
    else return "EndMessage";
  }

  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    sfs.putSingle("PluginName", plugname);
    sfs.putSingle("Identifier", identifier);
    if (dataLength() > 0) sfs.put("DataLength", dataLength());

    // The sfs.put() would throw IllegalArgumentException if plugparams.isEmpty() == true.
    if (plugparams != null && !plugparams.isEmpty()) {
      sfs.put(PARAM_PREFIX, plugparams);
    }

    if (success != null) {
      sfs.put("Success", success);

      // Use Boolean.FALSE.equals() to avoid unboxing and keep null handling explicit.
      //noinspection PointlessBooleanExpression
      if (Boolean.FALSE.equals(success) && errorCode != null) {
        sfs.putSingle("ErrorCode", errorCode);

        if (errorMessage != null) {
          sfs.putSingle("ErrorMessage", errorMessage);
        }
      }
    }
    return sfs;
  }

  /**
   * Returns the protocol-level name associated with this message type.
   *
   * <p>The returned value is the stable on-wire identifier used for frames carrying this message
   * and intentionally differs from the Java class name for historical compatibility reasons.
   *
   * @return the constant message name {@value #NAME} used when serializing this message over FCP.
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Handles an inbound instance of this message on the server side.
   *
   * <p>For {@code FCPPluginServerMessage} this method always rejects the invocation because the
   * message is defined as flowing strictly from server to client. If a client nevertheless sends
   * such a message, the method throws a {@link MessageInvalidException} that reports a protocol
   * error back to the caller, allowing the connection logic to treat the message as invalid.
   *
   * @param handler connection handler representing the FCP client that attempted to send this
   *     message; mainly used for contextual error reporting.
   * @param node node instance that owns the connection; not used directly by this implementation
   *     but required by the superclass contract.
   * @throws MessageInvalidException always thrown to indicate that the client sent a server-only
   *     message type and the message must be treated as invalid.
   */
  @Override
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    throw new MessageInvalidException(
        ProtocolErrorMessage.INVALID_MESSAGE,
        NAME + " goes from server to client not the other way around",
        null,
        false);
  }
}

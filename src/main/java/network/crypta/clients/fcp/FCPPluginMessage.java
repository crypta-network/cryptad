package network.crypta.clients.fcp;

import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.StringValidityChecker;
import network.crypta.support.api.Bucket;

/**
 * Represents a container for both incoming and outgoing FCP (Freenet Client Protocol) messages.
 *
 * <p>This class serves as a unified envelope for message data, metadata, and status information
 * exchanged between the FCP server and client plugins. It encapsulates the message identifier,
 * parameters, bulk data, and optional reply status. Instances are designed to be immutable, except
 * the internal {@link #markSent()} state which tracks transmission.
 *
 * <p>Typical usage involves constructing a message using one of the static factory methods (e.g.,
 * {@link #construct(SimpleFieldSet, Bucket)} for new requests, or {@link
 * #constructReplyMessage(FCPPluginMessage, SimpleFieldSet, Bucket, boolean, String, String)} for
 * responses) and passing it to an {@link FCPPluginConnection}.
 *
 * <p>This class enforces strict validation on construction to ensure that message identifiers are
 * present and that reply-specific fields (success, error code, error message) are consistent with
 * the message type.
 */
public final class FCPPluginMessage {

  /**
   * Defines the access levels granted to an FCP client connecting to the node.
   *
   * <p>This enumeration categorizes the trust level and capabilities associated with a client
   * connection. The permissions are determined by the node's configuration and the client's
   * connection origin (e.g., local vs. remote, specific IP allowlists).
   *
   * <p>These permissions control which FCP messages and commands the client is authorized to send
   * and receive. For example, a client with {@link #ACCESS_FCP_RESTRICTED} may be barred from
   * performing administrative actions or accessing sensitive data, whereas {@link #ACCESS_DIRECT}
   * implies the client is running as a plugin within the node's own process space, effectively
   * granting it full privileges.
   *
   * <p>The permission level is typically assigned during the connection handshake and remains
   * constant for the duration of the session. It is exposed via {@link
   * FCPPluginMessage#permissions} to allow message handlers to enforce access controls based on the
   * sender's authorization.
   */
  public enum ClientPermissions {
    /**
     * Indicates that the client is connected via the network and the node owner has configured
     * restricted access for the client's IP address.
     *
     * <p>Clients with this permission level may be limited in the types of commands they can
     * execute or the data they can access.
     */
    ACCESS_FCP_RESTRICTED,

    /**
     * Indicates that the client is connected via the network and the node owner has configured full
     * access for the client's IP address.
     *
     * <p>Clients with this permission level generally have unrestricted access to FCP commands and
     * data.
     */
    ACCESS_FCP_FULL,

    /**
     * Indicates that the client plugin is running within the same Java Virtual Machine as the
     * server plugin.
     *
     * <p>This permission level implies the highest level of trust. Since the client code is
     * executing directly within the node's process, it effectively has full control. This value is
     * provided for completeness and informational purposes.
     */
    ACCESS_DIRECT
  }

  /**
   * The permissions granted to the client that sent the message.
   *
   * <p>This field indicates the authorization level of the message sender. It is typically
   * populated by the {@link FCPPluginConnection} before the message is delivered to the handler.
   *
   * <p>For server-to-client messages or outgoing messages constructed by the plugin, this field is
   * {@code null}.
   */
  public final ClientPermissions permissions;

  /**
   * The unique identifier for the message.
   *
   * <p>This identifier is used to correlate requests with their corresponding replies and to track
   * message progress. For synchronous operations, such as {@link
   * FCPPluginConnection#sendSynchronous(FCPPluginConnection.SendDirection, FCPPluginMessage,
   * long)}, the caller waits for a reply message bearing the same identifier.
   *
   * <p>For reply messages, this field must match the identifier of the original request message.
   * For new (non-reply) messages, this must be a globally unique string to prevent collisions. The
   * default implementation uses a random {@link UUID}.
   *
   * <p>While the FCP protocol allows arbitrary strings, using a random {@link UUID} is strongly
   * recommended to ensure uniqueness. Non-unique identifiers can break message tracking and
   * response correlation.
   */
  public final String identifier;

  /**
   * The structured parameters of the message.
   *
   * <p>This field contains the human-readable, key-value pairs associated with the message. It is
   * typically used for metadata, command arguments, or status information.
   *
   * <p>This field may be {@code null} for messages that only transfer bulk data or indicate simple
   * success/failure status without additional details.
   */
  public final SimpleFieldSet params;

  /**
   * The bulk data payload of the message.
   *
   * <p>This field holds large, non-human-readable data, such as file contents or binary blobs. It
   * is represented as a {@link Bucket}, which may be backed by memory or a temporary file.
   *
   * <p>This field may be {@code null} if the message does not contain any bulk data.
   */
  public final Bucket data;

  /**
   * The success status for reply messages.
   *
   * <p>This field indicates the outcome of the operation triggered by the original message. It is
   * {@code true} if the operation succeeded, and {@code false} if it failed.
   *
   * <p>For messages that are not replies (i.e., new requests), this field is always {@code null}.
   * The presence of a non-null value in this field is used by {@link #isReplyMessage()} to
   * determine if the message is a reply.
   */
  public final Boolean success;

  /**
   * The machine-readable error code for failed reply messages.
   *
   * <p>If {@link #success} is {@code false}, this field may contain an alphanumeric string
   * identifying the specific error condition. This allows software to programmatically handle
   * different failure modes.
   *
   * <p>This field must be {@code null} if {@link #success} is {@code true} or {@code null}. Common
   * practice is to use "InternalError" for unexpected exceptions.
   */
  public final String errorCode;

  /**
   * The human-readable error message for failed reply messages.
   *
   * <p>If {@link #errorCode} is present, this field may contain a descriptive string explaining the
   * error to a user. It is encouraged to provide localized messages where possible.
   *
   * <p>This field must be {@code null} if {@link #errorCode} is {@code null}. Unlike the error
   * code, this string is not intended for programmatic parsing.
   */
  public final String errorMessage;

  /**
   * A guard flag to detect and prevent accidental reuse of the same message instance.
   *
   * <p>This mutable flag tracks whether this message container has already been passed to the send
   * pipeline. It ensures that a single message object is not sent multiple times, which could lead
   * to protocol confusion or race conditions.
   */
  private final AtomicBoolean sent = new AtomicBoolean(false);

  /**
   * Determines whether this message is a reply to a previous message.
   *
   * <p>A message is considered a reply if its {@link #success} field is non-null. Reply messages
   * indicate the outcome (success or failure) of a previous operation identified by the same {@link
   * #identifier}.
   *
   * <p>It is important not to send a reply to a message that is itself a reply, as this could lead
   * to an infinite loop of acknowledgments.
   *
   * @return {@code true} if this message is a reply (i.e., {@link #success} is not null); {@code
   *     false} otherwise.
   */
  public boolean isReplyMessage() {
    return success != null;
  }

  /**
   * Internal constructor for creating an {@code FCPPluginMessage} with all fields specified.
   *
   * <p>This constructor performs strict validation of the parameters to ensure consistency, such as
   * ensuring that error codes are only present for failed replies and that identifiers are never
   * null.
   *
   * @param permissions the permissions of the sender, or {@code null} for outgoing messages.
   * @param identifier the unique identifier for the message; must not be {@code null}.
   * @param params the structured parameters of the message; may be {@code null}.
   * @param data the bulk data payload; may be {@code null}.
   * @param success the success status for replies, or {@code null} for non-replies.
   * @param errorCode the error code for failed replies; must be {@code null} if success is true.
   * @param errorMessage the human-readable error message; must be {@code null} if errorCode is
   *     null.
   */
  private FCPPluginMessage(
      ClientPermissions permissions,
      String identifier,
      SimpleFieldSet params,
      Bucket data,
      Boolean success,
      String errorCode,
      String errorMessage) {

    // See JavaDoc of member variables with the same name for reasons of the requirements
    assert (identifier != null);

    assert (params != null || data != null || success != null) : "Messages should not be empty";

    assert (errorCode == null || (success != null && !success))
        : "errorCode should only be provided for reply messages which indicate failure.";

    assert (errorCode == null || StringValidityChecker.isLatinLettersAndNumbersOnly(errorCode))
        : "errorCode should be alpha-numeric";

    assert (errorMessage == null || errorCode != null)
        : "errorCode should always be provided if there is an errorMessage";

    this.permissions = permissions;
    this.identifier = identifier;
    this.params = params;
    this.data = data;
    this.success = success;
    this.errorCode = errorCode;
    this.errorMessage = errorMessage;
  }

  /**
   * Constructs a new outgoing message with the specified parameters and data.
   *
   * <p>This method creates a new request message (not a reply) with a randomly generated {@link
   * UUID} as its identifier. This ensures that the message can be uniquely tracked and that any
   * future replies can be correctly correlated.
   *
   * <p>The generated message will have {@code success}, {@code errorCode}, and {@code errorMessage}
   * set to {@code null}, as these are only used for replies.
   *
   * @param params the structured parameters to include in the message; may be {@code null}.
   * @param data the bulk data payload to include in the message; may be {@code null}.
   * @return a new {@link FCPPluginMessage} instance ready to be sent.
   */
  public static FCPPluginMessage construct(SimpleFieldSet params, Bucket data) {
    // Notice: While the specification of FCP formally allows the client to freely chose the
    // ID, we hereby restrict it to be a random UUID instead of allowing the client
    // (or server) to chose it. This is to prevent accidental collisions with the IDs of
    // other messages. I cannot think of any use cases of free-choice identifiers. And
    // collisions are *bad*: They can break the "ACK" mechanism of the "success" variable.
    // This would in turn break things such as the sendSynchronous() functions of
    // FCPPluginConnection.
    return new FCPPluginMessage(
        null,
        UUID.randomUUID().toString(),
        params,
        data,
        // success, errorCode, errorMessage are null since non-reply messages must not
        // indicate errors
        null,
        null,
        null);
  }

  /**
   * Constructs a new outgoing message with default parameters and no data.
   *
   * <p>This is a convenience method equivalent to calling {@link #construct(SimpleFieldSet,
   * Bucket)} with a new, short-lived {@link SimpleFieldSet} and {@code null} data.
   *
   * <p>This is useful for simple commands or signals that do not require extensive parameters or
   * bulk data transfer.
   *
   * @return a new {@link FCPPluginMessage} instance with a unique identifier.
   */
  public static FCPPluginMessage construct() {
    return construct(new SimpleFieldSet(true), null);
  }

  /**
   * Constructs a reply message in response to an incoming message.
   *
   * <p>This method creates a new message that shares the same {@link #identifier} as the {@code
   * originalMessage}. This allows the recipient to correlate this reply with their original
   * request.
   *
   * <p>This method enforces that one cannot reply to a message that is itself already a reply. This
   * prevents infinite loops of automated responses.
   *
   * @param originalMessage the message being replied to; must not be a reply itself.
   * @param params the parameters to include in the reply; may be {@code null}.
   * @param data the bulk data to include in the reply; may be {@code null}.
   * @param success {@code true} if the operation succeeded, {@code false} otherwise.
   * @param errorCode the error code if the operation failed; must be {@code null} on success.
   * @param errorMessage the error message if the operation failed; must be {@code null} on success.
   * @return a new {@link FCPPluginMessage} representing the reply.
   * @throws IllegalStateException if {@code originalMessage} is already a reply message.
   */
  public static FCPPluginMessage constructReplyMessage(
      FCPPluginMessage originalMessage,
      SimpleFieldSet params,
      Bucket data,
      boolean success,
      String errorCode,
      String errorMessage) {

    if (originalMessage.isReplyMessage()) {
      throw new IllegalStateException(
          "Constructing a reply message for a message which "
              + "was a reply message already not allowed.");
    }

    return new FCPPluginMessage(
        null, originalMessage.identifier, params, data, success, errorCode, errorMessage);
  }

  /**
   * Constructs a successful reply message with default parameters.
   *
   * <p>This is a convenience method for creating a standard success response. It sets {@code
   * success} to {@code true}, and both error fields to {@code null}. It uses a default short-lived
   * {@link SimpleFieldSet} for parameters and includes no bulk data.
   *
   * @param originalMessage the message being replied to; must not be a reply itself.
   * @return a new {@link FCPPluginMessage} indicating success.
   * @throws IllegalStateException if {@code originalMessage} is already a reply message.
   */
  public static FCPPluginMessage constructSuccessReply(FCPPluginMessage originalMessage) {
    return constructReplyMessage(originalMessage, new SimpleFieldSet(true), null, true, null, null);
  }

  /**
   * Constructs a failure reply message with the specified error details.
   *
   * <p>This is a convenience method for creating a standard error response. It sets {@code success}
   * to {@code false}, and populates the {@code errorCode} and {@code errorMessage} fields. It uses
   * a default short-lived {@link SimpleFieldSet} for parameters and includes no bulk data.
   *
   * @param originalMessage the message being replied to; must not be a reply itself.
   * @param errorCode the alphanumeric error code identifying the failure type.
   * @param errorMessage the human-readable description of the error.
   * @return a new {@link FCPPluginMessage} indicating failure.
   * @throws IllegalStateException if {@code originalMessage} is already a reply message.
   */
  public static FCPPluginMessage constructErrorReply(
      FCPPluginMessage originalMessage, String errorCode, String errorMessage) {

    return constructReplyMessage(
        originalMessage, new SimpleFieldSet(true), null, false, errorCode, errorMessage);
  }

  /**
   * Internal factory method for constructing raw messages, typically from network data.
   *
   * <p><b>Attention:</b> This method is intended for use by the internal network layer when parsing
   * incoming messages. It allows setting all fields directly, including the identifier and
   * permissions. Application code should generally use {@link #construct(SimpleFieldSet, Bucket)}
   * or the reply constructors instead.
   *
   * @param permissions the permissions of the sender.
   * @param identifier the unique identifier of the message.
   * @param params the message parameters.
   * @param data the bulk data payload.
   * @param success the success status (for replies).
   * @param errorCode the error code (for failed replies).
   * @param errorMessage the error message (for failed replies).
   * @return a new {@link FCPPluginMessage} instance.
   */
  static FCPPluginMessage constructRawMessage(
      ClientPermissions permissions,
      String identifier,
      SimpleFieldSet params,
      Bucket data,
      Boolean success,
      String errorCode,
      String errorMessage) {

    return new FCPPluginMessage(
        permissions, identifier, params, data, success, errorCode, errorMessage);
  }

  /**
   * Atomically marks this message as having been sent.
   *
   * <p>This method is used by the network layer to ensure that a message is not accidentally sent
   * multiple times. It uses an atomic state transition to provide thread safety.
   *
   * @return {@code true} if this call successfully marked the message as sent (i.e., it was the
   *     first time); {@code false} if the message had already been marked as sent.
   */
  public boolean markSent() {
    return sent.compareAndSet(false, true);
  }

  /**
   * Returns a string representation of this message.
   *
   * <p>The returned string includes the values of all major fields, including permissions,
   * identifier, data presence, success status, and error details. The parameters are appended at
   * the end, potentially spanning multiple lines.
   *
   * @return a string describing the message state.
   */
  @Override
  public String toString() {
    return super.toString()
        + " (permissions: "
        + permissions
        + "; identifier: "
        + identifier
        + "; data: "
        + data
        + "; success: "
        + success
        + "; errorCode: "
        + errorCode
        + "; errorMessage: "
        + errorMessage
        +
        // At the end because a SimpleFieldSet usually contains multiple line breaks.
        "; params: "
        + '\n'
        + (params != null ? params.toOrderedString() : null);
  }
}

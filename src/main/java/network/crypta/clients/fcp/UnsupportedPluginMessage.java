package network.crypta.clients.fcp;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.io.FileUtil;
import network.crypta.support.io.NullOutputStream;

/**
 * Rejects legacy plugin-related FCP commands with a deterministic protocol error.
 *
 * <p>Plugin runtime support has been removed from the node, but long-lived client implementations
 * can still send historical plugin command names. This message class serves as a compatibility
 * guardrail for that wire-level behavior: it accepts those command frames, validates whether their
 * payload framing is coherent, consumes any declared payload bytes when required, and then reports
 * an explicit protocol-level rejection.
 *
 * <p>This approach keeps the connection stream synchronized after a rejected command and avoids
 * turning a legacy feature use into cascading parser errors for subsequent messages on the same
 * socket. The class is intentionally narrow and side-effect free: it never performs plugin
 * execution, state mutation outside protocol responses, or server-originated payload writes.
 *
 * <ul>
 *   <li><b>Primary responsibility:</b> preserve deterministic FCP compatibility for removed plugin
 *       commands.
 *   <li><b>Secondary responsibility:</b> enforce data-framing rules so unread payload bytes do not
 *       desynchronize input parsing.
 * </ul>
 */
final class UnsupportedPluginMessage extends BaseDataCarryingMessage {
  /** Stable text returned to clients when a removed plugin command is invoked. */
  private static final String UNSUPPORTED_TEXT =
      "Plugin system has been removed; this command is no longer supported.";

  /**
   * Historical FCP command name that allowed a trailing data frame.
   *
   * <p>Only this legacy message type is permitted to carry a {@code DataLength}/{@code Data}
   * framing pair in this compatibility path.
   */
  private static final String LEGACY_PLUGIN_MESSAGE = "FCPPluginMessage";

  /** Incoming message name as parsed from the FCP frame header. */
  private final String messageName;

  /**
   * Optional request identifier provided by the client.
   *
   * <p>Forwarded in protocol error responses so callers can correlate asynchronous failures with
   * their original request.
   */
  private final String requestIdentifier;

  /**
   * Number of payload bytes to consume from the stream.
   *
   * <p>A negative value indicates that the message is non-data-carrying and no payload drain is
   * required.
   */
  private final long payloadLength;

  /**
   * Creates a compatibility handler for a removed plugin command.
   *
   * <p>The constructor captures request metadata and validates payload framing constraints for the
   * supplied command name. For {@code FCPPluginMessage}, data framing is accepted and a declared
   * payload length is parsed for later draining. For all other legacy plugin command names, data
   * framing is rejected to preserve strict protocol behavior.
   *
   * @param fs field set parsed from the incoming FCP frame; used for identifier and payload fields
   * @param messageName command name parsed from the incoming frame header
   * @throws MessageInvalidException if payload framing is invalid for the command or length parsing
   *     fails
   */
  UnsupportedPluginMessage(SimpleFieldSet fs, String messageName) throws MessageInvalidException {
    this.messageName = messageName;
    this.requestIdentifier = fs.get("Identifier");
    this.payloadLength = resolvePayloadLength(fs, messageName, requestIdentifier);
  }

  @Override
  public SimpleFieldSet getFieldSet() {
    return null;
  }

  @Override
  public String getName() {
    return messageName;
  }

  @Override
  long dataLength() {
    return payloadLength;
  }

  @Override
  public void readFrom(InputStream is, BucketFactory bf, FCPServer server) throws IOException {
    if (payloadLength <= 0) {
      return;
    }
    FileUtil.copy(is, new NullOutputStream(), payloadLength);
  }

  @Override
  protected void writeData(OutputStream os) {
    // Unsupported inbound command; server never serializes this type with payload bytes.
  }

  @Override
  public void run(FCPConnectionHandler handler) throws MessageInvalidException {
    handler.send(
        new ProtocolErrorMessage(
            ProtocolErrorMessage.INVALID_MESSAGE,
            false,
            UNSUPPORTED_TEXT,
            requestIdentifier,
            false));
  }

  /**
   * Validates and resolves payload framing for unsupported legacy plugin commands.
   *
   * <p>The parser-level compatibility rule is intentionally strict: only legacy {@code
   * FCPPluginMessage} may carry a data frame in this compatibility path. When data framing is
   * permitted, this method validates {@code DataLength}, parses it as a non-negative decimal value,
   * and returns the exact number of bytes that must be drained from the socket input stream. For
   * non-data messages it returns {@code -1}.
   *
   * @param fs parsed field set containing end marker and optional data length fields
   * @param messageName parsed FCP command name used to enforce framing rules
   * @param requestIdentifier optional request identifier echoed in protocol errors
   * @return non-negative payload length to consume, or {@code -1} when no payload is expected
   * @throws MessageInvalidException if framing rules are violated or {@code DataLength} is invalid
   */
  private static long resolvePayloadLength(
      SimpleFieldSet fs, String messageName, String requestIdentifier)
      throws MessageInvalidException {
    boolean hasData = "Data".equals(fs.getEndMarker());
    String dataLengthField = fs.get("DataLength");

    if (!LEGACY_PLUGIN_MESSAGE.equals(messageName)) {
      if (hasData || dataLengthField != null) {
        throw new MessageInvalidException(
            ProtocolErrorMessage.INVALID_FIELD,
            messageName + " does not support Data framing",
            requestIdentifier,
            false);
      }
      return -1;
    }

    if (!hasData) {
      if (dataLengthField != null) {
        throw new MessageInvalidException(
            ProtocolErrorMessage.INVALID_FIELD,
            "A nondata message can't have a DataLength field",
            requestIdentifier,
            false);
      }
      return -1;
    }

    if (dataLengthField == null) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.MISSING_FIELD,
          "Need DataLength on a Datamessage",
          requestIdentifier,
          false);
    }

    long parsedLength;
    try {
      parsedLength = Long.parseLong(dataLengthField, 10);
    } catch (NumberFormatException e) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.ERROR_PARSING_NUMBER,
          "Error parsing DataLength field: " + e.getMessage(),
          requestIdentifier,
          false);
    }

    if (parsedLength < 0) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.INVALID_FIELD,
          "DataLength must be non-negative",
          requestIdentifier,
          false);
    }
    return parsedLength;
  }
}

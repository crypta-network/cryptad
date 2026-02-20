package network.crypta.clients.fcp;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.io.FileUtil;
import network.crypta.support.io.NullOutputStream;

/**
 * Rejects legacy plugin-related FCP commands with a deterministic protocol error.
 *
 * <p>Plugin runtime support has been removed from the node. This message preserves parser-level
 * compatibility for historical plugin command names while returning a clear unsupported-feature
 * error instead of an unknown-message failure.
 */
final class UnsupportedPluginMessage extends BaseDataCarryingMessage {
  private static final String UNSUPPORTED_TEXT =
      "Plugin system has been removed; this command is no longer supported.";

  private static final String LEGACY_PLUGIN_MESSAGE = "FCPPluginMessage";

  private final String messageName;
  private final String requestIdentifier;
  private final long payloadLength;

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
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    handler.send(
        new ProtocolErrorMessage(
            ProtocolErrorMessage.INVALID_MESSAGE,
            false,
            UNSUPPORTED_TEXT,
            requestIdentifier,
            false));
  }

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

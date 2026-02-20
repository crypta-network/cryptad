package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;

/**
 * Rejects legacy plugin-related FCP commands with a deterministic protocol error.
 *
 * <p>Plugin runtime support has been removed from the node. This message preserves parser-level
 * compatibility for historical plugin command names while returning a clear unsupported-feature
 * error instead of an unknown-message failure.
 */
final class UnsupportedPluginMessage extends FCPMessage {
  private static final String UNSUPPORTED_TEXT =
      "Plugin system has been removed; this command is no longer supported.";

  private final String messageName;
  private final String requestIdentifier;

  UnsupportedPluginMessage(SimpleFieldSet fs, String messageName) {
    this.messageName = messageName;
    this.requestIdentifier = fs.get("Identifier");
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
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    handler.send(
        new ProtocolErrorMessage(
            ProtocolErrorMessage.INVALID_MESSAGE,
            false,
            UNSUPPORTED_TEXT,
            requestIdentifier,
            false));
  }
}

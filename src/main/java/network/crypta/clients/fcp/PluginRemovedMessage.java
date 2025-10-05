package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author saces
 */
public class PluginRemovedMessage extends FCPMessage {
  private static final Logger LOG = LoggerFactory.getLogger(PluginRemovedMessage.class);

  static final String NAME = "PluginRemoved";

  private final String identifier;

  private final String plugname;

  PluginRemovedMessage(String plugname2, String identifier2) {
    this.identifier = identifier2;
    this.plugname = plugname2;
  }

  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    sfs.putSingle("Identifier", identifier);
    sfs.putSingle("PluginName", plugname);
    return sfs;
  }

  @Override
  public String getName() {
    return NAME;
  }

  @Override
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    throw new MessageInvalidException(
        ProtocolErrorMessage.INVALID_MESSAGE,
        NAME + " goes from server to client not the other way around",
        null,
        false);
  }
}

package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class UnsubscribeUSKMessage extends FCPMessage {
  private static final Logger LOG = LoggerFactory.getLogger(UnsubscribeUSKMessage.class);

  public static final String NAME = "UnsubscribeUSK";
  private final String identifier;

  public UnsubscribeUSKMessage(SimpleFieldSet fs) throws MessageInvalidException {
    this.identifier = fs.get("Identifier");
    if (identifier == null)
      throw new MessageInvalidException(
          ProtocolErrorMessage.MISSING_FIELD, "No Identifier!", null, false);
  }

  @Override
  public SimpleFieldSet getFieldSet() {
    throw new UnsupportedOperationException();
  }

  @Override
  public String getName() {
    return NAME;
  }

  @Override
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    handler.unsubscribeUSK(identifier);
  }
}

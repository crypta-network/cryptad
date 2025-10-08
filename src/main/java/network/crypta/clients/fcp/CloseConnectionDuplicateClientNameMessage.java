package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Error sent when the connection is closed because another connection with the same client Name has
 * been opened. Usually the client will not see this, because it is being sent to a dead connection.
 */
public class CloseConnectionDuplicateClientNameMessage extends FCPMessage {
  private static final Logger LOG =
      LoggerFactory.getLogger(CloseConnectionDuplicateClientNameMessage.class);

  @Override
  public SimpleFieldSet getFieldSet() {
    return new SimpleFieldSet(true);
  }

  @Override
  public String getName() {
    return "CloseConnectionDuplicateClientName";
  }

  @Override
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    throw new MessageInvalidException(
        ProtocolErrorMessage.INVALID_MESSAGE,
        "CloseConnectionDuplicateClientName goes from server to client not the other way around",
        null,
        false);
  }
}

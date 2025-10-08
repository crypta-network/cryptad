package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class IdentifierCollisionMessage extends FCPMessage {
  private static final Logger LOG = LoggerFactory.getLogger(IdentifierCollisionMessage.class);

  final String identifier;
  final boolean global;

  public IdentifierCollisionMessage(String id, boolean global) {
    this.identifier = id;
    this.global = global;
  }

  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    sfs.putSingle("Identifier", identifier);
    sfs.put("Global", global);
    return sfs;
  }

  @Override
  public String getName() {
    return "IdentifierCollision";
  }

  @Override
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    throw new MessageInvalidException(
        ProtocolErrorMessage.INVALID_MESSAGE,
        "IdentifierCollision goes from server to client not the other way around",
        identifier,
        global);
  }
}

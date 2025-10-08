package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Node answer message after a RemovePersistentRequest message from client. */
public class PersistentRequestRemovedMessage extends FCPMessage {
  private static final Logger LOG = LoggerFactory.getLogger(PersistentRequestRemovedMessage.class);

  private final String ident;
  private final boolean global;

  public PersistentRequestRemovedMessage(String identifier, boolean global) {
    this.ident = identifier;
    this.global = global;
  }

  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", ident);
    fs.put("Global", global);
    return fs;
  }

  @Override
  public String getName() {
    return "PersistentRequestRemoved";
  }

  @Override
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    throw new MessageInvalidException(
        ProtocolErrorMessage.INVALID_MESSAGE,
        "PersistentRequestRemoved goes from server to client not the other way around",
        ident,
        global);
  }
}

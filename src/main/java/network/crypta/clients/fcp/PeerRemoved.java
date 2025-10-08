package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PeerRemoved extends FCPMessage {
  private static final Logger LOG = LoggerFactory.getLogger(PeerRemoved.class);

  static final String name = "PeerRemoved";
  final String identity;
  final String nodeIdentifier;
  final String identifier;

  public PeerRemoved(String identity, String nodeIdentifier, String identifier) {
    this.identity = identity;
    this.nodeIdentifier = nodeIdentifier;
    this.identifier = identifier;
  }

  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identity", identity);
    fs.putSingle("NodeIdentifier", nodeIdentifier);
    if (identifier != null) fs.putSingle("Identifier", identifier);
    return fs;
  }

  @Override
  public String getName() {
    return name;
  }

  @Override
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    throw new MessageInvalidException(
        ProtocolErrorMessage.INVALID_MESSAGE,
        "PeerRemoved goes from server to client not the other way around",
        identifier,
        false);
  }
}

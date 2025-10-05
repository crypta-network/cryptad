package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.node.PeerNode;
import network.crypta.support.SimpleFieldSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ListPeerMessage extends FCPMessage {
  private static final Logger LOG = LoggerFactory.getLogger(ListPeerMessage.class);

  static final String NAME = "ListPeer";

  final SimpleFieldSet fs;
  final String identifier;

  public ListPeerMessage(SimpleFieldSet fs) {
    this.fs = fs;
    this.identifier = fs.get("Identifier");
    fs.removeValue("Identifier");
  }

  @Override
  public SimpleFieldSet getFieldSet() {
    return new SimpleFieldSet(true);
  }

  @Override
  public String getName() {
    return NAME;
  }

  @Override
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    if (!handler.hasFullAccess()) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.ACCESS_DENIED, "ListPeer requires full access", identifier, false);
    }
    String nodeIdentifier = fs.get("NodeIdentifier");
    if (nodeIdentifier == null) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.MISSING_FIELD,
          "Error: NodeIdentifier field missing",
          identifier,
          false);
    }
    PeerNode pn = node.getPeerNode(nodeIdentifier);
    if (pn == null) {
      FCPMessage msg = new UnknownNodeIdentifierMessage(nodeIdentifier, identifier);
      handler.send(msg);
      return;
    }
    handler.send(new PeerMessage(pn, true, true, identifier));
  }
}

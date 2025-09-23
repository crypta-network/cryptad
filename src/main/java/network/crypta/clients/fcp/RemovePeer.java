package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.node.PeerNode;
import network.crypta.support.SimpleFieldSet;

public class RemovePeer extends FCPMessage {

  static final String NAME = "RemovePeer";

  final SimpleFieldSet fs;
  final String identifier;

  public RemovePeer(SimpleFieldSet fs) {
    this.fs = fs;
    identifier = fs.get("Identifier");
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
          ProtocolErrorMessage.ACCESS_DENIED, NAME + " requires full access", identifier, false);
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
    String identity = pn.getIdentityString();
    node.removePeerConnection(pn);
    handler.send(new PeerRemoved(identity, nodeIdentifier, identifier));
  }
}

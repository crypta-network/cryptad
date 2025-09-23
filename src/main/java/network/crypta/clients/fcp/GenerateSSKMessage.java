package network.crypta.clients.fcp;

import network.crypta.keys.FreenetURI;
import network.crypta.keys.InsertableClientSSK;
import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;

public class GenerateSSKMessage extends FCPMessage {

  static final String NAME = "GenerateSSK";
  final String identifier;

  GenerateSSKMessage(SimpleFieldSet fs) {
    identifier = fs.get("Identifier");
  }

  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    if (identifier != null) fs.putSingle("Identifier", identifier);
    return fs;
  }

  @Override
  public String getName() {
    return NAME;
  }

  @Override
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    InsertableClientSSK key = InsertableClientSSK.createRandom(node.getRandom(), "");
    FreenetURI insertURI = key.getInsertURI();
    FreenetURI requestURI = key.getURI();
    SSKKeypairMessage msg = new SSKKeypairMessage(insertURI, requestURI, identifier);
    handler.send(msg);
  }
}

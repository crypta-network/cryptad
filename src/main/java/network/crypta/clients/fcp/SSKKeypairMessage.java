package network.crypta.clients.fcp;

import network.crypta.keys.FreenetURI;
import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SSKKeypairMessage extends FCPMessage {
  private static final Logger LOG = LoggerFactory.getLogger(SSKKeypairMessage.class);

  private final FreenetURI insertURI;
  private final FreenetURI requestURI;
  private final String identifier;

  public SSKKeypairMessage(FreenetURI insertURI, FreenetURI requestURI, String identifier) {
    this.insertURI = insertURI;
    this.requestURI = requestURI;
    this.identifier = identifier;
  }

  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    sfs.putSingle("InsertURI", insertURI.toString());
    sfs.putSingle("RequestURI", requestURI.toString());
    if (identifier != null) // is optional on these two only
    sfs.putSingle("Identifier", identifier);
    return sfs;
  }

  @Override
  public String getName() {
    return "SSKKeypair";
  }

  @Override
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    throw new MessageInvalidException(
        ProtocolErrorMessage.INVALID_MESSAGE,
        "SSKKeypair goes from server to client not the other way around",
        identifier,
        false);
  }
}

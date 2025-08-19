package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.node.PeerNode;
import network.crypta.support.SimpleFieldSet;

public class PeerMessage extends FCPMessage {
  static final String name = "Peer";

  final PeerNode pn;
  final boolean withMetadata;
  final boolean withVolatile;
  final String identifier;

  public PeerMessage(PeerNode pn, boolean withMetadata, boolean withVolatile, String identifier) {
    this.pn = pn;
    this.withMetadata = withMetadata;
    this.withVolatile = withVolatile;
    this.identifier = identifier;
  }

  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet fs = pn.exportFieldSet();
    if (withMetadata) {
      SimpleFieldSet meta = pn.exportMetadataFieldSet(System.currentTimeMillis());
      if (!meta.isEmpty()) {
        fs.put("metadata", meta);
      }
    }
    if (withVolatile) {
      SimpleFieldSet vol = pn.exportVolatileFieldSet();
      if (!vol.isEmpty()) {
        fs.put("volatile", vol);
      }
    }
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
        "Peer goes from server to client not the other way around",
        null,
        false);
  }
}

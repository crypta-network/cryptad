package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ExpectedDataLength extends FCPMessage {
  private static final Logger LOG = LoggerFactory.getLogger(ExpectedDataLength.class);

  final String identifier;
  final boolean global;
  final long dataLength;

  ExpectedDataLength(String identifier, boolean global, long dataLength) {
    this.identifier = identifier;
    this.global = global;
    this.dataLength = dataLength;
  }

  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(false);
    fs.putOverwrite("Identifier", identifier);
    fs.put("Global", global);
    fs.put("DataLength", dataLength);
    return fs;
  }

  @Override
  public String getName() {
    return "ExpectedDataLength";
  }

  @Override
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    // Not supported
  }
}

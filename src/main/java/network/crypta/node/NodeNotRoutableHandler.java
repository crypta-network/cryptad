package network.crypta.node;

import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.MessageType;
import network.crypta.io.comm.NotConnectedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Handles early rejects for non-routable sources. */
final class NodeNotRoutableHandler {

  private static final Logger LOG = LoggerFactory.getLogger(NodeNotRoutableHandler.class);

  private final Node node;

  NodeNotRoutableHandler(Node node) {
    this.node = node;
  }

  boolean handle(Message m) {
    MessageType spec = m.getSpec();
    if (LOG.isTraceEnabled()) LOG.trace("Peer not routable");
    if (spec == DMT.FNPCHKDataRequest) {
      rejectRequest(m, node.network().stats().chkRequestCtr);
    } else if (spec == DMT.FNPSSKDataRequest) {
      rejectRequest(m, node.network().stats().sskRequestCtr);
    } else if (spec == DMT.FNPInsertRequest) {
      rejectRequest(m, node.network().stats().chkInsertCtr);
    } else if (spec == DMT.FNPSSKInsertRequest) {
      rejectRequest(m, node.network().stats().sskInsertCtr);
    } else if (spec == DMT.FNPSSKInsertRequestNew) {
      rejectRequest(m, node.network().stats().sskInsertCtr);
    } else if (spec == DMT.FNPGetOfferedKey) {
      rejectRequest(m, node.routing().failureTable().senderCounter);
    } else {
      return false;
    }
    return true;
  }

  private void rejectRequest(Message m, ByteCounter ctr) {
    long uid = m.getLong(DMT.UID);
    Message msg = DMT.createFNPRejectedOverload(uid, true);
    try {
      m.getSource().transport().sendAsync(msg, null, ctr);
    } catch (NotConnectedException _) {
      // Ignore
    }
  }
}

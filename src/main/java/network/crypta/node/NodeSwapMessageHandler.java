package network.crypta.node;

import network.crypta.io.comm.DMT;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.MessageType;

/** Handles swap request/response message family. */
final class NodeSwapMessageHandler {

  private final Node node;

  NodeSwapMessageHandler(Node node) {
    this.node = node;
  }

  boolean handle(Message m, PeerNode source) {
    MessageType spec = m.getSpec();
    if (spec == DMT.FNPSwapRequest) {
      node.network().locationManager().handleSwapRequest(m, source);
      return true;
    } else if (spec == DMT.FNPSwapReply) {
      return node.network().locationManager().handleSwapReply(m, source);
    } else if (spec == DMT.FNPSwapRejected) {
      return node.network().locationManager().handleSwapRejected(m, source);
    } else if (spec == DMT.FNPSwapCommit) {
      return node.network().locationManager().handleSwapCommit(m, source);
    } else if (spec == DMT.FNPSwapComplete) {
      return node.network().locationManager().handleSwapComplete(m, source);
    }
    return false;
  }
}

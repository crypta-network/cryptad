package network.crypta.node;

import network.crypta.io.comm.DMT;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.MessageType;
import network.crypta.node.probe.Listener;
import network.crypta.node.probe.Probe;
import network.crypta.node.probe.Type;

/** Handles probe requests and probe start delegation. */
final class NodeProbeHandler {

  private final Probe probe;

  NodeProbeHandler(Node node) {
    this.probe = new Probe(node);
  }

  boolean handle(Message m, PeerNode source) {
    MessageType spec = m.getSpec();
    if (spec == DMT.ProbeRequest) {
      probe.request(m, source);
      return true;
    }
    return false;
  }

  void startProbe(byte htl, long uid, Type type, Listener listener) {
    probe.start(htl, uid, type, listener);
  }
}

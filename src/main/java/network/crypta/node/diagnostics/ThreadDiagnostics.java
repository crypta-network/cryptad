package network.crypta.node.diagnostics;

import network.crypta.node.diagnostics.threads.NodeThreadSnapshot;

public interface ThreadDiagnostics {
  NodeThreadSnapshot getThreadSnapshot();
}

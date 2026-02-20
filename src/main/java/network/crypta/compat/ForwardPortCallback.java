package network.crypta.compat;

import java.util.Map;

/** Compatibility callback for asynchronous port-forward status updates. */
public interface ForwardPortCallback {
  void portForwardStatus(Map<ForwardPort, ForwardPortStatus> statuses);
}

package network.crypta.pluginmanager;

import java.util.Map;

/**
 * Callback called by port forwarding plugins to indicate success or failure.
 *
 * @author toad
 */
public interface ForwardPortCallback {

  /** Called to indicate status on one or more forwarded ports. */
  void portForwardStatus(Map<ForwardPort, ForwardPortStatus> statuses);
}

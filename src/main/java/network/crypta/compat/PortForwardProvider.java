package network.crypta.compat;

import java.util.Set;

/** Receives public-port updates and reports port-forward status checks. */
public interface PortForwardProvider {
  void onChangePublicPorts(Set<ForwardPort> ports, ForwardPortCallback callback);
}

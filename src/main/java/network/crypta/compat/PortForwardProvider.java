package network.crypta.compat;

import java.util.Set;

/**
 * Applies public-port forwarding requests and reports mapping outcomes through a callback.
 *
 * <p>Implementations receive the node's current desired set of externally reachable ports and are
 * responsible for translating those requests into concrete NAT/firewall actions (for example, UPnP,
 * NAT-PMP, PCP, or platform-specific rule management). After attempting changes, providers report
 * per-port status snapshots through the supplied {@link ForwardPortCallback}.
 *
 * <p>The contract is intentionally asynchronous-friendly: providers may perform work immediately or
 * on background workers and may emit multiple callback updates over time as state changes. Callers
 * should assume the provider can report partial success and that mappings may degrade or recover
 * independently across ports.
 *
 * <ul>
 *   <li><b>Input:</b> desired forwarded-port set represented as compatibility {@link ForwardPort}
 *       entries.
 *   <li><b>Output:</b> status updates pushed through {@link ForwardPortCallback}.
 * </ul>
 */
public interface PortForwardProvider {
  /**
   * Handles a change in desired public ports and begins forwarding checks or updates.
   *
   * <p>The provider should treat {@code ports} as the latest desired target set, reconciling any
   * previous mappings as needed. It may invoke the callback synchronously for quick results or
   * asynchronously when gateway discovery and verification require additional time.
   *
   * @param ports desired externally reachable ports to forward for the current node state
   * @param callback receiver for one or more status batches produced by this provider
   */
  void onChangePublicPorts(Set<ForwardPort> ports, ForwardPortCallback callback);
}

package network.crypta.io.comm;

/**
 * Transport that can re-evaluate external reachability (port forwarding) on demand.
 *
 * <p>Used by components that observe conditions implying that previously detected connectivity (for
 * example, NAT or firewall port mappings) may no longer be accurate. Implementations should trigger
 * a fresh probe and update the node's address-tracking status used for routing and UI hints.
 *
 * <p>Threading: Callers may invoke methods from I/O or management threads. Implementations should
 * avoid long blocking work on the caller thread.
 */
public interface PortForwardSensitiveSocketHandler extends SocketHandler {

  /**
   * Requests that the transport verify current port-forwarding status.
   *
   * <p>Implementations should initiate any necessary checks (for example, NAT-PMP/UPnP queries or
   * external reachability tests) and propagate updated status to interested components.
   */
  @SuppressWarnings("unused")
  void rescanPortForward();
}

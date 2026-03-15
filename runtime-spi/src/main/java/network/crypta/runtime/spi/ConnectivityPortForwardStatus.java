package network.crypta.runtime.spi;

/**
 * Detached connectivity-status states for the connectivity admin page.
 *
 * <p>These values mirror the legacy address-tracker status states closely enough that the
 * connectivity page can keep its existing localization keys and presentation logic. The enum lives
 * in {@code runtime-spi} so HTTP code can describe UDP reachability without depending on daemon
 * tracker classes or their serialization details.
 *
 * <p>The ordering is not significant. Callers should treat the values as named states rather than
 * as an ordered severity scale.
 */
public enum ConnectivityPortForwardStatus {
  /** Confirms that inbound UDP reachability is blocked by network address translation. */
  DEFINITELY_NATED,

  /** Suggests that the node is likely behind NAT, but the tracker does not have final evidence. */
  MAYBE_NATED,

  /** Indicates that the tracker has not observed enough data to classify the connection yet. */
  DONT_KNOW,

  /** Suggests that inbound UDP reachability may work, but the conclusion is not final. */
  MAYBE_PORT_FORWARDED,

  /** Confirms that the node appears reachable from the wider network on this socket. */
  DEFINITELY_PORT_FORWARDED
}

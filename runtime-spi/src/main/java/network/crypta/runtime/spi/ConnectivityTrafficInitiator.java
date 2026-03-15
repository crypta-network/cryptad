package network.crypta.runtime.spi;

/**
 * Detached initiator states for advanced connectivity tracker rows.
 *
 * <p>The connectivity page presents a coarse answer to a simple operator question: did the node
 * appear to send first, receive first, or never get a reply at all for a tracked address. This enum
 * carries that answer without exposing the daemon's tracker item implementation details to the HTTP
 * layer.
 */
public enum ConnectivityTrafficInitiator {
  /** The node has sent traffic, but no reply has been recorded for this tracker row. */
  NO_REPLY,

  /** The first observed traffic for this row originated from the local node. */
  LOCAL,

  /** The first observed traffic for this row originated from the remote side. */
  REMOTE
}

package network.crypta.runtime.spi;

import java.util.Objects;

/**
 * Signals that a resolved peer cannot satisfy a darknet-only operation.
 *
 * <p>This checked exception is part of the peer-management SPI boundary. It tells higher layers
 * that lookup succeeded, but the requested action only applies to darknet peers. Management-facing
 * code can keep its own access-control and wire-level error mapping while still distinguishing
 * "peer not found" from "peer found, but wrong peer family" without depending on daemon-only peer
 * classes.
 *
 * <p>The exception carries the node identifier that resolved to a non-darknet peer. Callers
 * normally map it to an existing protocol error and should not treat it as a transport or parsing
 * problem.
 */
public final class DarknetPeerRequiredException extends Exception {
  private final String nodeIdentifier;

  /**
   * Creates an exception describing a non-darknet peer.
   *
   * <p>The supplied identifier becomes part of the exception message, so higher layers can preserve
   * the current protocol behavior without consulting the daemon state again.
   *
   * @param nodeIdentifier identifier of the resolved non-darknet peer; must not be {@code null}
   */
  public DarknetPeerRequiredException(String nodeIdentifier) {
    super("Darknet peer required: " + Objects.requireNonNull(nodeIdentifier, "nodeIdentifier"));
    this.nodeIdentifier = nodeIdentifier;
  }

  /**
   * Returns the identifier of the resolved non-darknet peer.
   *
   * <p>This is the same identifier that was accepted by peer lookup and then rejected by the
   * darknet-only guard.
   *
   * @return peer identifier that failed the darknet-only check
   */
  public String nodeIdentifier() {
    return nodeIdentifier;
  }
}

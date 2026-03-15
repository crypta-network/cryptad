package network.crypta.runtime.spi;

import java.util.Objects;

/**
 * Signals that a requested peer could not be resolved.
 *
 * <p>Higher layers typically keep the user-facing node identifier from the original request and map
 * this checked exception onto their existing protocol-specific error responses.
 *
 * <p>The exception is intentionally small. It distinguishes lookup failure from other peer
 * management failures without exposing daemon-only peer maps or protocol-specific message classes
 * through the runtime SPI.
 */
public final class UnknownPeerException extends Exception {
  private final String nodeIdentifier;

  /**
   * Creates an exception describing a missing peer.
   *
   * <p>The identifier becomes part of the exception message, so callers can preserve existing error
   * text without reconstructing it later.
   *
   * @param nodeIdentifier identifier that could not be resolved; must not be {@code null}
   */
  public UnknownPeerException(String nodeIdentifier) {
    super("Unknown peer: " + Objects.requireNonNull(nodeIdentifier, "nodeIdentifier"));
    this.nodeIdentifier = nodeIdentifier;
  }

  /**
   * Returns the identifier that could not be resolved.
   *
   * <p>This is the same lookup identifier supplied to the peer-management port.
   *
   * @return missing peer identifier
   */
  public String nodeIdentifier() {
    return nodeIdentifier;
  }
}

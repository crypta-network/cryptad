package network.crypta.runtime.spi;

import java.util.Objects;

/**
 * Represents the detached result of a successful peer removal.
 *
 * <p>This value keeps only the removal details that the current management responses need after the
 * peer has already been detached from the live daemon structures. It avoids holding a removed
 * {@code PeerNode} reference while still preserving the identity and lookup identifier expected by
 * existing response messages.
 *
 * @param identity identity string exported from the removed peer
 * @param nodeIdentifier node identifier used to resolve the removed peer
 */
public record RemovedPeerSnapshot(String identity, String nodeIdentifier) {
  /**
   * Creates an immutable peer-removal result.
   *
   * <p>Both fields are required because higher layers may include them in separate protocol fields
   * after the live peer object has already been discarded.
   *
   * @param identity identity string exported from the removed peer; must not be {@code null}
   * @param nodeIdentifier node identifier used to resolve the removed peer; must not be {@code
   *     null}
   * @throws NullPointerException if either argument is {@code null}
   */
  public RemovedPeerSnapshot {
    Objects.requireNonNull(identity, "identity");
    Objects.requireNonNull(nodeIdentifier, "nodeIdentifier");
  }
}

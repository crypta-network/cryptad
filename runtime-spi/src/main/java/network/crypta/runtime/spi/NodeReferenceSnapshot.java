package network.crypta.runtime.spi;

import java.util.Objects;

/**
 * Represents an immutable point-in-time export of one node-reference tree.
 *
 * <p>This snapshot is the management-facing value produced by {@link NodeInfoPort} for the FCP
 * node-reference family. It intentionally carries only the root tree node and does not encode
 * request identifiers or other protocol-specific metadata, leaving those concerns to the caller's
 * wire format.
 *
 * <p>Callers normally obtain instances from {@link NodeInfoPort#exportReference(NodeReferenceView,
 * boolean)} and then adapt the tree to their own response format. The snapshot is safe to retain
 * for the duration of one request or one serialization pass because it does not hold references to
 * mutable daemon internals. An empty snapshot is valid and represents an export with no direct
 * fields or child subsets.
 *
 * @param root root field-set tree for the exported node reference
 * @see NodeFieldSet
 * @see NodeInfoPort
 */
public record NodeReferenceSnapshot(NodeFieldSet root) {
  /**
   * Creates an immutable node-reference snapshot.
   *
   * @param root root field-set tree for the export; must not be {@code null}
   * @throws NullPointerException if {@code root} is {@code null}
   */
  public NodeReferenceSnapshot {
    Objects.requireNonNull(root, "root");
  }

  /**
   * Returns an empty node-reference snapshot.
   *
   * <p>This is primarily a convenience for adapters and tests that need to express the absence of
   * exported node-reference data without constructing an explicit empty root node first.
   *
   * @return snapshot whose root tree has no direct values or subsets
   */
  public static NodeReferenceSnapshot empty() {
    return new NodeReferenceSnapshot(NodeFieldSet.empty());
  }

  /**
   * Returns whether the exported root tree contains no data.
   *
   * <p>This delegates to the root {@link NodeFieldSet} and therefore reports only whether the
   * stored snapshot tree is structurally empty. It does not distinguish between different reasons
   * why the export might have been empty.
   *
   * @return {@code true} when the root field-set tree is empty
   */
  public boolean isEmpty() {
    return root.isEmpty();
  }
}

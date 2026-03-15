package network.crypta.runtime.spi;

/**
 * Exposes the narrow node-info capabilities needed by management-facing protocols.
 *
 * <p>This port is intentionally limited to the current FCP node-info family. It provides detached
 * snapshots for the server greeting metadata and for node-reference exports without exposing daemon
 * internals such as {@code Node}, {@code Version}, localization services, or legacy field-set
 * transport types to higher layers.
 *
 * <p>Typical callers are protocol or management adapters that need a read-only description of the
 * running node. The port does not perform access control and does not know about request
 * identifiers or wire framing. Those concerns remain with the higher layer, which requests a
 * snapshot here and then decides whether and how that snapshot should be serialized.
 */
public interface NodeInfoPort {
  /**
   * Returns a point-in-time snapshot of the node greeting metadata.
   *
   * <p>The returned value should contain everything a caller needs to build an outbound greeting
   * message except protocol-owned fields such as the connection identifier. Implementations are
   * free to source the data from live daemon state, cached metadata, or another runtime backend, as
   * long as the snapshot is detached from mutable internal types.
   *
   * @return immutable snapshot containing the metadata required to build an outbound greeting
   */
  NodeGreetingSnapshot greeting();

  /**
   * Exports one node-reference tree for the requested view.
   *
   * <p>The volatile-data choice is kept as a separate flag because it remains orthogonal to the
   * base view selection and does not justify widening the enum at this stage of the migration. The
   * returned snapshot should represent the same logical export that the legacy daemon would have
   * produced for the same view, but without leaking daemon-only types across the SPI boundary.
   *
   * @param view requested node-reference export shape
   * @param includeVolatile whether transient volatile data should be attached under the root tree
   * @return immutable node-reference snapshot for the requested view
   * @throws NullPointerException if {@code view} is {@code null}
   */
  NodeReferenceSnapshot exportReference(NodeReferenceView view, boolean includeVolatile);
}

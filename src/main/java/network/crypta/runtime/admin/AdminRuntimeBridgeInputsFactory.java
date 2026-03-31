package network.crypta.runtime.admin;

import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;

/**
 * Creates the runtime-owned bridge inputs required to assemble the legacy admin runtime ports.
 *
 * <p>The factory keeps the concrete bridge assembly behind a narrow seam so composition roots can
 * choose the implementation without making lower-level code aware of endpoint-specific bridge
 * classes. Callers typically create one factory during node bootstrap and pass it into the client
 * core constructor, which then asks the factory for the admin bridge inputs at the same point in
 * startup where it previously assembled them directly. The seam is intentionally narrow: it exposes
 * only the owning {@link Node} and live {@link NodeClientCore}, leaving queue, GeoIP, and any
 * future endpoint-backed bridge construction behind the returned {@link AdminRuntimeBridgeInputs}
 * value.
 */
@FunctionalInterface
public interface AdminRuntimeBridgeInputsFactory {
  /**
   * Creates the bridge inputs used to assemble the legacy admin runtime ports.
   *
   * <p>Implementations should construct the same runtime-owned bridge inputs that the daemon would
   * otherwise wire inline but keep the concrete endpoint knowledge on the factory side of the seam.
   * The method is called during client-core construction, before HTTP and FCP endpoint startup
   * completes, so implementations should preserve the existing startup ordering and avoid forcing
   * eager endpoint initialization.
   *
   * @param node live daemon node that owns filesystem layout and other bootstrap-time states needed
   *     by endpoint-backed bridge adapters
   * @param core live daemon client core that owns queue, persistence, and endpoint registries used
   *     by bridge adapters
   * @return fully assembled runtime-owned bridge inputs for {@code LegacyRuntimePorts}
   */
  AdminRuntimeBridgeInputs create(Node node, NodeClientCore core);
}

package network.crypta.runtime.bootstrap;

import java.util.Objects;
import network.crypta.runtime.admin.AdminRuntimeBridgeInputsFactory;
import network.crypta.runtime.endpoints.admin.AdminRuntimeBridgeInputsFactories;
import network.crypta.runtime.endpoints.http.HttpShellRuntimeSupportFactory;

/**
 * Bootstrap-owned selection of runtime bridge factories for {@link network.crypta.node.Node}.
 *
 * <p>This holder keeps the composition-root decision about which runtime bridge implementations to
 * use out of the node kernel. Bootstrap code selects the seam implementations once, then passes
 * them into {@code Node} so the node can stay focused on coordination and lifecycle rather than on
 * choosing endpoint-backed defaults.
 *
 * <p>Typical startup paths create one instance during bootstrap, thread it through {@link
 * network.crypta.runtime.bootstrap.NodeStarter}, and then let the node reuse those seams at the
 * same construction points where it previously hard-coded the legacy endpoint pair. The record is
 * immutable and carries no caching or policy beyond that wiring choice, so startup order and bridge
 * behavior stay aligned with the existing daemon bootstrap flow.
 *
 * @param adminRuntimeBridgeInputsFactory factory for the admin/runtime bridge inputs used by the
 *     client core
 * @param httpShellRuntimeSupportFactory factory for HTTP shell runtime support used by the toadlet
 *     container
 */
public record NodeRuntimeBridgeFactories(
    AdminRuntimeBridgeInputsFactory adminRuntimeBridgeInputsFactory,
    HttpShellRuntimeSupportFactory httpShellRuntimeSupportFactory) {

  /**
   * Creates a bootstrap bridge-factory bundle.
   *
   * <p>Both factories are required because node construction expects explicit seams for the admin
   * runtime bridge inputs and the HTTP shell runtime support path. The constructor only validates
   * presence; it does not invoke the factories, cache runtime state, or trigger any endpoint
   * startup work on its own.
   *
   * @param adminRuntimeBridgeInputsFactory factory for admin bridge inputs passed into the client
   *     core during node construction
   * @param httpShellRuntimeSupportFactory factory for HTTP shell runtime support created after the
   *     client core exists
   * @throws NullPointerException if either factory reference is {@code null}
   */
  public NodeRuntimeBridgeFactories {
    Objects.requireNonNull(adminRuntimeBridgeInputsFactory, "adminRuntimeBridgeInputsFactory");
    Objects.requireNonNull(httpShellRuntimeSupportFactory, "httpShellRuntimeSupportFactory");
  }

  /**
   * Returns the legacy default bridge-factory pair backed by the current endpoint implementations.
   *
   * <p>This helper centralizes the existing production default in the bootstrap package. Callers
   * that need the historical daemon wiring can therefore get the same admin and HTTP shell bridge
   * choices without making the node kernel depend on the endpoint-owned static entry points.
   *
   * @return bridge factories that preserve the current core-backed admin and HTTP shell wiring
   */
  public static NodeRuntimeBridgeFactories coreBacked() {
    return new NodeRuntimeBridgeFactories(
        AdminRuntimeBridgeInputsFactories.coreBacked(),
        HttpShellRuntimeSupportFactory.coreBacked());
  }
}

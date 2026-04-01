package network.crypta.runtime.bootstrap;

import java.util.Objects;
import network.crypta.runtime.admin.AdminRuntimeBridgeInputsFactory;
import network.crypta.runtime.fcp.PersistentRequestEndpointServicesFactory;
import network.crypta.runtime.http.HttpShellContainerFactory;
import network.crypta.runtime.http.HttpShellRuntimeSupportFactory;
import network.crypta.runtime.http.security.PasswordFormPageRenderer;

/**
 * Immutable holder of already-selected runtime bridge factories for {@link
 * network.crypta.node.Node}.
 *
 * <p>Bootstrap code selects the seam implementations elsewhere, stores them in this record, and
 * then passes the holder into {@code Node} so node construction can stay focused on coordination
 * and lifecycle rather than on choosing production defaults. The record is immutable and carries no
 * caching or policy beyond retaining the already-selected seams. The contained factories are
 * expected to be a compatible set rather than arbitrary independent choices. In particular, the
 * current legacy-backed HTTP shell container still requires a runtime-support implementation that
 * can also satisfy the legacy HTTP adapter contract.
 *
 * @param adminRuntimeBridgeInputsFactory factory for the admin/runtime bridge inputs used by the
 *     client core
 * @param persistentRequestEndpointServicesFactory factory for the FCP persistent-request bundle
 *     used by client-core persistence wiring
 * @param httpShellRuntimeSupportFactory factory for HTTP shell runtime support used by the toadlet
 *     container
 * @param httpShellContainerFactory factory for HTTP shell container creation used by the service
 *     subsystem
 * @param passwordFormPageRenderer runtime-owned seam used to render the shared master-password
 *     prompt
 */
public record NodeRuntimeBridgeFactories(
    AdminRuntimeBridgeInputsFactory adminRuntimeBridgeInputsFactory,
    PersistentRequestEndpointServicesFactory persistentRequestEndpointServicesFactory,
    HttpShellRuntimeSupportFactory httpShellRuntimeSupportFactory,
    HttpShellContainerFactory httpShellContainerFactory,
    PasswordFormPageRenderer passwordFormPageRenderer) {

  /**
   * Creates a bootstrap bridge-factory bundle.
   *
   * <p>All supplied seams are required because node construction expects explicit bindings for the
   * admin runtime bridge inputs, the FCP persistent-request bundle, the HTTP shell runtime support
   * path, the HTTP shell container creation path, and the shared password-form renderer. The
   * constructor only validates presence; it does not invoke factories, prove cross-binding
   * compatibility, cache runtime state, or trigger any endpoint startup work on its own.
   *
   * @param adminRuntimeBridgeInputsFactory factory for admin bridge inputs passed into the client
   *     core during node construction
   * @param persistentRequestEndpointServicesFactory factory for the FCP persistent-request bundle
   *     consumed by {@code NodeClientPersistence}
   * @param httpShellRuntimeSupportFactory factory for HTTP shell runtime support created after the
   *     client core exists
   * @param httpShellContainerFactory factory for HTTP shell container creation used by {@code
   *     NodeServicesSubsystem}
   * @param passwordFormPageRenderer renderer used by node-owned password alerts without exposing
   *     endpoint-owned HTTP helpers to runtime packages
   * @throws NullPointerException if any supplied seam reference is {@code null}
   */
  public NodeRuntimeBridgeFactories {
    Objects.requireNonNull(adminRuntimeBridgeInputsFactory, "adminRuntimeBridgeInputsFactory");
    Objects.requireNonNull(
        persistentRequestEndpointServicesFactory, "persistentRequestEndpointServicesFactory");
    Objects.requireNonNull(httpShellRuntimeSupportFactory, "httpShellRuntimeSupportFactory");
    Objects.requireNonNull(httpShellContainerFactory, "httpShellContainerFactory");
    Objects.requireNonNull(passwordFormPageRenderer, "passwordFormPageRenderer");
  }
}

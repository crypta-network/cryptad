package network.crypta.clients.http;

import java.util.Objects;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.config.Config;
import network.crypta.runtime.spi.RuntimePorts;

/**
 * Narrow dependency bundle used to register the FProxy HTTP shell.
 *
 * <p>{@link SimpleToadletServer} assembles the live daemon collaborators needed for the root FProxy
 * endpoint, then hands that prebuilt state to {@link FProxyRegistrar}. The registrar can therefore
 * stay focused on HTTP concerns such as menu registration, toadlet registration, and wiring
 * already-created helpers into those routes. This record exists only to make that handoff explicit
 * and local to the HTTP package.
 *
 * <p>The type is intentionally package-private. It is not a general runtime abstraction and does
 * not try to hide broader node relationships. It simply groups the collaborators that the registrar
 * actually consumes so startup composition remains in one place while HTTP registration remains
 * deterministic and easy to test.
 *
 * @param client shared interactive client used by registered HTTP toadlets
 * @param runtimePorts detached runtime ports exposed to the HTTP shell
 * @param config node configuration used to list sub-config toadlets
 * @param fproxy prebuilt root FProxy toadlet handed to the registrar for root-path registration
 */
record FProxyRegistrarDependencies(
    HighLevelSimpleClient client, RuntimePorts runtimePorts, Config config, FProxyToadlet fproxy) {
  /**
   * Creates a validated dependency bundle for {@link FProxyRegistrar}.
   *
   * <p>All collaborators are required because registration is an all-or-nothing startup step. The
   * constructor rejects the partially assembled state early, so the caller fails to close to the
   * HTTP shell composition site rather than later during menu or toadlet registration.
   *
   * @param client shared interactive client used by registered HTTP toadlets during registration
   * @param runtimePorts runtime-spi ports exposed to HTTP-layer toadlets and helper pages
   * @param config node configuration used to list and filter sub-config toadlets
   * @param fproxy prebuilt root FProxy toadlet that is registered at the HTTP root path
   * @throws NullPointerException if any required collaborator is absent at construction time
   */
  FProxyRegistrarDependencies {
    Objects.requireNonNull(client);
    Objects.requireNonNull(runtimePorts);
    Objects.requireNonNull(config);
    Objects.requireNonNull(fproxy);
  }
}

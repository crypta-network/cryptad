package network.crypta.clients.http;

import java.util.Objects;
import network.crypta.runtime.spi.RuntimePorts;

/**
 * Immutable startup context for browse-owned legacy HTTP route registration.
 *
 * <p>This record keeps the browse-owned registrar seam narrow. It still exposes the collaborators
 * that the current browse route publication requires: the detached runtime ports used by welcome,
 * bookmark, and filter routes, and the prebuilt browse root toadlet. The type is public because
 * bridge-owned production code installs concrete browse registrars across module boundaries. The
 * carried state remains intentionally limited to the browse-owned registration concern.
 *
 * <p>Callers should treat the record as a startup snapshot, not as a long-lived service locator. It
 * exists so the admin-owned shell can hand the browse registrar exactly the collaborators that
 * browse-owned routes still need today while the broader physical split remains deferred. Keeping
 * the record small also makes later extraction easier: if a browse route needs a new collaborator,
 * that dependency change becomes visible at the seam instead of leaking back into the shared shell.
 *
 * @param runtimePorts detached runtime ports exposed to browse-owned HTTP routes
 * @param browseRoot prebuilt browse-root toadlet registered at the legacy browsing root
 */
public record LegacyHttpBrowseRouteRegistrarContext(RuntimePorts runtimePorts, Toadlet browseRoot) {

  /**
   * Creates a validated browse-route registration context.
   *
   * <p>Construction fails fast because browse-route publication is still a startup-only step. A
   * partially populated context would otherwise defer wiring mistakes until the registrar reaches a
   * later phase and tries to instantiate a route. The record stores the exact references prepared
   * by the shared bootstrap path and does not wrap or copy them.
   *
   * @param runtimePorts detached runtime ports exposed to browse-owned HTTP routes
   * @param browseRoot prebuilt browse-root toadlet registered at the legacy browsing root
   * @throws NullPointerException if any required collaborator is absent
   */
  public LegacyHttpBrowseRouteRegistrarContext {
    Objects.requireNonNull(runtimePorts);
    Objects.requireNonNull(browseRoot);
  }
}

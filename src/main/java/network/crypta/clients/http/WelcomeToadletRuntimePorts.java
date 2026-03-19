package network.crypta.clients.http;

import java.util.Objects;
import network.crypta.runtime.spi.DarknetConnectionsPort;
import network.crypta.runtime.spi.LifecyclePort;
import network.crypta.runtime.spi.WelcomeActionPort;
import network.crypta.runtime.spi.WelcomePagePort;

/**
 * Bundles the detached runtime ports used by the welcome toadlet.
 *
 * <p>The welcome page now reaches the daemon only through detached runtime ports. Collecting the
 * page-specific collaborators in one record keeps the constructor small, makes the migration
 * boundary explicit, and avoids introducing a broader HTTP abstraction layer for a single page.
 *
 * <p>The bundle is intentionally narrow. It contains only the collaborators that the welcome page
 * currently needs for read-only page assembly, wrapper-dependent visibility checks, bookmark peer
 * rendering, and the remaining welcome-page maintenance actions.
 *
 * @param welcomePagePort detached welcome-page read port used for config-backed snapshot and log
 *     tail reads during welcome-page GET handling
 * @param darknetConnectionsPort detached darknet connections port used for bookmark recommendation
 *     peer rendering in GET responses
 * @param lifecyclePort detached lifecycle port used for wrapper-dependent button visibility
 * @param welcomeActionPort detached welcome-page action port used for update/restart/shutdown and
 *     connection-speed upgrade POST handlers
 */
record WelcomeToadletRuntimePorts(
    WelcomePagePort welcomePagePort,
    DarknetConnectionsPort darknetConnectionsPort,
    LifecyclePort lifecyclePort,
    WelcomeActionPort welcomeActionPort) {
  /**
   * Validates that every detached collaborator required by the welcome page is present.
   *
   * <p>The record carries dependencies only. Construction fails fast if any required port is
   * missing, so the registration error appears at startup rather than during request handling.
   */
  WelcomeToadletRuntimePorts {
    Objects.requireNonNull(welcomePagePort);
    Objects.requireNonNull(darknetConnectionsPort);
    Objects.requireNonNull(lifecyclePort);
    Objects.requireNonNull(welcomeActionPort);
  }
}

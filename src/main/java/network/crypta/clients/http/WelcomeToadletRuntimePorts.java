package network.crypta.clients.http;

import java.util.Objects;
import network.crypta.runtime.spi.DarknetConnectionsPort;
import network.crypta.runtime.spi.LifecyclePort;
import network.crypta.runtime.spi.WelcomePagePort;

/**
 * Bundles the detached runtime ports used by the welcome toadlet's GET/read path.
 *
 * <p>{@code WelcomeToadlet} is still in the middle of its runtime-SPI migration. Its GET handling
 * now reads a few pieces of runtime state through detached ports, while its POST and action paths
 * still use the legacy live-daemon fields. Collecting the GET-only collaborators in one record
 * keeps the constructor small, makes the migration boundary explicit, and avoids introducing a
 * broader HTTP abstraction layer for a single page.
 *
 * <p>The bundle is intentionally narrow. It contains only the collaborators that the current PR
 * needs for read-only page assembly and visibility checks, and nothing for restart, shutdown,
 * update, or other action routes.
 *
 * @param welcomePagePort detached welcome-page read port used for config-backed snapshot and log
 *     tail reads during welcome-page GET handling
 * @param darknetConnectionsPort detached darknet connections port used for bookmark recommendation
 *     peer rendering in GET responses
 * @param lifecyclePort detached lifecycle port used for wrapper-dependent button visibility
 */
record WelcomeToadletRuntimePorts(
    WelcomePagePort welcomePagePort,
    DarknetConnectionsPort darknetConnectionsPort,
    LifecyclePort lifecyclePort) {
  /**
   * Validates that every detached collaborator required by the welcome-page GET path is present.
   *
   * <p>The record carries dependencies only. Construction fails fast if any required port is
   * missing, so the registration error appears at startup rather than during request handling.
   */
  WelcomeToadletRuntimePorts {
    Objects.requireNonNull(welcomePagePort);
    Objects.requireNonNull(darknetConnectionsPort);
    Objects.requireNonNull(lifecyclePort);
  }
}

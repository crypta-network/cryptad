package network.crypta.clients.http;

import java.util.Objects;
import network.crypta.runtime.spi.DarknetConnectionsPort;
import network.crypta.runtime.spi.DarknetMessagingPort;

/**
 * Bundles the detached runtime ports that the bookmark editor HTTP page needs.
 *
 * <p>This record keeps the remaining runtime-facing collaborators for {@code BookmarkEditorToadlet}
 * explicit without reintroducing a direct dependency on {@code NodeClientCore}. The toadlet still
 * performs local bookmark-manager work in the HTTP layer, but friend discovery and bookmark-feed
 * delivery cross the runtime SPI through this narrow bundle. That keeps the page boundary small and
 * makes the runtime migration visible in the constructor shape used by HTTP wiring.
 *
 * <p>The record is immutable after construction and has no lifecycle logic of its own. It only
 * groups the detached collaborators needed by the bookmark sharing flow:
 *
 * <ul>
 *   <li>{@link DarknetConnectionsPort} for detached peer snapshots used by the share form
 *   <li>{@link DarknetMessagingPort} for sending bookmark feeds to selected peers
 * </ul>
 *
 * @param darknetConnectionsPort detached peer-list port used to determine whether sharing is
 *     available and to render the legacy checkbox table
 * @param darknetMessagingPort detached messaging port used to send bookmark feeds to the selected
 *     peers after form submission
 */
record BookmarkEditorToadletRuntimePorts(
    DarknetConnectionsPort darknetConnectionsPort, DarknetMessagingPort darknetMessagingPort) {
  /**
   * Validates that the bookmark editor received all detached collaborators it needs.
   *
   * <p>Construction fails fast, so HTTP wiring errors surface during setup instead of later during
   * a request. Callers should provide both ports from the same runtime bundle so the editor sees a
   * consistent view of the detached darknet state.
   *
   * @throws NullPointerException if either detached runtime port is missing from the HTTP wiring
   */
  BookmarkEditorToadletRuntimePorts {
    Objects.requireNonNull(darknetConnectionsPort);
    Objects.requireNonNull(darknetMessagingPort);
  }
}

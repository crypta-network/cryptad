package network.crypta.clients.http;

import java.util.Objects;
import network.crypta.runtime.spi.ConfigPort;
import network.crypta.runtime.spi.LifecyclePort;
import network.crypta.runtime.spi.TransferAccessPort;

/**
 * Shared runtime-port bundle used by HTTP configuration toadlets.
 *
 * <p>{@link ConfigToadlet} still renders and edits the legacy daemon configuration model directly,
 * but its remaining runtime touches now flow through detached SPI ports. Grouping those three
 * collaborators keeps the constructor narrow without passing the full {@code RuntimePorts}
 * aggregate into the HTTP layer.
 *
 * @param configPort config persistence port used after option changes are applied.
 * @param transferAccessPort transfer-policy port used for the default downloads directory during
 *     directory-browser redirects.
 * @param lifecyclePort lifecycle port used to decide whether wrapper-backed restart affordances
 *     should be shown.
 */
record ConfigToadletRuntimePorts(
    ConfigPort configPort, TransferAccessPort transferAccessPort, LifecyclePort lifecyclePort) {
  ConfigToadletRuntimePorts {
    Objects.requireNonNull(configPort);
    Objects.requireNonNull(transferAccessPort);
    Objects.requireNonNull(lifecyclePort);
  }
}

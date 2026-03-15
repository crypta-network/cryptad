package network.crypta.runtime.spi;

/**
 * Detached snapshot of one listener port configuration used by the connectivity page.
 *
 * <p>The connectivity view shows several listener families, such as FProxy, FCP, and the TMCI
 * console. This record carries only the small amount of state needed to render those rows: whether
 * the listener is enabled and which port number the daemon currently advertises for it. The SPI
 * keeps the payload deliberately narrow, so HTTP code does not depend on daemon configuration
 * objects.
 *
 * <p>Instances are immutable and can be reused freely within a single page render or test fixture.
 *
 * @param enabled whether the listener is currently enabled and expected to accept inbound
 *     connections
 * @param port configured listener port when enabled, or an implementation-defined placeholder when
 *     the listener is disabled
 */
public record ConnectivityListenerPortSnapshot(boolean enabled, int port) {}

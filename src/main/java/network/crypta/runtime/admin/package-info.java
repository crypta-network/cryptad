/**
 * Legacy admin and page-oriented runtime SPI adapters.
 *
 * <p>This package intentionally groups the transitional runtime adapters that back the legacy admin
 * pages, queue views, statistics reports, and welcome or first-time-wizard flows. The adapters
 * still depend on daemon-local services such as {@code Node}, {@code NodeClientCore}, HTTP helper
 * classes, and queue/reporting internals, but they present the detached {@code runtime-spi}
 * interfaces expected by higher-level wiring.
 *
 * <p>Keeping these classes here makes the ownership boundary explicit. The narrower {@code
 * network.crypta.node.runtime} package can keep the core runtime nucleus, while this package
 * carries the page-oriented compatibility layer that may later be extracted or reshaped as a more
 * focused adapter cluster.
 */
package network.crypta.runtime.admin;

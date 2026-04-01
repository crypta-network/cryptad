/**
 * Runtime core bridge between daemon-local node services and the runtime SPI.
 *
 * <p>This package groups the remaining runtime nucleus that still depends directly on {@code Node},
 * {@code NodeClientCore}, and the embedded SSL helper while presenting the detached {@code
 * runtime-spi} ports consumed by higher-level wiring. The move into this neutral package is an
 * ownership re-home only; it keeps the existing behavior, constructors, and lifecycle semantics
 * intact.
 *
 * <p>The package also owns runtime/bootstrap helpers such as {@link
 * network.crypta.runtime.core.NodeClientCoreSupport}, which stay adjacent to the core orchestration
 * code that uses them.
 *
 * <p>The package exists so the runtime boundary can stay explicit while the daemon-specific core
 * continues to evolve independently of the page-oriented admin adapters.
 */
package network.crypta.runtime.core;

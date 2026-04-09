/**
 * Runtime core bridge between daemon-local node services and the runtime SPI.
 *
 * <p>This package now spans the daemon-bound core bridge classes that remain in {@code
 * :runtime-node} plus the extracted SSL helper owned by {@code :foundation-compat}. Together they
 * still present the detached {@code runtime-spi} ports and runtime-core helpers consumed by
 * higher-level wiring. The ownership split is a structural re-home only; it preserves behavior,
 * constructors, and lifecycle semantics.
 *
 * <p>The package also owns runtime/bootstrap helpers such as {@link
 * network.crypta.runtime.core.NodeClientCoreSupport}, which stay adjacent to the core orchestration
 * code that uses them.
 *
 * <p>The package exists so the runtime boundary can stay explicit while the daemon-specific core
 * continues to evolve independently of the page-oriented admin adapters.
 */
package network.crypta.runtime.core;

/**
 * Diagnostic-report Platform API handlers.
 *
 * <p>This package owns the read-only diagnostics surface for Platform API v1. It turns the detached
 * runtime diagnostic report into stable JSON while preserving the original section order supplied
 * by {@code :runtime-spi}. That lets the Web Shell and other local tooling render diagnostics
 * natively without depending on legacy diagnostic toadlets or rebuilding the report structure from
 * ad hoc text parsing.
 *
 * <p>The package is intentionally small. It does not interpret authentication policy or render HTML
 * views. Its responsibility is to expose one transport-neutral report shape that contains both the
 * structured sections and a copy-friendly plain-text export derived from the same snapshot.
 */
package network.crypta.platform.api.diagnostics;

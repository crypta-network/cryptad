/**
 * Alert-oriented Platform API handlers.
 *
 * <p>This package owns the narrow alert surface for Platform API v1. Its job is to translate the
 * detached alert SPI into stable JSON that the Web Shell and other local operator tooling can
 * consume directly. The package preserves the current runtime-owned alert model, including legacy
 * hash-based dismissal identifiers and localized action labels, while keeping those runtime types
 * behind the {@code :runtime-spi} boundary.
 *
 * <p>The package does not own HTTP authentication, HTML rendering, Atom feeds, or the broader
 * legacy toadlet alert pages. Those concerns remain in the bridge and runtime layers. Here, the
 * focus stays on transport-neutral request validation and JSON payload assembly for alert snapshots
 * and simple dismiss actions.
 */
package network.crypta.platform.api.alerts;

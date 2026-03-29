/**
 * HTTP-owned GeoIP bridge implementations for runtime adapters.
 *
 * <p>This package contains small adapters that let runtime-owned code consume HTTP-layer GeoIP
 * facilities without depending on {@code network.crypta.clients.http} directly. The bridge keeps
 * the legacy GeoIP database lookup behavior unchanged while preserving the current runtime/HTTP
 * ownership split.
 *
 * <p>The package deliberately stays narrow. It owns the adapter layer that translates HTTP-local
 * GeoIP types, static-resource paths, and singleton lookup behavior into the detached DTOs and
 * lookup interfaces defined under {@code network.crypta.runtime.admin.geoip}. That keeps the
 * remaining coupling explicit while avoiding any {@code runtime-spi} expansion in this migration
 * step.
 */
package network.crypta.runtime.endpoints.http.geoip;

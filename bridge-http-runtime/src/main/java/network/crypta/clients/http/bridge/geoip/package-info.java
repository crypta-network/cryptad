/**
 * Concrete GeoIP bridges used by runtime-admin HTTP pages.
 *
 * <p>This package now lives in {@code :bridge-http-runtime}. It contains the bridge code that lets
 * runtime-admin pages request GeoIP country information without depending directly on the legacy
 * HTTP lookup stack. The adapters here keep ownership of the remaining HTTP-specific details,
 * including use of the legacy {@code IPConverter}, selection of the daemon's GeoIP database file,
 * and expansion of bundled flag-icon paths into the static-resource URLs that the existing web UI
 * expects.
 *
 * <p>Runtime-admin code should continue to work through the detached lookup seam under {@code
 * network.crypta.runtime.admin.geoip}. These classes preserve the current best-effort
 * country-resolution behavior and file-selection rules, but they remain adapter implementations
 * rather than part of the long-lived runtime contract. Keeping them in the bridge leaf makes the
 * ownership split explicit without changing how the Connections page resolves country names or flag
 * artwork today.
 */
package network.crypta.clients.http.bridge.geoip;

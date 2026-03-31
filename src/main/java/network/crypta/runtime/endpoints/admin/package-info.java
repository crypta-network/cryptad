/**
 * Endpoint-owned admin endpoint bootstrap glue.
 *
 * <p>This package contains the endpoint-layer composition helpers that translate runtime-owned
 * admin seams into the concrete bridge implementations still provided by endpoint packages. Its
 * role is intentionally narrow: it keeps constructor knowledge for queue and HTTP-backed admin
 * bridges near those implementations, while allowing upstream composition roots such as the node
 * bootstrap path to depend only on runtime-owned factory types. That ownership split keeps endpoint
 * details out of lower-level runtime wiring without changing queue behavior, GeoIP rendering, or
 * startup sequencing.
 */
package network.crypta.runtime.endpoints.admin;

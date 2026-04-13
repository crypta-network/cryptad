/**
 * Legacy updateable page elements for the extracted HTTP and FProxy shell.
 *
 * <p>This package belongs to {@code :adapter-http-legacy-browse}. It contains the server-side page
 * fragments, event bookkeeping, and push-update coordination used by the current legacy browse and
 * FProxy shell to refresh parts of a rendered page without rebuilding the whole response.
 *
 * <p>These types are adapter-owned implementation details, not a new platform API. Code outside
 * {@code :adapter-http-legacy-admin} should not begin depending on them. They exist only to support
 * the current legacy browse and FProxy shell until later refinement or replacement work narrows
 * this adapter further.
 */
package network.crypta.clients.http.updateableelements;

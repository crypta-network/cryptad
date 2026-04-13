/**
 * Legacy-reusable HTML node fragments for the extracted HTTP and FProxy shell.
 *
 * <p>This package belongs to {@code :adapter-http-legacy-browse}. It contains small HTML-node
 * helpers that the current legacy browse shell uses to assemble richer page fragments without
 * duplicating markup logic inline. The package remains inside the extracted {@code
 * network.crypta.clients.http} tree as a browse-owned helper package.
 *
 * <p>These helpers are adapter-owned implementation details, not a new platform API. Code outside
 * {@code :adapter-http-legacy-admin} should not begin depending on them. They remain here only to
 * support the current legacy browse and FProxy shell until later refinement or replacement work
 * narrows this adapter further.
 */
package network.crypta.clients.http.complexhtmlnodes;

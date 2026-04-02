/**
 * Legacy HTTP-shell utilities for the extracted browse and FProxy adapter.
 *
 * <p>This package belongs to {@code :adapter-http-legacy-admin}. It contains small helper types for
 * the current legacy HTTP shell, including template rendering, localization glue, and conservative
 * proxy-header parsing. The package remains inside the extracted {@code
 * network.crypta.clients.http} tree while that shell is boundary-frozen.
 *
 * <p>These utilities are adapter-owned implementation details, not a new platform API. Code outside
 * {@code :adapter-http-legacy-admin} should not begin depending on them. They exist only to support
 * the current legacy browse and FProxy shell until later refinement or replacement work narrows
 * this adapter further.
 */
package network.crypta.clients.http.utils;

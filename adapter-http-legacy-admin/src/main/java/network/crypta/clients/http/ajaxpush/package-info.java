/**
 * Legacy Ajax-push helper endpoints for the extracted HTTP and FProxy shell.
 *
 * <p>This package belongs to {@code :adapter-http-legacy-admin}. It holds the small toadlets that
 * support the current browser push and long-poll update flow used by the legacy browse shell, such
 * as notification, keepalive, failover, and dismiss flows. The package remains part of the
 * extracted but still legacy {@code network.crypta.clients.http} tree while that shell is
 * boundary-frozen.
 *
 * <p>These types are adapter-owned implementation details, not a new platform API. Code outside
 * {@code :adapter-http-legacy-admin} should not begin depending on them. They remain here only to
 * support the current legacy browse and FProxy shell until later refinement or replacement work
 * narrows this adapter further.
 */
package network.crypta.clients.http.ajaxpush;

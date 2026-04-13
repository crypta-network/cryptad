/**
 * Legacy HTTP filtering callbacks for the extracted browse and FProxy adapter.
 *
 * <p>This package belongs to {@code :adapter-http-legacy-browse}. It contains HTTP-specific filter
 * helpers that adapt the sanitized content-filter pipeline to the current FProxy shell, including
 * rewriting tags so legacy push-enabled pages can inject scripts or updateable placeholders.
 *
 * <p>These types are adapter-owned implementation details, not a new platform API. Code outside
 * {@code :adapter-http-legacy-admin} should not begin depending on them. They exist only to support
 * the current legacy browse and FProxy shell until later refinement or replacement work narrows
 * this adapter further.
 */
package network.crypta.clients.http.filter;

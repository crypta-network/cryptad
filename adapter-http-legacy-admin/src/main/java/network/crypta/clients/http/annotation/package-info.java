/**
 * Legacy HTTP-handler annotations for the extracted browse and FProxy adapter.
 *
 * <p>This tiny package belongs to {@code :adapter-http-legacy-admin}. It provides annotation
 * metadata interpreted by the current legacy HTTP shell so handler methods can describe request
 * expectations such as whether a payload is accepted. The package remains inside the extracted
 * {@code network.crypta.clients.http} tree while that shell is boundary-frozen.
 *
 * <p>These annotations are adapter-local implementation details, not a new platform API. Code
 * outside {@code :adapter-http-legacy-admin} should not grow dependencies on them. They exist only
 * to support the current legacy browse and FProxy shell until later refinement work replaces or
 * narrows this surface.
 */
package network.crypta.clients.http.annotation;

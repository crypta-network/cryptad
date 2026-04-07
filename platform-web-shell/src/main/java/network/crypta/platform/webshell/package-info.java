/**
 * Browser-facing node-management shell assets, page renderer, and resource helpers.
 *
 * <p>This package owns the first-party Web Shell v1 surface for the node-management UI. It contains
 * the static resource loader and HTML renderer that turn shell-owned assets into a browser document
 * without depending on a separate front-end build chain or a server-side templating framework. The
 * route constants live under {@code network.crypta.platform.webshell.routes}, while the bootstrap
 * model and JSON serializer live under {@code network.crypta.platform.webshell.bootstrap}.
 *
 * <p>The root package deliberately stays transport-neutral. It does not know about HTTP toadlets,
 * runtime node state, or launcher wiring. That separation lets the legacy admin adapter remain a
 * thin bridge that serves the shell and injects bootstrap data without turning the shell leaf into
 * another runtime or adapter layer.
 */
package network.crypta.platform.webshell;

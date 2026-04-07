/**
 * Route constants for the first-party Web Shell v1.
 *
 * <p>This subpackage owns the stable browser and classpath mount points used by the shell leaf.
 * Those constants define where the shell page lives, where its static assets live, and how the
 * packaged resources are addressed from Java code. Centralizing the route surface here keeps the
 * browser contract explicit and avoids scattering path knowledge through the renderer, bootstrap
 * serializer, and HTTP bridge.
 *
 * <p>Keeping route constants separate from the browser model also lets the adapter stay thin. The
 * legacy HTTP layer can mount the shell by referring to one canonical route surface instead of
 * re-declaring paths in multiple places.
 */
package network.crypta.platform.webshell.routes;

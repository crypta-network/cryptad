/**
 * Browser bootstrap model and serializer for the first-party Web Shell v1.
 *
 * <p>This subpackage owns the small immutable data model that the shell injects into the HTML page
 * before the browser starts its Platform API fetches. The record types and serializer define the
 * shell's browser contract: title, descriptive text, route roots, API roots, and legacy deep links.
 * Keeping that contract here makes the shell payload stable and easy to test without coupling it to
 * any transport or runtime implementation details.
 *
 * <p>The HTTP bridge remains responsible only for supplying the actual values and embedding the
 * JSON blob into the rendered page. The bootstrap package therefore stays transport-neutral and can
 * evolve independently of the adapter glue that serves the page.
 */
package network.crypta.platform.webshell.bootstrap;

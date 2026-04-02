/**
 * Browser-facing HTTP interface for Crypta nodes, often referred to as the FProxy console.
 *
 * <p>The package provides the lightweight HTTP server surface that lets users browse freesites,
 * upload or insert files, inspect queue progress, and configure the node without embedding a
 * servlet container. Each endpoint is implemented as a {@link network.crypta.clients.http.Toadlet}
 * subclass and is registered with the {@link network.crypta.clients.http.ToadletContainer}, which
 * performs verb dispatch and lifecycle management. HTML responses are built with {@link
 * network.crypta.clients.http.PageMaker} and localized through the shared L10n utilities so status
 * pages, wizards, and dashboards remain consistent across the console.
 *
 * <p>Handlers are designed to be per-request stateless: request-specific state flows through {@link
 * network.crypta.clients.http.ToadletContext} while the underlying {@link
 * network.crypta.client.HighLevelSimpleClient} coordinates network fetch/insert operations.
 * Supporting components—such as {@link network.crypta.clients.http.SessionManager} for cookies,
 * updateable elements that stream incremental progress, and error helpers like {@link
 * network.crypta.clients.http.RedirectException}—keep page controllers focused on domain logic
 * rather than HTTP plumbing. The package also contains specialized toadlets for first-time setup,
 * security settings, translation, and bookmark management to cover the full administrative
 * workflow.
 *
 * <ul>
 *   <li>Implements the public web console and REST-like helper endpoints.
 *   <li>Wraps content filters so fetched freesites render safely in browsers.
 *   <li>Surfaces live progress for downloads, inserts, and network connectivity.
 * </ul>
 *
 * @see network.crypta.clients.http.Toadlet
 * @see network.crypta.clients.http.ToadletContainer
 * @see network.crypta.clients.http.PageMaker
 */
package network.crypta.clients.http;

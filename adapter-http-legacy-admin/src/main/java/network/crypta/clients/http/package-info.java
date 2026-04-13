/**
 * Browser-facing HTTP interface for Crypta nodes, often referred to as the FProxy console.
 *
 * <p>This package is split across the extracted {@code :adapter-http-legacy-admin} and {@code
 * :adapter-http-legacy-browse} leaves, together with the matching {@code
 * network/crypta/clients/http/**} main resources that currently remain in the admin leaf. The root
 * project no longer owns this main source/resource tree. The admin leaf keeps the shared shell and
 * seam types, while the browse leaf owns the concrete browse and FProxy implementation classes.
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
 * <p>Code outside the HTTP adapter boundary should treat this package as a legacy adapter-owned
 * implementation detail rather than as a new platform API. Runtime and bootstrap code should
 * continue to depend on runtime-owned seams and the narrow bridge/binding sites instead of growing
 * new direct dependencies on {@code network.crypta.clients.http.*}. The shared shell now uses the
 * HTTP-local route registrar seam, shared path/category helpers, the detached {@code
 * network.crypta.runtime.alerts.UserAlertSurface}, and other browse-neutral helpers, while {@code
 * network.crypta.runtime.bootstrap.DefaultNodeRuntimeBridgeFactories} remains the bootstrap-owned
 * binding site for the concrete HTTP bridge implementations.
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

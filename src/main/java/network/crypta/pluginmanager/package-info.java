/**
 * Defines the plugin model and the core services used to load, run, and manage plugins.
 *
 * <p>Plugins are extension modules that execute inside the same JVM as the node. They are not
 * sandboxed, so they can access internal services directly, and they may interact with networking,
 * storage, and client APIs as needed. Rather than a strict facade, this package provides a set of
 * focused capability interfaces, lifecycle hooks, and helper types that plugins implement or use.
 * This design favors flexibility and performance, but it also means plugin authors must be careful
 * about concurrency, resource ownership, and compatibility across node versions.
 *
 * <p>Typical usage starts with a plugin entry point implementing {@link
 * network.crypta.pluginmanager.FredPlugin} and optional capability interfaces such as {@link
 * network.crypta.pluginmanager.FredPluginHTTP} or {@link
 * network.crypta.pluginmanager.FredPluginFCPMessageHandler}. Plugins can access node facilities via
 * {@link network.crypta.pluginmanager.PluginRespirator}, while {@link
 * network.crypta.pluginmanager.PluginManager} coordinates loading, unloading, and metadata. HTTP
 * and configuration helpers, along with structured exceptions, provide consistent integration
 * points for UI and API behaviors.
 *
 * <ul>
 *   <li>Lifecycle and capabilities: entry points, optional interfaces, and versioning hooks.
 *   <li>Management: discovery, download, and activation orchestration.
 *   <li>Integration utilities: configuration, localization, HTTP/FCP helpers, and plugin stores.
 * </ul>
 *
 * @see network.crypta.pluginmanager.FredPlugin
 * @see network.crypta.pluginmanager.FredPluginHTTP
 * @see network.crypta.pluginmanager.PluginManager
 * @see network.crypta.pluginmanager.PluginRespirator
 */
package network.crypta.pluginmanager;

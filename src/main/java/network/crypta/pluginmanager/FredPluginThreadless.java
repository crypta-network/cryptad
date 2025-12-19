package network.crypta.pluginmanager;

/**
 * Marker interface for plugins that return promptly from {@code
 * FredPlugin#runPlugin(PluginRespirator)}.
 *
 * <p>The plugin manager interprets this marker as a lifecycle hint. Plugins that do not implement
 * {@code FredPluginThreadless} are treated as "threaded": their {@code runPlugin(...)} method is
 * expected to remain active (for example by running a loop) and, once it returns, the plugin
 * manager considers the plugin finished and proceeds to unload it. Plugins that do implement this
 * interface are treated as "threadless": they may perform lightweight setup in {@code runPlugin}
 * and then return immediately while remaining loaded.
 *
 * <p>A threadless plugin therefore performs its work outside of {@code runPlugin}, typically by
 * registering for callbacks, scheduling tasks on an existing ticker, or managing its own
 * executor/thread(s) for any background activity. The plugin remains loaded until it is explicitly
 * unloaded, at which point {@code FredPlugin#terminate()} is invoked to stop work and release
 * resources.
 *
 * <ul>
 *   <li><b>Typical pattern:</b> lightweight setup in {@code runPlugin}, then event-driven behavior.
 *   <li><b>Concurrency:</b> callbacks may arrive on arbitrary threads; implementations must be
 *       thread-safe for shared state.
 * </ul>
 */
public interface FredPluginThreadless {}

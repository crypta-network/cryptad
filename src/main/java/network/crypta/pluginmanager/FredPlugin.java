package network.crypta.pluginmanager;

/**
 * Defines the minimal lifecycle contract for a Crypta plugin.
 *
 * <p>Every plugin has a single "main" class that is instantiated by the plugin manager. That main
 * class must implement {@code FredPlugin} directly, because the plugin loader discovers additional
 * optional capabilities (the {@code FredPlugin*} interfaces) by checking the same instance for
 * those types. This enables automatic registration of the plugin with whichever services it opts
 * into (for example, HTTP integration or other extension points) without requiring a separate
 * registration API.
 *
 * <p>The lifecycle is split into two phases: {@link #runPlugin(PluginRespirator)} is called after
 * node startup and provides access to the node-facing integration surface via {@link
 * PluginRespirator}. {@link #terminate()} is called when the plugin is being unloaded and should
 * release resources and stop background work started by the plugin. Callers may invoke these
 * methods from different threads; implementations should therefore ensure appropriate
 * synchronization and avoid blocking the caller for extended periods.
 *
 * <p><b>Responsibilities</b>
 *
 * <ul>
 *   <li>Start plugin work when invoked after node startup.
 *   <li>Release resources promptly when the plugin is unloaded.
 * </ul>
 */
public interface FredPlugin {
  // HTTP-stuff has been moved to FredPluginHTTP

  /**
   * Shuts down the plugin and releases any resources it owns.
   *
   * <p>This method is called when the plugin is being unloaded. Implementations should stop
   * background activity (threads, timers, or other asynchronous work) and close any resources they
   * created during {@link #runPlugin(PluginRespirator)}. Implementations should be robust if called
   * when startup is only partially complete, and should aim to be idempotent so that repeated calls
   * do not cause additional side effects.
   */
  void terminate();

  /**
   * Starts the plugin after node startup and provides access to node integration services.
   *
   * <p>The plugin manager calls this method once the node is initialized so the plugin can perform
   * any startup work that requires access to the node's plugin-facing facilities. The {@code pr}
   * parameter acts as the primary entry point for interacting with the node (for example, obtaining
   * handles to plugin helpers or registering for events) and should be treated as valid for the
   * duration of the plugin's lifetime.
   *
   * <p>Plugins that do not implement {@code FredPluginThreadless} are treated as "threaded": once
   * this method returns, the plugin manager considers the plugin finished and will terminate it.
   * Plugins that do implement {@code FredPluginThreadless} are treated as "threadless": they may
   * return promptly from this method and will remain loaded until explicitly unloaded, with
   * shutdown performed via {@link #terminate()}.
   *
   * <pre>{@code
   * // Typical lifecycle: start, later stop.
   * plugin.runPlugin(pr);
   * plugin.terminate();
   * }</pre>
   *
   * @param pr plugin integration context provided by the node; expected non-null for normal
   *     operation
   */
  void runPlugin(PluginRespirator pr);
}

package network.crypta.pluginmanager;

/**
 * All the FredPlugin* APIs must be implemented by the main class - the class that implements
 * FredPlugin, because that's where we look for them when loading a plugin. That allows us to
 * automatically register the plugin for whichever service it is using.
 */
public interface FredPlugin {
  // HTTP-stuff has been moved to FredPluginHTTP

  /** Shut down the plugin. */
  void terminate();

  /**
   * Run the plugin. Called after node startup. Should be able to access queue etc at this point.
   * Plugins which do not implement FredPluginThreadless will be terminated after they return from
   * this function. Threadless plugins will not terminate until they are explicitly unloaded.
   */
  void runPlugin(PluginRespirator pr);
}

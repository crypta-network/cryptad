package network.crypta.pluginmanager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Starts a plugin instance and wires it into the running node.
 *
 * <p>This class provides a small, centralized entry point for taking a {@link PluginInfoWrapper}
 * that already carries a {@link FredPlugin} instance and making it "live" from the node's point of
 * view. The start operation is responsible for selecting the execution mode (threaded vs
 * threadless), arranging registration/unregistration with the {@link PluginManager}, and ensuring
 * that plugin code runs with the plugin's {@link ClassLoader} as the thread context class loader.
 *
 * <p>Typical call sites hand in the node's plugin manager and the wrapper created during plugin
 * discovery/initialization. For normal plugins, startup is delegated to a daemon thread whose start
 * is queued via the node ticker; for threadless plugins, startup happens inline on the caller's
 * thread.
 *
 * <ul>
 *   <li><strong>Lifecycle:</strong> register, run, then unregister and remove on termination.
 *   <li><strong>Threading:</strong> threaded plugins run on a dedicated daemon thread.
 *   <li><strong>Isolation:</strong> the thread context class loader is set to the plugin loader.
 * </ul>
 *
 * @author cyberdo
 */
public class PluginHandler {
  private static final Logger LOG = LoggerFactory.getLogger(PluginHandler.class);

  private PluginHandler() {}

  /**
   * Starts the plugin represented by the given wrapper and registers it with the plugin manager.
   *
   * <p>This method creates a small runnable that performs registration and calls {@link
   * FredPlugin#runPlugin(PluginRespirator)}. For non-threadless plugins, that runnable is executed
   * on a dedicated daemon thread, and the thread start is queued on the node ticker with zero delay
   * to avoid starting plugin code inline during node startup. For threadless plugins, the plugin is
   * initialized inline and then registered.
   *
   * <p>The thread context class loader is temporarily set to the plugin's defining class loader so
   * that plugin code and any service-loading performed during startup resolve resources from the
   * correct loader. The original context class loader is restored before returning, even when
   * plugin startup fails.
   *
   * @param pm plugin manager coordinating registration and ticker scheduling; must be non-null.
   * @param pi wrapper holding plugin instance, respirator, and thread metadata; must be non-null.
   */
  public static void startPlugin(PluginManager pm, PluginInfoWrapper pi) {
    final PluginStarter ps = new PluginStarter(pm, pi);

    FredPlugin plug = pi.getPlugin();
    ClassLoader oldClassLoader = Thread.currentThread().getContextClassLoader();
    ClassLoader pluginClassLoader = plug.getClass().getClassLoader();
    Thread.currentThread().setContextClassLoader(pluginClassLoader);
    try {
      // We must start the plugin *after startup has finished*
      Runnable job;
      if (!pi.isThreadlessPlugin()) {
        final Thread t = new Thread(ps);
        t.setDaemon(true);
        pi.setThread(t);
        job = t::start;
        pm.getTicker().queueTimedJob(job, 0);
      } else {
        // Avoid NPEs: let it init, then register it.
        plug.runPlugin(pi.getPluginRespirator());
        pm.register(pi);
      }
    } finally {
      Thread.currentThread().setContextClassLoader(oldClassLoader);
    }
  }

  private static class PluginStarter implements Runnable {
    private final PluginManager pm;
    final PluginInfoWrapper pi;

    public PluginStarter(PluginManager pm, PluginInfoWrapper pi) {
      this.pm = pm;
      this.pi = pi;
    }

    @Override
    public void run() {
      try {
        pm.register(pi);
        pi.getPlugin().runPlugin(pi.getPluginRespirator());
      } catch (Exception e) {
        LOG.info("Caught exception while running plugin", e);
      } finally {
        pi.unregister(pm, false); // If not already unregistered
        pm.removePlugin(pi);
      }
    }
  }
}

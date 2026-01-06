package network.crypta.pluginmanager;

import java.io.File;
import java.io.IOException;
import java.util.Date;
import java.util.HashSet;
import network.crypta.clients.http.ConfigToadlet;
import network.crypta.config.Config;
import network.crypta.config.FilePersistentConfig;
import network.crypta.config.SubConfig;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.Node;
import network.crypta.support.JarClassLoader;
import network.crypta.support.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Wraps a single loaded plugin instance together with the node integration objects that {@link
 * PluginManager} uses to manage its lifecycle.
 *
 * <p>This class is created when a {@link FredPlugin} has been instantiated and accepted by the
 * plugin manager. It captures stable identity details (the runtime class name, the loading
 * filename, and a generated thread name), detects which optional plugin capability interfaces are
 * implemented, and exposes helper objects such as the {@link PluginRespirator}. For configurable
 * plugins (those implementing {@link FredPluginConfigurable}) it also wires a per-plugin {@link
 * Config}/{@link SubConfig} and the corresponding {@link ConfigToadlet}.
 *
 * <p>Shutdown is performed in phases: unregistering callbacks, requesting termination, optionally
 * waiting for the plugin thread to finish, and closing any {@link JarClassLoader} used to load the
 * plugin so that the JAR can be deleted or replaced.
 *
 * <ul>
 *   <li><b>Responsibilities:</b> track plugin metadata, capability flags, and shutdown progress.
 *   <li><b>Notable behavior:</b> shutdown temporarily switches the thread context class loader to
 *       the plugin's class loader before calling {@link FredPlugin#terminate()}.
 * </ul>
 *
 * <p>Thread-safety: most state is immutable after construction. Mutable state is limited to the
 * plugin thread reference, toadlet link bookkeeping, and shutdown flags; those are guarded with
 * {@code synchronized} and/or {@code volatile} as appropriate.
 */
public class PluginInfoWrapper implements Comparable<PluginInfoWrapper> {
  private static final Logger LOG = LoggerFactory.getLogger(PluginInfoWrapper.class);

  private final String className;
  private Thread thread;
  private final long start;
  final PluginRespirator pr;
  private final String threadName;
  final FredPlugin plug;
  private final Config config;
  private final SubConfig subconfig;
  private final ConfigToadlet configToadlet;
  private final boolean isPproxyPlugin;
  private final boolean isThreadlessPlugin;
  private final boolean isIPDetectorPlugin;
  private final boolean isBandwidthIndicator;
  private final boolean isPortForwardPlugin;
  private final boolean isMultiplePlugin;

  private final boolean isFCPServerPlugin;
  private final boolean isVersionedPlugin;
  private final boolean isLongVersionedPlugin;
  private final boolean isThemedPlugin;
  private final boolean isL10nPlugin;
  private final boolean isBaseL10nPlugin;
  private final boolean isConfigurablePlugin;
  private final boolean isOfficialPlugin;
  private final String filename;
  private HashSet<String> toadletLinks = new HashSet<>();
  private volatile boolean stopping = false;
  private volatile boolean unregistered = false;

  /**
   * Creates a wrapper for an already-instantiated plugin and wires it into the node environment.
   *
   * <p>This constructor records identity details used by management and UI code (for example, the
   * generated {@linkplain #getThreadName() thread name} and the time the wrapper was created). It
   * also caches which optional plugin interfaces are implemented so callers can make capability
   * decisions without repeated {@code instanceof} checks.
   *
   * <p>If the plugin is configurable, a persistent configuration file is created under the node
   * configuration directory (named {@code plugin-&lt;pluginClass&gt;.ini}), the plugin is asked to
   * register its options, and a {@link ConfigToadlet} is created to expose those options over HTTP.
   * For non-configurable plugins, the configuration-related accessors return {@code null}.
   *
   * @param node the node hosting the plugin, used to locate directories and services.
   * @param plug the plugin instance to wrap; must be a fully constructed plugin object.
   * @param filename the on-disk filename or identifier used to load the plugin.
   * @param isOfficial whether this plugin is treated as an official/bundled plugin.
   * @throws IOException if persistent config initialization fails while preparing the plugin.
   */
  public PluginInfoWrapper(Node node, FredPlugin plug, String filename, boolean isOfficial)
      throws IOException {
    this.plug = plug;
    className = plug.getClass().toString();
    this.filename = filename;
    this.pr = new PluginRespirator(node, this);
    threadName = 'p' + className.replaceAll("^class ", "") + '_' + hashCode();
    start = System.currentTimeMillis();

    // Code quality: Do we really need to cache these values? I don't care about the
    // memory overhead, but it's the pointless clutter it causes in the member variables, while
    // the information is right there and always accessible in the runtime type of plug.
    // When fixing this, please also consider the related note at getFCPServerPlugin().
    isBandwidthIndicator = (plug instanceof FredPluginBandwidthIndicator);
    isPproxyPlugin = (plug instanceof FredPluginHTTP);
    isThreadlessPlugin = (plug instanceof FredPluginThreadless);
    isIPDetectorPlugin = (plug instanceof FredPluginIPDetector);
    isPortForwardPlugin = (plug instanceof FredPluginPortForward);
    isMultiplePlugin = (plug instanceof FredPluginMultiple);
    isFCPServerPlugin = (plug instanceof FredPluginFCPMessageHandler.ServerSideFCPMessageHandler);
    isVersionedPlugin = (plug instanceof FredPluginVersioned);
    isLongVersionedPlugin = (plug instanceof FredPluginRealVersioned);
    isThemedPlugin = (plug instanceof FredPluginThemed);
    isL10nPlugin = (plug instanceof FredPluginL10n);
    isBaseL10nPlugin = (plug instanceof FredPluginBaseL10n);
    isConfigurablePlugin = (plug instanceof FredPluginConfigurable);
    if (isConfigurablePlugin) {
      config =
          FilePersistentConfig.constructFilePersistentConfig(
              new File(node.getCfgDir(), "plugin-" + getPluginClassName() + ".ini"),
              "config options for plugin: " + getPluginClassName());
      subconfig = config.createSubConfig(getPluginClassName());
      ((FredPluginConfigurable) plug).setupConfig(subconfig);
      config.finishedInit();
      configToadlet =
          new ConfigToadlet(
              pr.getHLSimpleClient(),
              config,
              subconfig,
              node,
              node.services().clientCore(),
              (FredPluginConfigurable) plug);
    } else {
      config = null;
      subconfig = null;
      configToadlet = null;
    }
    isOfficialPlugin = isOfficial;
  }

  void setThread(Thread ps) {
    if (thread != null) throw new IllegalStateException("Already set a thread");
    thread = ps;
    thread.setName(threadName);
  }

  /**
   * Returns a concise, human-readable description of this wrapper for diagnostics and UI output.
   *
   * <p>The string includes the generated wrapper/thread identifier, the plugin runtime class name,
   * and the wrapper start timestamp. It is intended for logging and debug views rather than for
   * parsing or stable machine consumption. Callers should not rely on any particular formatting
   * beyond it being a single-line summary.
   *
   * @return a descriptive string containing identifier, class name, and start time information.
   */
  @Override
  public String toString() {
    return "ID: \"" + threadName + "\", Name: " + className + ", Started: " + (new Date(start));
  }

  /**
   * Returns the generated thread name used for the plugin thread (when one is used).
   *
   * <p>The value is generated during construction and is intended to be stable for the lifetime of
   * this wrapper. It is used for logging and operator-facing UIs where a deterministic label helps
   * correlate events to a specific plugin instance. This method does not create or start a thread;
   * it only returns the name that {@link #setThread(Thread)} applies when a thread is provided.
   *
   * @return the wrapper-specific thread name string, suitable for display and logs.
   */
  public String getThreadName() {
    return threadName;
  }

  /**
   * Returns the wall-clock start timestamp recorded when this wrapper was constructed.
   *
   * <p>The timestamp is captured using {@link System#currentTimeMillis()} when the wrapper is
   * created, which typically corresponds to when the plugin instance was integrated into the node.
   * It is primarily intended for status displays and diagnostic logging rather than for measuring
   * durations with high precision.
   *
   * @return the start time in milliseconds since the Unix epoch.
   */
  public long getStarted() {
    return start;
  }

  /**
   * Returns the fully-qualified Java class name of the wrapped plugin instance.
   *
   * <p>This value comes from {@link Class#getName()} on the runtime type of the plugin object. It
   * is a stable identifier that can be used in file naming, configuration keys, and user-facing
   * diagnostics where the file name alone is not sufficient to disambiguate plugins.
   *
   * @return the plugin's fully-qualified class name, never {@code null}.
   */
  public String getPluginClassName() {
    return plug.getClass().getName();
  }

  /**
   * Returns the plugin-reported version string when available, or a localized placeholder if not.
   *
   * <p>If the plugin implements {@link FredPluginVersioned}, this method delegates to {@link
   * FredPluginVersioned#getVersion()}. Otherwise, it returns a localized “no version” string via
   * {@link NodeL10n}, which is intended for display in UIs rather than for programmatic comparison.
   *
   * @return a human-readable version string, or a localized placeholder when unavailable.
   */
  public String getPluginVersion() {
    if (isVersionedPlugin) {
      return ((FredPluginVersioned) plug).getVersion();
    } else {
      return NodeL10n.getBase().getString("PproxyToadlet.noVersion");
    }
  }

  /**
   * Returns the currently recorded HTTP toadlet symlink paths for this plugin.
   *
   * <p>The returned array is a snapshot of the internal bookkeeping at the time of the call. The
   * method is synchronized to provide a consistent view with respect to {@link
   * #addPluginToadletSymlink(String)} and {@link #removePluginToadletSymlink(String)}. This wrapper
   * does not create filesystem links; it only tracks the strings that higher-level code registers.
   *
   * @return a snapshot array of symlink strings, possibly empty but never {@code null}.
   */
  public synchronized String[] getPluginToadletSymlinks() {
    return toadletLinks.toArray(new String[0]);
  }

  /**
   * Records an additional toadlet symlink path for this plugin.
   *
   * <p>This method updates only the wrapper's in-memory bookkeeping; it does not register HTTP
   * handlers or create filesystem links by itself. Callers typically invoke it when the plugin
   * registers a web toadlet so that management UIs can list the active paths. Duplicate
   * registrations are ignored by returning {@code false}.
   *
   * @param linkfrom the symlink path being registered for the plugin, as a stable string key.
   * @return {@code true} if the link was newly added, {@code false} if it was already present.
   */
  public synchronized boolean addPluginToadletSymlink(String linkfrom) {
    if (toadletLinks.isEmpty()) toadletLinks = new HashSet<>();
    return toadletLinks.add(linkfrom);
  }

  /**
   * Removes a previously recorded toadlet symlink path for this plugin.
   *
   * <p>This method updates only the wrapper's in-memory bookkeeping. If the provided path is not
   * present, the method returns {@code false} and leaves the internal state unchanged. The method
   * is synchronized to ensure that callers observe consistent results when concurrent registration
   * updates occur during plugin startup or shutdown.
   *
   * @param linkfrom the symlink path being unregistered for the plugin, as a stable string key.
   * @return {@code true} if the link was removed, {@code false} if it was not present.
   */
  public synchronized boolean removePluginToadletSymlink(String linkfrom) {
    if (toadletLinks.isEmpty()) return false;
    return toadletLinks.remove(linkfrom);
  }

  /**
   * Begins shutdown by unregistering callbacks and invoking {@link FredPlugin#terminate()}.
   *
   * <p>This method performs the “request termination” phase of shutdown. It first calls {@link
   * #unregister(PluginManager, boolean)} so the plugin becomes unreachable from UIs and callbacks.
   * It then logs the termination request and invokes {@link FredPlugin#terminate()} while
   * temporarily setting the current thread's context class loader to the plugin's class loader.
   * This improves compatibility with plugins that load resources via the context loader.
   *
   * <p>This method does not wait for any plugin thread to exit; callers should follow up with
   * {@link #finishShutdownPlugin(PluginManager, long, boolean)} when coordinated waiting and
   * class-loader cleanup is desired.
   *
   * @param manager the plugin manager coordinating shutdown and unregistration callbacks.
   * @param reloading {@code true} when stopping as part of a reload, {@code false} for full stop.
   */
  public void startShutdownPlugin(PluginManager manager, boolean reloading) {
    unregister(manager, reloading);
    // Consider adding a timeout for plug.terminate() as well.
    LOG.info("Terminating plugin {}", getFilename());

    // set the plugin’s class loader as context class loader
    ClassLoader originalClassLoader = Thread.currentThread().getContextClassLoader();
    Thread.currentThread().setContextClassLoader(plug.getClass().getClassLoader());

    try {
      plug.terminate();
    } catch (Exception e) {
      LOG.error("Error while terminating plugin.", e);
    } finally {
      Thread.currentThread().setContextClassLoader(originalClassLoader);
    }
    synchronized (this) {
      stopping = true;
    }
  }

  /**
   * Compares this wrapper to another object using reference identity.
   *
   * <p>This wrapper does not define a structural equality based on plugin fields. Equality is
   * intentionally implemented as {@code this == obj} so that wrapper instances remain distinct even
   * when they wrap the same plugin class or have similar metadata. This aligns with the fact that a
   * {@link PluginInfoWrapper} represents a specific loaded plugin instance with associated runtime
   * state.
   *
   * @param obj the object to compare against; may be {@code null} or any type.
   * @return {@code true} only when {@code obj} is the same wrapper instance.
   */
  @Override
  public boolean equals(Object obj) {
    return this == obj;
  }

  /**
   * Returns the identity-based hash code for this wrapper.
   *
   * <p>This method intentionally delegates to {@link Object#hashCode()} to preserve the default
   * identity-based behavior. It is consistent with {@link #equals(Object)} being implemented as
   * reference equality. Callers should not interpret this value as being derived from plugin
   * metadata; it is suitable only for hash-based collections keyed by the wrapper instance.
   *
   * @return the default identity hash code for this wrapper instance.
   */
  @Override
  public int hashCode() {
    return super.hashCode();
  }

  /**
   * Provides a deterministic ordering for plugin wrappers.
   *
   * <p>The ordering is intended for stable iteration and display. It first compares by the plugin
   * runtime class name, then by the wrapper start timestamp, and finally by several identity-based
   * tiebreakers (including {@link System#identityHashCode(Object)} values and the recorded file
   * name). This helps ensure a total ordering even when multiple plugin instances share the same
   * class and start time.
   *
   * @param pi the other wrapper to compare to; must be a non-null wrapper instance.
   * @return a negative value, zero, or a positive value per the {@link Comparable} contract.
   */
  @Override
  public int compareTo(PluginInfoWrapper pi) {
    int byClassName = className.compareTo(pi.className);
    if (byClassName != 0) {
      return byClassName;
    }
    if (this == pi) {
      return 0;
    }
    int byStart = Long.compare(start, pi.start);
    if (byStart != 0) {
      return byStart;
    }
    int byPluginIdentity =
        Integer.compare(System.identityHashCode(plug), System.identityHashCode(pi.plug));
    if (byPluginIdentity != 0) {
      return byPluginIdentity;
    }
    int byWrapperIdentity =
        Integer.compare(System.identityHashCode(this), System.identityHashCode(pi));
    if (byWrapperIdentity != 0) {
      return byWrapperIdentity;
    }
    int byFilename = String.valueOf(filename).compareTo(String.valueOf(pi.filename));
    if (byFilename != 0) {
      return byFilename;
    }
    return threadName.compareTo(pi.threadName);
  }

  /**
   * Completes shutdown by interrupting/joining the plugin thread and releasing loader resources.
   *
   * <p>If a plugin thread has been set via {@link #setThread(Thread)}, this method interrupts it
   * and optionally waits for it to terminate. The {@code maxWaitTime} parameter controls whether
   * the join is skipped ({@code -1}), unbounded ({@code 0}), or bounded (a positive number of
   * milliseconds). If the waiting thread itself is interrupted, this method restores the interrupt
   * status after logging and continues with cleanup.
   *
   * <p>After thread handling, the plugin's {@link ClassLoader} is checked; when it is a {@link
   * JarClassLoader}, it is closed so the plugin JAR can be deleted or replaced.
   *
   * @param manager the plugin manager coordinating shutdown; used only for diagnostic logging.
   * @param maxWaitTime the maximum time to wait, in milliseconds; {@code -1} skips waiting.
   * @param reloading {@code true} when stopping as part of a reload, {@code false} for full stop.
   * @return {@code true} if the plugin thread terminated within the wait policy, otherwise {@code
   *     false}.
   */
  public boolean finishShutdownPlugin(PluginManager manager, long maxWaitTime, boolean reloading) {
    if (LOG.isDebugEnabled()) {
      LOG.debug("finishShutdownPlugin(manager={}, reloading={})", manager, reloading);
    }
    boolean success = true;
    if (thread != null) {
      thread.interrupt();
      // Will be removed when the thread exits.
      if (maxWaitTime >= 0) {
        try {
          thread.join(maxWaitTime);
        } catch (InterruptedException _) {
          LOG.info(
              "stopPlugin interrupted while join()ed to terminating plugin thread - maybe one"
                  + " plugin stopping another???");
          Thread.currentThread().interrupt();
        }
        if (thread.isAlive()) {
          String error =
              "Waited for "
                  + thread
                  + " for "
                  + plug
                  + " to exit for "
                  + maxWaitTime
                  + "ms, and it is still alive!";
          LOG.error(error);
          success = false;
        }
      }
    }

    // Close the jar file, so we may delete / reload it
    ClassLoader cl = plug.getClass().getClassLoader();
    if (cl instanceof JarClassLoader loader) {
      IOUtils.closeQuietly(loader);
    }
    return success;
  }

  /**
   * Stops the plugin and removes it from the manager, optionally waiting for its thread to exit.
   *
   * <p>This is the coordinated “stop” entry point used by {@link PluginManager}. It first calls
   * {@link #startShutdownPlugin(PluginManager, boolean)} to unregister and invoke {@link
   * FredPlugin#terminate()}, then calls {@link #finishShutdownPlugin(PluginManager, long, boolean)}
   * to interrupt/join the plugin thread (if present) and close any {@link JarClassLoader}. Finally,
   * the plugin is removed from the manager via {@link
   * PluginManager#removePlugin(PluginInfoWrapper)} regardless of whether the thread terminated
   * within the wait policy.
   *
   * @param manager the plugin manager coordinating shutdown and final removal actions.
   * @param maxWaitTime the wait policy in milliseconds; {@code -1} skips waiting, {@code 0} waits
   *     indefinitely, otherwise waits up to the given duration.
   * @param reloading {@code true} when stopping due to a reload, {@code false} for full shutdown.
   */
  public void stopPlugin(PluginManager manager, long maxWaitTime, boolean reloading) {
    startShutdownPlugin(manager, reloading);
    finishShutdownPlugin(manager, maxWaitTime, reloading);
    // always remove plugin
    manager.removePlugin(this);
  }

  /**
   * Unregister the plugin from any user interface or other callbacks it may be registered with.
   * Call this before manager.removePlugin(): the plugin becomes unvisitable immediately, but it may
   * take time for it to shut down completely.
   */
  void unregister(PluginManager manager, boolean reloading) {
    synchronized (this) {
      if (unregistered) return;
      unregistered = true;
    }
    manager.unregisterPlugin(this, plug, reloading);
  }

  /**
   * Returns whether the wrapped plugin implements the HTTP/“Pproxy” plugin interface.
   *
   * <p>This is a cached capability flag determined once at construction time. Callers typically use
   * it to conditionally enable HTTP-related integration points and to decide whether the plugin
   * should be treated as providing HTTP handlers. The value reflects the plugin instance's runtime
   * type and does not change over time.
   *
   * @return {@code true} if the plugin implements {@link FredPluginHTTP}, otherwise {@code false}.
   */
  public boolean isPproxyPlugin() {
    return isPproxyPlugin;
  }

  /**
   * Returns the plugin's filename or identifier as provided when it was loaded.
   *
   * <p>This value is used for user-facing displays and for shutdown logging. It may be a simple
   * file name, a relative path, or another identifier depending on how the plugin was loaded. This
   * method performs no filesystem access and returns the original value captured at construction.
   *
   * @return the plugin filename or identifier string, which may be {@code null}.
   */
  public String getFilename() {
    return filename;
  }

  /**
   * Returns whether the wrapped plugin exposes bandwidth indication capabilities.
   *
   * <p>This is a cached capability flag determined at construction time via {@code instanceof}.
   * Callers typically use it to decide whether to route bandwidth events to the plugin or expose
   * related UI elements. The value is stable for the lifetime of this wrapper.
   *
   * @return {@code true} if the plugin implements {@link FredPluginBandwidthIndicator}.
   */
  public boolean isBandwidthIndicator() {
    return isBandwidthIndicator;
  }

  /**
   * Returns whether the wrapped plugin is threadless (does not run its own dedicated thread).
   *
   * <p>Threadless plugins are expected to perform their work via callbacks rather than a long-lived
   * worker thread. This cached flag helps {@link PluginManager} choose an appropriate shutdown
   * strategy and whether a {@link Thread} is expected to be associated with this wrapper.
   *
   * @return {@code true} if the plugin implements {@link FredPluginThreadless}.
   */
  public boolean isThreadlessPlugin() {
    return isThreadlessPlugin;
  }

  /**
   * Returns whether the wrapped plugin implements IP detection functionality.
   *
   * <p>This cached flag is determined once during construction and is used to enable or disable
   * integration points that supply external address information to plugins. It is derived from the
   * runtime type of the plugin instance and therefore does not change after creation.
   *
   * @return {@code true} if the plugin implements {@link FredPluginIPDetector}.
   */
  public boolean isIPDetectorPlugin() {
    return isIPDetectorPlugin;
  }

  /**
   * Returns whether the wrapped plugin implements port forwarding functionality.
   *
   * <p>This cached flag is computed at construction time and is used by management code to decide
   * whether to expose port-forwarding hooks to the plugin. The value reflects the plugin instance's
   * runtime type and is stable for the lifetime of the wrapper.
   *
   * @return {@code true} if the plugin implements {@link FredPluginPortForward}.
   */
  public boolean isPortForwardPlugin() {
    return isPortForwardPlugin;
  }

  /**
   * Returns whether the wrapped plugin declares itself as a “multiple” plugin implementation.
   *
   * <p>This cached capability flag indicates that the plugin implements {@link FredPluginMultiple}
   * and can participate in the corresponding manager behavior. The value is computed once at
   * construction time and does not change after creation.
   *
   * @return {@code true} if the plugin implements {@link FredPluginMultiple}.
   */
  public boolean isMultiplePlugin() {
    return isMultiplePlugin;
  }

  /**
   * Returns whether the wrapped plugin supports server-side FCP message handling.
   *
   * <p>This cached flag indicates that {@link #getPlugin()} also implements {@link
   * FredPluginFCPMessageHandler.ServerSideFCPMessageHandler}. Callers should check this method
   * before calling {@link #getFCPServerPlugin()} to avoid a {@link ClassCastException}.
   *
   * @return {@code true} if the plugin implements the server-side FCP handler interface.
   */
  public boolean isFCPServerPlugin() {
    return isFCPServerPlugin;
  }

  /**
   * If {@link #isFCPServerPlugin()} returns true, may be called to obtain the {@link
   * FredPluginFCPMessageHandler.ServerSideFCPMessageHandler} of the plugin.
   *
   * <p>Code quality: Currently, all the other is...() functions are used by PluginManager just to
   * then manually cast the plugin main object to the desired type, i.e. it manually does what the
   * body of this function does. This restricts the API to require the plugin main class to
   * implement all the various interfaces. Instead, please add equivalents of this function for all
   * the other is...(), and use those new functions everywhere in PluginManager. This will a
   * preparation for allowing plugins to implement the various interfaces in DIFFERENT classes than
   * their plugin main class - which will be a good idea for keeping plugin main classes short.
   *
   * @return the plugin instance cast to the server-side FCP handler interface.
   * @throws ClassCastException if the plugin does not implement the required interface.
   */
  public FredPluginFCPMessageHandler.ServerSideFCPMessageHandler getFCPServerPlugin() {

    return (FredPluginFCPMessageHandler.ServerSideFCPMessageHandler) plug;
  }

  /**
   * Returns whether the wrapped plugin supports theming integration.
   *
   * <p>This cached capability flag is computed once at construction time and is used by UI code to
   * decide whether to query or notify the plugin about theme-related changes. It reflects the
   * runtime type of the plugin instance and is stable for the lifetime of this wrapper.
   *
   * @return {@code true} if the plugin implements {@link FredPluginThemed}.
   */
  public boolean isThemedPlugin() {
    return isThemedPlugin;
  }

  /**
   * Returns whether the wrapped plugin provides localization resources.
   *
   * <p>This cached flag indicates that the plugin implements {@link FredPluginL10n}. Callers use it
   * to decide whether localization hooks should be invoked and whether plugin-provided translation
   * bundles may be consulted for UI strings.
   *
   * @return {@code true} if the plugin implements {@link FredPluginL10n}.
   */
  public boolean isL10nPlugin() {
    return isL10nPlugin;
  }

  /**
   * Returns whether the wrapped plugin participates in base localization integration.
   *
   * <p>This cached flag indicates that the plugin implements {@link FredPluginBaseL10n}. It is
   * computed once at construction time and is typically used to decide whether the plugin should be
   * treated as providing base translations or related localization behavior.
   *
   * @return {@code true} if the plugin implements {@link FredPluginBaseL10n}.
   */
  public boolean isBaseL10nPlugin() {
    return isBaseL10nPlugin;
  }

  /**
   * Returns whether the wrapped plugin provides a configurable settings surface.
   *
   * <p>This cached flag indicates that the plugin implements {@link FredPluginConfigurable}. When
   * true, this wrapper creates and exposes a per-plugin {@link Config}/{@link SubConfig} and a
   * {@link ConfigToadlet}. When false, {@link #getConfig()}, {@link #getSubConfig()}, and {@link
   * #getConfigToadlet()} return {@code null}.
   *
   * @return {@code true} if the plugin implements {@link FredPluginConfigurable}.
   */
  public boolean isConfigurablePlugin() {
    return isConfigurablePlugin;
  }

  /**
   * Returns whether shutdown has been requested and the wrapper considers the plugin stopping.
   *
   * <p>This flag transitions to {@code true} once {@link #startShutdownPlugin(PluginManager,
   * boolean)} has finished invoking {@link FredPlugin#terminate()}. The value is synchronized to
   * provide a consistent view when callers coordinate shutdown state with other synchronized
   * bookkeeping methods in this class.
   *
   * @return {@code true} when shutdown has been initiated, otherwise {@code false}.
   */
  public synchronized boolean isStopping() {
    return stopping;
  }

  /**
   * Returns the plugin's numeric “real version” when supported, otherwise {@code -1}.
   *
   * <p>If the plugin implements {@link FredPluginRealVersioned}, this method delegates to {@link
   * FredPluginRealVersioned#getRealVersion()} and returns the value. If the plugin does not
   * implement that interface, the method returns {@code -1} as a sentinel indicating “not
   * available”. Callers should treat {@code -1} as meaning “unknown” rather than a legitimate
   * version.
   *
   * @return the plugin's numeric version, or {@code -1} when unavailable.
   */
  public long getPluginLongVersion() {
    if (isLongVersionedPlugin) {
      return ((FredPluginRealVersioned) plug).getRealVersion();
    } else {
      return -1;
    }
  }

  /**
   * Returns the wrapped plugin instance.
   *
   * <p>The returned object is the same instance provided to the constructor. This wrapper does not
   * proxy calls or enforce lifecycle rules on the plugin; callers are expected to respect the
   * plugin manager's lifecycle and to avoid invoking plugin callbacks after unregistration has
   * begun. The returned reference should be treated as owned by the plugin manager.
   *
   * @return the wrapped {@link FredPlugin} instance, never {@code null}.
   */
  public FredPlugin getPlugin() {
    return this.plug;
  }

  /**
   * Returns the {@link PluginRespirator} associated with this plugin.
   *
   * <p>The {@link PluginRespirator} is created during construction and provides the plugin with
   * access to node services in a controlled way. It is safe to cache the returned reference for the
   * lifetime of the plugin. This method does not create additional objects and always returns the
   * same instance.
   *
   * @return the plugin respirator instance created for this wrapper, never {@code null}.
   */
  public PluginRespirator getPluginRespirator() {
    return pr;
  }

  /**
   * Returns the persistent configuration backing store for a configurable plugin, if present.
   *
   * <p>This method returns a {@link FilePersistentConfig}-backed {@link Config} when the plugin
   * implements {@link FredPluginConfigurable}. For non-configurable plugins, it returns {@code
   * null}. Callers should check {@link #isConfigurablePlugin()} before dereferencing the result.
   *
   * @return the plugin configuration object, or {@code null} when the plugin is not configurable.
   */
  public Config getConfig() {
    return config;
  }

  /**
   * Returns the plugin-specific {@link SubConfig} when the plugin is configurable, otherwise null.
   *
   * <p>The {@link SubConfig} is created from the wrapper's {@link #getConfig()} instance using the
   * plugin's class name as a key. It holds the plugin option definitions registered by {@link
   * FredPluginConfigurable#setupConfig(SubConfig)}. For non-configurable plugins, this method
   * returns {@code null}.
   *
   * @return the plugin's subconfiguration, or {@code null} when not applicable.
   */
  public SubConfig getSubConfig() {
    return subconfig;
  }

  /**
   * Returns the HTTP configuration toadlet for a configurable plugin, if one was created.
   *
   * <p>When the plugin implements {@link FredPluginConfigurable}, this wrapper constructs a {@link
   * ConfigToadlet} that exposes the plugin's configuration through the node's HTTP interface. For
   * plugins that do not support configuration, this method returns {@code null}. The returned
   * toadlet is created once during construction and is not recreated on subsequent calls.
   *
   * @return the configuration toadlet instance, or {@code null} when the plugin is not
   *     configurable.
   */
  public ConfigToadlet getConfigToadlet() {
    return configToadlet;
  }

  /**
   * Returns whether this plugin is treated as an official/bundled plugin.
   *
   * <p>This flag is provided by the caller at construction time and is typically used for display
   * and policy decisions (for example, whether a localized display name should be used). The value
   * is stable for the lifetime of this wrapper and does not depend on the plugin instance's class.
   *
   * @return {@code true} if the plugin is considered official, otherwise {@code false}.
   */
  public boolean isOfficialPlugin() {
    return isOfficialPlugin;
  }

  /**
   * Returns a user-facing plugin name suitable for display in UIs.
   *
   * <p>For official plugins, this method maps the plugin's file name through {@link
   * PluginManager#getOfficialPluginLocalisedName(String)} to obtain a localized display name. For
   * non-official plugins, it returns the file name as-is. This method does not load plugin
   * resources; it is intended as a lightweight display helper.
   *
   * @return a localized display name for official plugins, otherwise the raw plugin filename.
   */
  public String getLocalisedPluginName() {
    String pluginName = getFilename();
    if (isOfficialPlugin()) return PluginManager.getOfficialPluginLocalisedName(pluginName);
    else return pluginName;
  }
}

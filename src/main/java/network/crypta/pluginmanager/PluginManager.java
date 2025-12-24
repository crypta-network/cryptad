package network.crypta.pluginmanager;

import static java.util.concurrent.TimeUnit.MINUTES;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.ConcurrentModificationException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.Semaphore;
import java.util.jar.Attributes;
import java.util.jar.JarFile;
import java.util.jar.Manifest;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.clients.fcp.ClientPut;
import network.crypta.clients.http.PageMaker.THEME;
import network.crypta.clients.http.QueueToadlet;
import network.crypta.clients.http.Toadlet;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.NodeNeedRestartException;
import network.crypta.config.SubConfig;
import network.crypta.crypt.HashType;
import network.crypta.keys.FreenetURI;
import network.crypta.l10n.BaseL10n.LANGUAGE;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.RequestClient;
import network.crypta.node.RequestClientBuilder;
import network.crypta.node.RequestStarter;
import network.crypta.node.useralerts.AbstractUserAlert;
import network.crypta.node.useralerts.UserAlert;
import network.crypta.pluginmanager.OfficialPlugins.OfficialPluginDescription;
import network.crypta.support.HTMLNode;
import network.crypta.support.HexUtil;
import network.crypta.support.JarClassLoader;
import network.crypta.support.SerialExecutor;
import network.crypta.support.Ticker;
import network.crypta.support.api.BooleanCallback;
import network.crypta.support.api.HTTPRequest;
import network.crypta.support.api.StringArrCallback;
import network.crypta.support.io.FileUtil;
import network.crypta.support.io.NativeThread.PriorityLevel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.tanukisoftware.wrapper.WrapperManager;

/**
 * Coordinates plugin download, loading, and lifecycle management for a {@link Node}.
 *
 * <p>This class provides the node-facing API for starting plugins from several kinds of
 * specifications (official plugin name, Freenet URI, local file, or URL), tracking startup progress
 * for UI/reporting, and wiring plugins into node services (HTTP handlers, configuration,
 * localization, update management, and IP detector integrations).
 *
 * <p>Typical usage is:
 *
 * <ul>
 *   <li>Create an instance via {@link #create(Node, int)} during node startup.
 *   <li>Invoke {@link #start()} once configuration is ready; plugin startups are scheduled on the
 *       node executor.
 *   <li>On shutdown, call {@link #stop(long)} to request plugin termination and to wait until
 *       plugins are unloaded or a timeout elapses.
 * </ul>
 *
 * <p><strong>Threading:</strong> plugin operations are driven by the node executor and may involve
 * callbacks into plugin code. This manager uses internal synchronization for shared state (such as
 * the loaded plugin set and the HTTP handler registry), but callers should treat it as a
 * single-owner node component: avoid calling lifecycle methods concurrently and avoid long-running
 * work while holding locks that interact with other subsystems.
 */
public class PluginManager {
  private static final Logger LOG = LoggerFactory.getLogger(PluginManager.class);

  private static final String L10N_PREFIX = "PluginManager.";
  private static final String HTML_TAG_INPUT = "input";
  private static final String HTML_ATTR_VALUE = "value";
  private static final String CALLBACK_TASK_NAME = "Callback";
  private static final String CALLBACK_THROWABLE_MESSAGE = "Caught Throwable in Callback";

  private final HashMap<String, FredPlugin> toadletList = new HashMap<>();

  /* All currently starting plugins. */
  private final OfficialPlugins officialPlugins = new OfficialPlugins();
  private final LoadedPlugins loadedPlugins = new LoadedPlugins();
  final Node node;
  private final NodeClientCore core;

  private final HighLevelSimpleClient client;

  private static PluginManager selfinstance = null;

  private THEME fproxyTheme;

  private final SerialExecutor executor;

  /**
   * Creates and registers the singleton {@link PluginManager} instance for the current JVM.
   *
   * <p>The returned instance becomes the global {@code PluginManager} referenced by static helpers
   * such as {@link #setLanguage(LANGUAGE)}. Callers should therefore prefer using this factory
   * rather than invoking the constructor directly.
   *
   * <p>This method does not start plugins. Call {@link #start()} after construction to schedule
   * plugin startup work.
   *
   * @param node owning node instance whose services and configuration are used by plugins
   * @param lastVersion node build number used to apply upgrade-time compatibility adjustments
   * @return the newly created plugin manager instance for {@code node}
   */
  public static PluginManager create(Node node, int lastVersion) {
    PluginManager pluginManager = new PluginManager(node, lastVersion);
    selfinstance = pluginManager;
    return pluginManager;
  }

  static final short PRIO = RequestStarter.INTERACTIVE_PRIORITY_CLASS;

  /** Is the plugin system enabled? Set at boot time only. Mainly for simulations. */
  private final boolean enabled;

  /**
   * Creates a plugin manager bound to the given node.
   *
   * <p>Construction wires configuration options, initializes the callback executor used for
   * plugin-invoked operations, and captures the initial list of plugins to start from configuration
   * (including legacy upgrade adjustments based on {@code lastVersion}).
   *
   * <p>This constructor does not start or load any plugin. Use {@link #start()} to schedule startup
   * on the node executor once the node is ready.
   *
   * @param node node that owns this plugin manager and provides access to shared subsystems
   * @param lastVersion previous node build number used for one-time migration behaviors
   */
  public PluginManager(Node node, int lastVersion) {

    // config

    this.node = node;
    this.core = node.getClientCore();

    if (LOG.isTraceEnabled()) LOG.debug("Starting Plugin Manager");

    if (LOG.isTraceEnabled()) LOG.trace("Initialize Plugin Manager config");

    client = core.makeClient(PRIO, true, false);

    // callback executor
    executor = new SerialExecutor(PriorityLevel.NORM_PRIORITY.value);
    executor.start(node.getExecutor(), "PM callback executor");

    SubConfig pmconfig = node.getConfig().createSubConfig("pluginmanager");
    pmconfig.register(
        "enabled",
        true,
        0,
        true,
        true,
        "PluginManager.enabled",
        "PluginManager.enabledLong",
        new BooleanCallback() {

          @Override
          public synchronized Boolean get() {
            return enabled;
          }

          @Override
          public synchronized void set(Boolean val) throws NodeNeedRestartException {
            if (enabled != Boolean.TRUE.equals(val))
              throw new NodeNeedRestartException(l10n("changePluginManagerEnabledInConfig"));
          }
        });
    enabled = pmconfig.getBoolean("enabled");

    // Start plugins in the config
    pmconfig.register(
        "loadplugin",
        null,
        0,
        true,
        false,
        "PluginManager.loadedOnStartup",
        "PluginManager.loadedOnStartupLong",
        new StringArrCallback() {

          @Override
          public String[] get() {
            return getConfigLoadString();
          }

          @Override
          public void set(String[] val) throws InvalidConfigValueException {
            throw new InvalidConfigValueException(
                NodeL10n.getBase().getString("PluginManager.cannotSetOnceLoaded"));
          }

          @Override
          public boolean isReadOnly() {
            return true;
          }
        });

    toStart = pmconfig.getStringArr("loadplugin");

    if (lastVersion < 1237 && contains(toStart, "XMLLibrarian") && !contains(toStart, "Library")) {
      toStart = Arrays.copyOf(toStart, toStart.length + 1);
      toStart[toStart.length - 1] = "Library";
      LOG.warn("Loading Library plugin, replaces XMLLibrarian, when upgrading from pre-1237");
    }

    if (contains(toStart, "KeyExplorer")) {
      for (int i = 0; i < toStart.length; i++) {
        if ("KeyExplorer".equals(toStart[i])) toStart[i] = "KeyUtils";
      }
      LOG.warn("KeyExplorer plugin renamed to KeyUtils");
    }

    // ignore this in config files.
    pmconfig.registerIgnoredOption("alwaysLoadOfficialPluginsFromCentralServer");

    pmconfig.finishedInitialization();

    fproxyTheme = THEME.themeFromName(node.getConfig().get("fproxy").getString("css"));
  }

  private boolean contains(String[] array, String string) {
    for (String s : array) if (string.equals(s)) return true;
    return false;
  }

  private boolean started;
  private boolean stopping;
  private String[] toStart;

  /**
   * Starts all plugins configured to load on startup.
   *
   * <p>Startup is asynchronous: for each configured plugin entry, a task is scheduled on the node
   * executor to resolve the specification and load the plugin. After all tasks signal completion,
   * the manager marks itself as started and clears the startup list.
   *
   * <p>This method is idempotent. If the plugin system is disabled or already started, it returns
   * without scheduling work.
   */
  public void start() {
    if (!enabled) return;
    synchronized (loadedPlugins) {
      if (started) {
        return;
      }
    }

    final Semaphore startingPlugins = new Semaphore(0);
    for (final String name : toStart) {
      core.getExecutor()
          .execute(
              () -> {
                startPluginAuto(name, false);
                startingPlugins.release();
              });
    }

    core.getExecutor()
        .execute(
            () -> {
              startingPlugins.acquireUninterruptibly(toStart.length);
              synchronized (loadedPlugins) {
                started = true;
                toStart = null;
              }
            });
  }

  /**
   * Stops all loaded (and still-starting) plugins, waiting up to the given time budget.
   *
   * <p>This method:
   *
   * <ul>
   *   <li>Marks the manager as stopping to prevent new plugin loads.
   *   <li>Requests cancellation for plugins that are still in the "starting" phase.
   *   <li>Initiates shutdown for already loaded plugins and polls for completion until the timeout
   *       elapses.
   * </ul>
   *
   * <p>If the timeout elapses, the method logs the remaining plugins and returns; it does not throw
   * an exception.
   *
   * @param maxWaitTime maximum time to wait in milliseconds for plugins to unload
   */
  public void stop(long maxWaitTime) {
    if (!enabled) return;
    markStopping();
    killStartingPlugins();
    startLoadedPluginsShutdown();

    long deadline = System.currentTimeMillis() + maxWaitTime;
    while (true) {
      int remainingMillis = (int) (deadline - System.currentTimeMillis());
      if (remainingMillis <= 0) {
        logShutdownTimeout();
        return;
      }

      finishShutdownIteration(remainingMillis);
      if (!loadedPlugins.hasLoadedPlugins()) {
        LOG.info("All plugins unloaded");
        return;
      }

      logStillShuttingDown();
    }
  }

  private void markStopping() {
    // Stop loading plugins.
    synchronized (loadedPlugins) {
      stopping = true;
    }
  }

  private void killStartingPlugins() {
    for (PluginProgress progress : loadedPlugins.getStartingPlugins()) {
      progress.kill();
    }
  }

  private void startLoadedPluginsShutdown() {
    // Stop already loaded plugins.
    for (PluginInfoWrapper pluginInfoWrapper : loadedPlugins.getLoadedPlugins()) {
      pluginInfoWrapper.startShutdownPlugin(this, false);
    }
  }

  private void finishShutdownIteration(int remainingMillis) {
    for (PluginInfoWrapper pluginInfoWrapper : loadedPlugins.getLoadedPlugins()) {
      LOG.info("Waiting for plugin to finish shutting down: {}", pluginInfoWrapper.getFilename());
      if (pluginInfoWrapper.finishShutdownPlugin(this, remainingMillis, false)) {
        loadedPlugins.removeLoadedPlugin(pluginInfoWrapper);
      }
    }
  }

  private void logStillShuttingDown() {
    String list = pluginList(loadedPlugins.getLoadedPlugins());
    LOG.error("Plugins still shutting down:\n{}", list);
  }

  private void logShutdownTimeout() {
    String list = "";
    try {
      list = pluginList(loadedPlugins.getLoadedPlugins());
      LOG.error("Plugins still shutting down at timeout:\n{}", list);
    } catch (ConcurrentModificationException e) {
      LOG.error("Error during shutdown: {}", e, e);
      LOG.error("Plugins still shutting down at timeout:\n{}", list);
    }
  }

  private static String pluginList(Collection<PluginInfoWrapper> wrappers) {
    StringBuilder sb = new StringBuilder();
    for (PluginInfoWrapper pi : wrappers) {
      sb.append(pi.getFilename());
      sb.append('\n');
    }
    return sb.toString();
  }

  private String[] getConfigLoadString() {
    synchronized (loadedPlugins) {
      if (!started) {
        return toStart;
      }
    }
    List<String> v = new ArrayList<>();
    for (PluginInfoWrapper pi : loadedPlugins.getLoadedPlugins()) {
      v.add(pi.getFilename());
    }
    v.addAll(loadedPlugins.getFailedPluginNames());
    return v.toArray(new String[0]);
  }

  /**
   * Returns a set of all currently starting plugins.
   *
   * <p>The returned set is a snapshot copy and is safe to iterate without holding internal locks.
   * Modifications to the returned set do not affect the plugin manager.
   *
   * @return snapshot copy of all currently starting plugin progress trackers
   */
  public Set<PluginProgress> getStartingPlugins() {
    return new HashSet<>(loadedPlugins.getStartingPlugins());
  }

  /**
   * Starts a plugin from an arbitrary specification, choosing an appropriate loader.
   *
   * <p>This method applies a heuristic resolution order:
   *
   * <ul>
   *   <li>Official plugin name (as returned by {@link #isOfficialPlugin(String)}).
   *   <li>Freenet URI (string accepted by {@link FreenetURI}).
   *   <li>Existing local path (matched against the JVM's root directories).
   *   <li>URL as a final fallback.
   * </ul>
   *
   * <p>The returned {@link PluginInfoWrapper} is {@code null} when the plugin is already loaded or
   * when startup fails in a way that the manager converts into a user alert and potential retry.
   *
   * @param pluginname plugin specification; may be an official name, key, file path, or URL
   * @param store whether to persist configuration after attempting to start the plugin
   * @return wrapper for the started plugin, or {@code null} when not started
   */
  public PluginInfoWrapper startPluginAuto(final String pluginname, boolean store) {

    OfficialPluginDescription desc;
    if ((desc = isOfficialPlugin(pluginname)) != null) {
      return startPluginOfficial(pluginname, store, desc);
    }

    try {
      new FreenetURI(pluginname); // test for MalformedURLException
      return startPluginFreenet(pluginname, store);
    } catch (MalformedURLException _) {
      // not a freenet key
    }

    File[] roots = File.listRoots();
    for (File f : roots) {
      if (pluginname.startsWith(f.getName()) && new File(pluginname).exists()) {
        return startPluginFile(pluginname, store);
      }
    }

    return startPluginURL(pluginname, store);
  }

  /**
   * Starts an official plugin by its short name.
   *
   * <p>The plugin content is retrieved using the official plugin loader and is subject to the
   * official plugin descriptor configuration (including whether a fresh download is required).
   *
   * @param pluginname official plugin name as used in configuration and {@link OfficialPlugins}
   * @param store whether to persist configuration after the load attempt completes
   * @return wrapper for the started plugin, or {@code null} when not started
   */
  public PluginInfoWrapper startPluginOfficial(final String pluginname, boolean store) {
    return startPluginOfficial(pluginname, store, officialPlugins.get(pluginname));
  }

  /**
   * Legacy overload kept for compatibility. Prefer {@link #startPluginOfficial(String, boolean)}.
   *
   * <p>This overload accepts obsolete parameters that historically controlled loader behavior. The
   * current implementation intentionally ignores them.
   *
   * @param pluginname official plugin name as used in configuration and {@link OfficialPlugins}
   * @param store whether to persist configuration after the load attempt completes
   * @param force This parameter is ignored.
   * @param forceHTTPS This parameter is ignored.
   * @return wrapper for the started plugin, or {@code null} when not started
   */
  @SuppressWarnings("unused")
  public PluginInfoWrapper startPluginOfficial(
      final String pluginname, boolean store, boolean force, boolean forceHTTPS) {
    return startPluginOfficial(pluginname, store);
  }

  /**
   * Starts an official plugin using an already resolved descriptor.
   *
   * <p>This overload is used when the caller has already looked up the {@link
   * OfficialPluginDescription} and wants to avoid repeating that lookup.
   *
   * @param pluginname official plugin name as used in configuration and {@link OfficialPlugins}
   * @param store whether to persist configuration after the load attempt completes
   * @param desc descriptor for {@code pluginname}; must not be {@code null}
   * @return wrapper for the started plugin, or {@code null} when not started
   */
  public PluginInfoWrapper startPluginOfficial(
      final String pluginname, boolean store, OfficialPluginDescription desc) {
    return realStartPlugin(
        new PluginDownLoaderOfficialFreenet(client, node, false),
        pluginname,
        store,
        desc.alwaysFetchLatestVersion);
  }

  /**
   * Legacy overload kept for compatibility. Prefer {@link #startPluginOfficial(String, boolean,
   * OfficialPluginDescription)}.
   *
   * <p>This overload accepts obsolete parameters that historically controlled loader behavior. The
   * current implementation intentionally ignores them.
   *
   * @param pluginname official plugin name as used in configuration and {@link OfficialPlugins}
   * @param store whether to persist configuration after the load attempt completes
   * @param officialPluginDescription descriptor for the official plugin to load
   * @param force This parameter is ignored.
   * @param forceHTTPS This parameter is ignored.
   * @return wrapper for the started plugin, or {@code null} when not started
   */
  @SuppressWarnings("unused")
  public PluginInfoWrapper startPluginOfficial(
      final String pluginname,
      boolean store,
      OfficialPluginDescription officialPluginDescription,
      boolean force,
      boolean forceHTTPS) {
    return startPluginOfficial(pluginname, store, officialPluginDescription);
  }

  /**
   * Starts a plugin from a local file path.
   *
   * <p>The file is treated as a plugin JAR and loaded using the file-based plugin downloader.
   *
   * @param filename local filesystem path to the plugin JAR (absolute or relative to the process)
   * @param store whether to persist configuration after the load attempt completes
   * @return wrapper for the started plugin, or {@code null} when not started
   */
  public PluginInfoWrapper startPluginFile(final String filename, boolean store) {
    return realStartPlugin(new PluginDownLoaderFile(), filename, store, false);
  }

  /**
   * Starts a plugin from a URL specification.
   *
   * <p>The URL is interpreted by the URL-based plugin downloader, which may download the plugin
   * into the plugin directory. If caching is allowed and a cached copy exists, the downloader may
   * reuse it.
   *
   * @param filename URL string for the plugin JAR to download and load
   * @param store whether to persist configuration after the load attempt completes
   * @return wrapper for the started plugin, or {@code null} when not started
   */
  public PluginInfoWrapper startPluginURL(final String filename, boolean store) {
    return realStartPlugin(new PluginDownLoaderURL(), filename, store, false);
  }

  /**
   * Starts a plugin from a Freenet URI specification.
   *
   * <p>The provided string is expected to be a key that the Freenet-based downloader can resolve.
   * Depending on downloader policy, the manager may keep cached copies in the plugin directory and
   * may schedule retries when the plugin cannot be fetched immediately.
   *
   * @param filename freenet key string that identifies the plugin content
   * @param store whether to persist configuration after the load attempt completes
   * @return wrapper for the started plugin, or {@code null} when not started
   */
  public PluginInfoWrapper startPluginFreenet(final String filename, boolean store) {
    return realStartPlugin(
        new PluginDownLoaderFreenet(client, node, false), filename, store, false);
  }

  @SuppressWarnings("java:S1181")
  private PluginInfoWrapper realStartPlugin(
      final PluginDownLoader<?> pdl,
      final String filename,
      final boolean store,
      boolean alwaysDownload) {
    if (!enabled) throw new IllegalStateException("Plugins disabled");
    if (filename.trim().isEmpty()) return null;
    final PluginProgress pluginProgress = new PluginProgress(filename, pdl);
    loadedPlugins.addStartingPlugin(pluginProgress);
    LOG.info("Loading plugin: {}", filename);
    FredPlugin plug;
    PluginInfoWrapper pi = null;
    try {
      plug = loadPlugin(pdl, filename, pluginProgress, alwaysDownload);
      pluginProgress.setStarting();
      pi = new PluginInfoWrapper(node, plug, filename, pdl.isOfficialPluginLoader());
      PluginHandler.startPlugin(PluginManager.this, pi);
      loadedPlugins.addLoadedPlugin(pi);
      loadedPlugins.removeFailedPlugin(filename);
      LOG.info("Plugin loaded: {}", filename);
    } catch (PluginAlreadyLoaded _) {
      return null;
    } catch (PluginNotFoundException e) {
      LOG.info("Loading plugin failed ({})", filename, e);
      boolean stillTrying = scheduleRetryAfterPluginNotFound(pdl, filename, store);
      PluginLoadFailedUserAlert newAlert =
          new PluginLoadFailedUserAlert(filename, pdl.isOfficialPluginLoader(), stillTrying, e);
      PluginLoadFailedUserAlert oldAlert = loadedPlugins.replaceUserAlert(filename, newAlert);
      core.getAlerts().register(newAlert);
      core.getAlerts().unregister(oldAlert);
    } catch (UnsupportedClassVersionError e) {
      LOG.error("Could not load plugin {} : {}", filename, e, e);
      LOG.error("Plugin {} appears to require a later JVM", filename);
      PluginLoadFailedUserAlert newAlert =
          new PluginLoadFailedUserAlert(
              filename,
              pdl.isOfficialPluginLoader(),
              false,
              l10nName("pluginReqNewerJVMTitle", filename));
      PluginLoadFailedUserAlert oldAlert = loadedPlugins.replaceUserAlert(filename, newAlert);
      core.getAlerts().register(newAlert);
      core.getAlerts().unregister(oldAlert);
    } catch (Throwable t) {
      if (t instanceof VirtualMachineError vme) {
        throw vme;
      }
      LOG.error("Could not load plugin {} : {}", filename, t, t);
      LOG.error("Plugin {} is broken, but we want to retry after next startup", filename);
      PluginLoadFailedUserAlert newAlert =
          new PluginLoadFailedUserAlert(filename, pdl.isOfficialPluginLoader(), false, t);
      PluginLoadFailedUserAlert oldAlert = loadedPlugins.replaceUserAlert(filename, newAlert);
      core.getAlerts().register(newAlert);
      core.getAlerts().unregister(oldAlert);
    } finally {
      loadedPlugins.removeStartingPlugin(pluginProgress);
    }
    /* try not to destroy the config. */
    synchronized (this) {
      if (store) core.storeConfig();
    }
    if (pi != null) node.getNodeUpdater().startPluginUpdater(filename);
    return pi;
  }

  private boolean scheduleRetryAfterPluginNotFound(
      PluginDownLoader<?> pdl, String filename, boolean store) {
    if (!pdl.isLoadingFromFreenet()) {
      return false;
    }
    PluginDownLoaderFreenet downloader = (PluginDownLoaderFreenet) pdl;
    if (downloader.fatalFailure() || downloader.desperate || twoCopiesInStartingPlugins(filename)) {
      return false;
    }
    // Retry forever...
    final PluginDownLoader<?> retry = pdl.getRetryDownloader();
    node.getTicker().queueTimedJob(() -> realStartPlugin(retry, filename, store, true), 0);
    return true;
  }

  private synchronized boolean twoCopiesInStartingPlugins(String filename) {
    int count = 0;
    for (PluginProgress progress : loadedPlugins.getStartingPlugins()) {
      if (filename.equals(progress.name)) {
        count++;
        if (count == 2) return true;
      }
    }
    return false;
  }

  class PluginLoadFailedUserAlert extends AbstractUserAlert {

    final String filename;
    final String message;
    final StackTraceElement[] stacktrace;
    final boolean official;
    final boolean stillTrying;

    public PluginLoadFailedUserAlert(
        String filename, boolean official, boolean stillTrying, String message) {
      this.filename = filename;
      this.official = official;
      this.message = message;
      this.stacktrace = null;
      this.stillTrying = stillTrying;
    }

    public PluginLoadFailedUserAlert(
        String filename, boolean official, boolean stillTrying, Throwable e) {
      this.filename = filename;
      this.official = official;
      this.stillTrying = stillTrying;
      String msg;
      if (e instanceof PluginNotFoundException) {
        msg = e.getMessage();
        stacktrace = null;
      } else {
        // If it's something wierd, we need to know what it is.
        msg = e.getClass() + ": " + e.getMessage();
        stacktrace = e.getStackTrace();
      }
      if (msg == null) msg = e.toString();
      this.message = msg;
    }

    @Override
    public String dismissButtonText() {
      return l10n("deleteFailedPluginButton");
    }

    @Override
    public void onDismiss() {
      loadedPlugins.removeFailedPlugin(filename);
      node.getExecutor().execute(() -> cancelRunningLoads(filename, null));
    }

    @Override
    public String anchor() {
      return "pluginfailed:" + filename;
    }

    @Override
    public HTMLNode getHTMLText() {
      HTMLNode div = new HTMLNode("div");
      HTMLNode p = div.addChild("p");
      p.addChild("#", l10nPluginLoadingFailedWithMessage(filename, message));

      if (stacktrace != null) {
        for (StackTraceElement e : stacktrace) {
          p.addChild("br");
          p.addChild("%", "&nbsp; &nbsp; &nbsp; &nbsp;");
          p.addChild("#", "at " + e);
        }
      }

      if (stillTrying) {
        div.addChild("p", l10n("pluginLoadingFailedStillTryingOverFreenet"));
      }

      if (official) {
        p = div.addChild("p");
        p.addChild("#", l10n("officialPluginLoadFailedSuggestTryAgain"));

        if (!stillTrying) {
          HTMLNode reloadForm =
              div.addChild(
                  "form", new String[] {"action", "method"}, new String[] {"/plugins/", "post"});
          reloadForm.addChild(
              HTML_TAG_INPUT,
              new String[] {"type", "name", HTML_ATTR_VALUE},
              new String[] {"hidden", "formPassword", node.getClientCore().getFormPassword()});
          reloadForm.addChild(
              HTML_TAG_INPUT,
              new String[] {"type", "name", HTML_ATTR_VALUE},
              new String[] {"hidden", "plugin-name", filename});
          reloadForm.addChild(
              HTML_TAG_INPUT,
              new String[] {"type", "name", HTML_ATTR_VALUE},
              new String[] {
                "submit", "submit-official", l10n("officialPluginLoadFailedTryAgainFreenet")
              });
        }
      }

      return div;
    }

    @Override
    public short getPriorityClass() {
      return UserAlert.ERROR;
    }

    @Override
    public String getShortText() {
      return l10nName("pluginLoadingFailedShort", filename);
    }

    @Override
    public String getText() {
      return l10nPluginLoadingFailedWithMessage(filename, message);
    }

    @Override
    public String getTitle() {
      return l10n("pluginLoadingFailedTitle");
    }

    @Override
    public boolean isValid() {
      boolean success = loadedPlugins.isFailedPlugin(filename);
      if (!success) {
        core.getAlerts().unregister(this);
      }
      return success;
    }

    @Override
    public void isValid(boolean validity) {
      // No-op: validity is derived from LoadedPlugins state via isValid().
    }

    @Override
    public boolean shouldUnregisterOnDismiss() {
      return true;
    }

    @Override
    public boolean userCanDismiss() {
      return true;
    }
  }

  void register(PluginInfoWrapper pi) {
    FredPlugin plug = pi.getPlugin();

    // handles FProxy? If so, register
    if (pi.isPproxyPlugin()) registerToadlet(plug);

    if (pi.isConfigurablePlugin()) {
      // Registering the toadlet with atFront=false means that
      // the node's ConfigToadlet will clobber the plugin's
      // ConfigToadlet and the page will not be visible. So it
      // must be registered with atFront=true. This means that
      // malicious plugins could try to hijack node config
      // pages, to ill effect. Let's avoid that.
      boolean pluginIsTryingToHijackNodeConfig = false;
      for (SubConfig subconfig : node.getConfig().getConfigs()) {
        if (pi.getPluginClassName().equals(subconfig.getPrefix())) {
          pluginIsTryingToHijackNodeConfig = true;
          break;
        }
      }
      if (pluginIsTryingToHijackNodeConfig) {
        LOG.warn(
            "The plugin loaded from {} is attempting to hijack a node configuration page; refusing"
                + " to register its ConfigToadlet",
            pi.getFilename());
      } else {
        Toadlet toadlet = pi.getConfigToadlet();
        core.getToadletContainer()
            .register(
                toadlet,
                "FProxyToadlet.categoryConfig",
                toadlet.path(),
                true,
                "ConfigToadlet." + pi.getPluginClassName() + ".label",
                "ConfigToadlet." + pi.getPluginClassName() + ".tooltip",
                true,
                null,
                (FredPluginL10n) pi.getPlugin());
      }
    }

    if (pi.isIPDetectorPlugin())
      node.getIpDetector().registerIPDetectorPlugin((FredPluginIPDetector) plug);
    if (pi.isPortForwardPlugin())
      node.getIpDetector().registerPortForwardPlugin((FredPluginPortForward) plug);
    if (pi.isBandwidthIndicator())
      node.getIpDetector().registerBandwidthIndicatorPlugin((FredPluginBandwidthIndicator) plug);
  }

  /**
   * Cancels in-flight load operations for a given plugin name.
   *
   * <p>This method iterates over the current "starting" set and requests cancellation for any
   * matching entries except {@code exceptFor}. It also removes canceled entries from the starting
   * set to avoid reporting them as still loading.
   *
   * @param filename plugin name to match against starting plugins
   * @param exceptFor progress instance that should not be canceled, or {@code null} to cancel all
   */
  public void cancelRunningLoads(String filename, PluginProgress exceptFor) {
    LOG.info("Cancelling loads for plugin {}", filename);
    for (PluginProgress progress : loadedPlugins.getStartingPlugins()) {
      if ((progress != exceptFor) && filename.equals(progress.name)) {
        progress.kill();
        loadedPlugins.removeStartingPlugin(progress);
      }
    }
  }

  /**
   * Returns the translation of the given key, prefixed by the short name of the current class.
   *
   * @param key The key to fetch
   * @return The translation
   */
  static String l10n(String key) {
    return NodeL10n.getBase().getString(L10N_PREFIX + key);
  }

  /**
   * Returns the translation of the given key, replacing each occurrence of <code>
   * ${<em>pattern</em>}
   * </code> with <code>value</code>.
   *
   * @param key The key to fetch
   * @param name The value to substitute for the <code>${name}</code> pattern
   * @return The translation
   */
  private static String l10nName(String key, String name) {
    return NodeL10n.getBase().getString(L10N_PREFIX + key, "name", name);
  }

  private static String l10nPluginLoadingFailedWithMessage(String pluginName, String message) {
    return NodeL10n.getBase()
        .getString(
            L10N_PREFIX + "pluginLoadingFailedWithMessage",
            new String[] {"name", "message"},
            new String[] {pluginName, message});
  }

  private void registerToadlet(FredPlugin pl) {
    synchronized (toadletList) {
      toadletList.put(pl.getClass().getName(), pl);
    }
    LOG.info("Added HTTP handler for /plugins/{}/", pl.getClass().getName());
  }

  /**
   * Removes a plugin from the loaded plugin set and persists configuration.
   *
   * <p>This method only updates the manager's bookkeeping and configuration; it does not stop a
   * running plugin. Typical callers invoke it after the plugin has been shut down.
   *
   * @param pi wrapper for the plugin to remove from the loaded set
   */
  public void removePlugin(PluginInfoWrapper pi) {
    synchronized (loadedPlugins) {
      if (!stopping && !loadedPlugins.hasLoadedPlugin(pi)) {
        return;
      }
    }
    loadedPlugins.removeLoadedPlugin(pi);
    core.storeConfig();
  }

  /**
   * Removes the cached copy of the given plugin from the plugins/ directory.
   *
   * @param pluginSpecification plugin identifier, path, or URL used to resolve the cached file
   */
  public void removeCachedCopy(String pluginSpecification) {
    if (pluginSpecification == null) {
      // Will be null if the file for a given plugin can't be found, e.g. if it has already been
      // removed. Ignore it since the file isn't there anyway
      LOG.warn("Can't remove null from cache. Ignoring");
      return;
    }

    int lastSlash = pluginSpecification.lastIndexOf('/');
    String pluginFilename;
    if (lastSlash == -1)
      /* Windows, maybe? */
      lastSlash = pluginSpecification.lastIndexOf('\\');
    File pluginDirectory = node.getPluginDir();
    if (lastSlash == -1) {
      /* it's an official plugin or filename without path */
      if (pluginSpecification.toLowerCase().endsWith(".jar")) pluginFilename = pluginSpecification;
      else pluginFilename = pluginSpecification + ".jar";
    } else pluginFilename = pluginSpecification.substring(lastSlash + 1);
    LOG.debug("Delete plugin - plugname: {} filename: {}", pluginSpecification, pluginFilename);
    List<File> cachedFiles = getPreviousInstances(pluginDirectory, pluginFilename);
    for (File cachedFile : cachedFiles) {
      deleteFileIfExists(cachedFile);
    }
  }

  private void deleteFileIfExists(File file) {
    try {
      boolean deleted = Files.deleteIfExists(file.toPath());
      if (!deleted) {
        LOG.debug("File already absent: {}", file);
      }
    } catch (IOException e) {
      LOG.debug("Can't delete file {}", file, e);
    }
  }

  /**
   * Unregisters a plugin's HTTP handler mapping from the {@code /plugins/} namespace.
   *
   * <p>This method removes the plugin's class-name mapping from the internal handler registry. It
   * is invoked as part of plugin unload, and can also be called defensively during cleanup.
   *
   * @param pi wrapper for the plugin whose handler entry should be removed
   */
  public void unregisterPluginToadlet(PluginInfoWrapper pi) {
    synchronized (toadletList) {
      try {
        toadletList.remove(pi.getPluginClassName());
        LOG.debug("Removed HTTP handler for /plugins/{}/", pi.getPluginClassName());
      } catch (Exception ex) {
        LOG.error("removing Plugin", ex);
      }
    }
  }

  /**
   * Legacy method kept for compatibility.
   *
   * <p>This method removes any HTTP "symlink" mappings that point to the given plugin. It removes
   * the aliases from the internal registry but does not alter the plugin itself.
   *
   * @param pi wrapper for the plugin whose alias mappings should be removed
   */
  @SuppressWarnings("unused")
  public void addToadletSymlinks(PluginInfoWrapper pi) {
    synchronized (toadletList) {
      try {
        String[] targets = pi.getPluginToadletSymlinks();
        if (targets == null) return;

        for (String target : targets) {
          toadletList.remove(target);
          LOG.info("Removed HTTP symlink: {} => /plugins/{}/", target, pi.getPluginClassName());
        }
      } catch (Exception ex) {
        LOG.error("removing Toadlet-link", ex);
      }
    }
  }

  /**
   * Legacy method kept for compatibility.
   *
   * <p>This method removes the aliases from the internal registry and asks the wrapper to forget
   * each alias so it will not be restored on subsequent operations.
   *
   * @param pi wrapper for the plugin whose alias mappings should be removed
   */
  @SuppressWarnings("unused")
  public void removeToadletSymlinks(PluginInfoWrapper pi) {
    synchronized (toadletList) {
      String rm = null;
      try {
        String[] targets = pi.getPluginToadletSymlinks();
        if (targets == null) return;

        for (String target : targets) {
          rm = target;
          toadletList.remove(target);
          pi.removePluginToadletSymlink(target);
          LOG.info("Removed HTTP symlink: {} => /plugins/{}/", target, pi.getPluginClassName());
        }
      } catch (Exception ex) {
        LOG.error("removing Toadlet-link: {}", rm, ex);
      }
    }
  }

  /**
   * Returns a human-readable summary of currently loaded plugins.
   *
   * <p>The returned string is primarily intended for diagnostics and may change format. Each line
   * corresponds to a single {@link PluginInfoWrapper#toString()} value for a loaded plugin.
   *
   * @return multi-line summary of loaded plugins, or an empty string when none are loaded
   */
  public String dumpPlugins() {
    StringBuilder out = new StringBuilder();
    for (PluginInfoWrapper pluginInfoWrapper : loadedPlugins.getLoadedPlugins()) {
      out.append(pluginInfoWrapper.toString()).append('\n');
    }
    return out.toString();
  }

  /**
   * Returns the current set of loaded plugins.
   *
   * <p>The returned set is a snapshot and may not reflect subsequent load/unload activity.
   *
   * @return sorted snapshot set of currently loaded plugin wrappers
   */
  public Set<PluginInfoWrapper> getPlugins() {
    return new TreeSet<>(loadedPlugins.getLoadedPlugins());
  }

  /**
   * Finds a loaded plugin whose class name, filename, or filename without the `.jar` suffix matches
   * the provided identifier.
   *
   * @param identifier plugin class name or jar filename (with or without extension)
   * @return matching {@link PluginInfoWrapper}, or {@code null} if not found
   */
  public PluginInfoWrapper findPluginByIdentifier(String identifier) {
    if (identifier == null) {
      return null;
    }
    for (PluginInfoWrapper info : loadedPlugins.getLoadedPlugins()) {
      if (pluginIdentifierMatches(info, identifier)) {
        return info;
      }
    }
    return null;
  }

  private boolean pluginIdentifierMatches(PluginInfoWrapper info, String identifier) {
    if (identifier.equals(info.getPluginClassName())) {
      return true;
    }
    String filename = info.getFilename();
    if (filename == null) {
      return false;
    }
    if (identifier.equals(filename)) {
      return true;
    }
    String basename = new File(filename).getName();
    if (identifier.equals(basename)) {
      return true;
    }
    if (basename.endsWith(".jar")) {
      String withoutExtension = basename.substring(0, basename.length() - 4);
      return identifier.equals(withoutExtension);
    }
    return false;
  }

  /**
   * Look for PluginInfo for a Plugin with given classname or filename.
   *
   * @param plugname plugin class name or plugin filename to search for
   * @return the matching plugin info wrapper, or {@code null} if not found
   */
  @SuppressWarnings("unused")
  public PluginInfoWrapper getPluginInfo(String plugname) {
    return findPluginByIdentifier(plugname);
  }

  /**
   * Returns the wrapper for the plugin whose main class matches the provided name.
   *
   * <p>This method performs an exact string match against {@link
   * PluginInfoWrapper#getPluginClassName()}. It does not attempt suffix matching or filename
   * matching; use {@link #findPluginByIdentifier(String)} if that behavior is required.
   *
   * @param pluginClassName The name of the main class of the plugin - that is the class which
   *     implements {@link FredPlugin}.
   * @return The {@link PluginInfoWrapper} for the plugin with the given class name, or null if no
   *     matching plugin was found.
   */
  public PluginInfoWrapper getPluginInfoByClassName(String pluginClassName) {
    for (PluginInfoWrapper pluginInfoWrapper : loadedPlugins.getLoadedPlugins()) {
      if (pluginInfoWrapper.getPluginClassName().equals(pluginClassName)) {
        return pluginInfoWrapper;
      }
    }
    return null;
  }

  /**
   * Get the {@link FredPluginFCPMessageHandler.ServerSideFCPMessageHandler} of the plugin with the
   * given class name.
   *
   * @param pluginClassName See {@link #getPluginInfoByClassName(String)}.
   * @return the server-side FCP handler provided by the specified plugin
   * @throws PluginNotFoundException If the specified plugin is not loaded or does not provide an
   *     FCP server.
   */
  public FredPluginFCPMessageHandler.ServerSideFCPMessageHandler getPluginFCPServer(
      String pluginClassName) throws PluginNotFoundException {

    PluginInfoWrapper piw = getPluginInfoByClassName(pluginClassName);
    if (piw != null && piw.isFCPServerPlugin()) {
      return piw.getFCPServerPlugin();
    } else {
      throw new PluginNotFoundException(pluginClassName);
    }
  }

  /**
   * look for a Plugin with given classname
   *
   * @param plugname plugin class name or plugin filename to search for
   * @return {@code true} if the plugin is currently loaded, otherwise {@code false}
   */
  public boolean isPluginLoaded(String plugname) {
    for (PluginInfoWrapper pluginInfoWrapper : loadedPlugins.getLoadedPlugins()) {
      if (pluginInfoWrapper.getPluginClassName().equals(plugname)
          || pluginInfoWrapper.getFilename().equals(plugname)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Checks whether a plugin is loaded, currently starting, or tracked as known.
   *
   * <p>This is a broader predicate than {@link #isPluginLoaded(String)}: it treats plugins as
   * "known" if they are present in the starting set or have a recorded failure state, in addition
   * to being fully loaded.
   *
   * @param plugname The plugin filename e.g. "Library" for an official plugin.
   * @return {@code true} if the plugin is loaded, loading, or otherwise tracked as known
   */
  public boolean isPluginLoadedOrLoadingOrWantLoad(String plugname) {
    return loadedPlugins.isKnownPlugin(plugname);
  }

  /**
   * Dispatches an HTTP GET request to a plugin that implements {@link FredPluginHTTP}.
   *
   * <p>The manager temporarily sets the thread context class loader to the plugin's class loader so
   * the plugin can resolve its own resources and dependencies during request handling. The original
   * context class loader is restored before returning.
   *
   * @param plugin plugin identifier used as the handler key (typically the plugin main class name)
   * @param request request wrapper containing the parsed HTTP request and parameters
   * @return response body produced by the plugin, typically HTML content
   * @throws PluginHTTPException if the plugin is not loaded or does not support HTTP handling
   */
  public String handleHTTPGet(String plugin, HTTPRequest request) throws PluginHTTPException {
    FredPlugin handler;
    synchronized (toadletList) {
      handler = toadletList.get(plugin);
    }
    if (!(handler instanceof FredPluginHTTP)) {
      throw new NotFoundPluginHTTPException("Plugin not loaded!", "/plugins");
    }

    ClassLoader oldClassLoader = Thread.currentThread().getContextClassLoader();
    ClassLoader pluginClassLoader = handler.getClass().getClassLoader();
    Thread.currentThread().setContextClassLoader(pluginClassLoader);
    try {
      return ((FredPluginHTTP) handler).handleHTTPGet(request);
    } finally {
      Thread.currentThread().setContextClassLoader(oldClassLoader);
    }
  }

  /**
   * Dispatches an HTTP POST request to a plugin that implements {@link FredPluginHTTP}.
   *
   * <p>As with {@link #handleHTTPGet(String, HTTPRequest)}, the thread context class loader is
   * temporarily switched to the plugin class loader for the duration of request handling.
   *
   * @param plugin plugin identifier used as the handler key (typically the plugin main class name)
   * @param request request wrapper containing the parsed HTTP request and parameters
   * @return response body produced by the plugin, typically HTML content
   * @throws PluginHTTPException if the plugin is not loaded or does not support HTTP handling
   */
  public String handleHTTPPost(String plugin, HTTPRequest request) throws PluginHTTPException {
    FredPlugin handler;
    synchronized (toadletList) {
      handler = toadletList.get(plugin);
    }
    if (handler == null)
      throw new NotFoundPluginHTTPException("Plugin '" + plugin + "' not found!", "/plugins");

    ClassLoader oldClassLoader = Thread.currentThread().getContextClassLoader();
    ClassLoader pluginClassLoader = handler.getClass().getClassLoader();
    Thread.currentThread().setContextClassLoader(pluginClassLoader);
    try {
      if (handler instanceof FredPluginHTTP tP) return tP.handleHTTPPost(request);
    } finally {
      Thread.currentThread().setContextClassLoader(oldClassLoader);
    }
    throw new NotFoundPluginHTTPException("Plugin '" + plugin + "' not found!", "/plugins");
  }

  /**
   * Requests shutdown of a loaded plugin by its thread name.
   *
   * <p>This method searches the current loaded plugin set for a matching {@link
   * PluginInfoWrapper#getThreadName()} and, if found, calls {@link
   * PluginInfoWrapper#stopPlugin(PluginManager, long, boolean)} on that wrapper.
   *
   * @param name expected thread name of the plugin to stop
   * @param maxWaitTime maximum time to wait in milliseconds for plugin shutdown
   * @param reloading whether this stop is part of a reload operation
   */
  public void killPlugin(String name, long maxWaitTime, boolean reloading) {
    for (PluginInfoWrapper pluginInfoWrapper : loadedPlugins.getLoadedPlugins()) {
      if (pluginInfoWrapper.getThreadName().equals(name)) {
        pluginInfoWrapper.stopPlugin(this, maxWaitTime, reloading);
        break;
      }
    }
  }

  /**
   * Requests shutdown of a loaded plugin by its configured filename.
   *
   * <p>This is typically used for official plugins whose filename corresponds to their short name,
   * but it also works for file-based plugins when the wrapper filename matches the supplied value.
   *
   * @param name plugin filename to match against {@link PluginInfoWrapper#getFilename()}
   * @param maxWaitTime maximum time to wait in milliseconds for plugin shutdown
   * @param reloading whether this stop is part of a reload operation
   */
  public void killPluginByFilename(String name, long maxWaitTime, boolean reloading) {
    for (PluginInfoWrapper pluginInfoWrapper : loadedPlugins.getLoadedPlugins()) {
      if (pluginInfoWrapper.getFilename().equals(name)) {
        pluginInfoWrapper.stopPlugin(this, maxWaitTime, reloading);
        break;
      }
    }
  }

  /**
   * Requests shutdown of a loaded plugin by its main class name.
   *
   * <p>If a matching plugin is found, it is stopped with {@code reloading=false}.
   *
   * @param name plugin main class name to match against {@link
   *     PluginInfoWrapper#getPluginClassName()}
   * @param maxWaitTime maximum time to wait in milliseconds for plugin shutdown
   */
  public void killPluginByClass(String name, final long maxWaitTime) {
    for (PluginInfoWrapper pluginInfoWrapper : loadedPlugins.getLoadedPlugins()) {
      if (pluginInfoWrapper.getPluginClassName().equals(name)) {
        pluginInfoWrapper.stopPlugin(this, maxWaitTime, false);
        break;
      }
    }
  }

  /**
   * Requests shutdown of a loaded plugin by plugin instance reference.
   *
   * <p>This performs reference equality against wrapper-held plugin instances.
   *
   * @param plugin plugin instance to stop, as previously returned by the plugin loader
   * @param maxWaitTime maximum time to wait in milliseconds for plugin shutdown
   */
  public void killPlugin(FredPlugin plugin, long maxWaitTime) {
    for (PluginInfoWrapper pluginInfoWrapper : loadedPlugins.getLoadedPlugins()) {
      if (pluginInfoWrapper.plug == plugin) {
        pluginInfoWrapper.stopPlugin(this, maxWaitTime, false);
        break;
      }
    }
  }

  /**
   * Returns the descriptor for an official plugin by name.
   *
   * @param name official plugin name as used by {@link OfficialPlugins}
   * @return descriptor for {@code name}, or {@code null} if no such plugin exists
   */
  public OfficialPluginDescription getOfficialPlugin(String name) {
    return officialPlugins.get(name);
  }

  /**
   * Returns all known official plugin descriptors.
   *
   * <p>The returned collection is sourced from {@link OfficialPlugins} and is intended for UI and
   * administrative tooling.
   *
   * @return collection view of all known official plugin descriptors
   */
  public Collection<OfficialPluginDescription> getOfficialPlugins() {
    return officialPlugins.getAll();
  }

  /**
   * Returns a list of the names of all available official plugins. Right now this list is hardcoded
   * but in future we could retrieve this list from emu or from freenet itself.
   *
   * @return A list of all available plugin names
   */
  public List<OfficialPluginDescription> findAvailablePlugins() {
    return new ArrayList<>(officialPlugins.getAll());
  }

  /**
   * Checks whether a name refers to a known official plugin.
   *
   * <p>This performs a case-sensitive match against official plugin descriptors. Callers typically
   * use this to decide whether to treat a plugin specification as an "official plugin name" versus
   * a file path, Freenet key, or URL.
   *
   * @param name plugin name to validate; {@code null} and blank values return {@code null}
   * @return descriptor for {@code name}, or {@code null} if {@code name} is not official
   */
  public OfficialPluginDescription isOfficialPlugin(String name) {
    if ((name == null) || name.trim().isEmpty()) return null;
    List<OfficialPluginDescription> availablePlugins = findAvailablePlugins();
    for (OfficialPluginDescription desc : availablePlugins) {
      if (desc.name.equals(name)) return desc;
    }
    return null;
  }

  /**
   * Separate lock for plugin loading. Don't use (this) as we also use that for writing the config
   * file, and because we do a lot inside the lock below; it must not be taken in any other
   * circumstance.
   */
  private final Object pluginLoadSyncObject = new Object();

  /**
   * Request client shared by all plugin updater fetches.
   *
   * <p>Plugin updates are intentionally funneled through a single {@link RequestClient} to bound
   * concurrency and to make updater traffic easier to reason about. Callers should prefer accessing
   * this via {@link #getSingleUpdaterRequestClient()} to keep the field usage localized.
   */
  public final RequestClient singleUpdaterRequestClient = new RequestClientBuilder().build();

  /**
   * Returns the expected on-disk filename for an official plugin name.
   *
   * <p>This method ensures that the plugin directory exists, and returns a {@link File} pointing to
   * {@code <pluginDir>/<pluginName>.jar}. It does not validate that the file exists.
   *
   * @param pluginName short plugin name used as a base name (without {@code .jar})
   * @return file pointing to the plugin JAR location, or {@code null} if the directory cannot be
   *     used
   */
  public File getPluginFilename(String pluginName) {
    File pluginDirectory = node.getPluginDir();
    if ((pluginDirectory.exists() && !pluginDirectory.isDirectory())
        || (!pluginDirectory.exists() && !pluginDirectory.mkdirs())) return null;
    return new File(pluginDirectory, pluginName + ".jar");
  }

  /**
   * Tries to load a plugin from the given name. If the name only contains the name of a plugin it
   * is loaded from the plugin directory, if found, otherwise it's loaded from the project server.
   * If the name contains a complete url and the short file already exists in the plugin directory
   * it's loaded from the plugin directory, otherwise it's retrieved from the remote server.
   *
   * @param pdl downloader that resolves and fetches the plugin content, if needed
   * @param name The specification of the plugin
   * @param alwaysDownload If true, always download a new version anyway. This is especially
   *     important on Windows, where we will not usually be able to delete the file after
   *     determining that it is too old.
   * @return An instanciated object of the plugin
   * @throws PluginNotFoundException If anything goes wrong.
   * @throws PluginAlreadyLoaded if the plugin is already loaded
   */
  private FredPlugin loadPlugin(
      PluginDownLoader<?> pdl, String name, PluginProgress progress, boolean alwaysDownload)
      throws PluginNotFoundException, PluginAlreadyLoaded {

    pdl.setSource(name);

    File pluginDirectory = getPluginDirectory();

    /* get plugin filename. */
    String filename = pdl.getPluginName(name);
    File pluginFile =
        getTargetFileForPluginDownload(
            pluginDirectory, filename, !pdl.isCachingProhibited() && !alwaysDownload);

    /* check if file needs to be downloaded. */
    if (LOG.isDebugEnabled())
      LOG.debug(
          "plugin file {} exists: {} downloader {} name {}",
          pluginFile.getAbsolutePath(),
          pluginFile.exists(),
          pdl,
          name);
    return loadPluginWithRetries(pdl, name, progress, pluginDirectory, pluginFile);
  }

  private FredPlugin loadPluginWithRetries(
      PluginDownLoader<?> pdl,
      String name,
      PluginProgress progress,
      File pluginDirectory,
      File pluginFile)
      throws PluginNotFoundException, PluginAlreadyLoaded {
    boolean downloadWasAttempted = false;
    int retries = 5;

    for (int attempt = 0; attempt < retries; attempt++) {
      boolean retry = false;
      if (!pluginFile.exists() || pluginFile.length() == 0) {
        downloadWasAttempted = true;
        retry =
            !downloadPluginForRetry(
                pdl, name, pluginDirectory, pluginFile, progress, attempt, retries);
      }

      if (!retry) {
        cancelRunningLoads(name, progress);
        try {
          return loadPluginFromFile(pdl, name, pluginFile);
        } catch (PluginNotFoundException e) {
          deleteFileIfExists(pluginFile);
          retry = !downloadWasAttempted && attempt < retries - 1;
          if (!retry) {
            throw new PluginNotFoundException("could not load plugin: " + e.getMessage(), e);
          }
        }
      }
    }
    return null;
  }

  private boolean downloadPluginForRetry(
      PluginDownLoader<?> pluginDownLoader,
      String name,
      File pluginDirectory,
      File pluginFile,
      PluginProgress progress,
      int attempt,
      int retries)
      throws PluginNotFoundException {
    try {
      downloadPluginFileAndVerify(pluginDownLoader, name, pluginDirectory, pluginFile, progress);
      return true;
    } catch (PluginNotFoundException e) {
      if (attempt < retries - 1) {
        LOG.info("Failed to load plugin: {}", e, e);
        return false;
      }
      throw e;
    }
  }

  private FredPlugin loadPluginFromFile(PluginDownLoader<?> pdl, String name, File pluginFile)
      throws PluginNotFoundException, PluginAlreadyLoaded {
    // we do quite a lot inside the lock, use a dedicated one
    synchronized (pluginLoadSyncObject) {
      String pluginMainClassName = verifyJarFileAndGetPluginMainClass(pluginFile);
      return loadPluginFromJarFile(
          name, pluginFile, pluginMainClassName, pdl.isOfficialPluginLoader());
    }
  }

  private void downloadPluginFileAndVerify(
      PluginDownLoader<?> pluginDownLoader,
      String name,
      File pluginDirectory,
      File pluginFile,
      PluginProgress progress)
      throws PluginNotFoundException {
    LOG.info("Downloading plugin {}", name);
    WrapperManager.signalStarting((int) MINUTES.toMillis(5));
    try {
      downloadPluginFile(pluginDownLoader, pluginDirectory, pluginFile, progress);
      verifyDigest(pluginDownLoader, pluginFile);
    } catch (IOException e) {
      throw new PluginNotFoundException("could not load plugin: " + e.getMessage(), e);
    }
  }

  private File getPluginDirectory() throws PluginNotFoundException {
    File pluginDirectory = node.getPluginDir();
    if ((pluginDirectory.exists() && !pluginDirectory.isDirectory())
        || (!pluginDirectory.exists() && !pluginDirectory.mkdirs())) {
      LOG.error("could not create plugin directory");
      throw new PluginNotFoundException("could not create plugin directory");
    }
    return pluginDirectory;
  }

  private File getTargetFileForPluginDownload(
      File pluginDirectory, String filename, boolean useCachedFile) {
    List<File> filesInPluginDirectory = getPreviousInstances(pluginDirectory, filename);
    cleanCacheDirectory(filesInPluginDirectory, useCachedFile);
    if (!filesInPluginDirectory.isEmpty() && useCachedFile) {
      return new File(pluginDirectory, filesInPluginDirectory.getFirst().getName());
    }
    return new File(pluginDirectory, filename + "-" + System.currentTimeMillis());
  }

  private void cleanCacheDirectory(List<File> filesInPluginDirectory, boolean useCachedFile) {
    if (!useCachedFile) {
      deleteCachedVersions(filesInPluginDirectory);
    } else if (!filesInPluginDirectory.isEmpty()) {
      deleteCachedVersions(filesInPluginDirectory.subList(1, filesInPluginDirectory.size()));
    }
  }

  private void deleteCachedVersions(List<File> filesInPluginDirectory) {
    for (File cachedFile : filesInPluginDirectory) {
      deleteFileIfExists(cachedFile);
    }
  }

  private void downloadPluginFile(
      PluginDownLoader<?> pluginDownLoader,
      File pluginDirectory,
      File pluginFile,
      PluginProgress pluginProgress)
      throws IOException, PluginNotFoundException {
    File tempPluginFile = File.createTempFile("plugin-", ".jar", pluginDirectory);
    tempPluginFile.deleteOnExit();

    try (InputStream pluginInputStream = pluginDownLoader.getInputStream(pluginProgress);
        OutputStream pluginOutputStream = new FileOutputStream(tempPluginFile)) {

      FileUtil.copy(pluginInputStream, pluginOutputStream, -1);
    } catch (IOException ioe1) {
      deleteFileIfExists(tempPluginFile);
      throw ioe1;
    }
    if (tempPluginFile.length() == 0) {
      throw new PluginNotFoundException("downloaded zero length file");
    }
    if (!FileUtil.moveTo(tempPluginFile, pluginFile)) {
      LOG.error("could not rename temp file to plugin file");
      throw new PluginNotFoundException("could not rename temp file to plugin file");
    }
  }

  private void verifyDigest(PluginDownLoader<?> pluginDownLoader, File pluginFile)
      throws PluginNotFoundException {
    String digest = pluginDownLoader.getSHA1sum();
    if (digest == null) {
      return;
    }
    String testsum = getFileDigest(pluginFile);
    if (!(digest.equalsIgnoreCase(testsum))) {
      LOG.error("Checksum verification failed, should be {} but was {}", digest, testsum);
      throw new PluginNotFoundException(
          "Checksum verification failed, should be " + digest + " but was " + testsum);
    }
  }

  private String verifyJarFileAndGetPluginMainClass(File pluginFile)
      throws PluginNotFoundException, PluginAlreadyLoaded {
    try (JarFile pluginJarFile = new JarFile(pluginFile)) {
      String pluginMainClassName = getPluginMainClassNameFromManifest(pluginJarFile.getManifest());
      if (isPluginLoaded(pluginMainClassName)) {
        LOG.error("Plugin already loaded: {}", pluginFile.getName());
        throw new PluginAlreadyLoaded();
      }
      return pluginMainClassName;
    } catch (IOException ioe1) {
      throw new PluginNotFoundException("error procesesing jar file", ioe1);
    }
  }

  private static String getPluginMainClassNameFromManifest(Manifest manifest)
      throws PluginNotFoundException {
    if (manifest == null) {
      throw new PluginNotFoundException("could not load manifest from plugin file");
    }
    Attributes mainAttributes = manifest.getMainAttributes();
    if (mainAttributes == null) {
      throw new PluginNotFoundException("manifest does not contain attributes");
    }
    String pluginMainClassName = mainAttributes.getValue("Plugin-Main-Class");
    if (pluginMainClassName == null) {
      throw new PluginNotFoundException("manifest does not contain a Plugin-Main-Class attribute");
    }
    return pluginMainClassName;
  }

  private FredPlugin loadPluginFromJarFile(
      String name, File pluginFile, String pluginMainClassName, boolean isOfficialPlugin)
      throws PluginNotFoundException {
    try (JarClassLoaderLease lease = new JarClassLoaderLease(pluginFile)) {
      /*
       * The plugin class loader must stay alive for the lifetime of the plugin: many plugins load
       * additional classes/resources lazily during normal operation. We keep the JarClassLoader
       * open on success, and it is closed later when the plugin is unloaded (see PluginInfoWrapper).
       */
      JarClassLoader jarClassLoader = lease.loader();

      Class<?> pluginMainClass = jarClassLoader.loadClass(pluginMainClassName);
      Object pluginInstance = pluginMainClass.getDeclaredConstructor().newInstance();
      if (!(pluginInstance instanceof FredPlugin plugin)) {
        throw new PluginNotFoundException("plugin main class is not a plugin");
      }
      if (isOfficialPlugin) {
        verifyPluginVersion(name, plugin);
      }
      if (pluginInstance instanceof FredPluginL10n l10n) {
        l10n.setLanguage(NodeL10n.getBase().getSelectedLanguage());
      }
      if (pluginInstance instanceof FredPluginBaseL10n l10n) {
        l10n.setLanguage(NodeL10n.getBase().getSelectedLanguage());
      }
      if (pluginInstance instanceof FredPluginThemed themed) {
        themed.setTheme(fproxyTheme);
      }
      lease.keepOpen();
      return plugin;
    } catch (ClassNotFoundException cnfe1) {
      throw new PluginNotFoundException(
          "could not find plugin class: \"" + cnfe1.getMessage() + "\"", cnfe1);
    } catch (NoClassDefFoundError ncdfe1) {
      throw new PluginNotFoundException("could not find class def, may a missing lib?", ncdfe1);
    } catch (ReflectiveOperationException e) {
      throw new PluginNotFoundException("could not instantiate plugin", e);
    } catch (IOException ioe1) {
      throw new PluginNotFoundException("could not load plugin", ioe1);
    }
  }

  private static final class JarClassLoaderLease implements AutoCloseable {
    private final JarClassLoader loader;
    private boolean keepOpen;

    private JarClassLoaderLease(File pluginFile) throws IOException {
      this.loader = new JarClassLoader(pluginFile);
    }

    private JarClassLoader loader() {
      return loader;
    }

    private void keepOpen() {
      keepOpen = true;
    }

    @Override
    public void close() {
      if (keepOpen) {
        return;
      }
      try {
        loader.close();
      } catch (IOException _) {
        // best-effort cleanup; load failure will be surfaced via the thrown exception
      }
    }
  }

  private void verifyPluginVersion(String name, FredPlugin plugin) throws PluginTooOldException {
    LOG.info("Loading official plugin {}", name);

    OfficialPluginDescription desc = officialPlugins.get(name);

    long minVer = desc.minimumVersion;
    long ver = -1;

    if (minVer != -1 && plugin instanceof FredPluginRealVersioned versioned) {
      ver = versioned.getRealVersion();
    }

    if (ver < minVer) {
      LOG.error(
          "Failed to load plugin {} : TOO OLD: need at least version {} but is {}",
          name,
          minVer,
          ver);
      throw new PluginTooOldException(
          "plugin too old: need at least version " + minVer + " but is " + ver);
    }
  }

  /**
   * This returns all existing instances of cached JAR files that start with the given filename
   * followed by a dash (“-”), sorted numerically by the appendix, largest (i.e. newest) first.
   *
   * @param pluginDirectory The plugin cache directory
   * @param filename The name of the JAR file
   * @return All cached instances
   */
  private List<File> getPreviousInstances(File pluginDirectory, final String filename) {
    File[] matchingFiles =
        pluginDirectory.listFiles(
            pathname -> pathname.isFile() && pathname.getName().startsWith(filename));
    if (matchingFiles == null) {
      return List.of();
    }

    List<File> cachedFiles = new ArrayList<>(Arrays.asList(matchingFiles));
    cachedFiles.sort(
        new Comparator<>() {

          @Override
          public int compare(File file1, File file2) {
            return Math.clamp(
                extractTimestamp(file2.getName()) - extractTimestamp(file1.getName()),
                Integer.MIN_VALUE,
                Integer.MAX_VALUE);
          }

          private long extractTimestamp(String filename) {
            int lastIndexOfDash = filename.lastIndexOf(".jar-");
            if (lastIndexOfDash == -1) {
              return 0;
            }
            try {
              return Long.parseLong(filename.substring(lastIndexOfDash + 5));
            } catch (NumberFormatException _) {
              return 0;
            }
          }
        });
    return cachedFiles;
  }

  private String getFileDigest(File file) throws PluginNotFoundException {
    final int BUFFERSIZE = 4096;
    MessageDigest hash = HashType.SHA1.get();
    String result;

    try (FileInputStream fis = new FileInputStream(file);
        BufferedInputStream bis = new BufferedInputStream(fis)) {

      // We compute the hash
      // http://java.sun.com/developer/TechTips/1998/tt0915.html#tip2
      int len;
      byte[] buffer = new byte[BUFFERSIZE];
      while ((len = bis.read(buffer)) > -1) {
        hash.update(buffer, 0, len);
      }
      result = HexUtil.bytesToHex(hash.digest());
    } catch (Exception e) {
      throw new PluginNotFoundException(
          "Error while computing hash of the downloaded plugin: " + e, e);
    }
    return result;
  }

  Ticker getTicker() {
    return node.getTicker();
  }

  /**
   * Tracks the progress of loading and starting a plugin.
   *
   * @author David &lsquo;Bombe&rsquo; Roden &lt;bombe@freenetproject.org&gt;
   * @version $Id$
   */
  public static class PluginProgress {

    /**
     * Represents the coarse-grained phase of a plugin load operation.
     *
     * <p>This enum is intentionally small and UI-friendly: it describes whether a plugin is still
     * being fetched/verified or whether it has transitioned into in-process startup.
     */
    public enum ProgressState {
      /** The plugin content is being fetched, cached, and verified. */
      DOWNLOADING,
      /** The plugin class loader is active and the plugin is starting. */
      STARTING
    }

    /** The starting time. */
    private final long startingTime = System.currentTimeMillis();

    /** The current state. */
    private ProgressState pluginProgress;

    /** The name by which the plugin is loaded. */
    private final String name;

    /** Total. Might be bytes, might be blocks. */
    private int total;

    /** Minimum for success */
    private int minSuccessful;

    /** Current value. Same units as total. */
    private int current;

    private boolean finalisedTotal;
    private int failed;
    private int fatallyFailed;
    private final PluginDownLoader<?> loader;

    /**
     * Creates a new progress tracker for a plugin that is loaded by the given name.
     *
     * @param name The name by which the plugin is loaded
     * @param pdl downloader used for retrieval and cancellation of the in-flight load
     */
    PluginProgress(String name, PluginDownLoader<?> pdl) {
      this.name = name;
      pluginProgress = ProgressState.DOWNLOADING;
      loader = pdl;
    }

    /**
     * Requests cancellation of the current load operation, if supported by the loader.
     *
     * <p>This method is a best-effort signal. The loader may ignore cancellation requests, and
     * callers should still rely on higher-level shutdown timeouts where applicable.
     */
    public void kill() {
      loader.tryCancel();
    }

    /**
     * Returns the number of milliseconds this plugin is already being loaded.
     *
     * @return The time this plugin is already being loaded (in milliseconds)
     */
    public long getTime() {
      return System.currentTimeMillis() - startingTime;
    }

    /**
     * Returns the name by which the plugin is loaded.
     *
     * @return The name by which the plugin is loaded
     */
    public String getName() {
      return name;
    }

    /**
     * Returns the current state of the plugin start procedure.
     *
     * @return The current state of the plugin
     */
    public ProgressState getProgress() {
      return pluginProgress;
    }

    void setStarting() {
      this.pluginProgress = ProgressState.STARTING;
    }

    /**
     * If this object is one of the constants {@link ProgressState#DOWNLOADING} or {@link
     * ProgressState#STARTING}, the name of those constants will be returned, otherwise a textual
     * representation of the plugin progress is returned.
     *
     * @return The name of a constant, or the plugin progress
     */
    @Override
    public String toString() {
      return "PluginProgress[name="
          + name
          + ",startingTime="
          + startingTime
          + ",progress="
          + pluginProgress
          + "]";
    }

    /**
     * Returns a localized HTML node describing the current progress.
     *
     * <p>The returned node is intended for embedding into existing UI tables. For downloading
     * progress it delegates to {@link QueueToadlet#createProgressCell(boolean, boolean,
     * ClientPut.COMPRESS_STATE, int, int, int, int, int, boolean, boolean)}; otherwise it returns a
     * localized label for the current {@link ProgressState}.
     *
     * @return a {@link HTMLNode} describing the current load state for UI display
     */
    public HTMLNode toLocalisedHTML() {
      if (pluginProgress == ProgressState.DOWNLOADING && total > 0) {
        return QueueToadlet.createProgressCell(
            false,
            true,
            ClientPut.COMPRESS_STATE.WORKING,
            current,
            failed,
            fatallyFailed,
            minSuccessful,
            total,
            finalisedTotal,
            false);
      } else if (pluginProgress == ProgressState.DOWNLOADING)
        return new HTMLNode(
            "td", NodeL10n.getBase().getString("PproxyToadlet.startingPluginStatus.downloading"));
      else if (pluginProgress == ProgressState.STARTING)
        return new HTMLNode(
            "td", NodeL10n.getBase().getString("PproxyToadlet.startingPluginStatus.starting"));
      else return new HTMLNode("td", toString());
    }

    /**
     * Updates download progress counters for this plugin.
     *
     * <p>The supplied values are treated as raw counters whose exact unit is defined by the loader
     * (for example bytes versus blocks). This method does not perform validation; callers should
     * provide consistent values across calls.
     *
     * @param minSuccess minimum successful units required to treat the download as complete
     * @param current currently completed units; uses the same unit as {@code total}
     * @param total total units expected for the download, in loader-defined units
     * @param failed number of units that failed but may still be retried or tolerated
     * @param fatallyFailed number of units that failed in a non-recoverable way
     * @param finalised whether {@code total} has been finalized and will not increase
     */
    public void setDownloadProgress(
        int minSuccess, int current, int total, int failed, int fatallyFailed, boolean finalised) {
      this.pluginProgress = ProgressState.DOWNLOADING;
      this.total = total;
      this.current = current;
      this.minSuccessful = minSuccess;
      this.failed = failed;
      this.fatallyFailed = fatallyFailed;
      this.finalisedTotal = finalised;
    }

    /**
     * Marks the plugin as being in the downloading phase.
     *
     * <p>This does not reset counters; it only updates the phase marker.
     */
    public void setDownloading() {
      this.pluginProgress = ProgressState.DOWNLOADING;
    }

    /**
     * Returns whether this load originated from an official plugin loader.
     *
     * @return {@code true} if the underlying loader is an official-plugin loader
     */
    public boolean isOfficialPlugin() {
      return loader.isOfficialPluginLoader();
    }

    /**
     * Returns a localized plugin name when possible.
     *
     * <p>For official plugins this resolves the localized name from the node translation bundle;
     * for non-official plugins it returns the raw load name.
     *
     * @return localized name for official plugins, otherwise the raw plugin name
     */
    public String getLocalisedPluginName() {
      String pluginName = getName();
      if (isOfficialPlugin()) {
        return getOfficialPluginLocalisedName(pluginName);
      } else return pluginName;
    }
  }

  static String getOfficialPluginLocalisedName(String pluginName) {
    return l10n("pluginName." + pluginName);
  }

  /**
   * Updates the currently selected FProxy theme and notifies themed plugins.
   *
   * <p>The theme is applied to each loaded plugin's page maker. For plugins implementing {@link
   * FredPluginThemed}, {@link FredPluginThemed#setTheme(THEME)} is invoked asynchronously on the
   * callback executor.
   *
   * @param cssName theme selection to apply; must be a valid {@link THEME} value
   */
  public void setFProxyTheme(final THEME cssName) {
    fproxyTheme = cssName;
    for (PluginInfoWrapper pluginInfoWrapper : loadedPlugins.getLoadedPlugins()) {
      pluginInfoWrapper.pr.getPageMaker().setTheme(cssName);
      if (pluginInfoWrapper.isThemedPlugin()) {
        final FredPluginThemed plug = (FredPluginThemed) pluginInfoWrapper.plug;
        executor.execute(
            () -> {
              try {
                plug.setTheme(cssName);
              } catch (Exception e) {
                LOG.error(CALLBACK_THROWABLE_MESSAGE, e);
              }
            },
            CALLBACK_TASK_NAME);
      }
    }
  }

  /**
   * Sets the language on all loaded plugins that support localization.
   *
   * <p>This is a static convenience wrapper around the current singleton instance (created via
   * {@link #create(Node, int)}). If no instance is registered, the call is ignored.
   *
   * @param lang language selection to apply to localization-capable plugins
   */
  public static void setLanguage(LANGUAGE lang) {
    if (selfinstance == null) return;
    selfinstance.setPluginLanguage(lang);
  }

  private void setPluginLanguage(final LANGUAGE lang) {
    for (PluginInfoWrapper pluginInfoWrapper : loadedPlugins.getLoadedPlugins()) {
      if (pluginInfoWrapper.isL10nPlugin()) {
        final FredPluginL10n plug = (FredPluginL10n) (pluginInfoWrapper.plug);
        executor.execute(
            () -> {
              try {
                plug.setLanguage(lang);
              } catch (Exception e) {
                LOG.error(CALLBACK_THROWABLE_MESSAGE, e);
              }
            },
            CALLBACK_TASK_NAME);
      } else if (pluginInfoWrapper.isBaseL10nPlugin()) {
        final FredPluginBaseL10n plug = (FredPluginBaseL10n) (pluginInfoWrapper.plug);
        executor.execute(
            () -> {
              try {
                plug.setLanguage(lang);
              } catch (Exception e) {
                LOG.error(CALLBACK_THROWABLE_MESSAGE, e);
              }
            },
            CALLBACK_TASK_NAME);
      }
    }
  }

  /**
   * Legacy method kept for compatibility.
   *
   * @return currently configured FProxy theme value used for plugin-rendered pages
   */
  @SuppressWarnings("unused")
  public THEME getFProxyTheme() {
    return fproxyTheme;
  }

  /**
   * Unregisters a plugin from node subsystems during unload.
   *
   * <p>This removes plugin-provided toadlets, configuration pages, and auxiliary integrations (IP
   * detector and port forwarding hooks). When not reloading, it also stops the plugin updater for
   * the plugin file name.
   *
   * @param wrapper wrapper describing the plugin capabilities and registered components
   * @param plug plugin instance being unloaded; used for type-specific unregister calls
   * @param reloading whether this unload is part of a plugin reload operation
   */
  public void unregisterPlugin(PluginInfoWrapper wrapper, FredPlugin plug, boolean reloading) {
    unregisterPluginToadlet(wrapper);
    if (wrapper.isConfigurablePlugin()) {
      core.getToadletContainer().unregister(wrapper.getConfigToadlet());
    }
    if (wrapper.isIPDetectorPlugin())
      node.getIpDetector().unregisterIPDetectorPlugin((FredPluginIPDetector) plug);
    if (wrapper.isPortForwardPlugin())
      node.getIpDetector().unregisterPortForwardPlugin((FredPluginPortForward) plug);
    if (wrapper.isBandwidthIndicator())
      node.getIpDetector().unregisterBandwidthIndicatorPlugin((FredPluginBandwidthIndicator) plug);
    if (!reloading) node.getNodeUpdater().stopPluginUpdater(wrapper.getFilename());
  }

  /**
   * Returns whether the plugin system is enabled for this node.
   *
   * <p>This value is read from configuration at construction time and does not change until the
   * node restarts.
   *
   * @return {@code true} if the plugin manager will load plugins, otherwise {@code false}
   */
  public boolean isEnabled() {
    return enabled;
  }

  private static class LoadedPlugins {

    private final Set<PluginProgress> startingPlugins = new HashSet<>();
    private final Set<PluginInfoWrapper> loadedPluginWrappers = new HashSet<>();
    private final Map<String, PluginLoadFailedUserAlert> failedPluginAlerts = new HashMap<>();

    public void addStartingPlugin(PluginProgress pluginProgress) {
      synchronized (this) {
        startingPlugins.add(pluginProgress);
      }
    }

    /**
     * @return a copy of the starting plugins. Do not modify this: modifications will get thrown
     *     away.
     */
    public Collection<PluginProgress> getStartingPlugins() {
      Set<PluginProgress> startingPluginsCopy;
      synchronized (this) {
        startingPluginsCopy = new HashSet<>(startingPlugins);
      }
      return startingPluginsCopy;
    }

    public void removeStartingPlugin(PluginProgress pluginProgress) {
      synchronized (this) {
        startingPlugins.remove(pluginProgress);
      }
    }

    /**
     * @return a copy of the loaded plugins. Do not modify this: modifications will get thrown away.
     */
    public Collection<PluginInfoWrapper> getLoadedPlugins() {
      Set<PluginInfoWrapper> loadedPluginsCopy;
      synchronized (this) {
        loadedPluginsCopy = new HashSet<>(loadedPluginWrappers);
      }
      return loadedPluginsCopy;
    }

    public void removeLoadedPlugin(PluginInfoWrapper pluginInfoWrapper) {
      synchronized (this) {
        loadedPluginWrappers.remove(pluginInfoWrapper);
      }
    }

    public boolean hasLoadedPlugin(PluginInfoWrapper pluginInfoWrapper) {
      synchronized (this) {
        return loadedPluginWrappers.contains(pluginInfoWrapper);
      }
    }

    public boolean hasLoadedPlugins() {
      synchronized (this) {
        return !loadedPluginWrappers.isEmpty();
      }
    }

    public Collection<String> getFailedPluginNames() {
      synchronized (this) {
        return failedPluginAlerts.keySet();
      }
    }

    public void addLoadedPlugin(PluginInfoWrapper pluginInfoWrapper) {
      synchronized (this) {
        loadedPluginWrappers.add(pluginInfoWrapper);
      }
    }

    public PluginLoadFailedUserAlert replaceUserAlert(
        String pluginName, PluginLoadFailedUserAlert pluginLoadFailedUserAlert) {
      synchronized (this) {
        return failedPluginAlerts.put(pluginName, pluginLoadFailedUserAlert);
      }
    }

    public boolean isFailedPlugin(String filename) {
      synchronized (this) {
        return failedPluginAlerts.containsKey(filename);
      }
    }

    public void removeFailedPlugin(String pluginName) {
      synchronized (this) {
        failedPluginAlerts.remove(pluginName);
      }
    }

    public boolean isKnownPlugin(String pluginName) {
      synchronized (this) {
        if (failedPluginAlerts.containsKey(pluginName)) {
          return true;
        }
        for (PluginProgress pluginProgress : startingPlugins) {
          if (pluginProgress.getName().equals(pluginName)) {
            return true;
          }
        }
        for (PluginInfoWrapper pluginInfoWrapper : loadedPluginWrappers) {
          if (pluginInfoWrapper.getFilename().equals(pluginName)) {
            return true;
          }
        }
      }
      return false;
    }
  }

  /**
   * Returns the shared request client used for plugin updater activity.
   *
   * <p>Callers that schedule or perform plugin update fetches should use this client rather than
   * creating their own, so that updater traffic remains bounded and consistent.
   *
   * @return the shared request client for plugin updater requests
   */
  public RequestClient getSingleUpdaterRequestClient() {
    return singleUpdaterRequestClient;
  }
}

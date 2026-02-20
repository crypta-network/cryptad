package network.crypta.clients.http;

import java.io.File;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.SecureRandom;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Iterator;
import network.crypta.client.filter.HTMLFilter;
import network.crypta.client.filter.LinkFilterExceptionProvider;
import network.crypta.clients.http.FProxyFetchInProgress.REFILTER_POLICY;
import network.crypta.clients.http.PageMaker.THEME;
import network.crypta.clients.http.bookmark.BookmarkManager;
import network.crypta.clients.http.updateableelements.PushDataManager;
import network.crypta.config.EnumerableOptionCallback;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.NodeNeedRestartException;
import network.crypta.config.Option;
import network.crypta.config.SubConfig;
import network.crypta.crypt.SSL;
import network.crypta.io.AllowedHosts;
import network.crypta.io.NetworkInterface;
import network.crypta.io.SSLNetworkInterface;
import network.crypta.keys.FreenetURI;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.PrioRunnable;
import network.crypta.node.SecurityLevels.NETWORK_THREAT_LEVEL;
import network.crypta.node.SecurityLevels.PHYSICAL_THREAT_LEVEL;
import network.crypta.node.useralerts.UserAlertManager;
import network.crypta.pluginmanager.FredPluginL10n;
import network.crypta.support.HTMLNode;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.Ticker;
import network.crypta.support.api.BooleanCallback;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.IntCallback;
import network.crypta.support.api.LongCallback;
import network.crypta.support.api.StringCallback;
import network.crypta.support.io.ArrayBucketFactory;
import network.crypta.support.io.NativeThread;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.tanukisoftware.wrapper.WrapperManager;

/**
 * The Toadlet (HTTP) Server.
 *
 * <p>SimpleToadletServer owns the embedded HTTP listener that exposes FProxy and assorted control
 * endpoints to browsers and local tools. It wires configuration callbacks, constructs the network
 * interface, and manages registration of individual {@link Toadlet} handlers. Typical lifecycle:
 * construct the server with the node configuration, call {@link #setCore(NodeClientCore)} once the
 * node core becomes available, start the listener, and invoke {@link #finishStart()} after startup
 * housekeeping completes. The server keeps track of theme selection, panic button visibility,
 * gateway mode, and access controls. It also delegates bookmark management, push managers, and
 * theme overrides to the core and supporting helper classes.
 *
 * <p>Concurrency: the network listener and request handling threads read shared state such as the
 * {@link #core} reference, panic flags, and theme settings. The core reference is published through
 * a volatile write-in {@link #setCore(NodeClientCore)} so request threads see it once set.
 * Mutability: most configuration is thread-safe via synchronized blocks or volatile fields; URL
 * registration is guarded by the server monitor. Extended configuration callbacks are invoked on
 * the configuration thread; request handlers run on the executor.
 *
 * <ul>
 *   <li>Responsibilities: bind sockets, dispatch toadlets, surface configuration, and relay alerts.
 *   <li>Notable behaviors: preserves startup toadlet until replaced; honors gateway/public mode;
 *       mirrors theme changes to plugins; emits panic button state based on physical threat level.
 * </ul>
 *
 * @see Toadlet
 * @see NodeClientCore
 * @see network.crypta.clients.http.FProxyToadlet
 */
public final class SimpleToadletServer
    implements ToadletContainer, Runnable, LinkFilterExceptionProvider {
  private static final Logger LOG = LoggerFactory.getLogger(SimpleToadletServer.class);

  /** List of urlPrefix / Toadlet */
  private final ArrayDeque<ToadletElement> toadlets;

  private static class ToadletElement {
    public ToadletElement(Toadlet t2, String urlPrefix, String menu, String name) {
      t = t2;
      prefix = urlPrefix;
      this.menu = menu;
      this.name = name;
    }

    Toadlet t;
    String prefix;
    String menu;
    String name;
  }

  private static final String FILENAME_KEY = "filename";
  private static final String CSS_OVERRIDE_KEY = "CSSOverride";
  private static final String PASSTHROUGH_MAX_SIZE_PROGRESS_KEY = "passthroughMaxSizeProgress";

  // Socket / Binding
  private final int port;
  private String bindTo;
  private final String allowedHosts;
  private NetworkInterface networkInterface;
  private boolean ssl = false;

  /** Default TCP port used for the public FProxy listener when no override is supplied. */
  public static final int DEFAULT_FPROXY_PORT = 8888;

  // ACL
  private final AllowedHosts allowedFullAccess;
  private boolean publicGatewayMode;
  private final boolean wasPublicGatewayMode;

  // Theme
  private THEME cssTheme;
  private File cssOverride;
  private volatile boolean sendAllThemes;
  private boolean advancedModeEnabled;
  private final PageMaker pageMaker;
  private boolean fetchKeyBoxAboveBookmarks;

  // Control
  private Thread myThread;
  private final PriorityAwareExecutor executor;
  private final SecureRandom random;
  private BucketFactory bf;

  @SuppressWarnings("java:S3077")
  private volatile NodeClientCore core;

  // HTTP Option
  private boolean doRobots;
  private boolean enablePersistentConnections;
  private boolean enableInlinePrefetch;
  private boolean enableActivelinks;
  private boolean enableExtendedMethodHandling;
  private boolean enableCachingForChkAndSskKeys;

  // Something does not really belong to here
  static volatile boolean isPanicButtonToBeShown; // move to QueueToadlet?
  static volatile boolean noConfirmPanic;

  private static void setPanicButtonVisibility(boolean value) {
    isPanicButtonToBeShown = value;
  }

  private static void setNoConfirmPanic(boolean value) {
    noConfirmPanic = value;
  }

  private BookmarkManager bookmarkManager; // move to WelcomeToadlet / BookmarkEditorToadlet?
  private volatile boolean fProxyJavascriptEnabled; // ugh?
  private volatile boolean fProxyWebPushingEnabled; // ugh?
  private volatile boolean fproxyHasCompletedWizard; // hmmm..
  private volatile boolean disableProgressPage;
  private volatile int maxFproxyConnections;

  private int fproxyConnections;

  private boolean finishedStartup;

  private StartupToadlet startupToadlet;

  /** The PushDataManager handles all the pushing tasks. */
  private PushDataManager pushDataManager;

  /** The IntervalPusherManager handles interval pushing */
  private IntervalPusherManager intervalPushManager;

  // Legacy logMINOR removed; use LOG.isDebugEnabled() directly.

  // Config Callbacks
  private class FProxySSLCallback extends BooleanCallback {
    @Override
    public Boolean get() {
      return ssl;
    }

    @Override
    public void set(Boolean val) throws InvalidConfigValueException {
      if (get().equals(val)) return;
      if (!SSL.available()) {
        throw new InvalidConfigValueException("Enable SSL support before use ssl with Fproxy");
      }
      ssl = val;
      throw new InvalidConfigValueException("Cannot change SSL on the fly, please restart freenet");
    }

    @Override
    public boolean isReadOnly() {
      return true;
    }
  }

  private static class FProxyPassthruMaxSizeNoProgress extends LongCallback {
    @Override
    public Long get() {
      return FProxyToadlet.getMaxLengthNoProgress();
    }

    @Override
    public void set(Long val) {
      if (get().equals(val)) return;
      FProxyToadlet.setMaxLengthNoProgress(val);
    }
  }

  private static class FProxyPassthruMaxSizeProgress extends LongCallback {
    @Override
    public Long get() {
      return FProxyToadlet.getMaxLengthWithProgress();
    }

    @Override
    public void set(Long val) {
      if (get().equals(val)) return;
      FProxyToadlet.setMaxLengthWithProgress(val);
    }
  }

  private class FProxyPortCallback extends IntCallback {
    @Override
    public Integer get() {
      return port;
    }

    @Override
    public void set(Integer newPort) throws NodeNeedRestartException {
      if (port != newPort) {
        throw new NodeNeedRestartException("Port cannot change on the fly");
      }
    }
  }

  private class FProxyBindtoCallback extends StringCallback {
    @Override
    public String get() {
      return bindTo;
    }

    @Override
    public void set(String bindTo) throws InvalidConfigValueException {
      String oldValue = get();
      if (!bindTo.equals(oldValue)) {
        String[] failedAddresses = networkInterface.setBindTo(bindTo, false);
        if (failedAddresses == null) {
          SimpleToadletServer.this.bindTo = bindTo;
        } else {
          // This is an advanced option for reasons of reducing clutter,
          // but it is expected to be used by regular users, not devs.
          // So we translate the error messages.
          networkInterface.setBindTo(oldValue, false);
          throw new InvalidConfigValueException(
              l10n("couldNotChangeBindTo", "failedInterfaces", Arrays.toString(failedAddresses)));
        }
      }
    }
  }

  private class FProxyAllowedHostsCallback extends StringCallback {
    @Override
    public String get() {
      return networkInterface.getAllowedHosts();
    }

    @Override
    public void set(String allowedHosts) throws InvalidConfigValueException {
      if (!allowedHosts.equals(get())) {
        try {
          networkInterface.setAllowedHosts(allowedHosts);
        } catch (IllegalArgumentException e) {
          throw new InvalidConfigValueException(e);
        }
      }
    }
  }

  private class FProxyCSSNameCallback extends StringCallback implements EnumerableOptionCallback {
    @Override
    public String get() {
      return cssTheme.code;
    }

    @Override
    public void set(String cssName) throws InvalidConfigValueException {
      if ((cssName.indexOf(':') != -1) || (cssName.indexOf('/') != -1))
        throw new InvalidConfigValueException(l10n("illegalCSSName"));
      cssTheme = THEME.themeFromName(cssName);
      pageMaker.setTheme(cssTheme);
      NodeClientCore coreRef = SimpleToadletServer.this.core;
      if (coreRef.getNode().services().pluginManager() != null)
        coreRef.getNode().services().pluginManager().setFProxyTheme(cssTheme);
      fetchKeyBoxAboveBookmarks = cssTheme.fetchKeyBoxAboveBookmarks;
    }

    @Override
    public String[] getPossibleValues() {
      return THEME.possibleValues();
    }
  }

  private class FProxyCSSOverrideCallback extends StringCallback {
    @Override
    public String get() {
      return (cssOverride == null ? "" : cssOverride.toString());
    }

    @Override
    public void set(String val) throws InvalidConfigValueException {
      NodeClientCore coreRef = SimpleToadletServer.this.core;
      if (coreRef == null) return;
      if (val.equals(get()) || val.isEmpty()) cssOverride = null;
      else {
        File tmp = new File(val.trim());
        if (!coreRef.allowUploadFrom(tmp))
          throw new InvalidConfigValueException(
              l10n("cssOverrideNotInUploads", FILENAME_KEY, tmp.toString()));
        else if (!tmp.canRead() || !tmp.isFile())
          throw new InvalidConfigValueException(
              l10n("cssOverrideCantRead", FILENAME_KEY, tmp.toString()));
        File parent = tmp.getParentFile();
        // Basic sanity check.
        // Prevents user from specifying root dir.
        // They can still shoot themselves in the foot, but only when developing themes/using custom
        // themes.
        // Because of the ".." check above, any malicious thing cannot break out of the dir anyway.
        if (parent.getParentFile() == null)
          throw new InvalidConfigValueException(
              l10n("cssOverrideCantUseRootDir", FILENAME_KEY, parent.toString()));
        cssOverride = tmp;
      }
      if (cssOverride == null) pageMaker.setOverride(null);
      else {
        pageMaker.setOverride(StaticToadlet.OVERRIDE_URL + cssOverride.getName());
      }
    }
  }

  private class FProxyEnabledCallback extends BooleanCallback {
    @Override
    public Boolean get() {
      synchronized (SimpleToadletServer.this) {
        return myThread != null;
      }
    }

    @Override
    public void set(Boolean val) {
      if (get().equals(val)) return;
      boolean startServer = Boolean.TRUE.equals(val);
      Thread threadToStart;
      synchronized (SimpleToadletServer.this) {
        if (startServer) {
          // Start it
          threadToStart = new Thread(SimpleToadletServer.this, "SimpleToadletServer");
          myThread = threadToStart;
        } else {
          myThread.interrupt();
          myThread = null;
          SimpleToadletServer.this.notifyAll();
          return;
        }
      }
      createFproxy();
      threadToStart.setDaemon(true);
      threadToStart.start();
    }
  }

  private static class FProxyAdvancedModeEnabledCallback extends BooleanCallback {
    private final SimpleToadletServer ts;

    FProxyAdvancedModeEnabledCallback(SimpleToadletServer ts) {
      this.ts = ts;
    }

    @Override
    public Boolean get() {
      return ts.isAdvancedModeEnabled();
    }

    @Override
    public void set(Boolean val) {
      ts.setAdvancedMode(val);
    }
  }

  private static class FProxyJavascriptEnabledCallback extends BooleanCallback {

    private final SimpleToadletServer ts;

    FProxyJavascriptEnabledCallback(SimpleToadletServer ts) {
      this.ts = ts;
    }

    @Override
    public Boolean get() {
      return ts.isFProxyJavascriptEnabled();
    }

    @Override
    public void set(Boolean val) {
      if (get().equals(val)) return;
      ts.enableFProxyJavascript(val);
    }
  }

  private static class FProxyWebPushingEnabledCallback extends BooleanCallback {

    private final SimpleToadletServer ts;

    FProxyWebPushingEnabledCallback(SimpleToadletServer ts) {
      this.ts = ts;
    }

    @Override
    public Boolean get() {
      return ts.isFProxyWebPushingEnabled();
    }

    @Override
    public void set(Boolean val) {
      if (get().equals(val)) return;
      ts.enableFProxyWebPushing(val);
    }
  }

  private boolean haveCalledFProxy = false;

  // Consider factoring this out to a shared helper class if it grows further.

  private class ReFilterCallback extends StringCallback implements EnumerableOptionCallback {

    @Override
    public String[] getPossibleValues() {
      REFILTER_POLICY[] possible = REFILTER_POLICY.values();
      String[] ret = new String[possible.length];
      for (int i = 0; i < possible.length; i++) ret[i] = possible[i].name();
      return ret;
    }

    @Override
    public String get() {
      return refilterPolicy.name();
    }

    @Override
    public void set(String val) {
      refilterPolicy = REFILTER_POLICY.valueOf(val);
    }
  }

  /**
   * Builds the FProxy runtime structures once the core is ready.
   *
   * <p>Call this after {@link #setCore(NodeClientCore)} and before accepting requests to install
   * bookmark handling, interval push scheduling, and UI registration against the active node. This
   * method is idempotent; later calls are ignored after the first successful invocation. It
   * captures the current {@link #core} and {@link Node} references, wires the push managers to the
   * shared {@link Ticker}, and delegates to {@link FProxyRegistrar} to create request handlers and
   * configuration entries.
   */
  public void createFproxy() {
    NodeClientCore coreRef = this.core;
    Node node = coreRef.getNode();
    synchronized (this) {
      if (haveCalledFProxy) return;
      haveCalledFProxy = true;
    }

    pushDataManager = new PushDataManager(getTicker());
    intervalPushManager = new IntervalPusherManager(getTicker(), pushDataManager);
    bookmarkManager = new BookmarkManager(coreRef, publicGatewayMode());
    FProxyRegistrar.maybeCreateFProxyEtc(coreRef, node, node.getConfig(), this);
  }

  /**
   * Publishes the initialized node core to request handlers.
   *
   * <p>The core reference is written with volatile semantics so that listener threads see it after
   * startup. Call this exactly once, immediately after the node finishes constructing its {@link
   * NodeClientCore}, and before invoking {@link #createFproxy()} or {@link #start()}. Passing
   * {@code null} is not supported and leaves the server unable to service requests.
   *
   * @param core fully constructed {@link NodeClientCore}; must not be {@code null}.
   */
  public void setCore(NodeClientCore core) {
    this.core = core;
  }

  /**
   * Creates a SimpleToadletServer bound to the given FProxy configuration.
   *
   * <p>The constructor performs lightweight configuration registration, initializes option
   * callbacks, and defers expensive wiring (core assignment, network listener startup) to later
   * calls. It seeds random sources, sets the initial access control list, and records whether the
   * server should start enabled. The {@link #core} is left {@code null}; callers must invoke {@link
   * #setCore(NodeClientCore)} before servicing requests.
   *
   * @param fproxyConfig configuration subsection containing fproxy.* keys that drive listener
   *     options, theme settings, limits, and ACLs; must be non-null.
   * @param bucketFactory factory used to create buckets for request payload handling; callers may
   *     later replace it via {@link #setBucketFactory(BucketFactory)}.
   * @param executor executor that runs HTTP worker threads with priority awareness; ownership stays
   *     with the caller.
   * @param node parent {@link Node} providing global services such as logging and plugin access.
   * @throws InvalidConfigValueException if any configuration entry is invalid or fails validation
   *     during registration.
   */
  public SimpleToadletServer(
      SubConfig fproxyConfig,
      BucketFactory bucketFactory,
      PriorityAwareExecutor executor,
      Node node)
      throws InvalidConfigValueException {

    this.executor = executor;
    this.core = null; // setCore() will be called later.
    this.random = new SecureRandom();

    int configItemOrder = registerInitialOptions(fproxyConfig);

    boolean enabled = fproxyConfig.getBoolean("enabled");

    configItemOrder = registerPanicAndGatewayOptions(fproxyConfig, configItemOrder);
    publicGatewayMode = fproxyConfig.getBoolean("publicGatewayMode");
    wasPublicGatewayMode = publicGatewayMode;

    // This is OFF BY DEFAULT because, for example, firefox has a limit of 2 persistent
    // connections per server, but 8 non-persistent connections per server. We need 8 conns
    // more than we need the efficiency gain of reusing connections - especially on the first
    // installation.

    configItemOrder = registerConnectionOptions(fproxyConfig, configItemOrder);
    allowedFullAccess = new AllowedHosts(fproxyConfig.getString("allowedHostsFullAccess"));
    configItemOrder = registerAccessOptions(fproxyConfig, configItemOrder);

    configItemOrder = registerFilterAndLimitOptions(fproxyConfig, configItemOrder);

    this.bf = bucketFactory;
    port = fproxyConfig.getInt("port");
    bindTo = fproxyConfig.getString("bindTo");
    String cssName = fproxyConfig.getString("css");
    if ((cssName.indexOf(':') != -1) || (cssName.indexOf('/') != -1))
      throw new InvalidConfigValueException("CSS name must not contain slashes or colons!");
    cssTheme = THEME.themeFromName(cssName);
    pageMaker = new PageMaker(cssTheme, node);

    if (!fproxyConfig.getOption(CSS_OVERRIDE_KEY).isDefault()) {
      cssOverride = new File(fproxyConfig.getString(CSS_OVERRIDE_KEY));
      pageMaker.setOverride(StaticToadlet.OVERRIDE_URL + cssOverride.getName());
    } else {
      cssOverride = null;
      pageMaker.setOverride(null);
    }

    fproxyConfig.register(
        "fetchKeyBoxAboveBookmarks",
        cssTheme.fetchKeyBoxAboveBookmarks,
        new Option.Meta(
            configItemOrder,
            false,
            false,
            "SimpleToadletServer.fetchKeyBoxAboveBookmarks",
            "SimpleToadletServer.fetchKeyBoxAboveBookmarksLong"),
        new BooleanCallback() {
          @Override
          public Boolean get() {
            return fetchKeyBoxAboveBookmarks;
          }

          @Override
          public void set(Boolean val) {
            if (get().equals(val)) return;
            fetchKeyBoxAboveBookmarks = val;
          }
        });
    fetchKeyBoxAboveBookmarks = fproxyConfig.getBoolean("fetchKeyBoxAboveBookmarks");

    this.advancedModeEnabled = fproxyConfig.getBoolean("advancedModeEnabled");
    toadlets = new ArrayDeque<>();

    if (SSL.available()) {
      ssl = fproxyConfig.getBoolean("ssl");
    }

    this.allowedHosts = fproxyConfig.getString("allowedHosts");

    if (!enabled) {
      LOG.info("Not starting FProxy as it's disabled");
    } else {
      maybeGetNetworkInterface();
      myThread = new Thread(this, "SimpleToadletServer");
      myThread.setDaemon(true);
    }

    // Register static toadlet and startup toadlet

    StaticToadlet statictoadlet = new StaticToadlet();
    register(statictoadlet, ToadletRegistration.basic(null, "/static/", false, false));

    // "Freenet is starting up..." page, to be removed at #removeStartupToadlet()
    startupToadlet = new StartupToadlet(statictoadlet);
    register(startupToadlet, ToadletRegistration.basic(null, "/", false, false));
  }

  private int registerInitialOptions(SubConfig fproxyConfig) {
    int configItemOrder = 0;
    fproxyConfig.register(
        "enabled",
        true,
        new Option.Meta(
            configItemOrder++,
            true,
            true,
            "SimpleToadletServer.enabled",
            "SimpleToadletServer.enabledLong"),
        new FProxyEnabledCallback());

    fproxyConfig.register(
        "ssl",
        false,
        new Option.Meta(
            configItemOrder++,
            true,
            true,
            "SimpleToadletServer.ssl",
            "SimpleToadletServer.sslLong"),
        new FProxySSLCallback());
    fproxyConfig.register(
        "port",
        DEFAULT_FPROXY_PORT,
        new Option.Meta(
            configItemOrder++,
            true,
            true,
            "SimpleToadletServer.port",
            "SimpleToadletServer.portLong"),
        new FProxyPortCallback(),
        false);
    fproxyConfig.register(
        "bindTo",
        NetworkInterface.DEFAULT_BIND_TO,
        new Option.Meta(
            configItemOrder++,
            true,
            true,
            "SimpleToadletServer.bindTo",
            "SimpleToadletServer.bindToLong"),
        new FProxyBindtoCallback());
    fproxyConfig.register(
        "css",
        PageMaker.THEME.getDefault().code,
        new Option.Meta(
            configItemOrder++,
            false,
            false,
            "SimpleToadletServer.cssName",
            "SimpleToadletServer.cssNameLong"),
        new FProxyCSSNameCallback());
    fproxyConfig.register(
        CSS_OVERRIDE_KEY,
        "",
        new Option.Meta(
            configItemOrder++,
            true,
            false,
            "SimpleToadletServer.cssOverride",
            "SimpleToadletServer.cssOverrideLong"),
        new FProxyCSSOverrideCallback());
    fproxyConfig.register(
        "sendAllThemes",
        false,
        new Option.Meta(
            configItemOrder++,
            true,
            false,
            "SimpleToadletServer.sendAllThemes",
            "SimpleToadletServer.sendAllThemesLong"),
        new BooleanCallback() {

          @Override
          public Boolean get() {
            return sendAllThemes;
          }

          @Override
          public void set(Boolean val) {
            sendAllThemes = val;
          }
        });
    sendAllThemes = fproxyConfig.getBoolean("sendAllThemes");

    fproxyConfig.register(
        "advancedModeEnabled",
        false,
        new Option.Meta(
            configItemOrder++,
            true,
            false,
            "SimpleToadletServer.advancedMode",
            "SimpleToadletServer.advancedModeLong"),
        new FProxyAdvancedModeEnabledCallback(this));

    fproxyConfig.register(
        "enableExtendedMethodHandling",
        false,
        new Option.Meta(
            configItemOrder++,
            true,
            false,
            "SimpleToadletServer.enableExtendedMethodHandling",
            "SimpleToadletServer.enableExtendedMethodHandlingLong"),
        new BooleanCallback() {
          @Override
          public Boolean get() {
            return enableExtendedMethodHandling;
          }

          @Override
          public void set(Boolean val) {
            if (get().equals(val)) return;
            enableExtendedMethodHandling = val;
          }
        });
    fproxyConfig.register(
        "javascriptEnabled",
        true,
        new Option.Meta(
            configItemOrder++,
            true,
            false,
            "SimpleToadletServer.enableJS",
            "SimpleToadletServer.enableJSLong"),
        new FProxyJavascriptEnabledCallback(this));
    fproxyConfig.register(
        "webPushingEnabled",
        false,
        new Option.Meta(
            configItemOrder++,
            true,
            false,
            "SimpleToadletServer.enableWP",
            "SimpleToadletServer.enableWPLong"),
        new FProxyWebPushingEnabledCallback(this));
    fproxyConfig.register(
        "hasCompletedWizard",
        false,
        new Option.Meta(
            configItemOrder++,
            true,
            false,
            "SimpleToadletServer.hasCompletedWizard",
            "SimpleToadletServer.hasCompletedWizardLong"),
        new BooleanCallback() {
          @Override
          public Boolean get() {
            return fproxyHasCompletedWizard;
          }

          @Override
          public void set(Boolean val) {
            if (get().equals(val)) return;
            fproxyHasCompletedWizard = val;
          }
        });
    fproxyConfig.register(
        "disableProgressPage",
        false,
        new Option.Meta(
            configItemOrder++,
            true,
            false,
            "SimpleToadletServer.disableProgressPage",
            "SimpleToadletServer.disableProgressPageLong"),
        new BooleanCallback() {

          @Override
          public Boolean get() {
            return disableProgressPage;
          }

          @Override
          public void set(Boolean val) {
            if (get().equals(val)) return;
            disableProgressPage = val;
          }
        });
    fproxyHasCompletedWizard = fproxyConfig.getBoolean("hasCompletedWizard");
    fProxyJavascriptEnabled = fproxyConfig.getBoolean("javascriptEnabled");
    fProxyWebPushingEnabled = fproxyConfig.getBoolean("webPushingEnabled");
    disableProgressPage = fproxyConfig.getBoolean("disableProgressPage");
    enableExtendedMethodHandling = fproxyConfig.getBoolean("enableExtendedMethodHandling");
    return configItemOrder;
  }

  private int registerPanicAndGatewayOptions(SubConfig fproxyConfig, int configItemOrder) {
    fproxyConfig.register(
        "showPanicButton",
        false,
        new Option.Meta(
            configItemOrder++,
            true,
            true,
            "SimpleToadletServer.panicButton",
            "SimpleToadletServer.panicButtonLong"),
        new BooleanCallback() {
          @Override
          public Boolean get() {
            return SimpleToadletServer.isPanicButtonToBeShown;
          }

          @Override
          public void set(Boolean value) {
            boolean newValue = Boolean.TRUE.equals(value);
            if (newValue == SimpleToadletServer.isPanicButtonToBeShown) {
              return;
            }
            setPanicButtonVisibility(newValue);
          }
        });

    fproxyConfig.register(
        "noConfirmPanic",
        false,
        new Option.Meta(
            configItemOrder++,
            true,
            true,
            "SimpleToadletServer.noConfirmPanic",
            "SimpleToadletServer.noConfirmPanicLong"),
        new BooleanCallback() {

          @Override
          public Boolean get() {
            return SimpleToadletServer.noConfirmPanic;
          }

          @Override
          public void set(Boolean val) {
            boolean newValue = Boolean.TRUE.equals(val);
            if (newValue == SimpleToadletServer.noConfirmPanic) {
              return;
            }
            setNoConfirmPanic(newValue);
          }
        });

    fproxyConfig.register(
        "publicGatewayMode",
        false,
        new Option.Meta(
            configItemOrder++,
            true,
            true,
            "SimpleToadletServer.publicGatewayMode",
            "SimpleToadletServer.publicGatewayModeLong"),
        new BooleanCallback() {

          @Override
          public Boolean get() {
            return publicGatewayMode;
          }

          @Override
          public void set(Boolean val) throws NodeNeedRestartException {
            boolean newValue = Boolean.TRUE.equals(val);
            if (publicGatewayMode == newValue) return;
            publicGatewayMode = newValue;
            throw new NodeNeedRestartException(l10n("publicGatewayModeNeedsRestart"));
          }
        });
    setPanicButtonVisibility(fproxyConfig.getBoolean("showPanicButton"));
    setNoConfirmPanic(fproxyConfig.getBoolean("noConfirmPanic"));
    return configItemOrder;
  }

  private int registerConnectionOptions(SubConfig fproxyConfig, int configItemOrder) {
    fproxyConfig.register(
        "enablePersistentConnections",
        false,
        new Option.Meta(
            configItemOrder++,
            true,
            false,
            "SimpleToadletServer.enablePersistentConnections",
            "SimpleToadletServer.enablePersistentConnectionsLong"),
        new BooleanCallback() {

          @Override
          public Boolean get() {
            synchronized (SimpleToadletServer.this) {
              return enablePersistentConnections;
            }
          }

          @Override
          public void set(Boolean val) {
            synchronized (SimpleToadletServer.this) {
              enablePersistentConnections = val;
            }
          }
        });
    enablePersistentConnections = fproxyConfig.getBoolean("enablePersistentConnections");

    fproxyConfig.register(
        "enableInlinePrefetch",
        false,
        new Option.Meta(
            configItemOrder++,
            true,
            false,
            "SimpleToadletServer.enableInlinePrefetch",
            "SimpleToadletServer.enableInlinePrefetchLong"),
        new BooleanCallback() {

          @Override
          public Boolean get() {
            synchronized (SimpleToadletServer.this) {
              return enableInlinePrefetch;
            }
          }

          @Override
          public void set(Boolean val) {
            synchronized (SimpleToadletServer.this) {
              enableInlinePrefetch = val;
            }
          }
        });
    enableInlinePrefetch = fproxyConfig.getBoolean("enableInlinePrefetch");

    fproxyConfig.register(
        "enableActivelinks",
        false,
        new Option.Meta(
            configItemOrder++,
            false,
            false,
            "SimpleToadletServer.enableActivelinks",
            "SimpleToadletServer.enableActivelinksLong"),
        new BooleanCallback() {

          @Override
          public Boolean get() {
            return enableActivelinks;
          }

          @Override
          public void set(Boolean val) {
            enableActivelinks = val;
          }
        });
    enableActivelinks = fproxyConfig.getBoolean("enableActivelinks");

    fproxyConfig.register(
        "passthroughMaxSize",
        FProxyToadlet.getMaxLengthNoProgress(),
        new Option.Meta(
            configItemOrder++,
            true,
            false,
            "SimpleToadletServer.passthroughMaxSize",
            "SimpleToadletServer.passthroughMaxSizeLong"),
        new FProxyPassthruMaxSizeNoProgress(),
        true);
    FProxyToadlet.setMaxLengthNoProgress(fproxyConfig.getLong("passthroughMaxSize"));
    fproxyConfig.register(
        PASSTHROUGH_MAX_SIZE_PROGRESS_KEY,
        FProxyToadlet.getMaxLengthWithProgress(),
        new Option.Meta(
            configItemOrder++,
            true,
            false,
            "SimpleToadletServer.passthroughMaxSizeProgress",
            "SimpleToadletServer.passthroughMaxSizeProgressLong"),
        new FProxyPassthruMaxSizeProgress(),
        true);
    FProxyToadlet.setMaxLengthWithProgress(fproxyConfig.getLong(PASSTHROUGH_MAX_SIZE_PROGRESS_KEY));
    LOG.info(
        "Set fproxy max length to {} and max length with progress to {} = {}",
        FProxyToadlet.getMaxLengthNoProgress(),
        FProxyToadlet.getMaxLengthWithProgress(),
        fproxyConfig.getLong(PASSTHROUGH_MAX_SIZE_PROGRESS_KEY));

    fproxyConfig.register(
        "enableCachingForChkAndSskKeys",
        false,
        new Option.Meta(
            configItemOrder++,
            true,
            true,
            "SimpleToadletServer.enableCachingForChkAndSskKeys",
            "SimpleToadletServer.enableCachingForChkAndSskKeysLong"),
        new BooleanCallback() {
          @Override
          public Boolean get() {
            return enableCachingForChkAndSskKeys;
          }

          @Override
          public void set(Boolean value) {
            enableCachingForChkAndSskKeys = value;
          }
        });
    enableCachingForChkAndSskKeys = fproxyConfig.getBoolean("enableCachingForChkAndSskKeys");
    return configItemOrder;
  }

  private int registerAccessOptions(SubConfig fproxyConfig, int configItemOrder) {
    fproxyConfig.register(
        "allowedHosts",
        "127.0.0.1,0:0:0:0:0:0:0:1",
        new Option.Meta(
            configItemOrder++,
            true,
            true,
            "SimpleToadletServer.allowedHosts",
            "SimpleToadletServer.allowedHostsLong"),
        new FProxyAllowedHostsCallback());
    fproxyConfig.register(
        "allowedHostsFullAccess",
        "127.0.0.1,0:0:0:0:0:0:0:1",
        new Option.Meta(
            configItemOrder++,
            true,
            true,
            "SimpleToadletServer.allowedFullAccess",
            "SimpleToadletServer.allowedFullAccessLong"),
        new StringCallback() {

          @Override
          public String get() {
            return allowedFullAccess.getAllowedHosts();
          }

          @Override
          public void set(String val) throws InvalidConfigValueException {
            try {
              allowedFullAccess.setAllowedHosts(val);
            } catch (IllegalArgumentException e) {
              throw new InvalidConfigValueException(e);
            }
          }
        });
    fproxyConfig.register(
        "doRobots",
        false,
        new Option.Meta(
            configItemOrder++,
            true,
            false,
            "SimpleToadletServer.doRobots",
            "SimpleToadletServer.doRobotsLong"),
        new BooleanCallback() {
          @Override
          public Boolean get() {
            return doRobots;
          }

          @Override
          public void set(Boolean val) {
            doRobots = val;
          }
        });
    doRobots = fproxyConfig.getBoolean("doRobots");
    return configItemOrder;
  }

  private int registerFilterAndLimitOptions(SubConfig fproxyConfig, int configItemOrder) {
    fproxyConfig.register(
        "maxFproxyConnections",
        100,
        new Option.Meta(
            configItemOrder++,
            true,
            false,
            "SimpleToadletServer.maxFproxyConnections",
            "SimpleToadletServer.maxFproxyConnectionsLong"),
        new IntCallback() {

          @Override
          public Integer get() {
            synchronized (SimpleToadletServer.this) {
              return maxFproxyConnections;
            }
          }

          @Override
          public void set(Integer val) {
            synchronized (SimpleToadletServer.this) {
              maxFproxyConnections = val;
              SimpleToadletServer.this.notifyAll();
            }
          }
        },
        false);
    maxFproxyConnections = fproxyConfig.getInt("maxFproxyConnections");

    fproxyConfig.register(
        "metaRefreshSamePageInterval",
        1,
        new Option.Meta(
            configItemOrder++,
            true,
            false,
            "SimpleToadletServer.metaRefreshSamePageInterval",
            "SimpleToadletServer.metaRefreshSamePageIntervalLong"),
        new IntCallback() {

          @Override
          public Integer get() {
            return HTMLFilter.getMetaRefreshSamePageMinInterval();
          }

          @Override
          public void set(Integer val) throws InvalidConfigValueException {
            if (val < -1)
              throw new InvalidConfigValueException(
                  "-1 = disabled, 0+ = set a minimum interval"); // localization pending
            HTMLFilter.setMetaRefreshSamePageMinInterval(val);
          }
        },
        false);
    HTMLFilter.setMetaRefreshSamePageMinInterval(
        Math.max(-1, fproxyConfig.getInt("metaRefreshSamePageInterval")));

    fproxyConfig.register(
        "metaRefreshRedirectInterval",
        1,
        new Option.Meta(
            configItemOrder++,
            true,
            false,
            "SimpleToadletServer.metaRefreshRedirectInterval",
            "SimpleToadletServer.metaRefreshRedirectIntervalLong"),
        new IntCallback() {

          @Override
          public Integer get() {
            return HTMLFilter.getMetaRefreshRedirectMinInterval();
          }

          @Override
          public void set(Integer val) throws InvalidConfigValueException {
            if (val < -1)
              throw new InvalidConfigValueException(
                  "-1 = disabled, 0+ = set a minimum interval"); // localization pending
            HTMLFilter.setMetaRefreshRedirectMinInterval(val);
          }
        },
        false);
    HTMLFilter.setMetaRefreshRedirectMinInterval(
        Math.max(-1, fproxyConfig.getInt("metaRefreshRedirectInterval")));

    fproxyConfig.register(
        "embedM3uPlayerInFreesites",
        true,
        new Option.Meta(
            configItemOrder++,
            true,
            false,
            "SimpleToadletServer.embedM3uPlayerInFreesites",
            "SimpleToadletServer.embedM3uPlayerInFreesitesLong"),
        new BooleanCallback() {

          @Override
          public Boolean get() {
            return HTMLFilter.isEmbedM3uPlayerEnabled();
          }

          @Override
          public void set(Boolean val) {
            HTMLFilter.setEmbedM3uPlayerEnabled(val);
          }
        });
    HTMLFilter.setEmbedM3uPlayerEnabled(fproxyConfig.getBoolean("embedM3uPlayerInFreesites"));

    fproxyConfig.register(
        "refilterPolicy",
        "RE_FILTER",
        new Option.Meta(
            configItemOrder++,
            true,
            false,
            "SimpleToadletServer.refilterPolicy",
            "SimpleToadletServer.refilterPolicyLong"),
        new ReFilterCallback());

    this.refilterPolicy = REFILTER_POLICY.valueOf(fproxyConfig.getString("refilterPolicy"));
    return configItemOrder;
  }

  /**
   * Removes the temporary startup toadlet once the node is ready.
   *
   * <p>Calling this method unregisters the startup handler that served initial setup pages and
   * clears its reference for garbage collection. It must only be invoked after {@link #setCore} and
   * after startup has progressed far enough that the main toadlets are available.
   */
  public void removeStartupToadlet() {
    // setCore() must have been called first. It is in fact called much earlier on.
    synchronized (this) {
      unregister(startupToadlet);
      // Ready to be GCed
      startupToadlet = null;
      // Not in the navbar.
    }
  }

  private void maybeGetNetworkInterface() {
    if (this.networkInterface != null) return;
    if (ssl) {
      this.networkInterface =
          SSLNetworkInterface.createSsl(port, this.bindTo, allowedHosts, executor, true);
    } else {
      this.networkInterface =
          NetworkInterface.create(port, this.bindTo, allowedHosts, executor, true);
    }
  }

  @Override
  public boolean doRobots() {
    return doRobots;
  }

  @Override
  public boolean publicGatewayMode() {
    return wasPublicGatewayMode;
  }

  /**
   * Starts the HTTP listener thread if it has been initialized.
   *
   * <p>Callers should ensure {@link #setCore(NodeClientCore)} and {@link #createFproxy()} have
   * completed before invoking this method. When {@link #myThread} is non-null, the network
   * interface is lazily created and the thread is started, logging the bind address and port. This
   * call is idempotent when {@link #myThread} is already {@code null} or the thread has previously
   * been started.
   */
  @SuppressWarnings("java:S106")
  public void start() {
    Thread thread;
    synchronized (this) {
      thread = myThread;
    }
    if (thread != null) {
      maybeGetNetworkInterface();
      thread.start();
      LOG.info("Starting FProxy on {}:{}", bindTo, port);
      // Keep a plain stdout line for the launcher parser when INFO logs are filtered by default.
      System.out.println("Starting FProxy on " + bindTo + ":" + port);
    }
  }

  /**
   * Completes startup by wiring threat-level listeners and marking readiness.
   *
   * <p>This method should be called after {@link #start()} once the node finishes loading
   * subsystems. It attaches listeners to network and physical threat level changes so the server
   * can adjust refilter policies and panic button visibility in real time. When the wiring
   * succeeds, {@link #finishedStartup} becomes true, allowing deferred operations to proceed.
   */
  public void finishStart() {
    core.getNode()
        .services()
        .securityLevels()
        .addNetworkThreatLevelListener(
            (oldLevel, newLevel) -> {
              // At LOW, we do ACCEPT_OLD.
              // Otherwise, we do RE_FILTER.
              // But we don't change it unless it changes from LOW to not LOW.
              if (newLevel == NETWORK_THREAT_LEVEL.LOW && newLevel != oldLevel) {
                refilterPolicy = REFILTER_POLICY.ACCEPT_OLD;
              } else if (oldLevel == NETWORK_THREAT_LEVEL.LOW && newLevel != oldLevel) {
                refilterPolicy = REFILTER_POLICY.RE_FILTER;
              }
            });
    core.getNode()
        .services()
        .securityLevels()
        .addPhysicalThreatLevelListener(
            (oldLevel, newLevel) -> {
              if (newLevel != oldLevel && newLevel == PHYSICAL_THREAT_LEVEL.LOW) {
                setPanicButtonVisibility(false);
              } else if (newLevel != oldLevel) {
                setPanicButtonVisibility(true);
              }
            });
    synchronized (this) {
      finishedStartup = true;
    }
  }

  @Override
  public void register(Toadlet t, ToadletRegistration registration) {
    ToadletElement te =
        new ToadletElement(t, registration.urlPrefix(), registration.menu(), registration.name());
    synchronized (toadlets) {
      if (registration.atFront()) toadlets.addFirst(te);
      else toadlets.addLast(te);
      t.container = this;
    }
    if (registration.menu() != null && registration.name() != null) {
      pageMaker.addNavigationLink(
          registration.menu(),
          registration.urlPrefix(),
          registration.name(),
          registration.title(),
          registration.fullOnly(),
          registration.callback(),
          registration.l10n());
    }
  }

  /**
   * Registers a navigation category contributed by a plugin.
   *
   * <p>The category is added to the page maker so plugin pages appear in the navigation menu with
   * translated titles where available. Callers should supply stable identifiers; no synchronization
   * beyond the internal {@link PageMaker} handling is required.
   *
   * @param link navigation link target, typically a path prefix owned by the plugin.
   * @param name short category name shown in menus; should be unique within its level.
   * @param title descriptive title used for tooltips or extended labels; may be {@code null}.
   * @param plugin localization helper that translates the title/name for the current locale.
   */
  public void registerMenu(String link, String name, String title, FredPluginL10n plugin) {
    pageMaker.addNavigationCategory(link, name, title, plugin);
  }

  @Override
  public void unregister(Toadlet t) {
    ToadletElement e = null;
    synchronized (toadlets) {
      for (Iterator<ToadletElement> i = toadlets.iterator(); i.hasNext(); ) {
        e = i.next();
        if (e.t == t) {
          i.remove();
          break;
        }
      }
    }
    if (e != null && e.t == t && e.menu != null && e.name != null) {
      pageMaker.removeNavigationLink(e.menu, e.name);
    }
  }

  /**
   * Returns the startup toadlet currently registered with the server.
   *
   * <p>The startup toadlet serves the initial wizard and bootstrap pages before the main interface
   * becomes available. It may be removed via {@link #removeStartupToadlet()} once the node finishes
   * initialization.
   *
   * @return startup toadlet instance or {@code null} if it has already been removed.
   */
  public StartupToadlet getStartupToadlet() {
    return startupToadlet;
  }

  @Override
  public boolean fproxyHasCompletedWizard() {
    return fproxyHasCompletedWizard;
  }

  @Override
  public Toadlet findToadlet(URI uri) throws PermanentRedirectException {
    String path = uri.getPath();
    if (shouldRedirectToWizard(path)) {
      throw new PermanentRedirectException(createWizardRedirectURI(uri));
    }
    return findRegisteredToadlet(path);
  }

  private boolean shouldRedirectToWizard(String path) {
    NodeClientCore coreLocal = this.core;
    if (coreLocal == null || coreLocal.getNode() == null || fproxyHasCompletedWizard) {
      return false;
    }
    return !isWizardPathAllowed(path);
  }

  private boolean isWizardPathAllowed(String path) {
    return path.startsWith(FirstTimeWizardToadlet.TOADLET_URL)
        || path.startsWith(FirstTimeWizardNewToadlet.TOADLET_URL)
        || path.startsWith(StaticToadlet.ROOT_URL)
        || path.startsWith(ExternalLinkToadlet.EXTERNAL_LINK_PATH)
        || path.equals("/favicon.ico")
        || path.equals("/favicon.svg");
  }

  private URI createWizardRedirectURI(URI uri) {
    try {
      return new URI(
          null, null, null, -1, FirstTimeWizardToadlet.TOADLET_URL, uri.getQuery(), null);
    } catch (URISyntaxException e) {
      throw new IllegalStateException(e);
    }
  }

  private Toadlet findRegisteredToadlet(String path) throws PermanentRedirectException {
    synchronized (toadlets) {
      for (ToadletElement te : toadlets) {
        if (path.startsWith(te.prefix)) return te.t;
        if (te.prefix.charAt(te.prefix.length() - 1) == '/'
            && path.equals(te.prefix.substring(0, te.prefix.length() - 1))) {
          URI newURI;
          try {
            newURI = new URI(te.prefix);
          } catch (URISyntaxException e) {
            throw new IllegalStateException(e);
          }
          throw new PermanentRedirectException(newURI);
        }
      }
    }
    return null;
  }

  @Override
  public void run() {
    boolean finishedStartupFlag = false;
    while (true) {
      finishedStartupFlag = updateFinishedStartupFlag(finishedStartupFlag);
      if (!acquireConnectionSlot()) {
        return;
      }
      Socket conn = networkInterface.accept();
      if (WrapperManager.hasShutdownHookBeenTriggered()) return;
      if (conn == null) continue; // timeout
      if (LOG.isDebugEnabled()) LOG.debug("Accepted connection");
      SocketHandler sh = new SocketHandler(conn, finishedStartupFlag);
      sh.start();
    }
  }

  private boolean acquireConnectionSlot() {
    synchronized (this) {
      while (fproxyConnections > maxFproxyConnections) {
        try {
          wait();
        } catch (InterruptedException _) {
          Thread.currentThread().interrupt();
          return false;
        }
      }
      return myThread != null;
    }
  }

  private boolean updateFinishedStartupFlag(boolean finishedStartupFlag) {
    synchronized (this) {
      if (!finishedStartupFlag && this.finishedStartup) {
        return true;
      }
    }
    return finishedStartupFlag;
  }

  /**
   * Handles a single accepted HTTP socket connection.
   *
   * <p>A SocketHandler is created per connection and either executed on the configured executor
   * (after startup) or on a temporary thread during early boot. It owns the socket lifetime, runs
   * request processing via {@link ToadletContextImpl}, and decrements the active connection counter
   * on completion. Instances are short-lived and not reused across requests.
   */
  public class SocketHandler implements PrioRunnable {

    Socket sock;
    final boolean finishedStartup;

    /**
     * Creates a handler for a freshly accepted socket.
     *
     * @param conn connected client socket; ownership transfers to the handler.
     * @param finishedStartup whether the node has finished startup and can use the shared executor.
     */
    public SocketHandler(Socket conn, boolean finishedStartup) {
      this.sock = conn;
      this.finishedStartup = finishedStartup;
    }

    void start() {
      if (finishedStartup) executor.execute(this, "HTTP socket handler@" + hashCode());
      else new Thread(this).start();
      synchronized (SimpleToadletServer.this) {
        fproxyConnections++;
      }
    }

    @Override
    public void run() {
      if (LOG.isDebugEnabled()) LOG.debug("Handling connection");
      try {
        ToadletRequestServices services =
            new ToadletRequestServices(
                SimpleToadletServer.this, pageMaker, getUserAlertManager(), bookmarkManager);
        ToadletContextImpl.handle(sock, services);
      } catch (Exception t) {
        LOG.error("Caught in SimpleToadletServer: {}", t, t);
      } finally {
        synchronized (SimpleToadletServer.this) {
          fproxyConnections--;
          SimpleToadletServer.this.notifyAll();
        }
      }
      if (LOG.isDebugEnabled()) LOG.debug("Handled connection");
    }

    @Override
    public int getPriority() {
      return NativeThread.PriorityLevel.HIGH_PRIORITY.value - 1;
    }
  }

  @Override
  public THEME getTheme() {
    return this.cssTheme;
  }

  /**
   * Returns the user alert manager associated with the current core.
   *
   * <p>The alert manager surfaces node warnings and informational banners to the UI and handles
   * their dismissal state. When the core has not yet been assigned this method returns {@code
   * null}; callers should therefore wait until after {@link #setCore(NodeClientCore)} is invoked.
   *
   * @return active {@link UserAlertManager} from the core, or {@code null} when unavailable.
   */
  public UserAlertManager getUserAlertManager() {
    NodeClientCore coreRef = this.core;
    if (coreRef == null) return null;
    return coreRef.getAlerts();
  }

  /**
   * Overrides the current theme selection.
   *
   * <p>This setter is primarily used by configuration callbacks and assumes the provided theme has
   * already been validated. It does not persist the change; callers must handle storage.
   *
   * @param theme new theme enumeration value to use for rendering pages.
   */
  @SuppressWarnings("unused")
  public void setCSSName(THEME theme) {
    this.cssTheme = theme;
  }

  @Override
  public synchronized boolean sendAllThemes() {
    return this.sendAllThemes;
  }

  @Override
  public synchronized boolean isAdvancedModeEnabled() {
    return this.advancedModeEnabled;
  }

  @Override
  public void setAdvancedMode(boolean enabled) {
    synchronized (this) {
      if (advancedModeEnabled == enabled) return;
      advancedModeEnabled = enabled;
    }
    core.getNode().getConfig().store();
  }

  @Override
  public synchronized boolean isFProxyJavascriptEnabled() {
    return this.fProxyJavascriptEnabled;
  }

  /**
   * Enables or disables JavaScript in FProxy pages.
   *
   * <p>The flag is stored as a volatile boolean and read by template rendering code to decide
   * whether to include inline scripts. Callers are expected to persist the chosen value elsewhere.
   * Changing this setting only affects newly rendered pages; already rendered responses are
   * unchanged. The method is thread-safe and may be called from configuration UI handlers.
   *
   * @param b {@code true} to permit JavaScript, {@code false} to disable it across pages.
   */
  public synchronized void enableFProxyJavascript(boolean b) {
    fProxyJavascriptEnabled = b;
  }

  @Override
  public synchronized boolean isFProxyWebPushingEnabled() {
    return this.fProxyWebPushingEnabled;
  }

  /**
   * Toggles push support for FProxy web interfaces.
   *
   * <p>When enabled, pages may initiate push data channels to deliver live updates. The flag is
   * stored and read concurrently; synchronization guards write. Existing connections will read the
   * latest value on their next push attempt, so callers can flip this at runtime to triage load or
   * feature issues without restarting the node.
   *
   * @param b {@code true} to enable pushing, {@code false} to disable it.
   */
  public synchronized void enableFProxyWebPushing(boolean b) {
    fProxyWebPushingEnabled = b;
  }

  @Override
  public String getFormPassword() {
    if (core == null) return "";
    return core.getFormPassword();
  }

  @Override
  public boolean isAllowedFullAccess(InetAddress remoteAddr) {
    return this.allowedFullAccess.allowed(remoteAddr);
  }

  private static String l10n(String key, String pattern, String value) {
    return NodeL10n.getBase().getString("SimpleToadletServer." + key, pattern, value);
  }

  private static String l10n(String key) {
    return NodeL10n.getBase().getString("SimpleToadletServer." + key);
  }

  @Override
  public HTMLNode addFormChild(HTMLNode parentNode, String target, String id) {
    HTMLNode formNode =
        parentNode
            .addChild("div")
            .addChild(
                "form",
                new String[] {"action", "method", "enctype", "id", "accept-charset"},
                new String[] {target, "post", "multipart/form-data", id, "utf-8"});
    formNode.addChild(
        "input",
        new String[] {"type", "name", "value"},
        new String[] {"hidden", "formPassword", getFormPassword()});

    return formNode;
  }

  /**
   * Replaces the bucket factory used for incoming request handling.
   *
   * <p>Intended for controlled overrides or tests that need deterministic buffering behavior.
   * Synchronization ensures the new factory becomes visible to concurrent worker threads. Does not
   * retroactively alter buckets already allocated for in-flight requests.
   *
   * @param tempBucketFactory replacement {@link BucketFactory}; must not be {@code null}.
   */
  public synchronized void setBucketFactory(BucketFactory tempBucketFactory) {
    this.bf = tempBucketFactory;
  }

  /**
   * Indicates whether the HTTP listener is currently configured to run.
   *
   * <p>This mirrors whether the server thread was created at construction. It does not confirm the
   * socket bind succeeded; callers should also observe logs for binding errors when transitioning
   * to the running state.
   *
   * @return {@code true} when the listener thread exists, {@code false} otherwise.
   */
  public boolean isEnabled() {
    synchronized (this) {
      return myThread != null;
    }
  }

  /**
   * Returns the bookmark manager backing user bookmark operations.
   *
   * <p>The manager may be {@code null} before {@link #createFproxy()} wires the supporting
   * components. Once available, it manages storage, import/export, and UI synchronization for saved
   * bookmarks. Callers should treat the reference as owned by the server.
   *
   * @return {@link BookmarkManager} instance or {@code null} when not yet available.
   */
  public BookmarkManager getBookmarkManager() {
    return bookmarkManager;
  }

  /**
   * Convenience alias for {@link #getBookmarkManager()}.
   *
   * <p>Provided for compatibility with older call sites that referenced the shorter name.
   *
   * @return bookmark manager instance or {@code null}.
   */
  public BookmarkManager getBookmarks() {
    return getBookmarkManager();
  }

  /**
   * Returns the URIs of all currently stored bookmarks.
   *
   * <p>The returned array is a snapshot; later modifications to the bookmark store are not
   * reflected. Callers should not mutate the array contents.
   *
   * @return array of {@link FreenetURI} entries; empty when no bookmarks exist.
   */
  public FreenetURI[] getBookmarkURIs() {
    if (bookmarkManager == null) return new FreenetURI[0];
    return bookmarkManager.getBookmarkURIs();
  }

  @Override
  public boolean enablePersistentConnections() {
    return enablePersistentConnections;
  }

  @Override
  public boolean enableInlinePrefetch() {
    return enableInlinePrefetch;
  }

  @Override
  public boolean enableExtendedMethodHandling() {
    return enableExtendedMethodHandling;
  }

  @Override
  public boolean enableCachingForChkAndSskKeys() {
    return enableCachingForChkAndSskKeys;
  }

  @Override
  public synchronized boolean allowPosts() {
    return !(bf instanceof ArrayBucketFactory);
  }

  /**
   * Returns the bucket factory currently active for request bodies.
   *
   * <p>The factory is used to allocate buffers for uploads and other payloads. The method is
   * synchronized to ensure callers see the latest factory after runtime swaps.
   *
   * @return non-null {@link BucketFactory} used to allocate request storage.
   */
  @Override
  public synchronized BucketFactory getBucketFactory() {
    return bf;
  }

  @Override
  public boolean enableActivelinks() {
    return enableActivelinks;
  }

  @Override
  public boolean disableProgressPage() {
    return disableProgressPage;
  }

  /**
   * Returns the page maker responsible for building HTML responses.
   *
   * <p>PageMaker handles templating, navigation link management, and shared look-and-feel settings
   * such as theme overrides.
   *
   * @return configured {@link PageMaker} instance.
   */
  @Override
  public PageMaker getPageMaker() {
    return pageMaker;
  }

  /**
   * Provides the ticker used to schedule periodic tasks.
   *
   * <p>The ticker is shared across push managers and other time-based components. It is owned by
   * the {@link Node} and exposed here for convenience.
   *
   * @return {@link Ticker} from the node; never {@code null} after the core is set.
   */
  public Ticker getTicker() {
    return core.getNode().network().ticker();
  }

  /**
   * Returns the currently bound node core.
   *
   * <p>Callers must not mutate the core state in ways that violate server invariants. The reference
   * may change only through {@link #setCore(NodeClientCore)} during startup.
   *
   * @return {@link NodeClientCore} instance or {@code null} when unset.
   */
  public NodeClientCore getCore() {
    return core;
  }

  private REFILTER_POLICY refilterPolicy;

  /**
   * Returns the active refilter policy applied to request processing.
   *
   * <p>The policy is updated in response to threat-level changes to balance usability with
   * security. Caller should treat the value as read-only.
   *
   * @return current {@link REFILTER_POLICY} value.
   */
  @Override
  public REFILTER_POLICY getReFilterPolicy() {
    return refilterPolicy;
  }

  @Override
  public File getOverrideFile() {
    return cssOverride;
  }

  @Override
  public String getURL() {
    return getURL(null);
  }

  @Override
  public String getURL(String host) {
    StringBuilder sb = new StringBuilder();
    if (ssl) sb.append("https");
    else sb.append("http");
    sb.append("://");
    if (host == null) host = "127.0.0.1";
    sb.append(host);
    sb.append(":");
    sb.append(this.port);
    sb.append("/");
    return sb.toString();
  }

  @Override
  public boolean isSSL() {
    return ssl;
  }

  //
  // LINKFILTEREXCEPTIONPROVIDER METHODS
  //

  /** {@inheritDoc} */
  @Override
  public boolean isLinkExcepted(URI link) {
    Toadlet toadlet = null;
    try {
      toadlet = findToadlet(link);
    } catch (PermanentRedirectException _) {
      /* ignore. */
    }
    if (toadlet instanceof LinkFilterExceptedToadlet exceptedToadlet) {
      return exceptedToadlet.isLinkExcepted(link);
    }
    return false;
  }

  @Override
  public long generateUniqueID() {
    // Generates a unique ID per call; replace it with a counter if sequential IDs are required.
    return random.nextLong();
  }

  /**
   * Returns the interval pusher manager coordinating scheduled push cycles.
   *
   * <p>Used by pages that need periodic server-initiated updates. Ownership remains with the
   * server; callers should not attempt to shut it down directly.
   *
   * @return {@link IntervalPusherManager} instance, or {@code null} before {@link #createFproxy()}
   *     runs.
   */
  @SuppressWarnings("unused")
  public IntervalPusherManager getIntervalPushManager() {
    return intervalPushManager;
  }

  /**
   * Returns the push data manager handling ad-hoc push operations.
   *
   * <p>Supports one-off push transmissions triggered by toadlets. Like the interval manager, this
   * object is created during {@link #createFproxy()} and owned by the server.
   *
   * @return {@link PushDataManager} instance or {@code null} if initialization has not yet created
   *     one.
   */
  public PushDataManager getPushDataManager() {
    return pushDataManager;
  }
}

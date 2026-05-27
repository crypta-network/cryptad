package network.crypta.clients.http;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.SecureRandom;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Objects;
import java.util.StringTokenizer;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import network.crypta.client.filter.HTMLFilterPolicy;
import network.crypta.client.filter.LinkFilterExceptionProvider;
import network.crypta.clients.http.PageMaker.THEME;
import network.crypta.config.BooleanCallback;
import network.crypta.config.EnumerableOptionCallback;
import network.crypta.config.IntCallback;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.LongCallback;
import network.crypta.config.NodeNeedRestartException;
import network.crypta.config.Option;
import network.crypta.config.StringCallback;
import network.crypta.config.SubConfig;
import network.crypta.fs.readiness.LauncherReadinessInfo;
import network.crypta.io.AllowedHosts;
import network.crypta.io.NetworkInterface;
import network.crypta.io.SSLNetworkInterface;
import network.crypta.keys.FreenetURI;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.PrioRunnable;
import network.crypta.platform.appdist.AppUiMode;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.InstalledAppSnapshot;
import network.crypta.platform.webshell.routes.WebShellPaths;
import network.crypta.runtime.alerts.UserAlertSurface;
import network.crypta.runtime.core.SSL;
import network.crypta.runtime.spi.RuntimePorts;
import network.crypta.support.HTMLNode;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.Ticker;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.http.HttpFetchSizeLimits;
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
 * construct the server with the node configuration, publish runtime support through {@link
 * #setRuntimeSupport(HttpShellRuntimeSupport)} once the daemon is ready, start the listener, and
 * invoke {@link #finishStart()} after startup housekeeping completes. The server keeps track of
 * theme selection, panic button visibility, gateway mode, and access controls. It also delegates
 * bookmark management, push managers, and theme overrides to the HTTP-local runtime adapter and
 * supporting helper classes.
 *
 * <p>Concurrency: the network listener and request handling threads read shared state such as the
 * {@link #runtimeSupport} reference, panic flags, and theme settings. The runtime support reference
 * is published through a volatile write-in {@link #setRuntimeSupport(HttpShellRuntimeSupport)} so
 * request threads see it once set. Mutability: most configuration is thread-safe via synchronized
 * blocks or volatile fields; URL registration is guarded by the server monitor. Extended
 * configuration callbacks are invoked on the configuration thread; request handlers run on the
 * executor.
 *
 * <ul>
 *   <li>Responsibilities: bind sockets, dispatch toadlets, surface configuration, and relay alerts.
 *   <li>Notable behaviors: preserves startup toadlet until replaced; honors gateway/public mode;
 *       emits panic button state based on physical threat level.
 * </ul>
 *
 * @see Toadlet
 * @see HttpShellBrowseBootstrap
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
  private static final String IPV4_LOOPBACK_HOST = "127.0.0.1";
  private static final String IPV4_WILDCARD_HOST = "0.0.0.0";
  private static final String IPV6_LOOPBACK_HOST = "::1";
  private static final String IPV6_LOOPBACK_HOST_EXPANDED = "0:0:0:0:0:0:0:1";
  private static final String IPV6_WILDCARD_HOST = "::";
  private static final String IPV6_WILDCARD_HOST_EXPANDED = "0:0:0:0:0:0:0:0";
  private static final String IPV6_LOOPBACK_URL_HOST = "[::1]";
  private static final String LOCALHOST_HOST = "localhost";

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
  private volatile network.crypta.clients.http.HttpShellRuntimeSupport runtimeSupport;

  @SuppressWarnings("java:S3077")
  private volatile LegacyHttpRouteRegistrar routeRegistrar;

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

  private BookmarkManagerHandle bookmarkManager; // move to WelcomeToadlet / BookmarkEditorToadlet?
  private volatile boolean fProxyJavascriptEnabled; // ugh?
  private volatile boolean fProxyWebPushingEnabled; // ugh?
  private volatile boolean fproxyHasCompletedWizard; // hmmm..
  private volatile boolean disableProgressPage;
  private volatile int maxFproxyConnections;
  private final AtomicReference<Consumer<String>> primaryUiRootListener =
      new AtomicReference<>(_ -> {});

  private int fproxyConnections;

  private boolean finishedStartup;

  private StartupToadlet startupToadlet;

  /** The push/update manager handle coordinates all legacy-pushing tasks. */
  private PushDataManagerHandle pushDataManager;

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
      return HttpFetchSizeLimits.getMaxLengthNoProgress();
    }

    @Override
    public void set(Long val) {
      if (get().equals(val)) return;
      HttpFetchSizeLimits.setMaxLengthNoProgress(val);
    }
  }

  private static class FProxyPassthruMaxSizeProgress extends LongCallback {
    @Override
    public Long get() {
      return HttpFetchSizeLimits.getMaxLengthWithProgress();
    }

    @Override
    public void set(Long val) {
      if (get().equals(val)) return;
      HttpFetchSizeLimits.setMaxLengthWithProgress(val);
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
      network.crypta.clients.http.HttpShellRuntimeSupport runtimeSupportRef =
          SimpleToadletServer.this.runtimeSupport;
      if (runtimeSupportRef == null) return;
      if (val.equals(get()) || val.isEmpty()) cssOverride = null;
      else {
        File tmp = new File(val.trim());
        if (!runtimeSupportRef.allowUploadFrom(tmp))
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
      RefilterPolicy[] possible = RefilterPolicy.values();
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
      refilterPolicy = RefilterPolicy.valueOf(val);
    }
  }

  /**
   * Builds the FProxy runtime structures once runtime support is ready.
   *
   * <p>Call this after {@link #setRuntimeSupport(HttpShellRuntimeSupport)} and before accepting
   * requests to install bookmark handling, interval push scheduling, and UI registration against
   * the active node. This method is idempotent; later calls are ignored after the first successful
   * invocation. It captures the current runtime support reference, wires the push managers to the
   * shared {@link Ticker}, assembles the daemon-only root FProxy collaborators, and delegates to
   * the configured {@link LegacyHttpRouteRegistrar} for the remaining HTTP shell registration.
   */
  public void createFproxy() {
    network.crypta.clients.http.HttpShellRuntimeSupport runtimeSupportRef = requireRuntimeSupport();
    LegacyHttpRouteRegistrar routeRegistrarRef = requireRouteRegistrar();
    synchronized (this) {
      if (haveCalledFProxy) return;
      haveCalledFProxy = true;
    }

    Ticker ticker = runtimeSupportRef.ticker();
    pushDataManager = runtimeSupportRef.createPushDataManagerHandle(ticker);
    intervalPushManager = new IntervalPusherManager(ticker, pushDataManager);
    HttpShellBrowseBootstrap bootstrap =
        runtimeSupportRef.createBrowseBootstrap(publicGatewayMode());
    bookmarkManager = bootstrap.bookmarkManager();
    RuntimePorts runtimePorts = runtimeSupportRef.runtimePorts();
    bootstrap.initializeSharedShellState(runtimePorts);

    routeRegistrarRef.registerRoutes(
        new LegacyHttpRouteRegistrarContext(
            runtimePorts,
            runtimeSupportRef.appHost(),
            runtimeSupportRef.appCatalogManager(),
            runtimeSupportRef.appUpdateService(),
            runtimeSupportRef.contentSubscriptionService(),
            runtimeSupportRef.appDataService(),
            runtimeSupportRef.trustGraphApiHandler(),
            runtimeSupportRef.appVaultService(),
            runtimeSupportRef.config(),
            bootstrap.browseRoot(),
            bootstrap.browseRouteRegistrar(),
            runtimeSupportRef.insertCompatibilityModes()),
        this);
  }

  /**
   * Returns the configured HTTP listen port used by the current shell instance.
   *
   * <p>The launcher readiness protocol consumes this value only after the shell finishes its normal
   * startup sequence.
   *
   * @return configured HTTP port
   */
  public int listenPort() {
    return port;
  }

  /**
   * Returns the primary first-party browser route exposed by this shell host.
   *
   * <p>The launcher readiness protocol uses this route after the shell completes startup. Fresh
   * installs must continue advertising the historical HTTP root until the first-time wizard gate is
   * lifted. The shell also requires FProxy JavaScript to remain enabled; otherwise the launcher
   * must keep landing on the legacy root, because the current Web Shell v1 depends on browser-side
   * script execution to leave its loading placeholders.
   *
   * @return primary browser-facing shell route
   */
  @Override
  public String primaryUiRoot() {
    return shouldAdvertiseWebShellPrimaryUi()
        ? WebShellPaths.SHELL_ROOT
        : LauncherReadinessInfo.DEFAULT_UI_ROOT;
  }

  @Override
  public boolean isStaticAppUiAvailable(String appId) {
    if (appId == null || appId.isBlank()) {
      return false;
    }
    network.crypta.clients.http.HttpShellRuntimeSupport runtimeSupportRef = runtimeSupport;
    if (runtimeSupportRef == null) {
      return false;
    }
    AppHost appHost = runtimeSupportRef.appHost();
    if (appHost == null) {
      return false;
    }
    try {
      return appHost
          .describe(appId)
          .map(InstalledAppSnapshot::manifest)
          .map(manifest -> manifest.uiMode() == AppUiMode.STATIC)
          .orElse(false);
    } catch (IOException _) {
      return false;
    }
  }

  /**
   * Stores a listener that should be notified when the primary UI route changes after startup.
   *
   * <p>The server invokes this callback only for runtime transitions that make a different
   * launcher-facing entry route reachable while the shell is already live, most notably when the
   * first-time wizard completion flag flips.
   *
   * @param listener callback receiving the updated normalized UI root
   */
  public void setPrimaryUiRootListener(Consumer<String> listener) {
    primaryUiRootListener.set(Objects.requireNonNull(listener));
  }

  private void notifyPrimaryUiRootChangedIfStarted(String previousUiRoot) {
    Consumer<String> listener;
    String updatedUiRoot;
    synchronized (this) {
      if (!finishedStartup) {
        return;
      }
      listener = primaryUiRootListener.get();
      updatedUiRoot = primaryUiRoot();
      if (previousUiRoot != null && Objects.equals(previousUiRoot, updatedUiRoot)) {
        return;
      }
    }
    listener.accept(updatedUiRoot);
  }

  private boolean shouldAdvertiseWebShellPrimaryUi() {
    return fproxyHasCompletedWizard && fProxyJavascriptEnabled;
  }

  /**
   * Publishes the initialized HTTP runtime adapter to request handlers.
   *
   * <p>The runtime support reference is written with volatile semantics, so listener threads see it
   * after startup. Call this exactly once, immediately after daemon bootstrap finishes creating the
   * adapter, and before invoking {@link #createFproxy()} or {@link #start()}. When the runtime
   * support exposes runtime SPI ports, this method also late-injects the detached page-chrome port
   * into the shared {@link PageMaker}. Passing {@code null} leaves the server unable to service
   * requests.
   *
   * @param runtimeSupport fully constructed runtime adapter; may be {@code null} during tests that
   *     intentionally exercise uninitialized behavior
   */
  public void setRuntimeSupport(
      network.crypta.clients.http.HttpShellRuntimeSupport runtimeSupport) {
    this.runtimeSupport = runtimeSupport;
    RuntimePorts runtimePorts = runtimeSupport == null ? null : runtimeSupport.runtimePorts();
    pageMaker.setPageChromePort(runtimePorts == null ? null : runtimePorts.pageChrome());
  }

  /**
   * Installs the route registrar used by {@link #createFproxy()}.
   *
   * <p>This seam keeps the shared HTTP shell free from direct knowledge of the current admin-owned
   * registration helper. Bridge wiring should call this before FProxy creation so the shell can
   * delegate the concrete route-registration pass.
   *
   * @param routeRegistrar registrar that will register the concrete legacy HTTP routes
   */
  public void setRouteRegistrar(LegacyHttpRouteRegistrar routeRegistrar) {
    this.routeRegistrar = Objects.requireNonNull(routeRegistrar);
  }

  /**
   * Creates a SimpleToadletServer bound to the given FProxy configuration.
   *
   * <p>The constructor performs lightweight configuration registration, initializes option
   * callbacks, and defers expensive wiring (runtime support assignment, network listener startup)
   * to later calls. It seeds random sources, sets the initial access control list, and records
   * whether the server should start enabled. The {@link #runtimeSupport} is left {@code null};
   * callers must invoke {@link #setRuntimeSupport(HttpShellRuntimeSupport)} before servicing
   * requests.
   *
   * @param fproxyConfig configuration subsection containing fproxy.* keys that drive listener
   *     options, theme settings, limits, and ACLs; must be non-null.
   * @param bucketFactory factory used to create buckets for request payload handling; callers may
   *     later replace it via {@link #setBucketFactory(BucketFactory)}.
   * @param executor executor that runs HTTP worker threads with priority awareness; ownership stays
   *     with the caller.
   * @throws InvalidConfigValueException if any configuration entry is invalid or fails validation
   *     during registration.
   */
  public SimpleToadletServer(
      SubConfig fproxyConfig, BucketFactory bucketFactory, PriorityAwareExecutor executor)
      throws InvalidConfigValueException {

    this.executor = executor;
    this.runtimeSupport = null; // setRuntimeSupport() will be called later.
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
    configItemOrder = registerAccessOptions(fproxyConfig, configItemOrder);
    // Read only after registration so persistent values are visible instead of missing-option
    // fallback.
    allowedFullAccess = new AllowedHosts(fproxyConfig.getString("allowedHostsFullAccess"));

    configItemOrder = registerFilterAndLimitOptions(fproxyConfig, configItemOrder);

    this.bf = bucketFactory;
    port = fproxyConfig.getInt("port");
    bindTo = fproxyConfig.getString("bindTo");
    String cssName = fproxyConfig.getString("css");
    if ((cssName.indexOf(':') != -1) || (cssName.indexOf('/') != -1))
      throw new InvalidConfigValueException("CSS name must not contain slashes or colons!");
    cssTheme = THEME.themeFromName(cssName);
    pageMaker = new PageMaker(cssTheme);

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
            String previousUiRoot = primaryUiRoot();
            fproxyHasCompletedWizard = val;
            notifyPrimaryUiRootChangedIfStarted(previousUiRoot);
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
        HttpFetchSizeLimits.getMaxLengthNoProgress(),
        new Option.Meta(
            configItemOrder++,
            true,
            false,
            "SimpleToadletServer.passthroughMaxSize",
            "SimpleToadletServer.passthroughMaxSizeLong"),
        new FProxyPassthruMaxSizeNoProgress(),
        true);
    HttpFetchSizeLimits.setMaxLengthNoProgress(fproxyConfig.getLong("passthroughMaxSize"));
    fproxyConfig.register(
        PASSTHROUGH_MAX_SIZE_PROGRESS_KEY,
        HttpFetchSizeLimits.getMaxLengthWithProgress(),
        new Option.Meta(
            configItemOrder++,
            true,
            false,
            "SimpleToadletServer.passthroughMaxSizeProgress",
            "SimpleToadletServer.passthroughMaxSizeProgressLong"),
        new FProxyPassthruMaxSizeProgress(),
        true);
    HttpFetchSizeLimits.setMaxLengthWithProgress(
        fproxyConfig.getLong(PASSTHROUGH_MAX_SIZE_PROGRESS_KEY));
    LOG.info(
        "Set fproxy max length to {} and max length with progress to {} = {}",
        HttpFetchSizeLimits.getMaxLengthNoProgress(),
        HttpFetchSizeLimits.getMaxLengthWithProgress(),
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
            return HTMLFilterPolicy.getMetaRefreshSamePageMinInterval();
          }

          @Override
          public void set(Integer val) throws InvalidConfigValueException {
            if (val < -1)
              throw new InvalidConfigValueException(
                  "-1 = disabled, 0+ = set a minimum interval"); // localization pending
            HTMLFilterPolicy.setMetaRefreshSamePageMinInterval(val);
          }
        },
        false);
    HTMLFilterPolicy.setMetaRefreshSamePageMinInterval(
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
            return HTMLFilterPolicy.getMetaRefreshRedirectMinInterval();
          }

          @Override
          public void set(Integer val) throws InvalidConfigValueException {
            if (val < -1)
              throw new InvalidConfigValueException(
                  "-1 = disabled, 0+ = set a minimum interval"); // localization pending
            HTMLFilterPolicy.setMetaRefreshRedirectMinInterval(val);
          }
        },
        false);
    HTMLFilterPolicy.setMetaRefreshRedirectMinInterval(
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
            return HTMLFilterPolicy.isEmbedM3uPlayerEnabled();
          }

          @Override
          public void set(Boolean val) {
            HTMLFilterPolicy.setEmbedM3uPlayerEnabled(val);
          }
        });
    HTMLFilterPolicy.setEmbedM3uPlayerEnabled(fproxyConfig.getBoolean("embedM3uPlayerInFreesites"));

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

    this.refilterPolicy = RefilterPolicy.valueOf(fproxyConfig.getString("refilterPolicy"));
    return configItemOrder;
  }

  /**
   * Removes the temporary startup toadlet once the node is ready.
   *
   * <p>Calling this method unregisters the startup handler that served initial setup pages and
   * clears its reference for garbage collection. It must only be invoked after {@link
   * #setRuntimeSupport(HttpShellRuntimeSupport)} and after startup has progressed far enough that
   * the main toadlets are available.
   */
  public void removeStartupToadlet() {
    // setRuntimeSupport() must have been called first. It is in fact called much earlier on.
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
   * <p>Callers should ensure {@link #setRuntimeSupport(HttpShellRuntimeSupport)} and {@link
   * #createFproxy()} have completed before invoking this method. When {@link #myThread} is
   * non-null, the network interface is lazily created and the thread is started, logging the bind
   * address and port. This call is idempotent when {@link #myThread} is already {@code null} or the
   * thread has previously been started.
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
      // Keep a plain stdout line as a compatibility fallback when structured launcher readiness is
      // unavailable.
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
    network.crypta.clients.http.HttpShellRuntimeSupport runtimeSupportRef = requireRuntimeSupport();
    runtimeSupportRef.addNetworkThreatLevelListener(
        (oldLevel, newLevel) -> {
          // At LOW, we do ACCEPT_OLD.
          // Otherwise, we do RE_FILTER.
          // But we don't change it unless it changes from LOW to not LOW.
          if (newLevel == HttpShellRuntimeSupport.NetworkThreatLevel.LOW && newLevel != oldLevel) {
            refilterPolicy = RefilterPolicy.ACCEPT_OLD;
          } else if (oldLevel == HttpShellRuntimeSupport.NetworkThreatLevel.LOW
              && newLevel != oldLevel) {
            refilterPolicy = RefilterPolicy.RE_FILTER;
          }
        });
    runtimeSupportRef.addPhysicalThreatLevelListener(
        (oldLevel, newLevel) -> {
          if (newLevel != oldLevel && newLevel == HttpShellRuntimeSupport.PhysicalThreatLevel.LOW) {
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
          registration.callback());
    }
  }

  /**
   * Registers a navigation category.
   *
   * <p>The category is added to the page maker so related pages appear in the navigation menu.
   * Callers should supply stable identifiers; no synchronization beyond the internal {@link
   * PageMaker} handling is required.
   *
   * @param link navigation link target, typically a path prefix owned by the feature.
   * @param name short category name shown in menus; should be unique within its level.
   * @param title descriptive title used for tooltips or extended labels; may be {@code null}.
   */
  public void registerMenu(String link, String name, String title) {
    pageMaker.addNavigationCategory(link, name, title);
  }

  /**
   * Registers a navigation category with a runtime-selected fallback root.
   *
   * <p>The page maker uses {@code link} when {@code primaryLinkEnabled} allows it for the current
   * request, otherwise it renders {@code fallbackLink}. This is useful for category roots that
   * should prefer a script-backed primary UI only when that UI is currently advertised.
   *
   * @param link primary navigation target
   * @param name short category name shown in menus; should be unique within its level
   * @param title descriptive title used for tooltips or extended labels; may be {@code null}
   * @param fallbackLink alternate navigation target when {@code link} is not enabled
   * @param primaryLinkEnabled callback deciding whether the primary target is usable
   */
  public void registerMenu(
      String link,
      String name,
      String title,
      String fallbackLink,
      LinkEnabledCallback primaryLinkEnabled) {
    pageMaker.addNavigationCategory(link, name, title, fallbackLink, primaryLinkEnabled);
  }

  /**
   * Registers a navigation category with a runtime-selected fallback root and access scoping.
   *
   * <p>The {@code fullOnly} flag is consulted only when the root would be rendered without visible
   * child links.
   *
   * @param link primary navigation target
   * @param name short category name shown in menus; should be unique within its level
   * @param title descriptive title used for tooltips or extended labels; may be {@code null}
   * @param fallbackLink alternate navigation target when {@code link} is not enabled
   * @param fullOnly whether a root-only category requires full-access permission
   * @param primaryLinkEnabled callback deciding whether the primary target is usable
   */
  @SuppressWarnings("unused")
  public void registerMenu(
      String link,
      String name,
      String title,
      String fallbackLink,
      boolean fullOnly,
      LinkEnabledCallback primaryLinkEnabled) {
    pageMaker.addNavigationCategory(link, name, title, fallbackLink, fullOnly, primaryLinkEnabled);
  }

  /**
   * Registers a navigation category with runtime-selected target and visibility.
   *
   * <p>{@code primaryLinkEnabled} controls whether the primary or fallback target is rendered.
   * {@code rootLinkEnabled} controls whether the category root link is rendered; child links can
   * still keep the category visible.
   *
   * @param link primary navigation target
   * @param name short category name shown in menus; should be unique within its level
   * @param title descriptive title used for tooltips or extended labels; may be {@code null}
   * @param fallbackLink alternate navigation target when {@code link} is not enabled
   * @param fullOnly whether a root category with no visible children requires full-access
   *     permission
   * @param primaryLinkEnabled callback deciding whether the primary target is usable
   * @param rootLinkEnabled callback deciding whether the root link should render
   */
  public void registerMenu(
      String link,
      String name,
      String title,
      String fallbackLink,
      boolean fullOnly,
      LinkEnabledCallback primaryLinkEnabled,
      LinkEnabledCallback rootLinkEnabled) {
    pageMaker.addNavigationCategory(
        link, name, title, fallbackLink, fullOnly, primaryLinkEnabled, rootLinkEnabled);
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
    network.crypta.clients.http.HttpShellRuntimeSupport runtimeSupportLocal = this.runtimeSupport;
    if (runtimeSupportLocal == null
        || !runtimeSupportLocal.canRedirectToWizard()
        || fproxyHasCompletedWizard) {
      return false;
    }
    return !isWizardPathAllowed(path);
  }

  private boolean isWizardPathAllowed(String path) {
    return path.startsWith(FirstTimeWizardToadlet.TOADLET_URL)
        || path.startsWith(FirstTimeWizardNewToadlet.TOADLET_URL)
        || path.startsWith(StaticToadlet.ROOT_URL)
        || path.startsWith(LegacyHttpPaths.EXTERNAL_LINK_PATH)
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
   * Returns the detached user-alert surface associated with the current runtime support.
   *
   * <p>The alert surface exposes node warnings and informational banners to the UI and handles
   * their dismissal state. When runtime support has not yet been assigned this method returns
   * {@code null}; callers should therefore wait until after {@link
   * #setRuntimeSupport(HttpShellRuntimeSupport)} is invoked.
   *
   * @return active {@link UserAlertSurface}, or {@code null} when unavailable.
   */
  public UserAlertSurface getUserAlertManager() {
    network.crypta.clients.http.HttpShellRuntimeSupport runtimeSupportRef = this.runtimeSupport;
    if (runtimeSupportRef == null) return null;
    return runtimeSupportRef.userAlerts();
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
    requireRuntimeSupport().storeConfig();
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
  public void enableFProxyJavascript(boolean b) {
    String previousUiRoot;
    synchronized (this) {
      if (fProxyJavascriptEnabled == b) {
        return;
      }
      previousUiRoot = primaryUiRoot();
      fProxyJavascriptEnabled = b;
    }
    notifyPrimaryUiRootChangedIfStarted(previousUiRoot);
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
    network.crypta.clients.http.HttpShellRuntimeSupport runtimeSupportRef = this.runtimeSupport;
    if (runtimeSupportRef == null) return "";
    return runtimeSupportRef.formPassword();
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
   * @return {@link BookmarkManagerHandle} instance or {@code null} when not yet available.
   */
  public BookmarkManagerHandle getBookmarkManager() {
    return bookmarkManager;
  }

  /**
   * Convenience alias for {@link #getBookmarkManager()}.
   *
   * <p>Provided for compatibility with older call sites that referenced the shorter name.
   *
   * @return bookmark handle instance or {@code null}.
   */
  public BookmarkManagerHandle getBookmarks() {
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
  @SuppressWarnings("unused")
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
   * the node instance and exposed here for convenience.
   *
   * @return shared {@link Ticker}; never {@code null} after runtime support is published.
   */
  public Ticker getTicker() {
    return requireRuntimeSupport().ticker();
  }

  private network.crypta.clients.http.HttpShellRuntimeSupport requireRuntimeSupport() {
    return Objects.requireNonNull(runtimeSupport);
  }

  private LegacyHttpRouteRegistrar requireRouteRegistrar() {
    return Objects.requireNonNull(routeRegistrar);
  }

  private RefilterPolicy refilterPolicy;

  /**
   * Returns the active refilter policy applied to request processing.
   *
   * <p>The policy is updated in response to threat-level changes to balance usability with
   * security. Caller should treat the value as read-only.
   *
   * @return current {@link RefilterPolicy} value.
   */
  @Override
  public RefilterPolicy getReFilterPolicy() {
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

  String getLocalAdminURL() {
    return getURL(localAdminUrlHost(bindTo));
  }

  @Override
  public String getURL(String host) {
    StringBuilder sb = new StringBuilder();
    if (ssl) sb.append("https");
    else sb.append("http");
    sb.append("://");
    if (host == null) host = IPV4_LOOPBACK_HOST;
    sb.append(host);
    sb.append(":");
    sb.append(this.port);
    sb.append("/");
    return sb.toString();
  }

  private static String localAdminUrlHost(String configuredBindTo) {
    if (configuredBindTo == null || configuredBindTo.isBlank()) {
      return IPV4_LOOPBACK_HOST;
    }
    StringTokenizer hosts = new StringTokenizer(configuredBindTo, ",");
    boolean localhostBound = false;
    boolean ipv6LoopbackBound = false;
    while (hosts.hasMoreTokens()) {
      String host = hosts.nextToken();
      String normalizedHost = normalizeBindHost(host);
      if (isIpv4LocalAdminBindHost(normalizedHost)) {
        return IPV4_LOOPBACK_HOST;
      }
      if (LOCALHOST_HOST.equalsIgnoreCase(normalizedHost)) {
        localhostBound = true;
      }
      if (isIpv6LocalAdminBindHost(normalizedHost)) {
        ipv6LoopbackBound = true;
      }
    }
    if (localhostBound) {
      return LOCALHOST_HOST;
    }
    if (ipv6LoopbackBound) {
      return IPV6_LOOPBACK_URL_HOST;
    }
    return IPV4_LOOPBACK_HOST;
  }

  private static String normalizeBindHost(String host) {
    String trimmed = host == null ? "" : host.trim();
    if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
      return trimmed.substring(1, trimmed.length() - 1);
    }
    return trimmed;
  }

  private static boolean isIpv4LocalAdminBindHost(String host) {
    return IPV4_LOOPBACK_HOST.equals(host)
        || host.startsWith("127.")
        || IPV4_WILDCARD_HOST.equals(host);
  }

  private static boolean isIpv6LocalAdminBindHost(String host) {
    return IPV6_LOOPBACK_HOST.equalsIgnoreCase(host)
        || IPV6_LOOPBACK_HOST_EXPANDED.equalsIgnoreCase(host)
        || IPV6_WILDCARD_HOST.equals(host)
        || IPV6_WILDCARD_HOST_EXPANDED.equalsIgnoreCase(host);
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
   * @return {@link PushDataManagerHandle} instance or {@code null} if initialization has not yet
   *     created one.
   */
  public PushDataManagerHandle getPushDataManager() {
    return pushDataManager;
  }
}

package network.crypta.node;

import static java.util.concurrent.TimeUnit.MINUTES;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Properties;
import java.util.UUID;
import network.crypta.config.ConfigMigrator;
import network.crypta.config.CryptadConfig;
import network.crypta.config.FreenetFilePersistentConfig;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.PersistentConfig;
import network.crypta.config.SubConfig;
import network.crypta.crypt.JceLoader;
import network.crypta.crypt.RandomSource;
import network.crypta.crypt.SSL;
import network.crypta.crypt.Yarrow;
import network.crypta.fs.AppDirs;
import network.crypta.fs.AppEnv;
import network.crypta.fs.Resolved;
import network.crypta.fs.ServiceDirs;
import network.crypta.support.JVMVersion;
import network.crypta.support.Logging;
import network.crypta.support.PooledExecutor;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.ProcessPriority;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.io.NativeThread;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.tanukisoftware.wrapper.WrapperListener;
import org.tanukisoftware.wrapper.WrapperManager;
import picocli.CommandLine;

/**
 * Bridges the Tanuki Wrapper lifecycle and the Crypta node.
 *
 * <p>NodeStarter wires process lifecycle callbacks (start, stop, control events) from the native
 * Wrapper into the Java node. It also provides helpers for test environments and OSGi entry points.
 * Only one instance is created per JVM.
 *
 * @author nextgens
 */
public class NodeStarter implements WrapperListener {
  private static final Logger LOG = LoggerFactory.getLogger(NodeStarter.class);

  // Platform-dependent legacy constant removed; source control retains history.

  /*---------------------------------------------------------------
   * Constructors
   *-------------------------------------------------------------*/
  private NodeStarter() {
    // Force it to load right now, and log what exactly is loaded.
    JceLoader.dumpLoaded();
  }

  /**
   * Returns whether this JVM was initialized for testing via {@link #globalTestInit}.
   *
   * <p>When {@code true}, the process is in a test/simulator VM. When {@code false}, it is a
   * regular node process. This method is valid only after startup has begun.
   *
   * @return {@code true} when running in a testing VM; otherwise {@code false}
   * @throws IllegalStateException if called before startup initializes the flag
   */
  public static synchronized boolean isTestingVM() {
    if (isStarted) {
      return isTestingVM;
    } else {
      throw new IllegalStateException();
    }
  }

  /*---------------------------------------------------------------
   * Main Method
   *-------------------------------------------------------------*/
  /**
   * Process entrypoint. Delegates to the native Wrapper which invokes {@link #start(String[])}.
   *
   * @param args command-line arguments forwarded to the application
   */
  public static void main(String[] args) {
    // Enter background mode early so class loading also uses reduced priority.
    ProcessPriority.enterBackgroundMode();

    // Start the application. If launched by the native Wrapper, it will call start(); otherwise
    // start() is called immediately here.
    WrapperManager.start(new NodeStarter(), args);
  }

  /**
   * Initializes a testing VM. This is VM-scoped state; multiple nodes may be created afterward.
   *
   * @param baseDirectory directory for test data; created if missing (caller cleans up)
   * @param enablePlug when {@code true}, starts a background keep-alive thread
   * @param logThreshold minimum log level for test logging
   * @param details optional logging details string (may be {@code null})
   * @param noDNS when {@code true}, disables DNS requests in tests
   * @param randomSource random source to use; when {@code null}, a new {@link Yarrow} is created
   * @return the {@link RandomSource} in use (either {@code randomSource} or a new {@link Yarrow})
   * @throws IllegalStateException if called more than once per JVM
   *     <p>Side effects:
   *     <ul>
   *       <li>Bootstraps logging for test/simulator environments.
   *       <li>Sets {@code networkaddress.cache.ttl} and {@code networkaddress.cache.negative.ttl}
   *           to {@code 0} to avoid DNS caching.
   *       <li>Optionally spawns a keep-alive thread to prevent idle exits.
   *     </ul>
   */
  public static RandomSource globalTestInit(
      File baseDirectory,
      boolean enablePlug,
      org.slf4j.event.Level logThreshold,
      String details,
      boolean noDNS,
      RandomSource randomSource) {

    synchronized (NodeStarter.class) {
      if (isStarted) {
        throw new IllegalStateException();
      }
      isStarted = true;
      isTestingVM = true;
    }

    ensureDirectoryExists(baseDirectory);

    // Configure SLF4J logging for tests/simulator environments.
    Logging.bootstrap(logThreshold, details);

    // Do not cache DNS results; tests often rely on dynamic hostnames.
    Security.setProperty("networkaddress.cache.ttl", "0");
    Security.setProperty("networkaddress.cache.negative.ttl", "0");

    // Initialize RNG, defaulting to Yarrow if none supplied.
    RandomSource random = randomSource != null ? randomSource : new Yarrow();

    if (enablePlug) {
      startKeepAlivePlugThread();
    }

    DNSRequester.disable = noDNS;

    return random;
  }

  private static void ensureDirectoryExists(File dir) {
    if (!dir.mkdir() && (!dir.exists() || !dir.isDirectory())) {
      LOG.error("Cannot create test directory");
      System.exit(NodeInitException.EXIT_TEST_ERROR);
    }
  }

  @SuppressWarnings("java:S1181")
  private static void startKeepAlivePlugThread() {
    Runnable useless =
        () -> {
          while (true) {
            try {
              //noinspection BusyWait
              Thread.sleep(MINUTES.toMillis(60));
            } catch (InterruptedException e) {
              Thread.currentThread().interrupt();
              return;
            } catch (Exception t) {
              try {
                LOG.error("Keep-alive thread caught {}", t, t);
              } catch (Throwable ignored) {
                // Ignore
              }
            }
          }
        };
    Thread plug = new Thread(useless, "Plug");
    plug.setDaemon(false);
    plug.start();
  }

  /**
   * Creates a node configured for tests using {@link TestNodeParameters}.
   *
   * @param params test parameters including ports, store size, and feature toggles
   * @return a newly created {@link Node} not yet connected to any peers
   * @throws NodeInitException if startup cannot proceed due to configuration problems
   */
  public static Node createTestNode(TestNodeParameters params) throws NodeInitException {

    synchronized (NodeStarter.class) {
      if ((!isStarted) || (!isTestingVM)) {
        throw new IllegalStateException("Call globalTestInit() first!");
      }
    }

    File baseDir = params.getBaseDirectory();
    File portDir = new File(baseDir, Integer.toString(params.getPort()));
    if ((!portDir.mkdir()) && ((!portDir.exists()) || (!portDir.isDirectory()))) {
      LOG.error("Cannot create test directory");
      System.exit(NodeInitException.EXIT_TEST_ERROR);
    }

    // Set up config for testing.
    SimpleFieldSet configFS = new SimpleFieldSet(false); // Built once per simulation run.
    if (params.getOutputBandwidthLimit() > 0) {
      configFS.put("node.outputBandwidthLimit", params.getOutputBandwidthLimit());
      configFS.put("node.throttleLocalTraffic", true);
    } else {
      // Even with throttleLocalTraffic=false, requests count in NodeStats.
      // Set an extremely high outputBandwidthLimit to avoid throttling.
      configFS.put("node.outputBandwidthLimit", 16 * 1024 * 1024);
      configFS.put("node.throttleLocalTraffic", false);
    }
    configFS.put("node.useSlashdotCache", params.isUseSlashdotCache());
    configFS.put("node.listenPort", params.getPort());
    configFS.put("node.disableProbabilisticHTLs", params.isDisableProbabilisticHTLs());
    configFS.put("fproxy.enabled", false);
    configFS.put("fcp.enabled", params.isEnableFCP());
    configFS.put("fcp.port", 9481);
    configFS.put("fcp.ssl", false);
    configFS.put("pluginmanager.enabled", params.isEnablePlugins());
    configFS.put("console.enabled", false);
    configFS.putSingle("pluginmanager.loadplugin", "");
    configFS.put("node.updater.enabled", false);
    configFS.putSingle("node.install.tempDir", new File(portDir, "temp").toString());
    configFS.putSingle("node.install.storeDir", new File(portDir, "store").toString());
    configFS.put("fcp.persistentDownloadsEnabled", false);
    configFS.putSingle("node.throttleFile", new File(portDir, "throttle.dat").toString());
    configFS.putSingle("node.install.nodeDir", portDir.toString());
    configFS.putSingle("node.install.userDir", portDir.toString());
    configFS.putSingle("node.install.runDir", portDir.toString());
    configFS.putSingle("node.install.cfgDir", portDir.toString());
    configFS.put("node.maxHTL", params.getMaxHTL());
    configFS.put("node.testingDropPacketsEvery", params.getDropProb());
    configFS.put("node.alwaysAllowLocalAddresses", true);
    configFS.put("node.includeLocalAddressesInNoderefs", true);
    configFS.put("node.enableARKs", false);
    configFS.put("node.load.threadLimit", params.getThreadLimit());
    if (params.isRamStore()) {
      configFS.putSingle("node.storeType", "ram");
    }
    configFS.put("node.storeSize", params.getStoreSize());
    configFS.put("node.disableHangCheckers", true);
    configFS.put("node.enableSwapping", params.isEnableSwapping());
    configFS.put("node.enableSwapQueueing", params.isEnableSwapQueueing());
    configFS.put("node.enableARKs", params.isEnableARKs());
    configFS.put("node.enableULPRDataPropagation", params.isEnableULPRs());
    configFS.put("node.enablePerNodeFailureTables", params.isEnablePerNodeFailureTables());
    configFS.put("node.enablePacketCoalescing", params.isEnablePacketCoalescing());
    configFS.put("node.publishOurPeersLocation", params.isEnableFOAF());
    configFS.put("node.routeAccordingToOurPeersLocation", params.isEnableFOAF());
    configFS.put("node.opennet.enabled", params.getOpennetPort() > 0);
    configFS.put("node.opennet.listenPort", params.getOpennetPort());
    configFS.put("node.opennet.alwaysAllowLocalAddresses", true);
    configFS.put("node.opennet.oneConnectionPerIP", false);
    configFS.put("node.opennet.assumeNATed", true);
    configFS.put("node.opennet.connectToSeednodes", params.isConnectToSeednodes());
    configFS.put("node.encryptTempBuckets", false);
    configFS.put("node.encryptPersistentTempBuckets", false);
    configFS.put("node.enableRoutedPing", true);
    if (params.getIpAddressOverride() != null) {
      configFS.putSingle("node.ipAddressOverride", params.getIpAddressOverride());
    }
    if (params.isLongPingTimes()) {
      configFS.put("node.maxPingTime", 100000);
      configFS.put("node.subMaxPingTime", 50000);
    }
    configFS.put("node.respondBandwidth", true);
    configFS.put("node.respondBuild", true);
    configFS.put("node.respondIdentifier", true);
    configFS.put("node.respondLinkLengths", true);
    configFS.put("node.respondLocation", true);
    configFS.put("node.respondStoreSize", true);
    configFS.put("node.respondUptime", true);

    PersistentConfig config = new PersistentConfig(configFS);

    Node node =
        new Node(config, params.getRandom(), params.getRandom(), null, params.getExecutor());

    // All testing environments connect the nodes as they want, even if the old setup is restored,
    // it is not desired.
    node.getPeers().removeAllPeers();

    return node;
  }

  // Experimental OSGi support.
  @SuppressWarnings({"unused", "java:S100"})
  public static void start_osgi(String[] args) {
    nodestarter_osgi = new NodeStarter();
    nodestarter_osgi.start(args);
  }

  /*---------------------------------------------------------------
   * WrapperListener Methods
   *-------------------------------------------------------------*/

  // Experimental OSGi support.
  @SuppressWarnings({"unused", "java:S100"})
  public static void stop_osgi(int exitCode) {
    nodestarter_osgi.stop(exitCode);
    nodestarter_osgi = null;
  }

  /**
   * Returns the memory limit in mebibytes.
   *
   * <p>Special values: {@code -1} when unknown, {@code -2} when unlimited. Values round down to the
   * nearest MiB. Extremely large limits above {@code Integer.MAX_VALUE} MiB are reported as
   * unknown.
   *
   * @return memory limit in MiB, {@code -1} unknown, or {@code -2} unlimited
   */
  public static long getMemoryLimitMB() {
    long limit = getMemoryLimitBytes();
    if (limit <= 0) {
      return limit;
    }
    if (limit == Long.MAX_VALUE) {
      return -2;
    }
    limit /= (1024 * 1024);
    if (limit > Integer.MAX_VALUE) {
      // Note: values above ~2TB are reported as unknown (-1) due to int return limits.
      return -1;
    }
    return limit;
  }

  /**
   * Returns the JVM memory limit in bytes, or {@code -1} when unknown.
   *
   * <p>Some JVMs historically reported the limit in MiB. This method compensates by treating small
   * values as MiB and converting to bytes.
   *
   * @return memory limit in bytes, or {@code -1} when unknown
   */
  public static long getMemoryLimitBytes() {
    long maxMemory = Runtime.getRuntime().maxMemory();
    if (maxMemory == Long.MAX_VALUE) {
      return maxMemory;
    } else if (maxMemory <= 0) {
      return -1;
    } else {
      if (maxMemory < (1024 * 1024)) {
        // Some weird buggy JVMs provide this number in MB IIRC?
        return maxMemory * 1024 * 1024;
      }
      return maxMemory;
    }
  }

  /**
   * Heuristic 32-bit check for the runtime environment.
   *
   * <p>Returns {@code true} when indicators suggest a 32-bit setup. On Windows this may always
   * return {@code true} due to wrapper specifics.
   *
   * @return {@code true} if a 32-bit environment is detected
   */
  public static boolean isSomething32bits() {
    Properties wrapperProperties = WrapperManager.getProperties();
    return !JVMVersion.is32Bit()
        && !wrapperProperties.getProperty("wrapper.java.additional.auto_bits").startsWith("32");
  }

  /**
   * Returns a lazily-initialized process-wide {@link SecureRandom} and ensures it seeds eagerly.
   *
   * @return shared {@link SecureRandom} instance
   */
  public static synchronized SecureRandom getGlobalSecureRandom() {
    if (globalSecureRandom == null) {
      globalSecureRandom = new SecureRandom();
      globalSecureRandom.nextBytes(
          new byte[16]); // Force it to seed itself so it blocks now not later.
    }
    return globalSecureRandom;
  }

  /**
   * Returns this instance. Used by environments that require a direct reference (e.g., OSGi).
   *
   * @return this {@link NodeStarter}
   */
  public NodeStarter get() {
    return this;
  }

  /**
   * Print resolved directories to stdout to help users understand where files are stored. Includes
   * the configuration file path and the resolved config, data, cache, run, and logs directories.
   * Reflects environment detection (service vs user) and CLI overrides.
   */
  private static void printResolvedDirectories(Resolved r, File configFile, boolean serviceMode) {
    try {
      LOG.info(
          """
          Resolved directories ({} mode):
            Config file:  {}
            Config dir:   {}
            Data dir:     {}
            Cache dir:    {}
            Run dir:      {}
            Logs dir:     {}
          """,
          (serviceMode ? "service" : "user"),
          configFile.getAbsolutePath(),
          r.getConfigDir(),
          r.getDataDir(),
          r.getCacheDir(),
          r.getRunDir(),
          r.getLogsDir());
    } catch (Throwable t) {
      // Do not fail startup due to logging
    }
  }

  /**
   * The start method is called when the WrapperManager is signaled by the native wrapper code that
   * it can start its application. This method call is expected to return, so a new thread should be
   * launched if necessary.
   *
   * <p>CLI uses picocli. Standard help/version flags are supported, plus options for directory
   * overrides and service/user mode selection.
   *
   * <p>Supported CLI options: - <code>-h</code>, <code>--help</code>: Show usage help - <code>-V
   * </code>, <code>--version</code>: Show version information - <code>-c</code>, <code>
   * --config-file FILE</code>: Explicit <code>cryptad.ini</code> path - <code>-C</code>, <code>
   * --config-dir PATH</code>: Override configuration directory - <code>-d</code>, <code>
   * --data-dir PATH</code>: Override data directory - <code>-x</code>, <code>--cache-dir PATH
   * </code>: Override cache directory - <code>-r</code>, <code>--run-dir PATH</code>: Override run
   * directory - <code>-L</code>, <code>--logs-dir PATH</code>: Override logs directory - <code>-m
   * </code>, <code>--service-mode service|user</code>: Explicitly set service mode - <code>
   * --service</code>, <code>--daemon</code>: Shortcut for service mode - <code>--user
   * </code>, <code>--app</code>: Shortcut for user/app mode - positional <code>FILE</code>:
   * Alternative way to specify <code>cryptad.ini</code>
   *
   * @param args List of arguments used to initialize the application.
   * @return Any error code if the application should exit on completion of the start method. If
   *     there were no problems then this method should return null.
   */
  @Override
  public Integer start(String[] args) {
    synchronized (NodeStarter.class) {
      if (isStarted) {
        throw new IllegalStateException();
      }
      isStarted = true;
      isTestingVM = false;
    }

    NodeCli cli = new NodeCli();
    CommandLine cmd = new CommandLine(cli);
    cmd.setExecutionExceptionHandler(new NodeCli.PrettyExceptionHandler());
    Integer earlyExit = handleCliAndMaybeExit(args, cmd);
    if (earlyExit != null) {
      return earlyExit;
    }

    Map<String, String> overrides = cli.directoryOverrides();
    File explicitConfigFile = cli.explicitConfigFile();
    String serviceModeOverride = cli.serviceModeOverride();
    if (serviceModeOverride != null) {
      System.setProperty("cryptad.service.mode", serviceModeOverride.toLowerCase());
    }

    AppEnv appEnv = new AppEnv();
    boolean serviceMode = appEnv.isServiceMode();
    Path configDirPath = resolveConfigDirPath(overrides, serviceMode);
    File configFilename =
        Objects.requireNonNullElseGet(
            explicitConfigFile, () -> configDirPath.resolve("cryptad.ini").toFile());

    migrateConfigQuietly(overrides, serviceMode);

    // Do not cache DNS results; nodes are often accessed via dynamic hostnames.
    Security.setProperty("networkaddress.cache.ttl", "0");
    Security.setProperty("networkaddress.cache.negative.ttl", "0");

    FreenetFilePersistentConfig cfg;
    try {
      LOG.info("Loading configuration from {}", configFilename);
      cfg = loadConfig(configFilename, overrides, serviceMode, appEnv);
    } catch (IOException e) {
      LOG.error("Configuration load failed: {}", e, e);
      return -1;
    }

    LoggingConfigHandler logConfigHandler;
    try {
      logConfigHandler = setupLogging(cfg);
    } catch (InvalidConfigValueException e) {
      LOG.error("Logging setup failed: {}", e.getMessage(), e);
      return -2;
    }

    PooledExecutor executor = startExecutor();

    // Extend wrapper startup timeout to 500000 ms. Diffie-Hellman init can be slow on some hosts.
    WrapperManager.signalStarting(500000);

    startKeepAliveNativePlugThread();

    initSSL(cfg);

    try {
      node = new Node(cfg, null, null, this, executor);
      installSeednodesIfMissing(node);
      node.start(false);
      LOG.info("Node initialization completed");
    } catch (NodeInitException e) {
      LOG.error("Node load failed (exitCode={}): {}", e.exitCode, e.getMessage(), e);
      System.exit(e.exitCode);
    }

    return null;
  }

  private Integer handleCliAndMaybeExit(String[] args, CommandLine cmd) {
    try {
      CommandLine.ParseResult parseResult = cmd.parseArgs(args);
      if (parseResult.isVersionHelpRequested()) {
        cmd.printVersionHelp(cmd.getOut());
        return 0;
      }
      if (parseResult.isUsageHelpRequested()) {
        cmd.usage(cmd.getOut());
        return 0;
      }
      return null;
    } catch (CommandLine.ParameterException ex) {
      cmd.getErr().println("Error: " + ex.getMessage());
      cmd.getErr().println();
      cmd.usage(cmd.getErr());
      return CommandLine.ExitCode.USAGE;
    }
  }

  private static Path resolveConfigDirPath(Map<String, String> overrides, boolean serviceMode) {
    if (serviceMode) {
      ServiceDirs svc = new ServiceDirs(overrides);
      Resolved r = svc.resolve();
      return r.getConfigDir();
    } else {
      AppDirs dirs = new AppDirs(overrides);
      Resolved r = dirs.resolve();
      return r.getConfigDir();
    }
  }

  private void migrateConfigQuietly(Map<String, String> overrides, boolean serviceMode) {
    try {
      Resolved ar;
      if (serviceMode) {
        ServiceDirs svc = new ServiceDirs(overrides);
        ar = svc.resolve();
      } else {
        AppDirs dirs = new AppDirs(overrides);
        ar = dirs.resolve();
      }
      Path exeDir = getExecutableDir();
      ConfigMigrator.migrateIfNeeded(ar, exeDir);
    } catch (Exception e) {
      LOG.warn("Config migration error: {}", e.getMessage());
    }
  }

  private static FreenetFilePersistentConfig loadConfig(
      File configFilename, Map<String, String> overrides, boolean serviceMode, AppEnv appEnv)
      throws IOException {
    Path cfgPath = configFilename.toPath();
    Resolved resolved;
    if (serviceMode) {
      ServiceDirs svc = new ServiceDirs(overrides);
      resolved = svc.resolve();
    } else {
      Map<String, String> sysMap = new HashMap<>();
      Properties props = System.getProperties();
      for (Entry<Object, Object> e : props.entrySet()) {
        sysMap.put(String.valueOf(e.getKey()), String.valueOf(e.getValue()));
      }
      // Pass parameters matching AppDirs(env, systemProperties, cliOverrides, appEnv)
      AppDirs dirs = new AppDirs(System.getenv(), sysMap, overrides, appEnv);
      resolved = dirs.resolve();
    }
    printResolvedDirectories(resolved, configFilename, serviceMode);
    SimpleFieldSet sfs =
        CryptadConfig.loadExpandingPlaceholders(cfgPath, resolved, System.getProperties());
    File tmp = new File(configFilename.getPath() + ".tmp");
    return new FreenetFilePersistentConfig(sfs, configFilename, tmp);
  }

  private static LoggingConfigHandler setupLogging(FreenetFilePersistentConfig cfg)
      throws InvalidConfigValueException {
    LOG.info("Creating logger configuration...");
    SubConfig loggingConfig = cfg.createSubConfig("logger");
    return new LoggingConfigHandler(loggingConfig);
  }

  private static PooledExecutor startExecutor() {
    LOG.info("Starting executor");
    PooledExecutor executor = new PooledExecutor();
    executor.start();
    return executor;
  }

  @SuppressWarnings("java:S1181")
  private static void startKeepAliveNativePlugThread() {
    Runnable r =
        () -> {
          while (true) {
            try {
              //noinspection BusyWait
              Thread.sleep(MINUTES.toMillis(60));
            } catch (InterruptedException e) {
              Thread.currentThread().interrupt();
              return;
            } catch (Exception t) {
              try {
                LOG.error("Keep-alive thread caught {}", t, t);
              } catch (Throwable ignored) {
                // Ignore
              }
            }
          }
        };
    NativeThread plug =
        new NativeThread(r, "Plug", NativeThread.PriorityLevel.MAX_PRIORITY.value, false);
    plug.setDaemon(false);
    plug.start();
  }

  private static void initSSL(FreenetFilePersistentConfig cfg) {
    SubConfig sslConfig = cfg.createSubConfig("ssl");
    SSL.init(sslConfig);
  }

  @SuppressWarnings("java:S1181")
  private static void installSeednodesIfMissing(Node node) {
    try {
      File seedFile = NodeFile.SEEDNODES.getFile(node);
      if (!seedFile.exists()) {
        try (java.io.InputStream in =
            NodeStarter.class.getResourceAsStream("/seednodes/seednodes.fref")) {
          if (in != null) {
            java.nio.file.Files.createDirectories(seedFile.getParentFile().toPath());
            java.nio.file.Files.copy(in, seedFile.toPath());
            LOG.info("Installed default seednodes from resource at {}", seedFile.getAbsolutePath());
          } else {
            LOG.warn(
                "No default seednodes.fref found in resources; opennet bootstrap may be delayed.");
          }
        }
      }
    } catch (Throwable t) {
      try {
        LOG.error("Default seednodes install failed", t);
      } catch (Throwable ignored) {
        // ignored
      }
    }
  }

  private Path getExecutableDir() {
    try {
      URL url = NodeStarter.class.getProtectionDomain().getCodeSource().getLocation();
      Path p = Paths.get(url.toURI());
      if (p.toFile().isFile()) {
        return p.getParent();
      }
      return p;
    } catch (Exception e) {
      return Paths.get("").toAbsolutePath();
    }
  }

  /**
   * Called when the application is shutting down. The Wrapper assumes that this method will return
   * fairly quickly. If the shutdown code could take a long time, then
   * WrapperManager.signalStopping() should be called to extend the timeout period. If for some
   * reason, the stop method can not return, then it must call WrapperManager.stopped() to avoid
   * warning messages from the Wrapper.
   *
   * @param exitCode The suggested exit code that will be returned to the OS when the JVM exits.
   * @return The exit code to actually return to the OS. In most cases, this should just be the
   *     value of exitCode, however the user code has the option of changing the exit code if there
   *     are any problems during shutdown.
   */
  @Override
  public int stop(int exitCode) {
    LOG.info("Shutting down with exit code {}", exitCode);
    node.park();
    // Extend wrapper shutdown timeout to 120000 ms (see #354).
    WrapperManager.signalStopping(120000);

    return exitCode;
  }

  public void restart() {
    WrapperManager.restart();
  }

  /**
   * Called whenever the native wrapper code traps a system control signal against the Java process.
   * It is up to the callback to take any actions necessary. Possible values are:
   * WrapperManager.WRAPPER_CTRL_C_EVENT, WRAPPER_CTRL_CLOSE_EVENT, WRAPPER_CTRL_LOGOFF_EVENT, or
   * WRAPPER_CTRL_SHUTDOWN_EVENT
   *
   * @param event The system control signal.
   */
  @Override
  public void controlEvent(int event) {
    if (WrapperManager.isControlledByNativeWrapper()) {
      // The Wrapper will take care of this event
      return;
    }
    // We are not being controlled by the Wrapper, so handle the event ourselves.
    if ((event == WrapperManager.WRAPPER_CTRL_C_EVENT)
        || (event == WrapperManager.WRAPPER_CTRL_CLOSE_EVENT)
        || (event == WrapperManager.WRAPPER_CTRL_SHUTDOWN_EVENT)) {
      WrapperManager.stop(0);
    }
  }

  /**
   * Parameters for constructing a test node.
   *
   * <p>All fields are optional unless otherwise noted. Defaults favor a lightweight, local-only
   * configuration suitable for simulations.
   */
  public static final class TestNodeParameters {

    private int port;
    private int opennetPort;
    private File baseDirectory = new File("crypta-test-node-" + UUID.randomUUID());
    private boolean disableProbabilisticHTLs;
    private short maxHTL;
    private int dropProb;
    private RandomSource random;
    private PriorityAwareExecutor executor;
    private int threadLimit = 500;
    private long storeSize;
    private boolean ramStore;
    private boolean enableSwapping;
    private boolean enableARKs;
    private boolean enableULPRs;
    private boolean enablePerNodeFailureTables;
    private boolean enableSwapQueueing;
    private boolean enablePacketCoalescing;
    private int outputBandwidthLimit;
    private boolean enableFOAF;
    private boolean connectToSeednodes;
    private boolean longPingTimes;
    private boolean useSlashdotCache;
    private String ipAddressOverride;
    private boolean enableFCP;
    private boolean enablePlugins;

    public int getPort() {
      return port;
    }

    public void setPort(int port) {
      this.port = port;
    }

    public int getOpennetPort() {
      return opennetPort;
    }

    public void setOpennetPort(int opennetPort) {
      this.opennetPort = opennetPort;
    }

    public File getBaseDirectory() {
      return baseDirectory;
    }

    public void setBaseDirectory(File baseDirectory) {
      this.baseDirectory = baseDirectory;
    }

    public boolean isDisableProbabilisticHTLs() {
      return disableProbabilisticHTLs;
    }

    public void setDisableProbabilisticHTLs(boolean v) {
      this.disableProbabilisticHTLs = v;
    }

    public short getMaxHTL() {
      return maxHTL;
    }

    public void setMaxHTL(short maxHTL) {
      this.maxHTL = maxHTL;
    }

    public int getDropProb() {
      return dropProb;
    }

    public void setDropProb(int dropProb) {
      this.dropProb = dropProb;
    }

    public RandomSource getRandom() {
      return random;
    }

    public void setRandom(RandomSource random) {
      this.random = random;
    }

    public PriorityAwareExecutor getExecutor() {
      return executor;
    }

    public void setExecutor(PriorityAwareExecutor executor) {
      this.executor = executor;
    }

    public int getThreadLimit() {
      return threadLimit;
    }

    public void setThreadLimit(int threadLimit) {
      this.threadLimit = threadLimit;
    }

    public long getStoreSize() {
      return storeSize;
    }

    public void setStoreSize(long storeSize) {
      this.storeSize = storeSize;
    }

    public boolean isRamStore() {
      return ramStore;
    }

    public void setRamStore(boolean ramStore) {
      this.ramStore = ramStore;
    }

    public boolean isEnableSwapping() {
      return enableSwapping;
    }

    public void setEnableSwapping(boolean enableSwapping) {
      this.enableSwapping = enableSwapping;
    }

    public boolean isEnableARKs() {
      return enableARKs;
    }

    public void setEnableARKs(boolean enableARKs) {
      this.enableARKs = enableARKs;
    }

    public boolean isEnableULPRs() {
      return enableULPRs;
    }

    public void setEnableULPRs(boolean enableULPRs) {
      this.enableULPRs = enableULPRs;
    }

    public boolean isEnablePerNodeFailureTables() {
      return enablePerNodeFailureTables;
    }

    public void setEnablePerNodeFailureTables(boolean v) {
      this.enablePerNodeFailureTables = v;
    }

    public boolean isEnableSwapQueueing() {
      return enableSwapQueueing;
    }

    public void setEnableSwapQueueing(boolean enableSwapQueueing) {
      this.enableSwapQueueing = enableSwapQueueing;
    }

    public boolean isEnablePacketCoalescing() {
      return enablePacketCoalescing;
    }

    public void setEnablePacketCoalescing(boolean enablePacketCoalescing) {
      this.enablePacketCoalescing = enablePacketCoalescing;
    }

    public int getOutputBandwidthLimit() {
      return outputBandwidthLimit;
    }

    public void setOutputBandwidthLimit(int outputBandwidthLimit) {
      this.outputBandwidthLimit = outputBandwidthLimit;
    }

    public boolean isEnableFOAF() {
      return enableFOAF;
    }

    public void setEnableFOAF(boolean enableFOAF) {
      this.enableFOAF = enableFOAF;
    }

    public boolean isConnectToSeednodes() {
      return connectToSeednodes;
    }

    public void setConnectToSeednodes(boolean connectToSeednodes) {
      this.connectToSeednodes = connectToSeednodes;
    }

    public boolean isLongPingTimes() {
      return longPingTimes;
    }

    public void setLongPingTimes(boolean longPingTimes) {
      this.longPingTimes = longPingTimes;
    }

    public boolean isUseSlashdotCache() {
      return useSlashdotCache;
    }

    public void setUseSlashdotCache(boolean useSlashdotCache) {
      this.useSlashdotCache = useSlashdotCache;
    }

    public String getIpAddressOverride() {
      return ipAddressOverride;
    }

    public void setIpAddressOverride(String ipAddressOverride) {
      this.ipAddressOverride = ipAddressOverride;
    }

    public boolean isEnableFCP() {
      return enableFCP;
    }

    public void setEnableFCP(boolean enableFCP) {
      this.enableFCP = enableFCP;
    }

    public boolean isEnablePlugins() {
      return enablePlugins;
    }

    @SuppressWarnings("unused")
    public void setEnablePlugins(boolean enablePlugins) {
      this.enablePlugins = enablePlugins;
    }
  }

  // experimental osgi support
  @SuppressWarnings("java:S3008")
  private static NodeStarter nodestarter_osgi = null;

  private static boolean isTestingVM;
  private static boolean isStarted;

  /** Static instance of SecureRandom, as opposed to Node's copy. @see getSecureRandom() */
  private static SecureRandom globalSecureRandom;

  private Node node;
}

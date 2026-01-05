package network.crypta.node.subsystem;

import static network.crypta.node.Node.DEFAULT_HWRNG_PATH;
import static network.crypta.node.Node.HWRNG_PATH_PROPERTY;

import java.io.File;
import java.security.SecureRandom;
import java.util.Random;
import network.crypta.clients.http.SimpleToadletServer;
import network.crypta.config.SubConfig;
import network.crypta.crypt.ECDH;
import network.crypta.crypt.RandomSource;
import network.crypta.crypt.Util;
import network.crypta.crypt.Yarrow;
import network.crypta.crypt.ciphers.Rijndael;
import network.crypta.fs.AppDirs;
import network.crypta.fs.AppEnv;
import network.crypta.fs.Resolved;
import network.crypta.fs.ServiceDirs;
import network.crypta.node.Node;
import network.crypta.node.NodeInitException;
import network.crypta.node.NodeStarter;
import network.crypta.node.ProgramDirectory;
import network.crypta.support.io.FileUtil;
import network.crypta.support.io.NativeThread;
import network.crypta.support.math.MersenneTwister;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Coordinates early node bootstrap for program directories and randomness initialization.
 *
 * <p>This class centralizes the steps that must run before the node is fully operational: it
 * chooses default directory locations, prepares persistent program directories, and configures
 * cryptographic and non-cryptographic random sources. Typical call patterns start with {@link
 * #setupProgramDirectories(SubConfig)} during configuration loading, followed by {@link
 * #setupRandomSources(RandomSource, RandomSource, SimpleToadletServer, NativeThread,
 * ProgramDirectory)} once the HTTP startup toadlet and entropy thread are available. The class also
 * surfaces a lightweight readiness flag for the PRNG so other subsystems can gate behavior.
 *
 * <p>State is mutable and not inherently thread-safe beyond volatile publication of the readiness
 * flag; callers should perform bootstrap sequencing on a single thread, then treat the getters as
 * read-only accessors. The entropy gathering thread is optional and starts only when no pre-seeded
 * random source is provided. Directory defaults differ for user-session vs service mode, using
 * {@link AppDirs} or {@link ServiceDirs} respectively.
 *
 * <ul>
 *   <li>Responsibilities: resolve default directories, seed RNGs, and mark PRNG readiness.
 *   <li>Notable behaviors: starts entropy gathering only when needed and notifies the startup UI.
 * </ul>
 *
 * @see Node
 * @see NodeStarter
 * @see SimpleToadletServer
 */
public final class NodeBootstrap {
  private static final Logger LOG = LoggerFactory.getLogger(NodeBootstrap.class);

  private final Node node;
  private volatile boolean isPRNGReady = false;
  private RandomSource random;
  private SecureRandom secureRandom;
  private Random fastWeakRandom;

  /**
   * Creates a bootstrap coordinator bound to a specific node instance.
   *
   * <p>The provided {@link Node} is used to register program directories in configuration and to
   * resolve default locations. Construction itself performs no I/O and does not start any threads,
   * so it is safe to instantiate early during application startup. Callers are expected to invoke
   * the setup methods in the correct order (directories first, random sources next) on the same
   * thread before handing the instance to other subsystems.
   *
   * @param node owning node used to register directories and access configuration state; must not
   *     be {@code null} and must remain valid for the bootstrap lifecycle.
   */
  public NodeBootstrap(Node node) {
    this.node = node;
  }

  /**
   * Logs a one-line summary of startup environment information.
   *
   * <p>The log line includes build identifiers, JVM vendor/version, and the raw OS name and version
   * from {@link AppEnv}. The method has no return value and does not modify node state, making it
   * safe to call multiple times if the launcher repeats initialization or retries startup. Because
   * it uses system properties, callers should ensure these are stable before invocation. Any
   * exceptions are handled by the logging framework; the method itself does not throw.
   */
  public void logStartupInfo() {
    String tmp =
        "Initializing Node using Crypta v"
            + network.crypta.node.Version.currentBuildNumber()
            + "+"
            + network.crypta.node.Version.gitRevision()
            + " with "
            + System.getProperty("java.vendor")
            + " JVM version "
            + System.getProperty("java.version")
            + " running on "
            + System.getProperty("os.arch")
            + ' '
            + new AppEnv().osNameRaw()
            + ' '
            + new AppEnv().osVersionRaw();
    LOG.info(tmp);
  }

  /**
   * Resolves and registers the node's program directories with configuration defaults.
   *
   * <p>This method selects default paths based on whether the runtime is in service mode, then
   * registers the standard directory options (user, config, node data, run, and plugin) via {@link
   * Node#setupProgramDir(SubConfig, String, String, String, String)}. It returns a {@link
   * NodeProgramDirs} record containing the resolved {@link ProgramDirectory} instances. The call
   * performs filesystem setup through {@code ProgramDirectory.move}, so it may throw {@link
   * NodeInitException} when directories cannot be created or moved.
   *
   * <p>Callers should invoke this once during bootstrap before any component relies on directory
   * paths. The method is not idempotent with respect to configuration registration, so avoid
   * calling it repeatedly with different {@link SubConfig} instances.
   *
   * @param installConfig configuration section that stores directory paths and defaults; must not
   *     be {@code null} and must be writable during bootstrap.
   * @return resolved program directories for user, config, node data, run, and plugin locations.
   * @throws NodeInitException if a directory cannot be created, moved, or registered as required.
   */
  public NodeProgramDirs setupProgramDirectories(SubConfig installConfig) throws NodeInitException {
    AppEnv appEnv = new AppEnv();
    java.nio.file.Path defaultConfigDir;
    java.nio.file.Path defaultDataDir;
    java.nio.file.Path defaultRunDir;
    if (appEnv.isServiceMode()) {
      ServiceDirs serviceDirs = new ServiceDirs();
      Resolved serviceResolved = serviceDirs.resolve();
      defaultConfigDir = serviceResolved.getConfigDir();
      defaultDataDir = serviceResolved.getDataDir();
      defaultRunDir = serviceResolved.getRunDir();
    } else {
      AppDirs dirs = new AppDirs();
      Resolved appResolved = dirs.resolve();
      defaultConfigDir = appResolved.getConfigDir();
      defaultDataDir = appResolved.getDataDir();
      defaultRunDir = appResolved.getRunDir();
    }

    ProgramDirectory userDirLocal =
        node.setupProgramDir(
            installConfig,
            "userDir",
            defaultConfigDir.toString(),
            "Node.userDir",
            "Node.userDirLong");
    ProgramDirectory cfgDirLocal =
        node.setupProgramDir(
            installConfig, "cfgDir", defaultConfigDir.toString(), "Node.cfgDir", "Node.cfgDirLong");
    ProgramDirectory nodeDirLocal =
        node.setupProgramDir(
            installConfig,
            "nodeDir",
            defaultDataDir.resolve("node").toString(),
            "Node.nodeDir",
            "Node.nodeDirLong");
    ProgramDirectory runDirLocal =
        node.setupProgramDir(
            installConfig, "runDir", defaultRunDir.toString(), "Node.runDir", "Node.runDirLong");
    ProgramDirectory pluginDirLocal =
        node.setupProgramDir(
            installConfig,
            "pluginDir",
            defaultDataDir.resolve("plugins").toString(),
            "Node.pluginDir",
            "Node.pluginDirLong");
    return new NodeProgramDirs(
        userDirLocal, cfgDirLocal, nodeDirLocal, runDirLocal, pluginDirLocal);
  }

  /**
   * Creates the background thread used to gather entropy from the filesystem.
   *
   * <p>The returned {@link NativeThread} is configured with a low priority and a descriptive name.
   * It does not start automatically; callers are expected to start it only when the primary random
   * source is not yet ready. The task attempts to extend wrapper startup timeouts as it scans
   * filesystem roots, so it should be used only during early boot and not after the node is fully
   * initialized.
   *
   * @return a new, non-started entropy gathering thread ready for {@link Thread#start()}.
   */
  public NativeThread createEntropyGatheringThread() {
    return new NativeThread(
        new EntropyGatheringTask(this),
        "Entropy Gathering Thread",
        NativeThread.PriorityLevel.MIN_PRIORITY.value,
        true);
  }

  /**
   * Initializes and publishes the random sources used by the node.
   *
   * <p>If {@code r} is {@code null}, the method starts the entropy gathering thread, creates a
   * seeded {@link Yarrow} instance backed by {@code prng.seed} in {@code userDir}, and blocks for
   * ECDH initialization. Otherwise, it uses the provided {@link RandomSource} directly. The method
   * also obtains the shared {@link SecureRandom} from {@link NodeStarter}, marks the PRNG as ready,
   * and notifies the startup toadlet so the UI can drop the entropy warning. For the fast weak
   * random, {@code weakRandom} is used when provided; otherwise {@link #createRandom()} is invoked.
   *
   * <p>This method should be called once during bootstrap; subsequent calls overwrite the published
   * random instances. It is not synchronized, so callers must ensure a single-threaded startup
   * sequence.
   *
   * @param r primary cryptographic random source, or {@code null} to create a Yarrow instance.
   * @param weakRandom optional fast PRNG used for non-cryptographic sampling; {@code null} allowed.
   * @param toadlets HTTP server providing the startup toadlet for readiness notification.
   * @param entropyGatheringThread thread to start when entropy is insufficient; not started if
   *     {@code r} is non-null.
   * @param userDir program directory used to locate {@code prng.seed} for Yarrow persistence.
   */
  public void setupRandomSources(
      RandomSource r,
      RandomSource weakRandom,
      SimpleToadletServer toadlets,
      NativeThread entropyGatheringThread,
      ProgramDirectory userDir) {
    RandomSource initRandom;
    if (r == null) {
      if (LOG.isDebugEnabled())
        LOG.debug("Digest providers preloaded: {}", Util.mdProviders.size());
      Rijndael.getProviderName();

      File seed = userDir.file("prng.seed");
      FileUtil.setOwnerRW(seed);
      entropyGatheringThread.start();
      initRandom = new Yarrow(seed);
      ECDH.blockingInit();
    } else {
      initRandom = r;
    }
    SecureRandom initSecureRandom = NodeStarter.getGlobalSecureRandom();
    isPRNGReady = true;
    toadlets.getStartupToadlet().setIsPRNGReady();
    Random initFastWeak = weakRandom != null ? weakRandom : createRandom();
    random = initRandom;
    secureRandom = initSecureRandom;
    fastWeakRandom = initFastWeak;
  }

  /**
   * Returns the primary cryptographic random source selected during bootstrap.
   *
   * <p>The instance is set by {@link #setupRandomSources(RandomSource, RandomSource,
   * SimpleToadletServer, NativeThread, ProgramDirectory)} and is expected to remain stable for the
   * lifetime of the node. Callers should treat the returned reference as shared mutable state and
   * avoid replacing or reconfiguring it outside bootstrap.
   *
   * @return the configured {@link RandomSource} used for cryptographic operations.
   */
  public RandomSource random() {
    return random;
  }

  /**
   * Returns the shared process-wide {@link SecureRandom} instance.
   *
   * <p>This instance is obtained from {@link NodeStarter#getGlobalSecureRandom()} during bootstrap
   * and is intended for compatibility with APIs requiring {@code SecureRandom}. The returned object
   * is shared across the process, so callers should not attempt to reseed or replace it.
   *
   * @return the shared {@link SecureRandom} initialized by the node starter.
   */
  public SecureRandom secureRandom() {
    return secureRandom;
  }

  /**
   * Returns the fast weak random source for non-cryptographic use.
   *
   * <p>The instance is either the provided weak random source or a {@link MersenneTwister}
   * generated by {@link #createRandom()}. It is intended for quick sampling or simulation, not for
   * cryptographic security. The returned value may be {@code null} until {@link
   * #setupRandomSources(RandomSource, RandomSource, SimpleToadletServer, NativeThread,
   * ProgramDirectory)} has been invoked.
   *
   * @return the fast non-cryptographic {@link Random} instance used by the node.
   */
  public Random fastWeakRandom() {
    return fastWeakRandom;
  }

  /**
   * Returns whether the current runtime is detected as macOS.
   *
   * <p>The check is delegated to {@link AppEnv} and reflects the JVM's {@code os.name} properties.
   * It performs no caching and is safe to call repeatedly; it is also independent of the bootstrap
   * state. This method exists to centralize environment checks for callers that are otherwise
   * platform-neutral.
   *
   * @return {@code true} when the platform is macOS; {@code false} otherwise.
   */
  public boolean isMac() {
    return new AppEnv().isMac();
  }

  /**
   * Creates a synchronized {@link Random} seeded from the global secure random.
   *
   * <p>The method draws 16 bytes of seed material from {@link NodeStarter#getGlobalSecureRandom()}
   * and uses it to create a synchronized {@link MersenneTwister} instance. The resulting random is
   * fast but not cryptographically strong; callers should use it only for non-security-sensitive
   * operations. Each invocation returns a distinct instance.
   *
   * @return a new {@link Random} instance suitable for non-cryptographic sampling.
   */
  public Random createRandom() {
    byte[] seed = new byte[16];
    NodeStarter.getGlobalSecureRandom().nextBytes(seed);
    return MersenneTwister.createSynchronized(seed);
  }

  /**
   * Returns whether the PRNG has been marked ready during bootstrap.
   *
   * <p>This flag is set when {@link #setupRandomSources(RandomSource, RandomSource,
   * SimpleToadletServer, NativeThread, ProgramDirectory)} completes or when {@link
   * #markPrngReady()} is called explicitly. The value is volatile and intended for low-cost
   * readiness checks from other threads, such as the startup UI.
   *
   * @return {@code true} if the PRNG readiness flag has been set; {@code false} otherwise.
   */
  public boolean isPrngReady() {
    return isPRNGReady;
  }

  /**
   * Marks the PRNG readiness flag as true.
   *
   * <p>This method is a lightweight override for callers that complete PRNG initialization through
   * alternate means or after out-of-band checks. It does not notify the startup toadlet or perform
   * any additional initialization; it only updates the volatile flag.
   */
  public void markPrngReady() {
    isPRNGReady = true;
  }

  /**
   * Bundles the resolved program directory instances created during bootstrap.
   *
   * <p>This record groups the standard directory set required by the node: user configuration,
   * configuration files, node data, runtime files, and plugins. It is an immutable value type
   * returned by {@link #setupProgramDirectories(SubConfig)} and is safe to share across threads.
   *
   * @param userDir directory holding per-user configuration and state.
   * @param cfgDir directory where configuration files are stored and loaded.
   * @param nodeDir directory containing node data files and persisted state.
   * @param runDir directory for runtime-only files such as sockets or locks.
   * @param pluginDir directory containing plugin jars and plugin state.
   */
  public record NodeProgramDirs(
      ProgramDirectory userDir,
      ProgramDirectory cfgDir,
      ProgramDirectory nodeDir,
      ProgramDirectory runDir,
      ProgramDirectory pluginDir) {}

  private static final class EntropyGatheringTask implements Runnable {
    private static final int EXTEND_BY = 60 * 60 * 1000;
    private final NodeBootstrap bootstrap;
    private long tLastAdded = -1;

    private EntropyGatheringTask(NodeBootstrap bootstrap) {
      this.bootstrap = bootstrap;
    }

    @Override
    public void run() {
      try {
        Thread.sleep(100);
      } catch (InterruptedException _) {
        Thread.currentThread().interrupt();
      }
      if (bootstrap.isPRNGReady) return;
      LOG.warn("Not enough entropy available.");
      LOG.warn("Trying to gather entropy (randomness) by reading the disk...");
      if (File.separatorChar == '/') {
        String hwrngPath = System.getProperty(HWRNG_PATH_PROPERTY, DEFAULT_HWRNG_PATH);
        if (new File(hwrngPath).exists()) {
          LOG.warn("{} exists - have you installed rng-tools?", hwrngPath);
        } else {
          LOG.warn("You should consider installing a better random number generator e.g. haveged.");
        }
      }
      extendTimeouts();
      for (File root : File.listRoots()) {
        if (bootstrap.isPRNGReady) return;
        recurse(root);
      }
    }

    private void recurse(File f) {
      if (bootstrap.isPRNGReady) return;
      extendTimeouts();
      File[] subDirs =
          f.listFiles(
              pathname -> pathname.exists() && pathname.canRead() && pathname.isDirectory());
      if (subDirs != null) {
        for (File currentDir : subDirs) recurse(currentDir);
      }
    }

    private void extendTimeouts() {
      long now = System.currentTimeMillis();
      if (now - tLastAdded < EXTEND_BY / 2) return;
      long target = tLastAdded + EXTEND_BY;
      while (target < now) target += EXTEND_BY;
      long extend = target - now;
      assert (extend < Integer.MAX_VALUE);
      assert (extend > 0);
      org.tanukisoftware.wrapper.WrapperManager.signalStarting((int) extend);
      tLastAdded = now;
    }
  }
}

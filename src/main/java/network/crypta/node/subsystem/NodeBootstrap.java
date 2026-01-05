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

/** Bootstrap responsibilities (program directories, entropy, RNG). */
public final class NodeBootstrap {
  private static final Logger LOG = LoggerFactory.getLogger(NodeBootstrap.class);

  private final Node node;
  private volatile boolean isPRNGReady = false;
  private RandomSource random;
  private SecureRandom secureRandom;
  private Random fastWeakRandom;

  public NodeBootstrap(Node node) {
    this.node = node;
  }

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

  public NativeThread createEntropyGatheringThread() {
    return new NativeThread(
        new EntropyGatheringTask(this),
        "Entropy Gathering Thread",
        NativeThread.PriorityLevel.MIN_PRIORITY.value,
        true);
  }

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

  public RandomSource random() {
    return random;
  }

  public SecureRandom secureRandom() {
    return secureRandom;
  }

  public Random fastWeakRandom() {
    return fastWeakRandom;
  }

  public boolean isMac() {
    return new AppEnv().isMac();
  }

  public Random createRandom() {
    byte[] seed = new byte[16];
    NodeStarter.getGlobalSecureRandom().nextBytes(seed);
    return MersenneTwister.createSynchronized(seed);
  }

  public boolean isPrngReady() {
    return isPRNGReady;
  }

  public void markPrngReady() {
    isPRNGReady = true;
  }

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

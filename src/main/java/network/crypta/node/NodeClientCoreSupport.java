package network.crypta.node;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.HashSet;
import network.crypta.client.ArchiveManager;
import network.crypta.client.InsertContext;
import network.crypta.client.async.HealingDecisionSupplier;
import network.crypta.client.async.SimpleHealingQueue;
import network.crypta.client.events.SimpleEventProducer;
import network.crypta.config.SubConfig;
import network.crypta.fs.AppDirs;
import network.crypta.fs.AppEnv;
import network.crypta.fs.Resolved;
import network.crypta.fs.ServiceDirs;
import network.crypta.keys.CHKBlock;
import network.crypta.keys.CHKVerifyException;
import network.crypta.keys.ClientCHK;
import network.crypta.keys.ClientCHKBlock;
import network.crypta.keys.ClientKeyBlock;
import network.crypta.keys.ClientSSK;
import network.crypta.keys.ClientSSKBlock;
import network.crypta.keys.Key;
import network.crypta.keys.SSKBlock;
import network.crypta.keys.SSKVerifyException;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.useralerts.DatastoreTooSmallAlert;
import network.crypta.node.useralerts.DiskSpaceUserAlert;
import network.crypta.node.useralerts.SimpleUserAlert;
import network.crypta.node.useralerts.UserAlert;
import network.crypta.node.useralerts.UserAlertManager;
import network.crypta.support.compress.Compressor;
import network.crypta.support.io.FileUtil;
import network.crypta.support.io.TempBucketFactory;

/** Helper methods that keep NodeClientCore wiring focused while preserving existing behavior. */
public final class NodeClientCoreSupport {
  private NodeClientCoreSupport() {}

  /** Returns the default cache directory for the current environment (service or desktop). */
  public static File resolveDefaultCacheDir() {
    return resolveDefaultDirs().getCacheDir().toFile();
  }

  /** Returns the default data directory for the current environment (service or desktop). */
  public static File resolveDefaultDataDir() {
    return resolveDefaultDirs().getDataDir().toFile();
  }

  /** Returns the resolved program directory as a {@link File}. */
  public static File setupProgramDirFile(
      Node node,
      SubConfig installConfig,
      String cfgKey,
      String defaultValue,
      String shortDesc,
      String longDesc)
      throws NodeInitException {
    return setupProgramDirFile(
        node, installConfig, cfgKey, defaultValue, shortDesc, longDesc, null);
  }

  /** Returns the resolved program directory as a {@link File}. */
  public static File setupProgramDirFile(
      Node node,
      SubConfig installConfig,
      String cfgKey,
      String defaultValue,
      String shortDesc,
      String longDesc,
      String moveErrMsg)
      throws NodeInitException {
    return node.setupProgramDir(
            installConfig, cfgKey, defaultValue, shortDesc, longDesc, moveErrMsg)
        .dir();
  }

  /** Creates archive and healing resources required for client context initialization. */
  public static ClientContextResources createClientContextResources(
      Node node,
      TempBucketFactory tempBucketFactory,
      int maxArchiveHandlers,
      long maxCachedArchiveData,
      long maxArchivedFileSize,
      int maxCachedElements,
      int maxRunningHealingInserts) {
    ArchiveManager archiveManager =
        new ArchiveManager(
            maxArchiveHandlers,
            maxCachedArchiveData,
            maxArchivedFileSize,
            maxCachedElements,
            tempBucketFactory);
    SimpleHealingQueue healingQueue =
        new SimpleHealingQueue(
            new InsertContext(
                0,
                2,
                0,
                0,
                new SimpleEventProducer(),
                false,
                Node.FORK_ON_CACHEABLE_DEFAULT,
                false,
                Compressor.DEFAULT_COMPRESSORDESCRIPTOR,
                0,
                0,
                InsertContext.CompatibilityMode.COMPAT_DEFAULT),
            RequestStarter.PREFETCH_PRIORITY_CLASS,
            maxRunningHealingInserts,
            new HealingDecisionSupplier(node::getLocation, node::isOpennetEnabled));
    return new ClientContextResources(archiveManager, healingQueue);
  }

  /** Builds a client CHK block from an encoded block and key. */
  public static ClientKeyBlock buildClientChkBlock(CHKBlock block, ClientCHK key)
      throws CHKVerifyException {
    return new ClientCHKBlock(block, key);
  }

  /** Builds a client CHK block from raw data and headers. */
  public static ClientKeyBlock buildClientChkBlock(byte[] data, byte[] header, ClientCHK key)
      throws CHKVerifyException {
    return new ClientCHKBlock(data, header, key, true);
  }

  /** Builds a client SSK block from an encoded block and key. */
  public static ClientKeyBlock buildClientSskBlock(SSKBlock block, ClientSSK key)
      throws SSKVerifyException {
    return ClientSSKBlock.construct(block, key);
  }

  /**
   * Deletes the provided file, mirroring NodeClientCore's previous deletion behavior.
   *
   * @throws IOException if deletion fails
   */
  public static void deleteFile(File file) throws IOException {
    Files.delete(file.toPath());
  }

  /**
   * Computes the most recent failure timing for routing decisions.
   *
   * <p>Mirrors the originator behavior by decrementing HTL before invoking the routing selector.
   */
  public static long checkRecentlyFailed(Node node, Key key, boolean realTime) {
    RecentlyFailedReturn result = new RecentlyFailedReturn();
    short origHtl = node.decrementHTL(null, node.maxHTL());
    node.getPeers()
        .routingSelector()
        .closerPeer(
            null,
            new HashSet<PeerNode>(),
            key.toNormalizedDouble(),
            true,
            false,
            -1,
            null,
            2.0,
            key,
            origHtl,
            0,
            true,
            realTime,
            result,
            false,
            System.currentTimeMillis(),
            node.enableNewLoadManagement(realTime));
    return result.recentlyFailed();
  }

  /** Creates the startup alert displayed until the node finishes initialization. */
  public static UserAlert createStartingUpAlert(String title, String longText, String shortText) {
    return new SimpleUserAlert(true, title, longText, shortText, UserAlert.ERROR);
  }

  /** Registers the core FProxy alerts, including the persistence-broken warning. */
  public static void registerFProxyAlerts(
      UserAlertManager alerts, NodeClientCore core, UserAlert startingUpAlert) {
    alerts.register(startingUpAlert);
    alerts.register(createPersistenceBrokenAlert(core));
  }

  /** Registers disk-space related user alerts. */
  public static void registerStorageAlerts(UserAlertManager alerts, NodeClientCore core) {
    alerts.register(new DiskSpaceUserAlert(core));
    alerts.register(new DatastoreTooSmallAlert(core));
  }

  private static UserAlert createPersistenceBrokenAlert(NodeClientCore core) {
    Node node = core.getNode();
    String tempDir =
        new File(FileUtil.getCanonicalFile(core.getPersistentTempDir()), File.separator).toString();
    String dbFile = new File(FileUtil.getCanonicalFile(node.getUserDir()), "client.dat").toString();
    return new SimpleUserAlert(
        true,
        NodeL10n.getBase().getString("QueueToadlet.persistenceBrokenTitle"),
        NodeL10n.getBase()
            .getString(
                "QueueToadlet.persistenceBroken",
                new String[] {"TEMPDIR", "DBFILE"},
                new String[] {tempDir, dbFile}),
        NodeL10n.getBase().getString("QueueToadlet.persistenceBrokenShortAlert"),
        UserAlert.CRITICAL_ERROR) {
      @Override
      public boolean isValid() {
        synchronized (core) {
          if (!core.killedDatabase()) return false;
        }
        if (node.awaitingPassword()) return false;
        return !node.isStopping();
      }

      @Override
      public boolean userCanDismiss() {
        return false;
      }
    };
  }

  private static Resolved resolveDefaultDirs() {
    AppEnv appEnv = new AppEnv();
    return appEnv.isServiceMode() ? new ServiceDirs().resolve() : new AppDirs().resolve();
  }
}

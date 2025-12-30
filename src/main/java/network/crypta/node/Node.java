/* Freenet 0.7 node. */
package network.crypta.node;

import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.MINUTES;
import static java.util.concurrent.TimeUnit.SECONDS;
import static network.crypta.node.stats.DataStoreKeyType.CHK;
import static network.crypta.node.stats.DataStoreKeyType.PUB_KEY;
import static network.crypta.node.stats.DataStoreKeyType.SSK;
import static network.crypta.node.stats.DataStoreType.CACHE;
import static network.crypta.node.stats.DataStoreType.CLIENT;
import static network.crypta.node.stats.DataStoreType.SLASHDOT;
import static network.crypta.node.stats.DataStoreType.STORE;
import static network.crypta.support.io.DatastoreUtil.ONE_GIB;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.RandomAccessFile;
import java.io.Serial;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.MissingResourceException;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.client.FetchContext;
import network.crypta.clients.fcp.FCPMessage;
import network.crypta.clients.fcp.FeedMessage;
import network.crypta.clients.http.SecurityLevelsToadlet;
import network.crypta.clients.http.SimpleToadletServer;
import network.crypta.config.Dimension;
import network.crypta.config.EnumerableOptionCallback;
import network.crypta.config.FreenetFilePersistentConfig;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.NodeNeedRestartException;
import network.crypta.config.PersistentConfig;
import network.crypta.config.SubConfig;
import network.crypta.crypt.DSAPublicKey;
import network.crypta.crypt.ECDH;
import network.crypta.crypt.MasterSecret;
import network.crypta.crypt.PersistentRandomSource;
import network.crypta.crypt.RandomSource;
import network.crypta.crypt.Util;
import network.crypta.crypt.Yarrow;
import network.crypta.crypt.ciphers.Rijndael;
import network.crypta.fs.AppDirs;
import network.crypta.fs.AppEnv;
import network.crypta.fs.Resolved;
import network.crypta.fs.ServiceDirs;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.DisconnectedException;
import network.crypta.io.comm.FreenetInetAddress;
import network.crypta.io.comm.IOStatisticCollector;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.MessageCore;
import network.crypta.io.comm.MessageFilter;
import network.crypta.io.comm.Peer;
import network.crypta.io.comm.PeerParseException;
import network.crypta.io.comm.ReferenceSignatureVerificationException;
import network.crypta.io.comm.TrafficClass;
import network.crypta.io.comm.UdpSocketHandler;
import network.crypta.io.xfer.PartiallyReceivedBlock;
import network.crypta.keys.CHKBlock;
import network.crypta.keys.CHKVerifyException;
import network.crypta.keys.ClientCHK;
import network.crypta.keys.ClientCHKBlock;
import network.crypta.keys.ClientKey;
import network.crypta.keys.ClientKeyBlock;
import network.crypta.keys.ClientSSK;
import network.crypta.keys.ClientSSKBlock;
import network.crypta.keys.Key;
import network.crypta.keys.KeyBlock;
import network.crypta.keys.KeyVerifyException;
import network.crypta.keys.NodeCHK;
import network.crypta.keys.NodeSSK;
import network.crypta.keys.SSKBlock;
import network.crypta.keys.SSKVerifyException;
import network.crypta.l10n.BaseL10n;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.DarknetPeerNode.FRIEND_TRUST;
import network.crypta.node.DarknetPeerNode.FRIEND_VISIBILITY;
import network.crypta.node.NodeDispatcher.NodeDispatcherCallback;
import network.crypta.node.OpennetManager.ConnectionType;
import network.crypta.node.SecurityLevels.NETWORK_THREAT_LEVEL;
import network.crypta.node.SecurityLevels.PHYSICAL_THREAT_LEVEL;
import network.crypta.node.diagnostics.DefaultNodeDiagnostics;
import network.crypta.node.diagnostics.NodeDiagnostics;
import network.crypta.node.probe.Listener;
import network.crypta.node.probe.Probe;
import network.crypta.node.probe.Type;
import network.crypta.node.stats.DataStoreInstanceType;
import network.crypta.node.stats.DataStoreStats;
import network.crypta.node.stats.NotAvailNodeStoreStats;
import network.crypta.node.stats.StoreCallbackStats;
import network.crypta.node.updater.NodeUpdateManager;
import network.crypta.node.useralerts.JVMVersionAlert;
import network.crypta.node.useralerts.MeaningfulNodeNameUserAlert;
import network.crypta.node.useralerts.NotEnoughNiceLevelsUserAlert;
import network.crypta.node.useralerts.PeersOffersUserAlert;
import network.crypta.node.useralerts.SimpleUserAlert;
import network.crypta.node.useralerts.TimeSkewDetectedUserAlert;
import network.crypta.node.useralerts.UserAlert;
import network.crypta.pluginmanager.ForwardPort;
import network.crypta.pluginmanager.PluginManager;
import network.crypta.store.BlockMetadata;
import network.crypta.store.CHKStore;
import network.crypta.store.FreenetStore;
import network.crypta.store.KeyCollisionException;
import network.crypta.store.NullFreenetStore;
import network.crypta.store.PubkeyStore;
import network.crypta.store.RAMFreenetStore;
import network.crypta.store.SSKStore;
import network.crypta.store.SlashdotStore;
import network.crypta.store.StorableBlock;
import network.crypta.store.StoreCallback;
import network.crypta.store.caching.CachingFreenetStore;
import network.crypta.store.caching.CachingFreenetStoreTracker;
import network.crypta.store.saltedhash.ResizablePersistentIntBuffer;
import network.crypta.store.saltedhash.SaltedHashFreenetStore;
import network.crypta.support.Fields;
import network.crypta.support.HTMLNode;
import network.crypta.support.HexUtil;
import network.crypta.support.JVMVersion;
import network.crypta.support.OutputThrottle;
import network.crypta.support.PooledExecutor;
import network.crypta.support.PrioritizedTicker;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.ShortBuffer;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.Ticker;
import network.crypta.support.api.BooleanCallback;
import network.crypta.support.api.IntCallback;
import network.crypta.support.api.LongCallback;
import network.crypta.support.api.ShortCallback;
import network.crypta.support.api.StringCallback;
import network.crypta.support.io.ArrayBucketFactory;
import network.crypta.support.io.DatastoreUtil;
import network.crypta.support.io.FileUtil;
import network.crypta.support.io.NativeThread;
import network.crypta.support.math.MersenneTwister;
import network.crypta.support.transport.ip.HostnameSyntaxException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.tanukisoftware.wrapper.WrapperManager;

/**
 * Core node implementation coordinating all major subsystems (routing, storage, peers, and
 * services).
 *
 * <p>The {@code Node} class wires together the network stack (darknet/opennet crypto and sockets),
 * request/insert schedulers, datastores and caches (CHK/SSK/public key), the HTTP UI (FProxy),
 * plugins, and diagnostics. A typical lifecycle is: create a {@code Node} via {@link NodeStarter},
 * call {@link #start(boolean)} to initialize active components, interact with the node (e.g.,
 * enqueue requests/inserts), and finally call {@link #park()} to quiesce and shut down. Most
 * methods are designed for internal coordination and are not stable APIs for external callers;
 * public methods are documented for their observable effects.
 *
 * <p>Invariants and state model:
 *
 * <ul>
 *   <li>The node owns multiple persistent stores plus short‑lived caches; sizing and placement are
 *       configured at startup and may change only through well‑defined callbacks.
 *   <li>Networking is asynchronous; dispatchers, tickers, and executors coordinate background work.
 *       Many operations complete later on the ticker thread.
 *   <li>Security levels (network/physical) influence routing, caching, and persistence behavior at
 *       runtime.
 * </ul>
 *
 * <p>Concurrency: the node uses thread‑safe helpers (executors, synchronized fields) and avoids
 * blocking I/O on critical routing threads. Methods explicitly state when they may block or when
 * they trigger background activity. Mutability is confined to configuration/state holders and
 * caches; key objects and block payloads are treated as immutable once published.
 *
 * @author amphibian
 */
public class Node implements TimeSkewDetectorCallback {
  private static final Logger LOG = LoggerFactory.getLogger(Node.class);

  /** String literal for the salted-hash store/client-cache type. */
  private static final String TYPE_SALT_HASH = "salt-hash";

  /** Prefix for node file names (e.g., node-<port>). */
  private static final String NODE_FILE_PREFIX = "node-";

  /** Config key name used to control datastore preallocation. */
  private static final String STORE_PREALLOCATE_KEY = "storePreallocate";

  /** SimpleFieldSet key for Node-to-Node message type. */
  private static final String N2N_TYPE_KEY = "n2nType";

  /** L10n base prefix for Node strings. */
  private static final String L10N_PREFIX_NODE = "Node.";

  /** System property to override the hardware RNG device path. */
  private static final String HWRNG_PATH_PROPERTY = "crypta.hwrng.path";

  /** Default hardware RNG device path for Unix-like systems. */
  private static final String DEFAULT_HWRNG_PATH = "/dev/hwrng";

  /** Store kind identifier for public key stores. */
  private static final String STORE_KIND_PUBKEY = "PUBKEY";

  /** L10n key for SecurityLevels enter password message. */
  private static final String SECURITYLEVELS_ENTER_PASSWORD_KEY = "SecurityLevels.enterPassword";

  /**
   * Background migrator that copies data from a previously active store into the new one.
   *
   * <p>Used when delayed initialization is enabled or when client‑cache/password state changes.
   * Migration runs on a background thread and logs progress; failures are logged and do not abort
   * node startup.
   */
  public class MigrateOldStoreData implements Runnable {

    private final boolean clientCache;

    public MigrateOldStoreData(boolean clientCache) {
      this.clientCache = clientCache;
      if (clientCache) {
        oldCHKClientCache.set(chkClientcache);
        oldPKClientCache.set(pubKeyClientcache);
        oldSSKClientCache.set(sskClientcache);
      } else {
        oldCHK.set(chkDatastore);
        oldPK.set(pubKeyDatastore);
        oldSSK.set(sskDatastore);
        oldCHKCache.set(chkDatastore);
        oldPKCache.set(pubKeyDatastore);
        oldSSKCache.set(sskDatastore);
      }
    }

    @Override
    public void run() {
      LOG.info("Migrating old {}", (clientCache ? "client cache" : "datastore"));
      if (clientCache) {
        migrateOldStore(oldCHKClientCache.get(), chkClientcache, true);
        StoreCallback<? extends StorableBlock> old;
        synchronized (Node.this) {
          old = oldCHKClientCache.get();
          oldCHKClientCache.set(null);
        }
        closeOldStore(old);
        migrateOldStore(oldPKClientCache.get(), pubKeyClientcache, true);
        synchronized (Node.this) {
          old = oldPKClientCache.get();
          oldPKClientCache.set(null);
        }
        closeOldStore(old);
        migrateOldStore(oldSSKClientCache.get(), sskClientcache, true);
        synchronized (Node.this) {
          old = oldSSKClientCache.get();
          oldSSKClientCache.set(null);
        }
        closeOldStore(old);
      } else {
        migrateOldStore(oldCHK.get(), chkDatastore, false);
        oldCHK.set(null);
        migrateOldStore(oldPK.get(), pubKeyDatastore, false);
        oldPK.set(null);
        migrateOldStore(oldSSK.get(), sskDatastore, false);
        oldSSK.set(null);
        migrateOldStore(oldCHKCache.get(), chkDatacache, false);
        oldCHKCache.set(null);
        migrateOldStore(oldPKCache.get(), pubKeyDatacache, false);
        oldPKCache.set(null);
        migrateOldStore(oldSSKCache.get(), sskDatacache, false);
        oldSSKCache.set(null);
      }
      LOG.info("Finished migrating old {}", (clientCache ? "client cache" : "datastore"));
    }

    private <T extends StorableBlock> void migrateOldStore(
        StoreCallback<T> old, StoreCallback<T> newStore, boolean canReadClientCache) {
      FreenetStore<T> store = old.getStore();
      if (store instanceof RAMFreenetStore<T> ramstore) {
        try {
          ramstore.migrateTo(newStore, canReadClientCache);
        } catch (IOException e) {
          LOG.error("Caught migrating old store: {}", e, e);
        }
        ramstore.clear();
      } else if (store instanceof SaltedHashFreenetStore) {
        LOG.error(
            "Migrating from from a saltedhashstore not fully supported yet: will not keep old"
                + " keys");
      }
    }
  }

  private final AtomicReference<CHKStore> oldCHK = new AtomicReference<>();

  /** */
  private final AtomicReference<PubkeyStore> oldPK = new AtomicReference<>();

  private final AtomicReference<SSKStore> oldSSK = new AtomicReference<>();

  private final AtomicReference<CHKStore> oldCHKCache = new AtomicReference<>();

  /** */
  private final AtomicReference<PubkeyStore> oldPKCache = new AtomicReference<>();

  private final AtomicReference<SSKStore> oldSSKCache = new AtomicReference<>();

  private final AtomicReference<CHKStore> oldCHKClientCache = new AtomicReference<>();

  /** */
  private final AtomicReference<PubkeyStore> oldPKClientCache = new AtomicReference<>();

  private final AtomicReference<SSKStore> oldSSKClientCache = new AtomicReference<>();

  /**
   * Closes and securely destroys an old salted‑hash store used during migration.
   *
   * @param old callback whose underlying store will be closed and destroyed when applicable.
   */
  public <T extends StorableBlock> void closeOldStore(StoreCallback<T> old) {
    FreenetStore<T> store = old.getStore();
    if (store instanceof SaltedHashFreenetStore<T> saltstore) {
      saltstore.close();
      saltstore.destruct();
    }
  }

  // Static initializer not required

  private final MeaningfulNodeNameUserAlert nodeNameUserAlert;
  private static TimeSkewDetectedUserAlert timeSkewDetectedUserAlert;

  /**
   * Config callback for the node's display name.
   *
   * <p>Validates and persists the name, and notifies peers using a differential node reference so
   * UI components can reflect changes promptly.
   */
  public class NodeNameCallback extends StringCallback {
    NodeNameCallback() {}

    @Override
    public String get() {
      String name;
      synchronized (this) {
        name = myName;
      }
      if (name.startsWith("Node id|")
          || name.equals("MyFirstCryptaNode")
          || name.startsWith("Crypta node with no name #")) {
        clientCore.getAlerts().register(nodeNameUserAlert);
      } else {
        clientCore.getAlerts().unregister(nodeNameUserAlert);
      }
      return name;
    }

    @Override
    public void set(String val) throws InvalidConfigValueException {
      if (get().equals(val)) return;
      else if (val.length() > 128)
        throw new InvalidConfigValueException("The given node name is too long (" + val + ')');
      else if (val.isEmpty()) val = "~none~";
      synchronized (this) {
        myName = val;
      }
      // We'll broadcast the new name to our connected darknet peers via a differential node
      // reference
      SimpleFieldSet fs = new SimpleFieldSet(true);
      fs.putSingle("myName", myName);
      peers.messenger().locallyBroadcastDiffNodeRef(fs, true, false);
      // We call the callback once again to ensure MeaningfulNodeNameUserAlert
      // has been unregistered ... see #1595
      get();
    }
  }

  private class StoreTypeCallback extends StringCallback implements EnumerableOptionCallback {

    @Override
    public String get() {
      synchronized (Node.this) {
        return storeType;
      }
    }

    @Override
    public void set(String val) throws InvalidConfigValueException, NodeNeedRestartException {
      boolean found = false;
      for (String p : getPossibleValues()) {
        if (p.equals(val)) {
          found = true;
          break;
        }
      }
      if (!found) throw new InvalidConfigValueException("Invalid store type");

      String type;
      synchronized (Node.this) {
        type = storeType;
      }
      if (type.equals("ram")) {
        synchronized (this) { // Serialise this part.
          makeStore(val);
        }
      } else {
        synchronized (Node.this) {
          storeType = val;
        }
        throw new NodeNeedRestartException("Store type cannot be changed on the fly");
      }
    }

    @Override
    public String[] getPossibleValues() {
      return new String[] {TYPE_SALT_HASH, "ram"};
    }
  }

  private class ClientCacheTypeCallback extends StringCallback implements EnumerableOptionCallback {

    @Override
    public String get() {
      synchronized (Node.this) {
        return clientCacheType;
      }
    }

    @Override
    public void set(String val) throws InvalidConfigValueException, NodeNeedRestartException {
      boolean found = false;
      for (String p : getPossibleValues()) {
        if (p.equals(val)) {
          found = true;
          break;
        }
      }
      if (!found) throw new InvalidConfigValueException("Invalid store type");

      synchronized (this) { // Serialise this part.
        if (val.equals(TYPE_SALT_HASH)) {
          byte[] key;
          try {
            synchronized (Node.this) {
              if (keys == null) throw new MasterKeysWrongPasswordException();
              key = keys.clientCacheMasterKey;
              clientCacheType = val;
            }
          } catch (MasterKeysWrongPasswordException _) {
            setClientCacheAwaitingPassword();
            throw new InvalidConfigValueException("You must enter the password");
          }
          try {
            initSaltHashClientCacheFS(true, key);
          } catch (NodeInitException e) {
            throw new InvalidConfigValueException(e);
          }
        } else if (val.equals("ram")) {
          initRAMClientCacheFS();
        } else {
          initNoClientCacheFS();
        }

        synchronized (Node.this) {
          clientCacheType = val;
        }
      }
    }

    @Override
    public String[] getPossibleValues() {
      return new String[] {TYPE_SALT_HASH, "ram", "none"};
    }
  }

  private static class L10nCallback extends StringCallback implements EnumerableOptionCallback {
    @Override
    public String get() {
      return NodeL10n.getBase().getSelectedLanguage().fullName;
    }

    @Override
    public void set(String val) throws InvalidConfigValueException {
      if (val == null || get().equalsIgnoreCase(val)) return;
      try {
        NodeL10n.getBase().setLanguage(BaseL10n.LANGUAGE.mapToLanguage(val));
      } catch (MissingResourceException e) {
        throw new InvalidConfigValueException(e.getLocalizedMessage());
      }
      PluginManager.setLanguage(NodeL10n.getBase().getSelectedLanguage());
    }

    @Override
    public String[] getPossibleValues() {
      return BaseL10n.LANGUAGE.valuesWithFullNames();
    }
  }

  /** Encryption key for client.dat.crypt or client.dat.bak.crypt */
  private DatabaseKey databaseKey;

  /**
   * Encryption keys, if loaded, null if waiting for a password. We must be able to write them, and
   * they're all used elsewhere anyway, so there's no point trying not to keep them in memory.
   */
  private MasterKeys keys;

  /** Stats */
  private final NodeStats nodeStats;

  /** Config object for the whole node. */
  private final PersistentConfig config;

  // Static stuff related to logger
  /** Number of packets per transfer block used in link‑layer processing. */
  public static final int PACKETS_IN_BLOCK = 32;

  /** Default transport packet payload size in bytes. */
  public static final int PACKET_SIZE = 1024;

  /** Probability of decrementing at the minimum HTL boundary. */
  public static final double DECREMENT_AT_MIN_PROB = 0.25;

  /** Probability of decrementing at the maximum HTL boundary. */
  public static final double DECREMENT_AT_MAX_PROB = 0.5;

  // Send keepalives every 7-14 seconds. Will be acked and if necessary resent.
  // Old behaviour was keepalives every 14-28. Even that was adequate for a 30-second
  // timeout. Most nodes don't need to send keepalives because they are constantly busy,
  // this is only an issue for disabled darknet connections, very quiet private networks
  // etc.
  /** Interval for sending keep‑alive packets on idle connections (milliseconds). */
  public static final long KEEPALIVE_INTERVAL = SECONDS.toMillis(7);

  // If no activity for 30 seconds, node is dead
  // 35 seconds allows plenty of time for resends etc. even if above is 14 sec as it is on older
  // nodes.
  /** Inactivity timeout after which a peer is considered dead (milliseconds). */
  public static final long MAX_PEER_INACTIVITY = SECONDS.toMillis(35);

  /** Time budget in milliseconds for completing a handshake exchange. */
  public static final int HANDSHAKE_TIMEOUT =
      (int) MILLISECONDS.toMillis(4800); // Keep the below within the 30-second assumed timeout.

  // Inter-handshake time must be at least 2x handshake timeout
  /** Minimum interval between handshake attempts (milliseconds). */
  public static final int MIN_TIME_BETWEEN_HANDSHAKE_SENDS = HANDSHAKE_TIMEOUT * 2; // 10-20 secs

  /** Randomized extra delay between handshake attempts (milliseconds). */
  public static final int RANDOMIZED_TIME_BETWEEN_HANDSHAKE_SENDS =
      HANDSHAKE_TIMEOUT * 2; // avoid overlap when the two handshakes are at the same time

  /** Minimum interval between version probes (milliseconds). */
  public static final int MIN_TIME_BETWEEN_VERSION_PROBES = HANDSHAKE_TIMEOUT * 4;

  /** Randomized extra delay between version probes (milliseconds). */
  public static final int RANDOMIZED_TIME_BETWEEN_VERSION_PROBES =
      HANDSHAKE_TIMEOUT * 2; // 20-30 secs

  /** Minimum interval between sending version announcements (milliseconds). */
  public static final int MIN_TIME_BETWEEN_VERSION_SENDS = HANDSHAKE_TIMEOUT * 4;

  /** Randomized extra delay between version announcements (milliseconds). */
  public static final int RANDOMIZED_TIME_BETWEEN_VERSION_SENDS =
      HANDSHAKE_TIMEOUT * 2; // 20-30 secs

  /** Minimum interval between grouped handshake bursts (milliseconds). */
  public static final int MIN_TIME_BETWEEN_BURSTING_HANDSHAKE_BURSTS =
      HANDSHAKE_TIMEOUT * 24; // 2-5 minutes

  /** Randomized extra delay between grouped handshake bursts (milliseconds). */
  public static final int RANDOMIZED_TIME_BETWEEN_BURSTING_HANDSHAKE_BURSTS =
      HANDSHAKE_TIMEOUT * 36;

  /** Minimum count of handshakes sent per burst. */
  public static final int MIN_BURSTING_HANDSHAKE_BURST_SIZE = 1; // 1-4 handshake sends per burst

  /** Additional randomized count added to bursting handshake size. */
  public static final int RANDOMIZED_BURSTING_HANDSHAKE_BURST_SIZE = 3;

  // If we don't receive any packets at all in this period, from any node, tell the user
  /** Time without any traffic that triggers a user‑visible alarm (milliseconds). */
  public static final long ALARM_TIME = MINUTES.toMillis(1);

  static final long MIN_INTERVAL_BETWEEN_INCOMING_SWAP_REQUESTS = MILLISECONDS.toMillis(900);
  static final long MIN_INTERVAL_BETWEEN_INCOMING_PROBE_REQUESTS = MILLISECONDS.toMillis(1000);

  /** Length in bytes for symmetric keys used by the node (e.g., AES‑256). */
  public static final int SYMMETRIC_KEY_LENGTH =
      32; // 256 bits - note that this isn't used everywhere to determine it

  /** Datastore directory */
  private final ProgramDirectory storeDir;

  /** Datastore properties */
  private String storeType;

  private boolean storeUseSlotFilters;
  private boolean storeSaltHashResizeOnStart;
  private int storeSaltHashSlotFilterPersistenceTime;

  /** Absolute minimum store size in bytes accepted by configuration. */
  public static final long MIN_STORE_SIZE = 32L * 1024 * 1024;

  /** Default datastore size (must be at least MIN_STORE_SIZE) */
  static final long DEFAULT_STORE_SIZE = 32L * 1024 * 1024;

  /** Minimum client cache size */
  static final long MIN_CLIENT_CACHE_SIZE = 0;

  /** Default client cache size (must be at least MIN_CLIENT_CACHE_SIZE) */
  static final long DEFAULT_CLIENT_CACHE_SIZE = 10L * 1024 * 1024;

  /** Minimum slashdot cache size */
  static final long MIN_SLASHDOT_CACHE_SIZE = 0;

  /** Default slashdot cache size (must be at least MIN_SLASHDOT_CACHE_SIZE) */
  static final long DEFAULT_SLASHDOT_CACHE_SIZE = 10L * 1024 * 1024;

  /** Estimated total bytes per logical key across all stores (sizing heuristic). */
  public static final int SIZE_PER_KEY =
      CHKBlock.DATA_LENGTH
          + CHKBlock.TOTAL_HEADERS_LENGTH
          + DSAPublicKey.PADDED_SIZE
          + SSKBlock.DATA_LENGTH
          + SSKBlock.TOTAL_HEADERS_LENGTH;

  /** The maximum number of keys stored in each of the datastores, cache and store combined. */
  private long maxTotalKeys;

  long maxCacheKeys;
  long maxStoreKeys;

  /** The maximum size of the datastore. Kept to avoid rounding turning 5G into 5368698672 */
  private long maxTotalDatastoreSize;

  /**
   * If true, store shrinks occur immediately even if they are over 10% of the store size. If false,
   * we just set the storeSize and do an offline shrink on the next startup. Online shrinks do not
   * preserve the most recently used data so are not recommended.
   */
  private boolean storeForceBigShrinks;

  private final SemiOrderedShutdownHook shutdownHook;

  /**
   * The CHK datastore. Long term storage; data should only be inserted here if this node is the
   * closest location on the chain so far, and it is on an insert (because inserts will always reach
   * the most specialized node; if we allow requests to store here, then we get pollution by inserts
   * for keys not close to our specialization). These conclusions derived from Oskar's simulations.
   */
  private CHKStore chkDatastore;

  /** The SSK datastore. See description for chkDatastore. */
  private SSKStore sskDatastore;

  /** The store of DSAPublicKeys (by hash). See description for chkDatastore. */
  private PubkeyStore pubKeyDatastore;

  /** Client cache store type */
  private String clientCacheType;

  /** Client cache could not be opened so is a RAMFS until the correct password is entered */
  private boolean clientCacheAwaitingPassword;

  private boolean databaseAwaitingPassword;

  /** Client cache maximum cached keys for each type */
  long maxClientCacheKeys;

  /** Maximum size of the client cache. Kept to avoid rounding problems. */
  private long maxTotalClientCacheSize;

  /** The CHK datacache. Short term cache which stores everything that passes through this node. */
  private CHKStore chkDatacache;

  /** The SSK datacache. Short term cache which stores everything that passes through this node. */
  private SSKStore sskDatacache;

  /**
   * The public key datacache (by hash). Short term cache which stores everything that passes
   * through this node.
   */
  private PubkeyStore pubKeyDatacache;

  /** The CHK client cache. Caches local requests only. */
  private CHKStore chkClientcache;

  /** The SSK client cache. Caches local requests only. */
  private SSKStore sskClientcache;

  /** The pubkey client cache. Caches local requests only. */
  private PubkeyStore pubKeyClientcache;

  // These only cache keys for 30 minutes.

  // Consider making the first two configurable
  private long maxSlashdotCacheSize;
  private int maxSlashdotCacheKeys;
  static final long PURGE_INTERVAL = SECONDS.toMillis(60);

  private final CHKStore chkSlashdotcache;
  private final SlashdotStore<CHKBlock> chkSlashdotcacheStore;
  private final SSKStore sskSlashdotcache;
  private final SlashdotStore<SSKBlock> sskSlashdotcacheStore;
  private final PubkeyStore pubKeySlashdotcache;
  private final SlashdotStore<DSAPublicKey> pubKeySlashdotcacheStore;

  /** If false, only ULPRs will use the slashdot cache. If true, everything does. */
  private boolean useSlashdotCache;

  /**
   * If true, we write stuff to the datastore even though we shouldn't because the HTL is too high.
   * However, it is flagged as old so it won't be included in the Bloom filter for sharing purposes.
   */
  private boolean writeLocalToDatastore;

  private final NodeGetPubkey getPubKey;

  /** FetchContext for ARKs */
  private final FetchContext arkFetcherContext;

  /** IP detector */
  private final NodeIPDetector ipDetector;

  /**
   * For debugging/testing, set this to true to stop the probabilistic decrement at the edges of the
   * HTLs.
   */
  private boolean disableProbabilisticHTLs;

  private final RequestTracker tracker;

  /**
   * Semi-unique ID for swap requests. Used to identify us so that the topology can be
   * reconstructed.
   */
  private long swapIdentifier;

  /**
   * Returns the semi‑unique identifier used for swap requests so that the topology can be
   * reconstructed. The value is derived from the node's identity hash and may change when identity
   * material changes.
   *
   * <p>The identifier is intended only for correlating swap activity within a running cohort and is
   * not guaranteed to be globally unique or stable across restarts if identity material changes.
   *
   * @return the current swap identifier value used in swap routing and diagnostics.
   */
  @SuppressWarnings("unused")
  public long getSwapIdentifier() {
    return swapIdentifier;
  }

  private String myName;

  private final LocationManager lm;

  /** My peers */
  private final PeerManager peers;

  /** Node-reference directory (node identity, peers, etc.) */
  private final ProgramDirectory nodeDir;

  /** Config directory (l10n overrides, etc) */
  final ProgramDirectory cfgDir;

  /** User data directory (bookmarks, download lists, etc.) */
  final ProgramDirectory userDir;

  /** Run-time state directory (bootID, PRNG seed, etc.) */
  final ProgramDirectory runDir;

  /** Plugin directory */
  final ProgramDirectory pluginDir;

  /** File to write crypto master keys into, possibly passworded */
  final File masterKeysFile;

  /** Directory to put extra peer data into */
  final File extraPeerDataDir;

  private volatile boolean hasPanicked;

  /** Strong RNG */
  private final RandomSource random;

  /**
   * JCA-compliant strong RNG. WARNING: DO NOT CALL THIS ON THE MAIN NETWORK HANDLING THREADS! In
   * some configurations it can block, potentially forever, on nextBytes()!
   */
  private final SecureRandom secureRandom;

  /** Weak but fast RNG */
  private final Random fastWeakRandom;

  /** The object which handles incoming messages and allows us to wait for them */
  private final MessageCore usm;

  // Darknet stuff

  private final NodeCrypto darknetCrypto;

  // Back compat
  private boolean showFriendsVisibilityAlert;

  // Opennet stuff

  private final NodeCryptoConfig opennetCryptoConfig;

  private OpennetManager opennet;

  private volatile boolean isAllowedToConnectToSeednodes;
  private int maxOpennetPeers;
  private boolean acceptSeedConnections;
  private boolean passOpennetRefsThroughDarknet;

  // General stuff

  private final PriorityAwareExecutor executor;

  private final PacketSender ps;

  private final PrioritizedTicker ticker;

  private final DNSRequester dnsr;

  private final NodeDispatcher dispatcher;

  private final UptimeEstimator uptime;

  private final OutputThrottle outputThrottle;

  private boolean throttleLocalData;

  private int outputBandwidthLimit;
  private int inputBandwidthLimit;
  private long amountOfDataToCheckCompressionRatio;
  private int minimumCompressionPercentage;
  private boolean connectionSpeedDetection;
  boolean inputLimitDefault;

  private final boolean enableARKs;

  private final boolean enablePerNodeFailureTables;

  private final boolean enableULPRDataPropagation;

  private final boolean enableSwapping;

  private volatile boolean publishOurPeersLocation;
  private volatile boolean routeAccordingToOurPeersLocation;

  private boolean enableSwapQueueing;

  private boolean enablePacketCoalescing;

  /** Default maximum hop‑to‑live (HTL) used when no explicit value is configured. */
  public static final short DEFAULT_MAX_HTL = (short) 18;

  private short maxHTL;
  private boolean skipWrapperWarning;
  private int maxPacketSize;

  /** Default policy for ignoring low backoff during inserts. */
  public static final boolean IGNORE_LOW_BACKOFF_DEFAULT = false;

  /** Threshold in milliseconds defining a "low" backoff period for inserts. */
  public static final long LOW_BACKOFF = SECONDS.toMillis(30);

  /** Default policy for prioritizing inserts on accept. */
  public static final boolean PREFER_INSERT_DEFAULT = false;

  /** Default policy for forking insert when an item becomes cacheable. */
  public static final boolean FORK_ON_CACHEABLE_DEFAULT = true;

  private final IOStatisticCollector collector;

  /** Node‑to‑node message category used for FProxy messages. */
  public static final int N2N_MESSAGE_TYPE_FPROXY = 1;

  /** Node‑to‑node message category for differential node references. */
  public static final int N2N_MESSAGE_TYPE_DIFFNODEREF = 2;

  /** FProxy text sub‑type for user alerts. */
  public static final int N2N_TEXT_MESSAGE_TYPE_USERALERT = 1;

  /** FProxy text sub‑type for a file offer. */
  public static final int N2N_TEXT_MESSAGE_TYPE_FILE_OFFER = 2;

  /** FProxy text sub‑type signaling a file‑offer acceptance. */
  public static final int N2N_TEXT_MESSAGE_TYPE_FILE_OFFER_ACCEPTED = 3;

  /** FProxy text sub‑type signaling a file‑offer rejection. */
  public static final int N2N_TEXT_MESSAGE_TYPE_FILE_OFFER_REJECTED = 4;

  /** FProxy text sub‑type recommending a bookmark. */
  public static final int N2N_TEXT_MESSAGE_TYPE_BOOKMARK = 5;

  /** FProxy text sub‑type recommending a file download. */
  public static final int N2N_TEXT_MESSAGE_TYPE_DOWNLOAD = 6;

  /** Extra‑peer‑data category for node‑to‑node message payloads. */
  public static final int EXTRA_PEER_DATA_TYPE_N2NTM = 1;

  /** Extra‑peer‑data category for peer notes. */
  public static final int EXTRA_PEER_DATA_TYPE_PEER_NOTE = 2;

  /** Extra‑peer‑data category for queued outbound node‑to‑node messages. */
  public static final int EXTRA_PEER_DATA_TYPE_QUEUED_TO_SEND_N2NM = 3;

  /** Extra‑peer‑data category for bookmarked content. */
  public static final int EXTRA_PEER_DATA_TYPE_BOOKMARK = 4;

  /** Extra‑peer‑data category for download metadata. */
  public static final int EXTRA_PEER_DATA_TYPE_DOWNLOAD = 5;

  /** Peer‑note sub‑type for private darknet comments. */
  public static final int PEER_NOTE_TYPE_PRIVATE_DARKNET_COMMENT = 1;

  /**
   * The bootID of the last time the node booted up. Or -1 if we don't know due to permissions
   * problems, or we suspect that the node has been booted and not written the file e.g. if we can't
   * write it. So if we want to compare data gathered in the last session and only recorded to disk
   * on a clean shutdown to data we have now, we just include the lastBootID.
   */
  private final long lastBootID;

  private final long bootID;

  private final long startupTime;

  private final NodeClientCore clientCore;

  // ULPRs, RecentlyFailed, per node failure tables, are all managed by FailureTable.

  private final FailureTable failureTable;

  /** The version we were before we restarted. */
  private int lastVersion;

  /** NodeUpdater */
  private final NodeUpdateManager nodeUpdater;

  private final SecurityLevels securityLevels;

  /** Diagnostics */
  private final DefaultNodeDiagnostics nodeDiagnostics;

  /** Things that's needed to keep track of */
  private final PluginManager pluginManager;

  // Helpers
  /** Localhost IPv4/IPv6 address used for internal bindings and diagnostics. */
  public final InetAddress localhostAddress;

  private final FreenetInetAddress fLocalhostAddress;

  // The node starter
  private final NodeStarter nodeStarter;

  // The watchdog will be silenced until it's true
  private boolean hasStarted;
  private boolean isStopping = false;

  /**
   * Minimum uptime for us to consider a node an acceptable place to store a key. We store a key to
   * the datastore only if it's from an insert, and we are a sink, but when calculating whether we
   * are a sink we ignore nodes which have less uptime (percentage) than this parameter.
   */
  static final int MIN_UPTIME_STORE_KEY = 40;

  private volatile boolean isPRNGReady = false;

  private boolean storePreallocate;

  private boolean enableRoutedPing;

  private boolean enableNodeDiagnostics;

  private boolean peersOffersDismissed;

  private int datastoreTooSmallDismissed;

  /**
   * Minimum bandwidth limit in bytes considered usable: 10 KiB. If there is an attempt to set a
   * limit below this - excluding the reserved -1 for input bandwidth - the callback will throw. See
   * the callbacks for outputBandwidthLimit and inputBandwidthLimit. 10 KiB are equivalent to 50 GiB
   * traffic per month.
   */
  private static final int MINIMUM_BANDWIDTH = 10 * 1024;

  /** Quality of Service mark we will use for all outgoing packets (opennet/darknet) */
  private TrafficClass trafficClass;

  public TrafficClass getTrafficClass() {
    return trafficClass;
  }

  /*
   * Gets minimum bandwidth in bytes considered usable.
   *
   * @see #MINIMUM_BANDWIDTH
   */
  public static int getMinimumBandwidth() {
    return MINIMUM_BANDWIDTH;
  }

  /**
   * Dispatches a network probe with the specified parameters.
   *
   * <p>Probes are routed similar to requests and can be used by diagnostics and tooling to assess
   * reachability or measure path characteristics. This method is non‑blocking; completion is
   * reported asynchronously to the provided {@code listener}.
   *
   * @param htl hop‑to‑live used for the probe. Values greater than zero traverse the network; zero
   *     is not valid for a routed probe. Must be in the same range as regular request HTLs.
   * @param uid application‑provided correlation identifier to match callbacks and log entries.
   * @param type the probe {@link Type}; determines behavior and payload of the message.
   * @param listener callback that receives probe results and progress events; must be non‑null.
   * @see Probe#start(byte, long, Type, Listener)
   */
  public void startProbe(final byte htl, final long uid, final Type type, final Listener listener) {
    dispatcher.probe.start(htl, uid, type, listener);
  }

  /**
   * Read all storable settings (identity etc.) from the node file.
   *
   * @param filename The name of the file to read from.
   * @throws IOException throw when I/O error occur
   */
  private void readNodeFile(String filename) throws IOException {
    try (FileInputStream fis = new FileInputStream(filename);
        InputStreamReader isr = new InputStreamReader(fis, StandardCharsets.UTF_8);
        BufferedReader br = new BufferedReader(isr)) {
      SimpleFieldSet fs = new SimpleFieldSet(br, false, true);
      applyUdpFromFieldSet(fs);
      darknetCrypto.readCrypto(fs);
      swapIdentifier = Fields.bytesToLong(darknetCrypto.getIdentityHashHash());
      applyLocationAndNameFromFieldSet(fs);
      applyVersionFromFieldSet(fs);
    }
  }

  private void applyUdpFromFieldSet(SimpleFieldSet fs) throws IOException {
    String[] udp = fs.getAll("physical.udp");
    if (udp == null) return;
    for (String udpAddr : udp) {
      Peer p;
      try {
        p = new Peer(udpAddr, false, true);
      } catch (UnknownHostException _) {
        LOG.info(
            "Unknown host while parsing our darknet node reference: {} (likely host-local scope or"
                + " transient DNS)",
            udpAddr);
        p = null;
      } catch (HostnameSyntaxException _) {
        LOG.error(
            "Invalid hostname or IP Address syntax error while parsing our darknet node reference:"
                + " {}",
            udpAddr);
        p = null;
      } catch (PeerParseException e) {
        throw new IOException(e);
      }
      if (p != null && p.getPort() == getDarknetPortNumber()) {
        // DNSRequester doesn't deal with our own node
        ipDetector.setOldIPAddress(p.getFreenetAddress());
        return;
      }
    }
  }

  private void applyLocationAndNameFromFieldSet(SimpleFieldSet fs) throws IOException {
    String loc = fs.get("location");
    double locD = Location.getLocation(loc);
    if (locD == -1.0) throw new IOException("Invalid location: " + loc);
    lm.setLocation(locD);
    myName = fs.get("myName");
    if (myName == null) myName = newName();
  }

  private void applyVersionFromFieldSet(SimpleFieldSet fs) {
    String verString = fs.get("version");
    if (verString == null) {
      LOG.error("No version!");
    } else {
      lastVersion = Version.parseBuildNumberFromVersionStr(verString, -1);
    }
  }

  public void makeStore(String val) throws InvalidConfigValueException {
    if (val.equals(TYPE_SALT_HASH)) {
      try {
        initSaltHashFS(true, null);
      } catch (NodeInitException e) {
        throw new InvalidConfigValueException(e);
      }
    } else {
      initRAMFS();
    }

    synchronized (Node.this) {
      storeType = val;
    }
  }

  private String newName() {
    return "Crypta node with no name #" + random.nextLong();
  }

  private final Object writeNodeFileSync = new Object();

  private void logStartupInfo() {
    String tmp =
        "Initializing Node using Crypta v"
            + Version.currentBuildNumber()
            + "+"
            + Version.gitRevision()
            + " with "
            + System.getProperty("java.vendor")
            + " JVM version "
            + System.getProperty("java.version")
            + " running on "
            + System.getProperty("os.arch")
            + ' '
            + new network.crypta.fs.AppEnv().osNameRaw()
            + ' '
            + new network.crypta.fs.AppEnv().osVersionRaw();
    LOG.info(tmp);
  }

  private record NodeProgramDirs(
      ProgramDirectory userDir,
      ProgramDirectory cfgDir,
      ProgramDirectory nodeDir,
      ProgramDirectory runDir,
      ProgramDirectory pluginDir) {}

  private NodeProgramDirs setupProgramDirectories(SubConfig installConfig)
      throws NodeInitException {
    AppEnv appEnv = new AppEnv();
    Path defaultConfigDir;
    Path defaultDataDir;
    Path defaultRunDir;
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
        setupProgramDir(
            installConfig,
            "userDir",
            defaultConfigDir.toString(),
            "Node.userDir",
            "Node.userDirLong");
    ProgramDirectory cfgDirLocal =
        setupProgramDir(
            installConfig, "cfgDir", defaultConfigDir.toString(), "Node.cfgDir", "Node.cfgDirLong");
    ProgramDirectory nodeDirLocal =
        setupProgramDir(
            installConfig,
            "nodeDir",
            defaultDataDir.resolve("node").toString(),
            "Node.nodeDir",
            "Node.nodeDirLong");
    ProgramDirectory runDirLocal =
        setupProgramDir(
            installConfig, "runDir", defaultRunDir.toString(), "Node.runDir", "Node.runDirLong");
    ProgramDirectory pluginDirLocal =
        setupProgramDir(
            installConfig,
            "pluginDir",
            defaultDataDir.resolve("plugins").toString(),
            "Node.pluginDir",
            "Node.pluginDirLong");
    return new NodeProgramDirs(
        userDirLocal, cfgDirLocal, nodeDirLocal, runDirLocal, pluginDirLocal);
  }

  private int configureLocalization(SubConfig nodeConfig, int sortOrder) {
    nodeConfig.register(
        "l10n",
        Locale.getDefault().getLanguage().toLowerCase(),
        sortOrder++,
        false,
        true,
        "Node.l10nLanguage",
        "Node.l10nLanguageLong",
        new L10nCallback());

    try {
      new NodeL10n(BaseL10n.LANGUAGE.mapToLanguage(nodeConfig.getString("l10n")), getCfgDir());
    } catch (MissingResourceException _) {
      try {
        new NodeL10n(
            BaseL10n.LANGUAGE.mapToLanguage(nodeConfig.getOption("l10n").getDefault()),
            getCfgDir());
      } catch (MissingResourceException _) {
        new NodeL10n(
            BaseL10n.LANGUAGE.mapToLanguage(BaseL10n.LANGUAGE.getDefault().shortCode), getCfgDir());
      }
    }
    return sortOrder;
  }

  private SimpleToadletServer startWebInterface(
      PersistentConfig config, PriorityAwareExecutor executor) throws NodeInitException {
    SubConfig fproxyConfig = config.createSubConfig("fproxy");
    try {
      SimpleToadletServer toadlets =
          new SimpleToadletServer(fproxyConfig, new ArrayBucketFactory(), executor, this);
      fproxyConfig.finishedInitialization();
      toadlets.start();
      return toadlets;
    } catch (InvalidConfigValueException e4) {
      throw new NodeInitException(
          NodeInitException.EXIT_COULD_NOT_START_FPROXY, "Could not start FProxy: " + e4);
    }
  }

  private NativeThread createEntropyGatheringThread() {
    return new NativeThread(
        new EntropyGatheringTask(this),
        "Entropy Gathering Thread",
        NativeThread.PriorityLevel.MIN_PRIORITY.value,
        true);
  }

  private static final class EntropyGatheringTask implements Runnable {
    private static final int EXTEND_BY = 60 * 60 * 1000;
    private final Node node;
    private long tLastAdded = -1;

    EntropyGatheringTask(Node node) {
      this.node = node;
    }

    @Override
    public void run() {
      try {
        Thread.sleep(100);
      } catch (InterruptedException _) {
        Thread.currentThread().interrupt();
      }
      if (node.isPRNGReady) return;
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
        if (node.isPRNGReady) return;
        recurse(root);
      }
    }

    private void recurse(File f) {
      if (node.isPRNGReady) return;
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
      WrapperManager.signalStarting((int) extend);
      tLastAdded = now;
    }
  }

  private record RandomBundle(
      RandomSource random, SecureRandom secureRandom, Random fastWeakRandom) {}

  private RandomBundle setupRandomSources(
      RandomSource r,
      RandomSource weakRandom,
      SimpleToadletServer toadlets,
      NativeThread entropyGatheringThread) {
    RandomSource initRandom;
    if (r == null) {
      // Preload required freenet.crypt.Util and freenet.crypt.Rijndael classes (selftest can delay
      // Yarrow startup and trigger false lack-of-enthropy message). Log the size to use the value.
      if (LOG.isDebugEnabled())
        LOG.debug("Digest providers preloaded: {}", Util.mdProviders.size());
      Rijndael.getProviderName();

      File seed = userDir.file("prng.seed");
      FileUtil.setOwnerRW(seed);
      entropyGatheringThread.start();
      initRandom = new Yarrow(seed);
      // http://bugs.sun.com/view_bug.do?bug_id=4705093
      // This might block on /dev/random while doing new SecureRandom(). Once it's created, it won't
      // block.
      ECDH.blockingInit();
    } else {
      initRandom = r;
    }
    SecureRandom initSecureRandom = NodeStarter.getGlobalSecureRandom();
    isPRNGReady = true;
    toadlets.getStartupToadlet().setIsPRNGReady();
    Random initFastWeak = weakRandom != null ? weakRandom : createRandom();
    return new RandomBundle(initRandom, initSecureRandom, initFastWeak);
  }

  public void writeNodeFile() {
    synchronized (writeNodeFileSync) {
      writeNodeFile(
          nodeDir.file(NODE_FILE_PREFIX + getDarknetPortNumber()),
          nodeDir.file(NODE_FILE_PREFIX + getDarknetPortNumber() + ".bak"));
    }
  }

  public void writeOpennetFile() {
    OpennetManager om = opennet;
    if (om != null) om.writeFile();
  }

  private void writeNodeFile(File orig, File backup) {
    SimpleFieldSet fs = darknetCrypto.exportPrivateFieldSet();

    if (orig.exists()) {
      try {
        Files.delete(backup.toPath());
      } catch (IOException e) {
        LOG.info("Failed to delete backup {}: {}", backup, e.getMessage(), e);
      }
    }

    try (FileOutputStream fos = new FileOutputStream(backup)) {
      fs.writeTo(fos);
      FileUtil.moveTo(backup, orig);
    } catch (IOException ioe) {
      LOG.error("IOE :{}", ioe.getMessage(), ioe);
    }
  }

  private static long parseBootIdFromHex(String s) {
    try {
      return Fields.bytesToLong(HexUtil.hexToBytes(s));
    } catch (NumberFormatException _) {
      return -1;
    }
  }

  private void initNodeFileSettings() {
    LOG.info("Creating new node file from scratch");
    // Don't need to set getDarknetPortNumber()
    // Use a real IP address.
    darknetCrypto.initCrypto();
    swapIdentifier = Fields.bytesToLong(darknetCrypto.getIdentityHashHash());
    myName = newName();
  }

  /**
   * Entry point delegating to {@link NodeStarter}. Parses CLI arguments and boots the wrapper‑
   * managed node process.
   *
   * @param args command‑line arguments passed to the node launcher. Unknown options are forwarded
   *     to {@link NodeStarter} and may control wrapper behavior, config paths, or startup mode.
   */
  public static void main(String[] args) {
    NodeStarter.main(args);
  }

  public boolean isUsingWrapper() {
    return nodeStarter != null && WrapperManager.isControlledByNativeWrapper();
  }

  public NodeStarter getNodeStarter() {
    return nodeStarter;
  }

  /**
   * Create a Node from a Config object.
   *
   * @param config The Config object for this node.
   * @param r The random number generator for this node. Passed in because we may want to use a
   *     non-secure RNG for e.g. one-JVM live-code simulations. Should be a Yarrow in a production
   *     node. Yarrow will be used if that parameter is null
   * @param weakRandom The fast random number generator the node will use. If null an MT instance
   *     will be used, seeded from the secure PRNG.
   * @param ns NodeStarter
   * @param executor Executor
   * @throws NodeInitException If the node initialization fails.
   */
  @SuppressWarnings("java:S3776")
  Node(
      PersistentConfig config,
      RandomSource r,
      RandomSource weakRandom,
      NodeStarter ns,
      PriorityAwareExecutor executor)
      throws NodeInitException {
    this.shutdownHook = SemiOrderedShutdownHook.get();
    logStartupInfo();
    collector = new IOStatisticCollector();
    this.executor = executor;
    this.nodeStarter = ns;
    getPubKey = new NodeGetPubkey(this);
    startupTime = System.currentTimeMillis();
    SimpleFieldSet oldConfig = config.getSimpleFieldSet();
    final SubConfig nodeConfig = config.createSubConfig("node");
    final SubConfig installConfig = config.createSubConfig("node.install");

    int sortOrder = 0;

    NodeProgramDirs pd = setupProgramDirectories(installConfig);
    this.userDir = pd.userDir;
    this.cfgDir = pd.cfgDir;
    this.nodeDir = pd.nodeDir;
    this.runDir = pd.runDir;
    this.pluginDir = pd.pluginDir;
    sortOrder = configureLocalization(nodeConfig, sortOrder);
    SimpleToadletServer toadlets = startWebInterface(config, executor);
    NativeThread entropyGatheringThread = createEntropyGatheringThread();
    RandomBundle rb = setupRandomSources(r, weakRandom, toadlets, entropyGatheringThread);
    this.random = rb.random;
    this.secureRandom = rb.secureRandom;
    this.fastWeakRandom = rb.fastWeakRandom;

    nodeNameUserAlert = new MeaningfulNodeNameUserAlert(this);
    this.config = config;
    lm = new LocationManager(random, this);

    try {
      localhostAddress = InetAddress.getByName("127.0.0.1");
    } catch (UnknownHostException e3) {
      // Does not do a reverse lookup, so this is impossible
      throw new IllegalStateException(e3);
    }
    fLocalhostAddress = new FreenetInetAddress(localhostAddress);

    this.securityLevels = new SecurityLevels(this, config);

    // Location of master key
    nodeConfig.register(
        "masterKeyFile",
        "master.keys",
        sortOrder++,
        true,
        true,
        "Node.masterKeyFile",
        "Node.masterKeyFileLong",
        new StringCallback() {

          @Override
          public String get() {
            if (masterKeysFile == null) return "none";
            else return masterKeysFile.getPath();
          }

          @Override
          public void set(String val) throws InvalidConfigValueException {
            // Localization may be needed
            // Wipe the old one and move
            throw new InvalidConfigValueException(
                "Node.masterKeyFile cannot be changed on the fly, you must shutdown, wipe the old"
                    + " file and reconfigure");
          }
        });
    String value = nodeConfig.getString("masterKeyFile");
    File f;
    if (value.equalsIgnoreCase("none")) {
      f = null;
    } else {
      f = new File(value);

      if (f.exists() && !(f.canWrite() && f.canRead()))
        throw new NodeInitException(
            NodeInitException.EXIT_CANT_WRITE_MASTER_KEYS,
            "Cannot read from and write to master keys file " + f);
    }
    masterKeysFile = f;
    FileUtil.setOwnerRW(masterKeysFile);

    nodeConfig.register(
        "showFriendsVisibilityAlert",
        false,
        sortOrder++,
        true,
        false,
        "Node.showFriendsVisibilityAlert",
        "Node.showFriendsVisibilityAlert",
        new BooleanCallback() {

          @Override
          public Boolean get() {
            synchronized (Node.this) {
              return showFriendsVisibilityAlert;
            }
          }

          @Override
          public void set(Boolean val) {
            synchronized (this) {
              boolean requested = Boolean.TRUE.equals(val);
              if (requested == showFriendsVisibilityAlert) return;
              if (requested) return;
            }
            unregisterFriendsVisibilityAlert();
          }
        });

    showFriendsVisibilityAlert = nodeConfig.getBoolean("showFriendsVisibilityAlert");

    byte[] clientCacheKey = null;

    MasterSecret persistentSecret = null;
    int attempts = 0;
    boolean done = false;
    while (attempts < 2 && !done) {
      try {
        if (securityLevels.physicalThreatLevel == PHYSICAL_THREAT_LEVEL.MAXIMUM) {
          keys = MasterKeys.createRandom(secureRandom);
        } else {
          keys = MasterKeys.read(masterKeysFile, secureRandom, "");
        }
        clientCacheKey = keys.clientCacheMasterKey;
        persistentSecret = keys.getPersistentMasterSecret();
        databaseKey = keys.createDatabaseKey();
        if (securityLevels.getPhysicalThreatLevel() == PHYSICAL_THREAT_LEVEL.HIGH) {
          LOG.warn(
              "Physical threat level is set to HIGH but no password, resetting to NORMAL - probably"
                  + " timing glitch");
          securityLevels.resetPhysicalThreatLevel(PHYSICAL_THREAT_LEVEL.NORMAL);
        }
        done = true;
      } catch (MasterKeysFileSizeException e) {
        LOG.error(
            "Impossible: master keys file {} too {}! Deleting to enable startup, but you will lose"
                + " your client cache.",
            masterKeysFile,
            e.sizeToString());
        try {
          Files.delete(masterKeysFile.toPath());
        } catch (IOException ioe) {
          LOG.warn(
              "Failed to delete master keys file {}: {}", masterKeysFile, ioe.getMessage(), ioe);
        }
      } catch (MasterKeysWrongPasswordException | IOException _) {
        done = true;
      } finally {
        attempts++;
      }
    }

    // Boot ID
    bootID = random.nextLong();
    // Fixed length file containing boot ID. Accessed with random access file. So hopefully it will
    // always be
    // written. Note that we set lastBootID to -1 if we can't _write_ our ID as well as if we can't
    // read it,
    // because if we can't write it then we probably couldn't write it on the last bootup either.
    File bootIDFile = runDir.file("bootID");
    int bootFileLength = 64 / 4; // A long in padded hex bytes
    long oldBootID;

    try (RandomAccessFile raf = new RandomAccessFile(bootIDFile, "rw")) {
      if (raf.length() < bootFileLength) {
        oldBootID = -1;
      } else {
        byte[] buf = new byte[bootFileLength];
        raf.readFully(buf);
        String s = new String(buf, StandardCharsets.ISO_8859_1);
        oldBootID = parseBootIdFromHex(s);
        raf.seek(0);
      }
      String s = HexUtil.bytesToHex(Fields.longToBytes(bootID));
      byte[] buf = s.getBytes(StandardCharsets.ISO_8859_1);
      if (buf.length != bootFileLength) LOG.warn("Not 16 bytes for boot ID {} - WTF??", bootID);
      raf.write(buf);
    } catch (IOException _) {
      oldBootID = -1;
      // If we have an error in reading, *or in writing*, we don't reliably know the last boot ID.
    }
    lastBootID = oldBootID;

    nodeConfig.register(
        "disableProbabilisticHTLs",
        false,
        sortOrder++,
        true,
        false,
        "Node.disablePHTLS",
        "Node.disablePHTLSLong",
        new BooleanCallback() {

          @Override
          public Boolean get() {
            return disableProbabilisticHTLs;
          }

          @Override
          public void set(Boolean val) {
            disableProbabilisticHTLs = val;
          }
        });

    disableProbabilisticHTLs = nodeConfig.getBoolean("disableProbabilisticHTLs");

    nodeConfig.register(
        "maxHTL",
        DEFAULT_MAX_HTL,
        sortOrder++,
        true,
        false,
        "Node.maxHTL",
        "Node.maxHTLLong",
        new ShortCallback() {

          @Override
          public Short get() {
            return maxHTL;
          }

          @Override
          public void set(Short val) throws InvalidConfigValueException {
            if (val < 0) throw new InvalidConfigValueException("Impossible max HTL");
            maxHTL = val;
          }
        },
        false);

    maxHTL = nodeConfig.getShort("maxHTL");

    class TrafficClassCallback extends StringCallback implements EnumerableOptionCallback {
      @Override
      public String get() {
        return trafficClass.name();
      }

      @Override
      public void set(String tcName) throws InvalidConfigValueException, NodeNeedRestartException {
        try {
          trafficClass = TrafficClass.fromNameOrValue(tcName);
        } catch (IllegalArgumentException e) {
          throw new InvalidConfigValueException(e);
        }
        throw new NodeNeedRestartException("TrafficClass cannot change on the fly");
      }

      @Override
      public String[] getPossibleValues() {
        ArrayList<String> array = new ArrayList<>();
        for (TrafficClass tc : TrafficClass.values()) array.add(tc.name());
        return array.toArray(new String[0]);
      }
    }
    nodeConfig.register(
        "trafficClass",
        TrafficClass.getDefault().name(),
        sortOrder++,
        true,
        false,
        "Node.trafficClass",
        "Node.trafficClassLong",
        new TrafficClassCallback());
    String trafficClassValue = nodeConfig.getString("trafficClass");
    try {
      trafficClass = TrafficClass.fromNameOrValue(trafficClassValue);
    } catch (IllegalArgumentException e) {
      LOG.error("Invalid trafficClass:{} resetting the value to default.", trafficClassValue, e);
      trafficClass = TrafficClass.getDefault();
    }

    // These should maybe persist; they need to be private.
    decrementAtMax = random.nextDouble() <= DECREMENT_AT_MAX_PROB;
    decrementAtMin = random.nextDouble() <= DECREMENT_AT_MIN_PROB;

    // Determine where to bind to

    usm = new MessageCore(executor);

    // Consider whether these configs should be under a node.ip subconfig.
    ipDetector = new NodeIPDetector(this);
    sortOrder = ipDetector.registerConfigs(nodeConfig, sortOrder);

    // ARKs enabled?

    nodeConfig.register(
        "enableARKs",
        true,
        sortOrder++,
        true,
        false,
        "Node.enableARKs",
        "Node.enableARKsLong",
        new BooleanCallback() {

          @Override
          public Boolean get() {
            return enableARKs;
          }

          @Override
          public void set(Boolean val) throws InvalidConfigValueException {
            throw new InvalidConfigValueException("Cannot change on the fly");
          }

          @Override
          public boolean isReadOnly() {
            return true;
          }
        });
    enableARKs = nodeConfig.getBoolean("enableARKs");

    nodeConfig.register(
        "enablePerNodeFailureTables",
        true,
        sortOrder++,
        true,
        false,
        "Node.enablePerNodeFailureTables",
        "Node.enablePerNodeFailureTablesLong",
        new BooleanCallback() {

          @Override
          public Boolean get() {
            return enablePerNodeFailureTables;
          }

          @Override
          public void set(Boolean val) throws InvalidConfigValueException {
            throw new InvalidConfigValueException("Cannot change on the fly");
          }

          @Override
          public boolean isReadOnly() {
            return true;
          }
        });
    enablePerNodeFailureTables = nodeConfig.getBoolean("enablePerNodeFailureTables");

    nodeConfig.register(
        "enableULPRDataPropagation",
        true,
        sortOrder++,
        true,
        false,
        "Node.enableULPRDataPropagation",
        "Node.enableULPRDataPropagationLong",
        new BooleanCallback() {

          @Override
          public Boolean get() {
            return enableULPRDataPropagation;
          }

          @Override
          public void set(Boolean val) throws InvalidConfigValueException {
            throw new InvalidConfigValueException("Cannot change on the fly");
          }

          @Override
          public boolean isReadOnly() {
            return true;
          }
        });
    enableULPRDataPropagation = nodeConfig.getBoolean("enableULPRDataPropagation");

    nodeConfig.register(
        "enableSwapping",
        true,
        sortOrder++,
        true,
        false,
        "Node.enableSwapping",
        "Node.enableSwappingLong",
        new BooleanCallback() {

          @Override
          public Boolean get() {
            return enableSwapping;
          }

          @Override
          public void set(Boolean val) throws InvalidConfigValueException {
            throw new InvalidConfigValueException("Cannot change on the fly");
          }

          @Override
          public boolean isReadOnly() {
            return true;
          }
        });
    enableSwapping = nodeConfig.getBoolean("enableSwapping");

    /*
     * Publish our peers' locations is enabled, even in MAXIMUM network security and/or HIGH friends security,
     * because a node which doesn't publish its peers' locations will get dramatically less traffic.
     *
     * Publishing our peers' locations does make us slightly more vulnerable to some attacks, but I don't think
     * it's a big difference: swapping reveals the same information, it just doesn't update as quickly. This
     * may help slightly, but probably not dramatically against a clever attacker.
     *
     * Review this decision.
     */
    nodeConfig.register(
        "publishOurPeersLocation",
        true,
        sortOrder++,
        true,
        false,
        "Node.publishOurPeersLocation",
        "Node.publishOurPeersLocationLong",
        new BooleanCallback() {

          @Override
          public Boolean get() {
            return publishOurPeersLocation;
          }

          @Override
          public void set(Boolean val) {
            publishOurPeersLocation = val;
          }
        });
    publishOurPeersLocation = nodeConfig.getBoolean("publishOurPeersLocation");

    nodeConfig.register(
        "routeAccordingToOurPeersLocation",
        true,
        sortOrder++,
        true,
        false,
        "Node.routeAccordingToOurPeersLocation",
        "Node.routeAccordingToOurPeersLocation",
        new BooleanCallback() {

          @Override
          public Boolean get() {
            return routeAccordingToOurPeersLocation;
          }

          @Override
          public void set(Boolean val) {
            routeAccordingToOurPeersLocation = val;
          }
        });
    routeAccordingToOurPeersLocation = nodeConfig.getBoolean("routeAccordingToOurPeersLocation");

    nodeConfig.register(
        "enableSwapQueueing",
        true,
        sortOrder++,
        true,
        false,
        "Node.enableSwapQueueing",
        "Node.enableSwapQueueingLong",
        new BooleanCallback() {
          @Override
          public Boolean get() {
            return enableSwapQueueing;
          }

          @Override
          public void set(Boolean val) {
            enableSwapQueueing = val;
          }
        });
    enableSwapQueueing = nodeConfig.getBoolean("enableSwapQueueing");

    nodeConfig.register(
        "enablePacketCoalescing",
        true,
        sortOrder++,
        true,
        false,
        "Node.enablePacketCoalescing",
        "Node.enablePacketCoalescingLong",
        new BooleanCallback() {
          @Override
          public Boolean get() {
            return enablePacketCoalescing;
          }

          @Override
          public void set(Boolean val) {
            enablePacketCoalescing = val;
          }
        });
    enablePacketCoalescing = nodeConfig.getBoolean("enablePacketCoalescing");

    // Determine the port number
    // @see #191
    if (oldConfig != null && "-1".equals(oldConfig.get("node.listenPort")))
      throw new NodeInitException(
          NodeInitException.EXIT_COULD_NOT_BIND_USM,
          "Your freenet.ini file is corrupted! 'listenPort=-1'");
    NodeCryptoConfig darknetConfig =
        new NodeCryptoConfig(nodeConfig, sortOrder++, false, securityLevels);
    sortOrder += NodeCryptoConfig.OPTION_COUNT;

    darknetCrypto = new NodeCrypto(this, false, darknetConfig, startupTime, enableARKs);

    // Must be created after darknetCrypto
    dnsr = new DNSRequester(this);
    ps = new PacketSender(this);
    ticker = new PrioritizedTicker(executor, getDarknetPortNumber());
    if (executor instanceof PooledExecutor pooledExecutor) pooledExecutor.setTicker(ticker);

    LOG.info("Creating node...");

    shutdownHook.addEarlyJob(
        new Thread(
            () -> {
              if (opennet != null) opennet.stop(false);
            }));

    shutdownHook.addEarlyJob(new Thread(darknetCrypto::stop));

    // Bandwidth limit

    nodeConfig.register(
        "outputBandwidthLimit",
        "15K",
        sortOrder++,
        false,
        true,
        "Node.outBWLimit",
        "Node.outBWLimitLong",
        new IntCallback() {
          @Override
          public Integer get() {
            return outputBandwidthLimit;
          }

          @Override
          public void set(Integer obwLimit) throws InvalidConfigValueException {
            BandwidthManager.checkOutputBandwidthLimit(obwLimit);
            try {
              outputThrottle.changeNanosAndBucketSize(SECONDS.toNanos(1) / obwLimit, obwLimit / 2);
            } catch (IllegalArgumentException e) {
              throw new InvalidConfigValueException(e);
            }
            synchronized (Node.this) {
              outputBandwidthLimit = obwLimit;
            }
          }
        });

    int obwLimit = nodeConfig.getInt("outputBandwidthLimit");
    if (obwLimit < MINIMUM_BANDWIDTH) {
      obwLimit = MINIMUM_BANDWIDTH; // upgrade slow nodes automatically
      LOG.info(
          "Output bandwidth was lower than minimum bandwidth. Increased to minimum bandwidth.");
    }

    outputBandwidthLimit = obwLimit;
    try {
      BandwidthManager.checkOutputBandwidthLimit(outputBandwidthLimit);
    } catch (InvalidConfigValueException e) {
      throw new NodeInitException(NodeInitException.EXIT_BAD_BWLIMIT, e.getMessage());
    }

    // Bucket size of 0.5 seconds' worth of bytes.
    // Add them at a rate determined by the obwLimit.
    // Maximum forced bytes 80%, in other words, 20% of the bandwidth is reserved for
    // block transfers, so we will use that 20% for block transfers even if more than 80% of the
    // limit is used for non-limited data (resends etc.).
    int bucketSize = obwLimit / 2;
    // Must have at least space for ONE PACKET.
    // Make compatible with alternate transports if needed.
    try {
      outputThrottle = new OutputThrottle(bucketSize, SECONDS.toNanos(1) / obwLimit, obwLimit / 2);
    } catch (IllegalArgumentException e) {
      throw new NodeInitException(NodeInitException.EXIT_BAD_BWLIMIT, e.getMessage());
    }

    nodeConfig.register(
        "inputBandwidthLimit",
        "-1",
        sortOrder++,
        false,
        true,
        "Node.inBWLimit",
        "Node.inBWLimitLong",
        new IntCallback() {
          @Override
          public Integer get() {
            if (inputLimitDefault) return -1;
            return inputBandwidthLimit;
          }

          @Override
          public void set(Integer ibwLimit) throws InvalidConfigValueException {
            synchronized (Node.this) {
              BandwidthManager.checkInputBandwidthLimit(ibwLimit);

              if (ibwLimit == -1) {
                inputLimitDefault = true;
                ibwLimit = outputBandwidthLimit * 4;
              } else {
                inputLimitDefault = false;
              }

              inputBandwidthLimit = ibwLimit;
            }
          }
        });

    int ibwLimit = nodeConfig.getInt("inputBandwidthLimit");
    if (ibwLimit == -1) {
      inputLimitDefault = true;
      ibwLimit = obwLimit * 4;
    } else if (ibwLimit < MINIMUM_BANDWIDTH) {
      ibwLimit = MINIMUM_BANDWIDTH; // upgrade slow nodes automatically
      LOG.info("Input bandwidth was lower than minimum bandwidth. Increased to minimum bandwidth.");
    }
    inputBandwidthLimit = ibwLimit;
    try {
      BandwidthManager.checkInputBandwidthLimit(inputBandwidthLimit);
    } catch (InvalidConfigValueException e) {
      throw new NodeInitException(NodeInitException.EXIT_BAD_BWLIMIT, e.getMessage());
    }

    nodeConfig.register(
        "amountOfDataToCheckCompressionRatio",
        "8MiB",
        sortOrder++,
        true,
        true,
        "Node.amountOfDataToCheckCompressionRatio",
        "Node.amountOfDataToCheckCompressionRatioLong",
        new LongCallback() {
          @Override
          public Long get() {
            return amountOfDataToCheckCompressionRatio;
          }

          @Override
          public void set(Long amountOfDataToCheckCompressionRatio) {
            synchronized (Node.this) {
              if (amountOfDataToCheckCompressionRatio < 0
                  || amountOfDataToCheckCompressionRatio > 100 * 1024 * 1024) {
                LOG.info(
                    "Amount of data to check for compression should be 100 MiB max, {} bytes"
                        + " selected",
                    amountOfDataToCheckCompressionRatio);
                return;
              }

              Node.this.amountOfDataToCheckCompressionRatio = amountOfDataToCheckCompressionRatio;
            }
          }
        },
        true);

    amountOfDataToCheckCompressionRatio = nodeConfig.getLong("amountOfDataToCheckCompressionRatio");

    nodeConfig.register(
        "minimumCompressionPercentage",
        "10",
        sortOrder++,
        true,
        true,
        "Node.minimumCompressionPercentage",
        "Node.minimumCompressionPercentageLong",
        new IntCallback() {
          @Override
          public Integer get() {
            return minimumCompressionPercentage;
          }

          @Override
          public void set(Integer minimumCompressionPercentage) {
            synchronized (Node.this) {
              if (minimumCompressionPercentage < 0 || minimumCompressionPercentage > 100) {
                LOG.info(
                    "Wrong minimum compression percentage: must be between 0 and 100, but is {}",
                    minimumCompressionPercentage);
                return;
              }

              Node.this.minimumCompressionPercentage = minimumCompressionPercentage;
            }
          }
        },
        Dimension.NOT);

    minimumCompressionPercentage = nodeConfig.getInt("minimumCompressionPercentage");

    // max time for single compressor makes the insert compression CPU dependent, so it should not
    // have been used.
    nodeConfig.registerIgnoredOption("maxTimeForSingleCompressor");

    nodeConfig.register(
        "connectionSpeedDetection",
        true,
        sortOrder++,
        true,
        true,
        "Node.connectionSpeedDetection",
        "Node.connectionSpeedDetectionLong",
        new BooleanCallback() {
          @Override
          public Boolean get() {
            return connectionSpeedDetection;
          }

          @Override
          public void set(Boolean connectionSpeedDetection) {
            synchronized (Node.this) {
              Node.this.connectionSpeedDetection = connectionSpeedDetection;
            }
          }
        });

    connectionSpeedDetection = nodeConfig.getBoolean("connectionSpeedDetection");

    nodeConfig.register(
        "throttleLocalTraffic",
        false,
        sortOrder++,
        true,
        false,
        "Node.throttleLocalTraffic",
        "Node.throttleLocalTrafficLong",
        new BooleanCallback() {

          @Override
          public Boolean get() {
            return throttleLocalData;
          }

          @Override
          public void set(Boolean val) {
            throttleLocalData = val;
          }
        });

    throttleLocalData = nodeConfig.getBoolean("throttleLocalTraffic");

    String s =
"""
Testnet mode DISABLED. You may have some level of anonymity. :)
Note that this version of Crypta is still a very early alpha, and may well have numerous bugs and design flaws.
In particular: YOU ARE WIDE OPEN TO YOUR IMMEDIATE PEERS! They can eavesdrop on your requests with relatively little difficulty at present (correlation attacks etc).\
""";
    LOG.info(s);

    File nodeFile = nodeDir.file(NODE_FILE_PREFIX + getDarknetPortNumber());
    File nodeFileBackup = nodeDir.file(NODE_FILE_PREFIX + getDarknetPortNumber() + ".bak");
    // After we have set up testnet and IP address, load the node file
    try {
      // May take file directly in the future.
      readNodeFile(nodeFile.getPath());
    } catch (IOException e) {
      try {
        LOG.info("Trying to read node file backup ...");
        readNodeFile(nodeFileBackup.getPath());
      } catch (IOException e1) {
        if (nodeFile.exists() || nodeFileBackup.exists()) {
          LOG.error("No node file or cannot read, (re)initialising crypto etc", e1);
          LOG.error("After:", e);
        } else {
          LOG.info("Creating new cryptographic keys...");
        }
        initNodeFileSettings();
      }
    }

    // Then read the peers
    peers = new PeerManager(this, shutdownHook);

    tracker = new RequestTracker(peers, ticker);

    dispatcher = new NodeDispatcher(this);
    usm.setDispatcher(dispatcher);

    uptime = new UptimeEstimator(runDir, ticker, darknetCrypto.getIdentityHash());

    // ULPRs

    failureTable = new FailureTable(this);

    nodeStats = new NodeStats(this, sortOrder, config.createSubConfig("node.load"));

    // clientCore needs new load management and other settings from stats.
    NodeClientCoreInit clientCoreInit =
        new NodeClientCoreInit(config, nodeConfig, installConfig, toadlets);
    clientCore =
        new NodeClientCore(
            this, clientCoreInit, getDarknetPortNumber(), sortOrder, databaseKey, persistentSecret);
    toadlets.setCore(clientCore);

    if (JVMVersion.isEOL()) {
      clientCore.getAlerts().register(new JVMVersionAlert());
    }

    if (showFriendsVisibilityAlert) registerFriendsVisibilityAlert();

    // Node updater support

    LOG.info("Initializing Node Updater");
    try {
      nodeUpdater = NodeUpdateManager.maybeCreate(this, config);
    } catch (InvalidConfigValueException e) {
      throw new NodeInitException(
          NodeInitException.EXIT_COULD_NOT_START_UPDATER, "Could not create Updater: " + e);
    }

    // Opennet

    final SubConfig opennetConfig = config.createSubConfig("node.opennet");
    opennetConfig.register(
        "connectToSeednodes",
        true,
        0,
        true,
        false,
        "Node.withAnnouncement",
        "Node.withAnnouncementLong",
        new BooleanCallback() {
          @Override
          public Boolean get() {
            return isAllowedToConnectToSeednodes;
          }

          @Override
          public void set(Boolean val) throws NodeNeedRestartException {
            if (get().equals(val)) return;
            synchronized (Node.this) {
              isAllowedToConnectToSeednodes = val;
              if (opennet != null)
                throw new NodeNeedRestartException(
                    l10n("connectToSeednodesCannotBeChangedMustDisableOpennetOrReboot"));
            }
          }
        });
    isAllowedToConnectToSeednodes = opennetConfig.getBoolean("connectToSeednodes");

    // Can be enabled on the fly
    opennetConfig.register(
        "enabled",
        false,
        0,
        true,
        true,
        "Node.opennetEnabled",
        "Node.opennetEnabledLong",
        new BooleanCallback() {
          @Override
          public Boolean get() {
            synchronized (Node.this) {
              return opennet != null;
            }
          }

          @Override
          public void set(Boolean val) throws InvalidConfigValueException {
            OpennetManager o;
            boolean enable = Boolean.TRUE.equals(val);
            synchronized (Node.this) {
              if (enable == (opennet != null)) return;
              if (enable) {
                try {
                  o =
                      opennet =
                          new OpennetManager(
                              Node.this,
                              opennetCryptoConfig,
                              System.currentTimeMillis(),
                              isAllowedToConnectToSeednodes);
                } catch (NodeInitException e) {
                  opennet = null;
                  throw new InvalidConfigValueException(e.getMessage());
                }
              } else {
                o = opennet;
                opennet = null;
              }
            }
            if (enable) o.start();
            else o.stop(true);
            ipDetector.ipDetectorManager.notifyPortChange(getPublicInterfacePorts());
          }
        });
    boolean opennetEnabled = opennetConfig.getBoolean("enabled");

    opennetConfig.register(
        "maxOpennetPeers",
        OpennetManager.MAX_PEERS_FOR_SCALING,
        1,
        true,
        false,
        "Node.maxOpennetPeers",
        "Node.maxOpennetPeersLong",
        new IntCallback() {
          @Override
          public Integer get() {
            return maxOpennetPeers;
          }

          @Override
          public void set(Integer inputMaxOpennetPeers) throws InvalidConfigValueException {
            if (inputMaxOpennetPeers < 0)
              throw new InvalidConfigValueException(l10n("mustBePositive"));
            if (inputMaxOpennetPeers > OpennetManager.MAX_PEERS_FOR_SCALING)
              throw new InvalidConfigValueException(
                  l10n(
                      "maxOpennetPeersMustBeTwentyOrLess",
                      "maxpeers",
                      Integer.toString(OpennetManager.MAX_PEERS_FOR_SCALING)));
            maxOpennetPeers = inputMaxOpennetPeers;
          }
        },
        false);

    maxOpennetPeers = opennetConfig.getInt("maxOpennetPeers");
    if (maxOpennetPeers > OpennetManager.MAX_PEERS_FOR_SCALING) {
      LOG.error("maxOpennetPeers may not be over {}", OpennetManager.MAX_PEERS_FOR_SCALING);
      maxOpennetPeers = OpennetManager.MAX_PEERS_FOR_SCALING;
    }

    opennetCryptoConfig =
        new NodeCryptoConfig(opennetConfig, 2 /* 0 = enabled */, true, securityLevels);

    if (opennetEnabled) {
      opennet =
          new OpennetManager(
              this, opennetCryptoConfig, System.currentTimeMillis(), isAllowedToConnectToSeednodes);
      // Will be started later
    } else {
      opennet = null;
    }

    securityLevels.addNetworkThreatLevelListener(
        (oldLevel, newLevel) -> {
          if (newLevel == NETWORK_THREAT_LEVEL.HIGH || newLevel == NETWORK_THREAT_LEVEL.MAXIMUM) {
            OpennetManager om;
            synchronized (Node.this) {
              om = opennet;
              if (om != null) {
                opennet = null;
              }
            }
            if (om != null) {
              om.stop(true);
              ipDetector.ipDetectorManager.notifyPortChange(getPublicInterfacePorts());
            }
          } else if (newLevel == NETWORK_THREAT_LEVEL.NORMAL
              || newLevel == NETWORK_THREAT_LEVEL.LOW) {
            OpennetManager o = null;
            synchronized (Node.this) {
              if (opennet == null) {
                try {
                  o =
                      opennet =
                          new OpennetManager(
                              Node.this,
                              opennetCryptoConfig,
                              System.currentTimeMillis(),
                              isAllowedToConnectToSeednodes);
                } catch (NodeInitException e) {
                  opennet = null;
                  LOG.error("UNABLE TO ENABLE OPENNET: {}", e, e);
                  clientCore
                      .getAlerts()
                      .register(
                          new SimpleUserAlert(
                              false,
                              l10n("enableOpennetFailedTitle"),
                              l10n("enableOpennetFailed", "message", e.getLocalizedMessage()),
                              l10n("enableOpennetFailed", "message", e.getLocalizedMessage()),
                              UserAlert.ERROR));
                }
              }
            }
            if (o != null) {
              o.start();
              ipDetector.ipDetectorManager.notifyPortChange(getPublicInterfacePorts());
            }
          }
          Node.this.config.store();
        });

    opennetConfig.register(
        "acceptSeedConnections",
        false,
        2,
        true,
        true,
        "Node.acceptSeedConnectionsShort",
        "Node.acceptSeedConnections",
        new BooleanCallback() {

          @Override
          public Boolean get() {
            return acceptSeedConnections;
          }

          @Override
          public void set(Boolean val) {
            acceptSeedConnections = val;
          }
        });

    acceptSeedConnections = opennetConfig.getBoolean("acceptSeedConnections");

    if (acceptSeedConnections && opennet != null)
      opennet.getCrypto().getSocket().getAddressTracker().setHugeTracker();

    opennetConfig.finishedInitialization();

    nodeConfig.register(
        "passOpennetPeersThroughDarknet",
        true,
        sortOrder++,
        true,
        false,
        "Node.passOpennetPeersThroughDarknet",
        "Node.passOpennetPeersThroughDarknetLong",
        new BooleanCallback() {

          @Override
          public Boolean get() {
            synchronized (Node.this) {
              return passOpennetRefsThroughDarknet;
            }
          }

          @Override
          public void set(Boolean val) {
            synchronized (Node.this) {
              passOpennetRefsThroughDarknet = val;
            }
          }
        });

    passOpennetRefsThroughDarknet = nodeConfig.getBoolean("passOpennetPeersThroughDarknet");

    this.extraPeerDataDir = userDir.file("extra-peer-data-" + getDarknetPortNumber());
    if (!((extraPeerDataDir.exists() && extraPeerDataDir.isDirectory())
        || (extraPeerDataDir.mkdir()))) {
      String msg = "Could not find or create extra peer data directory";
      throw new NodeInitException(NodeInitException.EXIT_BAD_DIR, msg);
    }

    // Name
    nodeConfig.register(
        "name",
        myName,
        sortOrder++,
        false,
        true,
        "Node.nodeName",
        "Node.nodeNameLong",
        new NodeNameCallback());
    myName = nodeConfig.getString("name");

    // Datastore
    nodeConfig.register(
        "storeForceBigShrinks",
        false,
        sortOrder++,
        true,
        false,
        "Node.forceBigShrink",
        "Node.forceBigShrinkLong",
        new BooleanCallback() {

          @Override
          public Boolean get() {
            synchronized (Node.this) {
              return storeForceBigShrinks;
            }
          }

          @Override
          public void set(Boolean val) {
            synchronized (Node.this) {
              storeForceBigShrinks = val;
            }
          }
        });

    // Datastore

    nodeConfig.register(
        "storeType",
        "ram",
        sortOrder++,
        true,
        true,
        "Node.storeType",
        "Node.storeTypeLong",
        new StoreTypeCallback());

    storeType = nodeConfig.getString("storeType");

    /*
     * Very small initial store size, since the node will preallocate it when starting up for the first time,
     * BLOCKING STARTUP, and since everyone goes through the wizard anyway...
     */
    nodeConfig.register(
        "storeSize",
        DEFAULT_STORE_SIZE,
        sortOrder++,
        false,
        true,
        "Node.storeSize",
        "Node.storeSizeLong",
        new LongCallback() {

          @Override
          public Long get() {
            return maxTotalDatastoreSize;
          }

          @Override
          public void set(Long storeSize) throws InvalidConfigValueException {
            long maxDatastoreSize;
            if (storeSize < MIN_STORE_SIZE) {
              throw new InvalidConfigValueException(l10n("invalidMinStoreSize"));
            }
            if (storeSize > (maxDatastoreSize = DatastoreUtil.maxDatastoreSize())) {
              throw new InvalidConfigValueException(
                  l10n("invalidMaxStoreSize", Long.toString(maxDatastoreSize / ONE_GIB)));
            }

            long newMaxStoreKeys = storeSize / SIZE_PER_KEY;
            if (newMaxStoreKeys == maxTotalKeys) return;
            // Update each datastore
            synchronized (Node.this) {
              maxTotalDatastoreSize = storeSize;
              maxTotalKeys = newMaxStoreKeys;
              maxStoreKeys = maxTotalKeys / 2;
              maxCacheKeys = maxTotalKeys - maxStoreKeys;
            }
            try {
              chkDatastore.setMaxKeys(maxStoreKeys, storeForceBigShrinks);
              chkDatacache.setMaxKeys(maxCacheKeys, storeForceBigShrinks);
              pubKeyDatastore.setMaxKeys(maxStoreKeys, storeForceBigShrinks);
              pubKeyDatacache.setMaxKeys(maxCacheKeys, storeForceBigShrinks);
              sskDatastore.setMaxKeys(maxStoreKeys, storeForceBigShrinks);
              sskDatacache.setMaxKeys(maxCacheKeys, storeForceBigShrinks);
            } catch (IOException e) {
              LOG.error("Caught exception resizing the datastore", e);
            }
            // Perhaps a bit hackish...? Seems like this should be near its definition in
            // NodeStats.
            nodeStats.avgStoreCHKLocation.changeMaxReports((int) maxStoreKeys);
            nodeStats.avgCacheCHKLocation.changeMaxReports((int) maxCacheKeys);
            nodeStats.avgSlashdotCacheCHKLocation.changeMaxReports((int) maxCacheKeys);
            nodeStats.avgClientCacheCHKLocation.changeMaxReports((int) maxCacheKeys);

            nodeStats.avgStoreSSKLocation.changeMaxReports((int) maxStoreKeys);
            nodeStats.avgCacheSSKLocation.changeMaxReports((int) maxCacheKeys);
            nodeStats.avgSlashdotCacheSSKLocation.changeMaxReports((int) maxCacheKeys);
            nodeStats.avgClientCacheSSKLocation.changeMaxReports((int) maxCacheKeys);
          }
        },
        true);

    maxTotalDatastoreSize = nodeConfig.getLong("storeSize");

    if (maxTotalDatastoreSize < MIN_STORE_SIZE
        && !storeType.equals("ram")) { // totally arbitrary minimum!
      throw new NodeInitException(
          NodeInitException.EXIT_INVALID_STORE_SIZE, "Store size too small");
    }

    maxTotalKeys = maxTotalDatastoreSize / SIZE_PER_KEY;

    nodeConfig.register(
        "storeUseSlotFilters",
        true,
        sortOrder++,
        true,
        false,
        "Node.storeUseSlotFilters",
        "Node.storeUseSlotFiltersLong",
        new BooleanCallback() {

          public Boolean get() {
            synchronized (Node.this) {
              return storeUseSlotFilters;
            }
          }

          public void set(Boolean val) throws NodeNeedRestartException {
            synchronized (Node.this) {
              storeUseSlotFilters = val;
            }

            throw new NodeNeedRestartException("Need to restart to change storeUseSlotFilters");
          }
        });

    storeUseSlotFilters = nodeConfig.getBoolean("storeUseSlotFilters");

    nodeConfig.register(
        "storeSaltHashSlotFilterPersistenceTime",
        ResizablePersistentIntBuffer.DEFAULT_PERSISTENCE_TIME,
        sortOrder++,
        true,
        false,
        "Node.storeSaltHashSlotFilterPersistenceTime",
        "Node.storeSaltHashSlotFilterPersistenceTimeLong",
        new IntCallback() {

          @Override
          public Integer get() {
            return storeSaltHashSlotFilterPersistenceTime;
          }

          @Override
          public void set(Integer val) throws InvalidConfigValueException {
            if (val >= -1) {
              ResizablePersistentIntBuffer.setPersistenceTime(val);
              storeSaltHashSlotFilterPersistenceTime = val;
            } else throw new InvalidConfigValueException(l10n("slotFilterPersistenceTimeError"));
          }
        },
        false);
    storeSaltHashSlotFilterPersistenceTime =
        nodeConfig.getInt("storeSaltHashSlotFilterPersistenceTime");

    nodeConfig.register(
        "storeSaltHashResizeOnStart",
        false,
        sortOrder++,
        true,
        false,
        "Node.storeSaltHashResizeOnStart",
        "Node.storeSaltHashResizeOnStartLong",
        new BooleanCallback() {
          @Override
          public Boolean get() {
            return storeSaltHashResizeOnStart;
          }

          @Override
          public void set(Boolean val) {
            storeSaltHashResizeOnStart = val;
          }
        });
    storeSaltHashResizeOnStart = nodeConfig.getBoolean("storeSaltHashResizeOnStart");

    // Determine default data base again for storeDir (separate from earlier setup)
    Path defaultDataBase;
    AppEnv appEnv0 = new AppEnv();
    if (appEnv0.isServiceMode()) {
      defaultDataBase = new ServiceDirs().resolve().getDataDir();
    } else {
      defaultDataBase = new AppDirs().resolve().getDataDir();
    }

    this.storeDir =
        setupProgramDir(
            installConfig,
            "storeDir",
            defaultDataBase.toString(),
            "Node.storeDirectory",
            "Node.storeDirectoryLong");
    installConfig.finishedInitialization();

    // Store suffix resolved lazily by factory methods where required.

    maxStoreKeys = maxTotalKeys / 2;
    maxCacheKeys = maxTotalKeys - maxStoreKeys;

    /*
     * On Windows, setting the file length normally involves writing lots of zeros.
     * So it's an uninterruptible system call that takes a loooong time. On OS/X,
     * presumably the same is true. If the RNG is fast enough, this means that
     * setting the length and writing random data take exactly the same amount
     * of time. On most versions of Unix, holes can be created. However on all
     * systems, predictable disk usage is a good thing. So lets turn it on by
     * default for now, on all systems. The datastore can be read but mostly not
     * written while the random data is being written.
     */
    nodeConfig.register(
        STORE_PREALLOCATE_KEY,
        true,
        sortOrder++,
        true,
        true,
        "Node.storePreallocate",
        "Node.storePreallocateLong",
        new BooleanCallback() {
          @Override
          public Boolean get() {
            return storePreallocate;
          }

          @Override
          public void set(Boolean val) {
            storePreallocate = val;
            if (storeType.equals(TYPE_SALT_HASH)) {
              setPreallocate(chkDatastore, val);
              setPreallocate(chkDatacache, val);
              setPreallocate(pubKeyDatastore, val);
              setPreallocate(pubKeyDatacache, val);
              setPreallocate(sskDatastore, val);
              setPreallocate(sskDatacache, val);
            }
          }

          private void setPreallocate(StoreCallback<?> datastore, boolean val) {
            // Avoid race conditions by checking first.
            FreenetStore<?> store = datastore.getStore();
            if (store instanceof SaltedHashFreenetStore<?> freenetStore)
              freenetStore.setPreallocate(val);
          }
        });
    storePreallocate = nodeConfig.getBoolean(STORE_PREALLOCATE_KEY);

    if (File.separatorChar == '/' && !(new network.crypta.fs.AppEnv().isMac())) {
      securityLevels.addPhysicalThreatLevelListener(
          (oldLevel, newLevel) -> {
            try {
              nodeConfig.set(STORE_PREALLOCATE_KEY, newLevel != PHYSICAL_THREAT_LEVEL.LOW);
            } catch (NodeNeedRestartException | InvalidConfigValueException _) {
              // Ignore
            }
          });
    }

    securityLevels.addPhysicalThreatLevelListener(
        new SecurityLevelListener<>() {

          @Override
          public void onChange(PHYSICAL_THREAT_LEVEL oldLevel, PHYSICAL_THREAT_LEVEL newLevel) {
            if (newLevel == PHYSICAL_THREAT_LEVEL.MAXIMUM) {
              synchronized (this) {
                clientCacheAwaitingPassword = false;
                databaseAwaitingPassword = false;
              }
              try {
                killMasterKeysFile();
                clientCore.getClientLayerPersister().disableWrite();
                clientCore.getClientLayerPersister().waitForNotWriting();
                clientCore.getClientLayerPersister().deleteAllFiles();
              } catch (IOException _) {
                try {
                  Files.delete(masterKeysFile.toPath());
                } catch (IOException ioe) {
                  LOG.warn(
                      "Fallback Files.delete() failed for {}: {}",
                      masterKeysFile,
                      ioe.getMessage(),
                      ioe);
                }
                LOG.error("Unable to securely delete {}", masterKeysFile);
                LOG.error(
                    NodeL10n.getBase()
                        .getString(
                            "SecurityLevels.cantDeletePasswordFile",
                            "filename",
                            masterKeysFile.getAbsolutePath()));
                clientCore
                    .getAlerts()
                    .register(
                        new SimpleUserAlert(
                            true,
                            NodeL10n.getBase()
                                .getString("SecurityLevels.cantDeletePasswordFileTitle"),
                            NodeL10n.getBase().getString("SecurityLevels.cantDeletePasswordFile"),
                            NodeL10n.getBase()
                                .getString("SecurityLevels.cantDeletePasswordFileTitle"),
                            UserAlert.CRITICAL_ERROR));
              }
            }
            if (oldLevel == PHYSICAL_THREAT_LEVEL.MAXIMUM
                && newLevel != PHYSICAL_THREAT_LEVEL.HIGH) {
              // Not passworded.
              // Create the master.keys.
              // Keys must exist.
              try {
                MasterKeys currentKeys;
                synchronized (this) {
                  currentKeys = Node.this.keys;
                }
                currentKeys.changePassword(masterKeysFile, "", secureRandom);
              } catch (IOException e) {
                LOG.error("Unable to create encryption keys file: {}", masterKeysFile, e);
              }
            }
          }
        });

    if (securityLevels.physicalThreatLevel == PHYSICAL_THREAT_LEVEL.MAXIMUM) {
      try {
        killMasterKeysFile();
      } catch (IOException _) {
        String msg =
            "Unable to securely delete old master.keys file when switching to MAXIMUM seclevel!!";
        LOG.error(msg);
        throw new NodeInitException(NodeInitException.EXIT_CANT_WRITE_MASTER_KEYS, msg);
      }
    }

    long defaultCacheSize = getDefaultCacheSize();

    nodeConfig.register(
        "cachingFreenetStoreMaxSize",
        defaultCacheSize,
        sortOrder++,
        true,
        false,
        "Node.cachingCryptaStoreMaxSize",
        "Node.cachingCryptaStoreMaxSizeLong",
        new LongCallback() {
          @Override
          public Long get() {
            synchronized (Node.this) {
              return cachingFreenetStoreMaxSize;
            }
          }

          @Override
          public void set(Long val) throws InvalidConfigValueException, NodeNeedRestartException {
            if (val < 0) throw new InvalidConfigValueException(l10n("invalidMemoryCacheSize"));
            // Any positive value is legal. In particular, e.g. 1200 bytes would cause us to cache
            // SSKs but not CHKs.
            synchronized (Node.this) {
              cachingFreenetStoreMaxSize = val;
            }
            throw new NodeNeedRestartException("Caching Maximum Size cannot be changed on the fly");
          }
        },
        true);

    cachingFreenetStoreMaxSize = nodeConfig.getLong("cachingFreenetStoreMaxSize");
    if (cachingFreenetStoreMaxSize < 0)
      throw new NodeInitException(
          NodeInitException.EXIT_BAD_CONFIG, l10n("invalidMemoryCacheSize"));

    nodeConfig.register(
        "cachingFreenetStorePeriod",
        "300k",
        sortOrder++,
        true,
        false,
        "Node.cachingCryptaStorePeriod",
        "Node.cachingCryptaStorePeriod",
        new LongCallback() {
          @Override
          public Long get() {
            synchronized (Node.this) {
              return cachingFreenetStorePeriod;
            }
          }

          @Override
          public void set(Long val) throws NodeNeedRestartException {
            synchronized (Node.this) {
              cachingFreenetStorePeriod = val;
            }
            throw new NodeNeedRestartException("Caching Period cannot be changed on the fly");
          }
        },
        true);

    cachingFreenetStorePeriod = nodeConfig.getLong("cachingFreenetStorePeriod");

    if (cachingFreenetStoreMaxSize > 0 && cachingFreenetStorePeriod > 0) {
      cachingFreenetStoreTracker =
          new CachingFreenetStoreTracker(
              cachingFreenetStoreMaxSize, cachingFreenetStorePeriod, ticker);
    }

    boolean shouldWriteConfig = false;

    if (storeType.equals("bdb-index")) {
      LOG.warn("Old format Berkeley DB datastore detected.");
      LOG.warn("This datastore format is no longer supported.");
      LOG.warn("The old datastore will be securely deleted.");
      storeType = TYPE_SALT_HASH;
      shouldWriteConfig = true;
      deleteOldBDBIndexStoreFiles();
    }
    if (storeType.equals(TYPE_SALT_HASH)) {
      initRAMFS();
      initSaltHashFS(false, null);
    } else {
      initRAMFS();
    }

    if (databaseAwaitingPassword) createPasswordUserAlert();

    // Client cache

    // Default is 10MB, in memory only. The wizard will change this.

    nodeConfig.register(
        "clientCacheType",
        "ram",
        sortOrder++,
        true,
        true,
        "Node.clientCacheType",
        "Node.clientCacheTypeLong",
        new ClientCacheTypeCallback());

    clientCacheType = nodeConfig.getString("clientCacheType");

    nodeConfig.register(
        "clientCacheSize",
        DEFAULT_CLIENT_CACHE_SIZE,
        sortOrder++,
        false,
        true,
        "Node.clientCacheSize",
        "Node.clientCacheSizeLong",
        new LongCallback() {

          @Override
          public Long get() {
            return maxTotalClientCacheSize;
          }

          @Override
          public void set(Long storeSize) throws InvalidConfigValueException {
            if (storeSize < MIN_CLIENT_CACHE_SIZE)
              throw new InvalidConfigValueException(l10n("invalidStoreSize"));
            long newMaxStoreKeys = storeSize / SIZE_PER_KEY;
            if (newMaxStoreKeys == maxClientCacheKeys) return;
            // Update each datastore
            synchronized (Node.this) {
              maxTotalClientCacheSize = storeSize;
              maxClientCacheKeys = newMaxStoreKeys;
            }
            try {
              chkClientcache.setMaxKeys(maxClientCacheKeys, storeForceBigShrinks);
              pubKeyClientcache.setMaxKeys(maxClientCacheKeys, storeForceBigShrinks);
              sskClientcache.setMaxKeys(maxClientCacheKeys, storeForceBigShrinks);
            } catch (IOException e) {
              LOG.error("Caught exception resizing the clientcache", e);
            }
          }
        },
        true);

    maxTotalClientCacheSize = nodeConfig.getLong("clientCacheSize");

    if (maxTotalClientCacheSize < MIN_CLIENT_CACHE_SIZE) {
      throw new NodeInitException(
          NodeInitException.EXIT_INVALID_STORE_SIZE, "Client cache size too small");
    }

    maxClientCacheKeys = maxTotalClientCacheSize / SIZE_PER_KEY;

    boolean startedClientCache = false;

    if (clientCacheType.equals(TYPE_SALT_HASH)) {
      if (clientCacheKey == null) {
        LOG.warn("Cannot open client-cache, it is passworded");
        setClientCacheAwaitingPassword();
      } else {
        initSaltHashClientCacheFS(false, clientCacheKey);
        startedClientCache = true;
      }
    } else if (clientCacheType.equals("none")) {
      initNoClientCacheFS();
      startedClientCache = true;
    } else { // ram
      initRAMClientCacheFS();
      startedClientCache = true;
    }
    if (!startedClientCache) initRAMClientCacheFS();

    if (!clientCore.loadedDatabase() && databaseKey != null) {
      lateSetupDatabase(databaseKey);
    }

    nodeConfig.register(
        "useSlashdotCache",
        true,
        sortOrder++,
        true,
        false,
        "Node.useSlashdotCache",
        "Node.useSlashdotCacheLong",
        new BooleanCallback() {

          @Override
          public Boolean get() {
            return useSlashdotCache;
          }

          @Override
          public void set(Boolean val) {
            useSlashdotCache = val;
          }
        });
    useSlashdotCache = nodeConfig.getBoolean("useSlashdotCache");

    nodeConfig.register(
        "writeLocalToDatastore",
        false,
        sortOrder++,
        true,
        false,
        "Node.writeLocalToDatastore",
        "Node.writeLocalToDatastoreLong",
        new BooleanCallback() {

          @Override
          public Boolean get() {
            return writeLocalToDatastore;
          }

          @Override
          public void set(Boolean val) {
            writeLocalToDatastore = val;
          }
        });

    writeLocalToDatastore = nodeConfig.getBoolean("writeLocalToDatastore");

    // This is dangerous on opennet, but was enabled by default before if both security levels
    // were LOW. Upgrade to safe value; this setting only makes sense on small darknets.
    if (opennetEnabled) {
      writeLocalToDatastore = false;
    }

    nodeConfig.register(
        "slashdotCacheLifetime",
        MINUTES.toMillis(30),
        sortOrder++,
        true,
        false,
        "Node.slashdotCacheLifetime",
        "Node.slashdotCacheLifetimeLong",
        new LongCallback() {

          @Override
          public Long get() {
            return chkSlashdotcacheStore.getLifetime();
          }

          @Override
          public void set(Long val) throws InvalidConfigValueException {
            if (val < 0) throw new InvalidConfigValueException("Must be positive!");
            chkSlashdotcacheStore.setLifetime(val);
            pubKeySlashdotcacheStore.setLifetime(val);
            sskSlashdotcacheStore.setLifetime(val);
          }
        },
        false);

    long slashdotCacheLifetime = nodeConfig.getLong("slashdotCacheLifetime");

    nodeConfig.register(
        "slashdotCacheSize",
        DEFAULT_SLASHDOT_CACHE_SIZE,
        sortOrder++,
        false,
        true,
        "Node.slashdotCacheSize",
        "Node.slashdotCacheSizeLong",
        new LongCallback() {

          @Override
          public Long get() {
            return maxSlashdotCacheSize;
          }

          @Override
          public void set(Long storeSize) throws InvalidConfigValueException {
            if (storeSize < MIN_SLASHDOT_CACHE_SIZE)
              throw new InvalidConfigValueException(l10n("invalidStoreSize"));
            int newMaxStoreKeys = (int) Math.min(storeSize / SIZE_PER_KEY, Integer.MAX_VALUE);
            if (newMaxStoreKeys == maxSlashdotCacheKeys) return;
            // Update each datastore
            synchronized (Node.this) {
              maxSlashdotCacheSize = storeSize;
              maxSlashdotCacheKeys = newMaxStoreKeys;
            }
            try {
              chkSlashdotcache.setMaxKeys(maxSlashdotCacheKeys, storeForceBigShrinks);
              pubKeySlashdotcache.setMaxKeys(maxSlashdotCacheKeys, storeForceBigShrinks);
              sskSlashdotcache.setMaxKeys(maxSlashdotCacheKeys, storeForceBigShrinks);
            } catch (IOException e) {
              LOG.error("Caught exception resizing the slashdotcache", e);
            }
          }
        },
        true);

    maxSlashdotCacheSize = nodeConfig.getLong("slashdotCacheSize");

    if (maxSlashdotCacheSize < MIN_SLASHDOT_CACHE_SIZE) {
      throw new NodeInitException(
          NodeInitException.EXIT_INVALID_STORE_SIZE, "Slashdot cache size too small");
    }

    maxSlashdotCacheKeys = (int) Math.min(maxSlashdotCacheSize / SIZE_PER_KEY, Integer.MAX_VALUE);

    chkSlashdotcache = new CHKStore();
    chkSlashdotcacheStore =
        new SlashdotStore<>(
            chkSlashdotcache,
            maxSlashdotCacheKeys,
            slashdotCacheLifetime,
            PURGE_INTERVAL,
            ticker,
            this.clientCore.getTempBucketFactory());
    pubKeySlashdotcache = new PubkeyStore();
    pubKeySlashdotcacheStore =
        new SlashdotStore<>(
            pubKeySlashdotcache,
            maxSlashdotCacheKeys,
            slashdotCacheLifetime,
            PURGE_INTERVAL,
            ticker,
            this.clientCore.getTempBucketFactory());
    getPubKey.setLocalSlashdotcache(pubKeySlashdotcache);
    sskSlashdotcache = new SSKStore(getPubKey);
    sskSlashdotcacheStore =
        new SlashdotStore<>(
            sskSlashdotcache,
            maxSlashdotCacheKeys,
            slashdotCacheLifetime,
            PURGE_INTERVAL,
            ticker,
            this.clientCore.getTempBucketFactory());

    // MAXIMUM seclevel = no slashdot cache.

    securityLevels.addNetworkThreatLevelListener(
        (oldLevel, newLevel) -> {
          if (newLevel == NETWORK_THREAT_LEVEL.MAXIMUM) {
            useSlashdotCache = false;
          } else if (oldLevel == NETWORK_THREAT_LEVEL.MAXIMUM) {
            useSlashdotCache = true;
          }
        });

    nodeConfig.register(
        "skipWrapperWarning",
        false,
        sortOrder++,
        true,
        false,
        "Node.skipWrapperWarning",
        "Node.skipWrapperWarningLong",
        new BooleanCallback() {

          @Override
          public void set(Boolean value) {
            skipWrapperWarning = value;
          }

          @Override
          public Boolean get() {
            return skipWrapperWarning;
          }
        });

    skipWrapperWarning = nodeConfig.getBoolean("skipWrapperWarning");

    nodeConfig.register(
        "maxPacketSize",
        1280,
        sortOrder++,
        true,
        true,
        "Node.maxPacketSize",
        "Node.maxPacketSizeLong",
        new IntCallback() {

          @Override
          public Integer get() {
            synchronized (Node.this) {
              return maxPacketSize;
            }
          }

          @Override
          public void set(Integer val) throws InvalidConfigValueException {
            synchronized (Node.this) {
              if (val == maxPacketSize) return;
              if (val < UdpSocketHandler.MIN_MTU)
                throw new InvalidConfigValueException("Must be over 576");
              if (val > 1492)
                throw new InvalidConfigValueException(
                    "Larger than ethernet frame size unlikely to work!");
              maxPacketSize = val;
            }
            updateMTU();
          }
        },
        true);

    maxPacketSize = nodeConfig.getInt("maxPacketSize");

    nodeConfig.register(
        "enableRoutedPing",
        false,
        sortOrder++,
        true,
        false,
        "Node.enableRoutedPing",
        "Node.enableRoutedPingLong",
        new BooleanCallback() {

          @Override
          public Boolean get() {
            synchronized (Node.this) {
              return enableRoutedPing;
            }
          }

          @Override
          public void set(Boolean val) {
            synchronized (Node.this) {
              enableRoutedPing = val;
            }
          }
        });
    enableRoutedPing = nodeConfig.getBoolean("enableRoutedPing");

    nodeConfig.register(
        "enableNodeDiagnostics",
        false,
        sortOrder++,
        true,
        false,
        "Node.enableDiagnostics",
        "Node.enableDiagnosticsLong",
        new BooleanCallback() {
          @Override
          public Boolean get() {
            synchronized (Node.this) {
              return enableNodeDiagnostics;
            }
          }

          @Override
          public void set(Boolean val) {
            synchronized (Node.this) {
              enableNodeDiagnostics = val;
              nodeDiagnostics.stop();

              if (enableNodeDiagnostics) {
                nodeDiagnostics.start();
              }
            }
          }
        });
    enableNodeDiagnostics = nodeConfig.getBoolean("enableNodeDiagnostics");

    nodeConfig.register(
        "datastoreTooSmallDismissed",
        -1,
        sortOrder++,
        true,
        false,
        "Node.datastoreTooSmallDismissed",
        "Node.datastoreTooSmallDismissedLong",
        new IntCallback() {

          @Override
          public Integer get() {
            return datastoreTooSmallDismissed;
          }

          @Override
          public void set(Integer val) {
            datastoreTooSmallDismissed = val;
          }
        });
    datastoreTooSmallDismissed = nodeConfig.getInt("datastoreTooSmallDismissed");

    updateMTU();

    // peers-offers/*.fref files
    peersOffersFrefFilesConfiguration(nodeConfig, sortOrder);
    if (!peersOffersDismissed && checkPeersOffersFrefFiles())
      PeersOffersUserAlert.createAlert(this);

    /* Take care that no configuration options are registered after this point; they will not persist
     * between restarts.
     */
    nodeConfig.finishedInitialization();
    if (shouldWriteConfig) config.store();
    writeNodeFile();

    // Initialize the plugin manager
    LOG.info("Initializing Plugin Manager");
    pluginManager = PluginManager.create(this, lastVersion);

    shutdownHook.addEarlyJob(
        new NativeThread("Shutdown plugins", NativeThread.PriorityLevel.HIGH_PRIORITY.value, true) {
          @Override
          public void realRun() {
            pluginManager.stop(SECONDS.toMillis(30)); // Consider making it configurable.
          }
        });

    // Note:
    // Short timeouts and JVM timeouts with nothing more said than the above have been seen...
    // I don't know why... need a stack dump...
    // For now just give it an extra 2 minutes. If it doesn't start in that time,
    // it's likely (on reports so far) that a restart will fix it.
    // And we have to get a build out because ALL plugins are now failing to load,
    // including the absolutely essential (for most nodes) JSTUN and UPnP.
    WrapperManager.signalStarting((int) MINUTES.toMillis(2));

    FetchContext ctx = clientCore.makeClient((short) 0, true, false).getFetchContext();

    ctx.setAllowSplitfiles(false);
    ctx.setDontEnterImplicitArchives(true);
    ctx.setMaxArchiveRestarts(0);
    ctx.setMaxMetadataSize(256);
    ctx.setMaxNonSplitfileRetries(10);
    ctx.setMaxOutputLength(4096);
    ctx.setMaxRecursionLevel(2);
    ctx.setMaxTempLength(4096);

    this.arkFetcherContext = ctx;

    // Keep track of the fileNumber so we can potentially delete the extra peer data file
    // later, the file is authoritative
    // Shouldn't happen
    NodeToNodeMessageListener fproxyN2NMListener =
        (data, fromDarknet, src, type) -> {
          if (!fromDarknet) {
            LOG.error("Got N2NTM from non-darknet node ?!?!?!: from {}", src);
            return;
          }
          DarknetPeerNode darkSource = (DarknetPeerNode) src;
          LOG.info("Received N2NTM from '{}'", darkSource.getPeer());
          SimpleFieldSet fs;
          try {
            fs = new SimpleFieldSet(new String(data, StandardCharsets.UTF_8), false, true, false);
          } catch (IOException e) {
            LOG.error("IOException while parsing node to node message data", e);
            return;
          }
          fs.putOverwrite(N2N_TYPE_KEY, Integer.toString(type));
          fs.putOverwrite("receivedTime", Long.toString(System.currentTimeMillis()));
          fs.putOverwrite("receivedAs", "nodeToNodeMessage");
          int fileNumber = darkSource.writeNewExtraPeerDataFile(fs, EXTRA_PEER_DATA_TYPE_N2NTM);
          if (fileNumber == -1) {
            LOG.error(
                "Failed to write N2NTM to extra peer data file for peer {}", darkSource.getPeer());
          }
          // Keep track of the fileNumber so we can potentially delete the extra peer data file
          // later, the file is authoritative
          try {
            handleNodeToNodeTextMessageSimpleFieldSet(fs, darkSource, fileNumber);
          } catch (FSParseException e) {
            // Shouldn't happen
            throw new IllegalStateException(e);
          }
        };
    registerNodeToNodeMessageListener(N2N_MESSAGE_TYPE_FPROXY, fproxyN2NMListener);
    NodeToNodeMessageListener diffNoderefListener =
        (data, fromDarknet, src, type) -> {
          LOG.info(
              "Received differential node reference node to node message from {}", src.getPeer());
          SimpleFieldSet fs;
          try {
            fs = new SimpleFieldSet(new String(data, StandardCharsets.UTF_8), false, true, false);
          } catch (IOException e) {
            LOG.error("IOException while parsing node to node message data", e);
            return;
          }
          if (fs.get(N2N_TYPE_KEY) != null) {
            fs.removeValue(N2N_TYPE_KEY);
          }
          try {
            src.processDiffNoderef(fs);
          } catch (FSParseException e) {
            LOG.error("FSParseException while parsing node to node message data", e);
          }
        };
    registerNodeToNodeMessageListener(Node.N2N_MESSAGE_TYPE_DIFFNODEREF, diffNoderefListener);

    // Note: this is a hack
    // toadlet server should start after all initialized
    // see NodeClientCore line 437
    if (toadlets.isEnabled()) {
      toadlets.finishStart();
      toadlets.createFproxy();
      toadlets.removeStartupToadlet();
    }

    LOG.info("Node constructor completed");

    new BandwidthManager(this).start();

    nodeDiagnostics = new DefaultNodeDiagnostics(this.nodeStats, this.ticker);
  }

  private static long getDefaultCacheSize() {
    long defaultCacheSize;
    long memoryLimit = NodeStarter.getMemoryLimitBytes();
    // This is tricky because systems with low memory probably also have slow disks, but using
    // up too much memory can be catastrophic...
    // Heuristic; subject to tuning.
    if (memoryLimit == Long.MAX_VALUE || memoryLimit < 0) defaultCacheSize = 1024L * 1024;
    else if (memoryLimit <= 128 * 1024 * 1024)
      defaultCacheSize = 0; // Turn off completely for very small memory.
    else {
      // 9 stores, total should be 5% of memory, up to maximum of 1MB per store at 308MB+
      defaultCacheSize = Math.min(1024L * 1024, (memoryLimit - 128L * 1024 * 1024) / (20 * 9));
    }
    return defaultCacheSize;
  }

  private void peersOffersFrefFilesConfiguration(SubConfig nodeConfig, int configOptionSortOrder) {
    final Node node = this;
    nodeConfig.register(
        "peersOffersDismissed",
        false,
        configOptionSortOrder,
        true,
        true,
        "Node.peersOffersDismissed",
        "Node.peersOffersDismissedLong",
        new BooleanCallback() {

          @Override
          public Boolean get() {
            return peersOffersDismissed;
          }

          @Override
          public void set(Boolean val) {
            boolean dismissed = Boolean.TRUE.equals(val);
            if (dismissed) {
              for (UserAlert alert : clientCore.getAlerts().getAlerts())
                if (alert instanceof PeersOffersUserAlert) clientCore.getAlerts().unregister(alert);
            } else PeersOffersUserAlert.createAlert(node);
            peersOffersDismissed = dismissed;
          }
        });
    peersOffersDismissed = nodeConfig.getBoolean("peersOffersDismissed");
  }

  private boolean checkPeersOffersFrefFiles() {
    File[] files = runDir.file("peers-offers").listFiles();
    if (files != null) {
      for (File file : files) {
        if (file.isFile()) {
          String filename = file.getName();
          if (filename.endsWith(".fref")) return true;
        }
      }
    }
    return false;
  }

  /** Delete files from old BDB-index datastore. */
  private void deleteOldBDBIndexStoreFiles() {
    File dbDir = storeDir.file("database-" + getDarknetPortNumber());
    FileUtil.removeAll(dbDir);
    File dir = storeDir.dir();
    File[] list = dir.listFiles();
    if (list == null) return;
    for (File f : list) {
      String name = f.getName();
      if (f.isFile()
          && name.toLowerCase()
              .matches("((chk)|(ssk)|(pubkey))-\\d*\\.((store)|(cache))(\\.((keys)|(lru)))?")) {
        LOG.info("Deleting old datastore file \"{}\"", f);
        try {
          FileUtil.secureDelete(f);
        } catch (IOException e) {
          LOG.warn("Failed to delete old datastore file \"{}\"", f, e);
        }
      }
    }
  }

  /**
   * Sets up a program directory from configuration.
   *
   * <p>Registers a path option in the provided {@link SubConfig}, applies defaults when the option
   * is missing, and attempts to move/create the directory on disk. The option is persisted (forced
   * write) so installers and first‑run wizards can pin locations reliably. Failures to create or
   * move the directory surface as {@link NodeInitException} with a user‑oriented message.
   *
   * @param installConfig configuration section to register and read the directory option from.
   * @param cfgKey option key under which the directory path is stored.
   * @param defaultValue default path used when the option is unset; may be absolute or relative.
   * @param shortdesc i18n key for a short description shown to users.
   * @param longdesc i18n key for a longer description shown to users.
   * @param moveErrMsg message used when emitting errors during directory creation/move; may be
   *     {@code null}.
   * @return a {@link ProgramDirectory} bound to the resolved path and callbacks.
   * @throws NodeInitException if the directory cannot be created or set up.
   */
  public ProgramDirectory setupProgramDir(
      SubConfig installConfig,
      String cfgKey,
      String defaultValue,
      String shortdesc,
      String longdesc,
      String moveErrMsg)
      throws NodeInitException {
    ProgramDirectory dir = new ProgramDirectory(moveErrMsg);
    int sortOrder = ProgramDirectory.nextOrder();
    // forceWrite=true because currently it can't be changed on the fly, also for packages
    installConfig.register(
        cfgKey, defaultValue, sortOrder, true, true, shortdesc, longdesc, dir.getStringCallback());
    String dirName = installConfig.getString(cfgKey);
    try {
      dir.move(dirName);
    } catch (IOException _) {
      throw new NodeInitException(
          NodeInitException.EXIT_BAD_DIR, "could not set up directory: " + longdesc);
    }
    return dir;
  }

  protected ProgramDirectory setupProgramDir(
      SubConfig installConfig,
      String cfgKey,
      String defaultValue,
      String shortdesc,
      String longdesc)
      throws NodeInitException {
    return setupProgramDir(installConfig, cfgKey, defaultValue, shortdesc, longdesc, null);
  }

  public void lateSetupDatabase(DatabaseKey databaseKey) {
    if (clientCore.loadedDatabase()) return;
    LOG.info("Starting late database initialisation");

    if (!clientCore.lateInitDatabase(databaseKey)) failLateInitDatabase();
  }

  private void failLateInitDatabase() {
    LOG.error("Failed late initialisation of database, closing...");
  }

  public void killMasterKeysFile() throws IOException {
    MasterKeys.killMasterKeys(masterKeysFile);
  }

  private void setClientCacheAwaitingPassword() {
    createPasswordUserAlert();
    synchronized (this) {
      clientCacheAwaitingPassword = true;
    }
  }

  /** Called when the client layer needs the decryption password. */
  void setDatabaseAwaitingPassword() {
    synchronized (this) {
      databaseAwaitingPassword = true;
    }
  }

  private final UserAlert masterPasswordUserAlert =
      new UserAlert() {

        final long creationTime = System.currentTimeMillis();

        @Override
        public String anchor() {
          return "password";
        }

        @Override
        public String dismissButtonText() {
          return null;
        }

        @Override
        public long getUpdatedTime() {
          return creationTime;
        }

        @Override
        public FCPMessage getFCPMessage() {
          return new FeedMessage(
              getTitle(), getShortText(), getText(), getPriorityClass(), getUpdatedTime());
        }

        @Override
        public HTMLNode getHTMLText() {
          HTMLNode content = new HTMLNode("div");
          SecurityLevelsToadlet.generatePasswordFormPage(
              false,
              clientCore.getEndpoints().getToadletContainer(),
              content,
              false,
              false,
              false,
              null,
              null);
          return content;
        }

        @Override
        public short getPriorityClass() {
          return UserAlert.ERROR;
        }

        @Override
        public String getShortText() {
          return NodeL10n.getBase().getString(SECURITYLEVELS_ENTER_PASSWORD_KEY);
        }

        @Override
        public String getText() {
          return NodeL10n.getBase().getString(SECURITYLEVELS_ENTER_PASSWORD_KEY);
        }

        @Override
        public String getTitle() {
          return NodeL10n.getBase().getString(SECURITYLEVELS_ENTER_PASSWORD_KEY);
        }

        @Override
        public boolean isEventNotification() {
          return false;
        }

        @Override
        public boolean isValid() {
          synchronized (Node.this) {
            return clientCacheAwaitingPassword || databaseAwaitingPassword;
          }
        }

        @Override
        public void isValid(boolean validity) {
          // Ignore
        }

        @Override
        public void onDismiss() {
          // Ignore
        }

        @Override
        public boolean shouldUnregisterOnDismiss() {
          return false;
        }

        @Override
        public boolean userCanDismiss() {
          return false;
        }
      };

  private void createPasswordUserAlert() {
    this.clientCore.getAlerts().register(masterPasswordUserAlert);
  }

  private void initRAMClientCacheFS() {
    chkClientcache = new CHKStore();
    new RAMFreenetStore<>(chkClientcache, (int) Math.min(Integer.MAX_VALUE, maxClientCacheKeys))
        .close();
    pubKeyClientcache = new PubkeyStore();
    new RAMFreenetStore<>(pubKeyClientcache, (int) Math.min(Integer.MAX_VALUE, maxClientCacheKeys))
        .close();
    sskClientcache = new SSKStore(getPubKey);
    new RAMFreenetStore<>(sskClientcache, (int) Math.min(Integer.MAX_VALUE, maxClientCacheKeys))
        .close();
  }

  private void initNoClientCacheFS() {
    chkClientcache = new CHKStore();
    new NullFreenetStore<>(chkClientcache).close();
    pubKeyClientcache = new PubkeyStore();
    new NullFreenetStore<>(pubKeyClientcache).close();
    sskClientcache = new SSKStore(getPubKey);
    new NullFreenetStore<>(sskClientcache).close();
  }

  private void finishInitSaltHashFS(NodeClientCore clientCore) {
    if (clientCore.getAlerts() == null) throw new NullPointerException();
    chkDatastore.getStore().setUserAlertManager(clientCore.getAlerts());
    chkDatacache.getStore().setUserAlertManager(clientCore.getAlerts());
    pubKeyDatastore.getStore().setUserAlertManager(clientCore.getAlerts());
    pubKeyDatacache.getStore().setUserAlertManager(clientCore.getAlerts());
    sskDatastore.getStore().setUserAlertManager(clientCore.getAlerts());
    sskDatacache.getStore().setUserAlertManager(clientCore.getAlerts());
  }

  private void initRAMFS() {
    chkDatastore = new CHKStore();
    new RAMFreenetStore<>(chkDatastore, (int) Math.min(Integer.MAX_VALUE, maxStoreKeys)).close();
    chkDatacache = new CHKStore();
    new RAMFreenetStore<>(chkDatacache, (int) Math.min(Integer.MAX_VALUE, maxCacheKeys)).close();
    pubKeyDatastore = new PubkeyStore();
    new RAMFreenetStore<>(pubKeyDatastore, (int) Math.min(Integer.MAX_VALUE, maxStoreKeys)).close();
    pubKeyDatacache = new PubkeyStore();
    getPubKey.setDataStore(pubKeyDatastore, pubKeyDatacache);
    new RAMFreenetStore<>(pubKeyDatacache, (int) Math.min(Integer.MAX_VALUE, maxCacheKeys)).close();
    sskDatastore = new SSKStore(getPubKey);
    new RAMFreenetStore<>(sskDatastore, (int) Math.min(Integer.MAX_VALUE, maxStoreKeys)).close();
    sskDatacache = new SSKStore(getPubKey);
    new RAMFreenetStore<>(sskDatacache, (int) Math.min(Integer.MAX_VALUE, maxCacheKeys)).close();
  }

  private long cachingFreenetStoreMaxSize;
  private long cachingFreenetStorePeriod;
  private CachingFreenetStoreTracker cachingFreenetStoreTracker;

  @SuppressWarnings("SameParameterValue")
  private void initSaltHashFS(boolean dontResizeOnStart, byte[] masterKey)
      throws NodeInitException {
    try {
      final CHKStore chkDatastoreLocal = new CHKStore();
      makeStore("CHK", true, chkDatastoreLocal, dontResizeOnStart, masterKey);
      final CHKStore chkDatacacheLocal = new CHKStore();
      makeStore("CHK", false, chkDatacacheLocal, dontResizeOnStart, masterKey);
      ((SaltedHashFreenetStore<CHKBlock>) chkDatacacheLocal.getStore().getUnderlyingStore())
          .setAltStore(
              (SaltedHashFreenetStore<CHKBlock>) chkDatastoreLocal.getStore().getUnderlyingStore());
      final PubkeyStore pubKeyDatastoreLocal = new PubkeyStore();
      makeStore(STORE_KIND_PUBKEY, true, pubKeyDatastoreLocal, dontResizeOnStart, masterKey);
      final PubkeyStore pubKeyDatacacheLocal = new PubkeyStore();
      makeStore(STORE_KIND_PUBKEY, false, pubKeyDatacacheLocal, dontResizeOnStart, masterKey);
      ((SaltedHashFreenetStore<DSAPublicKey>) pubKeyDatacacheLocal.getStore().getUnderlyingStore())
          .setAltStore(
              (SaltedHashFreenetStore<DSAPublicKey>)
                  pubKeyDatastoreLocal.getStore().getUnderlyingStore());
      final SSKStore sskDatastoreLocal = new SSKStore(getPubKey);
      makeStore("SSK", true, sskDatastoreLocal, dontResizeOnStart, masterKey);
      final SSKStore sskDatacacheLocal = new SSKStore(getPubKey);
      makeStore("SSK", false, sskDatacacheLocal, dontResizeOnStart, masterKey);
      ((SaltedHashFreenetStore<SSKBlock>) sskDatacacheLocal.getStore().getUnderlyingStore())
          .setAltStore(
              (SaltedHashFreenetStore<SSKBlock>) sskDatastoreLocal.getStore().getUnderlyingStore());

      boolean dChkData = chkDatastoreLocal.getStore().start(ticker, false);
      boolean dChkCache = chkDatacacheLocal.getStore().start(ticker, false);
      boolean dPubkeyData = pubKeyDatastoreLocal.getStore().start(ticker, false);
      boolean dPubkeyCache = pubKeyDatacacheLocal.getStore().start(ticker, false);
      boolean dSskData = sskDatastoreLocal.getStore().start(ticker, false);
      boolean dSskCache = sskDatacacheLocal.getStore().start(ticker, false);

      boolean delay = dChkData || dChkCache || dPubkeyData || dPubkeyCache || dSskData || dSskCache;

      if (delay) {

        LOG.info("Delayed init of datastore");

        initRAMFS();

        final Runnable migrate = new MigrateOldStoreData(false);

        this.getTicker()
            .queueTimedJob(
                () -> {
                  LOG.info("Starting delayed init of datastore");
                  try {
                    chkDatastoreLocal.getStore().start(ticker, true);
                    chkDatacacheLocal.getStore().start(ticker, true);
                    pubKeyDatastoreLocal.getStore().start(ticker, true);
                    pubKeyDatacacheLocal.getStore().start(ticker, true);
                    sskDatastoreLocal.getStore().start(ticker, true);
                    sskDatacacheLocal.getStore().start(ticker, true);
                  } catch (IOException e) {
                    LOG.error("Failed to start datastore", e);
                    return;
                  }

                  Node.this.chkDatastore = chkDatastoreLocal;
                  Node.this.chkDatacache = chkDatacacheLocal;
                  Node.this.pubKeyDatastore = pubKeyDatastoreLocal;
                  Node.this.pubKeyDatacache = pubKeyDatacacheLocal;
                  getPubKey.setDataStore(pubKeyDatastoreLocal, pubKeyDatacacheLocal);
                  Node.this.sskDatastore = sskDatastoreLocal;
                  Node.this.sskDatacache = sskDatacacheLocal;

                  finishInitSaltHashFS(clientCore);

                  LOG.info("Finishing delayed init of datastore");
                  migrate.run();
                },
                "Start store",
                0,
                true,
                false); // Use Ticker to guarantee that this runs *after* constructors have
        // completed.

      } else {

        Node.this.chkDatastore = chkDatastoreLocal;
        Node.this.chkDatacache = chkDatacacheLocal;
        Node.this.pubKeyDatastore = pubKeyDatastoreLocal;
        Node.this.pubKeyDatacache = pubKeyDatacacheLocal;
        getPubKey.setDataStore(pubKeyDatastoreLocal, pubKeyDatacacheLocal);
        Node.this.sskDatastore = sskDatastoreLocal;
        Node.this.sskDatacache = sskDatacacheLocal;

        this.getTicker()
            .queueTimedJob(
                () -> {
                  Node.this.chkDatastore = chkDatastoreLocal;
                  Node.this.chkDatacache = chkDatacacheLocal;
                  Node.this.pubKeyDatastore = pubKeyDatastoreLocal;
                  Node.this.pubKeyDatacache = pubKeyDatacacheLocal;
                  getPubKey.setDataStore(pubKeyDatastoreLocal, pubKeyDatacacheLocal);
                  Node.this.sskDatastore = sskDatastoreLocal;
                  Node.this.sskDatacache = sskDatacacheLocal;

                  finishInitSaltHashFS(clientCore);
                },
                "Start store",
                0,
                true,
                false);
      }

    } catch (IOException e) {
      throw new NodeInitException(NodeInitException.EXIT_STORE_OTHER, e.getMessage());
    }
  }

  private void initSaltHashClientCacheFS(boolean dontResizeOnStart, byte[] clientCacheMasterKey)
      throws NodeInitException {

    try {
      final CHKStore chkClientcacheLocal = new CHKStore();
      makeClientcache("CHK", chkClientcacheLocal, dontResizeOnStart, clientCacheMasterKey);
      final PubkeyStore pubKeyClientcacheLocal = new PubkeyStore();
      makeClientcache(
          STORE_KIND_PUBKEY, pubKeyClientcacheLocal, dontResizeOnStart, clientCacheMasterKey);
      final SSKStore sskClientcacheLocal = new SSKStore(getPubKey);
      makeClientcache("SSK", sskClientcacheLocal, dontResizeOnStart, clientCacheMasterKey);

      boolean dChk = chkClientcacheLocal.getStore().start(ticker, false);
      boolean dPub = pubKeyClientcacheLocal.getStore().start(ticker, false);
      boolean dSsk = sskClientcacheLocal.getStore().start(ticker, false);
      boolean delay = dChk || dPub || dSsk;

      if (delay) {

        LOG.info("Delayed init of client-cache");

        initRAMClientCacheFS();

        final Runnable migrate = new MigrateOldStoreData(true);

        getTicker()
            .queueTimedJob(
                () -> {
                  LOG.info("Starting delayed init of client-cache");
                  try {
                    chkClientcacheLocal.getStore().start(ticker, true);
                    pubKeyClientcacheLocal.getStore().start(ticker, true);
                    sskClientcacheLocal.getStore().start(ticker, true);
                  } catch (IOException e) {
                    LOG.error("Failed to start client-cache", e);
                    return;
                  }
                  Node.this.chkClientcache = chkClientcacheLocal;
                  Node.this.pubKeyClientcache = pubKeyClientcacheLocal;
                  getPubKey.setLocalDataStore(pubKeyClientcacheLocal);
                  Node.this.sskClientcache = sskClientcacheLocal;

                  LOG.info("Finishing delayed init of client-cache");
                  migrate.run();
                },
                "Migrate store",
                0,
                true,
                false);
      } else {
        Node.this.chkClientcache = chkClientcacheLocal;
        Node.this.pubKeyClientcache = pubKeyClientcacheLocal;
        getPubKey.setLocalDataStore(pubKeyClientcacheLocal);
        Node.this.sskClientcache = sskClientcacheLocal;
      }

    } catch (IOException e) {
      throw new NodeInitException(NodeInitException.EXIT_STORE_OTHER, e.getMessage());
    }
  }

  private <T extends StorableBlock> void makeClientcache(
      String type, StoreCallback<T> cb, boolean dontResizeOnStart, byte[] clientCacheMasterKey)
      throws IOException {
    makeStore(type, "clientcache", maxClientCacheKeys, cb, dontResizeOnStart, clientCacheMasterKey);
  }

  private <T extends StorableBlock> void makeStore(
      String type,
      boolean isStore,
      StoreCallback<T> cb,
      boolean dontResizeOnStart,
      byte[] clientCacheMasterKey)
      throws IOException {
    String store = isStore ? "store" : "cache";
    long maxKeys = isStore ? maxStoreKeys : maxCacheKeys;
    makeStore(type, store, maxKeys, cb, dontResizeOnStart, clientCacheMasterKey);
  }

  private <T extends StorableBlock> void makeStore(
      String type,
      String store,
      long maxKeys,
      StoreCallback<T> cb,
      boolean lateStart,
      byte[] clientCacheMasterKey)
      throws IOException {
    LOG.info("Initializing {} Data{} ({} keys)", type, store, maxStoreKeys);

    SaltedHashFreenetStore<T> fs =
        SaltedHashFreenetStore.construct(
            getStoreDir(),
            type + "-" + store,
            cb,
            random,
            maxKeys,
            storeUseSlotFilters,
            shutdownHook,
            storePreallocate,
            storeSaltHashResizeOnStart && !lateStart,
            clientCacheMasterKey);
    if (cachingFreenetStoreMaxSize > 0) {
      new CachingFreenetStore<>(cb, fs, cachingFreenetStoreTracker);
      // CachingFreenetStore constructor calls cb.setStore(this)
    } else {
      cb.setStore(fs);
    }
  }

  public void start(boolean noSwaps) throws NodeInitException {
    if (LOG.isTraceEnabled()) {
      LOG.trace("start(noSwaps={})", noSwaps);
    }

    // IMPORTANT: Read the peers only after we have finished initializing Node.
    // Peer constructors are complex and can call methods on Node.
    peers
        .persistence()
        .tryReadPeers(
            nodeDir.file("peers-" + getDarknetPortNumber()).getPath(),
            darknetCrypto,
            null,
            false,
            false);
    peers.updatePMUserAlert();

    dispatcher.start(nodeStats); // must be before usm
    dnsr.start();
    peers.start(); // must be before usm
    nodeStats.start();
    uptime.start();
    failureTable.start();

    darknetCrypto.start();
    if (opennet != null) opennet.start();
    ps.start(nodeStats);
    ticker.start();
    usm.start(ticker);

    if (isUsingWrapper()) {
      LOG.info("Using wrapper correctly: {}", nodeStarter);
    } else {
      LOG.error(
          "NOT using wrapper (at least not correctly). Please ensure wrapper.jar and wrapper.conf"
              + " are current.");
    }
    if (LOG.isInfoEnabled()) {
      LOG.info("Crypta v{}+{}", Version.currentBuildNumber(), Version.gitRevision());
      LOG.info("FNP port is on {}:{}", darknetCrypto.getBindTo(), getDarknetPortNumber());
    }
    // Start services

    ipDetector.start();

    // Start sending swaps
    lm.start();

    // Node Updater
    try {
      LOG.info("Starting the node updater");
      nodeUpdater.start();
    } catch (Exception e) {
      throw new NodeInitException(
          NodeInitException.EXIT_COULD_NOT_START_UPDATER, "Could not start Updater: " + e);
    }

    warnIfNotUsingWrapper();

    if (!NativeThread.HAS_ENOUGH_NICE_LEVELS)
      clientCore.getAlerts().register(new NotEnoughNiceLevelsUserAlert());

    this.clientCore.start();

    tracker.startDeadUIDChecker();

    // After everything has been created, write the config file back to disk.
    if (config instanceof FreenetFilePersistentConfig cfg) {
      cfg.finishedInit(this.ticker);
      cfg.setHasNodeStarted();
    }
    config.store();

    // Process any data in the extra peer data directory
    peers.readExtraPeerData();

    if (enableNodeDiagnostics) {
      nodeDiagnostics.start();
    }

    LOG.info("Started node");

    hasStarted = true;
  }

  private void warnIfNotUsingWrapper() {
    if (!isUsingWrapper() && !skipWrapperWarning) {
      clientCore
          .getAlerts()
          .register(
              new SimpleUserAlert(
                  true,
                  l10n("notUsingWrapperTitle"),
                  l10n("notUsingWrapper"),
                  l10n("notUsingWrapperShort"),
                  UserAlert.WARNING));
    }
  }

  private String l10n(String key) {
    return NodeL10n.getBase().getString(L10N_PREFIX_NODE + key);
  }

  @SuppressWarnings("SameParameterValue")
  private String l10n(String key, String replacementValue) {
    return NodeL10n.getBase().getString(L10N_PREFIX_NODE + key, replacementValue);
  }

  private String l10n(String key, String pattern, String value) {
    return NodeL10n.getBase().getString(L10N_PREFIX_NODE + key, pattern, value);
  }

  /**
   * Exports volatile runtime metrics and state as a {@link SimpleFieldSet}.
   *
   * @return a snapshot of node statistics suitable for lightweight diagnostics and UI display.
   */
  public SimpleFieldSet exportVolatileFieldSet() {
    return nodeStats.exportVolatileFieldSet();
  }

  /**
   * Do a routed ping of another node on the network by its location.
   *
   * @param loc2 The location of the other node to ping. It must match exactly.
   * @param pubKeyHash The hash of the pubkey of the target node. We match by location; this is just
   *     a shortcut if we get close.
   * @return The number of hops it took to find the node, if it was found. Otherwise -1.
   */
  public int routedPing(double loc2, byte[] pubKeyHash) {
    long uid = random.nextLong();
    int initialX = random.nextInt();
    Message m = DMT.createFNPRoutedPing(uid, loc2, maxHTL, initialX, pubKeyHash);
    LOG.info("Message: {}", m);

    dispatcher.handleRouted(m, null);
    // Might be rejected
    MessageFilter mf1 =
        MessageFilter.create().setField(DMT.UID, uid).setType(DMT.FNPRoutedPong).setTimeout(5000);
    try {
      // Ignore Rejected - let it be retried on other peers
      m = usm.waitFor(mf1, null);
    } catch (DisconnectedException _) {
      LOG.info("Disconnected in waiting for pong");
      return -1;
    }
    if (m == null) return -1;
    if (m.getSpec() == DMT.FNPRoutedRejected) return -1;
    return m.getInt(DMT.COUNTER) - initialX;
  }

  /**
   * Look for a block in the datastore, as part of a request.
   *
   * @param key The key to fetch.
   * @param uid The UID of the request (for logging only).
   * @param canReadClientCache If the request is local, we can read the client cache.
   * @param canWriteClientCache If the request is local, and the client hasn't turned off writing to
   *     the client cache, we can write to the client cache.
   * @param canWriteDatastore If the request HTL is too high, including if it is local, we cannot
   *     write to the datastore.
   * @param offersOnly When true, accept only offered blocks without triggering new retrieval work.
   * @return A KeyBlock for the key requested or null.
   */
  private KeyBlock makeRequestLocal(
      Key key,
      long uid,
      boolean canReadClientCache,
      boolean canWriteClientCache,
      boolean canWriteDatastore,
      boolean offersOnly) {
    KeyBlock kb =
        switch (key) {
          case NodeCHK chk ->
              fetch(chk, false, canReadClientCache, canWriteClientCache, canWriteDatastore, null);
          case NodeSSK ssk ->
              tryFetchLocalForSSK(
                  ssk, uid, canReadClientCache, canWriteClientCache, canWriteDatastore, offersOnly);
          default -> throw new IllegalStateException("Unknown key type: " + key.getClass());
        };

    if (kb == null) return null;
    tripPendingSchedulers(kb);
    failureTable.onFound(kb);
    return kb;
  }

  private KeyBlock tryFetchLocalForSSK(
      NodeSSK sskKey,
      long uid,
      boolean canReadClientCache,
      boolean canWriteClientCache,
      boolean canWriteDatastore,
      boolean offersOnly) {
    DSAPublicKey pubKey = sskKey.getPubKey();
    if (pubKey == null) {
      pubKey = getPubKey.getKey(sskKey.getPubKeyHash(), canReadClientCache, offersOnly, null);
      if (LOG.isDebugEnabled()) LOG.debug("Fetched pubkey: {}", pubKey);
      try {
        sskKey.setPubKey(pubKey);
      } catch (SSKVerifyException e) {
        LOG.error("Error setting pubkey: {}", e, e);
      }
    }
    if (pubKey == null) {
      if (LOG.isDebugEnabled()) LOG.debug("Not found because no pubkey: {}", uid);
      return null;
    }
    if (LOG.isDebugEnabled()) LOG.debug("Got pubkey: {}", pubKey);
    return fetch(sskKey, canReadClientCache, canWriteClientCache, canWriteDatastore, false, null);
  }

  private void tripPendingSchedulers(KeyBlock kb) {
    if (clientCore == null || clientCore.getRequestStarters() == null) return;
    if (kb instanceof CHKBlock) {
      clientCore.getRequestStarters().chkFetchSchedulerBulk.tripPendingKey(kb);
      clientCore.getRequestStarters().chkFetchSchedulerRT.tripPendingKey(kb);
    } else {
      clientCore.getRequestStarters().sskFetchSchedulerBulk.tripPendingKey(kb);
      clientCore.getRequestStarters().sskFetchSchedulerRT.tripPendingKey(kb);
    }
  }

  /**
   * Options controlling how a request attempt is made when fetching a key.
   *
   * <p>The node first attempts a local lookup (client cache, caches, then stores) and only creates
   * a network {@code RequestSender} when allowed by the provided flags. These options are captured
   * as a compact value object to make call‑sites explicit and easy to extend in the future.
   *
   * @param localOnly when {@code true}, restrict resolution to local stores and caches; no routing
   *     occurs.
   * @param ignoreStore when {@code true}, skip checking the persistent store and rely on caches and
   *     routing.
   * @param offersOnly when {@code true}, only accept already offered blocks; do not trigger new
   *     retrievals that would increase load.
   * @param canReadClientCache allow the local client cache to be consulted when present.
   * @param canWriteClientCache allow populating the local client cache on successful resolution.
   * @param realTimeFlag when {@code true}, prefer real‑time queues and low‑latency scheduling.
   */
  public record RequestSenderOptions(
      boolean localOnly,
      boolean ignoreStore,
      boolean offersOnly,
      boolean canReadClientCache,
      boolean canWriteClientCache,
      boolean realTimeFlag) {

    public static RequestSenderOptions of(
        boolean localOnly,
        boolean ignoreStore,
        boolean offersOnly,
        boolean canReadClientCache,
        boolean canWriteClientCache,
        boolean realTimeFlag) {
      return new RequestSenderOptions(
          localOnly,
          ignoreStore,
          offersOnly,
          canReadClientCache,
          canWriteClientCache,
          realTimeFlag);
    }
  }

  /**
   * Creates a sender for a request or returns a locally available result.
   *
   * <p>The method first attempts a local resolution based on {@code opts}. If the key is present in
   * client caches or the main stores (subject to the flags) a {@link KeyBlock} is returned. When no
   * local copy exists and remote routing is permitted, it constructs and starts a {@link
   * RequestSender} to fetch the data asynchronously. If {@code htl} is zero, routing is not
   * possible and {@code null} is returned.
   *
   * @param key the key to resolve; must be a {@link NodeCHK} or {@link NodeSSK} instance.
   * @param htl current hop‑to‑live; values greater than zero enable routing, zero prevents it.
   * @param uid correlation identifier used in logs and for matching responses.
   * @param tag request owner used by schedulers; associates callbacks and cancellation.
   * @param source upstream peer for forwarded requests, or {@code null} for local originators.
   * @param opts options controlling local checks, cache read/write, and scheduling behavior.
   * @return a {@link KeyBlock} when found locally; a started {@link RequestSender} when routing is
   *     initiated; or {@code null} if neither applies (e.g., {@code htl == 0}).
   */
  public Object makeRequestSender(
      Key key, short htl, long uid, RequestTag tag, PeerNode source, RequestSenderOptions opts) {
    boolean canWriteDatastore = canWriteDatastoreRequest(htl);
    if (LOG.isDebugEnabled())
      LOG.debug(
          "makeRequestSender({},{},{},{}) on {}", key, htl, uid, source, getDarknetPortNumber());
    boolean localOnly = opts.localOnly();
    boolean ignoreStore = opts.ignoreStore();
    boolean offersOnly = opts.offersOnly();
    boolean canReadClientCache = opts.canReadClientCache();
    boolean canWriteClientCache = opts.canWriteClientCache();
    boolean realTimeFlag = opts.realTimeFlag();

    if (!ignoreStore) {
      KeyBlock kb =
          makeRequestLocal(
              key, uid, canReadClientCache, canWriteClientCache, canWriteDatastore, offersOnly);
      if (kb != null) return kb;
    }
    if (localOnly) return null;
    if (LOG.isDebugEnabled()) LOG.debug("Not in store locally");

    RequestSender existing = findCoalescedSender(key, realTimeFlag);
    if (existing != null) {
      existing.setTransferCoalesced();
      tag.setSender(existing, true);
      return existing;
    }

    if (htl == 0) {
      if (LOG.isDebugEnabled()) LOG.debug("No HTL");
      return null;
    }

    RequestSender created =
        new RequestSender(
            key,
            null,
            htl,
            uid,
            tag,
            this,
            source,
            offersOnly,
            canWriteClientCache,
            canWriteDatastore,
            realTimeFlag);
    tag.setSender(created, false);
    created.start();
    if (LOG.isDebugEnabled()) LOG.debug("Created new sender: {}", created);
    return created;
  }

  private RequestSender findCoalescedSender(Key key, boolean realTimeFlag) {
    // Transfer coalescing - match key only as HTL irrelevant
    if (key instanceof NodeCHK nchk)
      return tracker.getTransferringRequestSenderByKey(nchk, realTimeFlag);
    return null;
  }

  /**
   * Can we write to the datastore for a given request? We do not write to the datastore until 2
   * hops below maximum. This is an average of 4 hops from the originator. Thus, data returned from
   * local requests is never cached, finally solving The Register's attack, Bloom filter sharing
   * doesn't give away your local requests and inserts, and *anything starting at high HTL* is not
   * cached, including stuff from other nodes which hasn't been decremented far enough yet, so it's
   * not ONLY local requests that don't get cached.
   */
  boolean canWriteDatastoreRequest(short htl) {
    return htl <= (maxHTL - 2);
  }

  /**
   * Can we write to the datastore for a given insert? We do not write to the datastore until 3 hops
   * below maximum. This is an average of 5 hops from the originator. Thus, data sent by local
   * inserts is never cached, finally solving The Register's attack, Bloom filter sharing doesn't
   * give away your local requests and inserts, and *anything starting at high HTL* is not cached,
   * including stuff from other nodes which hasn't been decremented far enough yet, so it's not ONLY
   * local inserts that don't get cached.
   */
  boolean canWriteDatastoreInsert(short htl) {
    return htl <= (maxHTL - 3);
  }

  /**
   * Fetches a block from local stores and caches according to the provided flags.
   *
   * <p>No network routing is performed here. When the block is not present locally callers should
   * use {@link #makeRequestSender(Key, short, long, RequestTag, PeerNode, RequestSenderOptions)} to
   * initiate a routed fetch.
   *
   * @param key key to fetch; supports both {@link NodeCHK} and {@link NodeSSK} keys.
   * @param canReadClientCache whether to consult the client cache that stores results of local
   *     operations.
   * @param canWriteClientCache whether to populate the client cache when a block is found.
   * @param canWriteDatastore whether persistent store writes are allowed as a side effect of the
   *     lookup (promotion); typically governed by HTL.
   * @param forULPR whether the access is part of ULPR processing; enables slashdot caches.
   * @param meta optional metadata sink used by stores to return provenance and flags; may be {@code
   *     null}.
   * @return the {@link KeyBlock} if found; otherwise {@code null}.
   */
  public KeyBlock fetch(
      Key key,
      boolean canReadClientCache,
      boolean canWriteClientCache,
      boolean canWriteDatastore,
      boolean forULPR,
      BlockMetadata meta) {
    return switch (key) {
      case NodeSSK sK ->
          fetch(
              sK, false, canReadClientCache, canWriteClientCache, canWriteDatastore, forULPR, meta);
      case NodeCHK hK ->
          fetch(
              hK, false, canReadClientCache, canWriteClientCache, canWriteDatastore, forULPR, meta);
      default -> throw new IllegalArgumentException();
    };
  }

  /**
   * Fetches an SSK block from local stores and caches according to flags.
   *
   * @param key node SSK key to locate.
   * @param dontPromote when {@code true}, avoid promoting into hotter tiers.
   * @param canReadClientCache whether the client cache may be consulted.
   * @param canWriteClientCache whether the client cache may be updated.
   * @param canWriteDatastore whether the datastore may be updated (subject to policy).
   * @param forULPR whether this access is part of ULPR handling.
   * @param meta optional metadata sink; may be {@code null}.
   * @return the {@link SSKBlock} if found; otherwise {@code null}.
   */
  public SSKBlock fetch(
      NodeSSK key,
      boolean dontPromote,
      boolean canReadClientCache,
      boolean canWriteClientCache,
      boolean canWriteDatastore,
      boolean forULPR,
      BlockMetadata meta) {
    // Parameters grouping for client cache fetch helpers
    double loc = key.toNormalizedDouble();
    double dist = Location.distance(lm.getLocation(), loc);
    SSKBlock fromClient =
        fetchSSKFromClientCaches(
            key,
            new FetchParams(
                dontPromote, canWriteClientCache, canReadClientCache, forULPR, meta, loc, dist));
    if (fromClient != null) return fromClient;
    boolean ignoreOldBlocks = !writeLocalToDatastore && !canReadClientCache;
    if (LOG.isDebugEnabled()) dumpStoreHits();
    try {
      nodeStats.avgRequestLocation.report(loc);
      SSKBlock fromStores =
          fetchSSKFromStores(
              key,
              dontPromote,
              canReadClientCache,
              forULPR,
              ignoreOldBlocks,
              meta,
              canWriteDatastore);
      if (fromStores != null) {
        nodeStats.avgStoreSSKSuccess.report(loc);
        if (dist > nodeStats.furthestStoreSSKSuccess) nodeStats.furthestStoreSSKSuccess = dist;
        if (LOG.isTraceEnabled()) LOG.trace("Found key {} in store", key);
        return fromStores;
      }
      SSKBlock fromCaches =
          fetchSSKFromCaches(
              key,
              dontPromote,
              canReadClientCache,
              forULPR,
              ignoreOldBlocks,
              meta,
              canWriteDatastore);
      if (fromCaches != null) {
        nodeStats.avgCacheSSKSuccess.report(loc);
        if (dist > nodeStats.furthestCacheSSKSuccess) nodeStats.furthestCacheSSKSuccess = dist;
        if (LOG.isTraceEnabled()) LOG.trace("Found key {} in cache", key);
      }
      return fromCaches;
    } catch (IOException e) {
      LOG.error("Cannot fetch data: {}", e, e);
      return null;
    }
  }

  private record FetchParams(
      boolean dontPromote,
      boolean canWriteClientCache,
      boolean canReadClientCache,
      boolean forULPR,
      BlockMetadata meta,
      double loc,
      double dist) {}

  private SSKBlock fetchSSKFromClientCaches(NodeSSK key, FetchParams p) {
    SSKBlock fromClient = tryFetchFromSSKClientCache(key, p);
    if (fromClient != null) return fromClient;
    return tryFetchFromSSKSlashdotCache(
        key, p.dontPromote(), p.canReadClientCache(), p.forULPR(), p.meta(), p.loc(), p.dist());
  }

  private SSKBlock tryFetchFromSSKClientCache(NodeSSK key, FetchParams p) {
    if (!p.canReadClientCache()) return null;
    try {
      SSKBlock block =
          sskClientcache.fetch(
              key, p.dontPromote() || !p.canWriteClientCache(), true, p.forULPR(), false, p.meta());
      if (block != null) {
        nodeStats.avgClientCacheSSKSuccess.report(p.loc());
        if (p.dist() > nodeStats.furthestClientCacheSSKSuccess)
          nodeStats.furthestClientCacheSSKSuccess = p.dist();
        if (LOG.isTraceEnabled()) LOG.trace("Found key {} in client-cache", key);
        return block;
      }
    } catch (IOException e) {
      LOG.error("Could not read from client cache: {}", e, e);
    }
    return null;
  }

  private SSKBlock tryFetchFromSSKSlashdotCache(
      NodeSSK key,
      boolean dontPromote,
      boolean canReadClientCache,
      boolean forULPR,
      BlockMetadata meta,
      double loc,
      double dist) {
    if (!(forULPR || useSlashdotCache || canReadClientCache)) return null;
    try {
      SSKBlock block =
          sskSlashdotcache.fetch(key, dontPromote, canReadClientCache, forULPR, false, meta);
      if (block != null) {
        nodeStats.avgSlashdotCacheSSKSuccess.report(loc);
        if (dist > nodeStats.furthestSlashdotCacheSSKSuccess)
          nodeStats.furthestSlashdotCacheSSKSuccess = dist;
        if (LOG.isTraceEnabled()) LOG.trace("Found key {} in slashdot-cache", key);
        return block;
      }
    } catch (IOException e) {
      LOG.error("Could not read from slashdot/ULPR cache: {}", e, e);
    }
    return null;
  }

  private SSKBlock fetchSSKFromStores(
      NodeSSK key,
      boolean dontPromote,
      boolean canReadClientCache,
      boolean forULPR,
      boolean ignoreOldBlocks,
      BlockMetadata meta,
      boolean canWriteDatastore)
      throws IOException {
    SSKBlock block =
        sskDatastore.fetch(
            key,
            dontPromote || !canWriteDatastore,
            canReadClientCache,
            forULPR,
            ignoreOldBlocks,
            meta);
    if (block != null) return block;
    SSKStore store = oldSSK.get();
    if (store != null)
      block =
          store.fetch(
              key,
              dontPromote || !canWriteDatastore,
              canReadClientCache,
              forULPR,
              ignoreOldBlocks,
              meta);
    return block;
  }

  private SSKBlock fetchSSKFromCaches(
      NodeSSK key,
      boolean dontPromote,
      boolean canReadClientCache,
      boolean forULPR,
      boolean ignoreOldBlocks,
      BlockMetadata meta,
      boolean canWriteDatastore)
      throws IOException {
    SSKBlock block =
        sskDatacache.fetch(
            key,
            dontPromote || !canWriteDatastore,
            canReadClientCache,
            forULPR,
            ignoreOldBlocks,
            meta);
    if (block != null) return block;
    SSKStore store = oldSSKCache.get();
    if (store != null)
      block =
          store.fetch(
              key,
              dontPromote || !canWriteDatastore,
              canReadClientCache,
              forULPR,
              ignoreOldBlocks,
              meta);
    return block;
  }

  /**
   * Fetches a CHK block from local stores and caches according to flags.
   *
   * @param key node CHK key to locate.
   * @param dontPromote when {@code true}, avoid promoting into hotter tiers.
   * @param canReadClientCache whether the client cache may be consulted.
   * @param canWriteClientCache whether the client cache may be updated.
   * @param canWriteDatastore whether the datastore may be updated (subject to policy).
   * @param forULPR whether this access is part of ULPR handling.
   * @param meta optional metadata sink; may be {@code null}.
   * @return the {@link CHKBlock} if found; otherwise {@code null}.
   */
  public CHKBlock fetch(
      NodeCHK key,
      boolean dontPromote,
      boolean canReadClientCache,
      boolean canWriteClientCache,
      boolean canWriteDatastore,
      boolean forULPR,
      BlockMetadata meta) {
    double loc = key.toNormalizedDouble();
    double dist = Location.distance(lm.getLocation(), loc);
    CHKBlock fromClient =
        fetchCHKFromClientCaches(
            key,
            new FetchParams(
                dontPromote, canWriteClientCache, canReadClientCache, forULPR, meta, loc, dist));
    if (fromClient != null) return fromClient;
    boolean ignoreOldBlocks = !writeLocalToDatastore && !canReadClientCache;
    if (LOG.isDebugEnabled()) dumpStoreHits();
    try {
      nodeStats.avgRequestLocation.report(loc);
      CHKBlock fromStores = fetchCHKFromStores(key, dontPromote, canWriteDatastore, meta);
      if (fromStores != null) {
        nodeStats.avgStoreCHKSuccess.report(loc);
        if (dist > nodeStats.furthestStoreCHKSuccess) nodeStats.furthestStoreCHKSuccess = dist;
        return fromStores;
      }
      CHKBlock fromCaches =
          fetchCHKFromCaches(key, dontPromote, canWriteDatastore, ignoreOldBlocks, meta);
      if (fromCaches != null) {
        nodeStats.avgCacheCHKSuccess.report(loc);
        if (dist > nodeStats.furthestCacheCHKSuccess) nodeStats.furthestCacheCHKSuccess = dist;
      }
      return fromCaches;
    } catch (IOException e) {
      LOG.error("Cannot fetch data: {}", e, e);
      return null;
    }
  }

  private CHKBlock fetchCHKFromClientCaches(NodeCHK key, FetchParams p) {
    try {
      CHKBlock block =
          chkClientcache.fetch(key, p.dontPromote() || !p.canWriteClientCache(), false, p.meta());
      if (block != null) {
        nodeStats.avgClientCacheCHKSuccess.report(p.loc());
        if (p.dist() > nodeStats.furthestClientCacheCHKSuccess)
          nodeStats.furthestClientCacheCHKSuccess = p.dist();
        return block;
      }
    } catch (IOException e) {
      LOG.error("Could not read from client cache: {}", e, e);
    }
    if (p.forULPR() || useSlashdotCache || p.canReadClientCache()) {
      try {
        CHKBlock block = chkSlashdotcache.fetch(key, p.dontPromote(), false, p.meta());
        if (block != null) {
          nodeStats.avgSlashdotCacheCHKSucess.report(p.loc());
          if (p.dist() > nodeStats.furthestSlashdotCacheCHKSuccess)
            nodeStats.furthestSlashdotCacheCHKSuccess = p.dist();
          return block;
        }
      } catch (IOException e) {
        LOG.error("Could not read from slashdot/ULPR cache: {}", e, e);
      }
    }
    return null;
  }

  private CHKBlock fetchCHKFromStores(
      NodeCHK key, boolean dontPromote, boolean canWriteDatastore, BlockMetadata meta)
      throws IOException {
    CHKBlock block = chkDatastore.fetch(key, dontPromote || !canWriteDatastore, false, meta);
    if (block != null) return block;
    CHKStore store = oldCHK.get();
    if (store != null) block = store.fetch(key, dontPromote || !canWriteDatastore, false, meta);
    return block;
  }

  private CHKBlock fetchCHKFromCaches(
      NodeCHK key,
      boolean dontPromote,
      boolean canWriteDatastore,
      boolean ignoreOldBlocks,
      BlockMetadata meta)
      throws IOException {
    CHKBlock block =
        chkDatacache.fetch(key, dontPromote || !canWriteDatastore, ignoreOldBlocks, meta);
    if (block != null) return block;
    CHKStore store = oldCHKCache.get();
    if (store != null)
      block = store.fetch(key, dontPromote || !canWriteDatastore, ignoreOldBlocks, meta);
    return block;
  }

  CHKStore getChkDatacache() {
    return chkDatacache;
  }

  CHKStore getChkDatastore() {
    return chkDatastore;
  }

  SSKStore getSskDatacache() {
    return sskDatacache;
  }

  SSKStore getSskDatastore() {
    return sskDatastore;
  }

  CHKStore getChkSlashdotCache() {
    return chkSlashdotcache;
  }

  CHKStore getChkClientCache() {
    return chkClientcache;
  }

  SSKStore getSskSlashdotCache() {
    return sskSlashdotcache;
  }

  SSKStore getSskClientCache() {
    return sskClientcache;
  }

  /**
   * This method returns all statistics info for our data store stats table
   *
   * @return map that has an entry for each data store instance type and corresponding stats
   */
  public Map<DataStoreInstanceType, DataStoreStats> getDataStoreStats() {
    Map<DataStoreInstanceType, DataStoreStats> map = new LinkedHashMap<>();

    map.put(
        new DataStoreInstanceType(CHK, STORE),
        new StoreCallbackStats(chkDatastore, nodeStats.chkStoreStats()));
    map.put(
        new DataStoreInstanceType(CHK, CACHE),
        new StoreCallbackStats(chkDatacache, nodeStats.chkCacheStats()));
    map.put(
        new DataStoreInstanceType(CHK, SLASHDOT),
        new StoreCallbackStats(chkSlashdotcache, nodeStats.chkSlashDotCacheStats()));
    map.put(
        new DataStoreInstanceType(CHK, CLIENT),
        new StoreCallbackStats(chkClientcache, nodeStats.chkClientCacheStats()));

    map.put(
        new DataStoreInstanceType(SSK, STORE),
        new StoreCallbackStats(sskDatastore, nodeStats.sskStoreStats()));
    map.put(
        new DataStoreInstanceType(SSK, CACHE),
        new StoreCallbackStats(sskDatacache, nodeStats.sskCacheStats()));
    map.put(
        new DataStoreInstanceType(SSK, SLASHDOT),
        new StoreCallbackStats(sskSlashdotcache, nodeStats.sskSlashDotCacheStats()));
    map.put(
        new DataStoreInstanceType(SSK, CLIENT),
        new StoreCallbackStats(sskClientcache, nodeStats.sskClientCacheStats()));

    map.put(
        new DataStoreInstanceType(PUB_KEY, STORE),
        new StoreCallbackStats(pubKeyDatastore, new NotAvailNodeStoreStats()));
    map.put(
        new DataStoreInstanceType(PUB_KEY, CACHE),
        new StoreCallbackStats(pubKeyDatacache, new NotAvailNodeStoreStats()));
    map.put(
        new DataStoreInstanceType(PUB_KEY, SLASHDOT),
        new StoreCallbackStats(pubKeySlashdotcache, new NotAvailNodeStoreStats()));
    map.put(
        new DataStoreInstanceType(PUB_KEY, CLIENT),
        new StoreCallbackStats(pubKeyClientcache, new NotAvailNodeStoreStats()));

    return map;
  }

  public long getMaxTotalKeys() {
    return maxTotalKeys;
  }

  long timeLastDumpedHits;

  /** Logs aggregate hit/miss statistics for stores and caches for debugging. */
  public void dumpStoreHits() {
    long now = System.currentTimeMillis();
    if (now - timeLastDumpedHits > 5000) {
      timeLastDumpedHits = now;
    } else return;
    String distMsg =
        """
        Distribution of hits and misses over stores:
        CHK Datastore: {}/{}/{}
        CHK Datacache: {}/{}/{}
        SSK Datastore: {}/{}/{}
        SSK Datacache: {}/{}/{}
        """;
    LOG.debug(
        distMsg,
        chkDatastore.hits(),
        chkDatastore.hits() + chkDatastore.misses(),
        chkDatastore.keyCount(),
        chkDatacache.hits(),
        chkDatacache.hits() + chkDatacache.misses(),
        chkDatacache.keyCount(),
        sskDatastore.hits(),
        sskDatastore.hits() + sskDatastore.misses(),
        sskDatastore.keyCount(),
        sskDatacache.hits(),
        sskDatacache.hits() + sskDatacache.misses(),
        sskDatacache.keyCount());
  }

  public void storeShallow(
      CHKBlock block, boolean canWriteClientCache, boolean canWriteDatastore, boolean forULPR) {
    store(block, false, canWriteClientCache, canWriteDatastore, forULPR);
  }

  /**
   * Stores a block to caches and/or persistent store based on flags and policy.
   *
   * <p>This entry point accepts either CHK or SSK blocks and delegates to the type‑specific
   * implementation. Promotion into the persistent store is guarded by HTL and sink checks.
   *
   * @param block the block to store; CHK or SSK.
   * @param deep when {@code true}, writes to the main store if allowed; otherwise to the cache.
   * @param canWriteClientCache whether the client cache may be updated.
   * @param canWriteDatastore whether the persistent store may be updated (subject to policy).
   * @param forULPR whether this write originates from ULPR processing (enables slashdot cache).
   * @throws KeyCollisionException if a conflicting entry exists and overwrite is not permitted for
   *     the specific block type.
   */
  public void store(
      KeyBlock block,
      boolean deep,
      boolean canWriteClientCache,
      boolean canWriteDatastore,
      boolean forULPR)
      throws KeyCollisionException {
    switch (block) {
      case CHKBlock kBlock1 ->
          store(kBlock1, deep, canWriteClientCache, canWriteDatastore, forULPR);
      case SSKBlock kBlock ->
          store(kBlock, deep, false, canWriteClientCache, canWriteDatastore, forULPR);
      default -> throw new IllegalArgumentException("Unknown keytype ");
    }
  }

  private void store(
      CHKBlock block,
      boolean deep,
      boolean canWriteClientCache,
      boolean canWriteDatastore,
      boolean forULPR) {
    try {
      double loc = block.getKey().toNormalizedDouble();
      storeCHKToCachesAndStores(block, deep, canWriteClientCache, canWriteDatastore, forULPR, loc);
      if (canWriteDatastore || forULPR || useSlashdotCache) failureTable.onFound(block);
    } catch (IOException e) {
      LOG.error("Cannot store data: {}", e, e);
    } catch (RuntimeException e) {
      LOG.error("Caught unexpected error storing data", e);
    }
    tripPendingCHK(block);
  }

  private void storeCHKToCachesAndStores(
      CHKBlock block,
      boolean deep,
      boolean canWriteClientCache,
      boolean canWriteDatastore,
      boolean forULPR,
      double loc)
      throws IOException {
    if (canWriteClientCache) {
      chkClientcache.put(block, false);
      nodeStats.avgClientCacheCHKLocation.report(loc);
    }
    if ((forULPR || useSlashdotCache) && !(canWriteDatastore || writeLocalToDatastore)) {
      chkSlashdotcache.put(block, false);
      nodeStats.avgSlashdotCacheCHKLocation.report(loc);
    }
    if (!(canWriteDatastore || writeLocalToDatastore)) return;
    if (deep) {
      chkDatastore.put(block, !canWriteDatastore);
      nodeStats.avgStoreCHKLocation.report(loc);
    } else {
      chkDatacache.put(block, !canWriteDatastore);
      nodeStats.avgCacheCHKLocation.report(loc);
    }
  }

  private void tripPendingCHK(CHKBlock block) {
    if (clientCore == null || clientCore.getRequestStarters() == null) return;
    clientCore.getRequestStarters().chkFetchSchedulerBulk.tripPendingKey(block);
    clientCore.getRequestStarters().chkFetchSchedulerRT.tripPendingKey(block);
  }

  /**
   * Stores the SSK block if this node is a sink according to routing policy.
   *
   * @param block the SSK block to store.
   * @param deep when {@code true}, attempt to write to the main store; otherwise cache only.
   * @param overwrite whether to overwrite an existing entry when hashes collide.
   * @param canWriteClientCache whether the client cache may be updated.
   * @param canWriteDatastore whether the persistent store may be updated.
   * @throws KeyCollisionException if a collision occurs and {@code overwrite} is {@code false}.
   */
  public void storeInsert(
      SSKBlock block,
      boolean deep,
      boolean overwrite,
      boolean canWriteClientCache,
      boolean canWriteDatastore)
      throws KeyCollisionException {
    store(block, deep, overwrite, canWriteClientCache, canWriteDatastore, false);
  }

  /**
   * Stores to caches only (never to the main store).
   *
   * <p>Used by fetch paths where only cache promotion is desired. Persistent store writes are never
   * performed by this method regardless of flags.
   *
   * @param block the SSK block to cache.
   * @param canWriteClientCache whether the client cache may be updated.
   * @param canWriteDatastore whether the datastore write flag is set; ignored here (never used).
   * @param fromULPR whether the write originates from ULPR processing; enables slashdot cache.
   * @throws KeyCollisionException if the cache write detects a key collision.
   */
  public void storeShallow(
      SSKBlock block, boolean canWriteClientCache, boolean canWriteDatastore, boolean fromULPR)
      throws KeyCollisionException {
    store(block, false, canWriteClientCache, canWriteDatastore, fromULPR);
  }

  public void store(
      SSKBlock block,
      boolean deep,
      boolean overwrite,
      boolean canWriteClientCache,
      boolean canWriteDatastore,
      boolean forULPR)
      throws KeyCollisionException {
    try {
      double loc = block.getKey().toNormalizedDouble();
      // Store the pubkey before storing the data, otherwise we can get a race condition and
      // end up deleting the SSK data.
      getPubKey.cacheKey(
          (block.getKey()).getPubKeyHash(),
          (block.getKey()).getPubKey(),
          deep,
          canWriteClientCache,
          canWriteDatastore,
          forULPR || useSlashdotCache,
          writeLocalToDatastore);
      storeSSKToCachesAndStores(
          block, deep, overwrite, canWriteClientCache, canWriteDatastore, forULPR, loc);
      if (canWriteDatastore || forULPR || useSlashdotCache) failureTable.onFound(block);
    } catch (IOException e) {
      LOG.error("Cannot store data: {}", e, e);
    } catch (RuntimeException e) {
      LOG.error("Caught unexpected error storing data", e);
    }
    tripPendingSSK(block);
  }

  private void storeSSKToCachesAndStores(
      SSKBlock block,
      boolean deep,
      boolean overwrite,
      boolean canWriteClientCache,
      boolean canWriteDatastore,
      boolean forULPR,
      double loc)
      throws IOException, KeyCollisionException {
    if (canWriteClientCache) {
      sskClientcache.put(block, overwrite, false);
      nodeStats.avgClientCacheSSKLocation.report(loc);
    }
    if ((forULPR || useSlashdotCache) && !(canWriteDatastore || writeLocalToDatastore)) {
      sskSlashdotcache.put(block, overwrite, false);
      nodeStats.avgSlashdotCacheSSKLocation.report(loc);
    }
    if (!(canWriteDatastore || writeLocalToDatastore)) return;
    if (deep) {
      sskDatastore.put(block, overwrite, !canWriteDatastore);
      nodeStats.avgStoreSSKLocation.report(loc);
    } else {
      sskDatacache.put(block, overwrite, !canWriteDatastore);
      nodeStats.avgCacheSSKLocation.report(loc);
    }
  }

  private void tripPendingSSK(SSKBlock block) {
    if (clientCore == null || clientCore.getRequestStarters() == null) return;
    clientCore.getRequestStarters().sskFetchSchedulerBulk.tripPendingKey(block);
    clientCore.getRequestStarters().sskFetchSchedulerRT.tripPendingKey(block);
  }

  final boolean decrementAtMax;
  final boolean decrementAtMin;

  /**
   * Decrements the HTL according to policy for the given source.
   *
   * <p>Edges (minimum/maximum) may be decremented probabilistically to reduce routing artifacts.
   * When a {@code source} is present, the per‑peer policy is applied; otherwise a node‑level policy
   * is used. The returned value is never negative.
   *
   * @param source peer that forwarded the request, or {@code null} for locally originated traffic.
   * @param htl current hop‑to‑live value before decrement.
   * @return the decremented HTL, bounded between zero and {@code maxHTL}.
   */
  public short decrementHTL(PeerNode source, short htl) {
    if (source != null) return source.decrementHTL(htl);
    // Otherwise...
    if (htl >= maxHTL) htl = maxHTL;
    if (htl <= 0) {
      return 0;
    }
    if (htl == maxHTL) {
      if (decrementAtMax || disableProbabilisticHTLs) htl--;
      return htl;
    }
    if (htl == 1) {
      if (decrementAtMin || disableProbabilisticHTLs) htl--;
      return htl;
    }
    return --htl;
  }

  /**
   * Options for CHK insert senders.
   *
   * <p>These flags influence how a {@link CHKInsertSender} is created and how it behaves during an
   * insert operation (e.g., cache eligibility, coalescing, and backoff handling). Instances are
   * immutable; use the builder‑style {@code withXxx(...)} methods to derive modified copies.
   */
  public static final class ChkInsertOptions {
    public final byte[] headers;
    public final PartiallyReceivedBlock prb;
    public final boolean fromStore;
    public final boolean canWriteClientCache;
    public final boolean forkOnCacheable;
    public final boolean preferInsert;
    public final boolean ignoreLowBackoff;
    public final boolean realTimeFlag;

    @SuppressWarnings("PointlessBitwiseExpression")
    private static final int F_FROM_STORE = 1 << 0;

    private static final int F_CAN_WRITE_CLIENT_CACHE = 1 << 1;
    private static final int F_FORK_ON_CACHEABLE = 1 << 2;
    private static final int F_PREFER_INSERT = 1 << 3;
    private static final int F_IGNORE_LOW_BACKOFF = 1 << 4;
    private static final int F_REALTIME = 1 << 5;

    private ChkInsertOptions(byte[] headers, PartiallyReceivedBlock prb, int flags) {
      this.headers = headers;
      this.prb = prb;
      this.fromStore = (flags & F_FROM_STORE) != 0;
      this.canWriteClientCache = (flags & F_CAN_WRITE_CLIENT_CACHE) != 0;
      this.forkOnCacheable = (flags & F_FORK_ON_CACHEABLE) != 0;
      this.preferInsert = (flags & F_PREFER_INSERT) != 0;
      this.ignoreLowBackoff = (flags & F_IGNORE_LOW_BACKOFF) != 0;
      this.realTimeFlag = (flags & F_REALTIME) != 0;
    }

    public static ChkInsertOptions of(byte[] headers, PartiallyReceivedBlock prb) {
      return new ChkInsertOptions(headers, prb, 0);
    }

    private ChkInsertOptions withFlag(int flag, boolean value) {
      int current = 0;
      if (fromStore) current |= F_FROM_STORE;
      if (canWriteClientCache) current |= F_CAN_WRITE_CLIENT_CACHE;
      if (forkOnCacheable) current |= F_FORK_ON_CACHEABLE;
      if (preferInsert) current |= F_PREFER_INSERT;
      if (ignoreLowBackoff) current |= F_IGNORE_LOW_BACKOFF;
      if (realTimeFlag) current |= F_REALTIME;
      int updated = value ? (current | flag) : (current & ~flag);
      return new ChkInsertOptions(headers, prb, updated);
    }

    public ChkInsertOptions withFromStore(boolean v) {
      return withFlag(F_FROM_STORE, v);
    }

    public ChkInsertOptions withCanWriteClientCache(boolean v) {
      return withFlag(F_CAN_WRITE_CLIENT_CACHE, v);
    }

    public ChkInsertOptions withForkOnCacheable(boolean v) {
      return withFlag(F_FORK_ON_CACHEABLE, v);
    }

    public ChkInsertOptions withPreferInsert(boolean v) {
      return withFlag(F_PREFER_INSERT, v);
    }

    public ChkInsertOptions withIgnoreLowBackoff(boolean v) {
      return withFlag(F_IGNORE_LOW_BACKOFF, v);
    }

    public ChkInsertOptions withRealTimeFlag(boolean v) {
      return withFlag(F_REALTIME, v);
    }
  }

  /**
   * Fetches or creates a {@link CHKInsertSender} for a given key and HTL.
   *
   * <p>If an existing sender for the same key and scheduling class exists, it will be reused with
   * transfer coalescing; otherwise a new sender is constructed, started, and returned. The method
   * is non‑blocking and immediately returns the sender instance.
   *
   * @param key the CHK to insert; must not be {@code null}.
   * @param htl the current hop‑to‑live for the insert; affects sink decisions and routing.
   * @param uid caller‑supplied correlation identifier used in logs and metrics.
   * @param tag insert owner used by schedulers for tracking and cancellation.
   * @param source upstream peer that initiated the insert, or {@code null} for local.
   * @param opts immutable options controlling cache writes, fork‑on‑cacheable, and backoff policy.
   * @return a started {@link CHKInsertSender} coordinating the insert on background threads.
   */
  public CHKInsertSender makeInsertSender(
      NodeCHK key, short htl, long uid, InsertTag tag, PeerNode source, ChkInsertOptions opts) {
    if (LOG.isDebugEnabled())
      LOG.debug("makeInsertSender({},{},{},{},...,{}", key, htl, uid, source, opts.fromStore);
    CHKInsertSender is;
    is =
        new CHKInsertSender(
            key,
            uid,
            tag,
            opts.headers,
            htl,
            source,
            this,
            opts.prb,
            opts.fromStore,
            opts.forkOnCacheable,
            opts.preferInsert,
            opts.ignoreLowBackoff,
            opts.realTimeFlag);
    is.start();
    // CHKInsertSender adds itself to insertSenders
    return is;
  }

  /**
   * Options for SSK insert senders.
   *
   * <p>These flags influence how a {@link SSKInsertSender} is created and how it behaves during an
   * insert operation (e.g., cache/store writes, forking, and backoff handling). Instances are
   * immutable; use the builder‑style {@code withXxx(...)} methods to derive modified copies.
   */
  public static final class SskInsertOptions {
    public final boolean fromStore;
    public final boolean canWriteClientCache;
    public final boolean canWriteDatastore;
    public final boolean forkOnCacheable;
    public final boolean preferInsert;
    public final boolean ignoreLowBackoff;
    public final boolean realTimeFlag;

    @SuppressWarnings("PointlessBitwiseExpression")
    private static final int F_FROM_STORE = 1 << 0;

    private static final int F_CAN_WRITE_CLIENT_CACHE = 1 << 1;
    private static final int F_CAN_WRITE_DATASTORE = 1 << 2;
    private static final int F_FORK_ON_CACHEABLE = 1 << 3;
    private static final int F_PREFER_INSERT = 1 << 4;
    private static final int F_IGNORE_LOW_BACKOFF = 1 << 5;
    private static final int F_REALTIME = 1 << 6;

    private SskInsertOptions(int flags) {
      this.fromStore = (flags & F_FROM_STORE) != 0;
      this.canWriteClientCache = (flags & F_CAN_WRITE_CLIENT_CACHE) != 0;
      this.canWriteDatastore = (flags & F_CAN_WRITE_DATASTORE) != 0;
      this.forkOnCacheable = (flags & F_FORK_ON_CACHEABLE) != 0;
      this.preferInsert = (flags & F_PREFER_INSERT) != 0;
      this.ignoreLowBackoff = (flags & F_IGNORE_LOW_BACKOFF) != 0;
      this.realTimeFlag = (flags & F_REALTIME) != 0;
    }

    public static SskInsertOptions of() {
      return new SskInsertOptions(0);
    }

    private int currentFlags() {
      int f = 0;
      if (fromStore) f |= F_FROM_STORE;
      if (canWriteClientCache) f |= F_CAN_WRITE_CLIENT_CACHE;
      if (canWriteDatastore) f |= F_CAN_WRITE_DATASTORE;
      if (forkOnCacheable) f |= F_FORK_ON_CACHEABLE;
      if (preferInsert) f |= F_PREFER_INSERT;
      if (ignoreLowBackoff) f |= F_IGNORE_LOW_BACKOFF;
      if (realTimeFlag) f |= F_REALTIME;
      return f;
    }

    private SskInsertOptions withFlag(int flag, boolean v) {
      int f = currentFlags();
      int updated = v ? (f | flag) : (f & ~flag);
      return new SskInsertOptions(updated);
    }

    public SskInsertOptions withFromStore(boolean v) {
      return withFlag(F_FROM_STORE, v);
    }

    public SskInsertOptions withCanWriteClientCache(boolean v) {
      return withFlag(F_CAN_WRITE_CLIENT_CACHE, v);
    }

    public SskInsertOptions withCanWriteDatastore(boolean v) {
      return withFlag(F_CAN_WRITE_DATASTORE, v);
    }

    public SskInsertOptions withForkOnCacheable(boolean v) {
      return withFlag(F_FORK_ON_CACHEABLE, v);
    }

    public SskInsertOptions withPreferInsert(boolean v) {
      return withFlag(F_PREFER_INSERT, v);
    }

    public SskInsertOptions withIgnoreLowBackoff(boolean v) {
      return withFlag(F_IGNORE_LOW_BACKOFF, v);
    }

    public SskInsertOptions withRealTimeFlag(boolean v) {
      return withFlag(F_REALTIME, v);
    }
  }

  /**
   * Fetches or creates a {@link SSKInsertSender} for a given block and HTL.
   *
   * <p>If a sender for the same key and scheduling class exists, it may be reused via transfer
   * coalescing; otherwise a new sender is constructed, started, and returned. Public keys required
   * for the insert are cached locally before the sender is created.
   *
   * @param block the SSK block to insert; must contain a non‑null public key.
   * @param htl the current hop‑to‑live for the insert; affects sink decisions and routing.
   * @param uid caller‑supplied correlation identifier used in logs and metrics.
   * @param tag insert owner used by schedulers for tracking and cancellation.
   * @param source upstream peer that initiated the insert, or {@code null} for local.
   * @param opts immutable options controlling cache/store writes, forking, and backoff policy.
   * @return a started {@link SSKInsertSender} coordinating the insert on background threads.
   */
  public SSKInsertSender makeInsertSender(
      SSKBlock block, short htl, long uid, InsertTag tag, PeerNode source, SskInsertOptions opts) {
    NodeSSK key = block.getKey();
    if (key.getPubKey() == null) {
      throw new IllegalArgumentException("No pub key when inserting");
    }

    getPubKey.cacheKey(
        key.getPubKeyHash(),
        key.getPubKey(),
        false,
        opts.canWriteClientCache,
        opts.canWriteDatastore,
        false,
        writeLocalToDatastore);
    if (LOG.isDebugEnabled())
      LOG.debug("makeInsertSender({},{},{},{},...,{}", key, htl, uid, source, opts.fromStore);
    SSKInsertSender is;
    is =
        new SSKInsertSender(
            block,
            uid,
            tag,
            htl,
            source,
            this,
            opts.fromStore,
            opts.forkOnCacheable,
            opts.preferInsert,
            opts.ignoreLowBackoff,
            opts.realTimeFlag);
    is.start();
    return is;
  }

  /**
   * Returns a human‑readable summary of current node status.
   *
   * @return a multi‑line textual summary including peer and transfer information.
   */
  public String getStatus() {
    StringBuilder sb = new StringBuilder();
    if (peers != null) sb.append(peers.getStatus());
    else sb.append("No peers yet");
    sb.append(tracker.getNumTransferringRequestSenders());
    sb.append('\n');
    return sb.toString();
  }

  /**
   * Returns a textual list of peers formatted for TMCI.
   *
   * @return a string containing the current TMCI peer listing.
   */
  public String getTMCIPeerList() {
    StringBuilder sb = new StringBuilder();
    if (peers != null) sb.append(peers.getTMCIPeerList());
    else sb.append("No peers yet");
    return sb.toString();
  }

  /**
   * Fetches a client key (CHK or SSK) from local caches/stores.
   *
   * @param key client‑level key wrapper.
   * @param canReadClientCache allow consulting the client cache.
   * @param canWriteClientCache allow promoting results into the client cache.
   * @param canWriteDatastore allow promoting results into the persistent store (policy permitting).
   * @return a {@link ClientKeyBlock} when found locally; otherwise {@code null}.
   * @throws KeyVerifyException if block verification fails for the specific key type.
   */
  @SuppressWarnings("unused")
  public ClientKeyBlock fetchKey(
      ClientKey key,
      boolean canReadClientCache,
      boolean canWriteClientCache,
      boolean canWriteDatastore)
      throws KeyVerifyException {
    return switch (key) {
      case ClientCHK hK -> fetch(hK, canReadClientCache, canWriteClientCache, canWriteDatastore);
      case ClientSSK sK -> fetch(sK, canReadClientCache, canWriteClientCache, canWriteDatastore);
      default -> throw new IllegalStateException("Don't know what to do with " + key);
    };
  }

  /**
   * Fetches an SSK for a client key from local caches/stores.
   *
   * @param clientSSK client key wrapper; the public key will be resolved if missing.
   * @param canReadClientCache allow consulting the client cache.
   * @param canWriteClientCache allow promoting results into the client cache.
   * @param canWriteDatastore allow promoting results into the persistent store (policy permitting).
   * @return a constructed {@link ClientSSKBlock} when found; otherwise {@code null}.
   * @throws SSKVerifyException when verification fails or the public key is not valid.
   */
  public ClientKeyBlock fetch(
      ClientSSK clientSSK,
      boolean canReadClientCache,
      boolean canWriteClientCache,
      boolean canWriteDatastore)
      throws SSKVerifyException {
    DSAPublicKey key = clientSSK.getPubKey();
    if (key == null) {
      key = getPubKey.getKey(clientSSK.pubKeyHash, canReadClientCache, false, null);
    }
    if (key == null) return null;
    clientSSK.setPublicKey(key);
    SSKBlock block =
        fetch(
            (NodeSSK) clientSSK.getNodeKey(true),
            false,
            canReadClientCache,
            canWriteClientCache,
            canWriteDatastore,
            false,
            null);
    if (block == null) {
      if (LOG.isDebugEnabled()) LOG.debug("Could not find key for {}", clientSSK);
      return null;
    }
    // Move the pubkey to the top of the LRU, and fix it if it
    // was corrupt.
    getPubKey.cacheKey(
        clientSSK.pubKeyHash,
        key,
        false,
        canWriteClientCache,
        canWriteDatastore,
        false,
        writeLocalToDatastore);
    return ClientSSKBlock.construct(block, clientSSK);
  }

  /**
   * Fetches a CHK for a client key from local caches/stores.
   *
   * @param clientCHK client key wrapper.
   * @param canReadClientCache allow consulting the client cache.
   * @param canWriteClientCache allow promoting results into the client cache.
   * @param canWriteDatastore allow promoting results into the persistent store (policy permitting).
   * @return a constructed {@link ClientCHKBlock} when found; otherwise {@code null}.
   * @throws CHKVerifyException when verification fails.
   */
  private ClientKeyBlock fetch(
      ClientCHK clientCHK,
      boolean canReadClientCache,
      boolean canWriteClientCache,
      boolean canWriteDatastore)
      throws CHKVerifyException {
    CHKBlock block =
        fetch(
            clientCHK.getNodeCHK(),
            false,
            canReadClientCache,
            canWriteClientCache,
            canWriteDatastore,
            false,
            null);
    if (block == null) return null;
    return new ClientCHKBlock(block, clientCHK);
  }

  /**
   * Attempts a graceful shutdown and then exits the JVM with the given code.
   *
   * @param reason exit status code to return to the OS.
   */
  @SuppressWarnings("finally")
  public void exit(int reason) {
    try {
      this.park();
      LOG.info("Goodbye. ({})", reason);
    } finally {
      System.exit(reason);
    }
  }

  /**
   * Attempts a graceful shutdown and then exits the JVM (status 0).
   *
   * @param reason textual reason recorded in logs.
   */
  @SuppressWarnings("finally")
  public void exit(String reason) {
    try {
      this.park();
      LOG.info("Goodbye. from {} ({})", this, reason);
    } finally {
      System.exit(0);
    }
  }

  /**
   * Reports whether the node is in the process of shutting down.
   *
   * @return {@code true} when shutdown has begun and new work should not be scheduled.
   */
  public boolean isStopping() {
    return isStopping;
  }

  /**
   * Get the node into a state where it can be stopped safely May be called twice - once in exit
   * (above) and then again from the wrapper triggered by calling System.exit(). Beware!
   */
  public void park() {
    synchronized (this) {
      if (isStopping) return;
      isStopping = true;
    }

    try {
      Message msg = DMT.createFNPDisconnect(false, false, -1, new ShortBuffer(new byte[0]));
      peers.messenger().localBroadcast(msg, true, false, peers.messenger().getDisconnCounter());
    } catch (Exception t) {
      try {
        // E.g. if we haven't finished startup
        LOG.error("Failed to tell peers we are going down: {}", t, t);
      } catch (Exception _) {
        // Ignore. We don't want to mess up the exit process!
      }
    }

    config.store();

    if (random instanceof PersistentRandomSource source) {
      source.writeSeed(true);
    }
  }

  public NodeUpdateManager getNodeUpdater() {
    return nodeUpdater;
  }

  /**
   * Returns the current list of darknet peer connections.
   *
   * @return array of active darknet peers.
   */
  public DarknetPeerNode[] getDarknetConnections() {
    return peers.roster().getDarknetPeers();
  }

  /**
   * Adds a peer to the connection set and persists the peer list.
   *
   * @param pn peer to add.
   * @return {@code true} if added; {@code false} if it already existed.
   */
  @SuppressWarnings("BooleanMethodIsAlwaysInverted")
  public boolean addPeerConnection(PeerNode pn) {
    boolean retval = peers.addPeer(pn);
    peers.writePeersUrgent(pn.isOpennet());
    return retval;
  }

  /**
   * Disconnects and removes a peer connection.
   *
   * @param pn peer to disconnect and remove.
   */
  public void removePeerConnection(PeerNode pn) {
    peers.messenger().disconnectAndRemove(pn, true, false, false);
  }

  public void onConnectedPeer() {
    if (LOG.isDebugEnabled()) LOG.debug("onConnectedPeer()");
    ipDetector.onConnectedPeer();
  }

  /**
   * Returns the local darknet FNP UDP port.
   *
   * @return local UDP port number for the darknet socket.
   */
  public int getFNPPort() {
    return this.getDarknetPortNumber();
  }

  public boolean isOudated() {
    return peers.isOutdated();
  }

  private final Map<Integer, NodeToNodeMessageListener> n2nmListeners = new HashMap<>();

  public synchronized void registerNodeToNodeMessageListener(
      int type, NodeToNodeMessageListener listener) {
    n2nmListeners.put(type, listener);
  }

  /**
   * Handles a received node‑to‑node message provided by the transport layer.
   *
   * @param m the decoded message wrapper, including type and payload objects.
   * @param src the peer that sent the message.
   */
  public void receivedNodeToNodeMessage(Message m, PeerNode src) {
    int type = (Integer) m.getObject(DMT.NODE_TO_NODE_MESSAGE_TYPE);
    ShortBuffer messageData = (ShortBuffer) m.getObject(DMT.NODE_TO_NODE_MESSAGE_DATA);
    receivedNodeToNodeMessage(src, type, messageData, false);
  }

  public void receivedNodeToNodeMessage(
      PeerNode src, int type, ShortBuffer messageData, boolean partingMessage) {
    boolean fromDarknet = src instanceof DarknetPeerNode;

    NodeToNodeMessageListener listener;
    synchronized (this) {
      listener = n2nmListeners.get(type);
    }

    if (listener == null) {
      LOG.error(
          "Unknown n2nm ID (parting={}): {} - discarding packet length {}",
          partingMessage,
          type,
          messageData.getLength());
      return;
    }

    listener.handleMessage(messageData.getData(), fromDarknet, src, type);
  }

  /**
   * Handles a node‑to‑node text message formatted as a {@link SimpleFieldSet}.
   *
   * @param fs the parsed field set payload; ownership is not transferred.
   * @param source the darknet peer that sent the message.
   * @param fileNumber extra‑peer‑data file index used to reference persisted metadata.
   * @throws FSParseException if the field set does not conform to the expected schema.
   */
  public void handleNodeToNodeTextMessageSimpleFieldSet(
      SimpleFieldSet fs, DarknetPeerNode source, int fileNumber) throws FSParseException {
    if (LOG.isDebugEnabled()) LOG.debug("Got node to node message: \n{}", fs);
    int overallType = fs.getInt(N2N_TYPE_KEY);
    fs.removeValue(N2N_TYPE_KEY);
    if (overallType == Node.N2N_MESSAGE_TYPE_FPROXY) {
      handleFproxyNodeToNodeTextMessageSimpleFieldSet(fs, source, fileNumber);
    } else {
      LOG.error(
          "Received unknown node to node message type '{}' from {}", overallType, source.getPeer());
    }
  }

  private void handleFproxyNodeToNodeTextMessageSimpleFieldSet(
      SimpleFieldSet fs, DarknetPeerNode source, int fileNumber) throws FSParseException {
    int type = fs.getInt("type");
    switch (type) {
      case Node.N2N_TEXT_MESSAGE_TYPE_USERALERT -> source.handleFproxyN2NTM(fs, fileNumber);
      case Node.N2N_TEXT_MESSAGE_TYPE_FILE_OFFER -> source.handleFproxyFileOffer(fs, fileNumber);
      case Node.N2N_TEXT_MESSAGE_TYPE_FILE_OFFER_ACCEPTED ->
          source.handleFproxyFileOfferAccepted(fs, fileNumber);
      case Node.N2N_TEXT_MESSAGE_TYPE_FILE_OFFER_REJECTED ->
          source.handleFproxyFileOfferRejected(fs, fileNumber);
      case Node.N2N_TEXT_MESSAGE_TYPE_BOOKMARK -> source.handleFproxyBookmarkFeed(fs, fileNumber);
      case Node.N2N_TEXT_MESSAGE_TYPE_DOWNLOAD -> source.handleFproxyDownloadFeed(fs, fileNumber);
      default ->
          LOG.error(
              "Received unknown fproxy node to node message sub-type '{}' from {}",
              type,
              source.getPeer());
    }
  }

  public String getMyName() {
    return myName;
  }

  public MessageCore getUSM() {
    return usm;
  }

  public LocationManager getLocationManager() {
    return lm;
  }

  public int getSwaps() {
    return LocationManager.getSwaps();
  }

  public int getNoSwaps() {
    return LocationManager.getNoSwaps();
  }

  public int getStartedSwaps() {
    return LocationManager.getStartedSwaps();
  }

  public int getSwapsRejectedAlreadyLocked() {
    return LocationManager.getSwapsRejectedAlreadyLocked();
  }

  public int getSwapsRejectedNowhereToGo() {
    return LocationManager.getSwapsRejectedNowhereToGo();
  }

  public int getSwapsRejectedRateLimit() {
    return LocationManager.getSwapsRejectedRateLimit();
  }

  public int getSwapsRejectedRecognizedID() {
    return LocationManager.getSwapsRejectedRecognizedID();
  }

  public PeerNode[] getPeerNodes() {
    return peers.myPeers();
  }

  public PeerNode[] getConnectedPeers() {
    return peers.connectedPeers();
  }

  /**
   * Finds a peer node by identity string, name (darknet), or "host:port" text.
   *
   * @param nodeIdentifier peer selector: identity string, configured name (darknet only), or
   *     address in {@code host:port} format.
   * @return the matching peer node when found; otherwise {@code null}.
   */
  public PeerNode getPeerNode(String nodeIdentifier) {
    for (PeerNode pn : peers.myPeers()) {
      Peer peer = pn.getPeer();
      String nodeIpAndPort = "";
      if (peer != null) {
        nodeIpAndPort = peer.toString();
      }
      String identity = pn.getIdentityString();
      if (pn instanceof DarknetPeerNode dpn) {
        String name = dpn.myName;
        if (identity.equals(nodeIdentifier)
            || nodeIpAndPort.equals(nodeIdentifier)
            || name.equals(nodeIdentifier)) {
          return pn;
        }
      } else {
        if (identity.equals(nodeIdentifier) || nodeIpAndPort.equals(nodeIdentifier)) {
          return pn;
        }
      }
    }
    return null;
  }

  public boolean isHasStarted() {
    return hasStarted;
  }

  public void queueRandomReinsert(KeyBlock block) {
    clientCore.getTransfers().queueRandomReinsert(block);
  }

  public String getExtraPeerDataDir() {
    return extraPeerDataDir.getPath();
  }

  public boolean noConnectedPeers() {
    return !peers.anyConnectedPeers();
  }

  public double getLocation() {
    return lm.getLocation();
  }

  public double getLocationChangeSession() {
    return lm.getLocChangeSession();
  }

  /**
   * Returns the average outgoing swap completion time in milliseconds.
   *
   * @return moving average of swap completion time.
   */
  public int getAverageOutgoingSwapTime() {
    return lm.getAverageSwapTime();
  }

  public long getSendSwapInterval() {
    return lm.getSendSwapInterval();
  }

  public int getNumberOfRemotePeerLocationsSeenInSwaps() {
    return lm.numberOfRemotePeerLocationsSeenInSwaps;
  }

  public boolean isAdvancedModeEnabled() {
    if (clientCore == null) return false;
    return clientCore.isAdvancedModeEnabled();
  }

  public boolean isFProxyJavascriptEnabled() {
    return clientCore.isFProxyJavascriptEnabled();
  }

  // Consider converting these kinds of threads to Checkpointed and implement a handler
  // using the PacketSender/Ticker. Would save a few threads.

  public int getNumARKFetchers() {
    int x = 0;
    for (PeerNode p : peers.myPeers()) {
      if (p.isFetchingARK()) x++;
    }
    return x;
  }

  // Consider moving this elsewhere
  private final Object statsSync = new Object();

  /** The total number of bytes of real data i.e.&nbsp;payload sent by the node */
  private long totalPayloadSent;

  public void sentPayload(int len) {
    synchronized (statsSync) {
      totalPayloadSent += len;
    }
  }

  /**
   * Get the total number of bytes of payload (real data) sent by the node
   *
   * @return Total payload sent in bytes
   */
  public long getTotalPayloadSent() {
    synchronized (statsSync) {
      return totalPayloadSent;
    }
  }

  public void setName(String key) throws InvalidConfigValueException, NodeNeedRestartException {
    config.get("node").getOption("name").setValue(key);
  }

  public Ticker getTicker() {
    return ticker;
  }

  public int getUnclaimedFIFOSize() {
    return usm.getUnclaimedFIFOSize();
  }

  /**
   * Connects this node to a seed server peer (testing only).
   *
   * @param node seed peer to connect for controlled testing scenarios.
   */
  public void connectToSeednode(SeedServerTestPeerNode node) {
    peers.addPeer(node, false, false);
  }

  /**
   * Connects to another node using the supplied reference and friend settings.
   *
   * @param node target node to connect to.
   * @param trust initial friend trust level.
   * @param visibility visibility setting for the friend.
   * @throws FSParseException on reference parse errors.
   * @throws PeerParseException if peer fields are malformed.
   * @throws ReferenceSignatureVerificationException if the reference signature is invalid.
   * @throws PeerTooOldException if the peer does not meet minimum version requirements.
   */
  public void connect(Node node, FRIEND_TRUST trust, FRIEND_VISIBILITY visibility)
      throws FSParseException,
          PeerParseException,
          ReferenceSignatureVerificationException,
          PeerTooOldException {
    peers.connector().connect(node.darknetCrypto.exportPublicFieldSet(), trust, visibility);
  }

  public short maxHTL() {
    return maxHTL;
  }

  /**
   * Returns the darknet UDP port number in use.
   *
   * @return UDP port number.
   */
  public int getDarknetPortNumber() {
    return darknetCrypto.getPortNumber();
  }

  public synchronized int getOutputBandwidthLimit() {
    return outputBandwidthLimit;
  }

  public synchronized int getInputBandwidthLimit() {
    if (inputLimitDefault) return outputBandwidthLimit * 4;
    return inputBandwidthLimit;
  }

  /**
   * Returns the configured total datastore size in bytes.
   *
   * @return total byte capacity allocated for all persistent stores combined.
   */
  public synchronized long getStoreSize() {
    return maxTotalDatastoreSize;
  }

  @Override
  public synchronized void setTimeSkewDetectedUserAlert() {
    if (timeSkewDetectedUserAlert == null) {
      timeSkewDetectedUserAlert = new TimeSkewDetectedUserAlert();
      clientCore.getAlerts().register(timeSkewDetectedUserAlert);
    }
  }

  /**
   * Returns the node directory root (identity and peer files).
   *
   * @return node directory path.
   */
  public File getNodeDir() {
    return nodeDir.dir();
  }

  /**
   * Returns the configuration directory root.
   *
   * @return configuration directory path.
   */
  public File getCfgDir() {
    return cfgDir.dir();
  }

  /**
   * Returns the user data directory root.
   *
   * @return user data directory path.
   */
  public File getUserDir() {
    return userDir.dir();
  }

  /**
   * Returns the runtime state directory root.
   *
   * @return runtime state directory path.
   */
  public File getRunDir() {
    return runDir.dir();
  }

  /**
   * Returns the datastore base directory.
   *
   * @return datastore base directory path.
   */
  public File getStoreDir() {
    return storeDir.dir();
  }

  /**
   * Returns the plugin directory root.
   *
   * @return plugin directory path.
   */
  public File getPluginDir() {
    return pluginDir.dir();
  }

  /**
   * ProgramDirectory handle for the node directory.
   *
   * @return program directory handle.
   */
  public ProgramDirectory nodeDir() {
    return nodeDir;
  }

  /**
   * ProgramDirectory handle for the configuration directory.
   *
   * @return program directory handle.
   */
  public ProgramDirectory cfgDir() {
    return cfgDir;
  }

  /**
   * ProgramDirectory handle for the user data directory.
   *
   * @return program directory handle.
   */
  public ProgramDirectory userDir() {
    return userDir;
  }

  /**
   * ProgramDirectory handle for the runtime state directory.
   *
   * @return program directory handle.
   */
  public ProgramDirectory runDir() {
    return runDir;
  }

  /**
   * ProgramDirectory handle for the datastore base directory.
   *
   * @return program directory handle.
   */
  public ProgramDirectory storeDir() {
    return storeDir;
  }

  /**
   * ProgramDirectory handle for the plugin directory.
   *
   * @return program directory handle.
   */
  public ProgramDirectory pluginDir() {
    return pluginDir;
  }

  /**
   * Creates a new darknet peer from a reference.
   *
   * @param fs parsed darknet reference.
   * @param trust initial friend trust level.
   * @param visibility visibility setting for the friend.
   * @return constructed {@link DarknetPeerNode} not yet connected.
   * @throws FSParseException if the reference cannot be parsed.
   * @throws PeerParseException if peer fields are malformed.
   * @throws ReferenceSignatureVerificationException if the signature on the reference is invalid.
   * @throws PeerTooOldException if the peer does not meet minimum version requirements.
   */
  public DarknetPeerNode createNewDarknetNode(
      SimpleFieldSet fs, FRIEND_TRUST trust, FRIEND_VISIBILITY visibility)
      throws FSParseException,
          PeerParseException,
          ReferenceSignatureVerificationException,
          PeerTooOldException {
    return new DarknetPeerNode(fs, this, darknetCrypto, false, trust, visibility, getPeers());
  }

  /**
   * Creates a new opennet peer from a reference.
   *
   * @param fs parsed opennet reference; must belong to a compatible peer.
   * @return constructed {@link OpennetPeerNode} not yet connected.
   * @throws FSParseException on parse errors.
   * @throws OpennetDisabledException if opennet is not enabled on this node.
   * @throws PeerParseException if peer fields are malformed.
   * @throws ReferenceSignatureVerificationException if the signature on the reference is invalid.
   * @throws PeerTooOldException if the peer does not meet minimum version requirements.
   */
  public OpennetPeerNode createNewOpennetNode(SimpleFieldSet fs)
      throws FSParseException,
          OpennetDisabledException,
          PeerParseException,
          ReferenceSignatureVerificationException,
          PeerTooOldException {
    if (opennet == null) throw new OpennetDisabledException("Opennet is not currently enabled");
    return new OpennetPeerNode(fs, this, opennet.getCrypto(), opennet, false, getPeers());
  }

  /**
   * Creates a seed‑server test peer from a reference (testing).
   *
   * @param fs parsed opennet reference.
   * @return a {@link SeedServerTestPeerNode} instance used for local testing.
   * @throws FSParseException on parse errors.
   * @throws OpennetDisabledException if opennet is not enabled on this node.
   * @throws PeerParseException if peer fields are malformed.
   * @throws ReferenceSignatureVerificationException if the signature on the reference is invalid.
   * @throws PeerTooOldException if the peer does not meet minimum version requirements.
   */
  public SeedServerTestPeerNode createNewSeedServerTestPeerNode(SimpleFieldSet fs)
      throws FSParseException,
          OpennetDisabledException,
          PeerParseException,
          ReferenceSignatureVerificationException,
          PeerTooOldException {
    if (opennet == null) throw new OpennetDisabledException("Opennet is not currently enabled");
    return new SeedServerTestPeerNode(fs, this, opennet.getCrypto(), true, getPeers());
  }

  /**
   * Adds a new opennet peer to the manager.
   *
   * @param fs parsed opennet reference.
   * @param connectionType desired connection type.
   * @return the created {@link OpennetPeerNode} or {@code null} if opennet is disabled.
   * @throws FSParseException on parse errors.
   * @throws PeerParseException if peer fields are malformed.
   * @throws ReferenceSignatureVerificationException if the signature on the reference is invalid.
   */
  public OpennetPeerNode addNewOpennetNode(SimpleFieldSet fs, ConnectionType connectionType)
      throws FSParseException, PeerParseException, ReferenceSignatureVerificationException {
    // Perhaps this should throw OpennetDisabledExcemption rather than returning false
    if (opennet == null) return null;
    return opennet.addNewOpennetNode(fs, connectionType, false);
  }

  /**
   * Returns the opennet ECDSA public key hash.
   *
   * @return 32‑byte public key hash.
   */
  public byte[] getOpennetPubKeyHash() {
    return opennet.getCrypto().getEcdsaPubKeyHash();
  }

  /**
   * Returns the darknet ECDSA public key hash.
   *
   * @return 32‑byte public key hash.
   */
  public byte[] getDarknetPubKeyHash() {
    return darknetCrypto.getEcdsaPubKeyHash();
  }

  /**
   * Indicates whether opennet is currently enabled.
   *
   * @return {@code true} when opennet is enabled.
   */
  public synchronized boolean isOpennetEnabled() {
    return opennet != null;
  }

  /**
   * Exports the darknet public reference for this node.
   *
   * @return field set describing the public darknet reference.
   */
  public SimpleFieldSet exportDarknetPublicFieldSet() {
    return darknetCrypto.exportPublicFieldSet();
  }

  /**
   * Exports the opennet public reference for this node.
   *
   * @return field set describing the public opennet reference.
   */
  public SimpleFieldSet exportOpennetPublicFieldSet() {
    return opennet.getCrypto().exportPublicFieldSet();
  }

  /**
   * Exports the darknet private reference for this node.
   *
   * @return field set containing private darknet information.
   */
  public SimpleFieldSet exportDarknetPrivateFieldSet() {
    return darknetCrypto.exportPrivateFieldSet();
  }

  /**
   * Exports the opennet private reference for this node.
   *
   * @return field set containing private opennet information.
   */
  public SimpleFieldSet exportOpennetPrivateFieldSet() {
    return opennet.getCrypto().exportPrivateFieldSet();
  }

  /**
   * Indicates whether IP detection should be skipped in favor of explicit bindings.
   *
   * @return {@code true} when all in‑use ports have explicit {@code bindTo} values; otherwise
   *     {@code false}.
   */
  public synchronized boolean dontDetect() {
    // Only return true if bindTo is set on all ports which are in use
    if (!darknetCrypto.getBindTo().isRealInternetAddress(false, true, false)) return false;
    if (opennet != null) {
      return !opennet.getCrypto().getBindTo().isRealInternetAddress(false, true, false);
    }
    return true;
  }

  public int getOpennetFNPPort() {
    if (opennet == null) return -1;
    return opennet.getCrypto().getPortNumber();
  }

  public OpennetManager getOpennet() {
    return opennet;
  }

  public synchronized boolean passOpennetRefsThroughDarknet() {
    return passOpennetRefsThroughDarknet;
  }

  /**
   * Get the set of public ports that need to be forwarded. These are internal ports, not
   * necessarily external - they may be rewritten by the NAT.
   *
   * @return A Set of ForwardPort's to be fed to port forward plugins.
   */
  public Set<ForwardPort> getPublicInterfacePorts() {
    HashSet<ForwardPort> set = new HashSet<>();
    // IPv6 support may be added
    set.add(
        new ForwardPort(
            "darknet", false, ForwardPort.PROTOCOL_UDP_IPV4, darknetCrypto.getPortNumber()));
    if (opennet != null) {
      NodeCrypto crypto = opennet.getCrypto();
      if (crypto != null) {
        set.add(
            new ForwardPort(
                "opennet", false, ForwardPort.PROTOCOL_UDP_IPV4, crypto.getPortNumber()));
      }
    }
    return set;
  }

  /**
   * Get the time since the node was started in milliseconds.
   *
   * @return Uptime in milliseconds
   */
  public long getUptime() {
    return System.currentTimeMillis() - usm.getStartedTime();
  }

  public synchronized UdpSocketHandler[] getPacketSocketHandlers() {
    // Consider a better way to get these
    if (opennet != null) {
      return new UdpSocketHandler[] {darknetCrypto.getSocket(), opennet.getCrypto().getSocket()};

    } else {
      return new UdpSocketHandler[] {darknetCrypto.getSocket()};
    }
  }

  public int getMaxOpennetPeers() {
    return maxOpennetPeers;
  }

  public void onAddedValidIP() {
    OpennetManager om;
    synchronized (this) {
      om = opennet;
    }
    if (om != null) {
      Announcer announcer = om.getAnnouncer();
      if (announcer != null) {
        announcer.maybeSendAnnouncement();
      }
    }
  }

  public boolean isSeednode() {
    return acceptSeedConnections;
  }

  /**
   * Determines whether anonymous authentication should be attempted for unknown packets.
   *
   * @param isOpennet {@code true} if the packet arrived on the opennet transport.
   * @return {@code true} when anonymous auth should be attempted on the given transport.
   */
  public boolean wantAnonAuth(boolean isOpennet) {
    if (isOpennet) return opennet != null && acceptSeedConnections;
    else return false;
  }

  // Consider making this configurable
  // Probably should wait until we have non-opennet anon auth so we can add it to NodeCrypto.
  public boolean wantAnonAuthChangeIP(boolean isOpennet) {
    return !isOpennet;
  }

  @SuppressWarnings("unused")
  public boolean opennetDefinitelyPortForwarded() {
    OpennetManager om;
    synchronized (this) {
      om = this.opennet;
    }
    if (om == null) return false;
    NodeCrypto crypto = om.getCrypto();
    if (crypto == null) return false;
    return crypto.definitelyPortForwarded();
  }

  /**
   * Reports whether the darknet socket is definitely port‑forwarded.
   *
   * @return {@code true} if external reachability is confirmed; otherwise {@code false}.
   */
  public boolean darknetDefinitelyPortForwarded() {
    if (darknetCrypto == null) return false;
    return darknetCrypto.definitelyPortForwarded();
  }

  public boolean hasKey(Key key, boolean canReadClientCache, boolean forULPR) {
    // Consider optimizing
    if (key instanceof NodeCHK hK)
      return fetch(hK, true, canReadClientCache, false, false, forULPR, null) != null;
    else return fetch((NodeSSK) key, true, canReadClientCache, false, false, forULPR, null) != null;
  }

  /**
   * Sets the node's location without broadcasting a change to peers.
   *
   * @param loc new normalized location value.
   */
  public void setLocation(double loc) {
    lm.setLocation(loc);
  }

  @SuppressWarnings("unused")
  public boolean peersWantKey(Key key) {
    return failureTable.peersWantKey(key, null);
  }

  private final RequestClient nonPersistentClientBulk = new RequestClientBuilder().build();

  private final RequestClient nonPersistentClientRT = new RequestClientBuilder().realTime().build();

  public void setDispatcherHook(NodeDispatcherCallback cb) {
    this.dispatcher.setHook(cb);
  }

  public boolean shallWePublishOurPeersLocation() {
    return publishOurPeersLocation;
  }

  public boolean shallWeRouteAccordingToOurPeersLocation(int htl) {
    return routeAccordingToOurPeersLocation && htl > 1;
  }

  /**
   * Sets or unlocks the master password used for encrypted client material.
   *
   * @param password clear‑text password entered by the user.
   * @param inFirstTimeWizard {@code true} when called during the first‑time setup wizard.
   * @throws AlreadySetPasswordException if a password is already set; use changeMasterPassword().
   * @throws MasterKeysWrongPasswordException if the provided password does not unlock existing
   *     material.
   * @throws MasterKeysFileSizeException if the master key file has an invalid size.
   * @throws IOException on I/O errors while reading or writing key material.
   */
  public void setMasterPassword(String password, boolean inFirstTimeWizard)
      throws AlreadySetPasswordException,
          MasterKeysWrongPasswordException,
          MasterKeysFileSizeException,
          IOException {
    MasterKeys k;
    synchronized (this) {
      if (keys == null) {
        // First-time set or decrypting existing material.
        keys = MasterKeys.read(masterKeysFile, secureRandom, password);
        databaseKey = keys.createDatabaseKey();
      } else {
        // A password is already set; use changeMasterPassword() instead of setMasterPassword().
        throw new AlreadySetPasswordException();
      }
      k = keys;
    }
    setPasswordInner(k, inFirstTimeWizard);
  }

  private void setPasswordInner(MasterKeys keys, boolean inFirstTimeWizard) {
    if (LOG.isTraceEnabled()) {
      LOG.trace("setPasswordInner(inFirstTimeWizard={})", inFirstTimeWizard);
    }
    MasterSecret secret = keys.getPersistentMasterSecret();
    clientCore.setupMasterSecret(secret);
    boolean wantClientCache;
    boolean wantDatabase;
    synchronized (this) {
      wantClientCache = clientCacheAwaitingPassword;
      wantDatabase = databaseAwaitingPassword;
      databaseAwaitingPassword = false;
    }
    if (wantClientCache) activatePasswordedClientCache(keys);
    if (wantDatabase) lateSetupDatabase(keys.createDatabaseKey());
  }

  private void activatePasswordedClientCache(MasterKeys keys) {
    synchronized (this) {
      if (clientCacheType.equals("ram")) {
        LOG.warn("RAM client cache cannot be passworded!");
        return;
      }
      if (!clientCacheType.equals(TYPE_SALT_HASH)) {
        LOG.warn(
            "Unknown client cache type, cannot activate passworded store: {}", clientCacheType);
        return;
      }
    }
    Runnable migrate = new MigrateOldStoreData(true);

    try {
      initSaltHashClientCacheFS(true, keys.clientCacheMasterKey);
    } catch (NodeInitException e) {
      LOG.error("Unable to activate passworded client cache", e);
      return;
    }

    synchronized (this) {
      clientCacheAwaitingPassword = false;
    }

    executor.execute(migrate, "Migrate data from previous store");
  }

  /**
   * Changes the master password protecting client material.
   *
   * @param oldPassword the old password; may be empty when not previously set.
   * @param newPassword the new password to set for protecting client materials.
   * @param inFirstTimeWizard whether invoked from the first‑time wizard.
   * @throws MasterKeysWrongPasswordException if the old password is incorrect.
   * @throws MasterKeysFileSizeException if the master keys file has an invalid size.
   * @throws IOException on I/O errors while writing new key material.
   * @throws AlreadySetPasswordException if a password is already configured.
   */
  public void changeMasterPassword(
      String oldPassword, String newPassword, boolean inFirstTimeWizard)
      throws MasterKeysWrongPasswordException,
          MasterKeysFileSizeException,
          IOException,
          AlreadySetPasswordException {
    if (LOG.isTraceEnabled()) {
      LOG.trace(
          "changeMasterPassword(oldProvided={}, inFirstTimeWizard={})",
          oldPassword != null && !oldPassword.isEmpty(),
          inFirstTimeWizard);
    }
    if (securityLevels.getPhysicalThreatLevel() == PHYSICAL_THREAT_LEVEL.MAXIMUM)
      LOG.error("Changing password while physical threat level is at MAXIMUM???");
    if (masterKeysFile.exists()) {
      keys.changePassword(masterKeysFile, newPassword, secureRandom);
      setPasswordInner(keys, inFirstTimeWizard);
    } else {
      setMasterPassword(newPassword, inFirstTimeWizard);
    }
  }

  /** Thrown when a master password is already configured and a new one is set. */
  public static class AlreadySetPasswordException extends Exception {

    @Serial private static final long serialVersionUID = -7328456475029374032L;
  }

  public synchronized File getMasterPasswordFile() {
    return masterKeysFile;
  }

  boolean hasPanicked() {
    return hasPanicked;
  }

  public void panic() {
    hasPanicked = true;
    clientCore.getClientLayerPersister().panic();
    clientCore.getClientLayerPersister().killAndWaitForNotRunning();
    try {
      MasterKeys.killMasterKeys(getMasterPasswordFile());
    } catch (IOException _) {
      LOG.warn(
          "Unable to wipe master passwords key file! Please delete {} to ensure that nobody can"
              + " recover your old downloads.",
          getMasterPasswordFile());
    }
    // persistent-temp will be cleaned on restart.
  }

  /** Requests a wrapper restart after a panic and exits the current JVM. */
  public void finishPanic() {
    WrapperManager.restart();
    System.exit(0);
  }

  /**
   * Indicates whether the node is awaiting a password to unlock client materials.
   *
   * @return {@code true} when either the client cache or database requires a password.
   */
  public boolean awaitingPassword() {
    if (clientCacheAwaitingPassword) return true;
    return databaseAwaitingPassword;
  }

  public boolean wantEncryptedDatabase() {
    return this.securityLevels.getPhysicalThreatLevel() != PHYSICAL_THREAT_LEVEL.LOW;
  }

  public boolean wantNoPersistentDatabase() {
    return this.securityLevels.getPhysicalThreatLevel() == PHYSICAL_THREAT_LEVEL.MAXIMUM;
  }

  public boolean hasDatabase() {
    return !clientCore.getClientLayerPersister().isKilledOrNotLoaded();
  }

  /**
   * Returns the canonical path of the currently active database file.
   *
   * @return absolute canonical path string for the node database in use.
   */
  public String getDatabasePath() {
    return clientCore.getClientLayerPersister().getWriteFilename().toString();
  }

  /**
   * Determines whether a block should be stored in the main store (deep) rather than a cache.
   *
   * <p>The decision is based on relative proximity to the target key compared with the source and
   * the set of peers the request was routed to, discounting low‑uptime peers. This approximates the
   * behavior of storing at the best available sink while avoiding premature store writes that would
   * bias Bloom filters and traffic patterns.
   *
   * @param key the key being inserted or fetched.
   * @param source the previous hop (may be {@code null} for local originators).
   * @param routedTo peers selected for onward routing of the request.
   * @return {@code true} if the node is closer to the target than the considered peers and should
   *     therefore store deeply; {@code false} otherwise.
   */
  public boolean shouldStoreDeep(Key key, PeerNode source, PeerNode[] routedTo) {
    double myLoc = getLocation();
    double target = key.toNormalizedDouble();
    double myDist = Location.distance(myLoc, target);

    // First, calculate whether we would have stored it using the old formula.
    if (LOG.isDebugEnabled()) LOG.debug("Should store for {} ?", key);
    // Don't sink store if any of the nodes we routed to, or our predecessor, is both high-uptime
    // and closer to the target than we are.
    if (isCloserAndHighUptime(source, target, myDist)) {
      if (LOG.isDebugEnabled())
        LOG.debug("Not storing because source is closer to target for {} : {}", key, source);
      return false;
    }
    for (PeerNode pn : routedTo) {
      if (isCloserAndHighUptime(pn, target, myDist)) {
        if (LOG.isDebugEnabled())
          LOG.debug(
              "Not storing because peer {} is closer to target for {} his loc {} my loc {} target"
                  + " is {}",
              pn,
              key,
              pn.getLocation(),
              myLoc,
              target);
        return false;
      }
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Should store maybe, peer {} loc = {} my loc is {} target is {} low uptime is {}",
            pn,
            pn.getLocation(),
            myLoc,
            target,
            pn.isLowUptime());
    }
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Should store returning true for {} target={} myLoc={} peers: {}",
          key,
          target,
          myLoc,
          routedTo.length);
    return true;
  }

  private boolean isCloserAndHighUptime(PeerNode pn, double target, double myDist) {
    if (pn == null || pn.isLowUptime()) return false;
    return Location.distance(pn, target) < myDist;
  }

  public boolean getWriteLocalToDatastore() {
    return writeLocalToDatastore;
  }

  @SuppressWarnings("unused")
  public boolean getUseSlashdotCache() {
    return useSlashdotCache;
  }

  // Consider removing the visibility alert after a few builds

  public void createVisibilityAlert() {
    synchronized (this) {
      if (showFriendsVisibilityAlert) return;
      showFriendsVisibilityAlert = true;
    }
    // Wait until startup completed.
    this.getTicker().queueTimedJob(config::store, 0);
    registerFriendsVisibilityAlert();
  }

  private final UserAlert visibilityAlert =
      new SimpleUserAlert(
          true,
          l10n("pleaseSetPeersVisibilityAlertTitle"),
          l10n("pleaseSetPeersVisibilityAlert"),
          l10n("pleaseSetPeersVisibilityAlert"),
          UserAlert.ERROR) {

        @Override
        public void onDismiss() {
          synchronized (Node.this) {
            showFriendsVisibilityAlert = false;
          }
          config.store();
          unregisterFriendsVisibilityAlert();
        }
      };

  private void registerFriendsVisibilityAlert() {
    if (clientCore == null || clientCore.getAlerts() == null) {
      // Wait until startup completed.
      this.getTicker().queueTimedJob(this::registerFriendsVisibilityAlert, 0);
      return;
    }
    clientCore.getAlerts().register(visibilityAlert);
  }

  private void unregisterFriendsVisibilityAlert() {
    clientCore.getAlerts().unregister(visibilityAlert);
  }

  public int getMinimumMTU() {
    int mtu;
    synchronized (this) {
      mtu = maxPacketSize;
    }
    if (ipDetector != null) {
      int detected = ipDetector.getMinimumDetectedMTU();
      if (detected < mtu) return detected;
    }
    return mtu;
  }

  public void updateMTU() {
    this.darknetCrypto.getSocket().calculateMaxPacketSize();
    OpennetManager om = opennet;
    if (om != null) {
      om.getCrypto().getSocket().calculateMaxPacketSize();
    }
  }

  private static final boolean TESTNET_ENABLED = false;

  public static boolean isTestnetEnabled() {
    return TESTNET_ENABLED;
  }

  /**
   * Creates a thread‑safe {@link MersenneTwister} seeded from the secure PRNG.
   *
   * <p>Do not use the instance field {@code random} here: this method is called while wiring the
   * random sources, before {@code this.random} is initialized. Seeding from the global {@link
   * java.security.SecureRandom} avoids a null dereference and matches the constructor contract
   * which specifies that the weak random is seeded from a secure PRNG when not provided.
   *
   * @return a synchronized PRNG suitable for simulations and randomized scheduling.
   */
  public MersenneTwister createRandom() {
    byte[] seed = new byte[16];
    NodeStarter.getGlobalSecureRandom().nextBytes(seed);
    return MersenneTwister.createSynchronized(seed);
  }

  /**
   * Enables new load management instrumentation for the specified scheduling class.
   *
   * @param realTimeFlag when {@code true}, enables for real‑time queues; otherwise bulk.
   * @return {@code true} if enabled; {@code false} if stats are not initialized yet.
   */
  public boolean enableNewLoadManagement(boolean realTimeFlag) {
    NodeStats stats = this.nodeStats;
    if (stats == null) {
      LOG.error(
          "Calling enableNewLoadManagement before Node constructor completes! FIX THIS!",
          new Exception("error"));
      return false;
    }
    return stats.enableNewLoadManagement(realTimeFlag);
  }

  /**
   * Indicates whether routed pings are enabled on this node.
   *
   * @return {@code true} when routed probes are allowed; {@code false} otherwise.
   */
  public boolean enableRoutedPing() {
    return enableRoutedPing;
  }

  public boolean updateIsUrgent() {
    OpennetManager om = getOpennet();
    if (om != null && om.getAnnouncer() != null && om.getAnnouncer().isWaitingForUpdater())
      return true;
    return peers.getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_TOO_NEW, true)
        > PeerManager.OUTDATED_MIN_TOO_NEW_DARKNET;
  }

  /**
   * Returns the per-plugin encryption key derived from the node's database key.
   *
   * <p>When the node's master database key is not available (for example, database encryption is
   * disabled or a password has not been provided), this method returns {@code null}. Callers must
   * handle a {@code null} return value and avoid constructing encryption primitives in that case.
   * When present, the returned array contains a 32-byte key derived for the given {@code
   * storeIdentifier} and must be treated as secret.
   *
   * @param storeIdentifier plugin store identifier; must not be {@code null} when a key is
   *     available.
   * @return a 32-byte derived key, or {@code null} if no database key is available.
   */
  @SuppressWarnings("java:S1168")
  public byte[] getPluginStoreKey(String storeIdentifier) {
    DatabaseKey key;
    synchronized (this) {
      key = databaseKey;
    }
    if (key != null) return key.getPluginStoreKey(storeIdentifier);
    else return null;
  }

  /**
   * Returns the plugin manager instance.
   *
   * @return plugin manager.
   */
  public PluginManager getPluginManager() {
    return pluginManager;
  }

  DatabaseKey getDatabaseKey() {
    return databaseKey;
  }

  /**
   * Returns the node diagnostics facility.
   *
   * @return diagnostics facade.
   */
  public NodeDiagnostics getNodeDiagnostics() {
    return nodeDiagnostics;
  }

  /**
   * Indicates whether diagnostics gathering is enabled.
   *
   * @return {@code true} when diagnostics are enabled.
   */
  public boolean isNodeDiagnosticsEnabled() {
    return enableNodeDiagnostics;
  }

  /**
   * Returns the aggregate node statistics collector.
   *
   * @return node statistics.
   */
  public NodeStats getNodeStats() {
    return nodeStats;
  }

  /**
   * Returns the persistent configuration entry point.
   *
   * @return persistent config instance.
   */
  public PersistentConfig getConfig() {
    return config;
  }

  /**
   * Returns the helper responsible for public‑key caching and retrieval.
   *
   * @return pubkey helper.
   */
  public NodeGetPubkey getGetPubKey() {
    return getPubKey;
  }

  /**
   * Returns the IP detector managing local/external address discovery.
   *
   * @return IP detector.
   */
  public NodeIPDetector getIpDetector() {
    return ipDetector;
  }

  /**
   * Indicates whether probabilistic HTL decrementing is disabled.
   *
   * @return {@code true} when disabled.
   */
  public boolean isDisableProbabilisticHTLs() {
    return disableProbabilisticHTLs;
  }

  /**
   * Returns the request tracker coordinating in‑flight operations.
   *
   * @return request tracker.
   */
  public RequestTracker getTracker() {
    return tracker;
  }

  /**
   * Returns the peer manager overseeing all connections.
   *
   * @return peer manager.
   */
  public PeerManager getPeers() {
    return peers;
  }

  /**
   * Returns the node's strong random source.
   *
   * @return strong random source.
   */
  public RandomSource getRandom() {
    return random;
  }

  /**
   * Returns the JCA {@link SecureRandom} instance used for crypto operations.
   *
   * @return secure random instance.
   */
  public SecureRandom getSecureRandom() {
    return secureRandom;
  }

  /**
   * Returns a fast, weak PRNG for non‑cryptographic tasks.
   *
   * @return weak PRNG.
   */
  public Random getFastWeakRandom() {
    return fastWeakRandom;
  }

  /**
   * Returns the darknet crypto/session manager.
   *
   * @return darknet crypto manager.
   */
  public NodeCrypto getDarknetCrypto() {
    return darknetCrypto;
  }

  /**
   * Returns the primary executor used for background work.
   *
   * @return executor instance.
   */
  public PriorityAwareExecutor getExecutor() {
    return executor;
  }

  /**
   * Returns the transport packet sender.
   *
   * @return packet sender.
   */
  public PacketSender getPacketSender() {
    return ps;
  }

  /**
   * Returns the DNS requester used by the node.
   *
   * @return DNS requester.
   */
  public DNSRequester getDNSRequester() {
    return dnsr;
  }

  /**
   * Returns the node dispatcher responsible for message handling.
   *
   * @return dispatcher.
   */
  public NodeDispatcher getDispatcher() {
    return dispatcher;
  }

  /**
   * Returns the uptime estimator for the running node.
   *
   * @return uptime estimator.
   */
  public UptimeEstimator getUptimeEstimator() {
    return uptime;
  }

  /**
   * Returns the outbound bandwidth throttle.
   *
   * @return output throttle.
   */
  public OutputThrottle getOutputThrottle() {
    return outputThrottle;
  }

  /**
   * Indicates whether local traffic is throttled.
   *
   * @return {@code true} when local traffic throttling is enabled.
   */
  public boolean isThrottleLocalData() {
    return throttleLocalData;
  }

  /**
   * Indicates whether ARKs are enabled.
   *
   * @return {@code true} when ARKs are enabled.
   */
  public boolean isEnableARKs() {
    return enableARKs;
  }

  /**
   * Indicates whether per‑node failure tables are enabled.
   *
   * @return {@code true} when enabled.
   */
  public boolean isEnablePerNodeFailureTables() {
    return enablePerNodeFailureTables;
  }

  /**
   * Indicates whether ULPR data propagation is enabled.
   *
   * @return {@code true} when enabled.
   */
  public boolean isEnableULPRDataPropagation() {
    return enableULPRDataPropagation;
  }

  /**
   * Indicates whether swapping is enabled.
   *
   * @return {@code true} when enabled.
   */
  public boolean isEnableSwapping() {
    return enableSwapping;
  }

  /**
   * Indicates whether swap queueing is enabled.
   *
   * @return {@code true} when enabled.
   */
  public boolean isEnableSwapQueueing() {
    return enableSwapQueueing;
  }

  /**
   * Indicates whether packet coalescing is enabled.
   *
   * @return {@code true} when enabled.
   */
  public boolean isEnablePacketCoalescing() {
    return enablePacketCoalescing;
  }

  /**
   * Returns the IO statistics collector for transport metrics and diagnostics.
   *
   * @return IO stats collector instance.
   */
  public IOStatisticCollector getCollector() {
    return collector;
  }

  /**
   * Returns the node's client core, exposing high‑level client APIs and UI hooks.
   *
   * @return client core instance.
   */
  public NodeClientCore getClientCore() {
    return clientCore;
  }

  public FailureTable getFailureTable() {
    return failureTable;
  }

  public int getLastVersion() {
    return lastVersion;
  }

  public SecurityLevels getSecurityLevels() {
    return securityLevels;
  }

  /**
   * Returns the localhost address as a {@link FreenetInetAddress} helper.
   *
   * @return localhost freenet address wrapper.
   */
  public FreenetInetAddress getFreenetLocalhostAddress() {
    return fLocalhostAddress;
  }

  /**
   * Returns the {@link FetchContext} used for ARK retrievals.
   *
   * @return the ARK fetch context.
   */
  public FetchContext getArkFetcherContext() {
    return arkFetcherContext;
  }

  /**
   * Returns the boot identifier of the previous clean start (or -1 when unknown).
   *
   * @return last recorded boot identifier, or -1 if unavailable.
   */
  public long getLastBootId() {
    return lastBootID;
  }

  /**
   * Returns the randomly generated boot identifier for this process start.
   *
   * @return boot identifier value.
   */
  public long getBootId() {
    return bootID;
  }

  public long getStartupTime() {
    return startupTime;
  }

  public RequestClient getNonPersistentClientBulk() {
    return nonPersistentClientBulk;
  }

  public RequestClient getNonPersistentClientRT() {
    return nonPersistentClientRT;
  }

  public PubkeyStore getOldPK() {
    return oldPK.get();
  }

  public PubkeyStore getOldPKCache() {
    return oldPKCache.get();
  }

  public PubkeyStore getOldPKClientCache() {
    return oldPKClientCache.get();
  }
}

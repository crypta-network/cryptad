package network.crypta.node.subsystem;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.NodeNeedRestartException;
import network.crypta.crypt.DSAPublicKey;
import network.crypta.crypt.MasterSecret;
import network.crypta.fs.AppDirs;
import network.crypta.fs.AppEnv;
import network.crypta.fs.ServiceDirs;
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
import network.crypta.l10n.NodeL10n;
import network.crypta.node.DatabaseKey;
import network.crypta.node.MasterKeys;
import network.crypta.node.MasterKeysFileSizeException;
import network.crypta.node.MasterKeysWrongPasswordException;
import network.crypta.node.Node;
import network.crypta.node.NodeGetPubkey;
import network.crypta.node.NodeInitException;
import network.crypta.node.NodeStats;
import network.crypta.node.NodeStoreStatsProvider;
import network.crypta.node.SecurityLevels.PHYSICAL_THREAT_LEVEL;
import network.crypta.node.SemiOrderedShutdownHook;
import network.crypta.node.stats.DataStoreInstanceType;
import network.crypta.node.stats.DataStoreKeyType;
import network.crypta.node.stats.DataStoreStats;
import network.crypta.node.stats.DataStoreType;
import network.crypta.node.stats.NotAvailNodeStoreStats;
import network.crypta.node.stats.StoreCallbackStats;
import network.crypta.runtime.alerts.UserAlert;
import network.crypta.runtime.alerts.UserAlertManagerStoreAlertSink;
import network.crypta.runtime.endpoints.http.security.PasswordFormPageRenderer;
import network.crypta.runtime.endpoints.http.security.PasswordPromptOptions;
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
import network.crypta.store.alerts.StoreAlertSink;
import network.crypta.store.caching.CachingFreenetStore;
import network.crypta.store.caching.CachingFreenetStoreTracker;
import network.crypta.store.saltedhash.ResizablePersistentIntBuffer;
import network.crypta.store.saltedhash.SaltedHashFreenetStore;
import network.crypta.store.saltedhash.SaltedHashStoreDependencies;
import network.crypta.store.saltedhash.SaltedHashStoreLocation;
import network.crypta.store.saltedhash.SaltedHashStoreParams;
import network.crypta.store.saltedhash.SaltedHashStoreSizing;
import network.crypta.support.HTMLNode;
import network.crypta.support.io.DatastoreUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static network.crypta.support.io.DatastoreUtil.ONE_GIB;

/**
 * Coordinates node-local storage backends, cache tiers, and migration between store generations.
 *
 * <p>This subsystem centralizes initialization and runtime control for persistent datastores
 * (CHK/SSK/pubkey), in-memory or persistent client caches, and slashdot/ULPR cache tiers. It also
 * owns sizing calculations, backend-type switches, and delayed migration paths used when encrypted
 * stores cannot be opened until credentials are supplied. Public methods expose configuration and
 * fetch/store operations while delegating lower-level persistence details to store callback types.
 *
 * <p>The class is stateful and long-lived. Most mutable configuration is synchronized on the owning
 * {@link Node} instance to keep transitions coherent with other subsystems. Callers should treat
 * this API as a node-runtime service rather than as a stateless utility.
 *
 * <ul>
 *   <li><b>Primary responsibility:</b> own local store/caches lifecycle and capacity policy.
 *   <li><b>Secondary responsibility:</b> bridge password-gated startup with safe migration.
 * </ul>
 */
public final class NodeStorageSubsystem {
  private static final Logger LOG = LoggerFactory.getLogger(NodeStorageSubsystem.class);
  private static final String SECURITYLEVELS_ENTER_PASSWORD_KEY = "SecurityLevels.enterPassword";
  private static final String STORE_KIND_PUBKEY = "PUBKEY";
  private static final long PURGE_INTERVAL = java.util.concurrent.TimeUnit.SECONDS.toMillis(60);

  /**
   * Absolute minimum datastore size accepted by configuration, in bytes.
   *
   * <p>Values below this threshold are rejected for persistent backends to avoid pathological store
   * sizing and unstable key-capacity partitioning.
   */
  public static final long MIN_STORE_SIZE = 32L * 1024 * 1024;

  /**
   * Default total datastore size in bytes used when no explicit value is configured.
   *
   * <p>This baseline is guaranteed to satisfy {@link #MIN_STORE_SIZE}.
   */
  public static final long DEFAULT_STORE_SIZE = 32L * 1024 * 1024;

  /**
   * Minimum client-cache size in bytes accepted by configuration.
   *
   * <p>A value of zero allows deployments that intentionally disable client-cache persistence.
   */
  public static final long MIN_CLIENT_CACHE_SIZE = 0;

  /**
   * Default client-cache size in bytes used when unspecified.
   *
   * <p>This value is selected to remain valid against {@link #MIN_CLIENT_CACHE_SIZE}.
   */
  public static final long DEFAULT_CLIENT_CACHE_SIZE = 10L * 1024 * 1024;

  /**
   * Minimum slashdot/ULPR cache size in bytes accepted by configuration.
   *
   * <p>A zero-size configuration is allowed when slashdot caches should be effectively disabled.
   */
  public static final long MIN_SLASHDOT_CACHE_SIZE = 0;

  /**
   * Default slashdot/ULPR cache size in bytes used when unspecified.
   *
   * <p>This default remains valid against {@link #MIN_SLASHDOT_CACHE_SIZE}.
   */
  public static final long DEFAULT_SLASHDOT_CACHE_SIZE = 10L * 1024 * 1024;

  /**
   * Default persistence time (milliseconds) for the salted-hash store's slot filter backing
   * buffers.
   *
   * <p>This mirrors {@link ResizablePersistentIntBuffer#DEFAULT_PERSISTENCE_TIME} but is exposed
   * here so callers configuring storage do not need to depend on the low-level buffer
   * implementation.
   */
  public static final int DEFAULT_SALT_HASH_SLOT_FILTER_PERSISTENCE_TIME =
      ResizablePersistentIntBuffer.DEFAULT_PERSISTENCE_TIME;

  /**
   * Estimated bytes consumed per logical key across primary data and metadata structures.
   *
   * <p>This heuristic drives key-count derivation from configured byte capacities. It is not a
   * precise on-disk accounting number but a stable planning estimate used for store partitioning.
   */
  public static final int SIZE_PER_KEY =
      network.crypta.keys.CHKBlock.DATA_LENGTH
          + network.crypta.keys.CHKBlock.TOTAL_HEADERS_LENGTH
          + network.crypta.crypt.DSAPublicKey.PADDED_SIZE
          + network.crypta.keys.SSKBlock.DATA_LENGTH
          + network.crypta.keys.SSKBlock.TOTAL_HEADERS_LENGTH;

  private final Node node;
  private final NodeGetPubkey getPubKey;

  private final AtomicReference<CHKStore> oldCHK = new AtomicReference<>();
  private final AtomicReference<PubkeyStore> oldPK = new AtomicReference<>();
  private final AtomicReference<SSKStore> oldSSK = new AtomicReference<>();
  private final AtomicReference<CHKStore> oldCHKCache = new AtomicReference<>();
  private final AtomicReference<PubkeyStore> oldPKCache = new AtomicReference<>();
  private final AtomicReference<SSKStore> oldSSKCache = new AtomicReference<>();
  private final AtomicReference<CHKStore> oldCHKClientCache = new AtomicReference<>();
  private final AtomicReference<PubkeyStore> oldPKClientCache = new AtomicReference<>();
  private final AtomicReference<SSKStore> oldSSKClientCache = new AtomicReference<>();

  /** File to write crypto master keys into, possibly passworded. */
  private File masterKeysFile;

  /** Encryption key for client.dat.crypt or client.dat.bak.crypt */
  private DatabaseKey databaseKey;

  /**
   * Encryption keys, if loaded, null if waiting for a password. We must be able to write them, and
   * they're all used elsewhere anyway, so there's no point trying not to keep them in memory.
   */
  private MasterKeys keys;

  /** Datastore directory. */
  private network.crypta.node.ProgramDirectory storeDir;

  /** Datastore properties */
  private String storeType;

  private boolean storeUseSlotFilters;
  private volatile boolean storeSaltHashResizeOnStart;
  private volatile int storeSaltHashSlotFilterPersistenceTime;

  /** The maximum number of keys stored in each of the datastores, cache and store combined. */
  private volatile long maxTotalKeys;

  private volatile long maxCacheKeys;
  private volatile long maxStoreKeys;

  /** The maximum size of the datastore. Kept to avoid rounding turning 5G into 5,368,698,672 */
  private volatile long maxTotalDatastoreSize;

  /**
   * If true, store shrinks occur immediately even if they are over 10% of the store size. If false,
   * we just set the storeSize and do an offline shrink on the next startup. Online shrinks do not
   * preserve the most recently used data, so are not recommended.
   */
  private boolean storeForceBigShrinks;

  /** The CHK datastore. */
  private CHKStore chkDatastore;

  /** The SSK datastore. */
  private SSKStore sskDatastore;

  /** The store of DSAPublicKeys (by hash). */
  private PubkeyStore pubKeyDatastore;

  /** Client cache store type */
  private String clientCacheType;

  /** Client cache could not be opened, so is a RAMFS until the correct password is entered */
  private volatile boolean clientCacheAwaitingPassword;

  private volatile boolean databaseAwaitingPassword;

  /** Client caches maximum cached keys for each type */
  private volatile long maxClientCacheKeys;

  /** Maximum size of the client cache. Kept to avoid rounding problems. */
  private volatile long maxTotalClientCacheSize;

  /** The CHK datacache. */
  private CHKStore chkDatacache;

  /** The SSK datacache. */
  private SSKStore sskDatacache;

  /** The pubkey datacache. */
  private PubkeyStore pubKeyDatacache;

  /** The CHK client cache. */
  private CHKStore chkClientcache;

  /** The SSK client cache. */
  private SSKStore sskClientcache;

  /** The pubkey client cache. */
  private PubkeyStore pubKeyClientcache;

  /** Slashdot cache sizing. */
  private volatile long maxSlashdotCacheSize;

  private volatile int maxSlashdotCacheKeys;

  private CHKStore chkSlashdotcache;
  private SlashdotStore<CHKBlock> chkSlashdotcacheStore;
  private SSKStore sskSlashdotcache;
  private SlashdotStore<SSKBlock> sskSlashdotcacheStore;
  private PubkeyStore pubKeySlashdotcache;
  private SlashdotStore<DSAPublicKey> pubKeySlashdotcacheStore;

  private volatile boolean useSlashdotCache;
  private volatile boolean writeLocalToDatastore;

  private volatile long cachingFreenetStoreMaxSize;
  private volatile long cachingFreenetStorePeriod;
  private CachingFreenetStoreTracker cachingFreenetStoreTracker;

  private volatile boolean storePreallocate;

  /**
   * Creates the storage subsystem facade for a running node instance.
   *
   * <p>The constructor captures the owning node reference and initializes the pubkey helper used by
   * SSK store operations. Heavy store initialization is deferred to explicit init methods.
   *
   * @param node owning node used for services, statistics, and lifecycle coordination
   */
  public NodeStorageSubsystem(Node node) {
    this.node = node;
    this.getPubKey = new NodeGetPubkey(node);
  }

  /**
   * Background migrator that copies data from a previously active store into the new one.
   *
   * <p>Used when delayed initialization is enabled or when client‑cache/password state changes.
   * Migration runs on a background thread and logs progress; failures are logged and do not abort
   * node startup.
   */
  public final class MigrateOldStoreData implements Runnable {

    private final boolean clientCache;

    /**
     * Creates a migration task for either client cache stores or main datastore stores.
     *
     * @param clientCache {@code true} to migrate client-cache stores; {@code false} for main stores
     */
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
        synchronized (node) {
          old = oldCHKClientCache.get();
          oldCHKClientCache.set(null);
        }
        closeOldStore(old);
        migrateOldStore(oldPKClientCache.get(), pubKeyClientcache, true);
        synchronized (node) {
          old = oldPKClientCache.get();
          oldPKClientCache.set(null);
        }
        closeOldStore(old);
        migrateOldStore(oldSSKClientCache.get(), sskClientcache, true);
        synchronized (node) {
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

  /**
   * Creates a runnable that migrates data from previously active stores.
   *
   * <p>The returned runnable captures current old/new store references and can be executed on a
   * background executor once replacement stores are ready.
   *
   * @param clientCache {@code true} to migrate client cache stores, {@code false} for datastores
   * @return runnable migration task bound to the current store references
   */
  public Runnable createMigrateOldStoreData(boolean clientCache) {
    return new MigrateOldStoreData(clientCache);
  }

  /**
   * Closes and securely destroys an old salted‑hash store used during migration.
   *
   * <p>If the callback is not backed by a salted-hash store, this method performs no action.
   *
   * @param <T> storable block type handled by the store callback
   * @param old callback whose underlying store will be closed and destroyed when applicable.
   */
  public <T extends StorableBlock> void closeOldStore(StoreCallback<T> old) {
    FreenetStore<T> store = old.getStore();
    if (store instanceof SaltedHashFreenetStore<T> saltstore) {
      saltstore.close();
      saltstore.destruct();
    }
  }

  /**
   * Registers the password-required alert with the node alert manager.
   *
   * <p>This alert remains active while encrypted stores or database components await a password.
   */
  public void createPasswordUserAlert() {
    node.services().clientCore().getAlerts().register(masterPasswordUserAlert);
  }

  /**
   * Performs deferred database initialization after a decryption key becomes available.
   *
   * @param databaseKey database key used to unlock an encrypted database state
   */
  public void lateSetupDatabase(DatabaseKey databaseKey) {
    if (node.services().clientCore().loadedDatabase()) return;
    LOG.info("Starting late database initialisation");

    if (!node.services().clientCore().lateInitDatabase(databaseKey)) failLateInitDatabase();
  }

  /**
   * Deletes and invalidates persisted master key material.
   *
   * @throws IOException if the underlying key file cannot be securely removed
   */
  public void killMasterKeysFile() throws IOException {
    MasterKeys.killMasterKeys(masterKeysFile);
  }

  /**
   * Marks client-cache initialization as blocked on password entry and shows the password alert.
   *
   * <p>This flag is checked by setup paths that need encrypted client-cache material before they
   * can switch from temporary fallback stores.
   */
  public void setClientCacheAwaitingPassword() {
    createPasswordUserAlert();
    synchronized (node) {
      clientCacheAwaitingPassword = true;
    }
  }

  /**
   * Marks database initialization as blocked on password entry.
   *
   * <p>Unlike {@link #setClientCacheAwaitingPassword()}, this method only sets state and does not
   * register an additional alert because the same password prompt flow is shared.
   */
  public void setDatabaseAwaitingPassword() {
    synchronized (node) {
      databaseAwaitingPassword = true;
    }
  }

  private void failLateInitDatabase() {
    LOG.error("Failed late initialisation of database, closing...");
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
        public network.crypta.runtime.alerts.feed.UserAlertFeedEvent getFeedEvent() {
          return new network.crypta.runtime.alerts.feed.BasicUserAlertFeedEvent(
              getTitle(), getShortText(), getText(), getPriorityClass(), getUpdatedTime());
        }

        @Override
        public HTMLNode getHTMLText() {
          HTMLNode content = new HTMLNode("div");
          PasswordFormPageRenderer.generate(
              new PasswordPromptOptions(false, false, false, false, null, null),
              node.services().clientCore().getEndpoints().getToadletContainer(),
              content);
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
          synchronized (node) {
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

  /**
   * Returns whether large store shrinks are forced immediately instead of deferred.
   *
   * @return {@code true} when immediate large shrinking is enabled
   */
  public boolean isStoreForceBigShrinks() {
    synchronized (node) {
      return storeForceBigShrinks;
    }
  }

  /**
   * Sets whether large store shrinks are forced immediately.
   *
   * @param value {@code true} to force immediate large shrinks
   */
  public void setStoreForceBigShrinks(boolean value) {
    synchronized (node) {
      storeForceBigShrinks = value;
    }
  }

  /**
   * Returns whether salted-hash slot filters are enabled for datastore stores.
   *
   * @return {@code true} when slot filters are enabled
   */
  public boolean isStoreUseSlotFilters() {
    synchronized (node) {
      return storeUseSlotFilters;
    }
  }

  /**
   * Updates slot-filter configuration and signals that restart is required.
   *
   * @param value desired slot-filter enablement state
   * @throws NodeNeedRestartException always thrown after an update because the live switch is
   *     unsupported
   */
  public void setStoreUseSlotFilters(boolean value) throws NodeNeedRestartException {
    synchronized (node) {
      storeUseSlotFilters = value;
    }
    throw new NodeNeedRestartException("Need to restart to change storeUseSlotFilters");
  }

  /**
   * Initializes slot-filter configuration without triggering restart handling.
   *
   * @param value initial slot-filter enablement value
   */
  public void initializeStoreUseSlotFilters(boolean value) {
    synchronized (node) {
      storeUseSlotFilters = value;
    }
  }

  /**
   * Returns configured slot-filter persistence time for salted-hash buffers.
   *
   * @return persistence time value in milliseconds, or {@code -1} for disabled persistence
   */
  public int getStoreSaltHashSlotFilterPersistenceTime() {
    return storeSaltHashSlotFilterPersistenceTime;
  }

  /**
   * Sets slot-filter persistence time and applies it to persistent buffer defaults.
   *
   * @param value persistence time in milliseconds, or {@code -1} to disable periodic persistence
   * @throws InvalidConfigValueException if the supplied value is less than {@code -1}
   */
  public void setStoreSaltHashSlotFilterPersistenceTime(int value)
      throws InvalidConfigValueException {
    if (value >= -1) {
      ResizablePersistentIntBuffer.setPersistenceTime(value);
      storeSaltHashSlotFilterPersistenceTime = value;
    } else {
      throw new InvalidConfigValueException(l10n("slotFilterPersistenceTimeError"));
    }
  }

  /**
   * Initializes slot-filter persistence time at startup.
   *
   * @param value startup persistence time value to apply
   */
  public void initializeStoreSaltHashSlotFilterPersistenceTime(int value) {
    ResizablePersistentIntBuffer.setPersistenceTime(value);
    storeSaltHashSlotFilterPersistenceTime = value;
  }

  /**
   * Returns whether salted-hash stores may resize during startup.
   *
   * @return {@code true} when startup resizing is enabled
   */
  public boolean isStoreSaltHashResizeOnStart() {
    return storeSaltHashResizeOnStart;
  }

  /**
   * Sets whether salted-hash stores may resize during startup.
   *
   * @param value desired startup-resize behavior
   */
  public void setStoreSaltHashResizeOnStart(boolean value) {
    storeSaltHashResizeOnStart = value;
  }

  /**
   * Initializes startup resize behavior for salted-hash stores.
   *
   * @param value initial startup-resize behavior
   */
  public void initializeStoreSaltHashResizeOnStart(boolean value) {
    storeSaltHashResizeOnStart = value;
  }

  /**
   * Returns whether salted-hash stores should preallocate backing files.
   *
   * @return {@code true} when preallocation is enabled
   */
  public boolean isStorePreallocate() {
    return storePreallocate;
  }

  /**
   * Sets preallocation behavior for currently active salted-hash stores.
   *
   * @param value desired preallocation setting
   */
  public void setStorePreallocate(boolean value) {
    storePreallocate = value;
    if (Node.TYPE_SALT_HASH.equals(storeType)) {
      setPreallocate(chkDatastore, value);
      setPreallocate(chkDatacache, value);
      setPreallocate(pubKeyDatastore, value);
      setPreallocate(pubKeyDatacache, value);
      setPreallocate(sskDatastore, value);
      setPreallocate(sskDatacache, value);
    }
  }

  private void setPreallocate(StoreCallback<?> datastore, boolean value) {
    if (datastore == null) {
      return;
    }

    // Avoid races during startup/config init: the callback may exist while no store is bound yet,
    // and wrappers can sit in front of the salted-hash store.
    FreenetStore<?> store = datastore.getStore();
    if (store == null) {
      return;
    }

    FreenetStore<?> underlyingStore = store.getUnderlyingStore();
    if (underlyingStore instanceof SaltedHashFreenetStore<?> freenetStore) {
      freenetStore.setPreallocate(value);
    }
  }

  /**
   * Returns configured total datastore size in bytes.
   *
   * @return total datastore size in bytes
   */
  public long getDatastoreSize() {
    return maxTotalDatastoreSize;
  }

  /**
   * Returns configured total key capacity across store and cache partitions.
   *
   * @return maximum total key count
   */
  public long getMaxTotalKeys() {
    return maxTotalKeys;
  }

  /**
   * Resolves the default base directory for store data depending on service mode.
   *
   * @return default base directory for store data.
   */
  public Path defaultStoreBaseDir() {
    AppEnv appEnv = new AppEnv();
    if (appEnv.isServiceMode()) {
      return new ServiceDirs().resolve().dataDir();
    }
    return new AppDirs().resolve().dataDir();
  }

  /**
   * Initializes datastore sizing fields during the startup configuration load.
   *
   * @param storeSize configured datastore size in bytes
   * @throws NodeInitException if the size is invalid for the current store type
   */
  public void initializeDatastoreSize(long storeSize) throws NodeInitException {
    maxTotalDatastoreSize = storeSize;
    if (maxTotalDatastoreSize < MIN_STORE_SIZE
        && !Node.TYPE_SALT_HASH.equals(storeType)
        && !"ram".equals(storeType)) {
      throw new NodeInitException(
          NodeInitException.EXIT_INVALID_STORE_SIZE, "Store size too small");
    }
    maxTotalKeys = maxTotalDatastoreSize / SIZE_PER_KEY;
    maxStoreKeys = maxTotalKeys / 2;
    maxCacheKeys = maxTotalKeys - maxStoreKeys;
  }

  /**
   * Resizes persistent datastore and cache partitions.
   *
   * @param storeSize requested new total datastore size in bytes
   * @throws InvalidConfigValueException if size is out of configured bounds
   */
  public void resizeDatastore(long storeSize) throws InvalidConfigValueException {
    long maxDatastoreSize;
    if (storeSize < MIN_STORE_SIZE) {
      throw new InvalidConfigValueException(l10n("invalidMinStoreSize"));
    }
    if (storeSize > (maxDatastoreSize = DatastoreUtil.maxDatastoreSize())) {
      throw new InvalidConfigValueException(
          l10nInvalidMaxStoreSize(Long.toString(maxDatastoreSize / ONE_GIB)));
    }

    long newMaxStoreKeys = storeSize / SIZE_PER_KEY;
    if (newMaxStoreKeys == maxTotalKeys) return;
    // Update each datastore
    synchronized (node) {
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
    NodeStats stats = node.network().stats();
    stats.avgStoreCHKLocation.changeMaxReports((int) maxStoreKeys);
    stats.avgCacheCHKLocation.changeMaxReports((int) maxCacheKeys);
    stats.avgSlashdotCacheCHKLocation.changeMaxReports((int) maxCacheKeys);
    stats.avgClientCacheCHKLocation.changeMaxReports((int) maxCacheKeys);

    stats.avgStoreSSKLocation.changeMaxReports((int) maxStoreKeys);
    stats.avgCacheSSKLocation.changeMaxReports((int) maxCacheKeys);
    stats.avgSlashdotCacheSSKLocation.changeMaxReports((int) maxCacheKeys);
    stats.avgClientCacheSSKLocation.changeMaxReports((int) maxCacheKeys);
  }

  /**
   * Returns configured total client-cache size in bytes.
   *
   * @return total client-cache size in bytes
   */
  public long getClientCacheSize() {
    return maxTotalClientCacheSize;
  }

  /**
   * Initializes client-cache sizing fields during the startup configuration load.
   *
   * @param storeSize configured client-cache size in bytes
   * @throws NodeInitException if the configured size is below the minimum allowed size
   */
  public void initializeClientCacheSize(long storeSize) throws NodeInitException {
    maxTotalClientCacheSize = storeSize;
    if (maxTotalClientCacheSize < MIN_CLIENT_CACHE_SIZE) {
      throw new NodeInitException(
          NodeInitException.EXIT_INVALID_STORE_SIZE, "Client cache size too small");
    }
    maxClientCacheKeys = maxTotalClientCacheSize / SIZE_PER_KEY;
  }

  /**
   * Resizes the client cache capacity.
   *
   * @param storeSize requested new client-cache size in bytes
   * @throws InvalidConfigValueException if size is below the allowed minimum
   */
  public void resizeClientCache(long storeSize) throws InvalidConfigValueException {
    if (storeSize < MIN_CLIENT_CACHE_SIZE)
      throw new InvalidConfigValueException(l10n("invalidStoreSize"));
    long newMaxStoreKeys = storeSize / SIZE_PER_KEY;
    if (newMaxStoreKeys == maxClientCacheKeys) return;
    // Update each datastore
    synchronized (node) {
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

  /**
   * Returns a configured slashdot-cache size in bytes.
   *
   * @return slashdot-cache size in bytes
   */
  public long getSlashdotCacheSize() {
    return maxSlashdotCacheSize;
  }

  /**
   * Initializes slashdot-cache sizing fields during startup.
   *
   * @param storeSize configured slashdot-cache size in bytes
   * @throws NodeInitException if the configured size is below the minimum allowed size
   */
  public void initializeSlashdotCacheSize(long storeSize) throws NodeInitException {
    maxSlashdotCacheSize = storeSize;
    if (maxSlashdotCacheSize < MIN_SLASHDOT_CACHE_SIZE) {
      throw new NodeInitException(
          NodeInitException.EXIT_INVALID_STORE_SIZE, "Slashdot cache size too small");
    }
    maxSlashdotCacheKeys = (int) Math.min(maxSlashdotCacheSize / SIZE_PER_KEY, Integer.MAX_VALUE);
  }

  /**
   * Resizes slashdot cache capacity for CHK, SSK, and pubkey stores.
   *
   * @param storeSize requested new slashdot-cache size in bytes
   * @throws InvalidConfigValueException if size is below the allowed minimum
   */
  public void resizeSlashdotCache(long storeSize) throws InvalidConfigValueException {
    if (storeSize < MIN_SLASHDOT_CACHE_SIZE)
      throw new InvalidConfigValueException(l10n("invalidStoreSize"));
    int newMaxStoreKeys = (int) Math.min(storeSize / SIZE_PER_KEY, Integer.MAX_VALUE);
    if (newMaxStoreKeys == maxSlashdotCacheKeys) return;
    // Update each datastore
    synchronized (node) {
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

  /**
   * Returns whether slashdot caches are considered during store/fetch flows.
   *
   * @return {@code true} when slashdot cache usage is enabled
   */
  public boolean isUseSlashdotCache() {
    return useSlashdotCache;
  }

  /**
   * Sets whether slashdot caches are enabled.
   *
   * @param value desired slashdot-cache usage flag
   */
  public void setUseSlashdotCache(boolean value) {
    useSlashdotCache = value;
  }

  /**
   * Returns whether locally obtained blocks may be promoted to datastore.
   *
   * @return {@code true} when local writes to datastore are allowed
   */
  public boolean isWriteLocalToDatastore() {
    return writeLocalToDatastore;
  }

  /**
   * Sets whether locally obtained blocks may be promoted to datastore.
   *
   * @param value desired local-write-to-datastore behavior
   */
  public void setWriteLocalToDatastore(boolean value) {
    writeLocalToDatastore = value;
  }

  /**
   * Returns the CHK datacache callback.
   *
   * @return CHK datacache callback
   */
  public CHKStore getChkDatacache() {
    return chkDatacache;
  }

  /**
   * Returns the CHK datastore callback.
   *
   * @return CHK datastore callback
   */
  public CHKStore getChkDatastore() {
    return chkDatastore;
  }

  /**
   * Returns the SSK datacache callback.
   *
   * @return SSK datacache callback
   */
  public SSKStore getSskDatacache() {
    return sskDatacache;
  }

  /**
   * Returns the SSK datastore callback.
   *
   * @return SSK datastore callback
   */
  public SSKStore getSskDatastore() {
    return sskDatastore;
  }

  /**
   * Returns the CHK slashdot cache callback.
   *
   * @return CHK slashdot cache callback
   */
  public CHKStore getChkSlashdotCache() {
    return chkSlashdotcache;
  }

  /**
   * Returns the CHK client cache callback.
   *
   * @return CHK client cache callback
   */
  public CHKStore getChkClientCache() {
    return chkClientcache;
  }

  /**
   * Returns the SSK slashdot cache callback.
   *
   * @return SSK slashdot cache callback
   */
  public SSKStore getSskSlashdotCache() {
    return sskSlashdotcache;
  }

  /**
   * Returns the SSK client cache callback.
   *
   * @return SSK client cache callback
   */
  public SSKStore getSskClientCache() {
    return sskClientcache;
  }

  /**
   * Returns all statistics info for the data store stats table.
   *
   * <p>The map always contains entries for CHK, SSK, and pubkey stores across STORE, CACHE,
   * SLASHDOT, and CLIENT instances, in deterministic insertion order suitable for UI rendering.
   *
   * @return map that has an entry for each data store instance type and corresponding stats
   */
  public java.util.Map<DataStoreInstanceType, DataStoreStats> getDataStoreStats() {
    java.util.Map<DataStoreInstanceType, DataStoreStats> map = new java.util.LinkedHashMap<>();
    NodeStoreStatsProvider storeStatsProvider = new NodeStoreStatsProvider(node.network().stats());

    map.put(
        new DataStoreInstanceType(DataStoreKeyType.CHK, DataStoreType.STORE),
        new StoreCallbackStats(chkDatastore, storeStatsProvider.chkStoreStats()));
    map.put(
        new DataStoreInstanceType(DataStoreKeyType.CHK, DataStoreType.CACHE),
        new StoreCallbackStats(chkDatacache, storeStatsProvider.chkCacheStats()));
    map.put(
        new DataStoreInstanceType(DataStoreKeyType.CHK, DataStoreType.SLASHDOT),
        new StoreCallbackStats(chkSlashdotcache, storeStatsProvider.chkSlashDotCacheStats()));
    map.put(
        new DataStoreInstanceType(DataStoreKeyType.CHK, DataStoreType.CLIENT),
        new StoreCallbackStats(chkClientcache, storeStatsProvider.chkClientCacheStats()));

    map.put(
        new DataStoreInstanceType(DataStoreKeyType.SSK, DataStoreType.STORE),
        new StoreCallbackStats(sskDatastore, storeStatsProvider.sskStoreStats()));
    map.put(
        new DataStoreInstanceType(DataStoreKeyType.SSK, DataStoreType.CACHE),
        new StoreCallbackStats(sskDatacache, storeStatsProvider.sskCacheStats()));
    map.put(
        new DataStoreInstanceType(DataStoreKeyType.SSK, DataStoreType.SLASHDOT),
        new StoreCallbackStats(sskSlashdotcache, storeStatsProvider.sskSlashDotCacheStats()));
    map.put(
        new DataStoreInstanceType(DataStoreKeyType.SSK, DataStoreType.CLIENT),
        new StoreCallbackStats(sskClientcache, storeStatsProvider.sskClientCacheStats()));

    map.put(
        new DataStoreInstanceType(DataStoreKeyType.PUB_KEY, DataStoreType.STORE),
        new StoreCallbackStats(pubKeyDatastore, new NotAvailNodeStoreStats()));
    map.put(
        new DataStoreInstanceType(DataStoreKeyType.PUB_KEY, DataStoreType.CACHE),
        new StoreCallbackStats(pubKeyDatacache, new NotAvailNodeStoreStats()));
    map.put(
        new DataStoreInstanceType(DataStoreKeyType.PUB_KEY, DataStoreType.SLASHDOT),
        new StoreCallbackStats(pubKeySlashdotcache, new NotAvailNodeStoreStats()));
    map.put(
        new DataStoreInstanceType(DataStoreKeyType.PUB_KEY, DataStoreType.CLIENT),
        new StoreCallbackStats(pubKeyClientcache, new NotAvailNodeStoreStats()));

    return map;
  }

  /**
   * Returns whether the requested key is present in local stores or caches.
   *
   * @param key key to check.
   * @param canReadClientCache whether to consult the client cache.
   * @param forULPR true when this check is for ULPR routing decisions.
   * @return {@code true} if the key is available locally; otherwise {@code false}.
   */
  public boolean hasKey(Key key, boolean canReadClientCache, boolean forULPR) {
    if (key instanceof NodeCHK hK) {
      return fetch(hK, true, canReadClientCache, false, false, forULPR, null) != null;
    }
    return fetch((NodeSSK) key, true, canReadClientCache, false, false, forULPR, null) != null;
  }

  private long timeLastDumpedHits;

  /**
   * Logs aggregate hit/miss counters for core store tiers.
   *
   * <p>Logging is rate-limited to once every five seconds to reduce log noise under high request
   * volumes.
   */
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

  /**
   * Stores a CHK block in cache paths only, without deep store promotion.
   *
   * @param block CHK block to store
   * @param canWriteClientCache whether client cache writes are allowed
   * @param canWriteDatastore whether caller policy permits datastore writes
   * @param forULPR whether this writing originates from ULPR processing
   */
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
   * @param forULPR whether this writing originates from ULPR processing (enables slashdot cache).
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
      if (canWriteDatastore || forULPR || useSlashdotCache) {
        node.routing().failureTable().onFound(block);
      }
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
    NodeStats stats = node.network().stats();
    if (canWriteClientCache) {
      chkClientcache.put(block, false);
      stats.avgClientCacheCHKLocation.report(loc);
    }
    if ((forULPR || useSlashdotCache) && !(canWriteDatastore || writeLocalToDatastore)) {
      chkSlashdotcache.put(block, false);
      stats.avgSlashdotCacheCHKLocation.report(loc);
    }
    if (!(canWriteDatastore || writeLocalToDatastore)) return;
    if (deep) {
      chkDatastore.put(block, !canWriteDatastore);
      stats.avgStoreCHKLocation.report(loc);
    } else {
      chkDatacache.put(block, !canWriteDatastore);
      stats.avgCacheCHKLocation.report(loc);
    }
  }

  private void tripPendingCHK(CHKBlock block) {
    if (node.services().clientCore() == null
        || node.services().clientCore().getRequestStarters() == null) return;
    node.services().clientCore().getRequestStarters().chkFetchSchedulerBulk.tripPendingKey(block);
    node.services().clientCore().getRequestStarters().chkFetchSchedulerRT.tripPendingKey(block);
  }

  /**
   * Stores the SSK block if this node is a sink, according to routing policy.
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
   * <p>Used by fetch paths where only cache promotion is desired. This method never performs
   * persistent store writes regardless of flags.
   *
   * @param block the SSK block to cache.
   * @param canWriteClientCache whether the client cache may be updated.
   * @param canWriteDatastore whether the datastore write flag is set; ignored here (never used).
   * @param fromULPR whether the writing originates from ULPR processing; enables slashdot cache.
   * @throws KeyCollisionException if the cache writing detects a key collision.
   */
  public void storeShallow(
      SSKBlock block, boolean canWriteClientCache, boolean canWriteDatastore, boolean fromULPR)
      throws KeyCollisionException {
    store(block, false, canWriteClientCache, canWriteDatastore, fromULPR);
  }

  /**
   * Stores an SSK block to appropriate caches and optionally to persistent stores.
   *
   * @param block SSK block to store
   * @param deep {@code true} to target main store; {@code false} for cache-first write
   * @param overwrite whether existing colliding entries may be overwritten
   * @param canWriteClientCache whether client cache writes are allowed
   * @param canWriteDatastore whether caller policy permits datastore writes
   * @param forULPR whether this writing originates from ULPR processing
   * @throws KeyCollisionException if collision occurs and overwrite is not permitted
   */
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
          block.getKey().getPubKeyHash(),
          block.getKey().getPubKey(),
          deep,
          canWriteClientCache,
          canWriteDatastore,
          forULPR || useSlashdotCache,
          writeLocalToDatastore);
      storeSSKToCachesAndStores(
          block, deep, overwrite, canWriteClientCache, canWriteDatastore, forULPR, loc);
      if (canWriteDatastore || forULPR || useSlashdotCache) {
        node.routing().failureTable().onFound(block);
      }
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
    NodeStats stats = node.network().stats();
    if (canWriteClientCache) {
      sskClientcache.put(block, overwrite, false);
      stats.avgClientCacheSSKLocation.report(loc);
    }
    if ((forULPR || useSlashdotCache) && !(canWriteDatastore || writeLocalToDatastore)) {
      sskSlashdotcache.put(block, overwrite, false);
      stats.avgSlashdotCacheSSKLocation.report(loc);
    }
    if (!(canWriteDatastore || writeLocalToDatastore)) return;
    if (deep) {
      sskDatastore.put(block, overwrite, !canWriteDatastore);
      stats.avgStoreSSKLocation.report(loc);
    } else {
      sskDatacache.put(block, overwrite, !canWriteDatastore);
      stats.avgCacheSSKLocation.report(loc);
    }
  }

  private void tripPendingSSK(SSKBlock block) {
    if (node.services().clientCore() == null
        || node.services().clientCore().getRequestStarters() == null) return;
    node.services().clientCore().getRequestStarters().sskFetchSchedulerBulk.tripPendingKey(block);
    node.services().clientCore().getRequestStarters().sskFetchSchedulerRT.tripPendingKey(block);
  }

  /**
   * Fetches a block from local stores and caches according to the provided flags.
   *
   * <p>No network routing is performed here. When the block is not present locally callers should
   * use {@link
   * network.crypta.node.subsystem.NodeRoutingSubsystem#makeRequestSender(network.crypta.keys.Key,
   * short, long, network.crypta.node.RequestTag, network.crypta.node.PeerNode,
   * network.crypta.node.subsystem.NodeRoutingSubsystem.RequestSenderOptions)} to initiate a routed
   * fetch.
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
    double dist =
        network.crypta.node.Location.distance(node.network().locationManager().getLocation(), loc);
    SSKBlock fromClient =
        fetchSSKFromClientCaches(
            key,
            new FetchParams(
                dontPromote, canWriteClientCache, canReadClientCache, forULPR, meta, loc, dist));
    if (fromClient != null) return fromClient;
    boolean ignoreOldBlocks = !writeLocalToDatastore && !canReadClientCache;
    if (LOG.isDebugEnabled()) dumpStoreHits();
    try {
      NodeStats stats = node.network().stats();
      stats.reportRequestLocation(loc);
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
        stats.avgStoreSSKSuccess.report(loc);
        stats.updateFurthestStoreSSKSuccess(dist);
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
        stats.avgCacheSSKSuccess.report(loc);
        stats.updateFurthestCacheSSKSuccess(dist);
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
        NodeStats stats = node.network().stats();
        stats.avgClientCacheSSKSuccess.report(p.loc());
        stats.updateFurthestClientCacheSSKSuccess(p.dist());
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
        NodeStats stats = node.network().stats();
        stats.avgSlashdotCacheSSKSuccess.report(loc);
        stats.updateFurthestSlashdotCacheSSKSuccess(dist);
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
    double dist =
        network.crypta.node.Location.distance(node.network().locationManager().getLocation(), loc);
    CHKBlock fromClient =
        fetchCHKFromClientCaches(
            key,
            new FetchParams(
                dontPromote, canWriteClientCache, canReadClientCache, forULPR, meta, loc, dist));
    if (fromClient != null) return fromClient;
    boolean ignoreOldBlocks = !writeLocalToDatastore && !canReadClientCache;
    if (LOG.isDebugEnabled()) dumpStoreHits();
    try {
      NodeStats stats = node.network().stats();
      stats.reportRequestLocation(loc);
      CHKBlock fromStores = fetchCHKFromStores(key, dontPromote, canWriteDatastore, meta);
      if (fromStores != null) {
        stats.avgStoreCHKSuccess.report(loc);
        stats.updateFurthestStoreCHKSuccess(dist);
        return fromStores;
      }
      CHKBlock fromCaches =
          fetchCHKFromCaches(key, dontPromote, canWriteDatastore, ignoreOldBlocks, meta);
      if (fromCaches != null) {
        stats.avgCacheCHKSuccess.report(loc);
        stats.updateFurthestCacheCHKSuccess(dist);
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
        NodeStats stats = node.network().stats();
        stats.avgClientCacheCHKSuccess.report(p.loc());
        stats.updateFurthestClientCacheCHKSuccess(p.dist());
        return block;
      }
    } catch (IOException e) {
      LOG.error("Could not read from client cache: {}", e, e);
    }
    if (p.forULPR() || useSlashdotCache || p.canReadClientCache()) {
      try {
        CHKBlock block = chkSlashdotcache.fetch(key, p.dontPromote(), false, p.meta());
        if (block != null) {
          NodeStats stats = node.network().stats();
          stats.avgSlashdotCacheCHKSucess.report(p.loc());
          stats.updateFurthestSlashdotCacheCHKSuccess(p.dist());
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
    // Move the pubkey to the top of the LRU and fix it if it
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
   * Returns configured slashdot-cache entry lifetime.
   *
   * @return slashdot-cache lifetime in milliseconds
   */
  public long getSlashdotCacheLifetime() {
    return chkSlashdotcacheStore.getLifetime();
  }

  /**
   * Sets slashdot-cache entry lifetime for all slashdot stores.
   *
   * @param value new lifetime value in milliseconds
   * @throws InvalidConfigValueException if the lifetime value is negative
   */
  public void setSlashdotCacheLifetime(long value) throws InvalidConfigValueException {
    if (value < 0) throw new InvalidConfigValueException("Must be positive!");
    chkSlashdotcacheStore.setLifetime(value);
    pubKeySlashdotcacheStore.setLifetime(value);
    sskSlashdotcacheStore.setLifetime(value);
  }

  /**
   * Initializes slashdot cache store instances with current capacity settings.
   *
   * @param slashdotCacheLifetime entry lifetime value in milliseconds
   */
  public void initializeSlashdotCaches(long slashdotCacheLifetime) {
    chkSlashdotcache = new CHKStore();
    chkSlashdotcacheStore =
        new SlashdotStore<>(
            chkSlashdotcache,
            maxSlashdotCacheKeys,
            slashdotCacheLifetime,
            PURGE_INTERVAL,
            node.network().ticker(),
            node.services().clientCore().getTempBucketFactory());
    pubKeySlashdotcache = new PubkeyStore();
    pubKeySlashdotcacheStore =
        new SlashdotStore<>(
            pubKeySlashdotcache,
            maxSlashdotCacheKeys,
            slashdotCacheLifetime,
            PURGE_INTERVAL,
            node.network().ticker(),
            node.services().clientCore().getTempBucketFactory());
    getPubKey.setLocalSlashdotcache(pubKeySlashdotcache);
    sskSlashdotcache = new SSKStore(getPubKey);
    sskSlashdotcacheStore =
        new SlashdotStore<>(
            sskSlashdotcache,
            maxSlashdotCacheKeys,
            slashdotCacheLifetime,
            PURGE_INTERVAL,
            node.network().ticker(),
            node.services().clientCore().getTempBucketFactory());
  }

  /**
   * Returns whether client-cache initialization is blocked awaiting password entry.
   *
   * @return {@code true} when client cache awaits password input
   */
  public boolean isClientCacheAwaitingPassword() {
    return clientCacheAwaitingPassword;
  }

  /**
   * Returns whether database initialization is blocked awaiting password entry.
   *
   * @return {@code true} when the database awaits password input
   */
  public boolean isDatabaseAwaitingPassword() {
    return databaseAwaitingPassword;
  }

  /**
   * Clears password-waiting flags for both client-cache and database initialization paths.
   *
   * <p>Callers typically invoke this after successfully applying credentials or resetting the setup
   * state.
   */
  public void clearAwaitingPasswords() {
    clientCacheAwaitingPassword = false;
    databaseAwaitingPassword = false;
  }

  /**
   * Sets configured client-cache store type string without reinitializing stores.
   *
   * @param value client-cache type identifier
   */
  public void setClientCacheType(String value) {
    clientCacheType = value;
  }

  /**
   * Sets the program-directory wrapper used as a datastore root.
   *
   * @param value program-directory wrapper containing datastore location
   */
  public void setStoreDir(network.crypta.node.ProgramDirectory value) {
    storeDir = value;
  }

  /**
   * Returns program-directory wrapper representing datastore root.
   *
   * @return datastore program-directory wrapper
   */
  public network.crypta.node.ProgramDirectory getStoreProgramDir() {
    return storeDir;
  }

  /**
   * Returns filesystem directory for datastore root.
   *
   * @return datastore root directory
   */
  public File getStoreDir() {
    return storeDir.dir();
  }

  /**
   * Sets a filesystem path for the persisted master keys file.
   *
   * @param value master keys file path
   */
  public void setMasterKeysFile(File value) {
    masterKeysFile = value;
  }

  /**
   * Returns the filesystem path of the persisted master keys file.
   *
   * @return master keys file path
   */
  public File getMasterKeysFile() {
    return masterKeysFile;
  }

  /**
   * Sets in-memory master key bundle.
   *
   * @param value loaded master key bundle, or {@code null} when locked
   */
  public void setKeys(MasterKeys value) {
    keys = value;
  }

  /**
   * Returns in-memory master key bundle.
   *
   * @return loaded master keys, or {@code null} when not currently available
   */
  public MasterKeys getKeys() {
    return keys;
  }

  /**
   * Sets database encryption key reference.
   *
   * @param value database encryption key, or {@code null} when unavailable
   */
  public void setDatabaseKey(DatabaseKey value) {
    databaseKey = value;
  }

  /**
   * Returns database encryption key reference.
   *
   * @return database encryption key, or {@code null} when unavailable
   */
  public DatabaseKey getDatabaseKey() {
    return databaseKey;
  }

  /**
   * Returns previous pubkey datastore reference retained for migration.
   *
   * @return old pubkey datastore callback, or {@code null} when none is pending
   */
  public PubkeyStore getOldPK() {
    return oldPK.get();
  }

  /**
   * Returns previous pubkey datacache reference retained for migration.
   *
   * @return old pubkey datacache callback, or {@code null} when none is pending
   */
  public PubkeyStore getOldPKCache() {
    return oldPKCache.get();
  }

  /**
   * Returns previous pubkey client-cache reference retained for migration.
   *
   * @return old pubkey client-cache callback, or {@code null} when none is pending
   */
  public PubkeyStore getOldPKClientCache() {
    return oldPKClientCache.get();
  }

  /**
   * Returns configured maximum memory usage for caching-freenet-store wrapper.
   *
   * @return maximum cache wrapper size in bytes
   */
  public long getCachingFreenetStoreMaxSize() {
    return cachingFreenetStoreMaxSize;
  }

  /**
   * Sets maximum memory usage for caching-freenet-store wrapper.
   *
   * @param value maximum cache wrapper size in bytes
   * @throws InvalidConfigValueException if supplied size is negative
   * @throws NodeNeedRestartException always thrown because live reconfiguration is unsupported
   */
  public void setCachingFreenetStoreMaxSize(long value)
      throws InvalidConfigValueException, NodeNeedRestartException {
    if (value < 0) throw new InvalidConfigValueException(l10n("invalidMemoryCacheSize"));
    cachingFreenetStoreMaxSize = value;
    throw new NodeNeedRestartException("Caching Maximum Size cannot be changed on the fly");
  }

  /**
   * Initializes caching-freenet-store maximum size during startup.
   *
   * @param value maximum cache wrapper size in bytes
   * @throws NodeInitException if supplied size is negative
   */
  public void initializeCachingFreenetStoreMaxSize(long value) throws NodeInitException {
    cachingFreenetStoreMaxSize = value;
    if (cachingFreenetStoreMaxSize < 0)
      throw new NodeInitException(
          NodeInitException.EXIT_BAD_CONFIG, l10n("invalidMemoryCacheSize"));
  }

  /**
   * Returns a configured flush / eviction period for caching-freenet-store wrapper.
   *
   * @return caching period in milliseconds
   */
  public long getCachingFreenetStorePeriod() {
    return cachingFreenetStorePeriod;
  }

  /**
   * Sets the caching-freenet-store period and signals that restart is required.
   *
   * @param value caching period in milliseconds
   * @throws NodeNeedRestartException always thrown because live reconfiguration is unsupported
   */
  public void setCachingFreenetStorePeriod(long value) throws NodeNeedRestartException {
    cachingFreenetStorePeriod = value;
    throw new NodeNeedRestartException("Caching Period cannot be changed on the fly");
  }

  /**
   * Initializes a caching-freenet-store period during startup.
   *
   * @param value caching period in milliseconds
   */
  public void initializeCachingFreenetStorePeriod(long value) {
    cachingFreenetStorePeriod = value;
  }

  /**
   * Initializes the caching-store tracker when both size and period settings are positive.
   *
   * <p>When either value is zero or negative, no tracker is created and salted-hash stores operate
   * without the wrapper cache layer.
   */
  public void initializeCachingFreenetStoreTracker() {
    if (cachingFreenetStoreMaxSize > 0 && cachingFreenetStorePeriod > 0) {
      cachingFreenetStoreTracker =
          new CachingFreenetStoreTracker(
              cachingFreenetStoreMaxSize, cachingFreenetStorePeriod, node.network().ticker());
    }
  }

  /**
   * Sets or unlocks the master password used for encrypted client material.
   *
   * @param password clear‑text password entered by the user.
   * @param inFirstTimeWizard {@code true} when called during the first‑time setup wizard.
   * @throws Node.AlreadySetPasswordException if a password is already set; use
   *     changeMasterPassword().
   * @throws MasterKeysWrongPasswordException if the provided password does not unlock existing
   *     material.
   * @throws MasterKeysFileSizeException if the master key file has an invalid size.
   * @throws IOException on I/O errors while reading or writing key material.
   */
  public void setMasterPassword(String password, boolean inFirstTimeWizard)
      throws Node.AlreadySetPasswordException,
          MasterKeysWrongPasswordException,
          MasterKeysFileSizeException,
          IOException {
    MasterKeys k;
    synchronized (node) {
      if (keys == null) {
        // First-time set or decrypting existing material.
        keys = MasterKeys.read(masterKeysFile, node.bootstrap().secureRandom(), password);
        databaseKey = keys.createDatabaseKey();
      } else {
        // A password is already set; use changeMasterPassword() instead of setMasterPassword().
        throw new Node.AlreadySetPasswordException();
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
    node.services().clientCore().setupMasterSecret(secret);
    boolean wantClientCache;
    boolean wantDatabase;
    synchronized (node) {
      wantClientCache = clientCacheAwaitingPassword;
      wantDatabase = databaseAwaitingPassword;
      databaseAwaitingPassword = false;
    }
    if (wantClientCache) activatePasswordedClientCache(keys);
    if (wantDatabase) lateSetupDatabase(keys.createDatabaseKey());
  }

  private void activatePasswordedClientCache(MasterKeys keys) {
    synchronized (node) {
      if ("ram".equals(clientCacheType)) {
        LOG.warn("RAM client cache cannot be passworded!");
        return;
      }
      if (!Node.TYPE_SALT_HASH.equals(clientCacheType)) {
        LOG.warn(
            "Unknown client cache type, cannot activate passworded store: {}", clientCacheType);
        return;
      }
    }
    Runnable migrate = createMigrateOldStoreData(true);

    try {
      initSaltHashClientCacheFS(true, keys.getClientCacheMasterKey());
    } catch (NodeInitException e) {
      LOG.error("Unable to activate passworded client cache", e);
      return;
    }

    synchronized (node) {
      clientCacheAwaitingPassword = false;
    }

    node.network().executor().execute(migrate, "Migrate data from previous store");
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
   * @throws Node.AlreadySetPasswordException if a password is already configured.
   */
  public void changeMasterPassword(
      String oldPassword, String newPassword, boolean inFirstTimeWizard)
      throws MasterKeysWrongPasswordException,
          MasterKeysFileSizeException,
          IOException,
          Node.AlreadySetPasswordException {
    if (LOG.isTraceEnabled()) {
      LOG.trace(
          "changeMasterPassword(oldProvided={}, inFirstTimeWizard={})",
          oldPassword != null && !oldPassword.isEmpty(),
          inFirstTimeWizard);
    }
    if (node.services().securityLevels().getPhysicalThreatLevel() == PHYSICAL_THREAT_LEVEL.MAXIMUM)
      LOG.error("Changing password while physical threat level is at MAXIMUM???");
    SecureRandom secureRandom = node.bootstrap().secureRandom();
    if (masterKeysFile.exists()) {
      MasterKeys activeKeys = keys;
      if (activeKeys == null) {
        activeKeys = MasterKeys.read(masterKeysFile, secureRandom, oldPassword);
        synchronized (node) {
          if (keys == null) {
            keys = activeKeys;
            databaseKey = activeKeys.createDatabaseKey();
          } else {
            activeKeys = keys;
          }
        }
      }
      activeKeys.changePassword(masterKeysFile, newPassword, secureRandom);
      setPasswordInner(activeKeys, inFirstTimeWizard);
    } else {
      setMasterPassword(newPassword, inFirstTimeWizard);
    }
  }

  private String l10n(String key) {
    return NodeL10n.getBase().getString("Node." + key);
  }

  private String l10nInvalidMaxStoreSize(String replacementValue) {
    return NodeL10n.getBase().getString("Node.invalidMaxStoreSize", replacementValue);
  }

  /**
   * Initializes client-cache callbacks with in-memory RAM store backends.
   *
   * <p>This mode is used for transient caching or as a fallback while encrypted client caches are
   * unavailable.
   */
  public void initRAMClientCacheFS() {
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

  /**
   * Initializes client-cache callbacks with no-op backends that retain no data.
   *
   * <p>Use this mode when client-cache storage should be disabled while preserving callback wiring.
   */
  public void initNoClientCacheFS() {
    chkClientcache = new CHKStore();
    new NullFreenetStore<>(chkClientcache).close();
    pubKeyClientcache = new PubkeyStore();
    new NullFreenetStore<>(pubKeyClientcache).close();
    sskClientcache = new SSKStore(getPubKey);
    new NullFreenetStore<>(sskClientcache).close();
  }

  private void finishInitSaltHashFS() {
    if (node.services().clientCore().getAlerts() == null) throw new NullPointerException();
    StoreAlertSink storeAlertSink =
        new UserAlertManagerStoreAlertSink(node.services().clientCore().getAlerts());
    chkDatastore.getStore().setStoreAlertSink(storeAlertSink);
    chkDatacache.getStore().setStoreAlertSink(storeAlertSink);
    pubKeyDatastore.getStore().setStoreAlertSink(storeAlertSink);
    pubKeyDatacache.getStore().setStoreAlertSink(storeAlertSink);
    sskDatastore.getStore().setStoreAlertSink(storeAlertSink);
    sskDatacache.getStore().setStoreAlertSink(storeAlertSink);
  }

  /**
   * Initializes main datastore and datacache callbacks with in-memory RAM backends.
   *
   * <p>This backend is primarily used for non-persistent operation and as a temporary layer during
   * delayed salted-hash initialization.
   */
  public void initRAMFS() {
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

  /**
   * Initializes persistent salted-hash datastore and datacache stores.
   *
   * @param dontResizeOnStart {@code true} to skip immediate resize passes on startup
   * @param masterKey optional master key bytes used for store encryption, or {@code null}
   * @throws NodeInitException if store construction or startup fails
   */
  @SuppressWarnings("SameParameterValue")
  public void initSaltHashFS(boolean dontResizeOnStart, byte[] masterKey) throws NodeInitException {
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

      boolean dChkData = chkDatastoreLocal.getStore().start(node.network().ticker(), false);
      boolean dChkCache = chkDatacacheLocal.getStore().start(node.network().ticker(), false);
      boolean dPubkeyData = pubKeyDatastoreLocal.getStore().start(node.network().ticker(), false);
      boolean dPubkeyCache = pubKeyDatacacheLocal.getStore().start(node.network().ticker(), false);
      boolean dSskData = sskDatastoreLocal.getStore().start(node.network().ticker(), false);
      boolean dSskCache = sskDatacacheLocal.getStore().start(node.network().ticker(), false);

      boolean delay = dChkData || dChkCache || dPubkeyData || dPubkeyCache || dSskData || dSskCache;

      if (delay) {

        LOG.info("Delayed init of datastore");

        initRAMFS();

        final Runnable migrate = createMigrateOldStoreData(false);

        node.network()
            .ticker()
            .queueTimedJob(
                () -> {
                  LOG.info("Starting delayed init of datastore");
                  try {
                    chkDatastoreLocal.getStore().start(node.network().ticker(), true);
                    chkDatacacheLocal.getStore().start(node.network().ticker(), true);
                    pubKeyDatastoreLocal.getStore().start(node.network().ticker(), true);
                    pubKeyDatacacheLocal.getStore().start(node.network().ticker(), true);
                    sskDatastoreLocal.getStore().start(node.network().ticker(), true);
                    sskDatacacheLocal.getStore().start(node.network().ticker(), true);
                  } catch (IOException e) {
                    LOG.error("Failed to start datastore", e);
                    return;
                  }

                  chkDatastore = chkDatastoreLocal;
                  chkDatacache = chkDatacacheLocal;
                  pubKeyDatastore = pubKeyDatastoreLocal;
                  pubKeyDatacache = pubKeyDatacacheLocal;
                  getPubKey.setDataStore(pubKeyDatastoreLocal, pubKeyDatacacheLocal);
                  sskDatastore = sskDatastoreLocal;
                  sskDatacache = sskDatacacheLocal;

                  finishInitSaltHashFS();

                  LOG.info("Finishing delayed init of datastore");
                  migrate.run();
                },
                "Start store",
                0,
                true,
                false); // Use Ticker to guarantee that this runs *after* constructors have
        // completed.

      } else {

        chkDatastore = chkDatastoreLocal;
        chkDatacache = chkDatacacheLocal;
        pubKeyDatastore = pubKeyDatastoreLocal;
        pubKeyDatacache = pubKeyDatacacheLocal;
        getPubKey.setDataStore(pubKeyDatastoreLocal, pubKeyDatacacheLocal);
        sskDatastore = sskDatastoreLocal;
        sskDatacache = sskDatacacheLocal;

        node.network()
            .ticker()
            .queueTimedJob(
                () -> {
                  chkDatastore = chkDatastoreLocal;
                  chkDatacache = chkDatacacheLocal;
                  pubKeyDatastore = pubKeyDatastoreLocal;
                  pubKeyDatacache = pubKeyDatacacheLocal;
                  getPubKey.setDataStore(pubKeyDatastoreLocal, pubKeyDatacacheLocal);
                  sskDatastore = sskDatastoreLocal;
                  sskDatacache = sskDatacacheLocal;

                  finishInitSaltHashFS();
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

  /**
   * Initializes persistent salted-hash client cache stores.
   *
   * @param dontResizeOnStart {@code true} to skip immediate resize passes on startup
   * @param clientCacheMasterKey client-cache encryption key bytes
   * @throws NodeInitException if store construction or startup fails
   */
  public void initSaltHashClientCacheFS(boolean dontResizeOnStart, byte[] clientCacheMasterKey)
      throws NodeInitException {

    try {
      final CHKStore chkClientcacheLocal = new CHKStore();
      makeClientcache("CHK", chkClientcacheLocal, dontResizeOnStart, clientCacheMasterKey);
      final PubkeyStore pubKeyClientcacheLocal = new PubkeyStore();
      makeClientcache(
          STORE_KIND_PUBKEY, pubKeyClientcacheLocal, dontResizeOnStart, clientCacheMasterKey);
      final SSKStore sskClientcacheLocal = new SSKStore(getPubKey);
      makeClientcache("SSK", sskClientcacheLocal, dontResizeOnStart, clientCacheMasterKey);

      boolean dChk = chkClientcacheLocal.getStore().start(node.network().ticker(), false);
      boolean dPub = pubKeyClientcacheLocal.getStore().start(node.network().ticker(), false);
      boolean dSsk = sskClientcacheLocal.getStore().start(node.network().ticker(), false);
      boolean delay = dChk || dPub || dSsk;

      if (delay) {

        LOG.info("Delayed init of client-cache");

        initRAMClientCacheFS();

        final Runnable migrate = createMigrateOldStoreData(true);

        node.network()
            .ticker()
            .queueTimedJob(
                () -> {
                  LOG.info("Starting delayed init of client-cache");
                  try {
                    chkClientcacheLocal.getStore().start(node.network().ticker(), true);
                    pubKeyClientcacheLocal.getStore().start(node.network().ticker(), true);
                    sskClientcacheLocal.getStore().start(node.network().ticker(), true);
                  } catch (IOException e) {
                    LOG.error("Failed to start client-cache", e);
                    return;
                  }
                  chkClientcache = chkClientcacheLocal;
                  pubKeyClientcache = pubKeyClientcacheLocal;
                  getPubKey.setLocalDataStore(pubKeyClientcacheLocal);
                  sskClientcache = sskClientcacheLocal;

                  LOG.info("Finishing delayed init of client-cache");
                  migrate.run();
                },
                "Migrate store",
                0,
                true,
                false);
      } else {
        chkClientcache = chkClientcacheLocal;
        pubKeyClientcache = pubKeyClientcacheLocal;
        getPubKey.setLocalDataStore(pubKeyClientcacheLocal);
        sskClientcache = sskClientcacheLocal;
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

    SaltedHashStoreParams<T> params =
        SaltedHashStoreParams.of(
            new SaltedHashStoreLocation(getStoreDir(), type + "-" + store),
            new SaltedHashStoreDependencies<>(
                cb, node.bootstrap().random(), SemiOrderedShutdownHook.get(), clientCacheMasterKey),
            new SaltedHashStoreSizing(
                maxKeys,
                storeUseSlotFilters,
                storePreallocate,
                storeSaltHashResizeOnStart && !lateStart));
    SaltedHashFreenetStore<T> fs = SaltedHashFreenetStore.construct(params);
    if (cachingFreenetStoreMaxSize > 0) {
      new CachingFreenetStore<>(cb, fs, cachingFreenetStoreTracker);
      // CachingFreenetStore constructor calls cb.setStore(this)
    } else {
      cb.setStore(fs);
    }
  }

  /**
   * Returns configured datastore backend type identifier.
   *
   * @return datastore backend type string
   */
  public String getStoreType() {
    synchronized (node) {
      return storeType;
    }
  }

  /**
   * Sets datastore backend type identifier without rebuilding stores.
   *
   * @param value datastore backend type string
   */
  public void setStoreType(String value) {
    synchronized (node) {
      storeType = value;
    }
  }

  /**
   * Creates and activates datastore implementation for the requested backend type.
   *
   * @param value requested datastore backend type
   * @throws InvalidConfigValueException if the requested backend fails initialization
   */
  public void makeStore(String value) throws InvalidConfigValueException {
    if (value.equals(Node.TYPE_SALT_HASH)) {
      try {
        initSaltHashFS(true, null);
      } catch (NodeInitException e) {
        throw new InvalidConfigValueException(e);
      }
    } else {
      initRAMFS();
    }

    synchronized (node) {
      storeType = value;
    }
  }

  /**
   * Returns configured client-cache backend type identifier.
   *
   * @return client-cache backend type string
   */
  public String getClientCacheType() {
    synchronized (node) {
      return clientCacheType;
    }
  }

  /**
   * Switches the client-cache backend type and reinitializes backing stores.
   *
   * @param value requested client-cache backend type
   * @throws InvalidConfigValueException if the type is invalid or initialization cannot complete
   */
  public void changeClientCacheType(String value) throws InvalidConfigValueException {
    synchronized (node) { // Serialize this part.
      switch (value) {
        case Node.TYPE_SALT_HASH -> {
          byte[] key;
          try {
            synchronized (node) {
              if (keys == null) throw new MasterKeysWrongPasswordException();
              key = keys.getClientCacheMasterKey();
              clientCacheType = value;
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
        }
        case "ram" -> {
          synchronized (node) {
            clientCacheAwaitingPassword = false;
            clientCacheType = value;
          }
          initRAMClientCacheFS();
        }
        case "none" -> {
          synchronized (node) {
            clientCacheAwaitingPassword = false;
            clientCacheType = value;
          }
          initNoClientCacheFS();
        }
        default -> throw new InvalidConfigValueException("Invalid client cache type");
      }
    }
  }

  /**
   * Returns pubkey cache/store helper used by storage operations.
   *
   * @return node pubkey helper instance
   */
  public NodeGetPubkey getPubKey() {
    return getPubKey;
  }
}

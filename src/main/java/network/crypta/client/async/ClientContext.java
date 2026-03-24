package network.crypta.client.async;

import java.util.Random;
import network.crypta.client.ArchiveManager;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException;
import network.crypta.client.InsertContext;
import network.crypta.client.InsertException;
import network.crypta.client.events.SimpleEventProducer;
import network.crypta.client.filter.LinkFilterExceptionProvider;
import network.crypta.clients.fcp.PersistentRequestRoot;
import network.crypta.config.Config;
import network.crypta.crypt.CryptoResumeContext;
import network.crypta.crypt.MasterSecret;
import network.crypta.crypt.RandomSource;
import network.crypta.node.RequestScheduler;
import network.crypta.node.RequestStarterGroup;
import network.crypta.runtime.alerts.UserAlert;
import network.crypta.runtime.alerts.UserAlertManager;
import network.crypta.support.DummyJobRunner;
import network.crypta.support.MemoryLimitedJobRunner;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.Ticker;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.LockableRandomAccessBufferFactory;
import network.crypta.support.api.ResumeContext;
import network.crypta.support.compress.RealCompressor;
import network.crypta.support.io.FileRandomAccessBufferFactory;
import network.crypta.support.io.FilenameGenerator;
import network.crypta.support.io.NativeThread;
import network.crypta.support.io.PersistentFileTracker;
import network.crypta.support.io.PersistentFilenameGenerator;
import network.crypta.support.io.PersistentTempBucketFactory;
import network.crypta.support.io.TempBucketFactory;

/**
 * Coordinates client-layer operations and provides shared services to getters/putters.
 *
 * <p>This context bundles references to executors, schedulers, storage factories, crypto secrets,
 * and other collaborating components required by fetch and insert operations. Callers typically
 * obtain a single {@code ClientContext} during application startup and pass it to higher-level
 * request builders. The context centralizes configuration so individual operations remain
 * lightweight and easy to construct.
 *
 * <p>The instance acts as a façade over both transient and persistent facilities: it exposes
 * request schedulers for CHK/SSK fetches and inserts (in bulk or real-time modes), factories for
 * temporary and persistent buffers/buckets, and helpers for background jobs that must be serialized
 * against on-disk state. Most fields are immutable after construction. The context itself is not a
 * heavy state holder; it orchestrates access to the underlying subsystems.
 *
 * <p>Concurrency: methods are thread-safe where documented; request-scheduler and job-queue methods
 * are designed to be called from arbitrary threads. Mutators that flip persistent credentials are
 * synchronized to avoid races. Callers should treat the instance as long-lived and reuse it across
 * requests.
 *
 * <ul>
 *   <li>Provides access to fetch/insert schedulers for CHK and SSK keys.
 *   <li>Creates appropriate temporary or persistent storage for request pipelines.
 *   <li>Queues persistence-affecting work via a {@link PersistentJobRunner}.
 *   <li>Surfaces defaults such as {@link #getDefaultPersistentFetchContext()}.
 * </ul>
 *
 * @author toad
 * @see ClientRequestScheduler
 * @see RequestScheduler
 */
public class ClientContext implements CryptoResumeContext {

  private ClientRequestScheduler sskFetchSchedulerBulk;
  private ClientRequestScheduler chkFetchSchedulerBulk;
  private ClientRequestScheduler sskInsertSchedulerBulk;
  private ClientRequestScheduler chkInsertSchedulerBulk;
  private ClientRequestScheduler sskFetchSchedulerRT;
  private ClientRequestScheduler chkFetchSchedulerRT;
  private ClientRequestScheduler sskInsertSchedulerRT;
  private ClientRequestScheduler chkInsertSchedulerRT;
  private UserAlertManager alerts;

  private final PriorityAwareExecutor mainExecutorInternal;

  /**
   * We need to be able to suspend execution of jobs changing persistent state to write it to disk
   * consistently. Also, some jobs may want to request immediate serialization.
   */
  public final PersistentJobRunner jobRunner;

  /** Strong, cryptographic RNG used for IDs, nonce, and protocol randomness. Thread-safe. */
  public final RandomSource random;

  /**
   * Manages archive-related interactions for client operations, if enabled. Read-mostly; callers
   * should not mutate its configuration through this reference.
   */
  public final ArchiveManager archiveManager;

  /**
   * Factory for temporary buckets that persist on disk across restarts. Use when the request state
   * must survive crashes or shutdowns, such as persistent inserts or fetch retries.
   */
  public final PersistentTempBucketFactory persistentBucketFactory;

  private PersistentFileTracker persistentFileTracker;

  /**
   * Factory for purely in-flight temporary buckets. Contents are deleted when the node restarts;
   * suitable for transient requests and short-lived processing stages.
   */
  public final TempBucketFactory tempBucketFactory;

  /**
   * Produces lockable random-access buffers for transient data paths. The returned buffers may be
   * backed by memory or temporary files depending on configuration.
   */
  public final LockableRandomAccessBufferFactory tempRAFFactory;

  /**
   * Produces lockable random-access buffers for data that must persist. Use for persistent request
   * pipelines where the intermediate state needs to be crash-safe.
   */
  public final LockableRandomAccessBufferFactory persistentRAFFactory;

  /**
   * Queue that tracks and schedules background healing work produced by client operations. The
   * queue typically runs independently of foreground request lifecycles.
   */
  public final HealingQueue healingQueue;

  /** Manager for USK-related coordination used by client requests. */
  public final USKManager uskManager;

  /**
   * Fast but weak PRNG for non-cryptographic use (e.g., jitter, randomized backoff). Do not use it
   * for secrets or key material. Thread-confined unless otherwise documented by callers.
   */
  public final Random fastWeakRandomSource;

  /** Monotonic boot identifier for this process instance; stable until the node restarts. */
  public final long bootID;

  /**
   * Low-overhead ticker for scheduling timed jobs and deferring work. Preferred over ad-hoc timers
   * so long-running components can share infrastructure.
   */
  public final Ticker ticker;

  /** Filename generator for transient artifacts produced by client requests. */
  public final FilenameGenerator fg;

  /** Filename generator for on-disk artifacts that must persist across restarts. */
  public final FilenameGenerator persistentFG;

  /**
   * Compressor implementation used by client-side processing stages when compression is enabled.
   */
  public final RealCompressor rc;

  /**
   * Datastore integrity/checking helper available to client operations. Read-mostly; clients
   * typically call methods that report health or schedule verification.
   */
  public final DatastoreChecker checker;

  private DownloadCache downloadCache;

  /**
   * Used for memory-intensive jobs such as in-RAM FEC decoding. Some of these jobs may do disk I/O,
   * and we don't guarantee to serialize them. The new splitfile code does FEC decode entirely in
   * memory, which saves a lot of seeks and improves robustness.
   */
  public final MemoryLimitedJobRunner memoryLimitedJobRunner;

  /** Root for persistent request coordination, including recovery across restarts. */
  public final PersistentRequestRoot persistentRoot;

  private final FetchContext defaultPersistentFetchContext;
  private final InsertContext defaultPersistentInsertContext;

  /** Transient master secret used for cryptographic operations during the current run. */
  public final MasterSecret cryptoSecretTransient;

  private MasterSecret cryptoSecretPersistent;
  private final FileRandomAccessBufferFactory fileRAFTransient;
  private final FileRandomAccessBufferFactory fileRAFPersistent;

  /** Provider for link filter exceptions. */
  public final LinkFilterExceptionProvider linkFilterExceptionProvider;

  /**
   * Transient version of the PersistentJobRunner, just starts stuff immediately. Helpful for
   * avoiding having two different APIs, e.g., in SplitFileFetcherStorage.
   */
  PersistentJobRunner dummyJobRunner;

  private final Config config;

  /**
   * Creates a new client context wiring together schedulers, storage factories, crypto state, and
   * supporting services used by getters and putters.
   *
   * @param bootID Monotonic identifier for this process instance, remains constant until restart
   *     and can be used to disambiguate ephemeral artifacts.
   * @param runtime Runtime executors, schedulers, and randomness sources used by the client layer.
   * @param storageFactories Storage factories and filename generators for transient and persistent
   *     artifacts.
   * @param rafFactories Random-access buffer factories for transient and persistent buffers.
   * @param services Shared service collaborators such as archive/healing resources and managers.
   * @param defaults Default fetch/insert contexts and configuration backing client operations.
   */
  public ClientContext(
      long bootID,
      ClientContextRuntime runtime,
      ClientContextStorageFactories storageFactories,
      ClientContextRafFactories rafFactories,
      ClientContextServices services,
      ClientContextDefaults defaults) {
    this.bootID = bootID;
    this.jobRunner = runtime.jobRunner();
    this.mainExecutorInternal = runtime.mainExecutor();
    this.random = runtime.strongRandom();
    this.archiveManager = services.resources().archiveManager();
    this.persistentBucketFactory = storageFactories.persistentBucketFactory();
    this.persistentFileTracker = storageFactories.persistentFileTracker();
    this.tempBucketFactory = storageFactories.tempBucketFactory();
    this.healingQueue = services.resources().healingQueue();
    this.uskManager = services.uskManager();
    this.fastWeakRandomSource = runtime.fastWeakRandom();
    this.ticker = runtime.ticker();
    this.fg = storageFactories.filenameGenerator();
    this.persistentFG = storageFactories.persistentFilenameGenerator();
    this.persistentRAFFactory = rafFactories.persistentRAFFactory();
    this.fileRAFPersistent = storageFactories.fileRAFPersistent();
    this.fileRAFTransient = storageFactories.fileRAFTransient();
    this.rc = services.compressor();
    this.checker = services.checker();
    this.linkFilterExceptionProvider = services.linkFilterExceptionProvider();
    this.memoryLimitedJobRunner = runtime.memoryLimitedJobRunner();
    this.tempRAFFactory = rafFactories.tempRAFFactory();
    this.persistentRoot = services.persistentRoot();
    this.dummyJobRunner = new DummyJobRunner(mainExecutorInternal, this);
    this.defaultPersistentFetchContext = defaults.defaultPersistentFetchContext();
    this.defaultPersistentInsertContext = defaults.defaultPersistentInsertContext();
    this.cryptoSecretTransient = runtime.cryptoSecretTransient();
    this.config = defaults.config();
  }

  /**
   * Initializes request schedulers and user-alert manager after construction. This is expected to
   * be called during node startup once {@link RequestStarterGroup} is created.
   *
   * @param starters Group of request schedulers for CHK/SSK fetch/insert in bulk and real-time
   *     modes.
   * @param alerts User alert manager for surfacing notifications to end users.
   */
  public void init(RequestStarterGroup starters, UserAlertManager alerts) {
    this.sskFetchSchedulerBulk = starters.sskFetchSchedulerBulk;
    this.chkFetchSchedulerBulk = starters.chkFetchSchedulerBulk;
    this.sskInsertSchedulerBulk = starters.sskPutSchedulerBulk;
    this.chkInsertSchedulerBulk = starters.chkPutSchedulerBulk;
    this.sskFetchSchedulerRT = starters.sskFetchSchedulerRT;
    this.chkFetchSchedulerRT = starters.chkFetchSchedulerRT;
    this.sskInsertSchedulerRT = starters.sskPutSchedulerRT;
    this.chkInsertSchedulerRT = starters.chkPutSchedulerRT;
    this.alerts = alerts;
  }

  /**
   * Sets the persistent master secret used for operations that must survive restarts. Thread-safe;
   * synchronized to prevent partial visibility across threads.
   *
   * @param secret Master secret to associate with persistent operations; must be a valid instance
   *     created by the crypto subsystem.
   */
  public synchronized void setPersistentMasterSecret(MasterSecret secret) {
    this.cryptoSecretPersistent = secret;
  }

  /**
   * Returns the currently configured persistent master secret, if any.
   *
   * @return The master secret used for persistent operations; may be {@code null} until set.
   */
  @Override
  public synchronized MasterSecret getPersistentMasterSecret() {
    return cryptoSecretPersistent;
  }

  /**
   * Returns the weak PRNG exposed through {@link ResumeContext}.
   *
   * @return the fast weak random source used for non-cryptographic resume wiring
   */
  @Override
  public Random fastWeakRandom() {
    return fastWeakRandomSource;
  }

  /**
   * Returns the filename contract for persistent artifacts.
   *
   * @return the persistent filename contract
   */
  @Override
  public PersistentFilenameGenerator getPersistentFilenameGenerator() {
    return persistentFG;
  }

  /**
   * Returns the SSK fetch scheduler appropriate for the requested mode.
   *
   * @param realTime {@code true} for real-time scheduling; {@code false} for bulk scheduling to
   *     favor throughput.
   * @return The {@link ClientRequestScheduler} handling SSK fetches for the chosen mode.
   */
  public ClientRequestScheduler getSskFetchScheduler(boolean realTime) {
    return realTime ? sskFetchSchedulerRT : sskFetchSchedulerBulk;
  }

  /**
   * Returns the CHK fetch scheduler appropriate for the requested mode.
   *
   * @param realTime {@code true} for real-time scheduling; {@code false} for bulk scheduling.
   * @return The {@link ClientRequestScheduler} handling CHK fetches for the chosen mode.
   */
  public ClientRequestScheduler getChkFetchScheduler(boolean realTime) {
    return realTime ? chkFetchSchedulerRT : chkFetchSchedulerBulk;
  }

  /**
   * Returns the SSK insert scheduler appropriate for the requested mode.
   *
   * @param realTime {@code true} for real-time scheduling; {@code false} for bulk scheduling.
   * @return The {@link ClientRequestScheduler} handling SSK inserts for the chosen mode.
   */
  public ClientRequestScheduler getSskInsertScheduler(boolean realTime) {
    return realTime ? sskInsertSchedulerRT : sskInsertSchedulerBulk;
  }

  /**
   * Returns the CHK insert scheduler appropriate for the requested mode.
   *
   * @param realTime {@code true} for real-time scheduling; {@code false} for bulk scheduling.
   * @return The {@link ClientRequestScheduler} handling CHK inserts for the chosen mode.
   */
  public ClientRequestScheduler getChkInsertScheduler(boolean realTime) {
    return realTime ? chkInsertSchedulerRT : chkInsertSchedulerBulk;
  }

  /**
   * Starts an insert request, queuing on the persistence runner when necessary.
   *
   * <p>If the provided putter is persistent, the operation is scheduled on the database job runner
   * so its side effects can be serialized with other state changes. Transient inserts start
   * immediately on the calling thread and may signal failures synchronously.
   *
   * @param inserter The putter to start; may represent either a transient or persistent insert. The
   *     instance must be fully configured and not previously started.
   * @throws InsertException If the insert is transient and fails to start due to preconditions or
   *     immediate setup errors.
   * @throws PersistenceDisabledException If persistence is required but disabled (for example, the
   *     persistent store is locked or not yet unlocked by the user).
   */
  public void start(final ClientPutter inserter)
      throws InsertException, PersistenceDisabledException {
    if (inserter.persistent()) {
      jobRunner.queue(
          (PersistentJob)
              context -> {
                try {
                  inserter.start(false, context);
                } catch (InsertException e) {
                  if (inserter.callback != null) {
                    inserter.callback.onFailure(e, inserter);
                  }
                }
                return true;
              },
          NativeThread.PriorityLevel.NORM_PRIORITY.value);
    } else {
      inserter.start(false, this);
    }
  }

  /**
   * Starts a fetch request, scheduling on the persistence runner when the request is durable.
   *
   * <p>Persistent requests are queued to the database job runner to serialize state changes; purely
   * transient requests are started immediately. Failures for transient requests are surfaced on the
   * calling thread.
   *
   * @param getter The getter to start; must be configured and not already running.
   * @throws FetchException If the request is transient and fails to start due to validation or
   *     immediate setup conditions.
   * @throws PersistenceDisabledException If persistence was required but is disabled or unavailable
   *     at this time.
   */
  public void start(final ClientGetter getter) throws FetchException, PersistenceDisabledException {
    if (getter.persistent()) {
      jobRunner.queue(
          (PersistentJob)
              context -> {
                try {
                  getter.start(context);
                } catch (FetchException e) {
                  if (getter.clientCallback != null) {
                    getter.clientCallback.onFailure(e);
                  }
                }
                return true;
              },
          NativeThread.PriorityLevel.NORM_PRIORITY.value);
    } else {
      getter.start(this);
    }
  }

  /**
   * Starts a manifest-based (site) insert, deferring to the persistence runner when durable.
   *
   * <p>Persistent inserts are queued to the database job runner; transient inserts are started
   * immediately. Callers receive failures for transient inserts synchronously.
   *
   * @param inserter The manifest putter to start; must not have been started before.
   * @throws InsertException If the insert is transient and fails to start due to validation or
   *     immediate setup conditions.
   * @throws PersistenceDisabledException If persistence was required but is currently disabled or
   *     locked.
   */
  public void start(final BaseManifestPutter inserter)
      throws InsertException, PersistenceDisabledException {
    if (inserter.persistent()) {
      jobRunner.queue(
          (PersistentJob)
              context -> {
                try {
                  inserter.start(context);
                } catch (InsertException e) {
                  if (inserter.cb != null) {
                    inserter.cb.onFailure(e, inserter);
                  }
                }
                return true;
              },
          NativeThread.PriorityLevel.NORM_PRIORITY.value);
    } else {
      inserter.start(this);
    }
  }

  /**
   * Get the temporary bucket factory appropriate for a request.
   *
   * @param persistent If true, get the persistent temporary bucket factory. This creates buckets
   *     which persist across the restarts of the node. If false, get the temporary bucket factory,
   *     which creates buckets which will be deleted once the node is restarted.
   * @return The appropriate {@link BucketFactory} for the {@code persistent} setting.
   */
  public BucketFactory getBucketFactory(boolean persistent) {
    if (persistent) return persistentBucketFactory;
    else return tempBucketFactory;
  }

  /**
   * Get the RequestScheduler responsible for the given key type. This is used to queue low-level
   * requests.
   *
   * @param ssk If true, get the SSK request scheduler. If false, get the CHK request scheduler.
   * @param realTime If true, return the real-time scheduler variant; otherwise the bulk scheduler.
   * @return The {@link RequestScheduler} appropriate for the key type and mode.
   */
  public RequestScheduler getFetchScheduler(boolean ssk, boolean realTime) {
    if (ssk) return realTime ? sskFetchSchedulerRT : sskFetchSchedulerBulk;
    return realTime ? chkFetchSchedulerRT : chkFetchSchedulerBulk;
  }

  /**
   * Posts a user-facing alert. When the alert manager is not yet available, the alert is scheduled
   * to be posted as soon as initialization completes.
   *
   * @param alert The alert to register; must be a non-null instance.
   */
  public void postUserAlert(final UserAlert alert) {
    if (alerts == null) {
      // Wait until after startup
      ticker.queueTimedJob(() -> alerts.register(alert), "Post alert", 0L, false, false);
    } else {
      alerts.register(alert);
    }
  }

  /**
   * Sets the download cache reference used by client requests that support caching.
   *
   * @param cache Cache implementation to use for later downloads; may be {@code null} to disable
   *     caching.
   */
  public void setDownloadCache(DownloadCache cache) {
    this.downloadCache = cache;
  }

  /**
   * Returns the download cache currently configured for client requests.
   *
   * @return The active {@link DownloadCache}, or {@code null} when caching is disabled.
   */
  public DownloadCache getDownloadCache() {
    return downloadCache;
  }

  /**
   * Returns a copy of the default persistent fetch context. Callers receive an independent instance
   * and may adjust options without mutating the template.
   *
   * @return A new {@link FetchContext} derived from the default persistent template.
   */
  public FetchContext getDefaultPersistentFetchContext() {
    return new FetchContext(defaultPersistentFetchContext, FetchContext.IDENTICAL_MASK);
  }

  /**
   * Returns a copy of the default persistent insert context with a fresh event producer. Callers
   * may customize it for a specific request.
   *
   * @return A new {@link InsertContext} based on the persistent template.
   */
  public InsertContext getDefaultPersistentInsertContext() {
    return new InsertContext(defaultPersistentInsertContext, new SimpleEventProducer());
  }

  /**
   * Returns the job runner appropriate for the persistence mode.
   *
   * @param persistent {@code true} to get the persistence-serializing runner; {@code false} for the
   *     transient runner that starts work immediately.
   * @return The {@link PersistentJobRunner} matching the requested mode.
   */
  public PersistentJobRunner getJobRunner(boolean persistent) {
    return persistent ? jobRunner : dummyJobRunner;
  }

  /**
   * Returns the random-access file factory appropriate for the persistence mode.
   *
   * @param persistent {@code true} for the persistent factory; {@code false} for the transient
   *     factory.
   * @return The selected {@link FileRandomAccessBufferFactory}.
   */
  public FileRandomAccessBufferFactory getFileRandomAccessBufferFactory(boolean persistent) {
    return persistent ? fileRAFPersistent : fileRAFTransient;
  }

  /**
   * Returns a {@link LockableRandomAccessBufferFactory} suitable for the requested persistence
   * mode.
   *
   * @param persistent {@code true} for the persistent factory; {@code false} for the transient
   *     factory.
   * @return The selected {@link LockableRandomAccessBufferFactory}.
   */
  public LockableRandomAccessBufferFactory getRandomAccessBufferFactory(boolean persistent) {
    return persistent ? persistentRAFFactory : tempBucketFactory;
  }

  /**
   * Returns the effective configuration used by client-layer components.
   *
   * @return The immutable configuration reference backing this context.
   */
  public Config getConfig() {
    return config;
  }

  /**
   * Returns the main priority-aware executor for client-layer tasks.
   *
   * @return The executor used for general client scheduling outside persistence serialization.
   */
  public PriorityAwareExecutor getMainExecutor() {
    return mainExecutorInternal;
  }

  /**
   * Returns the tracker responsible for managing persistent files created by client operations.
   *
   * @return The current {@link PersistentFileTracker} instance.
   */
  @Override
  public PersistentFileTracker getPersistentFileTracker() {
    return persistentFileTracker;
  }

  /**
   * Updates the tracker responsible for persistent files created by client requests.
   *
   * @param tracker New persistent file tracker to use for later operations.
   */
  public void setPersistentFileTracker(PersistentFileTracker tracker) {
    this.persistentFileTracker = tracker;
  }
}

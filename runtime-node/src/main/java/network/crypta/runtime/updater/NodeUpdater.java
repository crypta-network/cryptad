package network.crypta.runtime.updater;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.concurrent.atomic.AtomicReference;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.FetchException;
import network.crypta.client.FetchResult;
import network.crypta.client.async.BinaryBlobWriter;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientGetCallback;
import network.crypta.client.async.ClientGetter;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.client.async.USKCallback;
import network.crypta.client.async.USKFoundEdition;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.USK;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.RequestClient;
import network.crypta.node.RequestStarter;
import network.crypta.support.Ticker;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.io.FileBucket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static java.util.concurrent.TimeUnit.SECONDS;

/**
 * Base class for components that subscribe to update keys, fetch new editions, and coordinate
 * post‑fetch processing.
 *
 * <p>This class encapsulates the common control flow used by updater components. It subscribes to a
 * USK, reacts to discovered editions, schedules and runs a {@code ClientGetter} fetch, and then
 * hands the result to subclass hooks for validation and deployment. Instances are long‑lived and
 * typically created once per updater type. They maintain internal state such as the latest
 * available and fetched versions, whether a fetch is currently in progress, and temporary file
 * paths used to persist fetched blobs.
 *
 * <p>Thread‑safety: the updater uses synchronized blocks to protect mutable fields that are shared
 * across callbacks (e.g., edition discovery, fetch success/failure). Subclasses should assume that
 * the abstract callbacks may be invoked from client layer threads and avoid blocking the ticker.
 * I/O is delegated to the client fetcher and to small, bounded parsing steps in this base class.
 * The class is mutable but designed to be driven by the node lifecycle.
 *
 * <ul>
 *   <li>Subscribes to a USK and tracks discovered editions.
 *   <li>Schedules fetches with suitable priorities and temporary file targets.
 *   <li>Provides hooks to parse manifests and process success after fetch completion.
 *   <li>Exposes helper accessors for blob files and progress reporting.
 * </ul>
 *
 * @see network.crypta.runtime.updater.CoreUpdater
 */
public abstract class NodeUpdater implements ClientGetCallback, USKCallback, RequestClient {
  private static final Logger LOG = LoggerFactory.getLogger(NodeUpdater.class);

  /** Maximum allowed manifest size to parse (1 MiB). */
  private static final long MAX_MANIFEST_SIZE = 1024L * 1024L;

  /** Maximum allowed compressed size of the manifest entry (1 MiB). */
  private static final long MAX_MANIFEST_COMPRESSED_SIZE = 1024L * 1024L;

  /** Maximum number of ZIP entries to scan while searching for the manifest. */
  private static final int MAX_ZIP_ENTRIES_SCANNED = 1024;

  /** Maximum number of compressed bytes to read from the ZIP stream overall. */
  private static final long MAX_ZIP_SCAN_BYTES = 16L * 1024L * 1024L; // 16 MiB

  /** Delay before retrying a fetch while the key is still in the recently-failed table. */
  private static final long RECENTLY_FAILED_RETRY_DELAY_MILLIS = SECONDS.toMillis(1);

  private final FetchContext ctx;
  private ClientGetter cg;
  private FreenetURI uri;
  private final Ticker ticker;

  /**
   * Owning client core used to create fetch contexts, schedule requests, and access alerts and
   * persistence. The reference is stable and not reassigned after construction.
   */
  public final NodeClientCore core;

  /**
   * Hosting node that provides environment information and directory paths. Subclasses use it for
   * follow‑up actions after a successful fetch.
   */
  protected final Node node;

  /**
   * Coordinator that owns and orchestrates updater instances. It controls enablement, auto‑update
   * policies, and top‑level alerting behavior across the application.
   */
  public final NodeUpdateManager manager;

  private final int currentVersion;
  private int realAvailableVersion;
  private int availableVersion;
  private int fetchingVersion;

  /**
   * Most recently fetched edition number. Increases as newer editions are downloaded and is used to
   * determine whether further fetches are necessary.
   */
  protected int fetchedVersion;

  private int maxDeployVersion;
  private int minDeployVersion;
  private volatile boolean isRunning;
  private boolean isFetching;
  private final String blobFilenamePrefix;

  /** Monotonic identity for the configured update-key subscription scope. */
  private long subscriptionGeneration;

  /** Per-fetch ownership metadata for the currently active fetch. */
  private FetchAttempt activeFetch;

  /** Monotonic identity for fetch-attempt ordering within and across subscription scopes. */
  private long fetchAttemptSequence;

  /**
   * Serializes USK subscription registration with shutdown.
   *
   * <p>This lock is deliberately separate from the updater monitor because the USK manager is
   * external code. If shutdown wins, a later start observes {@link #isRunning} as false and cannot
   * register a detached subscription. If start wins, shutdown waits for registration and then
   * unsubscribes it.
   */
  private final Object subscriptionLifecycleLock = new Object();

  /**
   * Temporary file used during the current fetch. On success, the file is renamed to a finalized
   * {@code .fblob}. Subclasses may read or delete it as part of deployment.
   */
  protected File tempBlobFile;

  /**
   * Returns a human‑readable name for the artifact handled by this updater.
   *
   * <p>The name appears in log messages and user alerts. Implementations typically return a concise
   * descriptor of the artifact being updated.
   *
   * @return a concise artifact name suitable for logs and UI; never {@code null}
   */
  public abstract String artifactName();

  NodeUpdater(NodeUpdaterParams params) {
    // Debug gating derives from LOG.isDebugEnabled() where needed
    this.manager = params.manager();
    this.node = manager.getNode();
    this.uri = params.updateUri().setSuggestedEdition(params.subscribeEditionSeed());
    this.ticker = node.network().ticker();
    this.core = node.services().clientCore();
    this.currentVersion = params.current();
    this.availableVersion = -1;
    this.isRunning = true;
    this.cg = null;
    this.isFetching = false;
    this.subscriptionGeneration = 0;
    this.activeFetch = null;
    this.fetchAttemptSequence = 0;
    this.blobFilenamePrefix = params.blobFilenamePrefix();
    this.maxDeployVersion = params.max();
    this.minDeployVersion = params.min();

    FetchContext tempContext = core.makeClient((short) 0, true, false).getFetchContext();
    tempContext.setAllowSplitfiles(true);
    tempContext.setDontEnterImplicitArchives(false);
    this.ctx = tempContext;
  }

  void start() {
    subscribe(() -> manager.blow("The auto-update URI isn't valid and can't be used", true));
  }

  private void subscribe(Runnable onError) {
    synchronized (subscriptionLifecycleLock) {
      if (!isRunning || isFetchingBlockedByManagerState()) {
        return;
      }
      try {
        FreenetURI localUri;
        synchronized (this) {
          localUri = this.uri;
        }
        USK myUsk = USK.create(localUri);
        core.getUskManager().subscribe(myUsk, this, true, getRequestClient());
      } catch (MalformedURLException _) {
        LOG.error("The auto-update URI isn't valid and can't be used");
        onError.run();
      }
    }
  }

  @Override
  public RequestClient getRequestClient() {
    return this;
  }

  @Override
  public void onFoundEdition(USKFoundEdition foundEdition) {
    if (foundEdition.newKnownGood() && !foundEdition.newSlotToo()) return;
    // Debug gating derives from LOG.isDebugEnabled() where needed
    if (LOG.isDebugEnabled()) LOG.debug("Found edition {}", foundEdition.edition());
    int found;
    synchronized (this) {
      if (!isRunning) return;
      found = (int) foundEdition.key().suggestedEdition;

      realAvailableVersion = found;
      if (found > maxDeployVersion) {
        if (LOG.isWarnEnabled())
          LOG.warn(
              "Ignoring {} update edition {}: version too new (min {} max {})",
              artifactName(),
              foundEdition.edition(),
              minDeployVersion,
              maxDeployVersion);
        found = maxDeployVersion;
      }

      found = selectDiscoveredEdition(found);

      if (found <= availableVersion) return;
      if (LOG.isInfoEnabled()) LOG.info("Found {} update edition {}", artifactName(), found);
      LOG.debug(
          "Updating availableVersion from {} to {} and queueing an update",
          availableVersion,
          found);
      this.availableVersion = found;
    }
    finishOnFoundEdition(found);
  }

  private void finishOnFoundEdition(int found) {
    ticker.queueTimedJob(
        this::maybeUpdate, SECONDS.toMillis(60)); // leave some time in case we get later editions
    // LOCKING: Always take the NodeUpdater lock *BEFORE* the NodeUpdateManager lock
    if (found <= currentVersion) {
      LOG.info("Cancelling fetch for {}: not newer than current version {}", found, currentVersion);
      return;
    }
    onStartFetching();
    if (LOG.isDebugEnabled()) LOG.debug("Fetching {} update edition {}", artifactName(), found);
  }

  /**
   * Hook invoked just before a new fetch is scheduled and started.
   *
   * <p>Implementations can use this callback to update the UI, reset flags, or perform lightweight
   * bookkeeping. The method must be fast and non‑blocking; heavy work should run after fetch
   * completion.
   */
  protected abstract void onStartFetching();

  /**
   * Attempts to start a fetch for the latest discovered edition.
   *
   * <p>The method skips when already fetching the same edition or when the edition is not newer. It
   * may cancel a stale fetch, prepare a new {@link ClientGetter}, and start it through the client
   * context. Repeated calls are safe; a new request starts only when the state warrants.
   */
  public void maybeUpdate() {
    ClientGetter toStart = null;
    if (!isFetchingEnabled()) return;
    if (isFetchingBlockedByManagerState()) return;
    ClientGetter cancelled = null;
    FetchAttempt cancelledAttempt = null;
    synchronized (this) {
      if (LOG.isDebugEnabled())
        LOG.debug(
            "maybeUpdate: isFetching={}, isRunning={}, availableVersion={}",
            isFetching,
            isRunning,
            availableVersion);

      if (shouldSkipUpdateLocked()) return;

      if (shouldCancelPreviousFetchLocked()) {
        LOG.info("Cancelling previous fetch");
        cancelled = cg;
        cancelledAttempt = activeFetch;
        cg = null;
        activeFetch = null;
      }

      fetchingVersion = availableVersion;
      logStartUpdateIfNeeded(availableVersion);

      try {
        toStart = prepareClientGetterIfNeeded(availableVersion);
        isFetching = true;
      } catch (Exception e) {
        LOG.error("Error while starting the fetching: {}", e, e);
        isFetching = false;
      }
    }

    if (toStart != null)
      try {
        node.services().clientCore().getClientContext().start(toStart);
      } catch (FetchException e) {
        LOG.error("Error while starting the fetching: {}", e, e);
        cleanupFailedStart(toStart);
      } catch (PersistenceDisabledException _) {
        cleanupFailedStart(toStart);
      }
    try {
      if (cancelled != null) cancelled.cancel(core.getClientContext());
    } catch (RuntimeException e) {
      LOG.debug("Unable to cancel replaced {} fetch", artifactName(), e);
    } finally {
      cleanupAttemptFile(cancelledAttempt, "after replacing fetch");
    }
  }

  /**
   * Returns whether this subscriber may fetch from its configured update-key document.
   *
   * <p>Package update subscribers follow the operator's updater enablement setting. Read-only
   * policy subscribers may override this gate when their security and support information must
   * remain current independently of package installation settings.
   *
   * @return {@code true} when this subscriber may start a fetch
   */
  protected boolean isFetchingEnabled() {
    return manager.isEnabled();
  }

  /**
   * Returns whether the manager's failure state blocks this subscriber's fetches.
   *
   * <p>Package update subscribers stop after any updater blow because package installation is no
   * longer safe. Read-only trust consumers may override this gate to distinguish a local package
   * updater failure from an authenticated compromise of the update key.
   *
   * @return {@code true} when this subscriber must not fetch in the current manager state
   */
  protected boolean isFetchingBlockedByManagerState() {
    return manager.isBlown();
  }

  private boolean shouldSkipUpdateLocked() {
    if (!isRunning) return true;
    if (isFetching && availableVersion == fetchingVersion) return true;
    return availableVersion <= fetchedVersion;
  }

  private boolean shouldCancelPreviousFetchLocked() {
    return fetchingVersion < minDeployVersion || fetchingVersion == currentVersion;
  }

  @SuppressWarnings("ReferenceEquality")
  private void cleanupFailedStart(ClientGetter failedGetter) {
    FetchAttempt failedAttempt = null;
    synchronized (this) {
      if (activeFetch != null && activeFetch.getter() == failedGetter && cg == failedGetter) {
        failedAttempt = activeFetch;
        detachActiveFetchLocked(activeFetch.tempBlobFile());
        isFetching = false;
      }
    }
    cleanupAttemptFile(failedAttempt, "after fetch start failure");
  }

  private void logStartUpdateIfNeeded(int version) {
    if (version > currentVersion) {
      LOG.info("Starting the update process ({})", version);
      LOG.info("Starting the update process: found the update ({}) now fetching it.", version);
    }
    if (LOG.isDebugEnabled()) LOG.debug("Starting the update process ({})", version);
  }

  private ClientGetter prepareClientGetterIfNeeded(int version) throws IOException {
    if ((cg == null) || cg.isCancelled()) {
      if (LOG.isDebugEnabled())
        LOG.debug("Scheduling request for {}", this.uri.setSuggestedEdition(version));
      if (version > currentVersion && LOG.isInfoEnabled())
        LOG.info("Starting {} fetch for {}", artifactName(), version);
      File newTempBlobFile =
          File.createTempFile(
              blobFilenamePrefix + version + "-",
              ".fblob.tmp",
              manager.getNode().services().clientCore().getPersistentTempDir());
      try {
        FreenetURI uskUri = this.uri.setSuggestedEdition(version);
        uskUri = uskUri.sskForUSK();
        long attemptSequence = fetchAttemptSequence + 1;
        FetchAttempt attempt =
            new FetchAttempt(
                this, newTempBlobFile, version, uskUri, subscriptionGeneration, attemptSequence);
        ClientGetter getter =
            new ClientGetter(
                attempt,
                uskUri,
                ctx,
                RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS,
                null,
                new BinaryBlobWriter(new FileBucket(newTempBlobFile, false, false, false, false)),
                null);
        attempt.bindGetter(getter);
        fetchAttemptSequence = attemptSequence;
        tempBlobFile = newTempBlobFile;
        cg = getter;
        activeFetch = attempt;
        return getter;
      } catch (RuntimeException e) {
        cleanupTempBlobFile(newTempBlobFile, "after fetch preparation failure");
        throw e;
      }
    } else {
      if (LOG.isInfoEnabled())
        LOG.info(
            "Already fetching {} fetch for {} want {}",
            artifactName(),
            fetchingVersion,
            availableVersion);
      return null;
    }
  }

  final File getBlobFile(int availableVersion) {
    return new File(
        node.services().clientCore().getPersistentTempDir(),
        blobFilenamePrefix + availableVersion + ".fblob");
  }

  @SuppressWarnings("unused")
  RandomAccessBucket getBlobBucket(int availableVersion) {
    File f = getBlobFile(availableVersion);
    return new FileBucket(f, true, false, false, false);
  }

  @Override
  @SuppressWarnings("ReferenceEquality")
  public void onSuccess(FetchResult result, ClientGetter state) {
    FetchAttempt attempt;
    File localTempBlobFile;
    int localFetchingVersion;
    long localSubscriptionGeneration;
    FreenetURI localUpdateKey;
    FreenetURI fetchedUri = state != null ? state.getURI() : null;
    synchronized (this) {
      // Callback ownership is an object-identity contract: an equal-looking getter from an old
      // subscription must never be allowed to commit into the active scope.
      attempt = activeFetch;
      if (state != null && (attempt == null || state != cg || state != attempt.getter())) {
        discardStaleResult(result);
        return;
      }
      localTempBlobFile = tempBlobFile;
      localFetchingVersion = fetchingVersion;
      localSubscriptionGeneration =
          state == null ? subscriptionGeneration : attempt.subscriptionGeneration();
      localUpdateKey = uri;
    }
    onSuccess(
        result,
        localTempBlobFile,
        localFetchingVersion,
        fetchedUri != null ? fetchedUri : localUpdateKey,
        localSubscriptionGeneration,
        attempt);
  }

  @SuppressWarnings("ReferenceEquality")
  private void onAttemptSuccess(
      FetchAttempt attempt, FetchResult result, ClientGetter callbackGetter) {
    if (callbackGetter != attempt.getter()) {
      discardStaleAttempt(result, attempt);
      return;
    }
    synchronized (this) {
      if (attempt != activeFetch
          || callbackGetter != cg
          || attempt.subscriptionGeneration() != subscriptionGeneration) {
        discardStaleAttempt(result, attempt);
        return;
      }
    }
    onSuccess(
        result,
        attempt.tempBlobFile(),
        attempt.fetchedVersion(),
        callbackGetter.getURI() != null ? callbackGetter.getURI() : attempt.fetchedUri(),
        attempt.subscriptionGeneration(),
        attempt);
  }

  void onSuccess(FetchResult result, File tempBlobFile, int fetchedVersion, FreenetURI fetchedUri) {
    long localSubscriptionGeneration;
    FreenetURI localUpdateKey;
    synchronized (this) {
      localSubscriptionGeneration = subscriptionGeneration;
      localUpdateKey = uri;
    }
    onSuccess(
        result,
        tempBlobFile,
        fetchedVersion,
        fetchedUri != null ? fetchedUri : localUpdateKey,
        localSubscriptionGeneration,
        null);
  }

  private void onSuccess(
      FetchResult result,
      File tempBlobFile,
      int fetchedVersion,
      FreenetURI fetchedUri,
      long fetchSubscriptionGeneration,
      FetchAttempt expectedAttempt) {
    FetchPreparation preparation =
        prepareFetchedResult(
            result, tempBlobFile, fetchedVersion, fetchSubscriptionGeneration, expectedAttempt);
    if (!preparation.readyForProcessing()) {
      return;
    }
    boolean accepted = processSuccess(fetchedVersion, result, preparation.blobFile());
    FetchCompletion completion =
        completeFetch(fetchedVersion, fetchSubscriptionGeneration, expectedAttempt, accepted);
    if (!completion.currentSubscription()) {
      return;
    }
    if (!accepted) {
      scheduleRejectedFetch(completion.ownsNewestAttempt());
      return;
    }
    if (!completion.acceptedAsNewestEdition()) {
      return;
    }
    logAcceptedFetch(fetchedVersion);
    recordSuccessfulFetch(fetchedUri, fetchedVersion);
    if (completion.fetchNextAvailableEdition()) {
      node.network().ticker().queueTimedJob(this::maybeUpdate, 0);
    }
  }

  private FetchPreparation prepareFetchedResult(
      FetchResult result,
      File tempBlobFile,
      int fetchedVersion,
      long fetchSubscriptionGeneration,
      FetchAttempt expectedAttempt) {
    synchronized (this) {
      if (isStaleFetchCompletion(fetchSubscriptionGeneration, expectedAttempt)) {
        discardStaleResult(result);
        cleanupTempBlobFile(tempBlobFile, "from superseded subscription");
        return FetchPreparation.SKIPPED;
      }
      if (shouldSkipAlreadyFetched(fetchedVersion)) {
        detachActiveFetchLocked(tempBlobFile);
        isFetching = false;
        cleanupAlreadyFetched(result, tempBlobFile);
        return FetchPreparation.SKIPPED;
      }
      if (isEmptyResult(result)) {
        detachActiveFetchLocked(tempBlobFile);
        isFetching = false;
        cleanupTempBlobFile(tempBlobFile, "after empty result");
        LOG.error("Cannot update: result either null or empty for {}", availableVersion);
        // Try again immediately; no need to inspect Bucket here
        node.network().ticker().queueTimedJob(this::maybeUpdate, 0);
        return FetchPreparation.SKIPPED;
      }
      File blobFile = tryFinalizeBlobFile(tempBlobFile, fetchedVersion);
      maybeParseManifest(result, fetchedVersion);
      detachActiveFetchLocked(tempBlobFile);
      return new FetchPreparation(true, blobFile);
    }
  }

  private boolean isStaleFetchCompletion(
      long fetchSubscriptionGeneration, FetchAttempt expectedAttempt) {
    return fetchSubscriptionGeneration != subscriptionGeneration
        || (expectedAttempt != null && expectedAttempt != activeFetch);
  }

  private FetchCompletion completeFetch(
      int fetchedVersion,
      long fetchSubscriptionGeneration,
      FetchAttempt expectedAttempt,
      boolean accepted) {
    boolean fetchNextAvailableEdition = false;
    boolean ownsNewestAttempt;
    boolean acceptedAsNewestEdition = false;
    synchronized (this) {
      if (fetchSubscriptionGeneration != subscriptionGeneration) {
        return FetchCompletion.STALE;
      }
      ownsNewestAttempt =
          expectedAttempt == null || expectedAttempt.sequence() == fetchAttemptSequence;
      if (ownsNewestAttempt) {
        isFetching = false;
      }
      if (accepted && fetchedVersion > this.fetchedVersion) {
        this.fetchedVersion = fetchedVersion;
        acceptedAsNewestEdition = true;
        if (fetchIntermediateEditionsSequentially() && fetchedVersion < realAvailableVersion) {
          availableVersion = fetchedVersion + 1;
        }
        fetchNextAvailableEdition = fetchedVersion < availableVersion;
      }
    }
    return new FetchCompletion(
        true, ownsNewestAttempt, acceptedAsNewestEdition, fetchNextAvailableEdition);
  }

  private void scheduleRejectedFetch(boolean ownsNewestAttempt) {
    if (!ownsNewestAttempt) {
      return;
    }
    long retryDelay = rejectedFetchRetryDelayMillis();
    if (retryDelay < 0) {
      return;
    }
    node.network().ticker().queueTimedJob(this::maybeUpdate, retryDelay);
  }

  private void logAcceptedFetch(int fetchedVersion) {
    if (!LOG.isInfoEnabled()) {
      return;
    }
    LOG.info("Found {} version {}", artifactName(), fetchedVersion);
    if (fetchedVersion > currentVersion) {
      LOG.info("Accepted {} edition {}", artifactName(), fetchedVersion);
    }
  }

  private record FetchPreparation(boolean readyForProcessing, File blobFile) {
    private static final FetchPreparation SKIPPED = new FetchPreparation(false, null);
  }

  private record FetchCompletion(
      boolean currentSubscription,
      boolean ownsNewestAttempt,
      boolean acceptedAsNewestEdition,
      boolean fetchNextAvailableEdition) {
    private static final FetchCompletion STALE = new FetchCompletion(false, false, false, false);
  }

  /**
   * Selects which edition to fetch when a subscription announces a newer highest known edition.
   *
   * <p>Most updater documents are independent and use the announced edition directly. Digest-chain
   * consumers may override this to fetch an authenticated missing successor first.
   *
   * @param discoveredEdition highest bounded edition announced by the subscription
   * @return positive edition to make available for the next fetch
   */
  protected int selectDiscoveredEdition(int discoveredEdition) {
    return discoveredEdition;
  }

  /**
   * Returns whether accepted editions should catch up one at a time to the highest announcement.
   *
   * @return {@code true} only for formats whose immediate-predecessor digest must be verified
   */
  protected boolean fetchIntermediateEditionsSequentially() {
    return false;
  }

  /**
   * Records an accepted fetched edition for restart seeding.
   *
   * <p>The default preserves core-info persistence. Updaters with an independent edition space and
   * durable last-known-good store override this hook so their editions cannot contaminate the
   * core-info build-number seed.
   *
   * @param fetchedUri exact public fetch URI used for the accepted edition
   * @param fetchedEdition accepted USK edition number
   */
  protected void recordSuccessfulFetch(FreenetURI fetchedUri, int fetchedEdition) {
    manager.recordSuccessfulCoreInfoFetch(fetchedUri, fetchedEdition);
  }

  /**
   * Returns the delay before fetching a rejected post-fetch result again.
   *
   * <p>The default avoids repeatedly fetching immutable invalid editions. Implementations may
   * return a non-negative delay for transient local failures such as an unavailable persistence
   * filesystem. Implementations own their retry policy and should back off repeated failures rather
   * than creating a tight fetch-and-process loop.
   *
   * @return retry delay in milliseconds, or a negative value to wait for another external event
   */
  protected long rejectedFetchRetryDelayMillis() {
    return -1;
  }

  private boolean shouldSkipAlreadyFetched(int fetchedVersion) {
    return fetchedVersion <= this.fetchedVersion;
  }

  private void cleanupAlreadyFetched(FetchResult result, File tmp) {
    cleanupTempBlobFile(tmp, "for already-fetched edition");
    if (result != null) {
      Bucket toFree = result.asBucket();
      if (toFree != null) {
        try (var _ = toFree) {
          if (LOG.isDebugEnabled()) LOG.debug("Releasing fetched result bucket");
        }
      }
    }
  }

  /** Releases fetched bytes delivered by a callback from a superseded subscription scope. */
  private void discardStaleResult(FetchResult result) {
    if (result == null) {
      return;
    }
    Bucket toFree = result.asBucket();
    if (toFree == null) {
      return;
    }
    try (toFree) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Discarding fetched result from a superseded {} scope", artifactName());
      }
    }
  }

  /** Releases fetched bytes and the exact temporary file owned by a superseded fetch. */
  private void discardStaleAttempt(FetchResult result, FetchAttempt attempt) {
    discardStaleResult(result);
    cleanupAttemptFile(attempt, "from superseded fetch");
  }

  private void detachActiveFetchLocked(File ownedTempBlobFile) {
    assert Thread.holdsLock(this);
    if (activeFetch != null && activeFetch.tempBlobFile().equals(ownedTempBlobFile)) {
      activeFetch = null;
      cg = null;
      tempBlobFile = null;
    }
  }

  private static void cleanupAttemptFile(FetchAttempt attempt, String context) {
    if (attempt != null) {
      cleanupTempBlobFile(attempt.tempBlobFile(), context);
    }
  }

  private static void cleanupTempBlobFile(File file, String context) {
    if (file == null) {
      return;
    }
    try {
      Files.deleteIfExists(file.toPath());
    } catch (IOException ex) {
      LOG.warn("Unable to delete temp blob {} {}", file, context, ex);
    }
  }

  private boolean isEmptyResult(FetchResult result) {
    return result == null || result.size() == 0;
  }

  private File tryFinalizeBlobFile(File tmp, int fetchedVersion) {
    File blobFile = getBlobFile(fetchedVersion);
    if (!tmp.renameTo(blobFile)) {
      try {
        Files.delete(blobFile.toPath());
      } catch (IOException ex) {
        LOG.warn("Unable to delete blob file {} before rename", blobFile, ex);
      }
      if (!tmp.renameTo(blobFile)) {
        if (blobFile.exists() && tmp.exists() && blobFile.length() == tmp.length()) {
          if (LOG.isDebugEnabled())
            LOG.debug(
                "Can't rename {} over {} for {} - probably not a big deal though as the files are"
                    + " the same size",
                tmp,
                blobFile,
                fetchedVersion);
        } else {
          LOG.error(
              "Not able to rename binary blob for node updater: {} -> {} - may not be able to"
                  + " tell other peers about this build",
              tmp,
              blobFile);
          blobFile = null;
        }
      }
    }
    return blobFile;
  }

  /**
   * Called after transport fetch completion to validate and perform post-processing.
   *
   * <p>Implementations typically validate compatibility, persist or rename files, update alerts,
   * and schedule deployment. The base class advances its accepted fetched edition only when this
   * method returns {@code true}.
   *
   * @param fetched the fetched edition number whose transport fetch completed; strictly positive
   * @param result the fetch result containing the fetched bytes and associated metadata
   * @param blobFile the finalized on‑disk blob, or {@code null} when the rename failed
   * @return {@code true} only when validation and required persistence have completed successfully
   */
  protected abstract boolean processSuccess(int fetched, FetchResult result, File blobFile);

  /**
   * Parses metadata from the freshly fetched result while internal locks are held.
   *
   * <p>The base class does not interpret manifest contents. Subclasses may extract version
   * requirements or other indicators from the fetched data. Implementations should limit work to
   * fast parsing and avoid blocking.
   *
   * @param result the fresh fetch result to inspect; must reference the just‑fetched bytes
   * @param build the edition number associated with {@code result}; used for logging and gating
   */
  protected abstract void maybeParseManifest(FetchResult result, int build);

  /**
   * Parses the JAR manifest from the finalized on‑disk blob.
   *
   * <p>This fallback path is used when a subclass needs to read the manifest after the blob has
   * been finalized on disk. The implementation enforces bounded parsing and delegates each line to
   * {@link #parseManifestLine(String)}.
   */
  @SuppressWarnings("unused")
  protected void parseManifest() {
    // Fallback: parse from the finalized on-disk blob if available, enforcing size cap.
    File jarFile = getBlobFile();
    try (InputStream is = Files.newInputStream(jarFile.toPath())) {
      parseManifestBounded(is);
    } catch (IOException _) {
      LOG.error("IOException trying to read manifest on update");
    } catch (Exception t) {
      LOG.error("Failed to parse update manifest: {}", t, t);
    }
  }

  /**
   * Parses the JAR manifest directly from the freshly fetched bytes.
   *
   * <p>This is preferred over reading from disk because it remains robust when the temporary file
   * cannot be renamed to its final location. Parsing is bounded for safety.
   *
   * @param result a non‑empty {@link FetchResult} containing the fetched JAR bytes
   */
  @SuppressWarnings({"resource", "java:S2095", "unused"})
  protected void parseManifest(FetchResult result) {
    if (result == null || result.size() == 0) return;
    Bucket bucket = result.asBucket();
    if (bucket == null) return;
    // Borrow the bucket for reading only; do NOT close/free it here because
    // subclasses may retain the FetchResult for later deployment handling.
    try (InputStream is = bucket.getInputStream()) {
      parseManifestBounded(is);
    } catch (IOException _) {
      LOG.error("IOException trying to read manifest from fetched result on update");
    } catch (Exception t) {
      LOG.error("Failed to parse update manifest from fetched result: {}", t, t);
    }
  }

  /**
   * Reads {@code META-INF/MANIFEST.MF} from a ZIP/JAR input stream with strict bounds.
   *
   * <p>The method limits the total number of scanned entries, caps compressed and uncompressed
   * sizes, and stops reading once the manifest has been processed. Parsed lines are dispatched to
   * {@link #parseManifestLine(String)} for interpretation.
   *
   * @param raw the input stream positioned at the start of a ZIP/JAR archive; not closed here
   * @throws IOException if an I/O error occurs while reading from the stream
   */
  @SuppressWarnings("java:S5042")
  private void parseManifestBounded(InputStream raw) throws IOException {
    InputStream bounded = new BoundedInputStream(raw, MAX_ZIP_SCAN_BYTES);
    try (ZipInputStream zis = new ZipInputStream(bounded)) {
      ZipEntry entry;
      int scanned = 0;
      while ((entry = zis.getNextEntry()) != null) {
        if (++scanned > MAX_ZIP_ENTRIES_SCANNED) {
          LOG.error("Too many ZIP entries scanned (>{}); aborting parse", MAX_ZIP_ENTRIES_SCANNED);
          return;
        }
        if (isManifestEntry(entry.getName())) {
          byte[] data = readManifestBytes(zis, entry);
          if (data.length == 0) {
            zis.closeEntry();
            return; // size cap exceeded or IO error already logged
          }
          dispatchManifestLines(data);
          zis.closeEntry();
          return; // Done after parsing manifest
        }
      }
    }
  }

  /**
   * Wraps an {@link InputStream} and limits the total number of bytes that can be read. Once the
   * limit is reached, later reads return {@code -1} (EOF). This protects callers against zip bombs
   * and other excessive input sizes when reading untrusted data.
   */
  private static final class BoundedInputStream extends java.io.FilterInputStream {
    private long remaining;

    BoundedInputStream(InputStream in, long limit) {
      super(in);
      this.remaining = Math.max(0L, limit);
    }

    @Override
    public int read() throws IOException {
      if (remaining <= 0) return -1;
      int b = super.read();
      if (b != -1) remaining--;
      return b;
    }

    @Override
    public int read(byte @org.jetbrains.annotations.NotNull [] b, int off, int len)
        throws IOException {
      if (remaining <= 0) return -1;
      int toRead = (int) Math.min(len, remaining);
      int r = super.read(b, off, toRead);
      if (r > 0) remaining -= r;
      return r;
    }

    @Override
    public long skip(long n) throws IOException {
      long toSkip = Math.min(n, remaining);
      long skipped = super.skip(toSkip);
      if (skipped > 0) remaining -= skipped;
      return skipped;
    }
  }

  /**
   * Returns whether the supplied ZIP entry name refers to the manifest file.
   *
   * @param name entry name as returned by the ZIP stream; case‑insensitive comparison is used
   * @return {@code true} if the entry is the manifest; otherwise {@code false}
   */
  private static boolean isManifestEntry(String name) {
    return "META-INF/MANIFEST.MF".equalsIgnoreCase(name);
  }

  /**
   * Reads the manifest entry into memory enforcing compressed and uncompressed size caps.
   *
   * @param zis the zip input stream positioned at the manifest entry
   * @param entry the manifest entry with metadata such as declared sizes
   * @return a non‑{@code null} byte array containing the manifest contents, or an empty array when
   *     caps are exceeded
   * @throws IOException if reading from the underlying stream fails
   */
  private byte[] readManifestBytes(ZipInputStream zis, ZipEntry entry) throws IOException {
    long declared = entry.getSize();
    if (declared > MAX_MANIFEST_SIZE) {
      LOG.error(
          "Manifest too large ({} bytes > {} cap); aborting parse", declared, MAX_MANIFEST_SIZE);
      return new byte[0];
    }
    long compressed = entry.getCompressedSize();
    if (compressed > MAX_MANIFEST_COMPRESSED_SIZE) {
      LOG.error(
          "Compressed manifest too large ({} bytes > {} cap); aborting parse",
          compressed,
          MAX_MANIFEST_COMPRESSED_SIZE);
      return new byte[0];
    }
    byte[] buf = new byte[8192];
    long total = 0L;
    java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
    int r;
    while ((r = zis.read(buf)) != -1) {
      total += r;
      if (total > MAX_MANIFEST_SIZE) {
        LOG.error("Manifest exceeds size cap (>{} bytes); aborting parse", MAX_MANIFEST_SIZE);
        return new byte[0];
      }
      bos.write(buf, 0, r);
    }
    return bos.toByteArray();
  }

  /**
   * Splits the provided manifest bytes into UTF‑8 lines and dispatches them to {@link
   * #parseManifestLine(String)}.
   *
   * @param data the manifest contents encoded as UTF‑8; may be empty to indicate prior failure
   * @throws IOException if the bytes cannot be decoded or the reader fails
   */
  private void dispatchManifestLines(byte[] data) throws IOException {
    try (BufferedReader br =
        new BufferedReader(
            new InputStreamReader(new ByteArrayInputStream(data), StandardCharsets.UTF_8))) {
      String line;
      while ((line = br.readLine()) != null) {
        parseManifestLine(line);
      }
    }
  }

  // Legacy dependencies.properties parsing hooks removed.

  /**
   * Interprets a single manifest line parsed by {@link #parseManifest()} or {@link
   * #parseManifest(FetchResult)}.
   *
   * <p>The base implementation is no‑op. Subclasses override to capture values relevant to their
   * compatibility or deployment logic. The {@code line} does not include a trailing newline.
   *
   * @param line a single raw manifest line to interpret; never {@code null}
   */
  @SuppressWarnings("unused")
  protected void parseManifestLine(String line) {
    // Do nothing by default; subclasses override if they need to parse manifest entries.
  }

  @Override
  public void onFailure(FetchException e) {
    FetchAttempt attempt;
    synchronized (this) {
      attempt = activeFetch;
    }
    if (attempt != null) {
      onAttemptFailure(attempt, e);
      return;
    }
    onUnownedFailure(e);
  }

  @SuppressWarnings("ReferenceEquality")
  private void onAttemptFailure(FetchAttempt attempt, FetchException e) {
    boolean owned;
    synchronized (this) {
      owned =
          isRunning
              && attempt == activeFetch
              && attempt.getter() == cg
              && attempt.subscriptionGeneration() == subscriptionGeneration;
      if (owned) {
        detachActiveFetchLocked(attempt.tempBlobFile());
        isFetching = false;
        if (e.isFatal() && e.getMode() != FetchExceptionMode.CANCELLED) {
          rearmSequentialEditionAfterFatalFailureLocked();
        }
      }
    }
    cleanupAttemptFile(attempt, owned ? "on failure" : "from superseded failure");
    if (!owned) {
      return;
    }
    finishFailure(e, attempt.getter());
  }

  private void onUnownedFailure(FetchException e) {
    // Debug gating derives from LOG.isDebugEnabled() where needed
    if (!isRunning) return;
    FetchExceptionMode errorCode = e.getMode();
    boolean shouldReschedule = errorCode == FetchExceptionMode.CANCELLED || !e.isFatal();

    File localTempBlobFile;
    ClientGetter localCg;
    synchronized (this) {
      localTempBlobFile = tempBlobFile;
      localCg = this.cg;
      this.cg = null;
      isFetching = false;
      if (!shouldReschedule) rearmSequentialEditionAfterFatalFailureLocked();
    }

    cleanupTempBlobFile(localTempBlobFile, "on failure");
    finishFailure(e, localCg);
  }

  private void finishFailure(FetchException e, ClientGetter failedGetter) {
    FetchExceptionMode errorCode = e.getMode();
    boolean shouldReschedule = errorCode == FetchExceptionMode.CANCELLED || !e.isFatal();
    if (LOG.isDebugEnabled()) LOG.debug("onFailure({},{})", e, failedGetter);
    if (shouldReschedule) {
      long retryDelay = retryDelayForFailure(errorCode);
      LOG.info("Rescheduling update request after {} with delay {} ms", errorCode, retryDelay);
      ticker.queueTimedJob(this::maybeUpdate, retryDelay);
    } else {
      LOG.error("Canceling fetch : {}", e.getMessage());
      LOG.error("Unexpected error fetching update: {}", e.getMessage());
      // Fatal error: wait for the next version; do not reschedule now.
    }
  }

  /**
   * Makes a fatally failed intermediate edition eligible for a later key announcement.
   *
   * <p>The method deliberately does not queue a retry. Digest-chained subscribers wait until the
   * update key is announced again, while ordinary latest-edition subscribers retain their existing
   * fatal-failure behavior.
   */
  private void rearmSequentialEditionAfterFatalFailureLocked() {
    assert Thread.holdsLock(this);
    if (!fetchIntermediateEditionsSequentially()) {
      return;
    }
    if (availableVersion == fetchingVersion && fetchingVersion > fetchedVersion) {
      availableVersion = fetchedVersion;
    }
  }

  private static long retryDelayForFailure(FetchExceptionMode errorCode) {
    return errorCode == FetchExceptionMode.RECENTLY_FAILED ? RECENTLY_FAILED_RETRY_DELAY_MILLIS : 0;
  }

  /** Called before {@link #kill()} to mark the updater as stopping. Avoids taking locks. */
  public void preKill() {
    isRunning = false;
  }

  /** Cancels any active fetch and unsubscribes from the USK. Safe to call multiple times. */
  void kill() {
    stopSubscription();
  }

  private void stopSubscription() {
    synchronized (subscriptionLifecycleLock) {
      ClientGetter stoppedGetter;
      FetchAttempt stoppedAttempt;
      FreenetURI stoppedUri;
      synchronized (this) {
        isRunning = false;
        subscriptionGeneration++;
        stoppedUri = this.uri;
        stoppedGetter = cg;
        stoppedAttempt = activeFetch;
        cg = null;
        activeFetch = null;
        tempBlobFile = null;
        isFetching = false;
      }
      try {
        USK myUsk = USK.create(stoppedUri.setSuggestedEdition(currentVersion));
        core.getUskManager().unsubscribe(myUsk, this);
      } catch (Exception e) {
        LOG.debug("Cannot unsubscribe stopped {} updater", artifactName(), e);
      }
      try {
        if (stoppedGetter != null) {
          stoppedGetter.cancel(core.getClientContext());
        }
      } catch (RuntimeException e) {
        LOG.debug("Cannot cancel stopped {} fetch", artifactName(), e);
      } finally {
        cleanupAttemptFile(stoppedAttempt, "while stopping updater");
      }
    }
  }

  /**
   * Returns the USK {@link FreenetURI} used to discover update editions for this updater.
   *
   * @return the immutable update key associated with this updater instance
   */
  @SuppressWarnings("unused")
  public synchronized FreenetURI getUpdateKey() {
    return this.uri;
  }

  /**
   * Reports whether a fetched edition newer than the current version is available for deployment.
   *
   * @return {@code true} when a newer fetched version exists; otherwise {@code false}
   */
  public synchronized boolean canUpdateNow() {
    return fetchedVersion > currentVersion;
  }

  /**
   * Called when the fetch URI has changed. The caller holds no major locks.
   *
   * @param newUri the new update key; its doc name is preserved when the argument omits one
   * @param subscribeEditionSeed edition to use when subscribing to the new update key
   */
  public void onChangeURI(FreenetURI newUri, int subscribeEditionSeed) {
    String previousDocName;
    synchronized (this) {
      previousDocName = (this.uri != null) ? this.uri.getDocName() : null;
    }
    stopSubscription();
    FreenetURI nextUri =
        (previousDocName != null && (newUri.getDocName() == null || newUri.getDocName().isEmpty()))
            ? newUri.setDocName(previousDocName)
            : newUri;
    synchronized (this) {
      this.uri = nextUri.setSuggestedEdition(subscribeEditionSeed);
      subscriptionGeneration++;
      activeFetch = null;
      availableVersion = -1;
      realAvailableVersion = -1;
      fetchingVersion = -1;
      fetchedVersion = fetchedEditionAfterUriChange(subscribeEditionSeed);
      isFetching = false;
      isRunning = true;
    }
    subscribe(() -> {});
    maybeUpdate();
  }

  /**
   * Selects the accepted-edition marker retained when a subscription URI changes.
   *
   * <p>Ordinary update descriptors are reset to the running build. Digest-chained subscribers may
   * override this hook when their separately persisted last-known-good state remains authoritative
   * across the new subscription.
   *
   * @param subscribeEditionSeed edition used to seed the replacement subscription
   * @return accepted edition to retain before processing announcements from the replacement URI
   */
  protected int fetchedEditionAfterUriChange(int subscribeEditionSeed) {
    return currentVersion;
  }

  /**
   * Returns the most recently fetched edition number.
   *
   * @return the last successfully fetched edition, or the current version when none were fetched
   */
  public synchronized int getFetchedVersion() {
    return fetchedVersion;
  }

  /**
   * Indicates whether a fetch for a newer edition is currently in progress.
   *
   * @return {@code true} if a fetch is active for a newer edition; otherwise {@code false}
   */
  public synchronized boolean isFetching() {
    return isRunning && availableVersion > fetchedVersion && availableVersion > currentVersion;
  }

  /**
   * Returns the edition number currently being fetched, or the latest available edition.
   *
   * @return an edition number used for progress reporting; never less than the current version
   */
  public synchronized int fetchingVersion() {
    // We will not deploy the currentVersion...
    if (fetchingVersion <= currentVersion) return availableVersion;
    else return fetchingVersion;
  }

  /**
   * Returns the size in bytes of the finalized blob corresponding to the fetched version.
   *
   * @return a non‑negative size of the blob on disk; {@code 0} when the file is missing
   */
  @SuppressWarnings("unused")
  public long getBlobSize() {
    return getBlobFile(getFetchedVersion()).length();
  }

  /**
   * Returns the path to the finalized blob file for the fetched version.
   *
   * @return a {@link File} pointing at the {@code .fblob} for the fetched edition
   */
  public File getBlobFile() {
    return getBlobFile(getFetchedVersion());
  }

  /** {@inheritDoc} */
  @Override
  public short getPollingPriorityNormal() {
    return RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS;
  }

  /** {@inheritDoc} */
  @Override
  public short getPollingPriorityProgress() {
    return RequestStarter.INTERACTIVE_PRIORITY_CLASS;
  }

  /** {@inheritDoc} */
  @Override
  public boolean persistent() {
    return false;
  }

  /**
   * Called by {@link NodeUpdateManager} to update the minimum and maximum deployable versions.
   *
   * <p>This method is invoked when a new core JAR has been downloaded so that the node avoids
   * installing incompatible combinations of main and extension artifacts. If the new bounds make a
   * previously out‑of‑range edition acceptable, a fetch may be scheduled.
   *
   * @param requiredExt the lower bound (inclusive) for acceptable editions; negative values mean
   *     “unchanged”
   * @param recommendedExt the upper bound (inclusive) for acceptable editions; negative values mean
   *     “unchanged”
   */
  @SuppressWarnings("unused")
  public void setMinMax(int requiredExt, int recommendedExt) {
    int callFinishedFound = -1;
    synchronized (this) {
      if (recommendedExt > -1) {
        maxDeployVersion = recommendedExt;
      }
      if (requiredExt > -1) {
        minDeployVersion = requiredExt;
        if (realAvailableVersion != availableVersion
            && availableVersion < requiredExt
            && realAvailableVersion >= requiredExt) {
          // We found a revision but didn't fetch it because it wasn't within the range for the old
          // jar.
          // The new one requires it, however.
          LOG.info(
              "Previously out-of-range edition {} is now needed by the new jar; scheduling fetch.",
              realAvailableVersion);
          callFinishedFound = availableVersion = realAvailableVersion;
        } else if (availableVersion < requiredExt) {
          // Including if it hasn't been found at all,
          // Just try it ...
          callFinishedFound = availableVersion = requiredExt;
          LOG.info(
              "Need minimum edition {} for new jar, found {}; scheduling fetch.",
              requiredExt,
              availableVersion);
        }
      }
    }
    if (callFinishedFound > -1) finishOnFoundEdition(callFinishedFound);
  }

  @Override
  public boolean realTimeFlag() {
    return false;
  }

  /** Immutable fetch resources captured by the callback that owns them. */
  private static final class FetchAttempt implements ClientGetCallback {
    private final NodeUpdater owner;
    private final File tempBlobFile;
    private final int fetchedVersion;
    private final FreenetURI fetchedUri;
    private final long subscriptionGeneration;
    private final long sequence;
    private final AtomicReference<ClientGetter> getter = new AtomicReference<>();

    private FetchAttempt(
        NodeUpdater owner,
        File tempBlobFile,
        int fetchedVersion,
        FreenetURI fetchedUri,
        long subscriptionGeneration,
        long sequence) {
      this.owner = owner;
      this.tempBlobFile = tempBlobFile;
      this.fetchedVersion = fetchedVersion;
      this.fetchedUri = fetchedUri;
      this.subscriptionGeneration = subscriptionGeneration;
      this.sequence = sequence;
    }

    private void bindGetter(ClientGetter getter) {
      if (!this.getter.compareAndSet(null, getter)) {
        throw new IllegalStateException("fetch getter is already bound");
      }
    }

    private ClientGetter getter() {
      return getter.get();
    }

    private File tempBlobFile() {
      return tempBlobFile;
    }

    private int fetchedVersion() {
      return fetchedVersion;
    }

    private FreenetURI fetchedUri() {
      return fetchedUri;
    }

    private long subscriptionGeneration() {
      return subscriptionGeneration;
    }

    private long sequence() {
      return sequence;
    }

    @Override
    public void onSuccess(FetchResult result, ClientGetter state) {
      owner.onAttemptSuccess(this, result, state);
    }

    @Override
    public void onFailure(FetchException e) {
      owner.onAttemptFailure(this, e);
    }

    @Override
    public void onResume(ClientContext context) {
      owner.onResume(context);
    }

    @Override
    public RequestClient getRequestClient() {
      return owner.getRequestClient();
    }
  }

  @Override
  public void onResume(ClientContext context) {
    // Do nothing. Not persistent.
  }
}

package network.crypta.node.updater;

import static java.util.concurrent.TimeUnit.SECONDS;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.FetchResult;
import network.crypta.client.async.BinaryBlobWriter;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientGetCallback;
import network.crypta.client.async.ClientGetter;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.NodeClientCore;
import network.crypta.node.RequestClient;
import network.crypta.node.RequestStarter;
import network.crypta.support.MediaType;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.api.RandomAccessBuffer;
import network.crypta.support.io.ArrayBucket;
import network.crypta.support.io.BucketTools;
import network.crypta.support.io.ByteArrayRandomAccessBuffer;
import network.crypta.support.io.FileBucket;
import network.crypta.support.io.FileRandomAccessBuffer;
import network.crypta.support.io.FileUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Monitors and fetches the auto‑update revocation message for this node.
 *
 * <p>This component issues lightweight fetches for the revocation URI configured in {@link
 * NodeUpdateManager}. Each time it is started it keeps attempting the fetch until it has observed
 * the configured minimum number of consecutive {@code DATA_NOT_FOUND} results. If the revocation
 * object is ever successfully retrieved, the checker immediately propagates the message to the
 * {@link NodeUpdateManager} and marks the update system as blown (revoked).
 *
 * <p>Typical usage is to construct a single instance tied to the lifetime of {@link
 * NodeUpdateManager}, then call {@link #start(boolean)} on startup and whenever the revocation URI
 * changes. The checker manages its own request state and ensures that low‑priority fetches are
 * replaced by aggressive ones after a successful core update.
 *
 * <p>Concurrency: instances are not immutable, but the critical fields are guarded internally.
 * Methods that mutate state take care to synchronize where required. Callers do not need to add
 * external synchronization beyond holding a single instance per manager. The class is designed for
 * use from the node’s coordinator threads rather than from arbitrary background threads.
 *
 * <ul>
 *   <li>Retries: counts consecutive {@code DATA_NOT_FOUND} outcomes and records the last time the
 *       minimum threshold was met.
 *   <li>Result handling: on success, stores the fetched blob to disk and notifies the manager.
 *   <li>Safety: does not follow redirects and enforces tight size limits for quick failure.
 * </ul>
 *
 * @see NodeUpdateManager
 */
public class RevocationChecker implements ClientGetCallback, RequestClient {
  private static final Logger LOG = LoggerFactory.getLogger(RevocationChecker.class);

  /**
   * Minimum number of consecutive {@code DATA_NOT_FOUND} observations before a fetch attempt is
   * considered complete.
   *
   * <p>This threshold determines when the checker stops the current cycle of attempts and records
   * the {@linkplain #lastSucceeded last completion time}. It does not disable future checks; a new
   * {@link #start(boolean)} invocation will begin a fresh cycle. The value is read by callers for
   * display and diagnostics and should be treated as a stable API constant.
   */
  public static final int REVOCATION_DNF_MIN = 3;

  private final NodeUpdateManager manager;
  private final NodeClientCore core;
  private int revocationDNFCounter;
  private final FetchContext ctxRevocation;
  private ClientGetter revocationGetter;
  private boolean wasAggressive;

  /** Last time at which we got 3 DNFs on the revocation key */
  private long lastSucceeded;

  // Kept separately from NodeUpdateManager.hasBeenBlown because there are local problems that can
  // blow the key.
  private volatile boolean blown;

  private final File blobFile;

  /** The original binary blob bucket. */
  private ArrayBucket blobBucket;

  /**
   * Creates a checker bound to the given update manager and on‑disk blob location.
   *
   * <p>The {@code blobFile} designates where a successfully fetched revocation message is persisted
   * so that it can be read again after restarts. The file is also consulted on startup by {@link
   * #start(boolean)} to allow the manager to process any previously downloaded revocation message.
   *
   * @param manager the owning {@link NodeUpdateManager}; used for configuration, logging context,
   *     and to receive blow notifications. Must not be {@code null}.
   * @param blobFile the file where the fetched revocation blob is stored and retrieved after
   *     restarts. The path must be writable by the process; if it is not, the checker logs a
   *     warning and continues without persisting the blob.
   */
  public RevocationChecker(NodeUpdateManager manager, File blobFile) {
    this.manager = manager;
    core = manager.getNode().getClientCore();
    this.revocationDNFCounter = 0;
    this.blobFile = blobFile;
    // Debug gating derives from LOG.isDebugEnabled() where needed
    ctxRevocation = core.makeClient((short) 0, true, false).getFetchContext();
    // Do not allow redirects etc.
    // If we allow redirects then it will take too long to download the revocation.
    // Anyone inserting it should be aware of this fact!
    // You must insert with no content type, and be less than the size limit, and less than the
    // block size after compression!
    // If it doesn't fit, we'll still tell the user, but the message may not be easily readable.
    ctxRevocation.setAllowSplitfiles(false);
    ctxRevocation.setMaxArchiveLevels(0);
    ctxRevocation.setFollowRedirects(false);
    // big enough ?
    ctxRevocation.setMaxOutputLength(NodeUpdateManager.MAX_REVOCATION_KEY_LENGTH);
    ctxRevocation.setMaxTempLength(NodeUpdateManager.MAX_REVOCATION_KEY_TEMP_LENGTH);
    // if we find content, try forever to get it; not used because of the above size limits.
    ctxRevocation.setMaxSplitfileBlockRetries(-1);
    ctxRevocation.setMaxNonSplitfileRetries(0); // but return quickly normally
  }

  /**
   * Returns the current count of consecutive {@code DATA_NOT_FOUND} results for the revocation
   * fetch cycle.
   *
   * <p>The counter resets to zero when {@link #start(boolean, boolean)} is invoked with {@code
   * reset = true} or after the threshold defined by {@link #REVOCATION_DNF_MIN} is reached and
   * recorded. Callers typically use this for diagnostics or for surfacing lightweight status to
   * users.
   *
   * @return the number of consecutive {@code DATA_NOT_FOUND} observations since the last reset or
   *     completion; never negative.
   */
  public int getRevocationDNFCounter() {
    return revocationDNFCounter;
  }

  /**
   * Starts a revocation fetch cycle with the default reset behavior.
   *
   * <p>When invoked, the checker schedules a new fetch. If a previous low‑priority request is still
   * running and {@code aggressive} is {@code true}, that request is cancelled and replaced with an
   * aggressive one. If a previously persisted blob exists, it is processed immediately before the
   * asynchronous fetch completes.
   *
   * @param aggressive when {@code true}, prioritizes the request (typically right after a core
   *     update) to reduce latency; when {@code false}, uses a lower priority suitable for idle
   *     polling.
   */
  public void start(boolean aggressive) {
    start(aggressive, true);
    if (blobFile.exists()) {
      ArrayBucket bucket = new ArrayBucket();
      try {
        BucketTools.copy(new FileBucket(blobFile, true, false, false, true), bucket);
        // Allow to free if bogus.
        manager.getUpdateOverMandatory().processRevocationBlob(bucket, "disk", true);
      } catch (IOException e) {
        LOG.error("Failed to read old revocation blob: {}", e, e);
        LOG.warn(
            "We may have downloaded an old revocation blob before restarting but it cannot be read:"
                + " {}",
            e.toString());
      }
    }
  }

  /**
   * Starts a revocation fetch, optionally resetting counters and adjusting priority.
   *
   * <p>If a fetch is already in progress and {@code aggressive} is {@code true} while the existing
   * request is not, the existing request is cancelled and replaced. When {@code reset} is {@code
   * true} the consecutive {@code DATA_NOT_FOUND} counter is cleared; otherwise it continues from
   * its previous value. The method returns whether an in‑flight request existed prior to this call
   * (useful for callers wanting to know if they took over an existing cycle).
   *
   * @param aggressive when {@code true}, raises priority to the maximum request class; when {@code
   *     false}, submits at a lower, immediate class suitable for background checking.
   * @param reset when {@code true}, clears the internal DNF counter before queuing a new request;
   *     when {@code false}, preserves the current count across cycles.
   * @return {@code true} if a previous fetch was running and was not already replaced by an
   *     aggressive one; {@code false} otherwise.
   */
  public boolean start(boolean aggressive, boolean reset) {
    if (manager.isBlown()) {
      LOG.error("Not starting revocation checker: key already blown!");
      return false;
    }
    boolean wasRunning;
    ClientGetter cg = null;
    ClientGetter toCancel;
    try {
      StartPrep prep = prepareStart(aggressive, reset);
      wasRunning = prep.wasRunning;
      cg = prep.cg;
      toCancel = prep.toCancel;
      if (toCancel != null) toCancel.cancel(core.getClientContext());
      if (cg != null) {
        core.getClientContext().start(cg);
        if (LOG.isDebugEnabled()) LOG.debug("Started revocation fetcher");
      }
      return wasRunning;
    } catch (FetchException e) {
      if (e.mode == FetchExceptionMode.RECENTLY_FAILED) {
        LOG.error("Cannot start revocation fetcher because recently failed");
      } else {
        LOG.error("Cannot start fetch for the auto-update revocation key: {}", e, e);
        manager.blow("Cannot start fetch for the auto-update revocation key: " + e, true);
      }
      synchronized (this) {
        if (revocationGetter == cg) {
          revocationGetter = null;
        }
      }
      return false;
    } catch (PersistenceDisabledException _) {
      // Impossible
      return false;
    }
  }

  private record StartPrep(ClientGetter cg, ClientGetter toCancel, boolean wasRunning) {}

  private StartPrep prepareStart(boolean aggressive, boolean reset) {
    ClientGetter cg;
    ClientGetter toCancel = null;
    boolean wasRunning = false;
    synchronized (this) {
      if (shouldCancelOld(aggressive)) {
        toCancel = revocationGetter; // Ignore old one.
        if (LOG.isDebugEnabled()) LOG.debug("Ignoring old request, because was low priority");
        revocationGetter = null;
        if (toCancel != null) wasRunning = true;
      }
      wasAggressive = aggressive;
      if (isGetterActive()) {
        if (LOG.isDebugEnabled())
          LOG.debug("Not queueing another revocation fetcher yet, old one still running");
        return new StartPrep(null, toCancel, false);
      }
      handleReset(reset);
      logFetcherStatus();
      ensurePersistentTempDir();
      cg = createAndAssignClientGetter(aggressive);
      if (LOG.isDebugEnabled())
        LOG.debug("Queued another revocation fetcher (count={})", revocationDNFCounter);
    }
    return new StartPrep(cg, toCancel, wasRunning);
  }

  private boolean shouldCancelOld(boolean aggressive) {
    return aggressive && !wasAggressive;
  }

  private boolean isGetterActive() {
    return revocationGetter != null
        && !(revocationGetter.isCancelled() || revocationGetter.isFinished());
  }

  private void handleReset(boolean reset) {
    if (reset) {
      if (LOG.isDebugEnabled()) LOG.debug("Resetting DNF count from {}", revocationDNFCounter);
      revocationDNFCounter = 0;
    } else {
      if (LOG.isDebugEnabled()) LOG.debug("Revocation count {}", revocationDNFCounter);
    }
  }

  private void logFetcherStatus() {
    if (LOG.isDebugEnabled()) LOG.debug("fetcher={}", revocationGetter);
    if (revocationGetter != null && LOG.isDebugEnabled())
      LOG.debug(
          "revocation fetcher: cancelled={}, finished={}",
          revocationGetter.isCancelled(),
          revocationGetter.isFinished());
  }

  private void ensurePersistentTempDir() {
    File dir = manager.getNode().getClientCore().getPersistentTempDir();
    if (!dir.exists() && !dir.mkdirs()) {
      LOG.warn("Failed to create persistent temp directory: {}", dir);
    }
  }

  private ClientGetter createAndAssignClientGetter(boolean aggressive) {
    ClientGetter cg =
        new ClientGetter(
            this,
            manager.getRevocationURI(),
            ctxRevocation,
            aggressive
                ? RequestStarter.MAXIMUM_PRIORITY_CLASS
                : RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS,
            null,
            new BinaryBlobWriter(new ArrayBucket()),
            null);
    revocationGetter = cg;
    return cg;
  }

  @SuppressWarnings("unused")
  long lastSucceeded() {
    return lastSucceeded;
  }

  long lastSucceededDelta() {
    if (lastSucceeded <= 0) return -1;
    return System.currentTimeMillis() - lastSucceeded;
  }

  /**
   * Notifies the checker that the configured revocation URI has changed.
   *
   * <p>This cancels any in‑flight request and immediately starts a new fetch with the most recent
   * aggressiveness setting previously used. Call this after updating the URI on the {@link
   * NodeUpdateManager} so that the new target is honored without delay.
   */
  public void onChangeRevocationURI() {
    kill();
    start(wasAggressive);
  }

  /**
   * Handles a successful fetch of the revocation message.
   *
   * <p>Marks the checker as blown, persists the received blob to disk, attempts to extract a user
   * readable message from the payload, and forwards the message to {@link
   * NodeUpdateManager#blow(String, boolean)}. Any errors while decoding the payload are logged and
   * do not prevent the revocation from being enforced.
   *
   * @param result the successful {@link FetchResult} containing the payload and its media type;
   *     never {@code null}.
   * @param state the associated request state supplied by the client framework; not used for logic
   *     beyond diagnostics.
   */
  @Override
  public void onSuccess(FetchResult result, ClientGetter state) {
    onSuccess(result, state, state.getBlobBucket());
  }

  void onSuccess(FetchResult result, ClientGetter state, Bucket blob) {
    // The key has been blown !
    // Note: Warning message content kept concise by design.
    blown = true;
    if (LOG.isDebugEnabled() && state != null) {
      LOG.debug("Revocation success; state={} (ignored)", state);
    }
    moveBlob(blob);
    String msg;
    try {
      byte[] buf = result.asByteArray();
      msg = new String(buf, MediaType.getCharsetRobustOrUTF(result.getMimeType()));
    } catch (Exception t) {
      try {
        msg = "Failed to extract result when key blown: " + t;
        LOG.error(msg, t);
        // Message already logged above
      } catch (Exception _) {
        msg = "Internal error after retreiving revocation key";
      }
    }
    manager.blow(msg, false); // Real one, even if we can't extract the message.
  }

  /**
   * Returns whether a revocation message has been observed during this process lifetime.
   *
   * <p>Once {@code true}, this flag remains {@code true} for the life of the process. The overall
   * node state should be considered revoked even if subsequent fetch cycles fail or if the payload
   * cannot be decoded.
   *
   * @return {@code true} if revocation has been detected and propagated; {@code false} otherwise.
   */
  public boolean hasBlown() {
    return blown;
  }

  private void moveBlob(Bucket tmpBlob) {
    if (tmpBlob == null) {
      LOG.error(
          "No temporary binary blob file moving it: may not be able to propagate revocation,"
              + " bug???");
      return;
    }
    if (tmpBlob instanceof ArrayBucket bucket1) {
      assignArrayBucket(bucket1, tmpBlob);
    } else {
      if (!copyTmpBlobToArrayBucket(tmpBlob)) return;
      verifyExpectedBlobFile(tmpBlob);
    }
    writeBlobToDisk(tmpBlob);
  }

  private void assignArrayBucket(ArrayBucket bucket1, Bucket tmpBlob) {
    synchronized (this) {
      if (tmpBlob == blobBucket) return;
      blobBucket = bucket1;
    }
  }

  private boolean copyTmpBlobToArrayBucket(Bucket tmpBlob) {
    try {
      ArrayBucket buf = new ArrayBucket(BucketTools.toByteArray(tmpBlob));
      synchronized (this) {
        blobBucket = buf;
      }
      return true;
    } catch (IOException e) {
      LOG.error("Unable to copy data from revocation bucket!", e);
      LOG.warn(
          "This should not happen and indicates there may be a problem with the auto-update"
              + " checker.");
      // Don't blow(), as that's already happened.
      return false;
    }
  }

  private void verifyExpectedBlobFile(Bucket tmpBlob) {
    if (tmpBlob instanceof FileBucket bucket) {
      File f = bucket.getFile();
      synchronized (this) {
        if (f == blobFile) return;
        if (f.equals(blobFile)) return;
        if (FileUtil.getCanonicalFile(f).equals(FileUtil.getCanonicalFile(blobFile))) return;
      }
    }
    LOG.warn("Unexpected blob file in revocation checker: {}", tmpBlob);
  }

  private void writeBlobToDisk(Bucket tmpBlob) {
    FileBucket fb = new FileBucket(blobFile, false, false, false, false);
    try {
      BucketTools.copy(tmpBlob, fb);
    } catch (IOException e) {
      LOG.error("Got revocation but cannot write it to disk: {}", e.toString());
      LOG.warn(
          "This means the auto-update system is blown but we can't tell other nodes about it!");
    }
  }

  /**
   * Handles a failed fetch attempt for the revocation message.
   *
   * <p>Non‑fatal failures update the internal {@code DATA_NOT_FOUND} counter and may schedule a
   * retry depending on policy. Fatal failures trigger a blow with a localized, user‑readable
   * message; when possible the partial blob is persisted for inspection. Redirects are treated as a
   * configuration error and cause an immediate blow to avoid following potentially unsafe targets.
   *
   * @param e the failure information, including the {@link FetchExceptionMode} and user‑friendly
   *     detail message; never {@code null}.
   * @param state the associated request state supplied by the client framework; not used for logic
   *     beyond diagnostics.
   */
  @Override
  public void onFailure(FetchException e, ClientGetter state) {
    onFailure(e, state, state.getBlobBucket());
  }

  void onFailure(FetchException e, ClientGetter state, Bucket blob) {
    // Debug gating derives from LOG.isDebugEnabled() where needed
    if (LOG.isDebugEnabled()) LOG.debug("Revocation fetch failed: {}", String.valueOf(e));
    if (LOG.isDebugEnabled() && state != null) {
      LOG.debug("State on failure: {} (ignored)", state);
    }
    FetchExceptionMode errorCode = e.getMode();
    boolean completed;
    long now = System.currentTimeMillis();
    if (errorCode == FetchExceptionMode.CANCELLED) {
      return; // cancelled by us above, or killed; either way irrelevant and doesn't need to be
      // restarted
    }
    if (handleFatalFailure(e, blob)) return;
    handleRedirectIfAny(e);
    completed = updateDNFAndState(errorCode, now);
    if (completed) manager.noRevocationFound();
    else {
      if (errorCode == FetchExceptionMode.RECENTLY_FAILED) {
        // Try again in 1 second.
        // This ensures we don't constantly start them, fail them, and start them again.
        this.manager
            .getNode()
            .getTicker()
            .queueTimedJob(() -> start(wasAggressive, false), SECONDS.toMillis(1));
      } else {
        start(wasAggressive, false);
      }
    }
  }

  private boolean handleFatalFailure(FetchException e, Bucket blob) {
    if (!e.isFatal()) return false;
    if (!e.isDefinitelyFatal()) {
      // INTERNAL_ERROR could be related to the key but isn't necessarily.
      String message =
          l10n(
              "revocationFetchFailedMaybeInternalError",
              new String[] {"detail", "key"},
              new String[] {e.toUserFriendlyString(), manager.getRevocationURI().toASCIIString()});
      LOG.error(message);
      manager.blow(message, true);
      return true;
    }
    // Really fatal, i.e. something was inserted but can't be decoded.
    // Strings are intentionally explicit despite being rarely seen.
    String message =
        l10n(
            "revocationFetchFailedFatally",
            new String[] {"detail", "key"},
            new String[] {e.toUserFriendlyString(), manager.getRevocationURI().toASCIIString()});
    manager.blow(message, false);
    moveBlob(blob);
    return true;
  }

  private void handleRedirectIfAny(FetchException e) {
    if (e.newURI == null) return;
    manager.blow(
        "Revocation URI redirecting to "
            + e.newURI
            + " - maybe you set the revocation URI to the update URI?",
        false);
  }

  private boolean updateDNFAndState(FetchExceptionMode errorCode, long now) {
    boolean completed = false;
    synchronized (this) {
      if (errorCode == FetchExceptionMode.DATA_NOT_FOUND) {
        revocationDNFCounter++;
        if (LOG.isDebugEnabled()) LOG.debug("Incremented DNF counter to {}", revocationDNFCounter);
      }
      if (revocationDNFCounter >= 3) {
        lastSucceeded = now;
        completed = true;
        revocationDNFCounter = 0;
      }
      revocationGetter = null;
    }
    return completed;
  }

  private String l10n(String key, String[] pattern, String[] value) {
    return NodeL10n.getBase().getString("RevocationChecker." + key, pattern, value);
  }

  /**
   * Cancels any currently running revocation fetch request.
   *
   * <p>This method does not reset counters or start a new cycle; it only attempts to stop the
   * in‑flight request. Call {@link #start(boolean)} afterward to begin a fresh cycle if desired.
   */
  public void kill() {
    if (revocationGetter != null) revocationGetter.cancel(core.getClientContext());
  }

  /**
   * Returns the length, in bytes, of the persisted revocation blob if present.
   *
   * <p>The value reflects the current size of the on‑disk file recorded at construction time.
   * Returns zero when the file does not exist or is empty.
   *
   * @return the size of the blob file in bytes; zero if absent.
   */
  public long getBlobSize() {
    return blobFile.length();
  }

  /**
   * Provides the revocation blob as a {@link RandomAccessBucket}, when available.
   *
   * <p>The bucket is readable and intended for downstream components that need to inspect or
   * re‑process the revocation message. When no revocation has been detected, or when the blob is
   * not yet available, this method returns {@code null}.
   *
   * @return a readable bucket for the stored blob, or {@code null} if not available or not blown.
   */
  public RandomAccessBucket getBlobBucket() {
    if (!manager.isBlown()) return null;
    synchronized (this) {
      if (blobBucket != null) return blobBucket;
    }
    File f = getBlobFile();
    if (f == null) return null;
    return new FileBucket(f, true, false, false, false);
  }

  /**
   * Provides the revocation blob as a read‑only {@link RandomAccessBuffer}, when available.
   *
   * <p>If the blob is already cached in memory it is returned as a read‑only byte array–backed
   * buffer. Otherwise, a file‑backed buffer is opened for the persisted blob. When the node is not
   * blown or the blob cannot be read, {@code null} is returned and details are logged.
   *
   * @return a read‑only random‑access buffer for the blob, or {@code null} if not available.
   */
  public RandomAccessBuffer getBlobBuffer() {
    if (!manager.isBlown()) return null;
    synchronized (this) {
      if (blobBucket != null) {
        try {
          ByteArrayRandomAccessBuffer t = new ByteArrayRandomAccessBuffer(blobBucket.toByteArray());
          t.setReadOnly();
          return t;
        } catch (IOException e) {
          LOG.error("Impossible: {}", e, e);
          return null;
        }
      }
    }
    File f = getBlobFile();
    if (f == null) return null;
    try {
      return new FileRandomAccessBuffer(f, true);
    } catch (FileNotFoundException e) {
      LOG.error(
          "We do not have the blob file for the revocation even though we have successfully"
              + " downloaded it!",
          e);
      return null;
    } catch (IOException e) {
      LOG.error("Error reading downloaded revocation blob file: {}", e, e);
      return null;
    }
  }

  /** Get the binary blob file if it exists on disk; otherwise returns {@code null}. */
  private File getBlobFile() {
    if (blobFile.exists()) return blobFile;
    return null;
  }

  /**
   * Indicates whether this request client is persistent across restarts.
   *
   * <p>Revocation checking is intentionally non‑persistent; it is restarted on demand by the owning
   * manager and does not rely on request resurrection.
   *
   * @return always {@code false} – the checker does not participate in persistent requests.
   */
  @Override
  public boolean persistent() {
    return false;
  }

  /**
   * Exposes the real‑time flag of this request client.
   *
   * <p>Revocation fetches are not marked as real‑time operations to avoid unnecessary
   * prioritization by the underlying client framework unless explicitly requested via the {@code
   * aggressive} parameter on {@link #start(boolean)}.
   *
   * @return always {@code false} – the checker does not request real‑time handling by default.
   */
  @Override
  public boolean realTimeFlag() {
    return false;
  }

  /**
   * No‑op resume hook required by the callback contract.
   *
   * <p>The checker does not use request persistence, so there is nothing to resume; this method is
   * present only to satisfy the {@link ClientGetCallback} lifecycle.
   *
   * @param context the client context supplied by the framework; ignored.
   */
  @Override
  public void onResume(ClientContext context) {
    // Do nothing. Not persistent.
  }

  /**
   * Returns this instance as its own {@link RequestClient} implementation.
   *
   * <p>The checker serves as both the callback target and the request client identity used by the
   * underlying client framework.
   *
   * @return {@code this} instance.
   */
  @Override
  public RequestClient getRequestClient() {
    return this;
  }
}

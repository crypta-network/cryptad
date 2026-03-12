package network.crypta.client.async;

import java.io.IOException;
import java.io.Serial;
import java.io.Serializable;
import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;
import network.crypta.client.InsertContext;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.client.InsertException;
import network.crypta.client.Metadata;
import network.crypta.keys.BaseClientKey;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.InsertableUSK;
import network.crypta.keys.USK;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.BucketTools;
import network.crypta.support.io.ResumeFailedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Inserts content into an {@link network.crypta.keys.USK} (Updatable Subspace Key).
 *
 * <p>The inserter performs a search for the latest known edition of the USK and attempts to insert
 * the provided block at the immediately following slot. If a collision is reported (the slot is
 * already taken), the inserter advances to the next slot and retries. After a bounded number of
 * consecutive collisions, it re-enters discovery to refresh the latest known good edition before
 * continuing.
 *
 * <p>Typical usage is to construct an instance with the desired data, compression settings, and
 * insert context, then call {@link #schedule(ClientContext)} to begin the asynchronous workflow.
 * Progress and completion are reported through the supplied {@link PutCompletionCallback}. This
 * class coordinates a {@link USKFetcherTag} to discover the current edition and a {@link
 * SingleBlockInserter} to perform the actual SSK block insert for a given edition of the USK.
 *
 * <p>Concurrency: instances are stateful and not intended for reuse across multiple inserts.
 * Internal state transitions occur on callbacks driven by the client framework; externally visible
 * methods guard the state via synchronization where necessary. Callers should treat an instance as
 * single-use and avoid concurrent calls other than lifecycle hooks invoked by the framework.
 *
 * <ul>
 *   <li>Search: discovers the latest known edition before first insert.
 *   <li>Insert: writes the SSK block to {@code edition + 1} and advances on collisions.
 *   <li>Hints: optionally emits USK date hints after a successful insert when configured.
 *   <li>Lifecycle: supports cancel, resume after persistence, and shutdown notifications.
 * </ul>
 *
 * @see USKFetcherTag
 * @see SingleBlockInserter
 * @see network.crypta.keys.USK
 * @see network.crypta.client.InsertContext
 * @see PutCompletionCallback
 */
public final class USKInserter
    implements ClientPutState, USKFetcherCallback, PutCompletionCallback, Serializable {
  private static final Logger LOG = LoggerFactory.getLogger(USKInserter.class);

  @Serial private static final long serialVersionUID = 1L;

  /** Stuff forwarded to the {@link SingleBlockInserter} when creating an insert. */
  final BaseClientPutter parent;

  /**
   * Source payload to insert. Implementations provide byte access, length, and free semantics; this
   * reference may be freed when the insert completes if {@code freeData} is enabled.
   */
  @SuppressWarnings("java:S1948")
  Bucket data;

  /** Compression codec identifier to apply to the payload prior to insertion. */
  final short compressionCodec;

  /** Per-insert configuration including retry policy, priorities, and flags. */
  final InsertContext ctx;

  /** Callback notified of encoding, success, failure, and state transitions. */
  @SuppressWarnings("java:S1948")
  final PutCompletionCallback cb;

  /** True if the payload represents metadata rather than primary content. */
  final boolean isMetadata;

  /** Original content length in bytes, when known, used for progress reporting. */
  final int sourceLength;

  /** Numeric token used by the parent for correlation and progress reporting. */
  final int token;

  /**
   * Opaque token supplied by the caller and returned in callbacks. It is not interpreted by the
   * inserter and may be {@code null}. Ownership and mutability follow caller conventions.
   */
  @SuppressWarnings("java:S1948")
  public final Object tokenObject;

  /** Whether this inserter participates in a persistent (resumable) operation. */
  final boolean persistent;

  /** Real-time request flag used to influence scheduler/priorities downstream. */
  final boolean realTimeFlag;

  /** Private insertable USK containing material needed to derive per-edition insert URIs. */
  final InsertableUSK privUSK;

  /** Corresponding public USK used to resolve and report editions to consumers. */
  final USK pubUSK;

  /** Fetcher used to discover the latest inserted edition (scanning for the latest slot). */
  private USKFetcherTag fetcher;

  /** Helper that inserts the actual SSK block for a given edition. */
  private SingleBlockInserter sbi;

  /** Candidate edition being attempted for insertion; advances on collision. */
  private long edition;

  /** Number of consecutive collisions encountered while attempting to insert. */
  private int consecutiveCollisions;

  /** True once the inserter has reached a terminal state (success, failure, or cancel). */
  private boolean finished;

  /** After this many attempted slots without success, fall back to re-fetch the latest. */
  private static final long MAX_TRIED_SLOTS = 10;

  /** Maximum time to wait for USK datehint child inserts to make progress before retrying. */
  private static final long DATEHINT_STALL_TIMEOUT_MILLIS = TimeUnit.MINUTES.toMillis(15);

  /**
   * Extra grace added when the SSK insert scheduler reports an explicit cooldown for this priority
   * class.
   */
  private static final long DATEHINT_SCHEDULER_COOLDOWN_GRACE_MILLIS = TimeUnit.SECONDS.toMillis(5);

  /**
   * Time to wait after issuing a watchdog cancel before force-completing a stuck datehint phase.
   *
   * <p>This guards cases where child states never deliver terminal callbacks after cancel and the
   * phase would otherwise remain pending indefinitely.
   */
  private static final long DATEHINT_CANCEL_COMPLETION_TIMEOUT_MILLIS =
      TimeUnit.MINUTES.toMillis(1);

  /** Retry stalled USK datehint phase at most this many times before surfacing failure. */
  private static final int MAX_DATEHINT_STALL_RETRIES = 1;

  /** If true, frees {@link #data} after completion or terminal failure. */
  private final boolean freeData;

  /** Precomputed identity-based hash code; used to keep stable identity semantics. */
  final int hashCode;

  /** Additional insert attempts or related behavior delegated to lower levels. */
  private final int extraInserts;

  /** Crypto algorithm identifier to use for underlying SSK insert, if applicable. */
  final byte cryptoAlgorithm;

  /** Optional override for the crypto key material; {@code null} to auto-generate. */
  final byte[] forceCryptoKey;

  /**
   * Last known non-null external request identifier for diagnostics correlation.
   *
   * <p>Persisted so datehint child inserts can restore correlation metadata after restart.
   */
  private String externalRequestIdentifierSnapshot;

  /** Active datehint insert phase; null when not currently inserting datehints. */
  private transient DateHintPhase activeDateHintPhase;

  /** Monotonic identifier for datehint phases; helps ignore stale callbacks. */
  private transient long nextDateHintPhaseId = 1;

  /**
   * Runtime-only state for one active datehint insert phase.
   *
   * <p>This state is intentionally transient and rebuilt by the terminal callback's {@link
   * PutCompletionCallback#onResume(ClientContext)} path after restart.
   */
  private static final class DateHintPhase {
    final long phaseId;
    final int retryCount;
    final DateHintTerminalCallback terminalCallback;
    final ClientPutState completionState;
    long lastProgressAtMillis;
    boolean watchdogCancelIssued;
    long watchdogCancelIssuedAtMillis;

    DateHintPhase(
        long phaseId,
        int retryCount,
        DateHintTerminalCallback terminalCallback,
        ClientPutState completionState) {
      this.phaseId = phaseId;
      this.retryCount = retryCount;
      this.terminalCallback = terminalCallback;
      this.completionState = completionState;
      this.lastProgressAtMillis = System.currentTimeMillis();
      this.watchdogCancelIssued = false;
      this.watchdogCancelIssuedAtMillis = 0L;
    }
  }

  private record DateHintPhaseFinishDecision(
      boolean ignoreEvent,
      boolean retryOnStallCancel,
      boolean treatWatchdogCancelAsBestEffortSuccess) {}

  private static final class DateHintWatchdogState {
    DateHintTerminalCallback callbackToCancel;
    DateHintTerminalCallback callbackToForceComplete;
    ClientPutState forceCompletionState;
    long rescheduleDelay = -1L;
    long stalledFor;
    long cancelAge;
    int retryCount;
    boolean evaluateSchedulerCooldown;
    long schedulerCooldownDelay;
  }

  /**
   * Terminal callback for a datehint phase.
   *
   * <p>Delegates normal notifications to {@link #cb}, while intercepting terminal success/failure
   * so we can retry a stalled phase once when the watchdog cancels it for lack of progress.
   */
  private final class DateHintTerminalCallback implements PutCompletionCallback, Serializable {
    @Serial private static final long serialVersionUID = 1L;

    private final long phaseId;
    private final long edition;
    private final int retryCount;
    private MultiPutCompletionCallback group;
    private volatile boolean watchdogCancelIssued;
    private transient volatile boolean awaitingPhaseRestore;
    private transient volatile boolean completedBeforePhaseRestore;

    DateHintTerminalCallback(long phaseId, long edition, int retryCount) {
      this.phaseId = phaseId;
      this.edition = edition;
      this.retryCount = retryCount;
      this.watchdogCancelIssued = false;
      this.awaitingPhaseRestore = false;
    }

    void bindGroup(MultiPutCompletionCallback group) {
      this.group = group;
    }

    void cancelGroup(ClientContext context) {
      MultiPutCompletionCallback localGroup = group;
      if (localGroup != null) localGroup.cancel(context);
    }

    private boolean isParentRequestCancelled() {
      BaseClientPutter parentPutter = parent;
      return parentPutter == null || parentPutter.isCancelled();
    }

    private PutCompletionCallback getCompletionCallbackOrNull(String eventName) {
      PutCompletionCallback callback = cb;
      if (callback == null && LOG.isDebugEnabled()) {
        LOG.debug(
            "Dropping datehint {} callback for {} phase {} because completion callback is null",
            eventName,
            USKInserter.this,
            phaseId);
      }
      return callback;
    }

    private void markDateHintProgress(long phaseId) {
      synchronized (USKInserter.this) {
        if (activeDateHintPhase == null || activeDateHintPhase.phaseId != phaseId) return;
        activeDateHintPhase.lastProgressAtMillis = System.currentTimeMillis();
      }
    }

    private long resumedPhaseWatchdogDelayMillis(DateHintPhase phase) {
      if (!phase.watchdogCancelIssued) {
        return DATEHINT_STALL_TIMEOUT_MILLIS;
      }
      long now = System.currentTimeMillis();
      if (phase.watchdogCancelIssuedAtMillis <= 0L) {
        phase.watchdogCancelIssuedAtMillis = now;
      }
      long cancelAge = now - phase.watchdogCancelIssuedAtMillis;
      if (cancelAge >= DATEHINT_CANCEL_COMPLETION_TIMEOUT_MILLIS) {
        return 1L;
      }
      return DATEHINT_CANCEL_COMPLETION_TIMEOUT_MILLIS - cancelAge;
    }

    private void onDateHintPhaseResumed(ClientContext context) {
      long watchdogDelayMillis;
      synchronized (USKInserter.this) {
        DateHintPhase current = activeDateHintPhase;
        if (current == null || current.phaseId != phaseId) {
          ClientPutState resumedState = (group != null) ? group : USKInserter.this;
          DateHintPhase restored = new DateHintPhase(phaseId, retryCount, this, resumedState);
          restored.watchdogCancelIssued = watchdogCancelIssued;
          restored.watchdogCancelIssuedAtMillis =
              watchdogCancelIssued ? System.currentTimeMillis() : 0L;
          activeDateHintPhase = restored;
          nextDateHintPhaseId = Math.max(nextDateHintPhaseId, phaseId + 1);
          watchdogDelayMillis = resumedPhaseWatchdogDelayMillis(restored);
        } else {
          current.watchdogCancelIssued |= watchdogCancelIssued;
          if (current.watchdogCancelIssued && current.watchdogCancelIssuedAtMillis <= 0L) {
            current.watchdogCancelIssuedAtMillis = System.currentTimeMillis();
          }
          current.lastProgressAtMillis = System.currentTimeMillis();
          watchdogDelayMillis = resumedPhaseWatchdogDelayMillis(current);
        }
      }
      scheduleDateHintWatchdog(context, phaseId, watchdogDelayMillis);
    }

    private DateHintPhaseFinishDecision decideDateHintPhaseCompletion(InsertException failure) {
      synchronized (USKInserter.this) {
        DateHintPhase phase = activeDateHintPhase;
        if (phase == null) {
          return decideDateHintCompletionWithoutActivePhase(failure);
        }
        if (phase.phaseId != phaseId) {
          return new DateHintPhaseFinishDecision(true, false, false);
        }
        return decideDateHintCompletionWithActivePhase(phase, failure);
      }
    }

    private DateHintPhaseFinishDecision decideDateHintCompletionWithoutActivePhase(
        InsertException failure) {
      // Resume-order race: MultiPut resumes children before callback.onResume() rebuilds phase.
      if (!awaitingPhaseRestore || completedBeforePhaseRestore) {
        return new DateHintPhaseFinishDecision(true, false, false);
      }
      completedBeforePhaseRestore = true;
      boolean parentCancelled = isParentRequestCancelled();
      boolean watchdogCancelFailure = isWatchdogCancelFailure(failure, watchdogCancelIssued);
      boolean retryOnStallCancel =
          watchdogCancelFailure && retryCount < MAX_DATEHINT_STALL_RETRIES && !parentCancelled;
      boolean treatWatchdogCancelAsBestEffortSuccess =
          watchdogCancelFailure && !retryOnStallCancel && !parentCancelled;
      return new DateHintPhaseFinishDecision(
          false, retryOnStallCancel, treatWatchdogCancelAsBestEffortSuccess);
    }

    private DateHintPhaseFinishDecision decideDateHintCompletionWithActivePhase(
        DateHintPhase phase, InsertException failure) {
      boolean watchdogCancelled = phase.watchdogCancelIssued || watchdogCancelIssued;
      boolean parentCancelled = isParentRequestCancelled();
      boolean watchdogCancelFailure = isWatchdogCancelFailure(failure, watchdogCancelled);
      boolean retryOnStallCancel =
          watchdogCancelFailure && retryCount < MAX_DATEHINT_STALL_RETRIES && !parentCancelled;
      boolean treatWatchdogCancelAsBestEffortSuccess =
          watchdogCancelFailure && !retryOnStallCancel && !parentCancelled;
      activeDateHintPhase = null;
      return new DateHintPhaseFinishDecision(
          false, retryOnStallCancel, treatWatchdogCancelAsBestEffortSuccess);
    }

    private static boolean isWatchdogCancelFailure(
        InsertException failure, boolean watchdogCancelled) {
      return failure != null
          && watchdogCancelled
          && failure.getMode() == InsertExceptionMode.CANCELLED;
    }

    private void forwardDateHintCompletion(
        ClientPutState completedState,
        InsertException failure,
        boolean treatWatchdogCancelAsBestEffortSuccess,
        ClientContext context) {
      boolean shouldForwardFailure = failure != null && !treatWatchdogCancelAsBestEffortSuccess;
      PutCompletionCallback callback =
          getCompletionCallbackOrNull(shouldForwardFailure ? "onFailure" : "onSuccess");
      if (callback == null) {
        return;
      }
      if (shouldForwardFailure) {
        callback.onFailure(failure, completedState, context);
      } else {
        callback.onSuccess(completedState, context);
      }
    }

    private void onDateHintPhaseFinished(
        ClientPutState completedState, InsertException failure, ClientContext context) {
      DateHintPhaseFinishDecision decision = decideDateHintPhaseCompletion(failure);
      if (decision.ignoreEvent) {
        return;
      }
      if (decision.retryOnStallCancel) {
        if (isParentRequestCancelled()) {
          LOG.warn(
              "Skipping USK datehint retry for {} edition {} because parent request was cancelled"
                  + " before retry scheduling",
              USKInserter.this,
              edition);
          return;
        }
        LOG.warn(
            "Retrying USK datehint insert phase for {} edition {} after watchdog cancel (attempt {}"
                + " of {})",
            USKInserter.this,
            edition,
            retryCount + 1,
            MAX_DATEHINT_STALL_RETRIES);
        startDateHintInsertPhase(context, edition, retryCount + 1, completedState);
        return;
      }
      if (decision.treatWatchdogCancelAsBestEffortSuccess) {
        LOG.warn(
            "USK datehint insert phase for {} edition {} remained cancelled after {} retry attempt"
                + "(s); continuing as success without datehint completion",
            USKInserter.this,
            edition,
            MAX_DATEHINT_STALL_RETRIES);
      }
      forwardDateHintCompletion(
          completedState, failure, decision.treatWatchdogCancelAsBestEffortSuccess, context);
    }

    @Override
    public void onSuccess(ClientPutState state, ClientContext context) {
      markDateHintProgress(phaseId);
      onDateHintPhaseFinished(state, null, context);
    }

    @Override
    public void onFailure(InsertException e, ClientPutState state, ClientContext context) {
      markDateHintProgress(phaseId);
      onDateHintPhaseFinished(state, e, context);
    }

    void forceCompletionAfterWatchdogTimeout(ClientContext context, ClientPutState completedState) {
      ClientPutState state = (completedState != null) ? completedState : USKInserter.this;
      onDateHintPhaseFinished(state, new InsertException(InsertExceptionMode.CANCELLED), context);
    }

    @Override
    public void onEncode(BaseClientKey usk, ClientPutState state, ClientContext context) {
      markDateHintProgress(phaseId);
      PutCompletionCallback callback = getCompletionCallbackOrNull("onEncode");
      if (callback != null) callback.onEncode(usk, state, context);
    }

    @Override
    public void onTransition(
        ClientPutState oldState, ClientPutState newState, ClientContext context) {
      markDateHintProgress(phaseId);
      PutCompletionCallback callback = getCompletionCallbackOrNull("onTransition");
      if (callback != null) callback.onTransition(oldState, newState, context);
    }

    @Override
    public void onMetadata(Metadata m, ClientPutState state, ClientContext context) {
      markDateHintProgress(phaseId);
      PutCompletionCallback callback = getCompletionCallbackOrNull("onMetadataMetadata");
      if (callback != null) callback.onMetadata(m, state, context);
    }

    @Override
    public void onMetadata(Bucket meta, ClientPutState state, ClientContext context) {
      markDateHintProgress(phaseId);
      PutCompletionCallback callback = getCompletionCallbackOrNull("onMetadataBucket");
      if (callback != null) callback.onMetadata(meta, state, context);
    }

    @Override
    public void onFetchable(ClientPutState state) {
      markDateHintProgress(phaseId);
      PutCompletionCallback callback = getCompletionCallbackOrNull("onFetchable");
      if (callback != null) callback.onFetchable(state);
    }

    @Override
    public void onBlockSetFinished(ClientPutState state, ClientContext context) {
      markDateHintProgress(phaseId);
      PutCompletionCallback callback = getCompletionCallbackOrNull("onBlockSetFinished");
      if (callback != null) callback.onBlockSetFinished(state, context);
    }

    @Override
    public void onResume(ClientContext context) throws InsertException, ResumeFailedException {
      if (!completedBeforePhaseRestore) {
        onDateHintPhaseResumed(context);
      }
      awaitingPhaseRestore = false;
      PutCompletionCallback callback = getCompletionCallbackOrNull("onResume");
      if (callback != null && callback != parent) callback.onResume(context);
    }

    @Serial
    private void readObject(java.io.ObjectInputStream in)
        throws IOException, ClassNotFoundException {
      in.defaultReadObject();
      awaitingPhaseRestore = true;
      completedBeforePhaseRestore = false;
    }
  }

  /**
   * Starts the asynchronous USK insert process.
   *
   * <p>Schedules a discovery pass to find the latest known edition and then attempts to insert the
   * provided data at the next edition. Progress and completion are delivered to the configured
   * {@link PutCompletionCallback}. Idempotent with respect to repeated calls before completion;
   * later calls after a terminal state have no effect.
   *
   * @param context the client context providing executors, managers, and factories; must be
   *     non-{@code null} and valid for the lifetime of the operation
   * @throws InsertException if scheduling the initial discovery or insert fails immediately
   */
  @Override
  public void schedule(ClientContext context) throws InsertException {
    // Caller calls schedule()
    // schedule() calls scheduleFetcher()
    // scheduleFetcher() creates a Fetcher (set up to tell us about author-errors as well as valid
    // inserts)
    // (and starts it)
    // when this completes, onFoundEdition() calls scheduleInsert()
    // scheduleInsert() starts a SingleBlockInserter
    // if that succeeds, we complete
    // if that fails, we increment our index and try again (in the callback)
    // if that continues to fail 5 times, we go back to scheduleFetcher()
    scheduleFetcher(context);
  }

  /**
   * Schedule a Fetcher to find us the latest inserted key of the USK. The Fetcher must be
   * insert-mode, in other words, it must know that we want the latest edition, including author
   * errors and so on.
   */
  private void scheduleFetcher(ClientContext context) {
    USKFetcherTag localFetcher;
    synchronized (this) {
      if (LOG.isDebugEnabled()) LOG.debug("scheduling fetcher for {}", pubUSK.getURI());
      if (finished) return;
      localFetcher =
          fetcher =
              context.uskManager.getFetcherForInsertDontSchedule(
                  persistent ? pubUSK.copy() : pubUSK,
                  parent.priorityClass,
                  this,
                  parent.getClient(),
                  context,
                  persistent,
                  ctx.isIgnoreUSKDatehints());
      if (LOG.isDebugEnabled()) LOG.debug("scheduled: {}", fetcher);
    }
    boolean shouldSchedule;
    synchronized (this) {
      shouldSchedule = !finished && fetcher != null && fetcher.equals(localFetcher);
    }
    if (shouldSchedule) {
      localFetcher.schedule(context);
    } else if (LOG.isDebugEnabled()) {
      LOG.debug("Skipping stale fetcher schedule on {}", this);
    }
  }

  /**
   * Callback from the USK fetcher indicating the latest known edition.
   *
   * <p>Updates the candidate edition and, when possible, determines whether the content is already
   * present by comparing data and codec. If the payload is already inserted at the reported
   * edition, it completes successfully. Otherwise, schedules an insert attempt at the next edition.
   *
   * @param foundEdition The payload describing the discovered edition and its metadata.
   */
  @Override
  public void onFoundEdition(USKFoundEdition foundEdition) {
    long editionFound = foundEdition.edition();
    ClientContext context = foundEdition.context();
    boolean lastContentWasMetadata = foundEdition.metadata();
    short codec = foundEdition.codec();
    byte[] hisData = foundEdition.data();
    boolean alreadyInserted = false;
    long currentEdition;
    Bucket dataToFree = null;
    synchronized (this) {
      edition = Math.max(editionFound, edition);
      currentEdition = edition;
      consecutiveCollisions = 0;
      if ((lastContentWasMetadata == isMetadata)
          && hisData != null
          && (codec == compressionCodec)) {
        try {
          byte[] myData = BucketTools.toByteArray(data);
          if (Arrays.equals(myData, hisData)) {
            // Success
            alreadyInserted = true;
            finished = true;
            sbi = null;
            if (freeData) {
              dataToFree = data;
              data = null;
            }
          }
        } catch (IOException e) {
          LOG.error("Could not decode: {}", e, e);
        }
      }
      if (persistent) {
        fetcher = null;
      }
    }
    if (alreadyInserted) {
      // Success!
      parent.completedBlock(true, context);
      cb.onEncode(pubUSK.copy(currentEdition), this, context);
      insertSucceeded(context, editionFound);
      if (dataToFree != null) dataToFree.free();
    } else {
      scheduleInsert(context);
    }
  }

  private void insertSucceeded(ClientContext context, long edition) {
    // Inserts optional USK date hints after a successful content insert when configured.
    if (ctx.isIgnoreUSKDatehints()) {
      if (LOG.isDebugEnabled()) LOG.debug("Inserted to edition {}", edition);
      cb.onSuccess(this, context);
      return;
    }
    startDateHintInsertPhase(context, edition, 0, this);
  }

  private void startDateHintInsertPhase(
      ClientContext context, long edition, int retryCount, ClientPutState transitionFrom) {
    reapplyExternalRequestIdentifierIfNeeded();
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Inserted to edition {} - inserting USK date hints (retry {} of {})...",
          edition,
          retryCount,
          MAX_DATEHINT_STALL_RETRIES);
    USKDateHint hint = USKDateHint.now();
    long phaseId = reserveDateHintPhaseId();
    DateHintTerminalCallback terminalCallback =
        new DateHintTerminalCallback(phaseId, edition, retryCount);
    MultiPutCompletionCallback m =
        new MultiPutCompletionCallback(terminalCallback, parent, tokenObject, persistent, true);
    terminalCallback.bindGroup(m);
    activateDateHintPhase(new DateHintPhase(phaseId, retryCount, terminalCallback, m));

    byte[] hintData = hint.getData(edition).getBytes(StandardCharsets.UTF_8);
    FreenetURI[] hintURIs = hint.getInsertURIs(privUSK);
    boolean added = false;
    for (FreenetURI uri : hintURIs) {
      try {
        Bucket bucket =
            BucketTools.makeImmutableBucket(context.getBucketFactory(persistent), hintData);
        SingleBlockInserter sb =
            new SingleBlockInserter(
                new BlockInsertPayload(
                    bucket, uri, (short) -1, false, sourceLength, cryptoAlgorithm, forceCryptoKey),
                new BlockInsertParams(parent, ctx, m, token, null, true, context),
                new BlockInsertOptions(persistent, realTimeFlag, true, extraInserts),
                true /* we don't use it */);
        LOG.info("Inserting {} with {} for insert of {}", uri, sb, pubUSK);
        m.add(sb);
        sb.schedule(context);
        added = true;
      } catch (IOException e) {
        LOG.error("Unable to insert USK date hints due to disk I/O error: {}", e, e);
        if (!added) {
          clearActiveDateHintPhase(phaseId);
          cb.onFailure(
              new InsertException(
                  InsertExceptionMode.BUCKET_ERROR, e, pubUSK.getSSK(edition).getURI()),
              this,
              context);
          return;
        } // Else try to insert the other hints.
      } catch (InsertException e) {
        LOG.error("Unable to insert USK date hints due to error: {}", e, e);
        if (!added) {
          clearActiveDateHintPhase(phaseId);
          cb.onFailure(e, this, context);
          return;
        } // Else try to insert the other hints.
      }
    }
    if (!added) {
      clearActiveDateHintPhase(phaseId);
      cb.onSuccess(this, context);
      return;
    }
    cb.onTransition(transitionFrom, m, context);
    m.arm(context);
    scheduleDateHintWatchdog(context, phaseId, DATEHINT_STALL_TIMEOUT_MILLIS);
  }

  private synchronized long reserveDateHintPhaseId() {
    return nextDateHintPhaseId++;
  }

  private synchronized void activateDateHintPhase(DateHintPhase phase) {
    activeDateHintPhase = phase;
    nextDateHintPhaseId = Math.max(nextDateHintPhaseId, phase.phaseId + 1);
  }

  private synchronized void clearActiveDateHintPhase(long phaseId) {
    if (activeDateHintPhase != null && activeDateHintPhase.phaseId == phaseId) {
      activeDateHintPhase = null;
    }
  }

  private void reapplyExternalRequestIdentifierIfNeeded() {
    BaseClientPutter parentPutter = parent;
    if (parentPutter == null) {
      return;
    }
    String current = parentPutter.getExternalRequestIdentifier();
    if (current != null) {
      externalRequestIdentifierSnapshot = current;
      return;
    }
    if (externalRequestIdentifierSnapshot != null) {
      parentPutter.setExternalRequestIdentifier(externalRequestIdentifierSnapshot);
    }
  }

  private long dateHintSchedulerCooldownDelayMillis(ClientContext context, long now) {
    BaseClientPutter parentPutter = parent;
    if (parentPutter == null) {
      return 0L;
    }
    ClientRequestScheduler scheduler = context.getSskInsertScheduler(realTimeFlag);
    if (scheduler == null) {
      return 0L;
    }
    long wakeupTime = scheduler.getPriorityCooldownUntil(parentPutter.getPriorityClass(), now);
    if (wakeupTime <= now) {
      return 0L;
    }
    return wakeupTime - now;
  }

  private void scheduleDateHintWatchdog(ClientContext context, long phaseId, long delayMillis) {
    if (context.ticker == null) return;
    long boundedDelay = Math.max(1L, delayMillis);
    context.ticker.queueTimedJob(() -> runDateHintWatchdog(context, phaseId), boundedDelay);
  }

  private DateHintWatchdogState snapshotDateHintWatchdogState(long phaseId) {
    DateHintWatchdogState state = new DateHintWatchdogState();
    synchronized (this) {
      DateHintPhase phase = activeDateHintPhase;
      if (phase == null || phase.phaseId != phaseId) {
        return null;
      }
      long now = System.currentTimeMillis();
      state.stalledFor = now - phase.lastProgressAtMillis;
      if (state.stalledFor < DATEHINT_STALL_TIMEOUT_MILLIS) {
        state.rescheduleDelay = DATEHINT_STALL_TIMEOUT_MILLIS - state.stalledFor;
        return state;
      }
      if (phase.watchdogCancelIssued) {
        if (phase.watchdogCancelIssuedAtMillis <= 0L) {
          phase.watchdogCancelIssuedAtMillis = now;
        }
        state.cancelAge = now - phase.watchdogCancelIssuedAtMillis;
        if (state.cancelAge < DATEHINT_CANCEL_COMPLETION_TIMEOUT_MILLIS) {
          state.rescheduleDelay = DATEHINT_CANCEL_COMPLETION_TIMEOUT_MILLIS - state.cancelAge;
        } else {
          state.callbackToForceComplete = phase.terminalCallback;
          state.forceCompletionState = phase.completionState;
        }
        return state;
      }
      state.evaluateSchedulerCooldown = true;
      state.retryCount = phase.retryCount;
      return state;
    }
  }

  private DateHintWatchdogState evaluateDateHintSchedulerCooldown(
      ClientContext context, long phaseId, DateHintWatchdogState state) {
    state.schedulerCooldownDelay =
        dateHintSchedulerCooldownDelayMillis(context, System.currentTimeMillis());
    if (state.schedulerCooldownDelay > 0L) {
      state.rescheduleDelay =
          state.schedulerCooldownDelay + DATEHINT_SCHEDULER_COOLDOWN_GRACE_MILLIS;
      return state;
    }
    synchronized (this) {
      DateHintPhase phase = activeDateHintPhase;
      if (phase == null || phase.phaseId != phaseId || phase.watchdogCancelIssued) {
        return null;
      }
      phase.watchdogCancelIssued = true;
      phase.watchdogCancelIssuedAtMillis = System.currentTimeMillis();
      phase.terminalCallback.watchdogCancelIssued = true;
      state.callbackToCancel = phase.terminalCallback;
      state.retryCount = phase.retryCount;
      return state;
    }
  }

  private boolean rescheduleDateHintWatchdogIfNeeded(
      ClientContext context, long phaseId, DateHintWatchdogState state) {
    if (state.rescheduleDelay <= 0L) {
      return false;
    }
    if (state.evaluateSchedulerCooldown
        && state.schedulerCooldownDelay > 0L
        && LOG.isInfoEnabled()) {
      LOG.info(
          "Deferring USK datehint watchdog cancel for {} phase {} due to scheduler cooldown {}"
              + " ms at priority {}",
          this,
          phaseId,
          state.schedulerCooldownDelay,
          (parent == null) ? -1 : parent.getPriorityClass());
    }
    scheduleDateHintWatchdog(context, phaseId, state.rescheduleDelay);
    return true;
  }

  private boolean forceCompleteDateHintWatchdogIfNeeded(
      ClientContext context, long phaseId, DateHintWatchdogState state) {
    if (state.callbackToForceComplete == null) {
      return false;
    }
    LOG.warn(
        "USK datehint insert phase {} did not deliver terminal callback {} ms after watchdog"
            + " cancel on {} - forcing completion",
        phaseId,
        state.cancelAge,
        this);
    state.callbackToForceComplete.forceCompletionAfterWatchdogTimeout(
        context, state.forceCompletionState);
    return true;
  }

  private void runDateHintWatchdog(ClientContext context, long phaseId) {
    DateHintWatchdogState state = snapshotDateHintWatchdogState(phaseId);
    if (state == null) {
      return;
    }
    if (state.evaluateSchedulerCooldown) {
      state = evaluateDateHintSchedulerCooldown(context, phaseId, state);
      if (state == null) {
        return;
      }
    }
    if (rescheduleDateHintWatchdogIfNeeded(context, phaseId, state)) {
      return;
    }
    if (forceCompleteDateHintWatchdogIfNeeded(context, phaseId, state)) {
      return;
    }
    if (state.callbackToCancel == null) {
      return;
    }
    LOG.warn(
        "USK datehint insert phase {} stalled for {} ms on {} (retry {} of {}) - cancelling phase",
        phaseId,
        state.stalledFor,
        this,
        state.retryCount,
        MAX_DATEHINT_STALL_RETRIES);
    state.callbackToCancel.cancelGroup(context);
    scheduleDateHintWatchdog(context, phaseId, DATEHINT_CANCEL_COMPLETION_TIMEOUT_MILLIS);
  }

  private void scheduleInsert(ClientContext context) {
    // Schedules a single-block insert for the current candidate edition.
    long latestKnownSlot = context.uskManager.lookupLatestSlot(pubUSK) + 1;
    SingleBlockInserter localSbi;
    synchronized (this) {
      if (finished) return;
      edition = Math.max(edition, latestKnownSlot);
      if (LOG.isDebugEnabled()) LOG.debug("scheduling insert for {} {}", pubUSK.getURI(), edition);
      localSbi =
          sbi =
              new SingleBlockInserter(
                  new BlockInsertPayload(
                      data,
                      privUSK.getInsertableSSK(edition).getInsertURI(),
                      compressionCodec,
                      isMetadata,
                      sourceLength,
                      cryptoAlgorithm,
                      forceCryptoKey),
                  new BlockInsertParams(parent, ctx, this, token, tokenObject, false, context),
                  new BlockInsertOptions(persistent, realTimeFlag, false, extraInserts),
                  true /* we don't use it */);
    }
    try {
      localSbi.schedule(context);
    } catch (InsertException e) {
      Bucket dataToFree = null;
      synchronized (this) {
        finished = true;
        if (freeData) {
          dataToFree = data;
          data = null;
        }
      }
      if (dataToFree != null) dataToFree.free();
      cb.onFailure(e, this, context);
    }
  }

  /**
   * Notifies that the single-block insert succeeded.
   *
   * <p>Updates the USK manager with the confirmed edition, frees data if configured, and reports
   * the encoded USK (with a concrete edition) to the completion callback. Also triggers optional
   * USK date hint insertion when enabled by the insert context.
   *
   * @param state the originating state that completed, expected to be a {@link SingleBlockInserter}
   * @param context the client context for follow-up work and bookkeeping
   */
  @Override
  public synchronized void onSuccess(ClientPutState state, ClientContext context) {
    USK newEdition = pubUSK.copy(edition);
    finished = true;
    sbi = null;
    FreenetURI targetURI = pubUSK.getSSK(edition).getURI();
    FreenetURI realURI = ((SingleBlockInserter) state).getURI(context);
    if (!targetURI.equals(realURI))
      LOG.error("URI should be {} actually is {}", targetURI, realURI);
    else {
      if (LOG.isDebugEnabled()) LOG.debug("URI should be {} actually is {}", targetURI, realURI);
      context.uskManager.updateKnownGood(pubUSK, edition, context);
    }
    if (freeData) {
      data.free();
      data = null;
    }
    cb.onEncode(newEdition, this, context);
    insertSucceeded(context, edition);
    // FINISHED!!!! Yay!!!
  }

  /**
   * Handles insert failure from the single-block inserter.
   *
   * <p>On collision, advances the edition and retries until a bound is reached, after which it
   * reschedules discovery. For other failures, transitions to a terminal state, frees data if
   * configured, and propagates the failure to the completion callback.
   *
   * @param e the cause of the failure, including mode information such as collisions
   * @param state the state reporting the failure, typically a {@link SingleBlockInserter}
   * @param context the client context used to schedule retries or propagate the failure
   */
  @Override
  public void onFailure(InsertException e, ClientPutState state, ClientContext context) {
    synchronized (this) {
      if (finished) return;
      sbi = null;
      if (e.getMode() == InsertExceptionMode.COLLISION) {
        // Try the next slot
        edition++;
        consecutiveCollisions++;
        if (consecutiveCollisions > MAX_TRIED_SLOTS) scheduleFetcher(context);
        else scheduleInsert(context);
      } else {
        Bucket dataToFree = null;
        finished = true;
        if (freeData) {
          dataToFree = data;
          data = null;
        }
        if (dataToFree != null) dataToFree.free();
        cb.onFailure(e, state, context);
      }
    }
  }

  /**
   * Returns a stable identity-based hash code for this inserter instance.
   *
   * @return the precomputed hash code suitable for identity maps and sets
   */
  @Override
  public int hashCode() {
    return hashCode;
  }

  /**
   * Uses reference equality. Inserter instances are not value objects and equality is not defined
   * over state.
   *
   * @param obj the object to compare with this instance
   * @return {@code true} if and only if {@code obj} is the same instance as this
   */
  @Override
  public boolean equals(Object obj) {
    return this == obj;
  }

  /**
   * Creates a new inserter for the given USK payload.
   *
   * <p>The constructor captures all parameters needed to discover the target edition and perform an
   * SSK block insert. No I/O or scheduling occurs until {@link #schedule(ClientContext)} is called.
   * Callers may choose to have the payload freed automatically upon terminal completion.
   *
   * @param payload block data and encoding parameters for the USK insert
   * @param params shared inserter parameters including parent, callbacks, and insert context
   * @param options persistence and scheduling options for this insert
   * @throws MalformedURLException if {@code payload.uri()} does not form a valid insertable USK
   */
  public USKInserter(
      BlockInsertPayload payload, BlockInsertParams params, BlockInsertOptions options)
      throws MalformedURLException {
    this.hashCode = System.identityHashCode(this);
    this.tokenObject = params.tokenObject();
    this.persistent = options.persistent();
    this.parent = params.parent();
    this.data = payload.data();
    this.compressionCodec = payload.compressionCodec();
    this.ctx = params.ctx();
    this.cb = params.callback();
    this.isMetadata = payload.isMetadata();
    this.sourceLength = payload.sourceLength();
    this.token = params.token();
    if (params.addToParent()) {
      params.parent().addMustSucceedBlocks(1);
      params.parent().notifyClients(params.context());
    }
    privUSK = InsertableUSK.createInsertable(payload.uri(), options.persistent());
    pubUSK = privUSK.getUSK();
    edition = pubUSK.suggestedEdition;
    this.freeData = options.freeData();
    this.extraInserts = options.extraInserts();
    this.cryptoAlgorithm = payload.cryptoAlgorithm();
    this.forceCryptoKey = payload.cryptoKey();
    this.realTimeFlag = options.realTimeFlag();
    this.externalRequestIdentifierSnapshot = null;
    reapplyExternalRequestIdentifierIfNeeded();
  }

  /**
   * No-arg constructor for serialization frameworks.
   *
   * <p>Not intended for direct use by application code. Fields are initialized to the defaults only
   * to satisfy deserialization requirements.
   */
  @SuppressWarnings("unused")
  USKInserter() {
    // For serialization.
    this.hashCode = 0;
    this.tokenObject = null;
    this.persistent = false;
    this.parent = null;
    this.data = null;
    this.compressionCodec = 0;
    this.ctx = null;
    this.cb = null;
    this.isMetadata = false;
    this.sourceLength = 0;
    this.token = 0;
    this.privUSK = null;
    this.pubUSK = null;
    this.edition = 0;
    this.freeData = false;
    this.extraInserts = 0;
    this.cryptoAlgorithm = 0;
    this.forceCryptoKey = null;
    this.realTimeFlag = false;
    this.externalRequestIdentifierSnapshot = null;
  }

  /**
   * Returns the parent putter that owns this inserter.
   *
   * @return the non-null parent used for coordination, progress, and prioritization
   */
  @Override
  public BaseClientPutter getParent() {
    return parent;
  }

  /**
   * Cancels the ongoing insert if it has not yet reached a terminal state.
   *
   * <p>Cancels any outstanding discovery and insert tasks, frees data when configured, and reports
   * a {@link InsertExceptionMode#CANCELLED} failure to the completion callback. Safe to call more
   * than once; later calls after completion have no effect.
   *
   * @param context the client context used to propagate cancellation downstream
   */
  @Override
  public void cancel(ClientContext context) {
    USKFetcherTag tag;
    SingleBlockInserter localSbi;
    DateHintTerminalCallback localDateHintCallback;
    synchronized (this) {
      if (finished) return;
      finished = true;
      tag = fetcher;
      fetcher = null;
      localSbi = sbi;
      sbi = null;
      localDateHintCallback =
          (activeDateHintPhase == null) ? null : activeDateHintPhase.terminalCallback;
      activeDateHintPhase = null;
    }
    if (tag != null) {
      tag.cancel(context);
    }
    if (localSbi != null) {
      localSbi.cancel(context); // will call onFailure, which will removeFrom()
    }
    if (localDateHintCallback != null) {
      localDateHintCallback.cancelGroup(context);
    }
    if (freeData) {
      Bucket dataToFree;
      synchronized (this) {
        dataToFree = data;
        data = null;
      }
      if (dataToFree != null) dataToFree.free();
    }
    cb.onFailure(new InsertException(InsertExceptionMode.CANCELLED), this, context);
  }

  /**
   * Callback from the USK fetcher when discovery did not find a suitable edition.
   *
   * <p>Proceeds to schedule an insert at the next candidate edition based on current knowledge.
   *
   * @param context the client context used to schedule the insert attempt
   */
  @Override
  public void onFailure(ClientContext context) {
    if (LOG.isDebugEnabled())
      LOG.debug("Fetcher failed to find the given edition or any later edition on {}", this);
    scheduleInsert(context);
  }

  /**
   * Indicates that the fetcher was canceled unexpectedly.
   *
   * <p>Treats this as an error and cancels the overall operation, reporting a cancellation failure
   * to the completion callback.
   *
   * @param context the client context used while propagating cancellation
   */
  @Override
  public void onCancelled(ClientContext context) {
    synchronized (this) {
      fetcher = null;
      if (finished) return;
    }
    LOG.error("Unexpected onCancelled()");
    cancel(context);
  }

  /**
   * Notifies that an encoding event occurred during the insert pipeline. This implementation does
   * not take action for encoding events; the final success path reports the encoded USK separately.
   *
   * @param key the key associated with the encoding event
   * @param state the state reporting the event
   * @param context the client context at the time of the event
   */
  @Override
  public void onEncode(BaseClientKey key, ClientPutState state, ClientContext context) {
    // Ignore
  }

  /**
   * Notifies that the inserter transitioned between internal states. This implementation does not
   * expect transitions outside the insert lifecycle; unexpected transitions are logged.
   *
   * @param oldState previous state instance
   * @param newState new state instance
   * @param context client context during the transition
   */
  @Override
  public void onTransition(
      ClientPutState oldState, ClientPutState newState, ClientContext context) {
    // Shouldn't happen
    LOG.error("Got onTransition({},{})", oldState, newState);
  }

  /**
   * Reports metadata produced during the insert pipeline. This inserter does not expect metadata
   * callbacks for USK inserts; unexpected events are logged.
   *
   * @param m metadata instance
   * @param state the state reporting the metadata
   * @param context the client context at the time of the callback
   */
  @Override
  public void onMetadata(Metadata m, ClientPutState state, ClientContext context) {
    // Shouldn't happen
    LOG.error("Got onMetadata({},{})", m, state);
  }

  /**
   * Indicates that a set of blocks has finished processing. Not used by this inserter.
   *
   * @param state reporting state
   * @param context client context
   */
  @Override
  public void onBlockSetFinished(ClientPutState state, ClientContext context) {
    // Ignore
  }

  /**
   * Returns the opaque token associated with this operation.
   *
   * @return the token object provided at construction time; may be {@code null}
   */
  @Override
  public Object getToken() {
    return tokenObject;
  }

  /**
   * Indicates that content is fetchable for verification or reporting. Not used by this inserter.
   *
   * @param state reporting state
   */
  @Override
  public void onFetchable(ClientPutState state) {
    // Ignore
  }

  /**
   * Returns the normal polling priority used by the scheduler for this operation.
   *
   * @return the priority class delegated from the parent
   */
  @Override
  public short getPollingPriorityNormal() {
    return parent.getPriorityClass();
  }

  /**
   * Returns the progress polling priority used by the scheduler for this operation.
   *
   * @return the priority class delegated from the parent
   */
  @Override
  public short getPollingPriorityProgress() {
    return parent.getPriorityClass();
  }

  /**
   * Receives metadata as a bucket during the insert pipeline. This inserter does not retain such
   * metadata and frees the provided bucket immediately.
   *
   * @param meta metadata as a bucket; will be freed by this method
   * @param state reporting state
   * @param context client context
   */
  @Override
  public void onMetadata(Bucket meta, ClientPutState state, ClientContext context) {
    LOG.error("onMetadata on {} from {}", this, state);
    meta.free();
  }

  private transient boolean resumed = false;

  /**
   * Resumes the inserter after persistence or a paused state.
   *
   * <p>Propagates resume events to owned resources exactly once and re-arms any outstanding fetch
   * or insert operations.
   *
   * @param context the client context used to resume subordinate components
   * @throws InsertException if resuming the insert pipeline fails
   * @throws ResumeFailedException if any component cannot resume cleanly
   */
  @Override
  public void onResume(ClientContext context) throws InsertException, ResumeFailedException {
    Bucket localData;
    USKFetcherTag localFetcher;
    SingleBlockInserter localSbi;
    synchronized (this) {
      if (resumed) return;
      resumed = true;
      localData = data;
      localFetcher = fetcher;
      localSbi = sbi;
    }
    reapplyExternalRequestIdentifierIfNeeded();
    if (localData != null) localData.onResume(context);
    if (cb != null && cb != parent) cb.onResume(context);
    if (localFetcher != null) localFetcher.onResume(context);
    if (localSbi != null) localSbi.onResume(context);
  }

  /**
   * Notifies the inserter of an imminent shutdown so it can release resources eagerly.
   *
   * @param context the client context at shutdown time
   */
  @Override
  public void onShutdown(ClientContext context) {
    SingleBlockInserter localSbi;
    synchronized (this) {
      localSbi = this.sbi;
    }
    if (localSbi != null) localSbi.onShutdown(context);
  }
}

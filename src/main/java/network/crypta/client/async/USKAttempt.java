package network.crypta.client.async;

import network.crypta.client.FetchContext;
import network.crypta.keys.ClientSSKBlock;
import network.crypta.keys.USK;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Tracks a single edition probe, including its checker state and polling metadata.
 *
 * <p>Each attempt owns a {@link USKChecker} that performs the actual request and reports completion
 * through {@link USKCheckerCallback}. The attempt records whether it has succeeded, failed (DNF),
 * or been canceled, and it exposes scheduling hooks used by the owning fetcher.
 */
final class USKAttempt implements USKCheckerCallback {
  /** Logger for attempt scheduling diagnostics. */
  private static final Logger LOG = LoggerFactory.getLogger(USKAttempt.class);

  /** Literal used in attempt descriptions to keep log formatting consistent. */
  private static final String FOR_LITERAL = " for ";

  /** Edition number. */
  long number;

  /** Attempt to fetch that edition number (or null if the fetch has finished). */
  USKChecker checker;

  /** Successful fetch? */
  boolean succeeded;

  /** DNF? */
  boolean dnf;

  /** Whether this attempt has been explicitly canceled. */
  boolean cancelled;

  /** Lookup descriptor associated with this attempt. */
  final USKFetcher.Lookup lookup;

  /** Whether this attempt is a long-lived polling attempt. */
  final boolean forever;

  /** Whether this attempt has ever entered finite cooldown. */
  private boolean everInCooldown;

  private final USKAttemptCallbacks callbacks;
  private final USK origUSK;
  private final FetchContext ctx;
  private final FetchContext ctxNoStore;
  private final ClientRequester parent;
  private final boolean realTimeFlag;

  /**
   * Creates a new attempt for the provided lookup descriptor.
   *
   * @param callbacks owning callback handler for lifecycle events
   * @param origUSK base USK used for logging
   * @param ctx base fetch context for scheduling
   * @param ctxNoStore no-store fetch context for probes that bypass the store
   * @param parent parent requester providing scheduling policy
   * @param lookup descriptor containing edition and key information
   * @param forever {@code true} to create a polling attempt; {@code false} for a one-off probe
   * @param realTimeFlag whether to use real-time scheduling for the checker
   */
  USKAttempt(
      USKAttemptCallbacks callbacks,
      USK origUSK,
      FetchContext ctx,
      FetchContext ctxNoStore,
      ClientRequester parent,
      USKFetcher.Lookup lookup,
      boolean forever,
      boolean realTimeFlag) {
    this.callbacks = callbacks;
    this.origUSK = origUSK;
    this.ctx = ctx;
    this.ctxNoStore = ctxNoStore;
    this.parent = parent;
    this.lookup = lookup;
    this.number = lookup.val;
    this.succeeded = false;
    this.dnf = false;
    this.forever = forever;
    this.realTimeFlag = realTimeFlag;
    this.checker =
        new USKChecker(
            this,
            lookup.key,
            forever ? -1 : ctx.maxUSKRetries,
            lookup.ignoreStore ? ctxNoStore : ctx,
            parent,
            realTimeFlag);
  }

  @Override
  public void onDNF(ClientContext context) {
    synchronized (this) {
      checker = null;
      dnf = true;
    }
    callbacks.onDNF(this, context);
  }

  @Override
  public void onSuccess(ClientSSKBlock block, ClientContext context) {
    synchronized (this) {
      checker = null;
      succeeded = true;
    }
    callbacks.onSuccess(this, false, block, context);
  }

  @Override
  public void onFatalAuthorError(ClientContext context) {
    synchronized (this) {
      checker = null;
    }
    // Counts as success except it doesn't update
    callbacks.onSuccess(this, true, null, context);
  }

  @Override
  public void onNetworkError(ClientContext context) {
    synchronized (this) {
      checker = null;
    }
    // Treat network error as DNF for scheduling purposes
    callbacks.onDNF(this, context);
  }

  @Override
  public void onCancelled(ClientContext context) {
    synchronized (this) {
      checker = null;
    }
    callbacks.onCancelled(this, context);
  }

  /**
   * Cancels this attempt and propagates cancellation to the checker if present.
   *
   * @param context client context used to cancel scheduling; must not be null
   */
  public void cancel(ClientContext context) {
    cancelled = true;
    USKChecker c;
    synchronized (this) {
      c = checker;
    }
    if (c != null) c.cancel(context);
    onCancelled(context);
  }

  /**
   * Schedules this attempt with its checker if still active.
   *
   * @param context client context used to schedule the checker; must not be null
   */
  public void schedule(ClientContext context) {
    USKChecker c;
    synchronized (this) {
      c = checker;
    }
    if (c == null) {
      if (LOG.isDebugEnabled()) LOG.debug("Checker == null in schedule() for {}", this);
    } else {
      assert (!c.persistent());
      c.schedule(context);
    }
  }

  @Override
  public String toString() {
    return "USKAttempt for "
        + number
        + FOR_LITERAL
        + origUSK.getURI()
        + (forever ? " (forever)" : "");
  }

  @Override
  public short getPriority() {
    if (callbacks.isBackgroundPoll()) {
      synchronized (this) {
        if (forever) {
          if (!everInCooldown) {
            // Boost the priority initially, so that finding the first edition takes precedence
            // over ongoing polling after we're fairly sure we're not going to find anything.
            // The ongoing polling keeps the ULPRs up to date so that we will get told quickly,
            // but if we are overloaded we won't be able to keep up regardless.
            return callbacks.getProgressPollPriority();
          } else {
            return callbacks.getNormalPollPriority();
          }
        } else {
          // If !forever, this is a random-probe.
          // It's not that important.
          return callbacks.getNormalPollPriority();
        }
      }
    }
    return parent.getPriorityClass();
  }

  @Override
  public void onEnterFiniteCooldown(ClientContext context) {
    synchronized (this) {
      everInCooldown = true;
    }
    callbacks.onEnterFiniteCooldown(context);
  }

  /**
   * Reports whether this attempt has ever entered a finite cooldown.
   *
   * @return {@code true} if the attempt has cooled down at least once
   */
  public synchronized boolean everInCooldown() {
    return everInCooldown;
  }

  /** Refreshes cached poll parameters on the underlying checker, if active. */
  public void reloadPollParameters() {
    USKChecker c;
    synchronized (this) {
      c = checker;
    }
    if (c == null) return;
    c.onChangedFetchContext();
  }
}

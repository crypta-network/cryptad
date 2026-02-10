package network.crypta.client.async;

import java.io.Serial;
import java.io.Serializable;
import network.crypta.client.FetchContext;
import network.crypta.keys.USK;
import network.crypta.support.io.NativeThread;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Tag object that associates a {@link USK} query with a callback to notify when a fetch completes.
 * The tag itself is serializable and suitable for inclusion in persistent client requests, while
 * the underlying {@code USKFetcher} that performs the work is always transient and recreated on
 * demand after restarts.
 *
 * <p>This type exists to decouple long-lived request intent from the short-lived mechanics of a
 * running fetch. Typical usage is to construct a tag via {@link #create(USK, USKFetcherCallback,
 * FetchContext, int, Flag...)} and then hand it to code that schedules work. On startup the node
 * reinstates pending USK fetches from a persistent state; tags are reused while a new transient
 * fetcher is created and wired to the original callback.
 *
 * <p>Concurrency: instances are designed to be passed across threads managed by {@code
 * ClientContext} and the persistent job runner. Internal state uses minimal synchronization to
 * protect the life‑cycle flag. Callbacks are invoked on the appropriate execution context depending
 * on whether the request is persistent.
 *
 * <p>WARNING: Altering the set of non‑transient fields of a {@code Serializable} class can affect
 * the on‑disk form and may cause requests to restart or state to be lost after upgrade.
 *
 * @author toad
 * @see USK
 * @see USKManager
 * @see USKFetcherCallback
 */
public class USKFetcherTag implements ClientGetState, USKFetcherCallback, Serializable {
  private static final Logger LOG = LoggerFactory.getLogger(USKFetcherTag.class);

  @Serial private static final long serialVersionUID = 1L;

  /**
   * Callback invoked when the associated USK fetch reaches a terminal outcome. The reference is
   * provided by the caller during construction and is not mutated by this class. Implementations
   * may assume the same instance will be used after restarts for persistent requests.
   */
  public final USKFetcherCallback callback;

  /**
   * The original USK supplied by the caller. This object is preserved for identity/reference; a
   * copy may be created internally when starting a fetch to adjust the edition or avoid
   * deactivation corner cases.
   */
  public final USK origUSK;

  /**
   * Latest known or requested edition. This value is monotonically increased via {@link
   * #updatedEdition(long)} when new information is learned. Implementations treat negative values
   * as invalid; typical callers provide a non‑negative edition.
   */
  protected long edition;

  /**
   * Whether the request is persistent across restarts. When {@code true}, callbacks are routed via
   * the persistent job runner so they execute after state reloading; when {@code false}, callbacks
   * are delivered immediately on the current context.
   */
  public final boolean persistent;

  /**
   * Fetch context controlling policies such as timeouts, routing, and verification. The context is
   * supplied by the caller and is treated as read‑only by this type; ownership and lifecycle remain
   * with the caller.
   */
  public final FetchContext ctx;

  /**
   * If {@code true}, the most recently retrieved data bytes are retained by the fetcher and may be
   * exposed to the callback even when newer editions are probed. Primarily influences how the
   * underlying {@code USKFetcher} manages in‑flight state.
   */
  public final boolean keepLastData;

  /** Priority used for the initial schedule; derived from the callback. */
  private final short priority;

  /**
   * Opaque application token preserved across callbacks. Useful for correlating fetch completion
   * with the original request or UI action. This class does not interpret the value.
   */
  private final long token;

  private transient USKFetcher fetcher;

  /** Priority to use when idle or without observed progress; sourced from the callback. */
  private final short pollingPriorityNormal;

  /** Priority to use while progress is observed; sourced from the callback. */
  private final short pollingPriorityProgress;

  /** Terminal state flag to avoid duplicate callbacks and to gate rescheduling. */
  private boolean finished;

  /** If true, restricts the fetcher to local store checks without network access. */
  private final boolean checkStoreOnly;

  /** Cached identity-based hash code captured at construction to remain stable across restarts. */
  private final int hashCode;

  /** Whether realtime requester class should be used when scheduling the transient fetcher. */
  private final boolean realTimeFlag;

  // Bit flags for options to reduce long parameter lists
  @SuppressWarnings("PointlessBitwiseExpression")
  private static final int OPT_PERSISTENT = 1 << 0;

  private static final int OPT_REALTIME = 1 << 1;
  private static final int OPT_KEEP_LAST = 1 << 2;
  private static final int OPT_CHECK_STORE_ONLY = 1 << 3;

  private USKFetcherTag(
      USK origUSK, USKFetcherCallback callback, FetchContext ctx, long token, int options) {
    this.callback = callback;
    this.origUSK = origUSK;
    this.edition = origUSK.suggestedEdition;
    this.persistent = (options & OPT_PERSISTENT) != 0;
    this.ctx = ctx;
    this.keepLastData = (options & OPT_KEEP_LAST) != 0;
    this.token = token;
    this.realTimeFlag = (options & OPT_REALTIME) != 0;
    pollingPriorityNormal = callback.getPollingPriorityNormal();
    pollingPriorityProgress = callback.getPollingPriorityProgress();
    priority = pollingPriorityNormal;
    this.checkStoreOnly = (options & OPT_CHECK_STORE_ONLY) != 0;
    this.hashCode = System.identityHashCode(this);
    if (LOG.isDebugEnabled()) LOG.debug("Created tag for {} and {} : {}", origUSK, callback, this);
  }

  @Override
  public int hashCode() {
    return hashCode;
  }

  /**
   * Creates a new tag binding a USK, callback, and fetch context, with optional behavior flags. The
   * returned tag can be serialized as part of a persistent request; the transient fetcher will be
   * constructed when the tag is scheduled or resumed.
   *
   * <p>For persistent requests, the caller is responsible for removing the request from persistent
   * storage when it is no longer necessary; the lifecycle of the {@link USKFetcherCallback} and
   * {@link FetchContext} remains under the caller’s control.
   *
   * @param usk The original {@link USK} to fetch; must be non‑null. The edition may be adjusted
   *     internally when scheduling.
   * @param callback Consumer that receives terminal outcomes; must be non‑null and remain valid for
   *     the lifetime of the request.
   * @param ctx Fetch policy and routing context to use for the fetch; must be non‑null and is
   *     treated as read‑only by this tag.
   * @param token Application‑supplied token for correlation; preserved and returned from {@link
   *     #getToken()} unchanged.
   * @param flags Optional behavior switches influencing persistence, realtime scheduling, and store
   *     probing. Omit for defaults; duplicates are ignored.
   * @return A new {@code USKFetcherTag} instance encapsulating the provided arguments and options;
   *     never {@code null}.
   */
  public static USKFetcherTag create(
      USK usk, USKFetcherCallback callback, FetchContext ctx, int token, Flag... flags) {
    int opts = 0;
    if (flags != null) {
      for (Flag f : flags) {
        if (f == null) continue;
        switch (f) {
          case PERSISTENT -> opts |= OPT_PERSISTENT;
          case REAL_TIME -> opts |= OPT_REALTIME;
          case KEEP_LAST_DATA -> opts |= OPT_KEEP_LAST;
          case CHECK_STORE_ONLY -> opts |= OPT_CHECK_STORE_ONLY;
        }
      }
    }
    return new USKFetcherTag(usk, callback, ctx, token, opts);
  }

  /**
   * Records that at least the given edition is known or observed. If the supplied edition is
   * greater than the current value, the internal edition is raised; otherwise this call has no
   * effect. The method is thread‑safe relative to other updates on the same instance.
   *
   * @param ed New lower‑bound for the desired or known edition; must be non‑negative for typical
   *     use. Values less than the current edition are ignored.
   */
  synchronized void updatedEdition(long ed) {
    if (edition < ed) edition = ed;
  }

  /**
   * Starts or restarts the transient fetcher for the current tag. If the supplied USK has an older
   * edition than the last known edition, a copy is made with the newer edition to avoid redundant
   * work. For persistent requests a defensive copy is also made to prevent deactivation issues.
   *
   * <p>Idempotency: calling {@code start()} after a previous start schedules a new fetcher instance
   * and does not signal the callback immediately. Typical callers prefer {@link
   * #schedule(ClientContext)}.
   *
   * @param manager The manager responsible for creating and tracking {@code USKFetcher} instances;
   *     must be non‑null.
   * @param context The client execution context used to schedule work and callbacks; must be
   *     non‑null.
   */
  public void start(USKManager manager, ClientContext context) {
    USK usk = origUSK;
    long editionSnapshot;
    synchronized (this) {
      editionSnapshot = edition;
    }
    if (usk.suggestedEdition < editionSnapshot) {
      usk = usk.copy(editionSnapshot);
    } else if (persistent) { // Copy it to avoid deactivation issues
      usk = usk.copy();
    }
    fetcher =
        manager.getFetcher(
            usk,
            ctx,
            new USKFetcherWrapper(
                usk, priority, realTimeFlag ? USKManager.rcRT : USKManager.rcBulk),
            keepLastData,
            checkStoreOnly);
    fetcher.addCallback(this);
    fetcher.schedule(context); // non-persistent
    if (LOG.isDebugEnabled()) LOG.debug("Starting {} for {}", fetcher, this);
  }

  /**
   * Requests cancellation of the in‑flight fetch, if any, and marks this tag as finished. For
   * persistent requests, a follow‑up callback is delivered on the persistent job runner so callers
   * can update the durable state.
   *
   * @param context The client context used to route the cancellation and potential callback.
   */
  @Override
  public void cancel(ClientContext context) {
    USKFetcher f = fetcher;
    if (f != null) fetcher.cancel(context);
    synchronized (this) {
      if (finished) {
        if (LOG.isDebugEnabled()) LOG.debug("Already cancelled {}", this);
        return;
      }
      finished = true;
    }
    if (f != null) LOG.error("cancel() for {} did not set finished on {} ???", fetcher, this);
  }

  @Override
  public long getToken() {
    return token;
  }

  /**
   * Schedules work for this tag on the provided context, creating a transient fetcher as needed. A
   * convenience that delegates to {@link #start(USKManager, ClientContext)} using the context’s
   * {@link USKManager}.
   *
   * @param context The client context that supplies the {@link USKManager} and scheduling queues.
   */
  @Override
  public void schedule(ClientContext context) {
    start(context.uskManager, context);
  }

  /**
   * Notification that the fetch was canceled before producing a result. Ensures callbacks are
   * delivered on the appropriate executor depending on persistence and marks this tag as finished.
   * Subsequent terminal events are ignored.
   *
   * @param context Client context on which to execute the callback or to enqueue a persistent job.
   */
  @Override
  public void onCancelled(ClientContext context) {
    if (LOG.isDebugEnabled()) LOG.debug("Cancelled on {}", this);
    synchronized (this) {
      finished = true;
    }
    if (persistent) {
      // This can be called from USKFetcher, in which case we want to run on the
      // PersistentJobRunner.
      try {
        context.jobRunner.queue(
            (PersistentJob)
                context1 -> {
                  if (callback instanceof USKFetcherTagCallback tagCallback)
                    tagCallback.setTag(USKFetcherTag.this, context1);
                  callback.onCancelled(context1);
                  return false;
                },
            NativeThread.PriorityLevel.HIGH_PRIORITY.value);
      } catch (PersistenceDisabledException _) {
        // Impossible.
      }
    } else {
      if (callback instanceof USKFetcherTagCallback tagCallback)
        tagCallback.setTag(USKFetcherTag.this, context);
      callback.onCancelled(context);
    }
  }

  /**
   * Notification that the fetch failed with a terminal error. The callback is invoked, and this tag
   * is marked as finished. When persistent, the notification is delivered via the persistent job
   * runner to preserve ordering with durable state updates.
   *
   * @param context Client context on which to execute the callback or to enqueue a persistent job.
   */
  @Override
  public void onFailure(ClientContext context) {
    if (LOG.isDebugEnabled()) LOG.debug("Failed on {}", this);
    synchronized (this) {
      if (finished) {
        LOG.warn("onFailure called after finish on {}", this);
        return;
      }
      finished = true;
    }
    if (persistent) {
      try {
        context.jobRunner.queue(
            (PersistentJob)
                context1 -> {
                  if (callback instanceof USKFetcherTagCallback tagCallback)
                    tagCallback.setTag(USKFetcherTag.this, context1);
                  callback.onFailure(context1);
                  return true;
                },
            NativeThread.PriorityLevel.HIGH_PRIORITY.value);
      } catch (PersistenceDisabledException _) {
        // Impossible.
      }
    } else {
      if (callback instanceof USKFetcherTagCallback tagCallback)
        tagCallback.setTag(USKFetcherTag.this, context);
      callback.onFailure(context);
    }
  }

  /**
   * Returns the priority to use when no progress is currently observed. The value is obtained from
   * the callback at construction time and remains constant for the life of this instance.
   *
   * @return The normal polling priority value as a short; higher means more urgent.
   */
  @Override
  public short getPollingPriorityNormal() {
    return pollingPriorityNormal;
  }

  /**
   * Returns the elevated priority to apply while progress is being made. The value is obtained from
   * the callback at construction time and remains constant for the life of this instance.
   *
   * @return The progress polling priority value as a short; higher means more urgent.
   */
  @Override
  public short getPollingPriorityProgress() {
    return pollingPriorityProgress;
  }

  /**
   * Notification that a USK edition was found. Marks this tag as finished and forwards the event to
   * the callback on the appropriate executor depending on persistence. The provided data may be
   * {@code null} when only metadata is available.
   *
   * @param foundEdition The payload describing the discovered edition and its metadata.
   */
  @Override
  public void onFoundEdition(final USKFoundEdition foundEdition) {
    if (LOG.isDebugEnabled()) LOG.debug("Found edition {} on {}", foundEdition.edition(), this);
    synchronized (this) {
      if (fetcher == null) {
        LOG.warn(
            "onFoundEdition but fetcher is null - isn't onFoundEdition() terminal for"
                + " USKFetcherCallback's??");
      }
      if (finished) {
        LOG.warn("onFoundEdition called after finish on {}", this);
        return;
      }
      finished = true;
      fetcher = null;
    }
    ClientContext context = foundEdition.context();
    if (persistent) {
      try {
        context.jobRunner.queue(
            (PersistentJob)
                context1 -> {
                  if (callback instanceof USKFetcherTagCallback tagCallback)
                    tagCallback.setTag(USKFetcherTag.this, context1);
                  callback.onFoundEdition(foundEdition.withContext(context1));
                  return false;
                },
            NativeThread.PriorityLevel.HIGH_PRIORITY.value);
      } catch (PersistenceDisabledException _) {
        // Impossible.
      }
    } else {
      if (callback instanceof USKFetcherTagCallback tagCallback)
        tagCallback.setTag(USKFetcherTag.this, context);
      callback.onFoundEdition(foundEdition);
    }
  }

  /**
   * Indicates whether this tag has already received a terminal event (canceled, failure, or edition
   * found). Once {@code true}, no further callbacks are emitted for this instance.
   *
   * @return {@code true} when a terminal event was processed; otherwise {@code false}.
   */
  public final synchronized boolean isFinished() {
    return finished;
  }

  /**
   * Identity equality. This type intentionally preserves {@link Object#equals(Object)} semantics
   * such that only the same instance compares equal. Tags are used as handles rather than value
   * objects; do not rely on field equality.
   *
   * @param obj The object to compare for identity equality.
   * @return {@code true} if and only if {@code obj} is the same instance.
   */
  @Override
  public boolean equals(Object obj) {
    return this == obj;
  }

  /**
   * Called when work should resume after a pause or restart. If the tag is not yet finished, a new
   * transient fetcher is started on the provided context.
   *
   * @param context The client context on which to start the fetcher.
   */
  @Override
  public void onResume(ClientContext context) {
    if (isFinished()) return;
    start(context.uskManager, context);
  }

  /**
   * Notification that the system is shutting down. This implementation does not perform additional
   * work because tags are either finished or will be rescheduled during startup.
   *
   * @param context The client context providing shutdown state; ignored.
   */
  @Override
  public void onShutdown(ClientContext context) {
    // Ignore.
  }

  /**
   * Aggregated flags for optional behavior when creating a tag. Flags can be combined to enable
   * persistence, realtime scheduling, retention of last data, or store‑only probing. Unknown or
   * duplicate values are ignored when constructing the tag.
   */
  public enum Flag {
    /**
     * Persist the request so it survives restarts. Callbacks are routed via the persistent job
     * runner to maintain ordering with durable state updates.
     */
    PERSISTENT,

    /**
     * Prefer realtime scheduling where supported. Typically maps to a higher requester class in the
     * {@link USKManager} to reduce latency at the cost of throughput.
     */
    REAL_TIME,

    /**
     * Retain the last successfully fetched data while probing for newer editions. Useful when
     * consumers prefer the best‑effort result even during upgrades.
     */
    KEEP_LAST_DATA,

    /**
     * Check the local store only without performing network fetches. Intended for quick existence
     * tests or cache‑only probes.
     */
    CHECK_STORE_ONLY
  }

  // Explicit serialization hooks to preserve default behavior while satisfying analysis
  /**
   * Custom serialization hook delegating to default serialization. Exists to keep the serialized
   * form stable and to allow future extension if needed. No additional fields are written.
   *
   * @param out Target stream to write the default form to; must be non-null.
   * @throws java.io.IOException If the underlying stream fails.
   */
  @Serial
  private void writeObject(java.io.ObjectOutputStream out) throws java.io.IOException {
    out.defaultWriteObject();
  }

  /**
   * Custom deserialization hook delegating to default deserialization. Ensures transient fields are
   * left in their initial state and that the stable fields are restored as written.
   *
   * @param in Source stream to read the default form from; must be non-null.
   * @throws java.io.IOException If reading fails.
   * @throws ClassNotFoundException If a required class cannot be resolved.
   */
  @Serial
  private void readObject(java.io.ObjectInputStream in)
      throws java.io.IOException, ClassNotFoundException {
    in.defaultReadObject();
  }
}

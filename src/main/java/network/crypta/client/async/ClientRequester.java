package network.crypta.client.async;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.Serial;
import java.io.Serializable;
import java.time.Instant;
import java.util.WeakHashMap;
import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;
import network.crypta.crypt.ChecksumChecker;
import network.crypta.keys.FreenetURI;
import network.crypta.node.RequestClient;
import network.crypta.node.SendableRequest;
import network.crypta.support.io.ResumeFailedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * High-level client requesting orchestration for fetch or insert operations.
 *
 * <p>This type represents a single user-visible request that may expand into many low-level network
 * operations over its lifetime. For example, a fetch may follow redirects, retrieve and verify
 * splitfiles, and unpack container formats before returning data to the caller. Similarly, a large
 * insert (such as a file or a freesite) may be split into many blocks and scheduled across the
 * network with redundancy and retries. Each high-level request is created by a client and is
 * configured via context objects owned by the client layer. Implementations coordinate state
 * transitions, track progress, and communicate updates back to the client in a thread‑safe manner.
 *
 * <p>Requests participate in scheduling via a priority class and a {@linkplain RequestClient}
 * association, which also determines persistence semantics. Persistent requests survive restarts
 * and are resumed, while transient ones are tracked only in memory. Implementations must treat
 * cancellation, failure, and partial completion carefully; the lifecycle is observable through
 * progress counters and transition callbacks. Concurrency is expected: notification callbacks may
 * run off the scheduling thread and should avoid expensive work.
 *
 * <ul>
 *   <li>Tracks total, successful, failed, and fatally failed block counts
 *   <li>Exposes lifecycle hooks for resume, shutdown, and network submission
 *   <li>Supports dynamic priority changes and real‑time scheduling policies
 * </ul>
 *
 * <p><strong>Serialization note:</strong> changing non‑transient members on {@link Serializable}
 * classes can require request restarts or cause loss of upload progress across upgrades. Keep the
 * serialized surface stable for persisted requests.
 *
 * @see SendableRequest
 */
public abstract class ClientRequester implements Serializable, ClientRequestSchedulerGroup {
  private static final Logger LOG = LoggerFactory.getLogger(ClientRequester.class);
  private static final AtomicIntegerFieldUpdater<ClientRequester> TOTAL_BLOCKS_UPDATER =
      AtomicIntegerFieldUpdater.newUpdater(ClientRequester.class, "totalBlocks");
  private static final AtomicIntegerFieldUpdater<ClientRequester> SUCCESSFUL_BLOCKS_UPDATER =
      AtomicIntegerFieldUpdater.newUpdater(ClientRequester.class, "successfulBlocks");
  private static final AtomicIntegerFieldUpdater<ClientRequester> FAILED_BLOCKS_UPDATER =
      AtomicIntegerFieldUpdater.newUpdater(ClientRequester.class, "failedBlocks");
  private static final AtomicIntegerFieldUpdater<ClientRequester> FATALLY_FAILED_BLOCKS_UPDATER =
      AtomicIntegerFieldUpdater.newUpdater(ClientRequester.class, "fatallyFailedBlocks");

  @Serial private static final long serialVersionUID = 1L;

  /**
   * Notifies the requester that its visible state has transitioned.
   *
   * <p>Implementations should treat this as an observation hook to update internal counters,
   * propagate progress, and possibly emit client notifications. The method is invoked by the owning
   * state machine when a transition occurs and may be called on a scheduler thread.
   *
   * @param oldState the previous state instance, or {@code null} if this is the initial state
   * @param newState the new state instance that became active for this requester
   * @param context the transient {@link ClientContext} providing access to schedulers and helpers
   */
  public abstract void onTransition(
      ClientGetState oldState, ClientGetState newState, ClientContext context);

  /** Priority class of the request or insert. */
  protected volatile short priorityClass;

  /** Whether this is a real-time request */
  protected final boolean realTimeFlag;

  /** Has the request or insert been canceled? */
  protected volatile boolean cancelled;

  /**
   * The RequestClient, used to determine whether this request is persistent, and also we
   * round-robin between different RequestClient's in scheduling within a given priority class and
   * retry count.
   */
  protected transient RequestClient client;

  /**
   * Returns the current scheduling priority class for this request.
   *
   * <p>The priority class influences how the request competes for network resources compared to
   * other requests. Implementations and schedulers use this value to order work relative to other
   * items in the same queue or group.
   *
   * @return the priority class identifier currently assigned to this request instance
   */
  public short getPriorityClass() {
    return priorityClass;
  }

  /** Required because we implement {@link Serializable}. */
  protected ClientRequester() {
    realTimeFlag = false;
    creationTime = 0;
    hashCode = 0;
  }

  /**
   * Constructs a requester with the specified priority and owning client.
   *
   * <p>The provided {@link RequestClient} defines persistence behavior and real‑time scheduling
   * policies for this request. A stable, process‑lifetime hash code is captured at construction so
   * that serialized forms can identify the instance across restarts.
   *
   * @param priorityClass the initial priority class used for scheduling; higher priorities may be
   *     processed earlier depending on scheduler policy
   * @param requestClient the owning client providing persistence policy and scheduling flags; must
   *     not be {@code null}
   * @throws NullPointerException if {@code requestClient} is {@code null}
   */
  protected ClientRequester(short priorityClass, RequestClient requestClient) {
    if (requestClient == null) throw new NullPointerException("requestClient");
    this.priorityClass = priorityClass;
    this.client = requestClient;
    this.realTimeFlag = requestClient.realTimeFlag();
    hashCode =
        System.identityHashCode(
            this); // the old object id will do fine, as long as we ensure it doesn't change!
    synchronized (allRequesters) {
      if (!persistent()) allRequesters.put(this, dumbValue);
    }
    creationTime = System.currentTimeMillis();
  }

  /**
   * Cancel the request. Inner method, subclasses should actually tell the ClientGetState or
   * whatever to cancel itself: this does not do anything apart from set a flag!
   *
   * @return Whether we were already canceled.
   */
  protected synchronized boolean cancel() {
    boolean ret = cancelled;
    cancelled = true;
    return ret;
  }

  /**
   * Requests cancellation of the high‑level operation and propagates it to underlying states.
   *
   * <p>Implementations should be idempotent and return quickly, scheduling any expensive work
   * asynchronously. After cancellation, implementations typically stop creating new network work
   * and allow in‑flight operations to wind down. Client code should observe completion via {@link
   * #isFinished()} and progress notifications rather than busy‑waiting.
   *
   * @param context the {@link ClientContext} carrying transient components such as schedulers used
   *     to propagate cancellation to running tasks
   */
  public abstract void cancel(ClientContext context);

  /**
   * Reports whether the request has been canceled.
   *
   * <p>Cancellation is sticky for the lifetime of the instance. Subclasses may set the canceled
   * flag and then propagate cancellation to underlying states; once set, it remains true even if
   * background work is still unwinding.
   *
   * @return {@code true} if cancellation was requested; {@code false} otherwise
   */
  public boolean isCancelled() {
    return cancelled;
  }

  /**
   * Returns the canonical URI associated with this request.
   *
   * <p>For fetch requests this value is fixed at creation time. For inserts, it becomes available
   * once the final URI is determined by the insert process. Implementations should document whether
   * this method can return {@code null} before initialization is complete.
   *
   * @return the request {@link FreenetURI}, or {@code null} if not yet known for inserts
   */
  public abstract FreenetURI getURI();

  /**
   * Indicates whether the request has reached a terminal state.
   *
   * <p>A terminal state includes success, explicit cancellation, or failure conditions that prevent
   * further progress. Implementations should return {@code true} only when no additional network
   * activity will occur and final notifications have been or will be emitted.
   *
   * @return {@code true} when the request will not perform any further work
   */
  public abstract boolean isFinished();

  /**
   * Stable per-instance hash used for persistence.
   *
   * <p>This field captures the construction‑time identity hash so that serialized forms can
   * preserve equality semantics across process restarts. See {@link #hashCode()} for the exposed
   * behavior.
   */
  private final int hashCode;

  /** We need a hash code that persists across restarts. */
  @Override
  public int hashCode() {
    return hashCode;
  }

  @Override
  @SuppressWarnings("RedundantMethodOverride")
  public boolean equals(Object obj) {
    return obj == this;
  }

  /** Total number of blocks this request has attempted to fetch or insert. */
  protected volatile int totalBlocks;

  /** Number of blocks successfully fetched or inserted so far. */
  protected volatile int successfulBlocks;

  /**
   * Timestamp of the most recent successful block completion.
   *
   * <p>ATTENTION: This may be {@code null} when reading from very old databases. See {@link
   * #getLatestSuccess()} for the precise semantics and defaulting behavior that keeps the user
   * interface sortable even before any blocks complete.
   */
  protected volatile Instant latestSuccess = Instant.now();

  /** Number of blocks which have failed. */
  protected volatile int failedBlocks;

  /** Number of blocks which have failed fatally. */
  protected volatile int fatallyFailedBlocks;

  /** Timestamp of the most recent failed or fatally failed block, if any. */
  protected volatile Instant latestFailure = null;

  /** Minimum number of blocks required to succeed for success. */
  protected volatile int minSuccessBlocks;

  /** Has totalBlocks stopped growing? */
  protected volatile boolean blockSetFinalized;

  /**
   * Has at least one block been scheduled to be sent to the network? Requests can be satisfied
   * entirely from the datastore sometimes.
   */
  protected volatile boolean sentToNetwork;

  /**
   * Returns the current total number of blocks considered by this request.
   *
   * <p>The value includes successful, failed, and pending blocks and may increase as the request
   * discovers additional work. After {@link #blockSetFinalized(ClientContext)} the total stops
   * growing.
   *
   * @return the total number of blocks counted for this request so far
   */
  public int getTotalBlocks() {
    return totalBlocks;
  }

  /**
   * Returns the UTC timestamp of the most recent successful block completion.
   *
   * <p>The value is initialized to the current time to keep “sort by last success” UIs usable for
   * newly created requests. For very old serialized data that lacks this field, the method returns
   * the epoch start.
   *
   * @return the last-success timestamp; never {@code null}
   */
  public Instant getLatestSuccess() {
    // Null-check for backwards compatibility: Old serialized versions of objects of this
    // class might not have this field yet.
    return latestSuccess != null ? latestSuccess : Instant.EPOCH;
  }

  /**
   * Returns the UTC timestamp of the most recent block failure or fatal failure.
   *
   * <p>When no failure has occurred the value is {@code null}.
   *
   * @return the last-failure timestamp, or {@code null} when no failures
   */
  public Instant getLatestFailure() {
    // Null-check for backwards compatibility: Old serialized versions of objects of this
    // class might not have this field yet.
    return latestFailure;
  }

  /**
   * Resets all progress counters and timestamps to their initial values.
   *
   * <p>Used when a requester is reconstructed or restarted and needs to clear tracking state prior
   * to re-scheduling work. Does not notify clients.
   */
  protected synchronized void resetBlocks() {
    totalBlocks = 0;
    successfulBlocks = 0;
    // See ClientRequester.getLatestSuccess() for why this defaults to the current time.
    latestSuccess = Instant.now();
    failedBlocks = 0;
    fatallyFailedBlocks = 0;
    latestFailure = null;
    minSuccessBlocks = 0;
    blockSetFinalized = false;
    sentToNetwork = false;
  }

  /**
   * Finalizes the set of blocks and notifies clients of the transition.
   *
   * <p>After finalization the {@link #totalBlocks} count will no longer increase. This method emits
   * a progress notification off-thread so UI or client code can update immediately.
   *
   * @param context the {@link ClientContext} providing access to schedulers and other transient
   *     services used to dispatch notifications
   */
  public void blockSetFinalized(ClientContext context) {
    synchronized (this) {
      if (blockSetFinalized) return;
      blockSetFinalized = true;
    }
    if (LOG.isDebugEnabled()) LOG.debug("Finalized set of blocks for {}", this);
    notifyClients(context);
  }

  /**
   * Increments the total block estimate by one without notifying clients.
   *
   * <p>Use when discovering additional work during planning or request expansion. If the block set
   * was already finalized, an error is logged and the counter is still incremented.
   */
  public void addBlock() {
    boolean wasFinalized;
    synchronized (this) {
      TOTAL_BLOCKS_UPDATER.incrementAndGet(this);
      wasFinalized = blockSetFinalized;
    }

    if (wasFinalized) {
      LOG.error("addBlock() but set finalized! on {}", this);
    }

    if (LOG.isDebugEnabled())
      LOG.debug(
          "addBlock(): total={} successful={} failed={} required={}",
          totalBlocks,
          successfulBlocks,
          failedBlocks,
          minSuccessBlocks);
  }

  /**
   * Adds the specified number of blocks to the total estimate without notifying clients.
   *
   * @param num the number of additional blocks discovered and added to the total; negative values
   *     are ignored by callers and not expected here
   */
  public void addBlocks(int num) {
    boolean wasFinalized;
    synchronized (this) {
      totalBlocks += num;
      wasFinalized = blockSetFinalized;
    }

    if (wasFinalized) {
      LOG.error("addBlocks() but set finalized! on {}", this);
    }

    if (LOG.isDebugEnabled())
      LOG.debug(
          "addBlocks({}): total={} successful={} failed={} required={}",
          num,
          totalBlocks,
          successfulBlocks,
          failedBlocks,
          minSuccessBlocks);
  }

  /**
   * Marks a block as completed and optionally notifies clients.
   *
   * <p>Updates counters and the {@link #latestSuccess} timestamp. When {@code dontNotify} is {@code
   * false}, a progress notification is queued off-thread. Calls from canceled requests are ignored.
   *
   * @param dontNotify when {@code true}, suppresses the asynchronous progress notification
   * @param context the transient {@link ClientContext} used to dispatch notifications
   */
  public void completedBlock(boolean dontNotify, ClientContext context) {
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Completed block ({}): total={} success={} failed={} fatally={} finalised={} required={}"
              + " on {}",
          dontNotify,
          totalBlocks,
          successfulBlocks,
          failedBlocks,
          fatallyFailedBlocks,
          blockSetFinalized,
          minSuccessBlocks,
          this);
    synchronized (this) {
      if (cancelled) return;
      SUCCESSFUL_BLOCKS_UPDATER.incrementAndGet(this);
      latestSuccess = Instant.now();
    }
    if (dontNotify) return;
    notifyClients(context);
  }

  /**
   * Records a non-fatal block failure and optionally notifies clients.
   *
   * @param dontNotify when {@code true}, suppresses the asynchronous progress notification
   * @param context the transient {@link ClientContext} used to dispatch notifications
   */
  public void failedBlock(boolean dontNotify, ClientContext context) {
    synchronized (this) {
      FAILED_BLOCKS_UPDATER.incrementAndGet(this);
      latestFailure = Instant.now();
    }
    if (!dontNotify) notifyClients(context);
  }

  /**
   * Records a non-fatal block failure and notifies clients.
   *
   * @param context the transient {@link ClientContext} used to dispatch notifications
   */
  public void failedBlock(ClientContext context) {
    failedBlock(false, context);
  }

  /**
   * Records a fatal block failure and notifies clients.
   *
   * @param context the transient {@link ClientContext} used to dispatch notifications
   */
  public void fatallyFailedBlock(ClientContext context) {
    synchronized (this) {
      FATALLY_FAILED_BLOCKS_UPDATER.incrementAndGet(this);
      latestFailure = Instant.now();
    }
    notifyClients(context);
  }

  /**
   * Adds required blocks that must succeed for overall success without notifying clients.
   *
   * @param blocks the number of additional blocks that are required to complete successfully
   */
  public synchronized void addMustSucceedBlocks(int blocks) {
    totalBlocks += blocks;
    minSuccessBlocks += blocks;
    if (LOG.isDebugEnabled())
      LOG.debug(
          "addMustSucceedBlocks({}): total={} successful={} failed={} required={}",
          blocks,
          totalBlocks,
          successfulBlocks,
          failedBlocks,
          minSuccessBlocks);
  }

  /**
   * Adds blocks that contribute redundancy for insert operations.
   *
   * <p>Insert implementations should override to apply insert‑specific semantics. The default
   * behavior counts them as required blocks.
   *
   * @param blocks the number of redundancy blocks discovered during planning
   */
  public synchronized void addRedundantBlocksInsert(int blocks) {
    addMustSucceedBlocks(blocks);
  }

  /**
   * Notifies clients of progress by delegating to {@link #innerNotifyClients(ClientContext)}
   * off-thread.
   *
   * @param context the transient {@link ClientContext} used to enqueue the notification job
   */
  public final void notifyClients(ClientContext context) {
    context
        .getJobRunner(persistent())
        .queueNormalOrDrop(
            context1 -> {
              innerNotifyClients(context1);
              return false;
            });
  }

  /**
   * Performs the actual progress notification to clients.
   *
   * <p>Implementations should emit events in order for the same requester and avoid heavy work in
   * the notification path. This method is called on a worker thread chosen by the scheduler.
   *
   * @param context the transient {@link ClientContext} providing access to event infrastructure
   */
  protected abstract void innerNotifyClients(ClientContext context);

  /**
   * Marks the first submission of this request to the network and invokes {@link
   * #innerToNetwork(ClientContext)}.
   *
   * <p>Idempotent: repeated calls after the first have no effect. Useful for UIs that wish to know
   * when a request moved beyond datastore checks.
   *
   * @param context the transient {@link ClientContext} used for notification
   */
  public void toNetwork(ClientContext context) {
    synchronized (this) {
      if (sentToNetwork) return;
      sentToNetwork = true;
    }
    innerToNetwork(context);
  }

  /**
   * Notifies clients that the network is now processing at least one part of the request.
   *
   * @param context the transient {@link ClientContext} used for notification and scheduling
   */
  protected abstract void innerToNetwork(ClientContext context);

  /**
   * Clears internal counters when a requester is reloaded or restarted.
   *
   * <p>Called during resume flows before any progress notifications are sent. Subclasses may
   * augment behavior but should preserve the reset semantics.
   */
  protected void clearCountersOnRestart() {
    this.blockSetFinalized = false;
    this.cancelled = false;
    this.failedBlocks = 0;
    this.fatallyFailedBlocks = 0;
    this.latestFailure = null;
    this.minSuccessBlocks = 0;
    this.sentToNetwork = false;
    this.successfulBlocks = 0;
    // See ClientRequester.getLatestSuccess() for why this defaults to the current time.
    this.latestSuccess = Instant.now();
    this.totalBlocks = 0;
  }

  /**
   * Returns the owning {@link RequestClient} associated with this request.
   *
   * @return the {@link RequestClient} that provides persistence and scheduling policy
   */
  public RequestClient getClient() {
    return client;
  }

  /**
   * Changes the scheduling priority class of this request and re-registers all sub-requests.
   *
   * <p>The change takes effect promptly by re-registering with the relevant schedulers. The method
   * is safe to call repeatedly and may be used to temporarily boost or reduce a request’s priority
   * based on user action or policy.
   *
   * @param newPriorityClass the new priority class to apply for all later scheduling
   * @param ctx the {@link ClientContext} used to perform re-registration with all schedulers
   */
  public void setPriorityClass(short newPriorityClass, ClientContext ctx) {
    short oldPrio;
    synchronized (this) {
      oldPrio = priorityClass;
      this.priorityClass = newPriorityClass;
    }
    if (LOG.isDebugEnabled())
      LOG.debug("Changing priority class of {} from {} to {}", this, oldPrio, newPriorityClass);
    ctx.getChkFetchScheduler(realTimeFlag).reregisterAll(this, oldPrio);
    ctx.getChkInsertScheduler(realTimeFlag).reregisterAll(this, oldPrio);
    ctx.getSskFetchScheduler(realTimeFlag).reregisterAll(this, oldPrio);
    ctx.getSskInsertScheduler(realTimeFlag).reregisterAll(this, oldPrio);
  }

  /**
   * Indicates whether this request is managed under real‑time scheduling policies.
   *
   * @return {@code true} if the owning client marked this request as real‑time
   */
  public boolean realTimeFlag() {
    return realTimeFlag;
  }

  /**
   * Reports whether this request is persistent and should survive restarts.
   *
   * @return {@code true} when the owning client is persistent; {@code false} otherwise
   */
  public boolean persistent() {
    return client.persistent();
  }

  private static final WeakHashMap<ClientRequester, Object> allRequesters = new WeakHashMap<>();
  private static final Object dumbValue = new Object();

  /**
   * Wall‑clock timestamp of construction in milliseconds since the epoch (UTC).
   *
   * <p>Useful for sorting and for UIs that display how long a request has been active.
   */
  public final long creationTime;

  /**
   * Returns a snapshot of all currently live non‑persistent requesters.
   *
   * <p>The returned array is the best‑effort snapshot based on weak references and may exclude
   * items that have been garbage‑collected.
   *
   * @return an array containing the live requesters known to this JVM
   */
  public static ClientRequester[] getAll() {
    synchronized (allRequesters) {
      return allRequesters.keySet().toArray(new ClientRequester[0]);
    }
  }

  /**
   * Encodes metadata describing the original client for persistence.
   *
   * <p>Implementations may include details such as an identifier, queue placement, and a client
   * name so that the request can be reconstructed after a restart. The default implementation
   * returns an empty array to indicate that no additional client metadata is stored.
   *
   * @param checker a checksum helper used to protect large sections so partial failures can be
   *     detected and isolated during reads
   * @return a byte array representing client metadata; callers should treat it as immutable data
   * @throws IOException if serialization of client details fails due to I/O or encoding errors
   */
  public byte[] getClientDetail(ChecksumChecker checker) throws IOException {
    return new byte[0];
  }

  /**
   * Helper that serializes a {@link PersistentClientCallback} into a byte array with checksum
   * protection.
   *
   * @param callback the callback that writes its client detail to the provided stream; must not be
   *     {@code null}
   * @param checker a checksum helper used to wrap large regions for integrity checking on readback
   * @return a byte array containing the callback’s serialized metadata; ownership is transferred to
   *     the caller
   * @throws IOException if the callback or stream encounters an I/O error during serialization
   */
  protected static byte[] getClientDetail(
      PersistentClientCallback callback, ChecksumChecker checker) throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    DataOutputStream dos = new DataOutputStream(baos);
    callback.getClientDetail(dos, checker);
    return baos.toByteArray();
  }

  private transient boolean resumed = false;

  /**
   * Resumes a persistent request after startup and performs any necessary re‑registration.
   *
   * <p>Implementations should register callbacks and then notify clients of the current state.
   *
   * @param context the transient {@link ClientContext} providing schedulers and helpers for resume
   * @throws ResumeFailedException if the persistent state cannot be restored successfully
   */
  public final void onResume(ClientContext context) throws ResumeFailedException {
    synchronized (this) {
      if (resumed) return;
      resumed = true;
    }
    innerOnResume(context);
  }

  /**
   * Implementation hook for resume, invoked exactly once by {@link #onResume(ClientContext)}.
   *
   * <p>Subclasses overriding this method must call {@code super.innerOnResume(context)} to ensure
   * common initialization is performed.
   *
   * @param context the transient {@link ClientContext} used during resume
   * @throws ResumeFailedException if restoring the persistent state fails
   */
  protected void innerOnResume(ClientContext context) throws ResumeFailedException {
    ClientBaseCallback cb = getCallback();
    client = cb.getRequestClient();
    assert client.persistent();
    if (sentToNetwork) innerToNetwork(context);
  }

  /**
   * Returns the callback that bridges this requester to its client for persistence and events.
   *
   * @return the client callback used to access the owning {@link RequestClient}
   */
  protected abstract ClientBaseCallback getCallback();

  /**
   * Hook invoked prior to the final writing during node shutdown.
   *
   * @param context the transient {@link ClientContext} provided for shutdown coordination
   */
  public void onShutdown(ClientContext context) {
    // Do nothing.
  }

  /**
   * Indicates whether the supplied state object represents this requester’s current state.
   *
   * @param state the state instance to compare against the requester’s current state
   * @return {@code true} if the argument describes the current state of this request
   */
  public boolean isCurrentState(ClientGetState state) {
    return false;
  }

  /**
   * Returns the scheduler group associated with this request.
   *
   * <p>For single requests this is the requester itself. Grouped requests (for example, a site
   * insert) return a shared grouping instance so schedulers can coordinate related work.
   *
   * @return the scheduler group that should be used for queueing and fairness decisions
   */
  public ClientRequestSchedulerGroup getSchedulerGroup() {
    return this;
  }
}

package network.crypta.client.async;

import java.io.Serial;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException;
import network.crypta.client.async.SplitFileFetcherStorage.SplitFileFetcherStorageKey;
import network.crypta.keys.ClientKey;
import network.crypta.keys.Key;
import network.crypta.node.KeysFetchingLocally;
import network.crypta.node.LowLevelGetException;
import network.crypta.node.RequestClient;
import network.crypta.node.SendableGet;
import network.crypta.node.SendableRequestItem;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Performs the network fetch for a split file and coordinates the lifecycle of the underlying block
 * requests.
 *
 * <p>This type represents the concrete {@code SendableGet} that drives a single end-to-end
 * retrieval of a split file: one instance per whole split file, selecting the next unfetched
 * blocks, scheduling requests, and reporting failures or completion back to the owning {@code
 * SplitFileFetcher}. The instance is <em>not</em> persistent; it is recreated on startup by {@code
 * SplitFileFetcher} based on persisted metadata maintained by the associated {@code
 * SplitFileFetcherStorage}.
 *
 * <p>Typical usage is internal to the fetcher: the owning fetcher constructs this class, calls
 * {@link #preRegister(ClientContext, boolean)} to account for local-store checks, and {@link
 * #schedule(ClientContext, boolean)} to register network requests. Progress and failures are
 * delegated through the storage layer, which tracks segments and block state. Fatal errors
 * short-circuit the whole split file; non-fatal errors cool down individual blocks.
 *
 * <p>Thread-safety: instances are used by the node's request scheduler. The class itself does not
 * expose mutating APIs intended for concurrent use by arbitrary threads; callers should treat it as
 * confined to the scheduler/executor that owns the fetch. The {@code storage} reference is {@code
 * transient} and not serialized with the fetch state.
 *
 * <ul>
 *   <li>Chooses keys to fetch from {@code SplitFileFetcherStorage}.
 *   <li>Translates low-level failures and decides whether to fail the entire fetch.
 *   <li>Respects cooldowns and reports progress to the parent requester.
 * </ul>
 *
 * @see SplitFileFetcher
 * @see SplitFileFetcherStorage
 * @see SendableGet
 */
public class SplitFileFetcherGet extends SendableGet implements HasKeyListener {
  @Serial private static final long serialVersionUID = 1L;
  private static final Logger LOG = LoggerFactory.getLogger(SplitFileFetcherGet.class);

  /**
   * Owning high-level fetcher that represents the overall split file operation. The field is
   * package-private by design and read for delegation; it is not intended to be mutated after
   * construction.
   */
  final SplitFileFetcher fetcher;

  /**
   * Storage component that tracks segments/blocks and their state during the fetch. Marked {@code
   * transient} because the runtime helpers it holds are reconstructed on startup from persistent
   * metadata managed by the parent fetcher.
   */
  final transient SplitFileFetcherStorage storage;

  /**
   * Creates a new driver for fetching a single split file.
   *
   * <p>The constructor wires this instance to its owning {@code SplitFileFetcher} and to the
   * storage that maintains per-block state. No network activity is scheduled here; call {@link
   * #preRegister(ClientContext, boolean)} followed by {@link #schedule(ClientContext, boolean)} to
   * start fetching.
   *
   * @param fetcher the parent fetcher coordinating the overall request; must be non-null and remain
   *     alive for the lifetime of this instance.
   * @param storage storage facade used to list, choose, and update block keys; must refer to the
   *     same logical fetch and match tokens created for this instance.
   */
  public SplitFileFetcherGet(SplitFileFetcher fetcher, SplitFileFetcherStorage storage) {
    super(fetcher.parent, fetcher.realTimeFlag);
    this.fetcher = fetcher;
    this.storage = storage;
  }

  /**
   * Returns the concrete {@link ClientKey} corresponding to a previously issued token.
   *
   * <p>The token must have been created by this instance's storage; otherwise an {@link
   * IllegalArgumentException} is thrown. The returned key identifies the block to be fetched on the
   * network.
   *
   * @param token a token produced by this fetcher for an unfetched block; must belong to this
   *     instance's {@code storage}.
   * @return the client key for the block identified by {@code token}; the object should be treated
   *     as immutable by callers.
   * @throws IllegalArgumentException if the token does not belong to this storage instance.
   */
  @Override
  public ClientKey getKey(SendableRequestItem token) {
    SplitFileFetcherStorageKey key = (SplitFileFetcherStorage.SplitFileFetcherStorageKey) token;
    if (key.get != storage) throw new IllegalArgumentException();
    return storage.getKey(key);
  }

  /**
   * Lists all currently unfetched keys for this split file.
   *
   * @return an array containing the remaining block keys. The array may be empty when all work is
   *     complete; the order is implementation-defined and may change between calls.
   */
  @Override
  public Key[] listKeys() {
    return storage.listUnfetchedKeys();
  }

  /**
   * Provides the fetch context used for individual block requests.
   *
   * @return the context carrying tunables and policy for block-level requests. The instance is
   *     owned by the parent fetcher and should be considered read-only by callers.
   */
  @Override
  public FetchContext getContext() {
    return fetcher.blockFetchContext;
  }

  /**
   * Handles a low-level failure reported for a specific block request.
   *
   * <p>Fatal failures immediately fail the entire split file. Non-fatal failures are delegated to
   * storage, which records the outcome and applies cooldowns so the scheduler can retry later.
   *
   * @param e the low-level exception that occurred during a block fetch; never {@code null}.
   * @param token identifies the affected block; must belong to this instance's storage.
   * @param context scheduler context providing access to request infrastructure for this thread.
   */
  @Override
  public void onFailure(LowLevelGetException e, SendableRequestItem token, ClientContext context) {
    FetchException fe = translateException(e);
    if (fe.isDefinitelyFatal()) {
      // If the error is definitely-fatal it means there is either a serious local problem
      // or the inserted data was corrupt. So we fail the entire splitfile immediately.
      // We don't track which blocks have fatally failed.
      if (LOG.isDebugEnabled()) LOG.debug("Fatal failure: {} for {}", fe, token);
      fetcher.fail(fe);
    } else {
      SplitFileFetcherStorage.SplitFileFetcherStorageKey key = (SplitFileFetcherStorageKey) token;
      if (key.get != storage) throw new IllegalArgumentException();
      storage.onFailure(key, fe);
    }
  }

  /**
   * Returns the next wakeup time for this fetcher based on storage cooldowns.
   *
   * @param context scheduler context for the current evaluation; not used for mutation.
   * @param now current wall-clock time in milliseconds since epoch used as a reference point.
   * @return the earliest time, in milliseconds since epoch, at which this fetcher should be
   *     reconsidered for scheduling.
   */
  @Override
  public long getWakeupTime(ClientContext context, long now) {
    return storage.getCooldownWakeupTime(now);
  }

  /**
   * Returns the cooldown expiry for a specific block.
   *
   * @param token identifies the block whose cooldown is queried; must belong to this storage.
   * @param context scheduler context; included for symmetry with the interface.
   * @return a timestamp in milliseconds since epoch when the block becomes eligible again.
   */
  @Override
  public long getCooldownWakeup(SendableRequestItem token, ClientContext context) {
    SplitFileFetcherStorageKey key = (SplitFileFetcherStorageKey) token;
    return storage.segments[key.segmentNumber].getCooldownTime(key.blockNumber);
  }

  /**
   * Performs pre-registration work before (re)registering to the network.
   *
   * <p>When {@code toNetwork} is {@code false}, no further work is needed and the method returns
   * {@code false}. When true and the request is local-only, the storage marks datastore checks as
   * finished; otherwise, it records that the store has been checked and the parent is notified.
   *
   * @param context scheduler context used for client notifications.
   * @param toNetwork whether the request is about to be scheduled onto the network.
   * @return {@code true} when local-only handling completes registration immediately; otherwise
   *     {@code false} so the caller proceeds to normal scheduling.
   */
  @Override
  public boolean preRegister(ClientContext context, boolean toNetwork) {
    if (!toNetwork) return false;
    // Notify clients of all the work we've done checking the datastore.
    if (fetcher.localRequestOnly()) {
      storage.finishedCheckingDatastoreOnLocalRequest(context);
      return true;
    } else {
      storage.setHasCheckedStore(context);
    }
    fetcher.toNetwork();
    fetcher.parent.notifyClients(context);
    return false;
  }

  /**
   * Returns the priority class to use for scheduling.
   *
   * @return the priority class as provided by the parent fetcher; higher classes consume more
   *     scarce network resources.
   */
  @Override
  public short getPriorityClass() {
    return fetcher.getPriorityClass();
  }

  /**
   * Chooses a random unfetched key to send next.
   *
   * <p>The implementation must not persist mutations or otherwise change durable state as a side
   * effect of selection. Cooldowns and other eligibility filters are applied by the storage layer.
   *
   * @param keys snapshot of keys currently fetching locally, used to avoid duplicate work.
   * @param context scheduler context for this evaluation; not used for mutation.
   * @return a token representing the chosen key, or {@code null} if none are currently eligible.
   */
  @Override
  public SendableRequestItem chooseKey(KeysFetchingLocally keys, ClientContext context) {
    return storage.chooseRandomKey();
  }

  /**
   * Counts the number of keys remaining for this split file.
   *
   * @param context scheduler context passed for interface completeness.
   * @return total number of unfetched keys, including those cooling down or otherwise not
   *     immediately sendable.
   */
  @Override
  public long countAllKeys(ClientContext context) {
    return storage.countUnfetchedKeys();
  }

  /**
   * Counts the number of keys that can be sent now.
   *
   * @param context scheduler context passed for interface completeness.
   * @return number of keys currently eligible to be scheduled without waiting.
   */
  @Override
  public long countSendableKeys(ClientContext context) {
    return storage.countSendableKeys();
  }

  /**
   * Indicates whether the overall fetch has finished or been cancelled.
   *
   * @return {@code true} when the parent fetcher reports completion/cancellation; otherwise {@code
   *     false}.
   */
  @Override
  public boolean isCancelled() {
    return fetcher.hasFinished();
  }

  /**
   * Returns the request client associated with this fetch.
   *
   * @return the {@link RequestClient} delegated from the parent requester; never {@code null}.
   */
  @Override
  public RequestClient getClient() {
    return fetcher.parent.getClient();
  }

  /**
   * Returns the higher-level requester that owns this operation.
   *
   * @return the parent requester that should be notified of progress and completion.
   */
  @Override
  public ClientRequester getClientRequest() {
    return fetcher.parent;
  }

  /**
   * Indicates whether the get is for an SSK key.
   *
   * @return always {@code false} because split files use CHK-based blocks.
   */
  @Override
  public boolean isSSK() {
    return false;
  }

  /**
   * Schedules or reschedules outstanding block requests for this split file.
   *
   * <p>This method registers the current set of unfetched blocks with the appropriate scheduler for
   * CHK fetches, honoring the configured priority class and the {@code ignoreStore} flag. When
   * {@code ignoreStore} is {@code true}, the datastore is not rechecked before re-registering
   * requests (typical after a normal cooldown). When {@code false}, the datastore is consulted so
   * blocks already present are not redundantly fetched (e.g., after recovering from corruption).
   *
   * @param context scheduler context used to obtain the CHK fetch scheduler and perform
   *     registration work; must not be {@code null}.
   * @param ignoreStore if {@code true}, skip local datastore checks before re-registering; if
   *     {@code false}, consult the store to avoid duplicate network work when appropriate.
   */
  public void schedule(ClientContext context, boolean ignoreStore) {
    ClientRequestScheduler sched = context.getChkFetchScheduler(realTimeFlag);
    BlockSet blocks = fetcher.blockFetchContext.blocks;
    sched.register(this, new SendableGet[] {this}, persistent, blocks, ignoreStore);
  }

  /**
   * Creates a listener that observes key events for this fetch.
   *
   * @param context scheduler context supplied by the caller.
   * @param onStartup whether this is being created during startup recovery.
   * @return a listener backed by the storage that updates per-block state.
   */
  @Override
  public KeyListener makeKeyListener(ClientContext context, boolean onStartup) {
    return storage.keyListener;
  }

  /**
   * Cancels scheduling by unregistering this fetch from the scheduler.
   *
   * @param context scheduler context used to perform the unregistration.
   */
  public void cancel(ClientContext context) {
    unregister(context, fetcher.getPriorityClass());
  }

  /**
   * Reports whether {@link #preRegister(ClientContext, boolean)} has completed its work.
   *
   * @return {@code true} once the storage has recorded that the local store was checked; this
   *     indicates pre-registration already ran for the current cycle.
   */
  public boolean hasQueued() {
    return storage.hasCheckedStore();
  }

  /** {@inheritDoc} */
  @Override
  protected ClientGetState getClientGetState() {
    return fetcher;
  }

  /**
   * Returns a specific key the fetch prefers to request next.
   *
   * <p>This implementation returns {@code null} to indicate no particular preference and to
   * delegate selection to {@link #chooseKey(KeysFetchingLocally, ClientContext)}.
   *
   * @return {@code null} because the selection is left to {@code chooseKey}.
   */
  @Override
  @SuppressWarnings("java:S1168")
  public byte[] getWantedKey() {
    return null;
  }
}

package network.crypta.client.async;

import java.io.Serial;
import network.crypta.client.FetchContext;
import network.crypta.keys.ClientKey;
import network.crypta.keys.ClientKeyBlock;
import network.crypta.keys.ClientSSK;
import network.crypta.keys.Key;
import network.crypta.keys.KeyBlock;
import network.crypta.keys.KeyVerifyException;
import network.crypta.keys.NodeSSK;
import network.crypta.node.KeysFetchingLocally;
import network.crypta.node.LowLevelGetException;
import network.crypta.node.NullSendableRequestItem;
import network.crypta.node.RequestClient;
import network.crypta.node.RequestScheduler;
import network.crypta.node.SendableGet;
import network.crypta.node.SendableRequestItem;
import network.crypta.support.TimeUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Base class that implements the common mechanics for fetching exactly one block from the network.
 *
 * <p>This fetcher owns a single {@link ClientKey} and coordinates registration with the {@link
 * RequestScheduler}, retry and cooldown behavior, and hand-off to subclass hooks for success and
 * error processing. Typical usage is: construct an instance with the desired {@link FetchContext}
 * and parent {@link ClientRequester}, call {@link #schedule(ClientContext)} to register it, and
 * implement {@link #onSuccess(ClientKeyBlock, boolean, Object, ClientContext)} plus {@link
 * #onBlockDecodeError(SendableRequestItem, ClientContext)} in a subclass to receive results. The
 * implementation tracks recent failures and may defer a retry using a finite cooldown derived from
 * the {@link FetchContext}.
 *
 * <p>Life-cycle and invariants:
 *
 * <ul>
 *   <li>The fetcher represents one logical block fetch; {@link #finished} becomes {@code true} when
 *       a terminal outcome is reached and it will no longer emit results.
 *   <li>{@link #cancelled} ends participation in scheduling; subsequent callbacks become no-ops.
 *   <li>Retry attempts are bounded by {@link #maxRetries} (or unbounded when {@code -1}) and may be
 *       spaced using context-defined cooldowns.
 * </ul>
 *
 * <p>Threading and mutability: instances are mutable and use narrow synchronization on {@code this}
 * to protect simple flags such as {@link #cancelled} and {@link #finished}. Callers should not
 * assume broader thread-safety beyond the documented methods.
 *
 * <p><strong>Serialization warning:</strong> Changing non-transient members on classes that are
 * {@link java.io.Serializable} can restart downloads or lose uploads when deserialized; keep field
 * layout stable.
 *
 * @author toad
 * @see SendableGet
 * @see RequestScheduler
 * @see FetchContext
 */
public abstract class BaseSingleFileFetcher extends SendableGet implements HasKeyListener {
  private static final Logger LOG = LoggerFactory.getLogger(BaseSingleFileFetcher.class);

  @Serial private static final long serialVersionUID = 1L;

  /** Immutable client-level key that identifies the single block being fetched. */
  protected final ClientKey key;

  /** Flag that becomes {@code true} once the request is explicitly cancelled. */
  protected boolean cancelled;

  /** Flag set when the fetch has reached a terminal state and will not emit more events. */
  protected boolean finished;

  /**
   * Maximum number of retry attempts. A value of {@code -1} indicates unlimited retries; a value of
   * {@code 0} means only the initial attempt is performed.
   */
  final int maxRetries;

  /** Current retry counter used to decide whether the next retry is allowed. */
  private int retryCount;

  /** Fetch configuration providing cooldown parameters and other scheduling preferences. */
  protected final FetchContext ctx;

  /** Whether the owner intends to delete the associated fetch context when finished. */
  protected boolean deleteFetchContext;

  /**
   * Singleton token array used when registering this fetcher with the scheduler. The token itself
   * has no payload; it only acts as a marker for the request lifecycle.
   */
  static final SendableRequestItem[] keys =
      new SendableRequestItem[] {NullSendableRequestItem.nullItem};

  /** Cached number of retries between cooldown sleeps, derived from {@link #ctx}. */
  private int cachedCooldownTries;

  /** Cached cooldown duration in milliseconds, derived from {@link #ctx}. */
  private long cachedCooldownTime;

  /**
   * Absolute wake-up time in milliseconds since the epoch for the current cooldown, or {@code 0}.
   */
  private transient long cooldownWakeupTime;

  /**
   * Creates a fetcher for a single block.
   *
   * <p>Construction does not schedule the request; callers typically invoke {@link
   * #schedule(ClientContext)} after creating a subclass instance. The supplied {@link FetchContext}
   * must be non-{@code null} and provides cooldown policy and other preferences.
   *
   * @param key the client key identifying the target block; must not be {@code null}
   * @param maxRetries maximum retry attempts; {@code -1} allows unlimited retries; {@code 0}
   *     performs only the initial attempt
   * @param ctx fetch context carrying cooldown timing and local/remote behavior; must not be {@code
   *     null}
   * @param parent requester that owns this fetch and supplies priority and client identity
   * @param deleteFetchContext whether the associated fetch context may be deleted by the owner when
   *     the request completes
   * @param realTimeFlag whether this request is considered real-time for scheduling purposes
   */
  protected BaseSingleFileFetcher(
      ClientKey key,
      int maxRetries,
      FetchContext ctx,
      ClientRequester parent,
      boolean deleteFetchContext,
      boolean realTimeFlag) {
    super(parent, realTimeFlag);
    this.deleteFetchContext = deleteFetchContext;
    if (LOG.isDebugEnabled()) LOG.debug("Creating BaseSingleFileFetcher for {}", key);
    retryCount = 0;
    this.maxRetries = maxRetries;
    this.key = key;
    this.ctx = ctx;
    if (ctx == null) throw new NullPointerException();
  }

  @Override
  public long countAllKeys(ClientContext context) {
    return 1;
  }

  @Override
  public long countSendableKeys(ClientContext context) {
    return 1;
  }

  @Override
  public SendableRequestItem chooseKey(KeysFetchingLocally fetching, ClientContext context) {
    Key k = key.getNodeKey(false);
    if (fetching.hasKey(k, this)) return null;
    long l = fetching.checkRecentlyFailed(k, realTimeFlag);
    long now = System.currentTimeMillis();
    if (l > 0 && l > now) {
      if (maxRetries == -1 || (maxRetries >= RequestScheduler.COOLDOWN_RETRIES)) {
        if (LOG.isDebugEnabled())
          LOG.debug(
              "RecentlyFailed -> cooldown until {} on {}", TimeUtil.formatTime(l - now), this);
        cooldownWakeupTime = Math.max(cooldownWakeupTime, l);
      } else {
        this.onFailure(
            new LowLevelGetException(LowLevelGetException.RECENTLY_FAILED), null, context);
      }
      return null;
    }
    return keys[0];
  }

  @Override
  public ClientKey getKey(SendableRequestItem token) {
    return key;
  }

  @Override
  public FetchContext getContext() {
    return ctx;
  }

  @Override
  public boolean isSSK() {
    return key instanceof ClientSSK;
  }

  /**
   * Attempts to schedule a retry according to the current policy.
   *
   * <p>When the request is empty (already finished or cancelled) the retry is suppressed. If the
   * retry limit is exceeded, the request is unregistered. Otherwise, this method either enters a
   * finite cooldown (deferring the retry) or clears the wakeup time to retry promptly.
   *
   * @param context client context used for interactions with the scheduler and request state
   * @return {@code true} if a retry is allowed (possibly after cooldown); {@code false} if no more
   *     retries should be attempted
   */
  protected boolean retry(ClientContext context) {
    if (isEmpty()) {
      if (LOG.isDebugEnabled()) LOG.debug("Not retrying because empty");
      return false; // Fatal errors (e.g. decode failure) should not retry.
    }
    // We want 0, 1, ... maxRetries i.e. maxRetries+1 attempts (maxRetries=0 => try once, no
    // retries, maxRetries=1 = original try + 1 retry)
    int r = ++retryCount;
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Attempting to retry... (max {}, current {}) on {} finished={} cancelled={}",
          maxRetries,
          r,
          this,
          finished,
          cancelled);
    if (!withinRetryLimit(r)) {
      unregister(context, getPriorityClass());
      return false;
    }
    checkCachedCooldownData();
    if (shouldEnterCooldown(r)) {
      enterCooldown(context);
    } else {
      // Wake the CRS after clearing cache.
      clearWakeupTime(context);
    }
    // We will retry in any case, maybe not just not yet.
    return true;
  }

  private boolean withinRetryLimit(int r) {
    return (r <= maxRetries) || (maxRetries == -1);
  }

  private boolean shouldEnterCooldown(int r) {
    return cachedCooldownTries == 0 || r % cachedCooldownTries == 0;
  }

  private void enterCooldown(ClientContext context) {
    long now = System.currentTimeMillis();
    if (cooldownWakeupTime > now) {
      if (LOG.isErrorEnabled()) {
        LOG.error(
            "Already on the cooldown queue for {} until {}",
            this,
            TimeUtil.formatTime(cooldownWakeupTime - now),
            new Exception("error"));
      }
      return;
    }
    if (LOG.isDebugEnabled()) LOG.debug("Adding to cooldown queue {}", this);
    cooldownWakeupTime = now + cachedCooldownTime;
    reduceWakeupTime(cooldownWakeupTime, context);
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Added single file fetcher into cooldown until {}",
          TimeUtil.formatTime(cooldownWakeupTime - now));
    onEnterFiniteCooldown(context);
  }

  private void checkCachedCooldownData() {
    // 0/0 is illegal, and it's also the default, so use it to indicate we haven't fetched them.
    if (!(cachedCooldownTime == 0 && cachedCooldownTries == 0)) {
      // Okay, we have already got them.
      return;
    }
    innerCheckCachedCooldownData();
  }

  private void innerCheckCachedCooldownData() {
    cachedCooldownTries = ctx.getCooldownRetries();
    cachedCooldownTime = ctx.getCooldownTime();
  }

  /**
   * Hook invoked after a finite cooldown has been scheduled. Subclasses may override to surface
   * progress or update external state. The default implementation does nothing.
   *
   * @param context the client context associated with this request
   */
  protected void onEnterFiniteCooldown(ClientContext context) {
    // Do nothing.
  }

  @Override
  public ClientRequester getClientRequest() {
    return parent;
  }

  @Override
  public short getPriorityClass() {
    return parent.getPriorityClass();
  }

  /**
   * Cancels the fetch and removes it from the scheduler.
   *
   * <p>After cancellation, the fetcher will not emit further events. The method is idempotent.
   *
   * @param context client context used to unregister from the scheduler
   */
  public void cancel(ClientContext context) {
    synchronized (this) {
      cancelled = true;
    }
    unregisterAll(context);
  }

  /**
   * Removes this request’s pending key token and also unregisters the request from the queue.
   *
   * <p>Call {@link #unregister(ClientContext, short)} instead if you only want to remove it from
   * the queue while keeping the pending key entry intact.
   *
   * @param context client context used to reach the scheduler
   */
  public void unregisterAll(ClientContext context) {
    getScheduler(context).removePendingKeys(this, false);
    unregister(context, (short) -1);
  }

  @Override
  public synchronized boolean isCancelled() {
    return cancelled;
  }

  /**
   * Returns whether there is nothing left to do for this request.
   *
   * <p>The method returns {@code true} when the request has been cancelled or already finished.
   *
   * @return {@code true} if cancelled or finished; otherwise {@code false}
   */
  public synchronized boolean isEmpty() {
    return cancelled || finished;
  }

  @Override
  public RequestClient getClient() {
    return parent.getClient();
  }

  /**
   * Processes a received low-level block for this request.
   *
   * <p>The method validates that the supplied {@link Key} matches the expected node key and, when
   * valid, unregisters the request and forwards the block to {@link #onSuccess(ClientKeyBlock,
   * boolean, Object, ClientContext)}. Calls made after the request has finished are ignored.
   *
   * @param key node-level key that was fetched; must equal this fetcher’s node key
   * @param block the low-level block corresponding to {@code key}
   * @param context client context used for scheduler interaction
   */
  public void onGotKey(Key key, KeyBlock block, ClientContext context) {
    synchronized (this) {
      if (finished) {
        if (LOG.isDebugEnabled()) LOG.debug("onGotKey() called twice on {}", this);
        return;
      }
      finished = true;
      if (isCancelled()) return;
      if (key == null) throw new NullPointerException();
      if (this.key == null) throw new NullPointerException("Key is null on " + this);
      if (!key.equals(this.key.getNodeKey(false))) {
        LOG.info("Got sent key {} but want {} for {}", key, this.key, this);
        return;
      }
    }
    unregister(context, getPriorityClass()); // Key has already been removed from pendingKeys
    onSuccess(block, false, null, context);
  }

  /**
   * Converts a low-level {@link KeyBlock} into a {@link ClientKeyBlock} and forwards it to the
   * subclass {@link #onSuccess(ClientKeyBlock, boolean, Object, ClientContext)}.
   *
   * <p>If block verification fails, {@link #onBlockDecodeError(SendableRequestItem, ClientContext)}
   * is invoked instead.
   *
   * @param lowLevelBlock the raw block obtained from the network or store
   * @param fromStore whether the block came from a store rather than the network
   * @param token scheduling token associated with the request, if any
   * @param context client context used for callback coordination
   */
  public void onSuccess(
      KeyBlock lowLevelBlock, boolean fromStore, SendableRequestItem token, ClientContext context) {
    ClientKeyBlock block;
    try {
      block = Key.createKeyBlock(this.key, lowLevelBlock);
      onSuccess(block, fromStore, token, context);
    } catch (KeyVerifyException e) {
      onBlockDecodeError(token, context);
    }
  }

  /**
   * Called when a block was received but failed client-level verification or decoding.
   *
   * @param token the scheduling token passed to the request, may be {@code null}
   * @param context client context used to report the error or schedule follow-up work
   */
  protected abstract void onBlockDecodeError(SendableRequestItem token, ClientContext context);

  /**
   * Called when and if the request succeeds at the client level.
   *
   * <p>Implementations should consume or persist the provided {@link ClientKeyBlock}. This method
   * is invoked at most once per instance.
   *
   * @param block verified client-level block corresponding to {@link #key}
   * @param fromStore {@code true} when the block originated from a local store
   * @param token scheduling token carried through the request, or {@code null}
   * @param context client context for any follow-up scheduling or notifications
   */
  public abstract void onSuccess(
      ClientKeyBlock block, boolean fromStore, Object token, ClientContext context);

  @Override
  public long getCooldownWakeup(SendableRequestItem token, ClientContext context) {
    return cooldownWakeupTime;
  }

  /**
   * Schedules this fetch with the current scheduler.
   *
   * @param context client context that provides access to the scheduler
   */
  public void schedule(ClientContext context) {
    if (key == null) throw new NullPointerException();
    getScheduler(context).register(this, new SendableGet[] {this}, persistent, ctx.blocks, false);
  }

  /**
   * Reschedules this fetch, keeping the existing request instance but re-registering it with the
   * scheduler.
   *
   * @param context client context used to reach the scheduler
   */
  public void reschedule(ClientContext context) {
    getScheduler(context).register(null, new SendableGet[] {this}, persistent, ctx.blocks, true);
  }

  @Override
  public Key[] listKeys() {
    synchronized (this) {
      if (cancelled || finished) return new Key[0];
    }
    return new Key[] {key.getNodeKey(true)};
  }

  @Override
  public KeyListener makeKeyListener(ClientContext context, boolean onStartup) {
    synchronized (this) {
      if (finished) return null;
      if (cancelled) return null;
    }
    if (key == null) {
      if (LOG.isErrorEnabled()) {
        LOG.error(
            "Key is null - left over BSSF? on {} in makeKeyListener()",
            this,
            new Exception("error"));
      }
      return null;
    }
    Key newKey = key.getNodeKey(true);
    if (parent == null) {
      LOG.error("Parent is null on {} persistent={} key={} ctx={}", this, persistent, key, ctx);
      return null;
    }
    short prio = parent.getPriorityClass();
    return new SingleKeyListener(newKey, this, prio, persistent);
  }

  /**
   * Called when the key is not found in a local store and the request must proceed to the network
   * or otherwise handle the absence.
   *
   * @param context client context used for follow-up actions
   */
  protected abstract void notFoundInStore(ClientContext context);

  @Override
  public boolean preRegister(ClientContext context, boolean toNetwork) {
    if (!toNetwork) return false;
    boolean localOnly = ctx.getLocalRequestOnly();
    if (localOnly) {
      notFoundInStore(context);
      return true;
    }
    parent.toNetwork(context);
    return false;
  }

  @Override
  public synchronized long getWakeupTime(ClientContext context, long now) {
    if (cancelled || finished) return -1;
    long wakeTime = cooldownWakeupTime;
    if (wakeTime <= now) cooldownWakeupTime = wakeTime = 0;
    KeysFetchingLocally fetching = getScheduler(context).fetchingKeys();
    if (wakeTime <= 0 && fetching.hasKey(getNodeKey(null), this)) {
      wakeTime = Long.MAX_VALUE;
      // tracker.cooldownWakeupTime is only set for a real cooldown period, NOT when we go into
      // hierarchical cooldown because the request is already running.
    }
    return wakeTime;
  }

  /**
   * Refreshes the cached cooldown parameters from the current {@link FetchContext} after it has
   * changed.
   *
   * <p>Ideally this would be handled by a shared configuration change mechanism, but here we take a
   * pragmatic approach so changes such as USK polling intervals take effect without rebuilding the
   * request.
   *
   * @see <a href="https://bugs.freenetproject.org/view.php?id=4984">Freenet bug 4984</a>
   */
  public void onChangedFetchContext() {
    synchronized (this) {
      if (cancelled || finished) return;
    }
    innerCheckCachedCooldownData();
  }

  @Override
  public byte[] getWantedKey() {
    Key newKey = key.getNodeKey(false);
    return newKey instanceof NodeSSK nssk ? nssk.getPubKeyHash() : newKey.getRoutingKey();
  }

  /**
   * Re-schedules a previously persisted or paused fetcher instance.
   *
   * @param context client context used for scheduling
   */
  public void onResume(ClientContext context) {
    schedule(context);
  }
}

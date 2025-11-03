package network.crypta.client.async;

import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serial;
import java.util.ArrayList;
import java.util.HashSet;
import network.crypta.crypt.RandomSource;
import network.crypta.keys.Key;
import network.crypta.node.BaseSendableGet;
import network.crypta.node.KeysFetchingLocally;
import network.crypta.node.LowLevelGetException;
import network.crypta.node.NodeClientCore;
import network.crypta.node.RequestClient;
import network.crypta.node.RequestCompletionListener;
import network.crypta.node.RequestScheduler;
import network.crypta.node.SendableRequestItem;
import network.crypta.node.SendableRequestItemKey;
import network.crypta.node.SendableRequestSender;
import network.crypta.support.ListUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Maintains keys that peers have explicitly offered for retrieval at a specific priority.
 *
 * <p>This helper acts as a small, opportunistic queue. When a peer advertises that it can serve a
 * given key, the key is {@linkplain #queueKey(Key) queued} here. The client request scheduler may
 * then {@linkplain #chooseKey(KeysFetchingLocally, ClientContext) choose} one of the offered keys
 * to try immediately using the sender provided by {@linkplain #getSender(ClientContext)}. Offered
 * keys temporarily override recent-failure heuristics so that a fresh offer can be attempted even
 * if the key failed recently elsewhere.
 *
 * <p>Typical usage is: enqueue on offer, pop when scheduling, and remove when a key is found or no
 * longer relevant. The list is de-duplicated and internally represented by a {@code HashSet} for
 * membership and an {@code ArrayList} to enable low-overhead random selection. The two structures
 * are kept in lockstep; all mutating operations are synchronized on the instance to provide simple
 * thread-safety for callers that access the list from different threads in the client layer.
 *
 * <ul>
 *   <li>Responsibilities: accept offered keys, provide random fair selection, and supply a sender
 *       that performs a short-lived asynchronous fetch attempt.
 *   <li>Notable behaviors: offered keys bypass the {@code RecentlyFailed} filter; attempts not
 *       write to the client cache; a key is removed from the list as soon as the attempt starts.
 *   <li>Lifecycle: empty until the first offer arrives; drains as attempts are made; never
 *       persisted and explicitly non-serializable.
 * </ul>
 *
 * @see ClientRequestScheduler
 * @see KeysFetchingLocally
 * @see SendableRequestSender
 */
public class OfferedKeysList extends BaseSendableGet implements RequestClient {
  private static final Logger LOG = LoggerFactory.getLogger(OfferedKeysList.class);

  /**
   * Set of currently offered keys used for efficient membership tests and de-duplication. The set
   * and the list below always contain the same elements.
   */
  private final HashSet<Key> keys;

  /**
   * List view of the offered keys used to pick a random element efficiently. Removal is O(1) by
   * swapping with the last element. See {@link #chooseKey(KeysFetchingLocally, ClientContext)}.
   */
  private final ArrayList<Key>
      keysList; // O(1) remove random element the way we use it, see chooseKey().

  /** Random source used to choose a key uniformly from {@link #keysList}. */
  private final RandomSource random;

  /** Priority class associated with all keys in this list; provided by the scheduler. */
  private final short priorityClass;

  /** Whether the offered keys refer to SSKs (as opposed to CHKs). */
  private final boolean isSSK;

  OfferedKeysList(RandomSource random, short priorityClass, boolean isSSK, boolean realTimeFlag) {
    super(false, realTimeFlag);
    this.keys = new HashSet<>();
    this.keysList = new ArrayList<>();
    this.random = random;
    this.priorityClass = priorityClass;
    this.isSSK = isSSK;
  }

  /**
   * Removes a key from the offered set when it has been found or when it no longer belongs here.
   *
   * <p>This operation is idempotent: removing a key that is not present has no effect. The method
   * maintains the invariant that the backing set and list contain the same elements.
   *
   * @param key the key to remove from the offered list; must not be {@code null}.
   */
  public synchronized void remove(Key key) {
    assert (keysList.size() == keys.size());
    if (keys.remove(key)) {
      ListUtils.removeBySwapLast(keysList, key);
      if (LOG.isDebugEnabled())
        LOG.debug("Found {} , removing it  for {} size now {}", key, this, keysList.size());
    }
    assert (keysList.size() == keys.size());
  }

  /**
   * Returns whether the offered-keys list is empty at the time of the call.
   *
   * <p>No synchronization beyond the method's own monitor is required by callers. The result is a
   * point-in-time observation that may change immediately after return if other threads add or
   * remove keys.
   *
   * @return {@code true} when no offered keys are currently queued; {@code false} otherwise.
   */
  public synchronized boolean isEmpty() {
    return keys.isEmpty();
  }

  @Override
  public long countAllKeys(ClientContext context) {
    // Not supported by this helper: it does not expose a full key inventory.
    throw new UnsupportedOperationException();
  }

  @Override
  public long countSendableKeys(ClientContext context) {
    // Not supported by this helper: selection is performed on-demand only.
    throw new UnsupportedOperationException();
  }

  private static class MySendableRequestItem
      implements SendableRequestItem, SendableRequestItemKey {
    final Key key;

    MySendableRequestItem(Key key) {
      this.key = key;
    }

    @Override
    public void dump() {
      // Ignore, we will be GC'ed
    }

    @Override
    public SendableRequestItemKey getKey() {
      return this;
    }
  }

  /**
   * Chooses an offered key to attempt, removing it from the internal structures.
   *
   * <p>If only one key is available it is returned directly (unless the key is already being
   * fetched locally). Otherwise, up to ten random candidates are sampled to find a key that is not
   * currently in the local fetching set. When a key is chosen it is removed from the list/set so
   * subsequent calls will not return it again.
   *
   * <p>Offered keys deliberately bypass any "recently failed" heuristics so that a fresh peer offer
   * can be tried immediately. If no acceptable key is found, the method returns {@code null}.
   *
   * @param fetching tracks keys being fetched locally; used to avoid duplicate work.
   * @param context the client context for scheduling decisions; not used directly here but kept for
   *     symmetry with other selectors.
   * @return a token representing the chosen key to send, or {@code null} when none is available or
   *     all candidates are currently being fetched.
   */
  @Override
  public synchronized SendableRequestItem chooseKey(
      KeysFetchingLocally fetching, ClientContext context) {
    assert (keysList.size() == keys.size());
    if (keys.size() == 1) {
      // Shortcut the common case
      Key k = keysList.getFirst();
      if (fetching.hasKey(k, null)) return null;
      // Ignore RecentlyFailed because an offered key overrides it.
      keys.remove(k);
      keysList.removeFirst();
      keysList.trimToSize();
      return new MySendableRequestItem(k);
    }
    for (int i = 0; i < 10; i++) {
      // Pick a random key
      if (keysList.isEmpty()) return null;
      int ptr = random.nextInt(keysList.size());
      // Avoid shuffling penalty by swapping the chosen element with the end.
      Key k = keysList.get(ptr);
      if (fetching.hasKey(k, null)) continue;
      // Ignore RecentlyFailed because an offered key overrides it.
      ListUtils.removeBySwapLast(keysList, ptr);
      keys.remove(k);
      assert (keysList.size() == keys.size());
      return new MySendableRequestItem(k);
    }
    return null;
  }

  /** {@inheritDoc} */
  @Override
  public RequestClient getClient() {
    return this;
  }

  /**
   * Returns no client request object. This helper does not correspond to a single persistent
   * request and therefore has no dedicated {@code ClientRequester} instance.
   *
   * @return always {@code null} because this list is an auxiliary facility, not a request.
   */
  @Override
  public ClientRequester getClientRequest() {
    return null;
  }

  /**
   * Returns the priority class associated with all keys selected from this list.
   *
   * @return a scheduler-defined priority class used for opportunistic offered-key attempts.
   */
  @Override
  public short getPriorityClass() {
    return priorityClass;
  }

  /**
   * Reports an internal error encountered while handling an offered key.
   *
   * <p>The implementation logs the error and allows the scheduler to continue. No retries are
   * triggered here.
   *
   * @param t the error that occurred.
   * @param sched the scheduler invoking the callback; may be used by callers for context.
   * @param context the client context in effect when the error happened.
   * @param persistent whether the request was persistent; ignored by this implementation.
   */
  @Override
  public void internalError(
      Throwable t, RequestScheduler sched, ClientContext context, boolean persistent) {
    LOG.error("Internal error: {}", t, t);
  }

  /**
   * Provides a sender that performs a short-lived asynchronous get for a chosen offered key.
   *
   * <p>The sender invokes {@code NodeClientCore.asyncGet(...)} with parameters suitable for an
   * opportunistic attempt: it checks the datastore and briefly accepts peer offers; it does not
   * escalate into a full client request and does not write to the client cache. Upon completion
   * (success or failure) the sender removes the key from the fetching set and wakes the starter so
   * other work can proceed.
   *
   * @param context the client context from which the sender may derive environment or configuration
   *     if needed.
   * @return a non-blocking sender whose {@code send(...)} call returns promptly.
   */
  @Override
  public SendableRequestSender getSender(ClientContext context) {
    return new SendableRequestSender() {

      @Override
      public boolean send(
          NodeClientCore core,
          final RequestScheduler sched,
          ClientContext context,
          ChosenBlock req) {
        final Key key = ((MySendableRequestItem) req.token).key;
        // Cache temporarily to allow propagation.
        // Don't let a node force us to start a real request for a specific key.
        // We check the datastore, take up offers if any (on a short timeout), and then quit if we
        // still haven't fetched the data.
        // Obviously this may have a marginal impact on load, but it should only be marginal.
        core.asyncGet(
            key,
            true,
            new RequestCompletionListener() {

              @Override
              public void onSucceeded() {
                // We don't use ChosenBlockImpl so have to remove the keys from the fetching set
                // ourselves.
                sched.removeFetchingKey(key);
                sched.wakeStarter();
              }

              @Override
              public void onFailed(LowLevelGetException e) {
                // We don't use ChosenBlockImpl so have to remove the keys from the fetching set
                // ourselves.
                sched.removeFetchingKey(key);
                // Something might be waiting for a request to complete (e.g. if we have two
                // requests for the same key),
                // so wake the starter thread.
                sched.wakeStarter();
              }
            },
            true,
            false,
            realTimeFlag,
            false,
            false);
        // canWriteClientCache remains false intentionally here.
        return true;
      }

      @Override
      public boolean sendIsBlocking() {
        return false;
      }
    };
  }

  /** {@inheritDoc} */
  @Override
  public boolean isCancelled() {
    return false;
  }

  /**
   * Enqueues an offered key if it is not already present.
   *
   * <p>Keys are de-duplicated across calls. The method is synchronized and maintains the invariant
   * that the internal list and set contain identical elements.
   *
   * @param key the key that was offered by a peer and should be considered for an opportunistic
   *     fetch; must not be {@code null}.
   */
  public synchronized void queueKey(Key key) {
    assert (keysList.size() == keys.size());
    if (keys.add(key)) {
      keysList.add(key);
      if (LOG.isDebugEnabled()) LOG.debug("Queued key {} on {}", key, this);
    }
    assert (keysList.size() == keys.size());
  }

  /**
   * Resolves the underlying {@link Key} contained in a selection token produced by {@link
   * #chooseKey(KeysFetchingLocally, ClientContext)}.
   *
   * @param token a token previously returned by {@code chooseKey}; must be non-{@code null} and of
   *     the correct internal type.
   * @return the concrete key to attempt.
   */
  @Override
  public Key getNodeKey(SendableRequestItem token) {
    return ((MySendableRequestItem) token).key;
  }

  /**
   * Indicates whether the offered keys are SSKs. When {@code false}, keys are CHKs.
   *
   * @return {@code true} for SSKs; {@code false} for CHKs.
   */
  @Override
  public boolean isSSK() {
    return isSSK;
  }

  /** {@inheritDoc} */
  @Override
  public boolean isInsert() {
    return false;
  }

  /**
   * Returns the scheduler responsible for handling attempts for this list based on the key type and
   * real-time flag.
   *
   * @param context the client context used to obtain the appropriate scheduler instance.
   * @return the SSK or CHK fetch scheduler, selected according to {@link #isSSK()} and {@code
   *     realTimeFlag}.
   */
  @Override
  public ClientRequestScheduler getScheduler(ClientContext context) {
    if (isSSK) return context.getSskFetchScheduler(realTimeFlag);
    else return context.getChkFetchScheduler(realTimeFlag);
  }

  /**
   * No-op for this helper. Offered keys do not require preregistration with the scheduler/network.
   *
   * @param context the client context, unused.
   * @param toNetwork {@code true} when registering for network activity; ignored here.
   * @return always {@code false} to indicate that no preregistration took place.
   */
  @Override
  public boolean preRegister(ClientContext context, boolean toNetwork) {
    return false;
  }

  /**
   * Returns the time at which the scheduler should next consider this list.
   *
   * <p>The list signals "not ready" by returning {@link Long#MAX_VALUE} when empty and returns
   * {@code 0} to indicate immediate readiness when there are offered keys available.
   *
   * @param context the client context; unused by this implementation.
   * @param now the current time in milliseconds since the epoch; unused here.
   * @return {@link Long#MAX_VALUE} when no work is pending, or {@code 0} when keys are available.
   */
  @Override
  public long getWakeupTime(ClientContext context, long now) {
    if (isEmpty()) {
      return Long.MAX_VALUE;
    }
    return 0;
  }

  /**
   * Explicitly disallows serialization to avoid accidental persistence of transient state.
   *
   * @param out the stream to which the object would be written; ignored.
   * @throws IOException always thrown via {@link NotSerializableException} to signal that this type
   *     is not serializable.
   */
  @Serial
  private void writeObject(ObjectOutputStream out) throws IOException {
    throw new NotSerializableException(getClass().getName());
  }

  /**
   * Explicitly disallows deserialization to avoid accidental restoration of transient state.
   *
   * @param in the stream from which the object would be read; ignored.
   * @throws IOException always thrown via {@link NotSerializableException} to signal that this type
   *     is not serializable.
   * @throws ClassNotFoundException included for the serialization signature; never actually used
   *     because this method always throws {@link NotSerializableException}.
   */
  @Serial
  private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    throw new NotSerializableException(getClass().getName());
  }
}

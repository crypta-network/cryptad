package network.crypta.client.async;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serial;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.client.InsertException;
import network.crypta.client.Metadata;
import network.crypta.keys.BaseClientKey;
import network.crypta.support.ListUtils;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.ResumeFailedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Aggregates completion and progress signals for a group of client put operations.
 *
 * <p>This callback acts as a rendezvous for multiple {@link ClientPutState} instances that together
 * form a larger logical insert. It tracks when each child becomes fetchable, when its block set is
 * finished, and when the overall group has either succeeded or failed. The instance also implements
 * {@link ClientPutState} so it can be passed downstream as a single delegate representing the whole
 * operation.
 *
 * <p>Typical usage is to construct the callback, add each participating state via {@link
 * #add(ClientPutState)}, optionally mark the URI-generating state with {@link
 * #addURIGenerator(ClientPutState)}, and finally call {@link #arm(ClientContext)} when the group is
 * ready to run. The class ensures that {@link #onFetchable(ClientPutState)} is forwarded once when
 * all children are fetchable and that {@link #onBlockSetFinished(ClientPutState, ClientContext)} is
 * forwarded after the last child reports its blocks finished.
 *
 * <p>Thread-safety: internal bookkeeping is guarded by synchronization and {@link
 * java.util.concurrent.CopyOnWriteArrayList} collections, allowing concurrent notifications from
 * child states without external locking. The instance is mutable during its active lifetime and
 * becomes effectively immutable once {@link #finished} is set. This class is optimized for
 * relatively small groups; using lists instead of sets reduces memory overhead.
 *
 * <ul>
 *   <li>Collisions can optionally be treated as success via the {@code collisionIsOK} flag.
 *   <li>When {@code finishOnFailure} is enabled, remaining children are canceled after the first
 *       failure.
 *   <li>For persistent operations, failures may be cloned to decouple from internal removal.
 * </ul>
 *
 * @see PutCompletionCallback
 * @see ClientPutState
 */
public class MultiPutCompletionCallback
    implements PutCompletionCallback, ClientPutState, Serializable {
  private static final Logger LOG = LoggerFactory.getLogger(MultiPutCompletionCallback.class);

  @Serial private static final long serialVersionUID = 1L;

  // ArrayLists rather than HashSet's for memory reasons.
  // This class will not be used with large sets, so O(n) is cheaper than O(1) -
  // at least it is on memory!
  /** Child states still expected to complete; mutated under synchronization. */
  @SuppressWarnings("java:S1948")
  private CopyOnWriteArrayList<ClientPutState> waitingFor;

  /**
   * Child states that have not yet reported {@link #onBlockSetFinished(ClientPutState,
   * ClientContext)}.
   */
  @SuppressWarnings("java:S1948")
  private CopyOnWriteArrayList<ClientPutState> waitingForBlockSet;

  /** Child states that have not yet reported {@link #onFetchable(ClientPutState)}. */
  @SuppressWarnings("java:S1948")
  private CopyOnWriteArrayList<ClientPutState> waitingForFetchable;

  /** Downstream callback that receives group-level notifications. */
  @SuppressWarnings("java:S1948")
  private final PutCompletionCallback cb;

  /**
   * Optional child designated as the URI generator; its metadata and {@link
   * #onEncode(BaseClientKey, ClientPutState, ClientContext)} events are forwarded.
   */
  @SuppressWarnings("java:S1948")
  private ClientPutState generator;

  /** Owning the putter that initiated the multi-put sequence. */
  private final BaseClientPutter parent;

  /** The first failure observed, retained until completion (may be replaced on later failure). */
  private InsertException e;

  /** True when a cancellation has been requested before {@link #arm(ClientContext)}. */
  private boolean cancelling;

  /** Set to true after the group definitively completes (success or failure). */
  private boolean finished;

  /** Set to true by {@link #arm(ClientContext)} to enable terminal forwarding. */
  private boolean started;

  /** Ensures {@link #onFetchable(ClientPutState)} is forwarded at most once. */
  private boolean calledFetchable;

  /**
   * Application-provided token associated with this multi-put.
   *
   * <p>The token is carried through callbacks unchanged and is useful for correlating events with
   * higher-level request state managed by the caller. The value is not interpreted by this class
   * and may be {@code null}. Immutability and thread-safety are the responsibility of the caller.
   */
  @SuppressWarnings("java:S1948")
  public final Object token;

  /** True, when the operation can survive restarts and should preserve the error context. */
  private final boolean persistent;

  /** Treat {@link InsertExceptionMode#COLLISION} as success when enabled. */
  private final boolean collisionIsOK;

  /** Cancel remaining children after the first failure when enabled. */
  private final boolean finishOnFailure;

  /** Guards idempotent resume; set after the first {@link #onResume(ClientContext)}. */
  private transient boolean resumed;

  /** The encoded key reported by the generator; used to squash duplicate notifications. */
  private BaseClientKey encodedKey;

  /**
   * Creates a multi-put callback that aggregates the given child operations.
   *
   * <p>This constructor treats collisions as failures and does not cancel remaining children on the
   * first failure. Use the longer forms to override those behaviors.
   *
   * @param cb the downstream {@link PutCompletionCallback} that receives group-level events; must
   *     accept callbacks from any thread; never {@code null}
   * @param parent the owning {@link BaseClientPutter} that logically groups the children; used for
   *     identity and scheduling context; never {@code null}
   * @param token opaque token returned by {@link #getToken()} and forwarded to callbacks; may be
   *     {@code null} and is not inspected
   * @param persistent whether the group should preserve failure details across restarts and clone
   *     exceptions when needed to avoid internal mutation side effects
   */
  public MultiPutCompletionCallback(
      PutCompletionCallback cb, BaseClientPutter parent, Object token, boolean persistent) {
    this(cb, parent, token, persistent, false);
  }

  /**
   * Creates a multi-put callback with explicit collision handling.
   *
   * <p>When {@code collisionIsOK} is {@code true}, a child failure with {@link
   * InsertExceptionMode#COLLISION} is treated as success for group completion.
   *
   * @param cb the downstream {@link PutCompletionCallback} for group-level events; never {@code
   *     null}
   * @param parent the owning {@link BaseClientPutter}; never {@code null}
   * @param token opaque correlation token stored in {@link #token}; may be {@code null}
   * @param persistent whether failure information should be preserved across resumes
   * @param collisionIsOK whether collisions are interpreted as success during aggregation
   */
  public MultiPutCompletionCallback(
      PutCompletionCallback cb,
      BaseClientPutter parent,
      Object token,
      boolean persistent,
      boolean collisionIsOK) {
    this(cb, parent, token, persistent, collisionIsOK, false);
  }

  /**
   * Creates a multi-put callback with full control over collision and early-cancel behavior.
   *
   * <p>When {@code finishOnFailure} is {@code true}, remaining children are canceled after the
   * first failure is observed (post-{@link #arm(ClientContext)}). This can reduce resource usage
   * and latency at the cost of losing additional error details from later children.
   *
   * @param cb the downstream {@link PutCompletionCallback} for group-level events; never {@code
   *     null}
   * @param parent the owning {@link BaseClientPutter}; never {@code null}
   * @param token opaque correlation token stored in {@link #token}; may be {@code null}
   * @param persistent whether failure information should be preserved across resumes
   * @param collisionIsOK whether collisions are interpreted as success during aggregation
   * @param finishOnFailure whether to cancel remaining children after the first failure once armed
   */
  public MultiPutCompletionCallback(
      PutCompletionCallback cb,
      BaseClientPutter parent,
      Object token,
      boolean persistent,
      boolean collisionIsOK,
      boolean finishOnFailure) {
    this.cb = cb;
    this.collisionIsOK = collisionIsOK;
    this.finishOnFailure = finishOnFailure;
    waitingFor = new CopyOnWriteArrayList<>();
    waitingForBlockSet = new CopyOnWriteArrayList<>();
    waitingForFetchable = new CopyOnWriteArrayList<>();
    this.parent = parent;
    this.token = token;
    cancelling = false;
    finished = false;
    this.persistent = persistent;
  }

  /** {@inheritDoc} */
  @Override
  public void onSuccess(ClientPutState state, ClientContext context) {
    onBlockSetFinished(state, context);
    onFetchable(state);
    boolean complete = true;
    synchronized (this) {
      if (finished) {
        LOG.error("event=multi-put-onSuccess-after-finish state={} callback={}", state, this);
        return;
      }
      ListUtils.removeBySwapLast(waitingFor, state);
      ListUtils.removeBySwapLast(waitingForBlockSet, state);
      ListUtils.removeBySwapLast(waitingForFetchable, state);
      if (!(waitingFor.isEmpty() && started)) {
        complete = false;
      }
      if (state == generator) {
        generator = null;
      }
    }
    if (complete) {
      LOG.debug("Completing...");
      complete(null, context);
    }
  }

  /**
   * Handles a failure notification from a child state and decides whether to continue or finish.
   *
   * <p>When {@code collisionIsOK} is enabled and the mode is {@link InsertExceptionMode#COLLISION},
   * the failure is converted into a success for the child and normal aggregation proceeds.
   * Otherwise, the first failure is recorded; if the group has already been {@link
   * #arm(ClientContext) armed} and {@code finishOnFailure} is enabled, remaining children are
   * canceled.
   *
   * @param e the failure reported by the child; may be cloned internally when persistence requires
   *     decoupling from internal removal
   * @param state the child that failed; must be one of the registered children
   * @param context ambient client context supplied by the caller
   */
  @Override
  public void onFailure(InsertException e, ClientPutState state, ClientContext context) {
    if (collisionIsOK && e.getMode() == InsertExceptionMode.COLLISION) {
      onSuccess(state, context);
      return;
    }
    boolean complete = true;
    boolean doCancel = false;
    synchronized (this) {
      if (finished) {
        LOG.error("event=multi-put-onFailure-after-finish state={} callback={}", state, this);
        return;
      }
      ListUtils.removeBySwapLast(waitingFor, state);
      ListUtils.removeBySwapLast(waitingForBlockSet, state);
      ListUtils.removeBySwapLast(waitingForFetchable, state);
      if (!(waitingFor.isEmpty() && started)) {
        this.e = e;
        if (LOG.isDebugEnabled())
          LOG.debug("Still running: {} started = {}", waitingFor.size(), started);
        complete = false;
      }
      if (state == generator) {
        generator = null;
      }
      if (finishOnFailure) {
        if (started) doCancel = true;
        else {
          cancelling = true;
        }
      }
    }
    if (complete) complete(e, context);
    else if (doCancel) cancel(context);
  }

  /** Completes the group and forwards the outcome to the downstream callback. */
  private void complete(InsertException e, ClientContext context) {
    synchronized (this) {
      if (finished) return;
      finished = true;
      if (e != null && this.e != null && this.e != e) {
        if (e.getMode()
            == InsertExceptionMode
                .CANCELLED) { // Canceled is okay, ignore it, we cancel after failure sometimes.
          // Ignore the new failure mode, use the old one
          e = this.e;
          if (persistent) {
            e = new InsertException(e); // deep copy before removal
          }
        } else {
          // Delete the old failure mode, use the new one
          this.e = e;
        }
      }
      if (e == null) {
        e = this.e;
        if (persistent && e != null) {
          e = new InsertException(e); // deep copy before removal
        }
      }
    }
    if (e != null) cb.onFailure(e, this, context);
    else cb.onSuccess(this, context);
  }

  /**
   * Adds a child state and marks it as the URI generator.
   *
   * <p>The generator’s {@link #onEncode(BaseClientKey, ClientPutState, ClientContext)} and metadata
   * callbacks are forwarded to the downstream callback, allowing callers to observe the final
   * encoded key and associated metadata once available.
   *
   * @param ps the child state that will generate the final URI and metadata; must be non-null and
   *     added only once
   */
  public synchronized void addURIGenerator(ClientPutState ps) {
    add(ps);
    generator = ps;
  }

  /**
   * Adds a child state to the aggregation, tracking its progress toward completion.
   *
   * <p>Callers typically add all children before invoking {@link #arm(ClientContext)}. Adding a
   * child after the group has finished is ignored.
   *
   * @param ps the child put state to include in the group; must be non-null
   */
  public synchronized void add(ClientPutState ps) {
    if (finished) return;
    waitingFor.add(ps);
    waitingForBlockSet.add(ps);
    waitingForFetchable.add(ps);
  }

  /**
   * Arms the aggregation, enabling completion and cancellation behavior.
   *
   * <p>After arming, if there are no remaining children, the outcome is forwarded immediately. If a
   * pre-arm cancellation was requested, the method cancels all children. The method also forwards
   * {@link #onBlockSetFinished(ClientPutState, ClientContext)} when the last child has finished
   * setting its blocks.
   *
   * @param context ambient client context used for forwarding downstream callbacks
   */
  public void arm(ClientContext context) {
    if (LOG.isDebugEnabled()) LOG.debug("Arming {}", this);
    boolean allDone;
    boolean allGotBlocks;
    boolean doCancel;
    InsertException failureSnapshot;
    synchronized (this) {
      started = true;
      allDone = waitingFor.isEmpty();
      allGotBlocks = waitingForBlockSet.isEmpty();
      doCancel = cancelling;
      failureSnapshot = e;
    }
    if (allGotBlocks) {
      cb.onBlockSetFinished(this, context);
    }
    if (allDone) {
      complete(failureSnapshot, context);
    } else if (doCancel) {
      cancel(context);
    }
  }

  @Override
  public BaseClientPutter getParent() {
    return parent;
  }

  /**
   * Forwards the encoded key from the designated generator to the downstream callback.
   *
   * <p>Duplicate notifications with the same key are squashed. If different keys are reported for
   * the same operation, the discrepancy is logged and the latest key is forwarded.
   *
   * @param key the encoded key produced by the generator; never {@code null}
   * @param state the child reporting the event; ignored unless it is the current generator
   * @param context ambient client context used for forwarding downstream callbacks
   */
  @Override
  public void onEncode(BaseClientKey key, ClientPutState state, ClientContext context) {
    synchronized (this) {
      if (state != generator) return;
      if (encodedKey != null) {
        if (key.equals(encodedKey)) return; // Squash duplicated call to onEncode().
        else
          LOG.error("Encoded twice with different keys for {} : {} -> {}", this, encodedKey, key);
      }
      encodedKey = key;
    }
    cb.onEncode(key, this, context);
  }

  /**
   * Cancels all outstanding children currently tracked by this aggregation.
   *
   * <p>Cancellation is best-effort and proceeds child-by-child. This invocation will not cancel any
   * children added concurrently after the snapshot is taken.
   *
   * @param context ambient client context supplied to each child’s {@code cancel}
   */
  @Override
  public void cancel(ClientContext context) {
    ClientPutState[] states = new ClientPutState[waitingFor.size()];
    synchronized (this) {
      states = waitingFor.toArray(states);
    }
    for (int i = 0; i < states.length; i++) {
      if (LOG.isDebugEnabled())
        LOG.debug("Cancelling state {} of {} : {}", i, states.length, states[i]);
      states[i].cancel(context);
    }
  }

  /**
   * Updates internal references when a child transitions to a new state instance.
   *
   * <p>All lists are updated in-place, so further notifications continue to be associated with the
   * correct child. If the old and new references are identical, the call is ignored.
   *
   * @param oldState the previous child state reference; must be tracked
   * @param newState the replacement state reference; must not be {@code null}
   * @param context ambient client context (unused but part of the contract)
   */
  @Override
  public synchronized void onTransition(
      ClientPutState oldState, ClientPutState newState, ClientContext context) {
    if (generator == oldState) generator = newState;
    if (oldState == newState) return;
    for (int i = 0; i < waitingFor.size(); i++) {
      if (waitingFor.get(i) == oldState) {
        waitingFor.set(i, newState);
      }
    }
    for (int i = 0; i < waitingForBlockSet.size(); i++) {
      if (waitingForBlockSet.get(i) == oldState) {
        waitingForBlockSet.set(i, newState);
      }
    }
    for (int i = 0; i < waitingForFetchable.size(); i++) {
      if (waitingForFetchable.get(i) == oldState) {
        waitingForFetchable.set(i, newState);
      }
    }
  }

  /**
   * Forwards structured metadata from the generator to the downstream callback.
   *
   * <p>Only metadata reported by the current generator is forwarded; other children reporting
   * metadata trigger an internal error log.
   *
   * @param m structured metadata for the encoded content; never {@code null}
   * @param state the child reporting metadata; must be the current generator
   * @param context ambient client context used for forwarding downstream callbacks
   */
  @Override
  public synchronized void onMetadata(Metadata m, ClientPutState state, ClientContext context) {
    if (generator == state) {
      cb.onMetadata(m, this, context);
    } else {
      LOG.error("event=multi-put-metadata-non-generator state={}", state);
    }
  }

  /**
   * Forwards opaque metadata from the generator to the downstream callback.
   *
   * <p>This overload is used when metadata is provided in a {@link Bucket}. Only notifications from
   * the generator are forwarded; others are logged.
   *
   * @param metadata opaque metadata bucket; the caller defines ownership and lifetime
   * @param state the child reporting metadata; must be the current generator
   * @param context ambient client context used for forwarding downstream callbacks
   */
  @Override
  public synchronized void onMetadata(
      Bucket metadata, ClientPutState state, ClientContext context) {
    if (generator == state) {
      cb.onMetadata(metadata, this, context);
    } else {
      LOG.error("event=multi-put-metadata-bucket-non-generator state={}", state);
    }
  }

  /**
   * Tracks completion of a child’s block set and forwards a group-level notification when all have
   * finished.
   *
   * <p>The downstream {@link #cb} is notified once after the last child reports completion and the
   * group has been armed.
   *
   * @param state the child whose block set finished
   * @param context ambient client context used for forwarding downstream callbacks
   */
  @Override
  public void onBlockSetFinished(ClientPutState state, ClientContext context) {
    synchronized (this) {
      ListUtils.removeBySwapLast(this.waitingForBlockSet, state);
      if (!started) return;
      if (!waitingForBlockSet.isEmpty()) return;
    }
    cb.onBlockSetFinished(this, context);
  }

  /**
   * No-op schedule method; aggregation itself does not perform additional scheduling.
   *
   * @param context ambient client context
   * @throws InsertException never thrown by this implementation
   */
  @Override
  public void schedule(ClientContext context) throws InsertException {
    // Do nothing
  }

  /**
   * Returns the opaque correlation token supplied at construction time.
   *
   * @return the token associated with this aggregation; may be {@code null} and is returned by
   *     reference without copying
   */
  @Override
  public Object getToken() {
    return token;
  }

  /**
   * Tracks that a child has become fetchable and forwards a single group-level notification when
   * all children are fetchable.
   *
   * <p>The downstream callback is invoked at most once per aggregation, even if additional
   * notifications arrive later.
   *
   * @param state the child that became fetchable
   */
  @Override
  public void onFetchable(ClientPutState state) {
    synchronized (this) {
      ListUtils.removeBySwapLast(this.waitingForFetchable, state);
      if (!started) return;
      if (!waitingForFetchable.isEmpty()) return;
      if (calledFetchable) {
        if (LOG.isDebugEnabled()) LOG.debug("Trying to call onFetchable() twice");
        return;
      }
      calledFetchable = true;
    }
    cb.onFetchable(this);
  }

  /**
   * Resumes all tracked children and, if needed, resumes the downstream callback.
   *
   * <p>The method is idempotent; only the first invocation performs any work. Children are resumed
   * sequentially, and any exceptions propagate, according to the contract.
   *
   * @param context ambient client context used for resuming
   * @throws InsertException if a child cannot be resumed due to an insert-related error
   * @throws ResumeFailedException if resuming the previously persisted state fails
   */
  @Override
  public void onResume(ClientContext context) throws InsertException, ResumeFailedException {
    synchronized (this) {
      if (resumed) return;
      resumed = true;
    }
    for (ClientPutState s : getWaitingFor()) s.onResume(context);
    if (cb != parent) cb.onResume(context);
  }

  /**
   * Propagates shutdown to all currently tracked children.
   *
   * @param context ambient client context supplied to each child’s shutdown
   */
  @Override
  public void onShutdown(ClientContext context) {
    for (ClientPutState state : getWaitingFor()) {
      state.onShutdown(context);
    }
  }

  /** Returns a snapshot copy of the children still being tracked. */
  private synchronized List<ClientPutState> getWaitingFor() {
    return new ArrayList<>(waitingFor);
  }

  /**
   * Reinitializes fields for backward compatibility after deserialization.
   *
   * <p>Older serialized forms may not carry the waiting state collections because they were marked
   * transient at the time. When absent, initialize them to empty lists so methods that iterate over
   * them remain safe. Newer serialized forms preserve the collections and the generator reference
   * across restarts, allowing accurate resumption.
   *
   * @param in the input stream providing the serialized state; must not be {@code null}
   * @throws IOException if reading from the underlying stream fails
   * @throws ClassNotFoundException if a class referenced in the stream cannot be resolved
   */
  @Serial
  private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    in.defaultReadObject();
    final var wf = waitingFor;
    waitingFor = (wf == null) ? new CopyOnWriteArrayList<>() : new CopyOnWriteArrayList<>(wf);
    final var wfbs = waitingForBlockSet;
    waitingForBlockSet =
        (wfbs == null) ? new CopyOnWriteArrayList<>() : new CopyOnWriteArrayList<>(wfbs);
    final var wff = waitingForFetchable;
    waitingForFetchable =
        (wff == null) ? new CopyOnWriteArrayList<>() : new CopyOnWriteArrayList<>(wff);
  }
}

package network.crypta.client.async;

import java.io.IOException;
import java.io.Serial;
import java.io.Serializable;
import network.crypta.client.ClientMetadata;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.FetchResult;
import network.crypta.keys.ClientKey;
import network.crypta.keys.ClientKeyBlock;
import network.crypta.keys.Key;
import network.crypta.keys.KeyDecodeException;
import network.crypta.keys.TooBigException;
import network.crypta.node.LowLevelGetException;
import network.crypta.node.SendableRequestItem;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.InsufficientDiskSpaceException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Fetches exactly one client-level block and reports the outcome to a completion callback.
 *
 * <p>This class is the minimal building block for a single-block GET operation. It composes the
 * request registration, cooldown/retry policy, and scheduler integration provided by {@link
 * BaseSingleFileFetcher} with a narrow API focused on producing a decoded {@link FetchResult}. Use
 * it when a caller already has a {@link ClientKey} that resolves to exactly one block or when a
 * higher-level helper can short-circuit into a direct block fetch. Typical usage is to build a
 * {@link Cfg}, construct the fetcher, and invoke {@link #schedule(ClientContext)} (inherited) so
 * the request participates in the client schedulers.
 *
 * <p>Instances are stateful and progress through a simple lifecycle: created, scheduled, retried
 * (optional), and then terminal success or failure. The instance tracks cancellation and completion
 * flags, and for persistent requests the callback and state are serialized, so work can resume
 * after restart. Callers should treat the fetcher as mutable and rely on its internal
 * synchronization for state transitions rather than accessing fields directly.
 *
 * <ul>
 *   <li><strong>Responsibilities</strong>: register a single key, decode the resulting block, and
 *       notify a {@link GetCompletionCallback}.
 *   <li><strong>Notable behaviors</strong>: cancellation reports {@link
 *       FetchException.FetchExceptionMode#CANCELLED} and prevents further callbacks.
 *   <li><strong>Threading</strong>: methods may be called on scheduler threads; the implementation
 *       synchronizes narrowly on {@code this} to protect flags.
 * </ul>
 *
 * @see BaseSingleFileFetcher
 * @see ClientRequester
 * @see ClientContext
 * @see FetchContext
 * @see SingleFileFetcher
 */
public class SimpleSingleFileFetcher extends BaseSingleFileFetcher
    implements ClientGetState, Serializable {

  /**
   * Supplies a custom priority class for scheduling operations.
   *
   * <p>Implementations provide a stable priority value for use by schedulers. The provider should
   * avoid expensive computation because it may be invoked from scheduling hot paths. Implementers
   * must be {@link Serializable} when the owning request is persistent.
   */
  public interface PriorityClassProvider extends Serializable {
    /**
     * Returns the priority class used to schedule this fetcher.
     *
     * <p>Callers expect a value compatible with the request scheduler priority bands. The return
     * value should remain consistent for the lifetime of the fetcher unless the caller explicitly
     * wants priority to change between scheduling cycles. Providers should avoid blocking work or
     * expensive computation because this method may be invoked from scheduling hot paths.
     *
     * @return priority class for scheduler registration and wakeup decisions
     */
    short getPriorityClass();
  }

  /**
   * Builds a key listener for this fetcher when scheduling.
   *
   * <p>The factory allows callers to customize listener creation while preserving the fetcher's
   * internal bookkeeping. Implementations should be {@link Serializable} if the parent request is
   * persistent so the listener logic survives restarts.
   */
  public interface KeyListenerFactory extends Serializable {
    /**
     * Creates the key listener used by schedulers to match and handle keys.
     *
     * <p>The implementation may return {@code null} to indicate that no listener should be created
     * for the current state (for example, when canceled). Factories should avoid mutating external
     * state and should return quickly to keep scheduler threads responsive. The {@code onStartup}
     * flag can be used to decide whether to suppress listener creation during initialization.
     *
     * @param fetcher fetcher requesting the listener, never {@code null}
     * @param context client context for scheduler access, never {@code null}
     * @param onStartup {@code true} when invoked during node startup initialization
     * @return a listener instance, or {@code null} to skip listener creation
     */
    KeyListener makeKeyListener(
        SimpleSingleFileFetcher fetcher, ClientContext context, boolean onStartup);
  }

  private static final Logger LOG = LoggerFactory.getLogger(SimpleSingleFileFetcher.class);

  @Serial private static final long serialVersionUID = 1L;

  SimpleSingleFileFetcher(Cfg cfg) {
    super(cfg.key, cfg.maxRetries, cfg.ctx, cfg.parent, cfg.deleteFetchContext, cfg.realTimeFlag);
    this.rcb = cfg.rcb;
    this.token = cfg.token;
    this.priorityClassProvider = cfg.priorityClassProvider;
    this.keyListenerFactory = cfg.keyListenerFactory;
    if (!cfg.dontAdd) {
      if (cfg.isEssential) cfg.parent.addMustSucceedBlocks(1);
      else cfg.parent.addBlock();
      cfg.parent.notifyClients(cfg.context);
    }
  }

  /**
   * Completion callback invoked on terminal success or failure and during progress reporting.
   *
   * <p>For persistent requests the concrete implementation is expected to be {@link Serializable}
   * and is serialized together with the fetcher so that callbacks continue to work after a restart.
   * The field is immutable after construction.
   */
  @SuppressWarnings("java:S1948")
  final GetCompletionCallback rcb;

  /**
   * Opaque token supplied by the creator to correlate this fetch with external state.
   *
   * <p>The token is returned from {@link #getToken()} and otherwise not interpreted by this class.
   * Implementations typically use it to associate scheduler events with higher-level request
   * bookkeeping.
   */
  final long token;

  /** Optional provider that supplies the scheduling priority for this fetcher. */
  private final PriorityClassProvider priorityClassProvider;

  /** Optional factory that customizes key listener creation for this fetcher. */
  private final KeyListenerFactory keyListenerFactory;

  /**
   * Returns the priority class used by schedulers to order this fetcher.
   *
   * <p>If a {@link PriorityClassProvider} is configured, the value is delegated to that provider;
   * otherwise the priority of the parent requester is used. The method performs no side effects and
   * may be called frequently while scheduling is active. Callers should not assume the value is
   * cached between invocations, so providers should keep the computation lightweight.
   *
   * @return scheduler priority class, consistent with the current request configuration
   */
  @Override
  public short getPriorityClass() {
    if (priorityClassProvider != null) return priorityClassProvider.getPriorityClass();
    return super.getPriorityClass();
  }

  /**
   * Creates the key listener used to match the fetcher's key in schedulers and stores.
   *
   * <p>The default implementation delegates to {@link BaseSingleFileFetcher} to create a listener
   * that tracks a single node key. When a {@link KeyListenerFactory} is supplied, this method
   * delegates to the factory instead, enabling custom cancellation checks or priority adjustments.
   * The method may return {@code null} when the request is already finished or canceled, and it
   * should not be used to perform long-running setup work.
   *
   * @param context client context used for scheduler access and node state
   * @param onStartup {@code true} when invoked during node startup initialization
   * @return a key listener for scheduling, or {@code null} if none should be registered
   */
  @Override
  public KeyListener makeKeyListener(ClientContext context, boolean onStartup) {
    if (keyListenerFactory != null)
      return keyListenerFactory.makeKeyListener(this, context, onStartup);
    return super.makeKeyListener(context, onStartup);
  }

  KeyListener createKeyListener(short priorityClass) {
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
    if (parent == null) {
      LOG.error("Parent is null on {} persistent={} key={} ctx={}", this, persistent, key, ctx);
      return null;
    }
    Key newKey = key.getNodeKey(true);
    return new SingleKeyListener(newKey, this, priorityClass, persistent);
  }

  // No static initialization required.

  /**
   * Translates a low-level failure into a client-level failure and forwards it.
   *
   * <p>This method maps a {@link LowLevelGetException} into a {@link FetchException} and then
   * delegates to {@link #onFailure(FetchException, boolean, ClientContext)} for retry and
   * notification handling. It does not attempt additional recovery on its own and does not inspect
   * the scheduler token beyond accepting the callback signature. The call is idempotent with
   * respect to an already finished or canceled fetch; any such state is handled in the delegated
   * method.
   *
   * @param e low-level failure reported by the scheduler, never {@code null}
   * @param reqTokenIgnored scheduling token for the failed request, ignored by this implementation
   * @param context client runtime context used for scheduler and callback access
   */
  @Override
  public void onFailure(
      LowLevelGetException e, SendableRequestItem reqTokenIgnored, ClientContext context) {
    onFailure(translateException(e), false, context);
  }

  /**
   * Handles a mapped client-level failure for this fetch.
   *
   * <p>The method checks cancellation state, applies retry and cooldown policy when the failure is
   * non-fatal, and emits the appropriate completion callback. When a terminal outcome is reached,
   * the request is unregistered and the parent counters are updated to reflect failure. This method
   * is safe to call multiple times; once the fetch is finished or canceled, further calls only
   * observe that state and return without scheduling additional work.
   *
   * @param e client-level failure describing the reason and details, never {@code null}
   * @param forceFatal when {@code true}, treat the error as terminal regardless of retry policy
   * @param context client runtime context used for schedulers and resource management
   */
  protected void onFailure(FetchException e, boolean forceFatal, ClientContext context) {
    if (LOG.isDebugEnabled()) LOG.debug("onFailure( {} , {})", e, forceFatal, e);
    if (parent.isCancelled() || cancelled) {
      if (LOG.isDebugEnabled()) LOG.debug("Failing: cancelled");
      e = new FetchException(FetchExceptionMode.CANCELLED);
      forceFatal = true;
    }
    if (!(e.isFatal() || forceFatal) && retry(context)) {
      if (LOG.isDebugEnabled()) LOG.debug("Retrying");
      return;
    }
    // :(
    unregisterAll(context);
    synchronized (this) {
      finished = true;
    }
    if (e.isFatal() || forceFatal) parent.fatallyFailedBlock(context);
    else parent.failedBlock(context);
    rcb.onFailure(e, this, context);
  }

  /**
   * Delivers a successful decoding to the completion callback.
   *
   * <p>The method guards against late cancellation: if the parent request is already canceled, the
   * decoded data is released and a cancellation failure is reported instead of success. Otherwise,
   * the data bucket is wrapped in a {@link SingleFileStreamGenerator} and forwarded to the
   * callback. This method performs no retries and is expected to be called at most once per
   * instance.
   *
   * @param data decoded result containing metadata and a data bucket, never {@code null}
   * @param context client runtime context used for resource cleanup and callbacks
   */
  protected void onSuccess(FetchResult data, ClientContext context) {
    if (parent.isCancelled()) {
      try (Bucket b = data.asBucket()) {
        // Explicitly free for mocks; try-with-resources ensures real buckets are closed too.
        b.free();
      }
      onFailure(new FetchException(FetchExceptionMode.CANCELLED), false, context);
      return;
    }
    rcb.onSuccess(
        new SingleFileStreamGenerator(data.asBucket(), persistent),
        data.getMetadata(),
        null,
        this,
        context);
  }

  /**
   * Handles a verified client-level block and completes the fetch if it contains data.
   *
   * <p>The method extracts a data bucket from the provided block and, when successful, forwards the
   * result to {@link #onSuccess(FetchResult, ClientContext)}. Metadata blocks are treated as an
   * error because this fetcher expects a single data block. Callers should pass the block as
   * verified; this method does not re-validate signatures beyond the decoding step.
   *
   * @param block verified client key block holding the fetched payload, never {@code null}
   * @param fromStore {@code true} when the block originated from local storage
   * @param reqTokenIgnored scheduler token for the request, ignored by this implementation
   * @param context client runtime context used for bucket factories and callbacks
   */
  @Override
  public void onSuccess(
      ClientKeyBlock block, boolean fromStore, Object reqTokenIgnored, ClientContext context) {
    if (parent instanceof ClientGetter getter) getter.addKeyToBinaryBlob(block, context);
    Bucket data = extract(block, context);
    if (data == null) return; // failed
    context.uskManager.checkUSK(key.getURI(), fromStore, block.isMetadata());
    if (!block.isMetadata()) {
      onSuccess(new FetchResult(new ClientMetadata(null), data), context);
    } else {
      onFailure(
          new FetchException(FetchExceptionMode.INVALID_METADATA, "Metadata where expected data"),
          false,
          context);
    }
  }

  /**
   * Extracts a decoded data bucket from a verified {@link ClientKeyBlock}.
   *
   * <p>The block is decoded using the current fetch context limits. Any decoding failure or I/O
   * error is reported through {@link #onFailure(FetchException, boolean, ClientContext)}, and this
   * method returns {@code null} to signal a terminal path. A non-null return indicates ownership of
   * the bucket has been transferred to the caller, who is responsible for closing or freeing it.
   *
   * @param block verified client key block obtained from network or local storage
   * @param context client runtime context providing bucket factories and scheduler access
   * @return a decoded data bucket, or {@code null} after a reported failure
   */
  protected Bucket extract(ClientKeyBlock block, ClientContext context) {
    Bucket data;
    try {
      data =
          block.decode(
              context.getBucketFactory(parent.persistent()),
              (int) (Math.min(ctx.getMaxOutputLength(), Integer.MAX_VALUE)),
              false);
    } catch (KeyDecodeException e1) {
      if (LOG.isDebugEnabled()) LOG.debug("Decode failure: {}", e1, e1);
      onFailure(
          new FetchException(FetchExceptionMode.BLOCK_DECODE_ERROR, e1.getMessage()),
          false,
          context);
      return null;
    } catch (TooBigException e) {
      onFailure(new FetchException(FetchExceptionMode.TOO_BIG, e), false, context);
      return null;
    } catch (InsufficientDiskSpaceException _) {
      onFailure(new FetchException(FetchExceptionMode.NOT_ENOUGH_DISK_SPACE), false, context);
      return null;
    } catch (IOException e) {
      LOG.error("Could not capture data - disk full?: {}", e, e);
      onFailure(new FetchException(FetchExceptionMode.BUCKET_ERROR, e), false, context);
      return null;
    }
    return data;
  }

  /**
   * Returns the opaque token associated with this fetcher.
   *
   * <p>The value originates from the {@link Cfg} used at construction time. It is propagated
   * unchanged through callbacks so higher-level code can correlate scheduler events with external
   * state. The token is not interpreted by this class and may be any 64-bit value chosen by the
   * caller.
   *
   * @return the creator-supplied token used for external correlation and logging
   */
  @Override
  public long getToken() {
    return token;
  }

  /**
   * Cancels the fetch and reports cancellation to the completion callback.
   *
   * <p>The fetcher is removed from scheduling via the superclass cancellation logic and then emits
   * a {@link FetchException.FetchExceptionMode#CANCELLED} failure to the callback. Repeated calls
   * are safe: once canceled, later invocations will simply re-emit the cancellation failure and
   * leave the instance in its terminal state.
   *
   * @param context client runtime context used to unregister from schedulers
   */
  @Override
  public void cancel(ClientContext context) {
    super.cancel(context);
    rcb.onFailure(new FetchException(FetchExceptionMode.CANCELLED), this, context);
  }

  /**
   * Reports a missing block when the local store did not contain the key.
   *
   * <p>This method converts the absence into a terminal failure with mode {@link
   * FetchException.FetchExceptionMode#DATA_NOT_FOUND}. It is invoked by the base fetcher when the
   * request is configured for local-only behavior and no matching data is found. The method does
   * not attempt retries because the local store has already been checked.
   *
   * @param context client runtime context used for failure reporting and scheduling
   */
  @Override
  protected void notFoundInStore(ClientContext context) {
    this.onFailure(new FetchException(FetchExceptionMode.DATA_NOT_FOUND), true, context);
  }

  /**
   * Reports a terminal failure when a block cannot be decoded or verified.
   *
   * <p>The failure is treated as fatal because the requested block does not match the expected
   * content. The callback receives a {@link FetchException.FetchExceptionMode#BLOCK_DECODE_ERROR}
   * to signal a non-retryable error for this logical fetch. The token is accepted for completeness
   * but is not used to change the failure handling.
   *
   * @param token scheduling token for the failed request, unused in this implementation
   * @param context client runtime context used for failure reporting and scheduling
   */
  @Override
  protected void onBlockDecodeError(SendableRequestItem token, ClientContext context) {
    onFailure(
        new FetchException(
            FetchExceptionMode.BLOCK_DECODE_ERROR,
            "Could not decode block with the URI given, probably invalid as inserted, possible the"
                + " URI is wrong"),
        true,
        context);
  }

  /**
   * Handles scheduler shutdown for this fetcher.
   *
   * <p>This implementation has no shutdown-specific behavior. The method exists to satisfy the
   * {@link ClientGetState} contract and may be overridden by subclasses that need to release
   * resources on shutdown. It does not attempt to cancel or reschedule work on its own.
   *
   * @param context client runtime context provided during shutdown
   */
  @Override
  public void onShutdown(ClientContext context) {
    // Do nothing.
  }

  /**
   * Returns the active {@link ClientGetState} for callbacks and scheduling.
   *
   * <p>This fetcher represents the current state itself, so the method simply returns {@code this}.
   * Subclasses that wrap or delegate to other states should override this method accordingly. The
   * return value is used by callbacks that need a stable handle to the active request state.
   *
   * @return this instance as the active client get state
   */
  @Override
  protected ClientGetState getClientGetState() {
    return this;
  }

  /**
   * Builder-style configuration used to construct a {@link SimpleSingleFileFetcher}.
   *
   * <p>This configuration aggregates the required constructor parameters and exposes fluent setters
   * for optional behavior such as essential accounting and real-time scheduling. Callers create an
   * instance using {@link #create(ClientKey, int, FetchContext, ClientRequester,
   * GetCompletionCallback, long, ClientContext)}, then refine the instance using the available
   * setters before passing it to the {@link SimpleSingleFileFetcher} constructor. The configuration
   * is immutable with respect to required fields and mutable for optional flags.
   *
   * <p>The intent is to keep call sites readable and to preserve a stable parameter ordering. The
   * configuration object itself does not validate inputs beyond nullness expectations; callers
   * should ensure the provided values align with the fetch context limits and scheduling policy.
   */
  public static final class Cfg {
    final ClientKey key;
    final int maxRetries;
    final FetchContext ctx;
    final ClientRequester parent;
    final GetCompletionCallback rcb;
    final long token;
    final ClientContext context;
    boolean isEssential;
    boolean dontAdd;
    boolean deleteFetchContext;
    boolean realTimeFlag;
    PriorityClassProvider priorityClassProvider;
    KeyListenerFactory keyListenerFactory;

    private Cfg(
        ClientKey key,
        int maxRetries,
        FetchContext ctx,
        ClientRequester parent,
        GetCompletionCallback rcb,
        long token,
        ClientContext context) {
      this.key = key;
      this.maxRetries = maxRetries;
      this.ctx = ctx;
      this.parent = parent;
      this.rcb = rcb;
      this.token = token;
      this.context = context;
    }

    /**
     * Creates a configuration instance with the required parameters.
     *
     * <p>The returned configuration captures the mandatory inputs needed to build a fetcher and
     * leaves optional behavior at its defaults. Callers should set any optional flags on the
     * returned instance before passing it to the fetcher constructor. The method performs no side
     * effects beyond storing the provided references and does not allocate network resources.
     *
     * @param key client key identifying the single block to fetch, never {@code null}
     * @param maxRetries maximum retry attempts; use {@code -1} to allow unlimited retries
     * @param ctx fetch context with limits, cooldown policy, and scheduling preferences
     * @param parent owning requester used for accounting, cancellation, and notifications
     * @param rcb completion callback receiving results and progress, must be serializable
     * @param token opaque token carried through callbacks for correlation and logging
     * @param context client runtime context used for schedulers and bucket factories
     * @return a new configuration instance ready for fluent option refinement
     */
    public static Cfg create(
        ClientKey key,
        int maxRetries,
        FetchContext ctx,
        ClientRequester parent,
        GetCompletionCallback rcb,
        long token,
        ClientContext context) {
      return new Cfg(key, maxRetries, ctx, parent, rcb, token, context);
    }

    /**
     * Marks the fetch as essential for the parent’s success accounting.
     *
     * <p>When set to {@code true}, the parent request increments the “must succeed” counters rather
     * than the standard block counters, which can affect higher-level success criteria. Leave this
     * flag {@code false} for ordinary single-block fetches that should not gate overall success.
     * The change is local to the configuration and takes effect when the fetcher is constructed. It
     * does not alter retry limits or other fetch context settings.
     *
     * @param value {@code true} to treat the block as essential for completion criteria
     * @return this configuration instance so callers can continue fluent updates
     */
    public Cfg essential(boolean value) {
      this.isEssential = value;
      return this;
    }

    /**
     * Controls whether the constructor updates parent counters and notifies clients.
     *
     * <p>When set to {@code true}, the constructor does not increment block counters and does not
     * notify listeners, allowing the caller to integrate the fetcher into existing accounting
     * flows. When {@code false}, the constructor performs the usual add/notify side effects. The
     * setting only affects construction-time bookkeeping and does not change retry handling or
     * decoding.
     *
     * @param value {@code true} to suppress parent add/notify side effects on construction
     * @return this configuration instance so additional options can be chained
     */
    public Cfg dontAdd(boolean value) {
      this.dontAdd = value;
      return this;
    }

    /**
     * Requests deletion of the associated fetch context after completion.
     *
     * <p>When enabled, the parent request may delete the fetch context once the fetch reaches a
     * terminal state, reducing retained state for short-lived requests. Disable this option if the
     * context must remain available for later operations that share the same settings. The flag
     * only affects cleanup after completion and does not change fetch behavior while active.
     *
     * @param value {@code true} to delete the fetch context after terminal completion
     * @return this configuration instance so additional options can be chained
     */
    public Cfg deleteFetchContext(boolean value) {
      this.deleteFetchContext = value;
      return this;
    }

    /**
     * Sets whether the fetch should use the real-time scheduling lane.
     *
     * <p>Real-time scheduling prioritizes latency-sensitive requests at the cost of throughput. Use
     * {@code true} for interactive user requests and {@code false} for background or bulk work. The
     * value is captured on construction and supplied to the base scheduler registration. It does
     * not modify fetch context limits or key decoding behavior.
     *
     * @param value {@code true} for real-time schedulers; {@code false} for bulk scheduling
     * @return this configuration instance so additional options can be chained
     */
    public Cfg realTime(boolean value) {
      this.realTimeFlag = value;
      return this;
    }

    /**
     * Overrides the priority class used by this fetcher.
     *
     * <p>Supplying a provider allows the caller to supply a priority class that may differ from the
     * parent requester, while still deferring computation to a lightweight callback. If {@code
     * null} is provided, the fetcher falls back to the parent’s priority value. The provider is
     * consulted whenever the fetcher reports its current scheduling priority.
     *
     * @param provider priority provider used for scheduling decisions, or {@code null}
     * @return this configuration instance so additional options can be chained
     */
    public Cfg priorityClassProvider(PriorityClassProvider provider) {
      this.priorityClassProvider = provider;
      return this;
    }

    /**
     * Overrides key listener creation for this fetcher.
     *
     * <p>When supplied, the factory is invoked to create the key listener used by schedulers to
     * match and dispatch keys. This enables callers to inject cancellation checks or custom
     * listener selection without subclassing. Passing {@code null} restores the default listener
     * behavior from {@link BaseSingleFileFetcher}. The factory is called on demand when schedulers
     * request a listener, not during configuration.
     *
     * @param factory key listener factory to use, or {@code null} for default behavior
     * @return this configuration instance so additional options can be chained
     */
    public Cfg keyListenerFactory(KeyListenerFactory factory) {
      this.keyListenerFactory = factory;
      return this;
    }
  }
}

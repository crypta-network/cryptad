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
 * <p>This type is used directly for trivial single-block GETs and also serves as the base for
 * higher-level helpers such as {@link SingleFileFetcher}. It wires common mechanics implemented by
 * {@link BaseSingleFileFetcher} — request registration, cooldown/retry handling, and delegation to
 * subclass hooks — with a compact surface area focused on the final delivery of a decoded {@link
 * FetchResult}. Typical usage is to construct an instance with a {@link Cfg} and then call {@link
 * #schedule(ClientContext)} (inherited) to participate in the client request schedulers.
 *
 * <p>Lifecycle and invariants:
 *
 * <ul>
 *   <li>Each instance represents one logical block fetch. It becomes <em>finished</em> after a
 *       terminal success or failure and will not emit further callbacks.
 *   <li>Cancellation ends scheduling and results in a failure callback with mode {@link
 *       FetchException.FetchExceptionMode#CANCELLED}.
 *   <li>When the owning request is persistent, this object is serialized and later resumed; the
 *       completion callback is part of the serialized state.
 * </ul>
 *
 * <p>Thread-safety: instances are mutable and synchronize narrowly on {@code this} for state flags
 * such as {@code finished} and {@code cancelled}. Callers should not assume broader thread-safety.
 *
 * @see BaseSingleFileFetcher
 * @see ClientRequester
 * @see ClientContext
 * @see FetchContext
 */
public class SimpleSingleFileFetcher extends BaseSingleFileFetcher
    implements ClientGetState, Serializable {

  private static final Logger LOG = LoggerFactory.getLogger(SimpleSingleFileFetcher.class);

  @Serial private static final long serialVersionUID = 1L;

  SimpleSingleFileFetcher(Cfg cfg) {
    super(cfg.key, cfg.maxRetries, cfg.ctx, cfg.parent, cfg.deleteFetchContext, cfg.realTimeFlag);
    this.rcb = cfg.rcb;
    this.token = cfg.token;
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

  // No static initialization required.

  // Translate it, then call the real onFailure
  @Override
  public void onFailure(
      LowLevelGetException e, SendableRequestItem reqTokenIgnored, ClientContext context) {
    onFailure(translateException(e), false, context);
  }

  /**
   * Handles a mapped client-level failure for this fetch.
   *
   * <p>The method translates cancellation state, applies retry/cooldown policy when the failure is
   * non-fatal, and emits the appropriate callback. When the outcome is terminal, the request is
   * unregistered and the parent counters are updated. This method is idempotent with respect to a
   * finished or cancelled fetch.
   *
   * @param e client-level failure describing the reason for the error; never {@code null}
   * @param forceFatal when {@code true}, treats the error as terminal regardless of retry policy
   * @param context client runtime context used to access schedulers and factories; never {@code
   *     null}
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
   * Delivers a successful decode to the completion callback.
   *
   * <p>If the owning request has been cancelled meanwhile, the provided data is released and a
   * cancellation failure is reported instead. On success, the method wraps the bucket inside a
   * {@link SingleFileStreamGenerator} for streaming to the client.
   *
   * @param data decoded result including metadata and data bucket; never {@code null}
   * @param context client runtime context used for resource management; never {@code null}
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
   * Extracts the data bucket from a verified {@link ClientKeyBlock}.
   *
   * <p>On decode errors or I/O conditions, this method reports the appropriate failure via {@link
   * #onFailure(FetchException, boolean, ClientContext)} and returns {@code null}. The caller should
   * treat a {@code null} return as a terminal path for this attempt.
   *
   * @param block verified client key block obtained from the network or a local store; never {@code
   *     null}
   * @param context client runtime context providing factories and schedulers; never {@code null}
   * @return the decoded {@link Bucket} when successful; {@code null} when a failure was reported
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
    } catch (InsufficientDiskSpaceException e) {
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
   * <p>The value originates from the {@link Cfg} used at construction time and can be used by
   * callers to correlate callbacks with external bookkeeping.
   *
   * @return the creator-supplied token value; no semantics are attached by this class
   */
  @Override
  public long getToken() {
    return token;
  }

  /** {@inheritDoc} */
  @Override
  public void cancel(ClientContext context) {
    super.cancel(context);
    rcb.onFailure(new FetchException(FetchExceptionMode.CANCELLED), this, context);
  }

  /** {@inheritDoc} */
  @Override
  protected void notFoundInStore(ClientContext context) {
    this.onFailure(new FetchException(FetchExceptionMode.DATA_NOT_FOUND), true, context);
  }

  /** {@inheritDoc} */
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

  /** {@inheritDoc} */
  @Override
  public void onShutdown(ClientContext context) {
    // Do nothing.
  }

  /** {@inheritDoc} */
  @Override
  protected ClientGetState getClientGetState() {
    return this;
  }

  /**
   * Builder-style configuration used to construct a {@link SimpleSingleFileFetcher}.
   *
   * <p>The configuration collects all constructor inputs to avoid long parameter lists. Instances
   * are created via {@link #create(ClientKey, int, FetchContext, ClientRequester,
   * GetCompletionCallback, long, ClientContext)} and can be refined through fluent setters before
   * being passed to the constructor.
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
     * @param key client key identifying the block to fetch; must not be {@code null}
     * @param maxRetries maximum number of retry attempts; use {@code -1} for unlimited retries
     * @param ctx fetch context carrying limits, cooldown policy, and preferences; must not be
     *     {@code null}
     * @param parent owning requester used for accounting and notifications; must not be {@code
     *     null}
     * @param rcb completion callback to receive results and progress; for persistent requests the
     *     implementation must be {@link Serializable}
     * @param token opaque token associated with this fetch; returned by {@link #getToken()}
     * @param context client runtime context used for scheduling and factories; must not be {@code
     *     null}
     * @return a new configuration instance ready to be refined via fluent setters
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
     * @param value when {@code true}, the parent increments “must succeed” counters; otherwise a
     *     regular block is added
     * @return this configuration instance for chaining
     */
    public Cfg essential(boolean value) {
      this.isEssential = value;
      return this;
    }

    /**
     * Controls whether the constructor updates the parent’s block counters and notifies clients.
     *
     * @param value when {@code true}, suppresses the add/notify side effects during construction
     * @return this configuration instance for chaining
     */
    public Cfg dontAdd(boolean value) {
      this.dontAdd = value;
      return this;
    }

    /**
     * Requests deletion of the associated fetch context after the request completes.
     *
     * @param value when {@code true}, the fetch context is deleted on terminal completion
     * @return this configuration instance for chaining
     */
    public Cfg deleteFetchContext(boolean value) {
      this.deleteFetchContext = value;
      return this;
    }

    /**
     * Sets whether the fetch should use the real-time scheduling lane.
     *
     * @param value {@code true} to use the real-time schedulers; {@code false} for the bulk lane
     * @return this configuration instance for chaining
     */
    public Cfg realTime(boolean value) {
      this.realTimeFlag = value;
      return this;
    }
  }
}

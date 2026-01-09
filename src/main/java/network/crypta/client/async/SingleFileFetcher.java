package network.crypta.client.async;

import java.io.BufferedInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.io.Serial;
import java.io.Serializable;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import network.crypta.client.ArchiveContext;
import network.crypta.client.ArchiveExtractCallback;
import network.crypta.client.ArchiveFailureException;
import network.crypta.client.ArchiveHandler;
import network.crypta.client.ArchiveManager;
import network.crypta.client.ArchiveRestartException;
import network.crypta.client.ClientMetadata;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.FetchResult;
import network.crypta.client.InsertContext.CompatibilityMode;
import network.crypta.client.Metadata;
import network.crypta.client.MetadataParseException;
import network.crypta.crypt.HashResult;
import network.crypta.crypt.MultiHashInputStream;
import network.crypta.keys.BaseClientKey;
import network.crypta.keys.ClientCHK;
import network.crypta.keys.ClientKey;
import network.crypta.keys.ClientKeyBlock;
import network.crypta.keys.ClientSSK;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.KeyDecodeException;
import network.crypta.keys.TooBigException;
import network.crypta.keys.USK;
import network.crypta.node.LowLevelGetException;
import network.crypta.node.SendableGet;
import network.crypta.node.SendableRequestItem;
import network.crypta.support.api.Bucket;
import network.crypta.support.compress.Compressor;
import network.crypta.support.compress.Compressor.COMPRESSOR_TYPE;
import network.crypta.support.compress.DecompressorThreadManager;
import network.crypta.support.io.BucketTools;
import network.crypta.support.io.InsufficientDiskSpaceException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Performs single-file fetches including redirects, manifests, splitfiles, and archive entries.
 *
 * <p>This state object drives the full life cycle of fetching a single logical file from the
 * network. It decodes the first retrieved block, parses {@link Metadata}, follows any redirects or
 * manifests, and transitions to other states (for example {@link SplitFileFetcher}) when the
 * content is a splitfile. When the target is inside a container, it cooperates with an {@link
 * ArchiveHandler} to read metadata or extract data. Callers typically construct a SingleFileFetcher
 * from a {@link ClientGetter} or via {@link #create(ClientRequester, GetCompletionCallback,
 * FreenetURI, FetchContext, ArchiveContext, CreationPolicy, CreationRuntime)} and then schedule it.
 *
 * <p>State and invariants: instances are created for one logical request; after a terminal callback
 * (success or failure) the instance is considered finished. The object is not intended to be reused
 * or shared across concurrent fetches. Some fields are persisted for long‑lived requests; changing
 * non‑transient members of serializable classes can cause restarts of queued work.
 *
 * <p>Concurrency: callbacks can execute on worker threads, and archive extraction may use helper
 * threads. The class coordinates transitions carefully, but callers should treat it as not
 * thread‑safe beyond the documented callback contract.
 *
 * <ul>
 *   <li>Parses and interprets metadata, including simple and archive manifests.
 *   <li>Follows internal/external redirects and enforces path component limits.
 *   <li>Builds a decompressor chain when the target is compressed.
 *   <li>Streams large files through buckets to avoid excessive memory overhead.
 * </ul>
 *
 * <p>WARNING: Changing non-transient members on classes that are Serializable can result in
 * restarting downloads or losing uploads.
 *
 * @author toad
 * @see ClientGetter
 * @see SplitFileFetcher
 * @see ArchiveManager
 * @see Metadata
 * @see FetchResult
 */
public class SingleFileFetcher extends BaseSingleFileFetcher implements ClientGetState {
  private static final Logger LOG = LoggerFactory.getLogger(SingleFileFetcher.class);
  private static final String LOG_META_LABEL = " meta=";
  private static final String LOG_FOR_LABEL = " for ";
  private static final String LOG_RETURNING_DATA = "Returning data";

  @Serial private static final long serialVersionUID = 1L;

  /** Original URI */
  final FreenetURI uri;

  /** Meta-strings. (Path elements that aren't part of a key type) */
  private final List<String> metaStrings;

  /**
   * Number of metaStrings which were added by redirects etc. They are added to the start, so this
   * is decremented when we consume one.
   */
  private int addedMetaStrings;

  /**
   * Client-provided or derived metadata associated with the current fetch. Carries MIME type and
   * other hints that are forwarded to callbacks and used for policy checks.
   */
  final ClientMetadata clientMetadata;

  /**
   * Working metadata for the current step. It may be a manifest, redirect, or splitfile descriptor
   * depending on progress through the state machine.
   */
  private Metadata metadata;

  /**
   * Metadata for the enclosing archive when the requested item lives inside a container. Populated
   * when entering archive flows so subsequent steps can proceed without re-fetching.
   */
  private Metadata archiveMetadata;

  /**
   * Archive processing context (loop detection, handler configuration) shared across archive steps
   * in the current request.
   */
  final ArchiveContext actx;

  /** Archive handler. We can only have one archive handler at a time. */
  private transient ArchiveHandler ah;

  /**
   * Guard against unbounded traversal through redirects/containers. Each transition increases the
   * recursion level and failures occur once the configured maximum is exceeded.
   */
  private final int recursionLevel;

  /** The URI of the currently-being-processed data, for archives etc. */
  private FreenetURI thisKey;

  /**
   * Stack of decompressors to apply to the eventual data stream. Elements are appended as metadata
   * indicates compression layers and consumed when streaming to the client.
   */
  private final LinkedList<COMPRESSOR_TYPE> decompressors;

  /**
   * When {@code true}, suppresses certain notifications to {@code ClientGet} during transitions to
   * keep higher-level progress reporting stable.
   */
  private final boolean dontTellClientGet;

  /**
   * If true, success/failure is immediately reported to the client, and therefore we can check
   * TOO_MANY_PATH_COMPONENTS.
   */
  private final boolean isFinal;

  private final transient SnoopMetadata metaSnoop;
  private final transient SnoopBucket bucketSnoop;

  /**
   * Bundle of constructor inputs for {@link SingleFileFetcher}.
   *
   * <p>Callers should populate the required fields directly before constructing a new fetcher. This
   * type mirrors the {@code InitParams} pattern used across the async fetch classes to avoid
   * excessively long parameter lists.
   */
  public static final class InitParams {
    ClientRequester parent;
    GetCompletionCallback cb;
    ClientMetadata metadata;
    ClientKey key;
    List<String> metaStrings;
    FreenetURI origURI;
    int addedMetaStrings;
    FetchContext ctx;
    boolean deleteFetchContext;
    ArchiveContext actx;
    ArchiveHandler ah;
    Metadata archiveMetadata;
    CreationPolicy policy;
    CreationRuntime runtime;
    boolean topDontCompress;
    short topCompatibilityMode;
  }

  /**
   * Create a new SingleFileFetcher and register self. Called when following a redirect, or direct
   * from ClientGet. Note: Many times when this is called internally we might be better off using a
   * copy constructor?
   *
   * @param params initialization bundle containing request inputs, policy, and runtime values
   * @throws FetchException if recursion limits are exceeded or policy checks fail during setup
   */
  public SingleFileFetcher(InitParams params) throws FetchException {
    super(
        params.key,
        params.policy.maxRetries,
        params.ctx,
        params.parent,
        params.deleteFetchContext,
        params.runtime.realTimeFlag);
    // Completion callback + token as used by SimpleSingleFileFetcher
    this.rcb = params.cb;
    this.token = params.runtime.token;
    // Mirror SimpleSingleFileFetcher constructor side effects (dontAdd == false)
    if (params.policy.isEssential) params.parent.addMustSucceedBlocks(1);
    else params.parent.addBlock();
    params.parent.notifyClients(params.runtime.context);
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Creating SingleFileFetcher"
              + LOG_FOR_LABEL
              + "{} from {}"
              + LOG_META_LABEL
              + "{} persistent={}",
          params.key,
          params.origURI,
          params.metaStrings.toString(),
          persistent,
          new Exception("debug"));
    this.isFinal = params.policy.isFinal;
    this.cancelled = false;
    this.dontTellClientGet = params.policy.dontTellClientGet;
    // Archive handler
    this.ah = selectArchiveHandler(params.ah);
    this.archiveMetadata = params.archiveMetadata;

    // Meta strings
    this.metaStrings = prepareMetaStrings(params.metaStrings);
    this.addedMetaStrings = params.addedMetaStrings;
    if (LOG.isDebugEnabled()) LOG.debug("Metadata: {}", params.metadata);
    this.clientMetadata =
        (params.metadata != null ? ClientMetadata.copyOf(params.metadata) : new ClientMetadata());
    thisKey = params.policy.hasInitialMetadata ? FreenetURI.EMPTY_CHK_URI : params.key.getURI();
    if (params.origURI == null) throw new NullPointerException();
    this.uri = persistent ? new FreenetURI(params.origURI) : params.origURI;
    this.actx = params.actx;
    this.recursionLevel = params.policy.recursionLevel + 1;
    if (params.policy.recursionLevel > params.ctx.getMaxRecursionLevel())
      throw new FetchException(
          FetchExceptionMode.TOO_MUCH_RECURSION,
          "Too much recursion: "
              + params.policy.recursionLevel
              + " > "
              + params.ctx.getMaxRecursionLevel());
    this.decompressors = new LinkedList<>();
    this.topDontCompress = params.topDontCompress;
    this.topCompatibilityMode = params.topCompatibilityMode;
    metaSnoop = metaSnoopFrom(params.parent);
    bucketSnoop = bucketSnoopFrom(params.parent);
  }

  private ArchiveHandler selectArchiveHandler(ArchiveHandler handler) {
    return (persistent && handler != null) ? handler.cloneHandler() : handler;
  }

  private List<String> prepareMetaStrings(List<String> strings) {
    // Always copy if persistent
    return (strings instanceof ArrayList && !persistent) ? strings : new ArrayList<>(strings);
  }

  // this.uri is final and must be assigned in the constructor

  private static SnoopMetadata metaSnoopFrom(ClientRequester parent) {
    return (parent instanceof ClientGetter getter) ? getter.getMetaSnoop() : null;
  }

  private static SnoopBucket bucketSnoopFrom(ClientRequester parent) {
    return (parent instanceof ClientGetter getter) ? getter.getBucketSnoop() : null;
  }

  private static FetchException wrapToFetchException(Exception e) {
    if (e instanceof ArchiveFailureException afe) {
      return new FetchException(afe);
    }
    if (e instanceof ArchiveRestartException are) {
      return new FetchException(are);
    }
    if (e instanceof MetadataParseException mpe) {
      return new FetchException(mpe);
    }
    // Fallback: should not happen for declared multi-catch types
    return new FetchException(FetchExceptionMode.INTERNAL_ERROR, e);
  }

  // Methods required after switching to BaseSingleFileFetcher
  @Override
  public void onFailure(
      LowLevelGetException e, SendableRequestItem reqTokenIgnored, ClientContext context) {
    onFailure(SendableGet.translateException(e), false, context);
  }

  /**
   * Handle a failure from this state, deciding whether to retry or surface the error.
   *
   * <p>When {@code forceFatal} is {@code true} or the exception is inherently fatal, the request is
   * finalized and the completion callback is notified. Otherwise, a retry is attempted subject to
   * the configured policy. If the parent has already been canceled, the error is converted to
   * {@link FetchExceptionMode#CANCELLED} and treated as fatal.
   *
   * @param e the failure that occurred while processing this state
   * @param forceFatal set to {@code true} to bypass retry and finalize immediately
   * @param context client context for unregistering and scheduling follow‑up work
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
    unregisterAll(context);
    synchronized (this) {
      finished = true;
    }
    if (e.isFatal() || forceFatal) parent.fatallyFailedBlock(context);
    else parent.failedBlock(context);
    rcb.onFailure(e, this, context);
  }

  @Override
  public long getToken() {
    return token;
  }

  @Override
  public void cancel(ClientContext context) {
    super.cancel(context);
    rcb.onFailure(new FetchException(FetchExceptionMode.CANCELLED), this, context);
  }

  @Override
  protected void notFoundInStore(ClientContext context) {
    this.onFailure(new FetchException(FetchExceptionMode.DATA_NOT_FOUND), true, context);
  }

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

  @Override
  public void onShutdown(ClientContext context) {
    // Do nothing.
  }

  @Override
  protected ClientGetState getClientGetState() {
    return this;
  }

  /**
   * Decode the provided client key block into a {@link Bucket} for downstream processing.
   *
   * <p>The returned bucket contains either plaintext data or metadata depending on the block type.
   * If any decode or resource error occurs, this method reports the failure via {@link
   * #onFailure(FetchException, boolean, ClientContext)} and returns {@code null}. Callers must free
   * the bucket when no longer needed.
   *
   * @param block the decoded block from the network; must not be {@code null}
   * @param context client context providing factories and disk limits; must not be {@code null}
   * @return a newly allocated bucket with the decoded contents, or {@code null} on failure
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
   * Copy constructor for continuing processing with a different metadata focus. Do not call {@code
   * schedule()} on the original instance after creating a copy.
   *
   * <p>This form is used for scenarios such as handling multi‑level metadata where the data has
   * already been obtained but needs to be interpreted in a separate state object. The new fetcher
   * intentionally does not duplicate transient state like path components.
   *
   * @param fetcher the original fetcher whose state seeds this instance; must not be {@code null}
   * @param persistent whether this instance should persist across restarts like the parent
   * @param deleteFetchContext whether to delete the fetch context after completion
   * @param newMeta metadata to process as the starting point of this copy
   * @param callback completion callback that receives results and failures
   * @param ctx2 fetch context to use for resource limits and policy decisions
   * @throws FetchException if recursion limits are exceeded or setup fails for policy reasons
   */
  public SingleFileFetcher(
      SingleFileFetcher fetcher,
      boolean persistent,
      boolean deleteFetchContext,
      Metadata newMeta,
      GetCompletionCallback callback,
      FetchContext ctx2)
      throws FetchException {
    // Don't add a block, we have already fetched the data, we are just handling the metadata in a
    // different fetcher.
    super(
        persistent ? fetcher.key.cloneKey() : fetcher.key,
        fetcher.maxRetries,
        ctx2,
        fetcher.parent,
        deleteFetchContext,
        fetcher.realTimeFlag);
    this.rcb = callback;
    this.token = fetcher.token;
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Creating SingleFileFetcher" + LOG_FOR_LABEL + "{}" + LOG_META_LABEL + "{}",
          fetcher.key,
          fetcher.metaStrings.toString(),
          new Exception("debug"));
    // We expect significant further processing in the parent
    this.isFinal = false;
    this.dontTellClientGet = fetcher.dontTellClientGet;
    this.actx = fetcher.actx;
    this.ah = fetcher.ah;
    if (persistent && ah != null) ah = ah.cloneHandler();
    this.archiveMetadata = null;
    this.clientMetadata =
        (fetcher.clientMetadata != null
            ? ClientMetadata.copyOf(fetcher.clientMetadata)
            : new ClientMetadata());
    this.metadata = newMeta;
    this.metaStrings = new ArrayList<>();
    this.addedMetaStrings = 0;
    this.recursionLevel = fetcher.recursionLevel + 1;
    if (recursionLevel > ctx.getMaxRecursionLevel())
      throw new FetchException(FetchExceptionMode.TOO_MUCH_RECURSION);
    this.thisKey = fetcher.thisKey;
    // Do not copy the decompressors. Whether the metadata/container is compressed
    // is independent of whether the final data is; when we find the data we will
    // call back into the original fetcher.
    this.decompressors = new LinkedList<>();
    if (fetcher.uri == null) throw new NullPointerException();
    this.uri = persistent ? new FreenetURI(fetcher.uri) : fetcher.uri;
    this.metaSnoop = fetcher.metaSnoop;
    this.bucketSnoop = fetcher.bucketSnoop;
    this.topDontCompress = fetcher.topDontCompress;
    this.topCompatibilityMode = fetcher.topCompatibilityMode;
  }

  // Completion callback + token (needed now that we don't extend SimpleSingleFileFetcher)
  /** Completion callback used to surface success, failure, and progress to the requester. */
  @SuppressWarnings("java:S1948")
  final GetCompletionCallback rcb;

  /**
   * Opaque token supplied by the caller and echoed in callbacks so clients can correlate events
   * with higher‑level requests or UI elements.
   */
  final long token;

  // Process the completed data. May result in us going to a
  // splitfile, or another SingleFileFetcher, etc.
  @Override
  public void onSuccess(
      ClientKeyBlock block, boolean fromStore, Object token, ClientContext context) {
    if (parent instanceof ClientGetter getter) getter.addKeyToBinaryBlob(block, context);
    parent.completedBlock(fromStore, context);
    // Extract data

    if (block == null) {
      LOG.error("block is null! fromStore={}, token={}", fromStore, token, new Exception("error"));
      return;
    }
    Bucket data = extract(block, context);
    if (key instanceof ClientSSK) {
      context.uskManager.checkUSK(uri, persistent, data != null && !block.isMetadata());
    }
    if (data == null) {
      if (LOG.isDebugEnabled()) LOG.debug("No data");
      // Already failed: if extract returns null it will call onFailure first.
      return;
    }
    if (LOG.isDebugEnabled())
      LOG.debug("Block {} on {}", (block.isMetadata() ? "is metadata" : "is not metadata"), this);

    if (bucketSnoop != null && bucketSnoop.snoopBucket(data, block.isMetadata(), context)) {
      cancel(context);
      data.free();
      return;
    }

    if (!block.isMetadata()) {
      onSuccess(new FetchResult(clientMetadata, data), context);
    } else {
      handleMetadata(data, context);
    }
  }

  // Package-local so that ClientGetter can call it instead of schedule().
  void startWithMetadata(Bucket data, ClientContext context) {
    parent.completedBlock(true, context);
    handleMetadata(data, context);
  }

  private void handleMetadata(Bucket data, ClientContext context) {
    if (!ctx.getFollowRedirects()) {
      onFailure(
          new FetchException(
              FetchExceptionMode.INVALID_METADATA,
              "Told me not to follow redirects (splitfile block??)"),
          false,
          context);
      data.free();
      return;
    }
    if (parent.isCancelled()) {
      onFailure(new FetchException(FetchExceptionMode.CANCELLED), false, context);
      data.free();
      return;
    }
    if (data.size() > ctx.getMaxMetadataSize()) {
      onFailure(new FetchException(FetchExceptionMode.TOO_BIG_METADATA), false, context);
      data.free();
      return;
    }
    // Parse metadata
    try {
      metadata = Metadata.construct(data);
      data.free();
      data = null;
      innerWrapHandleMetadata(false, context);
    } catch (MetadataParseException | EOFException e) {
      // EOFException is also a metadata error
      onFailure(new FetchException(FetchExceptionMode.INVALID_METADATA, e), false, context);
    } catch (InsufficientDiskSpaceException _) {
      onFailure(new FetchException(FetchExceptionMode.NOT_ENOUGH_DISK_SPACE), false, context);
    } catch (IOException e) {
      // Bucket error?
      onFailure(new FetchException(FetchExceptionMode.BUCKET_ERROR, e), false, context);
    } finally {
      if (data != null) data.free();
    }
  }

  /**
   * Finalize a successful fetch by enforcing policy and delivering the data to the callback.
   *
   * <p>This method validates path component rules and size limits, converts any violations into a
   * {@link FetchException}, and otherwise streams the data to the requester. The underlying bucket
   * is always closed by this method regardless of outcome to prevent resource leaks.
   *
   * @param result the completed result bundle containing client metadata and a data bucket
   * @param context client context used for scheduling and follow‑up transitions
   */
  protected void onSuccess(final FetchResult result, final ClientContext context) {
    synchronized (this) {
      // So a SingleKeyListener isn't created.
      finished = true;
    }
    if (parent.isCancelled()) {
      if (LOG.isDebugEnabled()) LOG.debug("Parent is cancelled");
      closeResultBucket(result);
      onFailure(new FetchException(FetchExceptionMode.CANCELLED), false, context);
      return;
    }
    if (isTooManyPathComponentsFinal()) {
      handleTooManyPathComponentsResult(result, context);
      closeResultBucket(result);
      return;
    }
    if (isResultTooBig(result)) {
      failTooBig(result, context);
      closeResultBucket(result);
      return;
    }
    copyToJobRunnerAndFree(result, context);
  }

  private boolean isTooManyPathComponentsFinal() {
    return (!ctx.ignoreTooManyPathComponents) && (!metaStrings.isEmpty()) && isFinal;
  }

  private void handleTooManyPathComponentsResult(FetchResult result, ClientContext context) {
    if (addedMetaStrings > 0) {
      rcb.onFailure(
          new FetchException(
              FetchExceptionMode.INVALID_METADATA,
              "Invalid metadata: too many path components in redirects",
              thisKey),
          this,
          context);
      return;
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Too many path components:" + LOG_FOR_LABEL + "{}" + LOG_META_LABEL + "{}",
          uri,
          metaStrings);
    }
    FreenetURI tryURI = uri.dropLastMetaStrings(metaStrings.size());
    rcb.onFailure(
        new FetchException(
            FetchExceptionMode.TOO_MANY_PATH_COMPONENTS,
            result.size(),
            (rcb == parent),
            result.getMimeType(),
            tryURI),
        this,
        context);
  }

  private boolean isResultTooBig(FetchResult result) {
    return result.size() > ctx.getMaxOutputLength();
  }

  private void failTooBig(FetchResult result, ClientContext context) {
    rcb.onFailure(
        new FetchException(
            FetchExceptionMode.TOO_BIG, result.size(), (rcb == parent), result.getMimeType()),
        this,
        context);
  }

  private void copyToJobRunnerAndFree(FetchResult result, ClientContext context) {
    // Break locks, don't run filtering on FEC thread etc.
    // Create a defensive copy of the bucket to prevent "Already freed" race condition
    Bucket originalBucket = result.asBucket();
    Bucket bucketCopy;
    try {
      bucketCopy = context.getBucketFactory(persistent()).makeBucket(originalBucket.size());
      BucketTools.copy(originalBucket, bucketCopy);
    } catch (IOException e) {
      LOG.error("Failed to create defensive copy of bucket: {}", e, e);
      originalBucket.free();
      rcb.onFailure(
          new FetchException(FetchExceptionMode.BUCKET_ERROR, "Failed to copy bucket", e),
          this,
          context);
      return;
    }

    context
        .getJobRunner(persistent())
        .queueInternal(
            context1 -> {
              rcb.onSuccess(
                  new SingleFileStreamGenerator(bucketCopy, persistent),
                  result.getMetadata(),
                  decompressors,
                  SingleFileFetcher.this,
                  context1);
              return true;
            });

    // Free the original bucket now that we have a copy
    originalBucket.free();
  }

  private void closeResultBucket(FetchResult result) {
    try (Bucket b = result.asBucket()) {
      if (LOG.isDebugEnabled()) LOG.debug("Discarding result bucket {}", b.getName());
      // Explicitly free to satisfy tests that verify free() is invoked on the bucket
      b.free();
    }
  }

  private ClientGetWorkerThread makeAndStartWorker(
      InputStream input, OutputStream output, ClientContext context) {
    try {
      ClientGetWorkerThread worker =
          new ClientGetWorkerThread(
              new BufferedInputStream(input),
              output,
              null,
              null,
              new ClientGetWorkerThread.Options(
                  null,
                  ctx.getSchemeHostAndPort(),
                  false,
                  null,
                  null,
                  null,
                  context.linkFilterExceptionProvider));
      worker.start();
      return worker;
    } catch (URISyntaxException e) {
      throw new IllegalArgumentException(e);
    }
  }

  /**
   * Whether the top layer of a splitfile should avoid compression when reassembled. Propagated to
   * the client when the top block provides this hint.
   */
  private boolean topDontCompress;

  /**
   * Compatibility mode derived from the top block, used to negotiate splitfile decoding details
   * between writer and reader.
   */
  private short topCompatibilityMode;

  /**
   * Handle the current metadata. I.e. do something with it: transition to a splitfile, look up a
   * manifest, etc. LOCKING: Synchronized as it changes so many variables; if we want to write the
   * structure to disk, we don't want this running at the same time. LOCKING: Therefore it should
   * not directly call e.g. onFailed, innerWrapHandleMetadata, other stuff that might cause lots of
   * stuff to happen on other objects, eventually ClientRequestScheduler gets locked -> deadlock.
   * This is irrelevant for persistent requests however, as they are single thread.
   *
   * @throws FetchException if policy or size checks fail, resources are insufficient, or decoding
   *     and I/O produce a non‑recoverable fetch error during planning.
   * @throws MetadataParseException if metadata bytes cannot be parsed into a valid structure.
   * @throws ArchiveFailureException if container access or extraction fails with a permanent,
   *     non‑retryable error.
   * @throws ArchiveRestartException if container processing requires a restart before continuing.
   */
  private synchronized void handleMetadata(final ClientContext context)
      throws FetchException,
          MetadataParseException,
          ArchiveFailureException,
          ArchiveRestartException {
    if (uri == null) {
      throw new NullPointerException("uri = null on SFI?? " + this);
    }
    synchronized (this) {
      if (cancelled) return;
      // So a SingleKeyListener isn't created.
      finished = true;
    }
    while (true) {
      if (snoopAndMaybeCancel(context)) return;
      handleTopDataAndHashesIfNoMetaStrings(context);
      StepDecision step = processNextMetadataStep(context);
      switch (step) {
        case RETURN -> {
          return;
        }
        case CONTINUE -> {
          // no-op, continue loop
        }
        case UNKNOWN -> {
          LOG.error("Don't know what to do with metadata: {}", metadata);
          throw new FetchException(FetchExceptionMode.UNKNOWN_METADATA);
        }
      }
    }
  }

  private boolean snoopAndMaybeCancel(ClientContext context) {
    if (metaSnoop != null && metaSnoop.snoopMetadata(metadata, context)) {
      cancel(context);
      return true;
    }
    return false;
  }

  private void handleTopDataAndHashesIfNoMetaStrings(ClientContext context) throws FetchException {
    if (!metaStrings.isEmpty()) return;
    if (metadata.hasTopData()) {
      if ((metadata.topSize > ctx.getMaxOutputLength())
          || (metadata.topCompressedSize > ctx.getMaxTempLength())) {
        if (metadata.isSimpleRedirect() || metadata.isSplitfile())
          clientMetadata.mergeNoOverwrite(metadata.getClientMetadata());
        throw new FetchException(
            FetchExceptionMode.TOO_BIG, metadata.topSize, true, clientMetadata.getMIMEType());
      }
      rcb.onExpectedTopSize(
          metadata.topSize,
          metadata.topCompressedSize,
          metadata.topBlocksRequired,
          metadata.topBlocksTotal,
          context);
      topCompatibilityMode = metadata.getTopCompatibilityCode();
      topDontCompress = metadata.getTopDontCompress();
    }
    HashResult[] hashes = metadata.getHashes();
    if (hashes != null) {
      rcb.onHashes(hashes, context);
    }
  }

  // Metadata kinds to dispatch on
  private enum MetaKind {
    SIMPLE_MANIFEST,
    ARCHIVE_MANIFEST,
    ARCHIVE_METADATA_REDIRECT,
    ARCHIVE_INTERNAL_REDIRECT,
    MULTI_LEVEL_METADATA,
    SINGLE_FILE_REDIRECT,
    SPLITFILE,
    UNKNOWN
  }

  private MetaKind detectMetaKind() {
    if (metadata.isSimpleManifest()) return MetaKind.SIMPLE_MANIFEST;
    if (metadata.isArchiveManifest()) return MetaKind.ARCHIVE_MANIFEST;
    if (metadata.isArchiveMetadataRedirect()) return MetaKind.ARCHIVE_METADATA_REDIRECT;
    if (metadata.isArchiveInternalRedirect()) return MetaKind.ARCHIVE_INTERNAL_REDIRECT;
    if (metadata.isMultiLevelMetadata()) return MetaKind.MULTI_LEVEL_METADATA;
    if (metadata.isSingleFileRedirect()) return MetaKind.SINGLE_FILE_REDIRECT;
    if (metadata.isSplitfile()) return MetaKind.SPLITFILE;
    return MetaKind.UNKNOWN;
  }

  private enum StepDecision {
    CONTINUE,
    RETURN,
    UNKNOWN
  }

  // Decide the next action: CONTINUE, RETURN, or UNKNOWN
  private StepDecision processNextMetadataStep(final ClientContext context)
      throws FetchException,
          MetadataParseException,
          ArchiveFailureException,
          ArchiveRestartException {
    MetaKind kind = detectMetaKind();
    if (kind == MetaKind.UNKNOWN) return StepDecision.UNKNOWN;
    if (isArchiveKind(kind)) return handleArchiveKind(kind, context);
    return handleOtherKind(kind, context);
  }

  private boolean isArchiveKind(MetaKind kind) {
    return kind == MetaKind.ARCHIVE_MANIFEST
        || kind == MetaKind.ARCHIVE_METADATA_REDIRECT
        || kind == MetaKind.ARCHIVE_INTERNAL_REDIRECT;
  }

  private StepDecision handleArchiveKind(MetaKind kind, ClientContext context)
      throws FetchException,
          MetadataParseException,
          ArchiveFailureException,
          ArchiveRestartException {
    return switch (kind) {
      case ARCHIVE_MANIFEST ->
          processArchiveManifestStep(context) ? StepDecision.RETURN : StepDecision.CONTINUE;
      case ARCHIVE_METADATA_REDIRECT ->
          processArchiveMetadataRedirectStep(context) ? StepDecision.RETURN : StepDecision.CONTINUE;
      case ARCHIVE_INTERNAL_REDIRECT -> {
        processArchiveInternalRedirectStep(context);
        yield StepDecision.RETURN;
      }
      default -> StepDecision.UNKNOWN;
    };
  }

  private StepDecision handleOtherKind(MetaKind kind, ClientContext context)
      throws FetchException, MetadataParseException {
    return switch (kind) {
      case SIMPLE_MANIFEST -> {
        processSimpleManifestStep();
        yield StepDecision.CONTINUE;
      }
      case MULTI_LEVEL_METADATA -> {
        processMultiLevelMetadataStep(context);
        yield StepDecision.RETURN;
      }
      case SINGLE_FILE_REDIRECT ->
          processSingleFileRedirectStep(context) ? StepDecision.RETURN : StepDecision.CONTINUE;
      case SPLITFILE -> processSplitfileStep(context) ? StepDecision.RETURN : StepDecision.CONTINUE;
      default -> StepDecision.UNKNOWN;
    };
  }

  private String removeMetaString() {
    String name = metaStrings.removeFirst();
    if (addedMetaStrings > 0) addedMetaStrings--;
    return name;
  }

  private void addDecompressor(COMPRESSOR_TYPE codec) {
    if (LOG.isDebugEnabled()) LOG.debug("Adding decompressor: {} on {}", codec, this);
    decompressors.add(codec);
  }

  // Returns true if this method should return to caller; false to continue outer loop
  private boolean processArchiveManifestStep(final ClientContext context)
      throws FetchException,
          ArchiveFailureException,
          ArchiveRestartException,
          MetadataParseException {
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Is archive manifest (type={} codec={})",
          metadata.getArchiveType(),
          metadata.getCompressionCodec());
    if (metaStrings.isEmpty() && ctx.getReturnZIPManifests()) {
      metadata.setSimpleRedirect();
      return false; // continue outer loop
    }
    ensureArchiveHandler(context);
    archiveMetadata = metadata;
    metadata = null;
    Bucket metadataBucket = ah.getMetadata(actx, context.archiveManager);
    return handleArchiveManifestBucketOrSchedule(metadataBucket, context);
  }

  private void ensureArchiveHandler(ClientContext context) throws ArchiveFailureException {
    if (ah == null || !ah.getKey().equals(thisKey)) {
      actx.doLoopDetection(thisKey);
      ah =
          context.archiveManager.makeHandler(
              thisKey,
              metadata.getArchiveType(),
              metadata.getCompressionCodec(),
              (parent instanceof ClientGetter cg && cg.collectingBinaryBlob()),
              persistent);
    }
  }

  private boolean handleArchiveManifestBucketOrSchedule(
      Bucket metadataBucket, ClientContext context) throws FetchException, MetadataParseException {
    if (metadataBucket != null) {
      try {
        metadata = Metadata.construct(metadataBucket);
      } catch (InsufficientDiskSpaceException _) {
        throw new FetchException(FetchExceptionMode.NOT_ENOUGH_DISK_SPACE);
      } catch (IOException e) {
        throw new FetchException(FetchExceptionMode.BUCKET_ERROR, e);
      } finally {
        metadataBucket.free();
      }
      return false;
    }
    final boolean persistentLocal = this.persistent;
    fetchArchive(
        false,
        archiveMetadata,
        ArchiveManager.METADATA_NAME,
        new ArchiveExtractCallback() {
          @Serial private static final long serialVersionUID = 1L;

          @Override
          public void gotBucket(Bucket data, ClientContext ctx1) {
            if (LOG.isDebugEnabled())
              LOG.debug("gotBucket on {} persistent={}", SingleFileFetcher.this, persistentLocal);
            try {
              metadata = Metadata.construct(data);
              innerWrapHandleMetadata(true, ctx1);
            } catch (MetadataParseException e) {
              onFailure(new FetchException(FetchExceptionMode.INVALID_METADATA, e), false, ctx1);
            } catch (IOException e) {
              onFailure(new FetchException(FetchExceptionMode.BUCKET_ERROR, e), false, ctx1);
            } finally {
              data.free();
            }
          }

          @Override
          public void notInArchive(ClientContext ctx1) {
            onFailure(
                new FetchException(
                    FetchExceptionMode.INTERNAL_ERROR,
                    "No metadata in container! Cannot happen as ArchiveManager should synthesise"
                        + " some!"),
                false,
                ctx1);
          }

          @Override
          public void onFailed(ArchiveRestartException e, ClientContext ctx1) {
            SingleFileFetcher.this.onFailure(new FetchException(e), false, ctx1);
          }

          @Override
          public void onFailed(ArchiveFailureException e, ClientContext ctx1) {
            SingleFileFetcher.this.onFailure(new FetchException(e), false, ctx1);
          }
        },
        context);
    return true;
  }

  private boolean processArchiveMetadataRedirectStep(final ClientContext context)
      throws FetchException {
    if (LOG.isDebugEnabled()) LOG.debug("Is archive-metadata");
    if (ah == null)
      throw new FetchException(
          FetchExceptionMode.UNKNOWN_METADATA, "Archive redirect not in an archive manifest");
    String filename = metadata.getArchiveInternalName();
    if (LOG.isDebugEnabled()) LOG.debug("Fetching {}", filename);
    Bucket dataBucket;
    try {
      dataBucket = ah.get(filename, actx, context.archiveManager);
    } catch (ArchiveFailureException | ArchiveRestartException | MetadataParseException e) {
      throw wrapToFetchException(e);
    }
    if (dataBucket != null) {
      handleArchiveMetadataBucket(dataBucket);
      return false;
    }
    scheduleFetchArchiveForMetadata(filename, context);
    return true;
  }

  private void handleArchiveMetadataBucket(Bucket dataBucket) throws FetchException {
    if (LOG.isDebugEnabled()) LOG.debug(LOG_RETURNING_DATA);
    try {
      Metadata newMetadata = Metadata.construct(dataBucket);
      synchronized (this) {
        metadata = newMetadata;
      }
    } catch (InsufficientDiskSpaceException _) {
      throw new FetchException(FetchExceptionMode.NOT_ENOUGH_DISK_SPACE);
    } catch (MetadataParseException e) {
      throw new FetchException(FetchExceptionMode.INVALID_METADATA, e);
    } catch (IOException _) {
      throw new FetchException(FetchExceptionMode.BUCKET_ERROR);
    } finally {
      dataBucket.free();
    }
  }

  private void scheduleFetchArchiveForMetadata(String filename, final ClientContext context)
      throws FetchException {
    if (LOG.isDebugEnabled()) LOG.debug("Fetching archive (thisKey={})", thisKey);
    fetchArchive(
        true,
        archiveMetadata,
        filename,
        new ArchiveExtractCallback() {
          @Serial private static final long serialVersionUID = 1L;

          @Override
          public void gotBucket(Bucket data, ClientContext ctx1) {
            if (LOG.isDebugEnabled()) LOG.debug(LOG_RETURNING_DATA);
            try {
              Metadata newMetadata = Metadata.construct(data);
              synchronized (SingleFileFetcher.this) {
                metadata = newMetadata;
              }
              innerWrapHandleMetadata(true, ctx1);
            } catch (IOException _) {
              onFailure(new FetchException(FetchExceptionMode.BUCKET_ERROR), false, ctx1);
            } catch (MetadataParseException _) {
              onFailure(new FetchException(FetchExceptionMode.INVALID_METADATA), false, ctx1);
            } finally {
              data.free();
            }
          }

          @Override
          public void notInArchive(ClientContext ctx1) {
            onFailure(new FetchException(FetchExceptionMode.NOT_IN_ARCHIVE), false, ctx1);
          }

          @Override
          public void onFailed(ArchiveRestartException e, ClientContext ctx1) {
            SingleFileFetcher.this.onFailure(new FetchException(e), false, ctx1);
          }

          @Override
          public void onFailed(ArchiveFailureException e, ClientContext ctx1) {
            SingleFileFetcher.this.onFailure(new FetchException(e), false, ctx1);
          }
        },
        context);
  }

  private void processArchiveInternalRedirectStep(final ClientContext context)
      throws FetchException {
    if (LOG.isDebugEnabled()) LOG.debug("Is archive-internal redirect");
    clientMetadata.mergeNoOverwrite(metadata.getClientMetadata());
    String mime = clientMetadata.getMIMEType();
    if (mime != null) rcb.onExpectedMIME(clientMetadata, context);
    validateAllowedMimeForArchiveInternal();
    if (ah == null)
      throw new FetchException(
          FetchExceptionMode.UNKNOWN_METADATA, "Archive redirect not in an archive manifest");
    String filename = metadata.getArchiveInternalName();
    if (LOG.isDebugEnabled()) LOG.debug("Fetching {}", filename);
    Bucket dataBucket;
    try {
      dataBucket = ah.get(filename, actx, context.archiveManager);
    } catch (ArchiveFailureException | ArchiveRestartException | MetadataParseException e) {
      throw wrapToFetchException(e);
    }
    if (dataBucket != null) {
      if (LOG.isDebugEnabled()) LOG.debug(LOG_RETURNING_DATA);
      final Bucket out = copyOrAdoptBucketForReturn(dataBucket, context);
      onSuccess(new FetchResult(clientMetadata, out), context);
      return; // returned data, method should return
    }
    if (LOG.isDebugEnabled()) LOG.debug("Fetching archive (thisKey={})", thisKey);
    fetchArchive(
        true,
        archiveMetadata,
        filename,
        new ArchiveExtractCallback() {
          @Serial private static final long serialVersionUID = 1L;

          @Override
          public void gotBucket(Bucket data, ClientContext ctx1) {
            if (LOG.isDebugEnabled()) LOG.debug(LOG_RETURNING_DATA);
            onSuccess(new FetchResult(clientMetadata, data), ctx1);
          }

          @Override
          public void notInArchive(ClientContext ctx1) {
            onFailure(new FetchException(FetchExceptionMode.NOT_IN_ARCHIVE), false, ctx1);
          }

          @Override
          public void onFailed(ArchiveRestartException e, ClientContext ctx1) {
            SingleFileFetcher.this.onFailure(new FetchException(e), false, ctx1);
          }

          @Override
          public void onFailed(ArchiveFailureException e, ClientContext ctx1) {
            SingleFileFetcher.this.onFailure(new FetchException(e), false, ctx1);
          }
        },
        context);
    // scheduled
  }

  private void validateAllowedMimeForArchiveInternal() throws FetchException {
    if (metaStrings.isEmpty()
        && isFinal
        && clientMetadata.getMIMETypeNoParams() != null
        && ctx.getAllowedMIMETypes() != null
        && !ctx.getAllowedMIMETypes().contains(clientMetadata.getMIMETypeNoParams())) {
      throw new FetchException(
          FetchExceptionMode.WRONG_MIME_TYPE, -1, false, clientMetadata.getMIMEType());
    }
  }

  private Bucket copyOrAdoptBucketForReturn(Bucket dataBucket, ClientContext context)
      throws FetchException {
    try {
      if (persistent) {
        Bucket out = context.persistentBucketFactory.makeBucket(dataBucket.size());
        BucketTools.copy(dataBucket, out);
        dataBucket.free();
        return out;
      } else {
        return dataBucket;
      }
    } catch (InsufficientDiskSpaceException _) {
      throw new FetchException(FetchExceptionMode.NOT_ENOUGH_DISK_SPACE);
    } catch (IOException _) {
      throw new FetchException(FetchExceptionMode.BUCKET_ERROR);
    }
  }

  private void processMultiLevelMetadataStep(final ClientContext context) throws FetchException {
    if (LOG.isDebugEnabled()) LOG.debug("Is multi-level metadata");
    metadata.setSimpleRedirect();
    final SingleFileFetcher f =
        new SingleFileFetcher(
            this, persistent, false, metadata, new MultiLevelMetadataCallback(), ctx);
    this.metadata = null;
    parent.onTransition(this, f, context);
    context
        .getJobRunner(persistent)
        .queueInternal(
            context1 -> {
              f.innerWrapHandleMetadata(true, context1);
              return true;
            });
    // continue outer loop
  }

  private boolean processSingleFileRedirectStep(final ClientContext context) throws FetchException {
    if (LOG.isDebugEnabled()) LOG.debug("Is single-file redirect");
    clientMetadata.mergeNoOverwrite(metadata.getClientMetadata());
    emitExpectedMimeIfPresent(context);
    String mimeType = clientMetadata.getMIMETypeNoParams();
    if (mimeType != null
        && ArchiveManager.ARCHIVE_TYPE.isUsableArchiveType(mimeType)
        && !metaStrings.isEmpty()) {
      metadata.setArchiveManifest();
      clientMetadata.clear();
      if (LOG.isDebugEnabled()) LOG.debug("Handling implicit container... (redirect)");
      return false; // continue loop
    }
    validateAllowedMimeForSingleRedirect(mimeType);
    FreenetURI newURI = metadata.getSingleTarget();
    if (LOG.isDebugEnabled()) LOG.debug("Redirecting to {}", newURI);
    ClientKey redirectedKey = resolveRedirectedKey(newURI);
    addNewMetaStringsFrom(newURI);
    final SingleFileFetcher f =
        new SingleFileFetcher(initParamsForRedirect(redirectedKey, clientMetadata, context));
    this.deleteFetchContext = false;
    if ((redirectedKey instanceof ClientCHK hK1) && !hK1.isMetadata()) {
      rcb.onBlockSetFinished(this, context);
      byte[] redirectedCryptoKey = hK1.getCryptoKey();
      if (key instanceof ClientCHK hK && !Arrays.equals(hK.getCryptoKey(), redirectedCryptoKey))
        redirectedCryptoKey = null;
      rcb.onSplitfileCompatibilityMode(
          metadata.getMinCompatMode(),
          metadata.getMaxCompatMode(),
          redirectedCryptoKey,
          !hK1.isCompressed(),
          true,
          true,
          context);
    }
    if (metadata.isCompressed()) {
      COMPRESSOR_TYPE codec = metadata.getCompressionCodec();
      f.addDecompressor(codec);
    }
    parent.onTransition(this, f, context);
    f.schedule(context);
    archiveMetadata = null;
    return true;
  }

  private void emitExpectedMimeIfPresent(ClientContext context) throws FetchException {
    if (clientMetadata != null && !clientMetadata.isTrivial()) {
      rcb.onExpectedMIME(clientMetadata, context);
      if (LOG.isDebugEnabled()) LOG.debug("MIME type is {}", clientMetadata);
    }
  }

  private void validateAllowedMimeForSingleRedirect(String mimeType) throws FetchException {
    if (metaStrings.isEmpty()
        && isFinal
        && mimeType != null
        && ctx.getAllowedMIMETypes() != null
        && !ctx.getAllowedMIMETypes().contains(mimeType)) {
      throw new FetchException(
          FetchExceptionMode.WRONG_MIME_TYPE, -1, false, clientMetadata.getMIMEType());
    }
  }

  private ClientKey resolveRedirectedKey(FreenetURI newURI) throws FetchException {
    try {
      BaseClientKey k = BaseClientKey.getBaseKey(newURI);
      if (k instanceof ClientKey clientKey) return clientKey;
      throw new FetchException(FetchExceptionMode.UNKNOWN_METADATA, "Redirect to a USK");
    } catch (MalformedURLException e) {
      throw new FetchException(FetchExceptionMode.INVALID_URI, e);
    }
  }

  private void addNewMetaStringsFrom(FreenetURI newURI) {
    List<String> newMetaStrings = newURI.listMetaStrings();
    while (!newMetaStrings.isEmpty()) {
      String o = newMetaStrings.removeLast();
      metaStrings.addFirst(o);
      addedMetaStrings++;
    }
  }

  private InitParams initParamsForRedirect(
      ClientKey redirectedKey, ClientMetadata metadataForRedirect, ClientContext context) {
    InitParams p = new InitParams();
    p.parent = parent;
    p.cb = rcb;
    p.metadata = metadataForRedirect;
    p.key = redirectedKey;
    p.metaStrings = metaStrings;
    p.origURI = this.uri;
    p.addedMetaStrings = addedMetaStrings;
    p.ctx = ctx;
    p.deleteFetchContext = deleteFetchContext;
    p.actx = actx;
    p.ah = ah;
    p.archiveMetadata = archiveMetadata;
    p.policy = new CreationPolicy(maxRetries, recursionLevel, false, true, isFinal, false);
    p.runtime = new CreationRuntime(context, realTimeFlag, token);
    p.topDontCompress = topDontCompress;
    p.topCompatibilityMode = topCompatibilityMode;
    return p;
  }

  private boolean processSplitfileStep(final ClientContext context)
      throws FetchException, MetadataParseException {
    if (LOG.isDebugEnabled()) LOG.debug("Fetching splitfile");
    clientMetadata.mergeNoOverwrite(metadata.getClientMetadata());
    String mimeType = clientMetadata.getMIMETypeNoParams();
    if (mimeType != null
        && ArchiveManager.ARCHIVE_TYPE.isUsableArchiveType(mimeType)
        && !metaStrings.isEmpty()) {
      metadata.setArchiveManifest();
      clientMetadata.clear();
      if (LOG.isDebugEnabled()) LOG.debug("Handling implicit container... (splitfile)");
      return false; // continue loop
    } else {
      emitExpectedMimeIfPresent(context);
    }
    validateAllowedMimeForSplitfile(mimeType);
    applyDecompressorIfCompressed();
    if (handleTooManyPathComponentsIfNeeded(context)) return true;
    final long len = metadata.dataLength();
    final long uncompressedLen = metadata.isCompressed() ? metadata.uncompressedDataLength() : len;
    if ((uncompressedLen > ctx.getMaxOutputLength()) || (len > ctx.getMaxTempLength())) {
      boolean compressed = metadata.isCompressed();
      throw new FetchException(
          FetchExceptionMode.TOO_BIG,
          uncompressedLen,
          isFinal && decompressors.size() <= (compressed ? 1 : 0),
          clientMetadata.getMIMEType());
    }
    boolean reallyFinal = isFinal;
    if (isFinal && !parent.isCurrentState(this)) {
      LOG.error("isFinal but not the current state for {}", this);
      reallyFinal = false;
    }
    SplitFileFetcher.InitParams p = new SplitFileFetcher.InitParams();
    p.metadata = metadata;
    p.rcb = rcb;
    p.parent = parent;
    p.fetchContext = ctx;
    p.realTimeFlag = realTimeFlag;
    p.decompressors = decompressors;
    p.clientMetadata = clientMetadata;
    p.token = token;
    p.topDontCompress = topDontCompress;
    p.topCompatibilityMode = topCompatibilityMode;
    p.persistent = persistent;
    p.thisKey = thisKey;
    p.isFinalFetch = reallyFinal;
    p.context = context;
    ClientGetState sf = new SplitFileFetcher(p);
    this.deleteFetchContext = false;
    parent.onTransition(this, sf, context);
    sf.schedule(context);
    rcb.onBlockSetFinished(this, context);
    return true;
  }

  private void applyDecompressorIfCompressed() {
    if (metadata.isCompressed()) {
      COMPRESSOR_TYPE codec = metadata.getCompressionCodec();
      addDecompressor(codec);
    }
  }

  private void validateAllowedMimeForSplitfile(String mimeType) throws FetchException {
    if (metaStrings.isEmpty()
        && isFinal
        && mimeType != null
        && ctx.getAllowedMIMETypes() != null
        && !ctx.getAllowedMIMETypes().contains(mimeType)) {
      long len = metadata.uncompressedDataLength();
      throw new FetchException(
          FetchExceptionMode.WRONG_MIME_TYPE, len, false, clientMetadata.getMIMEType());
    }
  }

  private boolean handleTooManyPathComponentsIfNeeded(ClientContext context) {
    if (isFinal && !ctx.ignoreTooManyPathComponents) {
      if (!metaStrings.isEmpty()) {
        if (addedMetaStrings > 0) {
          rcb.onFailure(
              new FetchException(
                  FetchExceptionMode.INVALID_METADATA,
                  "Invalid metadata: too many path components in redirects",
                  thisKey),
              this,
              context);
        } else {
          FreenetURI tryURI = uri.dropLastMetaStrings(metaStrings.size());
          rcb.onFailure(
              new FetchException(
                  FetchExceptionMode.TOO_MANY_PATH_COMPONENTS,
                  metadata.uncompressedDataLength(),
                  (rcb == parent),
                  clientMetadata.getMIMEType(),
                  tryURI),
              this,
              context);
        }
        return true;
      }
    } else if (LOG.isDebugEnabled()) {
      LOG.debug("Not finished: rcb={}" + LOG_FOR_LABEL + "{}", rcb, this);
    }
    return false;
  }

  // Extracted from handleMetadata() to reduce complexity.
  // Returns true to indicate the outer loop should continue.
  private void processSimpleManifestStep() throws FetchException {
    if (LOG.isDebugEnabled()) LOG.debug("Is simple manifest");
    String name = resolveManifestName();
    if (LOG.isDebugEnabled())
      LOG.debug("Next meta-string: {} length {}" + LOG_FOR_LABEL + "{}", name, name.length(), this);
    if (name == null) {
      selectDefaultManifestDocument();
    } else {
      selectManifestDocumentByName(name);
    }
    // continue outer loop
  }

  private String resolveManifestName() throws FetchException {
    if (metadata.countDocuments() == 1
        && metadata.getDocument("") != null
        && metadata.getDocument("").isSimpleManifest()) {
      LOG.error("Manifest is called \"\" for {}", this);
      return "";
    } else if (metaStrings.isEmpty()) {
      FreenetURI u = uri;
      String last = u.lastMetaString();
      if (last == null || !last.isEmpty()) u = u.addMetaStrings(new String[] {""});
      else u = null;
      throw new FetchException(FetchExceptionMode.NOT_ENOUGH_PATH_COMPONENTS, -1, false, null, u);
    } else {
      return removeMetaString();
    }
  }

  private void selectDefaultManifestDocument() throws FetchException {
    if (!persistent) {
      metadata = metadata.getDefaultDocument();
    } else {
      metadata = metadata.grabDefaultDocument();
    }
    if (metadata == null)
      throw new FetchException(
          FetchExceptionMode.NOT_ENOUGH_PATH_COMPONENTS,
          -1,
          false,
          null,
          uri.addMetaStrings(new String[] {""}));
  }

  private void selectManifestDocumentByName(String name) throws FetchException {
    if (!persistent) {
      Metadata origMd = metadata;
      metadata = origMd.getDocument(name);
      if (metadata != null && metadata.isSymbolicShortlink()) {
        String oldName = name;
        name = metadata.getSymbolicShortlinkTargetName();
        if (oldName.equals(name))
          throw new FetchException(FetchExceptionMode.INVALID_METADATA, "redirect loop: " + name);
        metadata = origMd.getDocument(name);
      }
      thisKey = thisKey.pushMetaString(name);
    } else {
      Metadata newMeta = metadata.grabDocument(name);
      if (newMeta != null && newMeta.isSymbolicShortlink()) {
        String oldName = name;
        name = newMeta.getSymbolicShortlinkTargetName();
        if (oldName.equals(name))
          throw new FetchException(FetchExceptionMode.INVALID_METADATA, "redirect loop: " + name);
        newMeta = metadata.getDocument(name);
      }
      metadata = newMeta;
      thisKey = thisKey.pushMetaString(name);
    }
    if (metadata == null)
      throw new FetchException(FetchExceptionMode.NOT_IN_ARCHIVE, "can't find " + name);
  }

  private void fetchArchive(
      boolean forData,
      Metadata meta,
      String element,
      ArchiveExtractCallback callback,
      final ClientContext context)
      throws FetchException {
    if (LOG.isDebugEnabled()) LOG.debug("fetchArchive()");
    // Fetch the archive
    // How?
    // Spawn a separate SingleFileFetcher,
    // which fetches the archive, then calls
    // our Callback, which unpacks the archive, then
    // reschedules us.
    Metadata newMeta = new Metadata(meta);
    newMeta.setSimpleRedirect();
    final SingleFileFetcher f;
    // Note: arguably archive data is "temporary", but
    // this will use ctx.maxOutputLength
    f =
        new SingleFileFetcher(
            this,
            persistent,
            true,
            newMeta,
            new ArchiveFetcherCallback(forData, element, callback),
            new FetchContext(ctx, FetchContext.SET_RETURN_ARCHIVES, true, null));
    if (LOG.isDebugEnabled()) LOG.debug("fetchArchive(): {}", f);
    // Fetch the archive. The archive fetcher callback will unpack it, and either call the element
    // callback, or just go back around handleMetadata() on this, which will see that the data is
    // now
    // available.

    // We need to transition here, so that everything gets deleted if we are canceled during the
    // archive fetch phase.
    parent.onTransition(this, f, context);

    // Break locks. Must not call onFailure(), etc, from within SFF lock.
    context
        .getJobRunner(persistent)
        .queueInternal(
            context1 -> {
              f.innerWrapHandleMetadata(true, context1);
              return true;
            });
  }

  // LOCKING: If transient, DO NOT call this method from within handleMetadata.
  /**
   * Invoke {@link #handleMetadata(ClientContext)} and convert errors into {@link FetchException}
   * callbacks.
   *
   * <p>When {@code notFinalizedSize} is {@code true}, any sizes previously reported to the client
   * are marked as provisional to avoid over‑committing. Archive and parsing failures are wrapped
   * and forwarded to the completion callback.
   *
   * @param notFinalizedSize set to {@code true} to mark reported sizes as provisional
   * @param context the client context used by nested operations and callbacks
   */
  protected void innerWrapHandleMetadata(boolean notFinalizedSize, ClientContext context) {
    try {
      handleMetadata(context);
    } catch (MetadataParseException e) {
      onFailure(new FetchException(FetchExceptionMode.INVALID_METADATA, e), false, context);
    } catch (FetchException e) {
      FetchException failure = e;
      if (notFinalizedSize) {
        failure = e.notFinalized();
      }
      onFailure(failure, false, context);
    } catch (ArchiveFailureException | ArchiveRestartException e) {
      onFailure(wrapToFetchException(e), false, context);
    }
  }

  class ArchiveFetcherCallback implements GetCompletionCallback, Serializable {

    @Serial private static final long serialVersionUID = 1L;
    private final boolean wasFetchingFinalData;
    private final String element;
    private final ArchiveExtractCallback callback;

    /**
     * For activation, we need to know whether we are persistent even though the parent may not have
     * been activated yet
     */
    private final boolean persistent;

    private HashResult[] hashes;
    private final FetchContext ctx;

    ArchiveFetcherCallback(
        boolean wasFetchingFinalData, String element, ArchiveExtractCallback cb) {
      this.wasFetchingFinalData = wasFetchingFinalData;
      this.element = element;
      this.callback = cb;
      this.persistent = SingleFileFetcher.this.persistent;
      this.ctx = SingleFileFetcher.this.ctx;
    }

    @Override
    public void onSuccess(
        StreamGenerator streamGenerator,
        ClientMetadata clientMetadata,
        List<? extends Compressor> decompressors,
        ClientGetState state,
        ClientContext context) {
      Bucket data;
      // Note: not strictly correct and unnecessary - archive size already checked against
      // ctx.max*Length inside SingleFileFetcher
      long maxLen = Math.min(ctx.getMaxTempLength(), ctx.getMaxOutputLength());
      try {
        data = context.getBucketFactory(persistent).makeBucket(maxLen);
        try (PipedInputStream pipeIn = new PipedInputStream();
            PipedOutputStream pipeOut = new PipedOutputStream();
            OutputStream output = data.getOutputStream()) {

          if (decompressors != null) {
            if (LOG.isDebugEnabled()) LOG.debug("decompressing...");
            pipeOut.connect(pipeIn);
            DecompressorThreadManager decompressorManager =
                new DecompressorThreadManager(pipeIn, decompressors, maxLen);
            try (PipedInputStream newPipeIn = decompressorManager.execute()) {
              ClientGetWorkerThread worker = makeAndStartWorker(newPipeIn, output, context);
              streamGenerator.writeTo(pipeOut, context);
              decompressorManager.waitFinished();
              worker.waitFinished();
            }
          } else {
            streamGenerator.writeTo(output, context);
          }
        }
      } catch (Exception t) {
        LOG.error("Caught {}", t, t);
        onFailure(new FetchException(FetchExceptionMode.INTERNAL_ERROR, t), state, context);
        return;
      }
      if (key instanceof ClientSSK) {
        // Fetching the container is essentially a full success, we should update the latest known
        // good.
        context.uskManager.checkUSK(uri, persistent, false);
      }

      // Run directly, even if persistent.
      parent.onTransition(state, SingleFileFetcher.this, context);
      innerSuccess(data, context);
    }

    private void innerSuccess(Bucket data, ClientContext context) {
      boolean ok = true;
      try {
        if (hashes != null) ok = verifyHashes(data, context);
        if (ok) {
          ah.extractToCache(data, actx, element, callback, context.archiveManager, context);
        }
      } catch (ArchiveFailureException | ArchiveRestartException e) {
        SingleFileFetcher.this.onFailure(wrapToFetchException(e), false, context);
        ok = false;
      } finally {
        data.free();
      }
      if (!ok) {
        return;
      }
      if (callback != null) return;
      innerWrapHandleMetadata(true, context);
    }

    private boolean verifyHashes(Bucket data, ClientContext context) {
      try (InputStream is = data.getInputStream();
          MultiHashInputStream hasher =
              new MultiHashInputStream(is, HashResult.makeBitmask(hashes))) {
        byte[] buf = new byte[32768];
        int read;
        do {
          read = hasher.read(buf);
        } while (read > 0);
        HashResult[] results = hasher.getResults();
        if (!HashResult.strictEquals(results, hashes)) {
          onFailure(
              new FetchException(FetchExceptionMode.CONTENT_HASH_FAILED),
              SingleFileFetcher.this,
              context);
          return false;
        }
        return true;
      } catch (InsufficientDiskSpaceException _) {
        onFailure(
            new FetchException(FetchExceptionMode.NOT_ENOUGH_DISK_SPACE),
            SingleFileFetcher.this,
            context);
        return false;
      } catch (IOException e) {
        onFailure(
            new FetchException(FetchExceptionMode.BUCKET_ERROR, e),
            SingleFileFetcher.this,
            context);
        return false;
      }
    }

    @Override
    public void onFailure(FetchException e, ClientGetState state, ClientContext context) {
      // Force fatal as the fetcher is presumed to have made a reasonable effort.
      SingleFileFetcher.this.onFailure(e, true, context);
    }

    @Override
    public void onBlockSetFinished(ClientGetState state, ClientContext context) {
      if (wasFetchingFinalData) {
        rcb.onBlockSetFinished(SingleFileFetcher.this, context);
      }
    }

    @Override
    public void onTransition(
        ClientGetState oldState, ClientGetState newState, ClientContext context) {
      // Ignore
    }

    @Override
    public void onExpectedMIME(ClientMetadata metadata, ClientContext context) {
      // Ignore
    }

    @Override
    public void onExpectedSize(long size, ClientContext context) {
      rcb.onExpectedSize(size, context);
    }

    @Override
    public void onFinalizedMetadata() {
      // Ignore
    }

    @Override
    public void onExpectedTopSize(
        long size, long compressed, int blocksReq, int blocksTotal, ClientContext context) {
      // Ignore
    }

    @Override
    public void onSplitfileCompatibilityMode(
        CompatibilityMode min,
        CompatibilityMode max,
        byte[] splitfileKey,
        boolean dontCompress,
        boolean bottomLayer,
        boolean definitiveAnyway,
        ClientContext context) {
      // Not the bottom layer nor definitive when fetching container metadata.
      rcb.onSplitfileCompatibilityMode(min, max, splitfileKey, dontCompress, false, false, context);
    }

    @Override
    public void onHashes(HashResult[] hashes, ClientContext context) {
      this.hashes = hashes;
    }
  }

  class MultiLevelMetadataCallback implements GetCompletionCallback, Serializable {

    @Serial private static final long serialVersionUID = 1L;
    private final boolean persistent;
    private final FetchContext ctx;

    MultiLevelMetadataCallback() {
      this.persistent = SingleFileFetcher.this.persistent;
      this.ctx = SingleFileFetcher.this.ctx;
    }

    @Override
    public void onSuccess(
        StreamGenerator streamGenerator,
        ClientMetadata clientMetadata,
        List<? extends Compressor> decompressors,
        ClientGetState state,
        ClientContext context) {
      Bucket finalData;
      // Pre-1255 keys lack top block sizes; only minor decompression/alloc perf impact.
      long maxLen = Math.min(ctx.getMaxTempLength(), ctx.getMaxOutputLength());
      try {
        finalData = context.getBucketFactory(persistent).makeBucket(maxLen);
        try (PipedInputStream pipeIn = new PipedInputStream();
            PipedOutputStream pipeOut = new PipedOutputStream();
            OutputStream output = finalData.getOutputStream()) {

          if (decompressors != null) {
            if (LOG.isDebugEnabled()) LOG.debug("decompressing...");
            pipeIn.connect(pipeOut);
            DecompressorThreadManager decompressorManager =
                new DecompressorThreadManager(pipeIn, decompressors, maxLen);
            try (PipedInputStream newPipeIn = decompressorManager.execute()) {
              ClientGetWorkerThread worker = makeAndStartWorker(newPipeIn, output, context);
              streamGenerator.writeTo(pipeOut, context);
              decompressorManager.waitFinished();
              worker.waitFinished();
              // ClientGetWorkerThread will close output.
            }
          } else {
            streamGenerator.writeTo(output, context);
          }
        }
      } catch (Exception t) {
        LOG.error("Caught {}", t, t);
        onFailure(new FetchException(FetchExceptionMode.INTERNAL_ERROR, t), state, context);
        return;
      }

      try {
        parent.onTransition(state, SingleFileFetcher.this, context);
        // Note: Pass an InputStream here, and save ourselves a Bucket
        Metadata meta = Metadata.construct(finalData);
        synchronized (SingleFileFetcher.this) {
          metadata = meta;
        }
        innerWrapHandleMetadata(true, context);
      } catch (MetadataParseException e) {
        SingleFileFetcher.this.onFailure(
            new FetchException(FetchExceptionMode.INVALID_METADATA, e), false, context);
      } catch (InsufficientDiskSpaceException _) {
        SingleFileFetcher.this.onFailure(
            new FetchException(FetchExceptionMode.NOT_ENOUGH_DISK_SPACE), false, context);
      } catch (IOException e) {
        // Bucket error?
        SingleFileFetcher.this.onFailure(
            new FetchException(FetchExceptionMode.BUCKET_ERROR, e), false, context);
      } finally {
        finalData.free();
      }
    }

    @Override
    public void onFailure(FetchException e, ClientGetState state, ClientContext context) {
      parent.onTransition(state, SingleFileFetcher.this, context);
      // Pass it on; fetcher is assumed to have retried as appropriate already, so this is fatal.
      SingleFileFetcher.this.onFailure(e, true, context);
    }

    @Override
    public void onBlockSetFinished(ClientGetState state, ClientContext context) {
      // Ignore as we are fetching metadata here
    }

    @Override
    public void onTransition(
        ClientGetState oldState, ClientGetState newState, ClientContext context) {
      // Ignore
    }

    @Override
    public void onExpectedMIME(ClientMetadata mime, ClientContext context) {
      // Ignore
    }

    @Override
    public void onExpectedSize(long size, ClientContext context) {
      rcb.onExpectedSize(size, context);
    }

    @Override
    public void onFinalizedMetadata() {
      // Ignore
    }

    @Override
    public void onExpectedTopSize(
        long size, long compressed, int blocksReq, int blocksTotal, ClientContext context) {
      // Ignore
    }

    @Override
    public void onSplitfileCompatibilityMode(
        CompatibilityMode min,
        CompatibilityMode max,
        byte[] splitfileKey,
        boolean dontCompress,
        boolean bottomLayer,
        boolean definitiveAnyway,
        ClientContext context) {
      // Pass through definitiveAnyway as the top block may include the details.
      // Hence, we can get them straight away rather than waiting for the bottom layer.
      rcb.onSplitfileCompatibilityMode(
          min, max, splitfileKey, dontCompress, false, definitiveAnyway, context);
    }

    @Override
    public void onHashes(HashResult[] hashes, ClientContext context) {
      // Ignore
    }
  }

  /** Encapsulates policy and limits for creation. */
  public static final class CreationPolicy {
    final int maxRetries;
    final int recursionLevel;
    final boolean dontTellClientGet;
    final boolean isEssential;
    final boolean isFinal;
    final boolean hasInitialMetadata;

    /**
     * Create a new {@code CreationPolicy} describing retry, recursion and reporting behavior.
     *
     * @param maxRetries maximum number of retries permitted before surfacing failure
     * @param recursionLevel current recursion depth used to guard against cycles
     * @param dontTellClientGet whether to suppress some ClientGetter notifications
     * @param isEssential whether this request should count toward must‑succeed accounting
     * @param isFinal whether this leg is final with respect to path component checks
     * @param hasInitialMetadata whether the caller already holds initial metadata
     */
    public CreationPolicy(
        int maxRetries,
        int recursionLevel,
        boolean dontTellClientGet,
        boolean isEssential,
        boolean isFinal,
        boolean hasInitialMetadata) {
      this.maxRetries = maxRetries;
      this.recursionLevel = recursionLevel;
      this.dontTellClientGet = dontTellClientGet;
      this.isEssential = isEssential;
      this.isFinal = isFinal;
      this.hasInitialMetadata = hasInitialMetadata;
    }
  }

  /** Encapsulates runtime parameters for creation. */
  public static final class CreationRuntime {
    final ClientContext context;
    final boolean realTimeFlag;
    final long token;

    /**
     * Create a new {@code CreationRuntime} that carries per-run values.
     *
     * @param context runtime client context providing factories, caches, and schedulers
     * @param realTimeFlag whether this request prefers real‑time scheduling and timeouts
     * @param token opaque token propagated to callbacks so clients can correlate events
     */
    public CreationRuntime(ClientContext context, boolean realTimeFlag, long token) {
      this.context = context;
      this.realTimeFlag = realTimeFlag;
      this.token = token;
    }
  }

  /** Compact arguments holder for USK create helpers and callback construction. */
  static final class UskCreateArgs {
    ClientRequester requester;
    GetCompletionCallback cb;
    USK usk;
    List<String> metaStrings;
    FetchContext ctx;
    ArchiveContext actx;
    CreationPolicy policy;
    CreationRuntime runtime;
  }

  /**
   * Create a fetch state for a URI.
   *
   * <p>This helper inspects the URI and context to choose an efficient path: it may create a {@link
   * SimpleSingleFileFetcher} when redirects and splitfiles are disabled, return a {@link
   * SingleFileFetcher} for regular cases, or initiate a USK flow when the URI resolves to a USK.
   * The decision is based solely on the provided inputs and does not perform network I/O.
   *
   * @param requester parent requester that owns accounting and notifies clients
   * @param cb completion callback receiving progress, success, or failure signals
   * @param uri the original request URI including any meta‑strings
   * @param ctx fetch context governing limits, policy, and allowed MIME types
   * @param actx archive context used when the target lives inside a container
   * @param policy creation policy including retries, recursion and notifications
   * @param runtime runtime parameters such as real‑time flag and opaque token
   * @return a new {@link ClientGetState} appropriate for the URI and policy
   * @throws MalformedURLException if {@code uri} cannot be parsed into a client key
   * @throws FetchException if recursion limits or policy checks fail during planning
   */
  public static ClientGetState create(
      ClientRequester requester,
      GetCompletionCallback cb,
      FreenetURI uri,
      FetchContext ctx,
      ArchiveContext actx,
      CreationPolicy policy,
      CreationRuntime runtime)
      throws MalformedURLException, FetchException {
    BaseClientKey key = null;
    if (!policy.hasInitialMetadata) key = BaseClientKey.getBaseKey(uri);
    if ((!uri.hasMetaStrings())
        && !ctx.getAllowSplitfiles()
        && !ctx.getFollowRedirects()
        && key instanceof ClientKey clientKey) {
      return new SimpleSingleFileFetcher(
          SimpleSingleFileFetcher.Cfg.create(
                  clientKey, policy.maxRetries, ctx, requester, cb, runtime.token, runtime.context)
              .essential(policy.isEssential)
              .dontAdd(false)
              .deleteFetchContext(false)
              .realTime(runtime.realTimeFlag));
    }
    if (key instanceof ClientKey || policy.hasInitialMetadata) {
      InitParams p = new InitParams();
      p.parent = requester;
      p.cb = cb;
      p.metadata = null;
      p.key = (ClientKey) key;
      p.metaStrings = new ArrayList<>(uri.listMetaStrings());
      p.origURI = uri;
      p.addedMetaStrings = 0;
      p.ctx = ctx;
      p.deleteFetchContext = false;
      p.actx = actx;
      p.ah = null;
      p.archiveMetadata = null;
      p.policy = policy;
      p.runtime = runtime;
      p.topDontCompress = false;
      p.topCompatibilityMode = (short) 0;
      return new SingleFileFetcher(p);
    } else {
      UskCreateArgs a = new UskCreateArgs();
      a.requester = requester;
      a.cb = cb;
      a.usk = (USK) key;
      a.metaStrings = new ArrayList<>(uri.listMetaStrings());
      a.ctx = ctx;
      a.actx = actx;
      a.policy = policy;
      a.runtime = runtime;
      return uskCreate(a);
    }
  }

  private static ClientGetState uskCreate(UskCreateArgs a) throws FetchException {
    if (a.usk.suggestedEdition >= 0) {
      return uskCreateKnownGood(a);
    } else {
      return uskCreateThoroughSearch(a);
    }
  }

  private static ClientGetState uskCreateKnownGood(UskCreateArgs a) throws FetchException {
    long edition = a.runtime.context.uskManager.lookupKnownGood(a.usk);
    if (edition > a.usk.suggestedEdition) {
      if (LOG.isDebugEnabled()) LOG.debug("Redirecting to edition {}", edition);
      a.cb.onFailure(
          new FetchException(
              FetchExceptionMode.PERMANENT_REDIRECT,
              a.usk.copy(edition).getURI().addMetaStrings(a.metaStrings)),
          null,
          a.runtime.context);
      return null;
    }
    a.runtime.context.uskManager.startTemporaryBackgroundFetcher(
        a.usk, a.runtime.context, a.ctx, true, a.runtime.realTimeFlag);
    edition = a.runtime.context.uskManager.lookupKnownGood(a.usk);
    return decideAfterBackgroundFetcher(a, edition);
  }

  private static ClientGetState decideAfterBackgroundFetcher(UskCreateArgs a, long edition)
      throws FetchException {
    if (edition > a.usk.suggestedEdition) {
      if (LOG.isDebugEnabled()) LOG.debug("Redirecting to edition {}", edition);
      a.cb.onFailure(
          new FetchException(
              FetchExceptionMode.PERMANENT_REDIRECT,
              a.usk.copy(edition).getURI().addMetaStrings(a.metaStrings)),
          null,
          a.runtime.context);
      return null;
    }
    if (edition == -1 && a.runtime.context.uskManager.lookupLatestSlot(a.usk) == -1) {
      USKFetcherTag tag =
          a.runtime.context.uskManager.getFetcher(
              a.usk.copy(a.usk.suggestedEdition),
              a.ctx,
              false,
              a.requester.persistent(),
              a.runtime.realTimeFlag,
              new MyUSKFetcherCallback(a, true),
              false,
              a.runtime.context,
              true);
      if (a.policy.isEssential) a.requester.addMustSucceedBlocks(1);
      return tag;
    }
    GetCompletionCallback myCB =
        new USKProxyCompletionCallback(a.usk, a.cb, a.requester.persistent());
    InitParams p = new InitParams();
    p.parent = a.requester;
    p.cb = myCB;
    p.metadata = null;
    p.key = a.usk.getSSK();
    p.metaStrings = a.metaStrings;
    p.origURI = a.usk.getURI().addMetaStrings(a.metaStrings);
    p.addedMetaStrings = 0;
    p.ctx = a.ctx;
    p.deleteFetchContext = false;
    p.actx = a.actx;
    p.ah = null;
    p.archiveMetadata = null;
    p.policy = a.policy;
    p.runtime = a.runtime;
    p.topDontCompress = false;
    p.topCompatibilityMode = (short) 0;
    return new SingleFileFetcher(p);
  }

  private static ClientGetState uskCreateThoroughSearch(UskCreateArgs a) {
    USKFetcherTag tag =
        a.runtime.context.uskManager.getFetcher(
            a.usk.copy(-a.usk.suggestedEdition),
            a.ctx,
            false,
            a.requester.persistent(),
            a.runtime.realTimeFlag,
            new MyUSKFetcherCallback(a, false),
            false,
            a.runtime.context,
            false);
    if (a.policy.isEssential) a.requester.addMustSucceedBlocks(1);
    return tag;
  }

  static class MyUSKFetcherCallback implements USKFetcherTagCallback, Serializable {

    @Serial private static final long serialVersionUID = 1L;
    final ClientRequester parent;
    // Must be serializable to preserve persistent USK fetch completion after restart
    final GetCompletionCallback cb;
    final USK usk;
    private final List<String> metaStrings;
    final FetchContext ctx;
    final ArchiveContext actx;
    final int maxRetries;
    final int recursionLevel;
    final boolean dontTellClientGet;
    final long token;
    final boolean persistent;
    final boolean realTimeFlag;
    final boolean datastoreOnly;
    final int hashCode;
    private USKFetcherTag tag;

    @Override
    public void setTag(USKFetcherTag tag, ClientContext context) {
      this.tag = tag;
    }

    public MyUSKFetcherCallback(UskCreateArgs args, boolean datastoreOnly) {
      this.parent = args.requester;
      this.cb = args.cb;
      this.usk = args.usk;
      this.metaStrings = args.metaStrings;
      this.ctx = args.ctx;
      this.actx = args.actx;
      this.maxRetries = args.policy.maxRetries;
      this.recursionLevel = args.policy.recursionLevel;
      this.dontTellClientGet = args.policy.dontTellClientGet;
      this.token = args.runtime.token;
      this.persistent = args.requester.persistent();
      this.datastoreOnly = datastoreOnly;
      this.hashCode = super.hashCode();
      this.realTimeFlag = args.runtime.realTimeFlag;
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Created {}" + LOG_FOR_LABEL + "{} and {} datastore only = {}",
            this,
            this.usk,
            this.cb,
            datastoreOnly);
    }

    @Serial
    private void writeObject(ObjectOutputStream out) throws IOException {
      if (cb != null && !(cb instanceof Serializable)) {
        throw new NotSerializableException(
            "GetCompletionCallback must be Serializable: " + cb.getClass().getName());
      }
      out.defaultWriteObject();
    }

    @Serial
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
      in.defaultReadObject();
    }

    @Override
    public int hashCode() {
      return hashCode;
    }

    @Override
    @SuppressWarnings("RedundantMethodOverride")
    public boolean equals(Object obj) {
      return this == obj;
    }

    @Override
    public void onFoundEdition(USKFoundEdition foundEdition) {
      long edition = foundEdition.edition();
      USK newUSK = foundEdition.key();
      ClientContext context = foundEdition.context();
      if (edition < usk.suggestedEdition && datastoreOnly) {
        edition = usk.suggestedEdition;
      }
      ClientSSK key = usk.getSSK(edition);
      try {
        if (edition == usk.suggestedEdition || (edition == 0 && usk.suggestedEdition == 1)) {
          InitParams p = new InitParams();
          p.parent = parent;
          p.cb = cb;
          p.metadata = null;
          p.key = key;
          p.metaStrings = metaStrings;
          p.origURI = key.getURI().addMetaStrings(metaStrings);
          p.addedMetaStrings = 0;
          p.ctx = ctx;
          p.deleteFetchContext = false;
          p.actx = actx;
          p.ah = null;
          p.archiveMetadata = null;
          p.policy =
              new CreationPolicy(
                  maxRetries, recursionLevel + 1, dontTellClientGet, false, true, false);
          p.runtime = new CreationRuntime(context, realTimeFlag, token);
          p.topDontCompress = false;
          p.topCompatibilityMode = (short) 0;
          SingleFileFetcher sf = new SingleFileFetcher(p);
          if (tag != null) {
            cb.onTransition(tag, sf, context);
          }
          sf.schedule(context);
        } else {
          cb.onFailure(
              new FetchException(
                  FetchExceptionMode.PERMANENT_REDIRECT,
                  newUSK.getURI().addMetaStrings(metaStrings)),
              null,
              context);
        }
      } catch (FetchException e) {
        cb.onFailure(e, null, context);
      }
    }

    @Override
    public void onFailure(ClientContext context) {
      FetchException e = null;
      if (datastoreOnly) {
        try {
          onFoundEdition(
              new USKFoundEdition(
                  usk.suggestedEdition, usk, context, false, (short) -1, null, false, false));
          return;
        } catch (Exception t) {
          e = new FetchException(FetchExceptionMode.INTERNAL_ERROR, t);
        }
      }
      if (e == null) e = new FetchException(FetchExceptionMode.DATA_NOT_FOUND, "No USK found");
      if (LOG.isDebugEnabled()) LOG.debug("Failing USK with {}", e, e);
      if (cb == null)
        throw new NullPointerException(
            "Callback is null in "
                + this
                + " for usk "
                + usk
                + " with datastoreOnly="
                + datastoreOnly);
      cb.onFailure(e, null, context);
    }

    @Override
    public void onCancelled(ClientContext context) {
      cb.onFailure(new FetchException(FetchExceptionMode.CANCELLED, (String) null), null, context);
    }

    @Override
    public short getPollingPriorityNormal() {
      return parent.getPriorityClass();
    }

    @Override
    public short getPollingPriorityProgress() {
      return parent.getPriorityClass();
    }
  }
}

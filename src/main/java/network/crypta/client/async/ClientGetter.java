package network.crypta.client.async;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.io.RandomAccessFile;
import java.io.Serial;
import java.io.Serializable;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.util.List;
import network.crypta.client.ArchiveContext;
import network.crypta.client.ClientMetadata;
import network.crypta.client.DefaultMIMETypes;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.FetchResult;
import network.crypta.client.InsertContext.CompatibilityMode;
import network.crypta.client.async.BinaryBlobWriter.BinaryBlobAlreadyClosedException;
import network.crypta.client.events.EnterFiniteCooldownEvent;
import network.crypta.client.events.ExpectedFileSizeEvent;
import network.crypta.client.events.ExpectedHashesEvent;
import network.crypta.client.events.ExpectedMIMEEvent;
import network.crypta.client.events.SendingToNetworkEvent;
import network.crypta.client.events.SplitfileCompatibilityModeEvent;
import network.crypta.client.events.SplitfileProgressEvent;
import network.crypta.client.filter.ContentFilter;
import network.crypta.client.filter.FilterMIMEType;
import network.crypta.client.filter.UnsafeContentTypeException;
import network.crypta.crypt.ChecksumChecker;
import network.crypta.crypt.HashResult;
import network.crypta.keys.ClientKeyBlock;
import network.crypta.keys.FreenetURI;
import network.crypta.support.api.Bucket;
import network.crypta.support.compress.CompressionOutputSizeException;
import network.crypta.support.compress.Compressor;
import network.crypta.support.compress.DecompressorThreadManager;
import network.crypta.support.io.FileBucket;
import network.crypta.support.io.FileUtil;
import network.crypta.support.io.InsufficientDiskSpaceException;
import network.crypta.support.io.NullOutputStream;
import network.crypta.support.io.ResumeFailedException;
import network.crypta.support.io.StorageFormatException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * High‑level client fetch operation for retrieving content and metadata.
 *
 * <p>This class coordinates fetching a URI, following redirects, and retrieving multi‑part
 * splitfiles. It behaves similarly to the fetch logic exposed via FCP and is used internally by the
 * server, the HTTP proxy, and plugins. The request progresses through a sequence of {@link
 * ClientGetState} implementations (for example {@code SingleFileFetcher} and {@code
 * SplitFileFetcher}) and the current state is held in {@link #currentState}.
 *
 * <p>Typical usage is:
 *
 * <ul>
 *   <li>Construct a {@code ClientGetter} with a {@link ClientGetCallback} and a target {@link
 *       FreenetURI} plus a {@link FetchContext}.
 *   <li>Call {@link #start(ClientContext)} (or {@link #start(boolean, FreenetURI, ClientContext)})
 *       to enqueue the request.
 *   <li>React to callbacks for success/failure and optional progress or metadata signals.
 * </ul>
 *
 * <p>State and life cycle: a single instance represents one logical fetch. It can be restarted
 * under some conditions (see {@link #canRestart()}) and keeps track of metadata such as expected
 * MIME type and size as they become known. When enabled, content filtering is applied and may cause
 * the request to fail early if the MIME type is considered unsafe.
 *
 * <p>Concurrency and thread‑safety: instances are accessed from job runner threads and callback
 * threads. Internal fields that change during the fetch are guarded by synchronized blocks on
 * {@code this}; external callers should assume the class is not generally thread‑safe beyond the
 * documented callback contract. Mutability is limited to request progress and associated metadata;
 * configuration passed via the constructor is treated as read‑mostly.
 *
 * @see ClientGetState
 * @see FetchContext
 * @see ClientGetCallback
 */
public class ClientGetter extends BaseClientGetter
    implements WantsCooldownCallback, FileGetCompletionCallback, Serializable {

  private static final Logger LOG = LoggerFactory.getLogger(ClientGetter.class);

  private static final String BLOB_STREAM_ALREADY_CLOSED_PREFIX =
      "Failed to close binary blob stream, already closed: ";
  private static final String BLOB_STREAM_FAIL_PREFIX = "Failed to close binary blob stream: ";
  private static final String CAUGHT_MESSAGE = "Caught {}";
  private static final String DEBUG_EXCEPTION_MESSAGE = "debug";
  private static final String RESTORE_FROM_SPLITFILE_FAILED_MSG =
      "Failed to restore from splitfile, restarting: {}";

  @Serial private static final long serialVersionUID = 1L;

  /** Will be called when the request completes */
  @SuppressWarnings("java:S1948")
  final ClientGetCallback clientCallback;

  /** The initial Freenet URI being fetched. */
  FreenetURI uri;

  /** Settings for the fetch - max size etc */
  final FetchContext ctx;

  /** Checks for container loops. */
  final ArchiveContext actx;

  /**
   * The current state of the request. SingleFileFetcher when processing metadata for fetching a
   * simple key, SplitFileFetcher when fetching a splitfile, etc.
   */
  @SuppressWarnings("java:S1948")
  private ClientGetState currentState;

  /** Has the request finished? */
  private boolean finished;

  /** Number of times the fetch has been restarted because a container was out of date */
  private int archiveRestarts;

  /**
   * If not null, Bucket to return the data in, otherwise we create one. If non-null, it is the
   * responsibility of the callback to create and resume this bucket.
   */
  @SuppressWarnings("java:S1948")
  final Bucket returnBucket;

  /** If not null, BucketWrapper to return a binary blob in */
  private final transient BinaryBlobWriter binaryBlobWriter;

  /** If true, someone else is responsible for this BlobWriter, usually it's a shared one */
  private final boolean dontFinalizeBlobWriter;

  /** The expected MIME type, if we know it. Should not change. */
  private String expectedMIME;

  /** The expected size of the file, if we know it. */
  private long expectedSize;

  /** If true, the metadata (mostly the expected size) shouldn't change further. */
  private boolean finalizedMetadata;

  /** Callback to spy on the metadata at each stage of the request */
  private transient SnoopMetadata snoopMeta;

  /** Callback to spy on the data at each stage of the request */
  private transient SnoopBucket snoopBucket;

  /**
   * Optional set of hash results associated with the current request. When present, these are used
   * for integrity checks or to seed downstream filtering and verification steps.
   */
  private HashResult[] hashes;

  private final transient Bucket initialMetadata;

  /**
   * If set, and filtering is enabled, the MIME type we filter with must be compatible with this
   * extension.
   */
  final String forceCompatibleExtension;

  private transient boolean resumedFetcher;

  // Constructors.

  /**
   * Create a getter from a request and optional settings.
   *
   * <p>This constructor centralizes request initialization while keeping the request parameters and
   * optional behavior flags in reusable parameter objects. It performs no validation and preserves
   * the legacy behavior of the expanded constructor.
   *
   * @param request base request parameters including callback, URI, context, and priority
   * @param options optional settings such as return buckets and binary blob recording
   */
  public ClientGetter(ClientGetterRequest request, ClientGetterOptions options) {
    super(request.priorityClass(), request.client().getRequestClient());
    this.clientCallback = request.client();
    this.returnBucket = options.returnBucket();
    this.uri = request.uri();
    this.ctx = request.ctx();
    this.finished = false;
    this.actx = new ArchiveContext(ctx.getMaxTempLength(), ctx.getMaxArchiveLevels());
    this.binaryBlobWriter = options.binaryBlobWriter();
    this.dontFinalizeBlobWriter = options.dontFinalizeBlobWriter();
    this.initialMetadata = options.initialMetadata();
    archiveRestarts = 0;
    this.forceCompatibleExtension = options.forceCompatibleExtension();
  }

  /**
   * Create a getter with default options.
   *
   * @param request base request parameters including callback, URI, context, and priority
   */
  public ClientGetter(ClientGetterRequest request) {
    this(request, ClientGetterOptions.defaults());
  }

  // Shorter constructors for convenience and backwards compatibility.

  /**
   * Create a getter with minimal parameters.
   *
   * <p>This convenience constructor delegates to the full constructor, using {@code null} for the
   * optional return bucket, binary blob writer, and initial metadata.
   *
   * @param client callback that receives completion and failure notifications; must not be {@code
   *     null} and should be prepared to run on a background thread
   * @param uri target {@link FreenetURI} to fetch; non‑{@code null}; may be redirected by metadata
   * @param ctx fetch configuration including size limits, filtering, and retry behavior
   * @param priorityClass scheduling priority; smaller values represent higher priority
   */
  public ClientGetter(
      ClientGetCallback client, FreenetURI uri, FetchContext ctx, short priorityClass) {
    this(new ClientGetterRequest(client, uri, ctx, priorityClass), ClientGetterOptions.defaults());
  }

  /**
   * Create a getter that returns data into the supplied bucket when possible.
   *
   * <p>If {@code returnBucket} is non‑{@code null}, the implementation may write directly to it or
   * move the final data into it. Callers own the bucket lifecycle.
   *
   * @param client callback that receives completion and failure notifications
   * @param uri target {@link FreenetURI} to fetch
   * @param ctx fetch configuration including limits and filtering flags
   * @param priorityClass scheduling priority; smaller values represent higher priority
   * @param returnBucket optional destination bucket; when {@code null}, a temporary bucket is used
   */
  public ClientGetter(
      ClientGetCallback client,
      FreenetURI uri,
      FetchContext ctx,
      short priorityClass,
      Bucket returnBucket) {
    this(
        new ClientGetterRequest(client, uri, ctx, priorityClass),
        ClientGetterOptions.withReturnBucket(returnBucket));
  }

  /**
   * Create a getter that also records the accessed keys to a binary blob.
   *
   * <p>When {@code binaryBlobWriter} is supplied, the fetcher records each accessed (or potentially
   * accessed in redundant structures) key into the blob. The caller is responsible for the writer
   * lifecycle unless otherwise noted by the {@link #ClientGetter(ClientGetCallback, FreenetURI,
   * FetchContext, short, Bucket, BinaryBlobWriter, boolean, Bucket, String) full constructor}.
   *
   * @param client callback that receives completion and failure notifications
   * @param uri target {@link FreenetURI} to fetch
   * @param ctx fetch configuration including limits and filtering flags
   * @param priorityClass scheduling priority; smaller values represent higher priority
   * @param returnBucket optional destination bucket for the final data
   * @param binaryBlobWriter writer that collects referenced keys during the fetch; may be {@code
   *     null} to disable collection
   */
  public ClientGetter(
      ClientGetCallback client,
      FreenetURI uri,
      FetchContext ctx,
      short priorityClass,
      Bucket returnBucket,
      BinaryBlobWriter binaryBlobWriter) {
    this(
        new ClientGetterRequest(client, uri, ctx, priorityClass),
        ClientGetterOptions.withBinaryBlobWriter(returnBucket, binaryBlobWriter));
  }

  /**
   * Create a getter with optional initial metadata.
   *
   * <p>Supplies an initial metadata bucket that can speed up or resume processing when already
   * available. Delegates to the full constructor with default values for writer finalization and
   * forced extension filtering.
   *
   * @param client callback that receives completion and failure notifications
   * @param uri target {@link FreenetURI} to fetch
   * @param ctx fetch configuration including limits and filtering flags
   * @param priorityClass scheduling priority; smaller values represent higher priority
   * @param returnBucket optional destination bucket for the final data
   * @param binaryBlobWriter writer that collects referenced keys during the fetch; may be {@code
   *     null}
   * @param initialMetadata optional initial metadata to seed the request
   */
  public ClientGetter(
      ClientGetCallback client,
      FreenetURI uri,
      FetchContext ctx,
      short priorityClass,
      Bucket returnBucket,
      BinaryBlobWriter binaryBlobWriter,
      Bucket initialMetadata) {
    this(
        new ClientGetterRequest(client, uri, ctx, priorityClass),
        ClientGetterOptions.withInitialMetadata(returnBucket, binaryBlobWriter, initialMetadata));
  }

  /**
   * Fetch a key.
   *
   * @param client The callback we will call when it is completed.
   * @param uri The URI to fetch.
   * @param ctx The config settings for the fetch.
   * @param priorityClass The priority at which to schedule the request.
   * @param returnBucket The bucket to return the data in. Can be null. If not null, the
   *     ClientGetter must either write the data directly to the bucket, or copy it and free the
   *     original temporary bucket. Preferably the former, obviously!
   * @param binaryBlobWriter If non-null, we will write all the keys accessed (or that could have
   *     been accessed in the case of redundant structures such as splitfiles) to this binary blob
   *     writer.
   * @param dontFinalizeBlobWriter If true, the caller is responsible for BlobWriter finalization
   * @param initialMetadata If non-null, initial metadata to use for the request
   * @param forceCompatibleExtension If set, and filtering is enabled, the MIME type we filter with
   *     must be compatible with this extension
   */
  @SuppressWarnings("java:S107")
  public ClientGetter(
      ClientGetCallback client,
      FreenetURI uri,
      FetchContext ctx,
      short priorityClass,
      Bucket returnBucket,
      BinaryBlobWriter binaryBlobWriter,
      boolean dontFinalizeBlobWriter,
      Bucket initialMetadata,
      String forceCompatibleExtension) {
    this(
        new ClientGetterRequest(client, uri, ctx, priorityClass),
        new ClientGetterOptions(
            returnBucket,
            binaryBlobWriter,
            dontFinalizeBlobWriter,
            initialMetadata,
            forceCompatibleExtension));
  }

  /** Required because we implement {@link Serializable}. */
  protected ClientGetter() {
    clientCallback = null;
    ctx = null;
    actx = null;
    returnBucket = null;
    binaryBlobWriter = null;
    dontFinalizeBlobWriter = false;
    initialMetadata = null;
    forceCompatibleExtension = null;
  }

  /**
   * Start the request using the current configuration.
   *
   * <p>This convenience method is equivalent to calling {@link #start(boolean, FreenetURI,
   * ClientContext) start(false, null, context)}. It schedules the fetch if the request has not yet
   * been started or has been properly reset. Errors that prevent scheduling are reported via a
   * {@link FetchException}.
   *
   * @param context client context providing shared services and job runners for scheduling
   * @throws FetchException if the request cannot be queued due to invalid state or URI problems
   */
  public void start(ClientContext context) throws FetchException {
    start(false, null, context);
  }

  /**
   * Start the request.
   *
   * @param restart If true, restart a finished request.
   * @param overrideURI If non-null, change the URI we are fetching (usually when restarting).
   * @param context The client context, contains important mostly non-persistent global objects.
   * @return True if we restarted, false if we didn't (but only in a few cases).
   * @throws FetchException If we were unable to restart.
   */
  public boolean start(boolean restart, FreenetURI overrideURI, ClientContext context)
      throws FetchException {
    if (LOG.isDebugEnabled())
      LOG.debug("Starting {} persistent={} for {}", this, persistent(), uri);
    try {
      if (!initStart(restart, overrideURI, context)) return false;
      if (cancelled) cancel();
      scheduleIfReady(context);
      if (cancelled) cancel();
    } catch (MalformedURLException e) {
      throw new FetchException(FetchExceptionMode.INVALID_URI, e);
    }
    return true;
  }

  private boolean initStart(boolean restart, FreenetURI overrideURI, ClientContext context)
      throws FetchException, MalformedURLException {
    // See note in the original method: avoid synchronizing while scheduling, which may call back
    // into arbitrary code.
    synchronized (this) {
      if (restart) clearCountersOnRestart();
      if (overrideURI != null) uri = overrideURI;
      if (finished) {
        if (!restart) return false;
        currentState = null;
        cancelled = false;
        finished = false;
      }
      if (!resumedFetcher) {
        actx.clear();
        expectedMIME = null;
        expectedSize = 0;
        // Preserve hash-reset semantics
        // (the previous code stored oldHashes but never used it).
        hashes = null;
        finalBlocksRequired = 0;
        finalBlocksTotal = 0;
        resetBlocks();
        currentState =
            SingleFileFetcher.create(
                this,
                this,
                uri,
                ctx,
                actx,
                new SingleFileFetcher.CreationPolicy(
                    ctx.getMaxNonSplitfileRetries(), 0, false, true, true, initialMetadata != null),
                new SingleFileFetcher.CreationRuntime(context, realTimeFlag, -1));
      }
      String overrideMIME = ctx.getOverrideMIME();
      if (overrideMIME != null) expectedMIME = overrideMIME;
    }
    return true;
  }

  private void scheduleIfReady(ClientContext context) {
    // schedule() may deactivate stuff, so store it now.
    if (currentState != null && !finished) {
      if (initialMetadata != null
          && currentState instanceof SingleFileFetcher fetcher
          && !resumedFetcher) {
        fetcher.startWithMetadata(initialMetadata, context);
      } else {
        currentState.schedule(context);
      }
    }
  }

  @Override
  protected void clearCountersOnRestart() {
    this.archiveRestarts = 0;
    this.expectedMIME = null;
    this.expectedSize = 0;
    this.finalBlocksRequired = 0;
    this.finalBlocksTotal = 0;
    super.clearCountersOnRestart();
  }

  /**
   * Called when the request succeeds.
   *
   * @param state The ClientGetState which retrieved the data.
   */
  @Override
  public void onSuccess(
      StreamGenerator streamGenerator,
      ClientMetadata clientMetadata,
      List<? extends Compressor> decompressors,
      ClientGetState state,
      ClientContext context) {
    if (LOG.isDebugEnabled()) LOG.debug("Succeeded from {} on {}", state, this);
    // Fetching the container is essentially a full success, we should update the latest known good.
    context.uskManager.checkUSK(uri, persistent(), false);

    if (!finalizeBlobWriterOrForwardError(context)) return;

    String mimeType = clientMetadata == null ? null : clientMetadata.getMIMEType();
    if (!ensureCompatibleExtensionOrForwardError(mimeType, context)) return;

    markFinishedAndSetMIME(mimeType);

    long maxLen = computeMaxLen();
    try {
      FetchResult result =
          processStreams(streamGenerator, clientMetadata, decompressors, maxLen, context);
      context.getJobRunner(persistent()).setCheckpointASAP();
      clientCallback.onSuccess(result, ClientGetter.this);
    } catch (Exception e) {
      FetchException ex = mapToFetchException(e);
      onFailure(ex, state, context, true);
    }
  }

  @SuppressWarnings("BooleanMethodIsAlwaysInverted")
  private boolean finalizeBlobWriterOrForwardError(ClientContext context) {
    try {
      if (binaryBlobWriter != null && !dontFinalizeBlobWriter) binaryBlobWriter.finalizeBucket();
      return true;
    } catch (IOException | BinaryBlobAlreadyClosedException e) {
      String msg =
          e instanceof BinaryBlobAlreadyClosedException
              ? BLOB_STREAM_ALREADY_CLOSED_PREFIX + e
              : BLOB_STREAM_FAIL_PREFIX + e;
      onFailure(new FetchException(FetchExceptionMode.BUCKET_ERROR, msg, e), null, context);
      return false;
    }
  }

  private boolean ensureCompatibleExtensionOrForwardError(String mimeType, ClientContext context) {
    if (forceCompatibleExtension != null && ctx.getFilterData()) {
      if (mimeType == null) {
        onFailure(
            new FetchException(
                FetchExceptionMode.MIME_INCOMPATIBLE_WITH_EXTENSION,
                "No MIME type but need specific extension \"" + forceCompatibleExtension + "\""),
            null,
            context);
        return false;
      }
      try {
        checkCompatibleExtension(mimeType);
      } catch (FetchException e) {
        onFailure(e, null, context);
        return false;
      }
    }
    return true;
  }

  private void markFinishedAndSetMIME(String mimeType) {
    synchronized (this) {
      finished = true;
      currentState = null;
      expectedMIME = mimeType;
    }
  }

  private long computeMaxLen() {
    long maxLen = -1;
    synchronized (this) {
      if (expectedSize > 0) maxLen = expectedSize;
    }
    if (ctx.getFilterData() && maxLen >= 0) {
      maxLen = expectedSize * 2 + 1024;
    }
    if (maxLen == -1) {
      maxLen = Math.max(ctx.getMaxTempLength(), ctx.getMaxOutputLength());
    }
    return maxLen;
  }

  private FetchResult processStreams(
      StreamGenerator streamGenerator,
      ClientMetadata clientMetadata,
      List<? extends Compressor> decompressors,
      long maxLen,
      ClientContext context)
      throws IOException, URISyntaxException {
    Bucket finalResult = null;
    boolean createdTempResult = false;
    boolean completed = false;
    try (PipedOutputStream dataOutput = new PipedOutputStream();
        PipedInputStream dataInput = new PipedInputStream()) {
      createdTempResult = (returnBucket == null);
      finalResult =
          createdTempResult
              ? context.getBucketFactory(persistent()).makeBucket(maxLen)
              : returnBucket;
      if (LOG.isDebugEnabled())
        LOG.debug("Writing final data to {} return bucket is {}", finalResult, returnBucket);
      dataOutput.connect(dataInput);

      DecompressionSetup dec = setupDecompression(dataInput, decompressors, maxLen);
      FetchResult result =
          runWorkerAndStream(
              streamGenerator,
              clientMetadata,
              finalResult,
              dec.processedInput,
              dataOutput,
              dec.manager,
              context);
      completed = true;
      return result;
    } finally {
      if (!completed && createdTempResult && finalResult != null) {
        try {
          finalResult.free();
        } catch (Exception freeErr) {
          LOG.warn("Failed to free temporary result bucket after error: {}", freeErr, freeErr);
        }
      }
    }
  }

  private record DecompressionSetup(
      InputStream processedInput, DecompressorThreadManager manager) {}

  private DecompressionSetup setupDecompression(
      PipedInputStream dataInput, List<? extends Compressor> decompressors, long maxLen)
      throws IOException {
    if (decompressors == null) {
      return new DecompressionSetup(dataInput, null);
    }
    if (LOG.isDebugEnabled()) LOG.debug("Decompressing...");
    DecompressorThreadManager manager =
        new DecompressorThreadManager(dataInput, decompressors, maxLen);
    InputStream processed = manager.execute();
    return new DecompressionSetup(processed, manager);
  }

  private String computeMime(ClientMetadata clientMetadata) {
    String mimeType = (clientMetadata == null) ? null : clientMetadata.getMIMEType();
    if (ctx.getOverrideMIME() != null) mimeType = ctx.getOverrideMIME();
    return mimeType;
  }

  private FetchResult runWorkerAndStream(
      StreamGenerator streamGenerator,
      ClientMetadata initialMetadata,
      Bucket finalResult,
      InputStream processedDataInput,
      PipedOutputStream dataOutput,
      DecompressorThreadManager decompressorManager,
      ClientContext context)
      throws IOException, URISyntaxException {
    FetchResult result = new FetchResult(initialMetadata, finalResult);
    try (OutputStream output = finalResult.getOutputStream()) {
      ClientGetWorkerThread worker =
          new ClientGetWorkerThread(
              new BufferedInputStream(processedDataInput),
              output,
              uri,
              hashes,
              new ClientGetWorkerThread.Options(
                  computeMime(initialMetadata),
                  ctx.getSchemeHostAndPort(),
                  ctx.getFilterData(),
                  ctx.getCharset(),
                  ctx.getPrefetchHook(),
                  ctx.getTagReplacer(),
                  context.linkFilterExceptionProvider));
      worker.start();
      try {
        streamGenerator.writeTo(dataOutput, context);
      } catch (IOException e) {
        worker.getError();
        throw e;
      }

      if (LOG.isDebugEnabled()) LOG.debug("Waiting for hashing, filtration, and writing to finish");
      worker.waitFinished();

      if (decompressorManager != null) {
        if (LOG.isDebugEnabled()) LOG.debug("Waiting for decompression to finalize");
        decompressorManager.waitFinished();
      }

      ClientMetadata workerMeta = worker.getClientMetadata();
      if (workerMeta != null) {
        result = new FetchResult(workerMeta, finalResult);
      }
      synchronized (this) {
        this.expectedMIME = result.getMimeType();
        this.expectedSize = result.size();
      }
    }
    return result;
  }

  private FetchException mapToFetchException(Throwable t) {
    if (t == null) {
      LOG.error("Caught null Throwable while mapping to FetchException");
      return new FetchException(FetchExceptionMode.INTERNAL_ERROR);
    }
    switch (t) {
      case UnsafeContentTypeException e -> {
        LOG.info("Error filtering content: will not validate", e);
        return e.createFetchException(
            ctx.getOverrideMIME() != null ? ctx.getOverrideMIME() : expectedMIME, expectedSize);
      }
      case URISyntaxException e -> {
        LOG.error("URISyntaxException converting a Crypta URI to a URI!: {}", e, e);
        return new FetchException(FetchExceptionMode.INTERNAL_ERROR, e);
      }
      case CompressionOutputSizeException e -> {
        LOG.error(CAUGHT_MESSAGE, e, e);
        return new FetchException(FetchExceptionMode.TOO_BIG, e);
      }
      case InsufficientDiskSpaceException _ -> {
        return new FetchException(FetchExceptionMode.NOT_ENOUGH_DISK_SPACE);
      }
      case FetchException e -> {
        LOG.error(CAUGHT_MESSAGE, e, e);
        return e;
      }
      case IOException e -> {
        LOG.error(CAUGHT_MESSAGE, e, e);
        return new FetchException(FetchExceptionMode.BUCKET_ERROR, e);
      }
      default -> {
        LOG.error(CAUGHT_MESSAGE, t, t);
        return new FetchException(FetchExceptionMode.INTERNAL_ERROR, t);
      }
    }
  }

  @Override
  public void onSuccess(
      File tempFile,
      long length,
      ClientMetadata metadata,
      ClientGetState state,
      ClientContext context) {
    context.uskManager.checkUSK(uri, persistent(), false);
    if (!finalizeBlobWriterOrForwardError(context)) return;
    File completionFile = getCompletionFile();
    assert (completionFile != null);
    assert (!ctx.getFilterData());
    LOG.info("Succeeding via truncation from {} to {}", tempFile, completionFile);
    try {
      FetchResult result =
          completeViaTruncationInternal(tempFile, length, metadata, completionFile, context);
      context.getJobRunner(persistent()).setCheckpointASAP();
      clientCallback.onSuccess(result, ClientGetter.this);
    } catch (Exception e) {
      LOG.error("Failed while completing via truncation: {}", e, e);
      FetchException ex = mapToFetchException(e);
      onFailure(ex, state, context, true);
      try {
        java.nio.file.Files.delete(tempFile.toPath());
      } catch (IOException ioe) {
        LOG.warn("Failed to delete temp file {}", tempFile, ioe);
      }
    }
  }

  private FetchResult completeViaTruncationInternal(
      File tempFile,
      long length,
      ClientMetadata metadata,
      File completionFile,
      ClientContext context)
      throws IOException, FetchException, URISyntaxException {
    try (RandomAccessFile raf = new RandomAccessFile(tempFile, "rw");
        InputStream is = new BufferedInputStream(new FileInputStream(raf.getFD()))) {
      if (raf.length() < length)
        throw new IOException("File is shorter than target length " + length);
      raf.setLength(length);

      ClientGetWorkerThread worker =
          new ClientGetWorkerThread(
              is,
              new NullOutputStream(),
              uri,
              hashes,
              new ClientGetWorkerThread.Options(
                  null,
                  ctx.getSchemeHostAndPort(),
                  false,
                  null,
                  ctx.getPrefetchHook(),
                  ctx.getTagReplacer(),
                  context.linkFilterExceptionProvider));
      worker.start();
      if (LOG.isDebugEnabled()) LOG.debug("Waiting for hashing, filtration, and writing to finish");
      worker.waitFinished();
    }

    if (!FileUtil.moveTo(tempFile, completionFile))
      throw new FetchException(
          FetchExceptionMode.BUCKET_ERROR, "Failed to rename from temp file " + tempFile);

    synchronized (this) {
      finished = true;
      currentState = null;
      expectedMIME = metadata.getMIMEType();
      expectedSize = length;
    }
    return new FetchResult(metadata, returnBucket);
  }

  /**
   * Called when the request fails. Retrying will have already been attempted by the calling state,
   * if appropriate; we have tried to get the data, and given up.
   *
   * @param e The reason for failure, in the form of a FetchException.
   * @param state The failing state.
   */
  @Override
  public void onFailure(FetchException e, ClientGetState state, ClientContext context) {
    onFailure(e, state, context, false);
  }

  /**
   * Handle a terminal failure for this request.
   *
   * <p>This internal variant allows callers to force completion semantics even when {@link
   * #finished} may already be true (for example when invoked from a success path that finalizes
   * state). It normalizes the supplied {@link FetchException}, updates persisted state, and
   * notifies the client callback exactly once per logical failure.
   *
   * @param e normalized failure explaining the reason the fetch cannot proceed; may be adjusted to
   *     include expected size or MIME if known at failure time
   * @param state the state that raised the failure; used for logging and consistency checks
   * @param context client context for scheduling and persistence side effects
   * @param force when {@code true}, proceed with failure handling even if {@link #finished} is
   *     already set due to a prior path; callers must ensure idempotency
   */
  public void onFailure(
      FetchException e, ClientGetState state, ClientContext context, boolean force) {
    if (LOG.isDebugEnabled()) LOG.debug("Failed from {} : {} on {}", state, e, this, e);
    if (expectedSize > 0 && (e.getExpectedSize() <= 0 || finalBlocksTotal != 0))
      e = e.withExpectedSize(expectedSize);

    context.getJobRunner(persistent()).setCheckpointASAP();
    e = adjustTooBigForFilter(e);

    FetchException pending = handleArchiveRestart(e, context);
    if (pending == null) return; // Restarted successfully
    e = pending;

    boolean alreadyFinished = updateStateOnFailure(e, force);
    if (!alreadyFinished) {
      e = maybeFinalizeBlobOnFailure(e, force);
    }

    e = normalizeFetchException(e);
    if (LOG.isDebugEnabled()) LOG.debug("onFailure({}, {}) on {} for {}", e, state, this, uri, e);
    if (!alreadyFinished) clientCallback.onFailure(e);
  }

  private FetchException adjustTooBigForFilter(FetchException e) {
    if (e.mode == FetchExceptionMode.TOO_BIG && ctx.getFilterData() && e.finalizedSize()) {
      String mime = e.getExpectedMimeType();
      if (ctx.getOverrideMIME() != null) mime = ctx.getOverrideMIME();
      if (mime != null && !mime.isEmpty()) {
        UnsafeContentTypeException unsafe = ContentFilter.checkMIMEType(mime);
        if (unsafe != null) return unsafe.recreateFetchException(e, mime);
      }
    }
    return e;
  }

  private FetchException handleArchiveRestart(FetchException e, ClientContext context) {
    if (e.mode != FetchExceptionMode.ARCHIVE_RESTART) return e;
    int ar;
    synchronized (this) {
      archiveRestarts++;
      ar = archiveRestarts;
    }
    if (LOG.isDebugEnabled()) LOG.debug("Archive restart on {} ar={}", this, ar);
    if (ar > ctx.getMaxArchiveRestarts())
      return new FetchException(FetchExceptionMode.TOO_MANY_ARCHIVE_RESTARTS);
    try {
      start(context);
      return null; // restarted
    } catch (FetchException e1) {
      return e1; // try again with the new exception
    }
  }

  private boolean updateStateOnFailure(FetchException e, boolean force) {
    boolean alreadyFinished = false;
    synchronized (this) {
      if (finished && !force) {
        if (!cancelled)
          LOG.error("Already finished - not calling callbacks on {}", this, new Exception("error"));
        alreadyFinished = true;
      }
      finished = true;
      currentState = null;
      String mime = e.getExpectedMimeType();
      if (mime != null) this.expectedMIME = mime;
    }
    return alreadyFinished;
  }

  private FetchException maybeFinalizeBlobOnFailure(FetchException e, boolean force) {
    try {
      if (binaryBlobWriter != null && !dontFinalizeBlobWriter) binaryBlobWriter.finalizeBucket();
    } catch (IOException | BinaryBlobAlreadyClosedException ex) {
      if (e.mode != FetchExceptionMode.CANCELLED
          && !force
          && !(ex instanceof BinaryBlobAlreadyClosedException
              && e.mode == FetchExceptionMode.BUCKET_ERROR)) {
        String msg =
            ex instanceof BinaryBlobAlreadyClosedException
                ? BLOB_STREAM_ALREADY_CLOSED_PREFIX + ex
                : BLOB_STREAM_FAIL_PREFIX + ex;
        e = new FetchException(FetchExceptionMode.BUCKET_ERROR, msg, ex);
      }
    }
    return e;
  }

  private FetchException normalizeFetchException(FetchException e) {
    if (e.errorCodes != null && e.errorCodes.isOneCodeOnly())
      e = new FetchException(e.errorCodes.getFirstCodeFetch());
    if (e.mode == FetchExceptionMode.DATA_NOT_FOUND && super.successfulBlocks > 0)
      e = new FetchException(e, FetchExceptionMode.ALL_DATA_NOT_FOUND);
    return e;
  }

  /**
   * Cancel the request. This must result in onFailure() being called in order to send the client a
   * cancel FetchException, and to removeFrom() the state.
   */
  @Override
  public void cancel(ClientContext context) {
    if (LOG.isDebugEnabled()) LOG.debug("Cancelling {}", this);
    ClientGetState s;
    synchronized (this) {
      if (super.cancel()) {
        if (LOG.isDebugEnabled()) LOG.debug("Already cancelled {}", this);
        return;
      }
      s = currentState;
    }
    if (s != null) {
      if (LOG.isDebugEnabled()) LOG.debug("Cancelling {} for {} instance {}", s, this, this);
      s.cancel(context);
    } else {
      if (LOG.isDebugEnabled()) LOG.debug("Nothing to cancel");
    }
  }

  /** Has the fetch completed? */
  @Override
  public synchronized boolean isFinished() {
    return finished || cancelled;
  }

  /** What was the URI we were fetching? */
  @Override
  public FreenetURI getURI() {
    return uri;
  }

  /**
   * Notify clients listening to our ClientEventProducer of the current progress, in the form of a
   * SplitfileProgressEvent.
   */
  @Override
  protected void innerNotifyClients(ClientContext context) {
    SplitfileProgressEvent e;
    synchronized (this) {
      int total = this.totalBlocks;
      int minSuccess = this.minSuccessBlocks;
      boolean finalized = blockSetFinalized;
      if (this.finalBlocksRequired != 0) {
        total = finalBlocksTotal;
        minSuccess = finalBlocksRequired;
        finalized = true;
      }
      e =
          new SplitfileProgressEvent(
              total,
              this.successfulBlocks,
              this.latestSuccess,
              this.failedBlocks,
              this.fatallyFailedBlocks,
              this.latestFailure,
              minSuccess,
              0,
              finalized);
    }
    // Already off-thread.
    ctx.getEventProducer().produceEvent(e, context);
  }

  /**
   * Notify clients that some part of the request has been sent to the network i.e. we have finished
   * checking the datastore for at least some part of the request. Sent once only for any given
   * request.
   */
  @Override
  protected void innerToNetwork(ClientContext context) {
    context
        .getJobRunner(persistent())
        .queueNormalOrDrop(
            context1 -> {
              ctx.getEventProducer().produceEvent(new SendingToNetworkEvent(), context1);
              return false;
            });
  }

  /**
   * Called when no more blocks will be added to the total, and therefore we can confidently display
   * a percentage for the overall progress. Will notify clients with a SplitfileProgressEvent.
   */
  @Override
  public void onBlockSetFinished(ClientGetState state, ClientContext context) {
    if (LOG.isDebugEnabled()) LOG.debug("Set finished");
    blockSetFinalized(context);
  }

  /**
   * Called when the current state creates a new state, and we switch to that. For example, a
   * SingleFileFetcher might switch to a SplitFileFetcher. Sometimes this will be called with
   * oldState not equal to our currentState; this means that a subsidiary request has changed state,
   * so we ignore it.
   */
  @Override
  public void onTransition(
      ClientGetState oldState, ClientGetState newState, ClientContext context) {
    synchronized (this) {
      if (currentState == oldState) {
        currentState = newState;
        if (LOG.isDebugEnabled())
          LOG.debug(
              "Transition: {} -> {} on {} persistent = {} instance = {}",
              oldState,
              newState,
              this,
              persistent(),
              this,
              new Exception(DEBUG_EXCEPTION_MESSAGE));
      } else {
        if (LOG.isDebugEnabled())
          LOG.debug(
              "Ignoring transition: {} -> {} because current = {} on {} persistent = {}",
              oldState,
              newState,
              currentState,
              this,
              persistent(),
              new Exception(DEBUG_EXCEPTION_MESSAGE));
        return;
      }
    }
    if (persistent()) context.jobRunner.setCheckpointASAP();
  }

  /**
   * Whether this request can be restarted in its current state.
   *
   * @return {@code true} when no active state is running or the request has finished; otherwise
   *     {@code false}
   */
  public boolean canRestart() {
    if (currentState != null && !finished) {
      if (LOG.isDebugEnabled()) LOG.debug("Cannot restart because not finished for {}", uri);
      return false;
    }
    return true;
  }

  /**
   * Restart the request.
   *
   * @param redirect Use this URI instead of the old one.
   * @param filterData Whether to filter the data
   * @param context The client context.
   * @return True if we successfully restarted, false if we can't restart.
   * @throws FetchException If something went wrong.
   */
  public boolean restart(FreenetURI redirect, boolean filterData, ClientContext context)
      throws FetchException {
    ctx.setFilterData(filterData);
    return start(true, redirect, context);
  }

  @Override
  public String toString() {
    return super.toString();
  }

  // Identity semantics are inherited from ClientRequester. Override explicitly to
  // satisfy static analysis while preserving behavior.
  @Override
  public boolean equals(Object obj) {
    return super.equals(obj);
  }

  @Override
  public int hashCode() {
    return super.hashCode();
  }

  // Note: binary blob data is not persisted; streams do not survive shutdown.

  /**
   * Add an accessed key block to the binary blob collector.
   *
   * @param block the {@link ClientKeyBlock} describing the fetched block and its client key; must
   *     not be {@code null}
   * @param context client context used for failure routing if the writer cannot accept data
   */
  protected void addKeyToBinaryBlob(ClientKeyBlock block, ClientContext context) {
    if (binaryBlobWriter == null) return;
    synchronized (this) {
      if (finished) {
        if (LOG.isDebugEnabled())
          LOG.debug("Add key to binary blob for {} but already finished", this);
        return;
      }
    }
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Adding key {} to {}",
          block.getClientKey().getURI(),
          this,
          new Exception(DEBUG_EXCEPTION_MESSAGE));
    try {
      binaryBlobWriter.addKey(block, context);
    } catch (IOException e) {
      LOG.error("Failed to write key to binary blob stream: {}", e, e);
      onFailure(
          new FetchException(
              FetchExceptionMode.BUCKET_ERROR, "Failed to write key to binary blob stream: " + e),
          null,
          context);
    } catch (BinaryBlobAlreadyClosedException e) {
      LOG.error("Failed to write key to binary blob stream (already closed??): {}", e, e);
      onFailure(
          new FetchException(
              FetchExceptionMode.BUCKET_ERROR,
              "Failed to write key to binary blob stream (already closed??): " + e),
          null,
          context);
    }
  }

  /**
   * Whether key collection into a binary blob is currently active.
   *
   * @return {@code true} when a {@link BinaryBlobWriter} is configured and open; {@code false}
   *     otherwise
   */
  protected boolean collectingBinaryBlob() {
    return binaryBlobWriter != null;
  }

  /**
   * Notified when the MIME type of the final data becomes known.
   *
   * <p>If filtering is enabled, the MIME is validated and an error is raised when the content type
   * is considered unsafe or incompatible with a forced extension. The method may schedule
   * additional bookkeeping work asynchronously.
   *
   * @param clientMetadata metadata discovered so far for the fetch; may be trivial and not contain
   *     MIME information
   * @param context client context used for scheduling follow‑up jobs related to metadata
   * @throws FetchException when the MIME type fails validation or violates a configured constraint
   */
  @Override
  public void onExpectedMIME(ClientMetadata clientMetadata, ClientContext context)
      throws FetchException {
    if (finalizedMetadata) return;
    String mime = null;
    if (!clientMetadata.isTrivial()) mime = clientMetadata.getMIMEType();
    if (ctx.getOverrideMIME() != null) mime = ctx.getOverrideMIME();
    if (mime == null || mime.isEmpty()) return;
    synchronized (this) {
      expectedMIME = mime;
    }
    if (ctx.getFilterData()) {
      UnsafeContentTypeException e = ContentFilter.checkMIMEType(mime);
      if (e != null) {
        throw e.createFetchException(mime, expectedSize);
      }
      if (forceCompatibleExtension != null) checkCompatibleExtension(mime);
    }
    context
        .getJobRunner(persistent())
        .queueNormalOrDrop(
            new PersistentJob() {

              @Override
              public boolean run(ClientContext context) {
                String mime;
                synchronized (this) {
                  mime = expectedMIME;
                }
                ctx.getEventProducer().produceEvent(new ExpectedMIMEEvent(mime), context);
                return false;
              }
            });
  }

  private void checkCompatibleExtension(String mimeType) throws FetchException {
    FilterMIMEType type = ContentFilter.getMIMEType(mimeType);
    if (type == null)
      // Not our problem, will be picked up elsewhere.
      return;
    if (!DefaultMIMETypes.isValidExt(mimeType, forceCompatibleExtension))
      throw new FetchException(FetchExceptionMode.MIME_INCOMPATIBLE_WITH_EXTENSION);
  }

  /** Called when we have some idea of the length of the final data */
  @Override
  public void onExpectedSize(final long size, ClientContext context) {
    if (finalizedMetadata) return;
    if (finalBlocksRequired != 0) return;
    expectedSize = size;
    context
        .getJobRunner(persistent())
        .queueNormalOrDrop(
            context1 -> {
              ctx.getEventProducer().produceEvent(new ExpectedFileSizeEvent(size), context1);
              return false;
            });
  }

  /** Called when we are fairly sure that the expected MIME and size will not change. */
  @Override
  public void onFinalizedMetadata() {
    finalizedMetadata = true;
  }

  /**
   * Report whether the expected MIME and size are final for this request.
   *
   * @return {@code true} once {@link #onFinalizedMetadata()} has been called and future metadata
   *     updates are not expected; {@code false} otherwise
   */
  @SuppressWarnings("unused")
  public boolean finalizedMetadata() {
    return finalizedMetadata;
  }

  /**
   * Get the expected MIME type if it is currently known.
   *
   * @return a MIME type string representing the predicted final content type, or {@code null} if
   *     not yet determined
   */
  public synchronized String expectedMIME() {
    return expectedMIME;
  }

  /**
   * Get the expected size of the returned data if currently known (may still change).
   *
   * @return a non‑negative number of bytes when the size is known; {@code 0} when unknown
   */
  public synchronized long expectedSize() {
    return expectedSize;
  }

  /**
   * Get the client callback that receives success and failure notifications for this request.
   *
   * @return the callback instance provided at construction time; never {@code null}
   */
  @SuppressWarnings("unused")
  public ClientGetCallback getClientCallback() {
    return clientCallback;
  }

  /**
   * Get the metadata snoop callback.
   *
   * @return the current metadata observer or {@code null} when not configured
   */
  public SnoopMetadata getMetaSnoop() {
    return snoopMeta;
  }

  /**
   * Set a callback to snoop on metadata during fetches. Call this before starting the request.
   *
   * @param newSnoop the replacement callback to observe metadata processing; use {@code null} to
   *     disable observation
   * @return the previous callback or {@code null} if none was set
   */
  @SuppressWarnings("UnusedReturnValue")
  public SnoopMetadata setMetaSnoop(SnoopMetadata newSnoop) {
    SnoopMetadata old = snoopMeta;
    snoopMeta = newSnoop;
    return old;
  }

  /**
   * Get the intermediate data snoop callback.
   *
   * @return the current bucket observer or {@code null} when not configured
   */
  public SnoopBucket getBucketSnoop() {
    return snoopBucket;
  }

  /**
   * Set a callback to snoop on buckets (all intermediary data - metadata, containers) during
   * fetches. Call this before starting the request.
   *
   * @param newSnoop the replacement callback to observe intermediary buckets; use {@code null} to
   *     disable observation
   * @return the previous callback or {@code null} if none was set
   */
  @SuppressWarnings("unused")
  public SnoopBucket setBucketSnoop(SnoopBucket newSnoop) {
    SnoopBucket old = snoopBucket;
    snoopBucket = newSnoop;
    return old;
  }

  /**
   * Expected number of final blocks required to complete the top‑level splitfile. Set when the
   * top‑level block layout becomes known and remains unchanged thereafter.
   */
  private int finalBlocksRequired;

  /**
   * Total number of final blocks in the top‑level splitfile. This is used with {@link
   * #finalBlocksRequired} to report progress.
   */
  private int finalBlocksTotal;

  @Override
  public void onExpectedTopSize(
      long size, long compressed, int blocksReq, int blocksTotal, ClientContext context) {
    if (finalBlocksRequired != 0 || finalBlocksTotal != 0) return;
    if (LOG.isDebugEnabled())
      LOG.debug(
          "New format metadata has top data: original size {} (compressed {}) blocks {} / {}",
          size,
          compressed,
          blocksReq,
          blocksTotal);
    onExpectedSize(size, context);
    this.finalBlocksRequired = this.minSuccessBlocks + blocksReq;
    this.finalBlocksTotal = this.totalBlocks + blocksTotal;
    notifyClients(context);
  }

  @Override
  public void onSplitfileCompatibilityMode(
      final CompatibilityMode min,
      final CompatibilityMode max,
      final byte[] customSplitfileKey,
      final boolean dontCompress,
      final boolean bottomLayer,
      final boolean definitiveAnyway,
      ClientContext context) {
    context
        .getJobRunner(persistent())
        .queueNormalOrDrop(
            context1 -> {
              ctx.getEventProducer()
                  .produceEvent(
                      new SplitfileCompatibilityModeEvent(
                          min,
                          max,
                          customSplitfileKey,
                          dontCompress,
                          bottomLayer || definitiveAnyway),
                      context1);
              return false;
            });
  }

  @Override
  public void onHashes(HashResult[] hashes, ClientContext context) {
    synchronized (this) {
      if (this.hashes != null) {
        if (!HashResult.strictEquals(hashes, this.hashes)) LOG.error("Two sets of hashes?!");
        return;
      }
      this.hashes = hashes;
    }
    HashResult[] clientHashes = hashes;
    if (persistent()) clientHashes = HashResult.copy(hashes);
    final HashResult[] h = clientHashes;
    context
        .getJobRunner(persistent())
        .queueNormalOrDrop(
            context1 -> {
              ctx.getEventProducer().produceEvent(new ExpectedHashesEvent(h), context1);
              return false;
            });
  }

  @Override
  public void enterCooldown(ClientGetState state, long wakeupTime, ClientContext context) {
    synchronized (this) {
      if (state != currentState) return;
    }
    if (wakeupTime != Long.MAX_VALUE) {
      // Already off-thread.
      ctx.getEventProducer().produceEvent(new EnterFiniteCooldownEvent(wakeupTime), context);
    }
  }

  @Override
  public void clearCooldown(ClientGetState state) {
    // Intentionally no-op: cooldown managed by states
  }

  /**
   * Return the final bucket used by the binary blob writer.
   *
   * <p>This is only meaningful when a {@link BinaryBlobWriter} was configured and finalized. The
   * caller owns the returned bucket and must manage its lifecycle.
   *
   * @return the final bucket produced by the blob writer, or {@code null} when no writer exists
   */
  public Bucket getBlobBucket() {
    return binaryBlobWriter.getFinalBucket();
  }

  @Override
  public byte[] getClientDetail(ChecksumChecker checker) throws IOException {
    if (clientCallback instanceof PersistentClientCallback callback) {
      return getClientDetail(callback, checker);
    } else return new byte[0];
  }

  /**
   * Called for a persistent request after startup to restore state and resume work.
   *
   * @param context client context providing services required to rehydrate state and queue work
   * @throws ResumeFailedException when stored state is incompatible, missing, or cannot be
   *     deserialized; the request should be treated as failed and re‑queued from scratch if needed
   */
  @Override
  public void innerOnResume(ClientContext context) throws ResumeFailedException {
    super.innerOnResume(context);
    if (currentState != null)
      try {
        currentState.onResume(context);
      } catch (FetchException e) {
        currentState = null;
        throw new ResumeFailedException(e);
      } catch (RuntimeException e) {
        // Severe serialization problems, lost a class silently etc.
        throw new ResumeFailedException(e);
      }
    // returnBucket is responsibility of the callback.
    notifyClients(context);
  }

  @Override
  protected ClientBaseCallback getCallback() {
    return clientCallback;
  }

  /**
   * Persist minimal progress information for simple requests.
   *
   * <p>When the fetch is a single, final splitfile operation, this writes enough information to
   * resume. Otherwise, a marker is written indicating that a trivial resume is not possible. The
   * caller remains responsible for writing other metadata such as expected MIME and hashes.
   *
   * @param dos output stream used to persist the progress marker and any required resume data; the
   *     caller is responsible for closing the stream
   * @return {@code true} when trivial progress data was written and the request can be trivially
   *     resumed; {@code false} when a trivial resume is not applicable for the current state
   * @throws IOException if the stream cannot be written or the underlying destination fails
   */
  public boolean writeTrivialProgress(DataOutputStream dos) throws IOException {
    if (!(this.binaryBlobWriter == null
        && this.snoopBucket == null
        && this.snoopMeta == null
        && initialMetadata == null)) {
      dos.writeBoolean(false);
      return false;
    }
    ClientGetState state;
    synchronized (this) {
      state = currentState;
    }
    if (!(state instanceof SplitFileFetcher fetcher)) {
      dos.writeBoolean(false);
      return false;
    }
    if (fetcher.cb != this) {
      dos.writeBoolean(false);
      return false;
    }
    return fetcher.writeTrivialProgress(dos);
  }

  /**
   * Attempt to resume the request from previously written trivial progress data.
   *
   * <p>If a trivial progress marker is present, reconstructs the {@code SplitFileFetcher} state and
   * marks this getter as resumed. If the marker is absent or the stored data cannot be parsed, the
   * method returns {@code false} and the caller should fall back to a full resume or restart.
   *
   * @param dis input stream positioned at the trivial progress marker and data
   * @param context client context used to rebuild the necessary state
   * @return {@code true} when the trivial resume succeeds; {@code false} when no marker exists or
   *     the stored data is invalid
   * @throws IOException if reading from the input stream fails
   */
  public boolean resumeFromTrivialProgress(DataInputStream dis, ClientContext context)
      throws IOException {
    if (dis.readBoolean()) {
      try {
        currentState = new SplitFileFetcher(this, dis, context);
        resumedFetcher = true;
        return true;
      } catch (StorageFormatException | ResumeFailedException | IOException e) {
        LOG.error(RESTORE_FROM_SPLITFILE_FAILED_MSG, e, e);
        return false;
      }
    } else return false;
  }

  /**
   * Whether a {@code SplitFileFetcher} was reconstructed from trivial progress during resume.
   *
   * @return {@code true} when {@link #resumeFromTrivialProgress(DataInputStream, ClientContext)}
   *     successfully rebuilt the fetcher; {@code false} otherwise
   */
  public boolean resumedFetcher() {
    return resumedFetcher;
  }

  @Override
  public void onShutdown(ClientContext context) {
    ClientGetState state;
    synchronized (this) {
      state = currentState;
    }
    if (state != null) state.onShutdown(context);
  }

  @Override
  public boolean isCurrentState(ClientGetState state) {
    synchronized (this) {
      return currentState == state;
    }
  }

  @Override
  public File getCompletionFile() {
    if (returnBucket == null) return null;
    if (!(returnBucket instanceof FileBucket)) return null;
    // Just a plain FileBucket. Not a temporary, not delayed free, etc.
    return ((FileBucket) returnBucket).getFile();
  }
}

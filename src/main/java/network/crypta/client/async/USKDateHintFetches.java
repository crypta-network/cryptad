package network.crypta.client.async;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Random;
import network.crypta.client.ClientMetadata;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.InsertContext.CompatibilityMode;
import network.crypta.crypt.HashResult;
import network.crypta.keys.ClientKey;
import network.crypta.keys.ClientSSK;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.Key;
import network.crypta.keys.USK;
import network.crypta.support.api.Bucket;
import network.crypta.support.compress.Compressor;
import network.crypta.support.compress.DecompressorThreadManager;
import network.crypta.support.io.BucketTools;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Coordinates Date-Based Request (DBR) hint fetching for a {@link USKFetcher}.
 *
 * <p>This helper schedules lightweight hint fetches that probe a few date-derived editions of an
 * updatable key. Each hint is fetched as a single block, decoded, and parsed for a suggested
 * edition number. The result is then forwarded to {@link USKManager} as a non-authoritative hint so
 * the owning {@link USKFetcher} can bias its probing logic. Typical usage is to create an instance
 * alongside the fetcher and call {@link #maybeStart(ClientContext)} once per polling cycle,
 * followed by {@link #cancelAll(ClientContext)} when the fetcher shuts down.
 *
 * <p>Instances are mutable and synchronize on {@code this} for state such as scheduled flags and
 * active attempts. The set of in-flight attempts is small (one per {@link USKDateHint.Type}) and is
 * pruned when a more precise hint succeeds. The helper is intentionally conservative: if hints are
 * disabled or already scheduled, it performs no work and leaves the fetcher to continue its normal
 * probing.
 *
 * <ul>
 *   <li><strong>Responsibilities</strong>: schedule DBR hint fetches, parse hint payloads, and
 *       forward valid editions to {@link USKManager}.
 *   <li><strong>State model</strong>: scheduled once per cycle; attempts cleared on completion or
 *       cancellation.
 *   <li><strong>Threading</strong>: internal collections are guarded by synchronization; callbacks
 *       may run on scheduler threads.
 * </ul>
 */
final class USKDateHintFetches {
  /** Logger for hint scheduling, parsing, and failure diagnostics. */
  private static final Logger LOG = LoggerFactory.getLogger(USKDateHintFetches.class);

  /** Owning fetcher that supplies priority class and completion hooks for DBR work. */
  private final USKFetcher owner;

  /** Manager that consumes DBR hint updates and schedules follow-up probes. */
  private final USKManager uskManager;

  /** Original USK used to derive hint request URIs and to copy with hinted editions. */
  private final USK origUSK;

  /** Base fetch context used for size limits and configuration on parse. */
  private final FetchContext ctx;

  /** Fetch context specialized for DBR hint requests, including retry behavior. */
  private final FetchContext ctxDBR;

  /** Parent requester that defines persistence and real-time scheduling policies. */
  private final ClientRequester parent;

  /** Cached real-time flag from the parent to avoid repeated lookups. */
  private final boolean realTimeFlag;

  /** Active DBR attempts, guarded by {@code this} for thread-safe access. */
  private final HashSet<DBRAttempt> attempts = new HashSet<>();

  /** Whether DBR scheduling has already been attempted for the current cycle. */
  private boolean scheduled;

  /** Count of successfully parsed hints during the current scheduling cycle. */
  private int hintsFound;

  /** Count of hint attempts started during the current scheduling cycle. */
  private int hintsStarted;

  /**
   * Creates a coordinator for DBR hint fetches associated with a single USK fetcher.
   *
   * <p>The instance is bound to the provided contexts and parent requester. It does not schedule
   * work until {@link #maybeStart(ClientContext)} is invoked, and it does not mutate the contexts.
   * Callers should reuse the instance for the lifetime of the owning {@link USKFetcher}.
   *
   * @param owner owning fetcher that provides priority and lifecycle callbacks; must not be null
   * @param uskManager manager to receive parsed hint updates; must not be null
   * @param origUSK base USK used to derive hint URIs and to copy editions; must not be null
   * @param ctx main fetch context used for limits and parsing decisions; must not be null
   * @param ctxDBR fetch context for DBR requests including retry policy; must not be null
   * @param parent requester whose scheduling flags govern the hint fetches; must not be null
   */
  USKDateHintFetches(
      USKFetcher owner,
      USKManager uskManager,
      USK origUSK,
      FetchContext ctx,
      FetchContext ctxDBR,
      ClientRequester parent) {
    this.owner = owner;
    this.uskManager = uskManager;
    this.origUSK = origUSK;
    this.ctx = ctx;
    this.ctxDBR = ctxDBR;
    this.parent = parent;
    this.realTimeFlag = parent.realTimeFlag();
  }

  /**
   * Reports whether there are any in-flight DBR attempts.
   *
   * <p>This check is synchronized and reflects the current contents of the internal attempt set. It
   * is used by the owning fetcher to decide whether to wait for hint work to settle or to start
   * additional probing. The result is a snapshot and may change immediately after return.
   *
   * @return {@code true} when at least one DBR attempt is still outstanding; otherwise {@code
   *     false}
   */
  boolean hasOutstanding() {
    synchronized (this) {
      return !attempts.isEmpty();
    }
  }

  /**
   * Schedules DBR hint fetches if they have not been scheduled yet and are not disabled.
   *
   * <p>The method is intended to be called once per polling cycle. If hints are disabled or the
   * method has already been invoked, no work is scheduled and {@code false} is returned. When
   * scheduling proceeds, one attempt is created per {@link USKDateHint.Type} and registered with
   * the appropriate scheduler; each attempt runs independently and reports completion via the
   * owning fetcher.
   *
   * @param context client context used to access schedulers and bucket factories; must not be null
   * @return {@code true} when hint fetches were scheduled; {@code false} when skipped or disabled
   */
  boolean maybeStart(ClientContext context) {
    synchronized (this) {
      if (scheduled || ctx.getIgnoreUSKDatehints()) {
        scheduled = true;
        return false;
      }
      scheduled = true;
    }

    USKDateHint date = USKDateHint.now();
    ClientSSK[] ssks = date.getRequestURIs(origUSK);
    if (ssks.length == 0) return false;

    DBRAttempt[] created = new DBRAttempt[ssks.length];
    for (int i = 0; i < ssks.length; i++) {
      ClientKey key = ssks[i];
      DBRAttempt attempt = new DBRAttempt(key, context, USKDateHint.Type.values()[i]);
      synchronized (this) {
        attempts.add(attempt);
      }
      created[i] = attempt;
    }
    synchronized (this) {
      hintsStarted = created.length;
    }

    for (DBRAttempt attempt : created) attempt.start(context);
    return true;
  }

  /**
   * Cancels all in-flight DBR attempts and clears internal tracking.
   *
   * <p>This method is idempotent and may be called multiple times; subsequent calls will simply
   * observe an empty attempt set. It is typically invoked when the owning request is canceled or
   * shut down, ensuring that no more hint callbacks will fire.
   *
   * @param context client context used to propagate cancellation to schedulers; must not be null
   */
  void cancelAll(ClientContext context) {
    DBRAttempt[] toCancel;
    synchronized (this) {
      toCancel = attempts.toArray(new DBRAttempt[0]);
      attempts.clear();
    }
    for (DBRAttempt attempt : toCancel) attempt.cancel(context);
  }

  /**
   * Decides whether to add random edition probes based on prior hint outcomes.
   *
   * <p>The decision is stochastic to spread load: the method samples a random value in a range
   * based on how many hints were started and compares it to how many were successfully parsed. On
   * the first loop, the method always returns {@code false} to avoid extra work before hints have
   * had a chance to complete.
   *
   * @param random random source used to make a probabilistic choice; must not be null
   * @param firstLoop {@code true} on the first polling loop, which suppresses extra probes
   * @return {@code true} when a random edition probe should be added; otherwise {@code false}
   */
  boolean shouldAddRandomEditions(Random random, boolean firstLoop) {
    if (firstLoop) return false;
    int started;
    int found;
    synchronized (this) {
      started = hintsStarted;
      found = hintsFound;
    }
    return random.nextInt(started + 1) >= found;
  }

  /**
   * Represents one DBR hint fetch attempt for a specific precision level.
   *
   * <p>This callback object owns a {@link SimpleSingleFileFetcher} and implements the completion
   * interface to parse hint payloads. Attempts are removed from the outer set on completion and may
   * cancel less precise siblings when a higher-precision hint succeeds.
   */
  private final class DBRAttempt implements GetCompletionCallback {
    /** Fetcher that performs the single-block hint request. */
    final SimpleSingleFileFetcher fetcher;

    /** Date-hint precision represented by this attempt. */
    final USKDateHint.Type type;

    /**
     * Builds a DBR attempt around the given key and precision type.
     *
     * <p>The created fetcher is configured to avoid altering parent counters and to honor the
     * DBR-specific fetch context, while inheriting priority from the owning fetcher. Scheduling is
     * deferred until {@link #start(ClientContext)} is called.
     *
     * @param key client key that identifies the hint block to fetch; must not be null
     * @param context client context used for initial configuration; must not be null
     * @param type precision level represented by the hint document; must not be null
     */
    DBRAttempt(ClientKey key, ClientContext context, USKDateHint.Type type) {
      fetcher =
          new SimpleSingleFileFetcher(
              SimpleSingleFileFetcher.Cfg.create(
                      key, ctxDBR.maxUSKRetries, ctxDBR, parent, this, 0, context)
                  .essential(false)
                  .dontAdd(true)
                  .deleteFetchContext(false)
                  .realTime(realTimeFlag)) {
            @Override
            public short getPriorityClass() {
              return owner.getPriorityClass();
            }

            @Override
            public KeyListener makeKeyListener(ClientContext context, boolean onStartup) {
              synchronized (this) {
                if (finished) return null;
              }
              if (owner.isCancelled()) return null;
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
              short prio = owner.getPriorityClass();
              return new SingleKeyListener(newKey, this, prio, persistent);
            }
          };
      this.type = type;
      if (LOG.isTraceEnabled()) LOG.trace("Created {} with {}", this, fetcher);
    }

    /**
     * Handles a successful fetch by streaming, optional decompression, and parsing.
     *
     * <p>The method streams the data into a temporary bucket, optionally running a decompressor
     * chain. It then parses the hint payload and forwards any valid edition hint to {@link
     * #handleHintFound(long, ClientContext)}. Any exception is treated as an internal failure and
     * routed through {@link #onFailure(FetchException, ClientGetState, ClientContext)}. Resources
     * are released in all cases.
     *
     * @param streamGenerator stream producer for the fetched block; must not be null
     * @param clientMetadata metadata for the fetched block, unused by this implementation
     * @param decompressors optional decompressor chain to apply, or {@code null} for raw data
     * @param state state object associated with the fetch, passed through to failures
     * @param context client context providing bucket factories and scheduler access; must not be
     *     null
     */
    @Override
    @SuppressWarnings("java:S1181")
    public void onSuccess(
        StreamGenerator streamGenerator,
        ClientMetadata clientMetadata,
        List<? extends Compressor> decompressors,
        ClientGetState state,
        ClientContext context) {
      Bucket data = null;
      long maxLen = Math.max(ctx.getMaxTempLength(), ctx.getMaxOutputLength());
      try {
        data = context.getBucketFactory(false).makeBucket(maxLen);
        try (PipedInputStream pipeIn = new PipedInputStream();
            PipedOutputStream pipeOut = new PipedOutputStream();
            OutputStream output = data.getOutputStream()) {

          if (decompressors != null) {
            if (LOG.isDebugEnabled()) LOG.debug("decompressing...");
            pipeOut.connect(pipeIn);
            DecompressorThreadManager decompressorManager =
                new DecompressorThreadManager(pipeIn, decompressors, maxLen);
            PipedInputStream newPipeIn = decompressorManager.execute();
            ClientGetWorkerThread worker = createClientGetWorkerThread(newPipeIn, output, context);
            worker.start();
            streamGenerator.writeTo(pipeOut, context);
            decompressorManager.waitFinished();
            worker.waitFinished();
            newPipeIn.close();
          } else {
            streamGenerator.writeTo(output, context);
          }
        }

        innerSuccess(data, context);
      } catch (Throwable t) {
        LOG.error("Caught {}", t, t);
        onFailure(new FetchException(FetchExceptionMode.INTERNAL_ERROR, t), state, context);
      } finally {
        finish(context);
        if (data != null) data.free();
      }
    }

    /**
     * Parses the hint payload from the provided bucket and emits a hint update.
     *
     * <p>The payload is expected to be UTF-8 text with three lines: {@code HINT}, a decimal edition
     * number, and a date string. Malformed input is logged and ignored. Successful parses forward
     * the edition to {@link #handleHintFound(long, ClientContext)}.
     *
     * @param bucket bucket containing the hint payload; must not be null
     * @param context client context used for downstream hint handling; must not be null
     */
    private void innerSuccess(Bucket bucket, ClientContext context) {
      byte[] data;
      try {
        data = BucketTools.toByteArray(bucket);
      } catch (IOException e) {
        LOG.error(
            "Unable to read hint data because of I/O error, maybe bad decompression?: {}", e, e);
        return;
      }
      String line;
      try {
        line = new String(data, StandardCharsets.UTF_8);
      } catch (Exception t) {
        LOG.error("Impossible throwable - maybe bogus encoding?: {}", t, t);
        return;
      }
      String[] split = line.split("\n");
      if (split.length < 3) {
        LOG.error("Unable to parse hint (not enough lines): \"{}\"", line);
        return;
      }
      if (!split[0].startsWith("HINT")) {
        LOG.error("Unable to parse hint (first line doesn't start with HINT): \"{}\"", line);
        return;
      }
      String value = split[1];
      long hint;
      try {
        hint = Long.parseLong(value);
      } catch (NumberFormatException e) {
        LOG.error("Unable to parse hint \"{}\"", value, e);
        return;
      }
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Found DBR hint edition {} for {} for {}",
            hint,
            this.fetcher.getKey(null).getURI(),
            owner);
      handleHintFound(hint, context);
    }

    /**
     * Handles a terminal failure by logging and clearing attempt tracking.
     *
     * <p>Failures are expected during hint probing; the method logs at debug level and then calls
     * {@link #finish(ClientContext)} to remove the attempt from the outer set and notify the owner
     * when no attempts remain.
     *
     * @param e failure describing the reason for the fetch outcome; must not be null
     * @param state associated state object, unused by this implementation
     * @param context client context used for completion callbacks; must not be null
     */
    @Override
    public void onFailure(FetchException e, ClientGetState state, ClientContext context) {
      if (LOG.isDebugEnabled())
        LOG.debug("Failed to fetch hint {} for {}", fetcher.getKey(null), owner);
      finish(context);
    }

    /**
     * No-op callback for block set completion.
     *
     * @param state state object associated with the fetch, unused by this implementation
     * @param context client context, unused by this implementation
     */
    @Override
    public void onBlockSetFinished(ClientGetState state, ClientContext context) {
      // Ignore.
    }

    /**
     * No-op callback for state transitions.
     *
     * @param oldState previous state, unused by this implementation
     * @param newState new state, unused by this implementation
     * @param context client context, unused by this implementation
     */
    @Override
    public void onTransition(
        ClientGetState oldState, ClientGetState newState, ClientContext context) {
      // Ignore.
    }

    /**
     * No-op callback for expected size notifications.
     *
     * @param size expected size in bytes, unused by this implementation
     * @param context client context, unused by this implementation
     */
    @Override
    public void onExpectedSize(long size, ClientContext context) {
      // Ignore.
    }

    /**
     * No-op callback for expected MIME notifications.
     *
     * @param meta metadata describing the MIME type, unused by this implementation
     * @param context client context, unused by this implementation
     */
    @Override
    public void onExpectedMIME(ClientMetadata meta, ClientContext context) {
      // Ignore.
    }

    /** No-op callback for finalized metadata notifications. */
    @Override
    public void onFinalizedMetadata() {
      // Ignore.
    }

    /**
     * No-op callback for expected top-level size notifications.
     *
     * @param size expected size in bytes, unused by this implementation
     * @param compressed expected compressed size in bytes, unused by this implementation
     * @param blocksReq requested block count, unused by this implementation
     * @param blocksTotal total block count, unused by this implementation
     * @param context client context, unused by this implementation
     */
    @Override
    public void onExpectedTopSize(
        long size, long compressed, int blocksReq, int blocksTotal, ClientContext context) {
      // Ignore.
    }

    /**
     * No-op callback for splitfile compatibility information.
     *
     * @param min minimum compatibility mode, unused by this implementation
     * @param max maximum compatibility mode, unused by this implementation
     * @param customSplitfileKey custom splitfile key, unused by this implementation
     * @param compressed whether data is compressed, unused by this implementation
     * @param bottomLayer whether this is a bottom layer, unused by this implementation
     * @param definitiveAnyway whether definitive despite compatibility, unused by this
     *     implementation
     * @param context client context, unused by this implementation
     */
    @Override
    public void onSplitfileCompatibilityMode(
        CompatibilityMode min,
        CompatibilityMode max,
        byte[] customSplitfileKey,
        boolean compressed,
        boolean bottomLayer,
        boolean definitiveAnyway,
        ClientContext context) {
      // Ignore.
    }

    /**
     * No-op callback for hash notifications.
     *
     * @param hashes hash results, unused by this implementation
     * @param context client context, unused by this implementation
     */
    @Override
    public void onHashes(HashResult[] hashes, ClientContext context) {
      // Ignore.
    }

    /**
     * Schedules this attempt with the appropriate client scheduler.
     *
     * @param context client context used to access schedulers; must not be null
     */
    void start(ClientContext context) {
      fetcher.schedule(context);
    }

    /**
     * Cancels this attempt and removes it from scheduling.
     *
     * @param context client context used to propagate cancellation; must not be null
     */
    void cancel(ClientContext context) {
      fetcher.cancel(context);
    }

    /**
     * Removes the attempt from tracking and notifies the owner when all attempts are done.
     *
     * @param context client context used for completion callbacks; must not be null
     */
    private void finish(ClientContext context) {
      boolean finished;
      synchronized (USKDateHintFetches.this) {
        attempts.remove(this);
        finished = attempts.isEmpty();
      }
      if (finished) owner.onDBRsFinished(context);
    }

    /**
     * Handles a parsed hint by updating the manager and canceling less precise attempts.
     *
     * <p>The method increments the found counter, prunes attempts that are strictly less precise
     * than this one, and forwards the hint edition to {@link USKManager}. If the owning fetcher is
     * already finished, the hint is ignored.
     *
     * @param hint suggested edition parsed from the hint payload; may be any long value
     * @param context client context used to schedule the hint update; must not be null
     */
    private void handleHintFound(long hint, ClientContext context) {
      if (owner.isFinished()) return;

      short prio = owner.refreshAndGetProgressPollPriority();

      List<DBRAttempt> toCancel = null;
      synchronized (USKDateHintFetches.this) {
        hintsFound++;
        for (Iterator<DBRAttempt> it = attempts.iterator(); it.hasNext(); ) {
          DBRAttempt attempt = it.next();
          if (type.alwaysMorePreciseThan(attempt.type)) {
            if (toCancel == null) toCancel = new ArrayList<>();
            toCancel.add(attempt);
            it.remove();
          }
        }
      }

      try {
        FreenetURI uri = origUSK.copy(hint).getURI();
        uskManager.hintUpdate(uri, context, prio);
      } catch (MalformedURLException _) {
        // Impossible: the USK comes from validated inputs and copy() preserves structure.
      }

      if (toCancel != null) {
        for (DBRAttempt attempt : toCancel) attempt.cancel(context);
      }
    }

    /**
     * Creates the worker that streams and filters hint data into the output bucket.
     *
     * @param in input stream providing decompressed hint data; must not be null
     * @param output output stream for the bucket that will hold the payload; must not be null
     * @param context client context providing filter configuration; must not be null
     * @return a started-but-not-running worker thread configured for hint streaming
     * @throws java.net.URISyntaxException if the scheme/host configuration is invalid
     */
    private ClientGetWorkerThread createClientGetWorkerThread(
        java.io.InputStream in, OutputStream output, ClientContext context)
        throws java.net.URISyntaxException {
      return new ClientGetWorkerThread(
          new BufferedInputStream(in),
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
    }

    /**
     * Returns a human-readable description for logging and debugging.
     *
     * @return a string describing the attempt type and base USK
     */
    @Override
    public String toString() {
      return "DBRAttempt(" + type + ") for " + origUSK;
    }
  }
}

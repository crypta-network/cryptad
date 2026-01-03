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
 * Handles Date-Based Request (DBR) hint fetching for a {@link USKFetcher}.
 *
 * <p>DBR hint files provide a coarse (and sometimes more precise) edition estimate. The hint fetch
 * work is implemented separately so that {@link USKFetcher} can focus on edition probing and
 * polling orchestration.
 */
final class USKDateHintFetches {
  private static final Logger LOG = LoggerFactory.getLogger(USKDateHintFetches.class);

  private final USKFetcher owner;
  private final USKManager uskManager;
  private final USK origUSK;
  private final FetchContext ctx;
  private final FetchContext ctxDBR;
  private final ClientRequester parent;
  private final boolean realTimeFlag;

  private final HashSet<DBRAttempt> attempts = new HashSet<>();
  private boolean scheduled;
  private int hintsFound;
  private int hintsStarted;

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

  boolean hasOutstanding() {
    synchronized (this) {
      return !attempts.isEmpty();
    }
  }

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

  void cancelAll(ClientContext context) {
    DBRAttempt[] toCancel;
    synchronized (this) {
      toCancel = attempts.toArray(new DBRAttempt[0]);
      attempts.clear();
    }
    for (DBRAttempt attempt : toCancel) attempt.cancel(context);
  }

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

  private final class DBRAttempt implements GetCompletionCallback {
    final SimpleSingleFileFetcher fetcher;
    final USKDateHint.Type type;

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

    @Override
    public void onFailure(FetchException e, ClientGetState state, ClientContext context) {
      if (LOG.isDebugEnabled())
        LOG.debug("Failed to fetch hint {} for {}", fetcher.getKey(null), owner);
      finish(context);
    }

    @Override
    public void onBlockSetFinished(ClientGetState state, ClientContext context) {
      // Ignore.
    }

    @Override
    public void onTransition(
        ClientGetState oldState, ClientGetState newState, ClientContext context) {
      // Ignore.
    }

    @Override
    public void onExpectedSize(long size, ClientContext context) {
      // Ignore.
    }

    @Override
    public void onExpectedMIME(ClientMetadata meta, ClientContext context) {
      // Ignore.
    }

    @Override
    public void onFinalizedMetadata() {
      // Ignore.
    }

    @Override
    public void onExpectedTopSize(
        long size, long compressed, int blocksReq, int blocksTotal, ClientContext context) {
      // Ignore.
    }

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

    @Override
    public void onHashes(HashResult[] hashes, ClientContext context) {
      // Ignore.
    }

    void start(ClientContext context) {
      fetcher.schedule(context);
    }

    void cancel(ClientContext context) {
      fetcher.cancel(context);
    }

    private void finish(ClientContext context) {
      boolean finished;
      synchronized (USKDateHintFetches.this) {
        attempts.remove(this);
        finished = attempts.isEmpty();
      }
      if (finished) owner.onDBRsFinished(context);
    }

    private void handleHintFound(long hint, ClientContext context) {
      short prio = owner.refreshAndGetProgressPollPriority();

      List<DBRAttempt> toCancel = null;
      synchronized (USKDateHintFetches.this) {
        if (owner.isFinished()) return;
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

    @Override
    public String toString() {
      return "DBRAttempt(" + type + ") for " + origUSK;
    }
  }
}

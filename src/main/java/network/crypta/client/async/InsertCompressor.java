package network.crypta.client.async;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.client.InsertException;
import network.crypta.config.Config;
import network.crypta.crypt.HashResult;
import network.crypta.crypt.MultiHashInputStream;
import network.crypta.keys.CHKBlock;
import network.crypta.node.PrioRunnable;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.compress.CompressJob;
import network.crypta.support.compress.CompressionOutputSizeException;
import network.crypta.support.compress.CompressionRatioException;
import network.crypta.support.compress.Compressor.COMPRESSOR_TYPE;
import network.crypta.support.compress.InvalidCompressionCodecException;
import network.crypta.support.io.NativeThread;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Compresses source data as a preparatory step before inserting it into the network.
 *
 * <p>The compressor is created by a {@link SingleFileInserter} and is responsible for selecting an
 * appropriate compression codec, producing the compressed payload, and reporting progress and
 * completion back to the inserter. It also serves as a persistence tag in the node database so that
 * in-flight insertions can resume after a restart when persistence is enabled. Instances are
 * scheduled onto the execution infrastructure and may run either on a database-backed persistent
 * thread or on the main executor, depending on the configuration.
 *
 * <p>Typical usage: construct the compressor via {@link #start(ClientContext, SingleFileInserter,
 * RandomAccessBucket, int, BucketFactory, boolean, long)} or by direct construction in tests, call
 * {@link #init(ClientContext)} to enqueue the job, and let the instance call back into the {@link
 * SingleFileInserter} as compression starts and completes. The class tries multiple codecs (fastest
 * first) and stops early when the output already fits within a single data block.
 *
 * <p>Concurrency and lifecycle:
 *
 * <ul>
 *   <li>Instances are single-use. A per-instance guard prevents being enqueued more than once.
 *   <li>When {@code persistent} is {@code true}, callbacks are scheduled via the persistent job
 *       runner so work is resumed after restarts; otherwise they are dispatched on the main
 *       executor.
 *   <li>Resources created during compression (temporary buckets) are released on all paths,
 *       including failure and persistence-disabled scenarios.
 * </ul>
 *
 * @author toad
 * @see SingleFileInserter
 * @see CompressJob
 * @see BucketFactory
 */
public class InsertCompressor implements CompressJob {
  private static final Logger LOG = LoggerFactory.getLogger(InsertCompressor.class);

  /**
   * The SingleFileInserter we report to. We were created by it, and when we have compressed our
   * data, we will call a method to process it and schedule the data.
   */
  private final SingleFileInserter inserter;

  /**
   * The original, uncompressed data to be inserted. The data is read using streaming access and is
   * never modified by this class.
   */
  final RandomAccessBucket origData;

  /**
   * Upper threshold that determines when to stop trying stronger codecs. If the compressed size is
   * less than or equal to this value, the output fits into a single block, so no further attempts
   * are made. The value is expressed in bytes.
   */
  public final int minSize;

  /**
   * Factory used to allocate temporary buckets that hold compression output and, when appropriate,
   * intermediate results. Implementations may return in-memory or file-backed buckets depending on
   * size.
   */
  public final BucketFactory bucketFactory;

  /**
   * Whether this job participates in persistence. When {@code true}, callbacks into the {@link
   * SingleFileInserter} are scheduled via the persistent job runner so work can be resumed after a
   * node restart. When {@code false}, callbacks run on the main executor for the lifetime of the
   * current process only.
   */
  public final boolean persistent;

  /**
   * Descriptor string that controls which codecs are attempted and in what order. It is typically
   * provided by the environment and parsed by the compressor selection logic.
   */
  public final String compressorDescriptor;

  /**
   * Guard to prevent double-enqueue while the process is running. Transient so a persisted
   * compressor never restores with {@code true} and skips re-scheduling after a restart.
   */
  @SuppressWarnings("java:S2065")
  private transient boolean scheduled;

  private final long generateHashes;
  private final Config config;

  private static final String DB_DISABLED_COMPRESS_MSG =
      "Compression queue failed: database disabled";
  private static final String DB_DISABLED_FAIL_MSG = "Failure callback skipped: database disabled";

  InsertCompressor(
      SingleFileInserter inserter,
      RandomAccessBucket origData,
      int minSize,
      BucketFactory bf,
      boolean persistent,
      long generateHashes,
      Config config) {
    this.inserter = inserter;
    this.origData = origData;
    this.minSize = minSize;
    this.bucketFactory = bf;
    this.persistent = persistent;
    this.compressorDescriptor = inserter.ctx.getCompressorDescriptor();
    this.generateHashes = generateHashes;
    this.config = config;
  }

  /**
   * Enqueues this compressor for execution in the provided client context.
   *
   * <p>The method is idempotent with respect to scheduling and returns immediately if the instance
   * has already been enqueued. When persistence is enabled, the job will be picked up by the
   * persistent job runner; otherwise it is dispatched to the main executor. Progress and start
   * notifications are delivered to the owning {@link SingleFileInserter}.
   *
   * @param ctx the client context providing executors, job runners, and configuration; must not be
   *     {@code null}
   */
  public void init(final ClientContext ctx) {
    synchronized (this) {
      // Can happen with the above activation and lazy query evaluation.
      if (scheduled) {
        LOG.error("Already scheduled compression, not rescheduling");
        return;
      }
      scheduled = true;
    }
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Compressing {} : origData.size={} for {} origData={} hashes={}",
          this,
          origData.size(),
          inserter,
          origData,
          generateHashes);
    ctx.rc.enqueueNewJob(this);
  }

  /**
   * Attempts to compress the original data using one or more codecs and reports the best result to
   * the owning inserter.
   *
   * <p>The method tries available codecs in a pragmatic order (typically the fastest first). It
   * stops early when the output fits in a single data block or after all codecs have been
   * attempted. When {@code persistent} is enabled, follow-up processing is scheduled via the
   * persistent job runner; otherwise it is dispatched on the main executor. Intermediate buckets
   * are freed on all execution paths to avoid leaking temporary files.
   *
   * @param context the client context providing access to executors, configuration, and job
   *     services; must not be {@code null}
   * @throws InsertException when a non-recoverable error occurs while preparing the data for
   *     insertion (for example, when accessing the underlying buckets or internal errors in codecs)
   */
  @Override
  public void tryCompress(final ClientContext context) throws InsertException {
    long origSize = origData.size();
    long origNumberOfBlocks = origSize / CHKBlock.DATA_LENGTH;

    if (LOG.isDebugEnabled()) LOG.debug("Starting compression cycle");
    // Try to compress the data.
    // Try each algorithm, starting with the fastest and weakest.
    // Stop when run out of algorithms, or the compressed data fits in a single block.
    RandomAccessBucket producedData = null;
    try {
      CompressionSelection selection = chooseBestCompression(context, origSize, origNumberOfBlocks);

      producedData = selection.bestCompressedData;
      final CompressionOutput output =
          new CompressionOutput(producedData, selection.bestCodec, selection.hashes);

      if (persistent) {

        // This can wait until after the next checkpoint because it's still in the
        // persistentInsertCompressors list, so will be restarted if necessary.
        context.jobRunner.queue(
            (PersistentJob)
                context1 -> {
                  inserter.onCompressed(output, context1);
                  return true;
                },
            NativeThread.PriorityLevel.NORM_PRIORITY.value + 1);
      } else {
        // We do it off thread so that RealCompressor can release the semaphore
        context
            .getMainExecutor()
            .execute(
                new PrioRunnable() {

                  @Override
                  public int getPriority() {
                    return NativeThread.PriorityLevel.NORM_PRIORITY.value;
                  }

                  @Override
                  public void run() {
                    try {
                      inserter.onCompressed(output, context);
                    } catch (Exception e) {
                      LOG.error("Caught {} running compression job", e, e);
                    }
                  }
                },
                "Insert thread for " + this);
      }
    } catch (PersistenceDisabledException _) {
      // When persistence is disabled and queueing fails, explicitly free any temporary
      // compressed bucket to avoid leaking the backing file.
      if (producedData != null && producedData != origData) {
        producedData.free();
      }
      LOG.error(DB_DISABLED_COMPRESS_MSG);
    } catch (InvalidCompressionCodecException e) {
      fail(new InsertException(InsertExceptionMode.INTERNAL_ERROR, e, null), context);
    } catch (final IOException e) {
      fail(new InsertException(InsertExceptionMode.BUCKET_ERROR, e, null), context);
    }
  }

  private static final class CompressionSelection {
    COMPRESSOR_TYPE bestCodec;
    RandomAccessBucket bestCompressedData;
    long bestCompressedDataSize;
    long bestNumberOfBlocks;
    HashResult[] hashes;
  }

  private CompressionSelection chooseBestCompression(
      final ClientContext context, long origSize, long origNumberOfBlocks)
      throws PersistenceDisabledException, InvalidCompressionCodecException, IOException {
    CompressionSelection sel = new CompressionSelection();
    sel.bestCodec = null;
    sel.bestCompressedData = origData;
    sel.bestCompressedDataSize = origSize;
    sel.bestNumberOfBlocks = origNumberOfBlocks;
    sel.hashes = null;

    COMPRESSOR_TYPE[] comps = COMPRESSOR_TYPE.getCompressorsArray(compressorDescriptor);
    boolean first = true;
    long amountOfDataToCheckCompressionRatio =
        config.get("node").getLong("amountOfDataToCheckCompressionRatio");
    int minimumCompressionPercentage = config.get("node").getInt("minimumCompressionPercentage");
    try {
      for (final COMPRESSOR_TYPE comp : comps) {
        CompressionAttempt attempt = null;
        try {
          if (LOG.isDebugEnabled()) LOG.debug("Compression attempt with codec {}", comp);
          notifyStartCompression(comp, context);
          attempt =
              performCompressionAttempt(
                  comp,
                  first,
                  origSize,
                  sel.bestCompressedDataSize,
                  amountOfDataToCheckCompressionRatio,
                  minimumCompressionPercentage);
          if (attempt.hashes != null) {
            sel.hashes = attempt.hashes;
            first = false;
          }
          if (applyAttemptToSelection(sel, attempt, comp)) break;
        } finally {
          if (attempt != null && attempt.result != null && attempt.result != origData) {
            attempt.result.free();
          }
        }
      }
    } catch (PersistenceDisabledException e) {
      if (sel.bestCompressedData != null && sel.bestCompressedData != origData) {
        sel.bestCompressedData.free();
      }
      throw e;
    }
    return sel;
  }

  private boolean applyAttemptToSelection(
      CompressionSelection sel, CompressionAttempt attempt, COMPRESSOR_TYPE comp) {
    if (attempt.shouldContinue) return false;
    // minSize is {SSKBlock,CHKBlock}.MAX_COMPRESSED_DATA_LENGTH
    if (attempt.size <= minSize) {
      if (LOG.isDebugEnabled())
        LOG.debug("New size {} smaller then minSize {}", attempt.size, minSize);
      sel.bestCodec = comp;
      if (sel.bestCompressedData != null && sel.bestCompressedData != origData)
        sel.bestCompressedData.free();
      sel.bestCompressedData = attempt.result;
      sel.bestCompressedDataSize = attempt.size;
      sel.bestNumberOfBlocks = attempt.blocks;
      attempt.result = null; // ownership transferred
      return true; // stop: fits in a single block
    }
    if (attempt.blocks < sel.bestNumberOfBlocks) {
      if (LOG.isDebugEnabled())
        LOG.debug(
            "New size {} ({} blocks) better than old best {} ({} blocks)",
            attempt.size,
            attempt.blocks,
            sel.bestCompressedDataSize,
            sel.bestNumberOfBlocks);
      if (sel.bestCompressedData != null && sel.bestCompressedData != origData)
        sel.bestCompressedData.free();
      sel.bestCompressedData = attempt.result;
      sel.bestCompressedDataSize = attempt.size;
      sel.bestNumberOfBlocks = attempt.blocks;
      sel.bestCodec = comp;
      attempt.result = null; // ownership transferred
    }
    return false;
  }

  private void notifyStartCompression(COMPRESSOR_TYPE comp, ClientContext context)
      throws PersistenceDisabledException {
    if (persistent) {
      context.jobRunner.queue(
          (PersistentJob)
              context2 -> {
                inserter.onStartCompression(comp, context2);
                return false;
              },
          NativeThread.PriorityLevel.NORM_PRIORITY.value + 1);
    } else {
      try {
        inserter.onStartCompression(comp, context);
      } catch (Exception e) {
        LOG.error("Transient insert callback threw {}", e, e);
      }
    }
  }

  private static final class CompressionAttempt {
    RandomAccessBucket result;
    long size;
    long blocks;
    boolean shouldContinue;
    HashResult[] hashes;
  }

  private CompressionAttempt performCompressionAttempt(
      COMPRESSOR_TYPE comp,
      boolean first,
      long origSize,
      long bestCompressedDataSize,
      long amountOfDataToCheckCompressionRatio,
      int minimumCompressionPercentage)
      throws IOException {
    CompressionAttempt attempt = new CompressionAttempt();
    MultiHashInputStream hasher = null;
    try (InputStream baseIs = origData.getInputStream()) {
      attempt.result = bucketFactory.makeBucket(-1);
      try (OutputStream os = attempt.result.getOutputStream()) {
        InputStream is = baseIs;
        if (first && generateHashes != 0) {
          if (LOG.isDebugEnabled()) LOG.debug("Generating hashes: {}", generateHashes);
          is = hasher = new MultiHashInputStream(is, generateHashes);
        }
        try {
          comp.compress(
              is,
              os,
              origSize,
              bestCompressedDataSize,
              amountOfDataToCheckCompressionRatio,
              minimumCompressionPercentage);
        } catch (CompressionOutputSizeException | CompressionRatioException _) {
          if (hasher != null) {
            drainFully(is);
            attempt.hashes = hasher.getResults();
          }
          attempt.shouldContinue = true; // try the next compressor type
          return attempt;
        } catch (RuntimeException e) {
          // ArithmeticException has been seen in bzip2 codec.
          LOG.error("Compression failed with codec {} : {}", comp, e, e);
          attempt.shouldContinue = true; // try the next compressor type; do not compute hashes
          return attempt;
        }
        if (hasher != null) {
          attempt.hashes = hasher.getResults();
        }
      }
    }
    attempt.size = attempt.result.size();
    attempt.blocks = attempt.size / CHKBlock.DATA_LENGTH;
    return attempt;
  }

  private static void drainFully(InputStream is) throws IOException {
    is.transferTo(OutputStream.nullOutputStream());
  }

  private void fail(final InsertException ie, ClientContext context) {
    if (persistent) {
      try {
        context.jobRunner.queue(
            (PersistentJob)
                context1 -> {
                  inserter.cb.onFailure(ie, inserter, context1);
                  return true;
                },
            NativeThread.PriorityLevel.NORM_PRIORITY.value + 1);
      } catch (PersistenceDisabledException _) {
        LOG.error(DB_DISABLED_FAIL_MSG);
      }
    } else {
      inserter.cb.onFailure(ie, inserter, context);
    }
  }

  /**
   * Create an {@code InsertCompressor}, register it with the persistence layer when available, and
   * enqueue it for execution.
   *
   * <p>This is a convenience factory used by callers that already have a {@link ClientContext}. It
   * constructs the instance, invokes {@link #init(ClientContext)}, and returns the scheduled
   * compressor.
   *
   * @param ctx the client context used for scheduling and configuration; must not be {@code null}
   * @param inserter the owning inserter that receives progress and completion callbacks; must not
   *     be {@code null}
   * @param origData the source data to compress; the compressor reads from it but does not modify
   *     it
   * @param minSize threshold in bytes under which further compression attempts are skipped because
   *     the result already fits into one block
   * @param bf factory for creating temporary buckets during compression
   * @param persistent whether the compression job should be persistent across restarts
   * @param generateHashes bitmask describing which hashes to compute while streaming the original
   *     data; zero disables hashing
   * @return the scheduled compressor instance; callers typically keep the reference only for test
   *     synchronization or diagnostics
   */
  @SuppressWarnings("UnusedReturnValue")
  static InsertCompressor start(
      ClientContext ctx,
      SingleFileInserter inserter,
      RandomAccessBucket origData,
      int minSize,
      BucketFactory bf,
      boolean persistent,
      long generateHashes) {
    InsertCompressor compressor =
        new InsertCompressor(
            inserter, origData, minSize, bf, persistent, generateHashes, ctx.getConfig());
    compressor.init(ctx);
    return compressor;
  }

  /**
   * Forwards a failure to the owning inserter's callback, honoring the persistence mode.
   *
   * <p>When {@code persistent} is enabled, the notification is scheduled through the persistent job
   * runner; otherwise it is delivered directly on the current thread. This method does not throw
   * and attempts to deliver the error in a best-effort manner even when persistence is disabled at
   * runtime.
   *
   * @param e the failure that occurred while preparing or scheduling the insert; never {@code null}
   * @param c the client put state associated with the operation, if available
   * @param context the client context used for scheduling callback delivery
   */
  @Override
  public void onFailure(final InsertException e, ClientPutState c, ClientContext context) {
    if (persistent) {
      try {
        context.jobRunner.queue(
            (PersistentJob)
                context1 -> {
                  inserter.cb.onFailure(e, inserter, context1);
                  return true;
                },
            NativeThread.PriorityLevel.NORM_PRIORITY.value + 1);
      } catch (PersistenceDisabledException _) {
        // Can't do anything
      }
    } else {
      inserter.cb.onFailure(e, inserter, context);
    }
  }
}

package network.crypta.client.async;

import java.io.IOException;
import java.io.Serial;
import java.io.Serializable;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.client.ArchiveManager.ARCHIVE_TYPE;
import network.crypta.client.ClientMetadata;
import network.crypta.client.InsertContext;
import network.crypta.client.InsertException;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.client.Metadata;
import network.crypta.client.async.SplitFileInserterSegmentStorage.MissingKeyException;
import network.crypta.crypt.CRCChecksumChecker;
import network.crypta.crypt.ChecksumFailedException;
import network.crypta.crypt.HashResult;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.compress.Compressor.COMPRESSOR_TYPE;
import network.crypta.support.io.ResumeFailedException;
import network.crypta.support.io.StorageFormatException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Coordinates a split-file insert from caller-provided data into the network.
 *
 * <p>A split-file insert encodes the original content into segments and blocks, computes the
 * necessary checksums and keys, and then schedules network inserts for those pieces. The {@code
 * SplitFileInserter} orchestrates this high-level flow while delegating the heavy lifting to {@link
 * SplitFileInserterStorage} (encoding and state persistence) and {@link SplitFileInserterSender}
 * (network scheduling). Storage is not kept as a persistent object instance across restarts;
 * instead, its state is reconstructed from a random-access file (RAF) on resume, similar to the
 * fetch path.
 *
 * <p>Typical usage is: construct the inserter with an {@link InsertContext} and options, call
 * {@link #schedule(ClientContext)} to begin, and then react to completion via the provided {@link
 * PutCompletionCallback}. When resuming a persistent insert, call {@link #onResume(ClientContext)}
 * to rehydrate state and continue. The inserter reports metadata once keys are available and
 * ensures buffers are closed/freed on success or failure.
 *
 * <p>Concurrency: this class is used from the client layer and from worker callbacks. It relies on
 * {@link AtomicReference} fields for thread-safe publication of its storage and sender helpers, and
 * performs scheduling through the {@link ClientContext} job runners. Instances are not generally
 * thread-safe for arbitrary concurrent calls; callers should follow the lifecycle entry points
 * ({@link #schedule(ClientContext)}, {@link #cancel(ClientContext)}, {@link
 * #onResume(ClientContext)}).
 *
 * <ul>
 *   <li>Persists progress in an RAF to enable a reliable resuming.
 *   <li>Streams metadata to the caller early when configured to do so.
 *   <li>Honors real-time priority settings via the provided {@link InsertContext}.
 * </ul>
 *
 * @author toad
 * @see SplitFileInserterStorage
 * @see SplitFileInserterSender
 */
public final class SplitFileInserter
    implements ClientPutState, Serializable, SplitFileInserterStorageCallback {

  private static final Logger LOG = LoggerFactory.getLogger(SplitFileInserter.class);

  @Serial private static final long serialVersionUID = 1L;

  /** Is the insert persistent? */
  final boolean persistent;

  /** Parent ClientPutter etc */
  final BaseClientPutter parent;

  /** Callback to send Metadata, completion status etc to */
  private final PutCompletionCallback cb;

  /** The file to be inserted */
  private final LockableRandomAccessBuffer originalData;

  /**
   * Whether to free the data when the insert completes/fails. E.g., this is true if the data is the
   * result of compression.
   */
  private final boolean freeData;

  /** The RAF that stores check blocks and status info, used and created by storage. */
  private final LockableRandomAccessBuffer raf;

  /**
   * Stores the state of the insert and does most of the work. Created in onResume() or in the
   * constructor, so must be volatile.
   */
  private transient AtomicReference<SplitFileInserterStorage> storageRef;

  /** Actually does the insert. Created in onResume() or in the constructor, so must be volatile. */
  private transient AtomicReference<SplitFileInserterSender> senderRef;

  /** Used any time a callback from storage needs us to do something higher level */
  private transient ClientContext context;

  /** Is the insert real-time? */
  final boolean realTime;

  /** Token to be kept with the insert */
  private final Object token;

  /** Insert settings */
  final InsertContext ctx;

  private transient boolean resumed;

  /* ===== Options to reduce constructor parameter count (Sonar S107) ===== */

  /**
   * Immutable bundle of options used to construct a {@link SplitFileInserter}. Using a builder
   * avoids overly long constructors while keeping call sites explicit and readable. The values are
   * captured at build time and are not subsequently mutated.
   *
   * <p>Unless otherwise noted, sizes are in bytes and counts are non-negative. Callers should
   * ensure that referenced buffers and contexts outlive the construction phase and remain valid
   * until the insert is started or resumed.
   */
  public static final class Options {

    /** Insert behavior, scheduling, and encoding options used by the client layer. */
    final InsertContext ctx;

    /** Execution context and facilities provided by the runtime. */
    final ClientContext context;

    /** Length of the content after decompression; used when the original is compressed. */
    final long decompressedLength;

    /** Compression algorithm to apply at the top level, or {@code null} for none. */
    final COMPRESSOR_TYPE compressionCodec;

    /** Optional client metadata to embed or return with the insert result. */
    final ClientMetadata meta;

    /** Whether the payload itself represents metadata rather than regular file content. */
    final boolean isMetadata;

    /** Archive format for bundling, when applicable; controls how data is framed. */
    final ARCHIVE_TYPE archiveType;

    /** Splitfile crypto algorithm identifier used for key derivation and block protection. */
    final byte splitfileCryptoAlgorithm;

    /** Opaque splitfile crypto key material, stored defensively. */
    final byte[] splitfileCryptoKey;

    /** Optional layer-local hash, stored defensively when non-null. */
    final byte[] hashThisLayerOnly;

    /** Precomputed hash results for segments/blocks, stored as a shallow defensive copy. */
    final HashResult[] hashes;

    /** If {@code true}, skip top-level compression even when a codec is present. */
    final boolean topDontCompress;

    /** Minimum number of blocks that must succeed at the top layer. */
    final int topRequiredBlocks;

    /** Total number of blocks at the top layer; includes redundant blocks. */
    final int topTotalBlocks;

    /** Size of the original (uncompressed) data in bytes for reporting and checks. */
    final long origDataSize;

    /** Size of the original compressed form, when available; zero when unknown. */
    final long origCompressedDataSize;

    /** If {@code true}, use real-time insertion priorities; otherwise use background scheduling. */
    final boolean realTime;

    /** Opaque caller token associated with this insert; returned unchanged in callbacks. */
    final Object token;

    private Options(Builder b) {
      this.ctx = b.ctx;
      this.context = b.context;
      this.decompressedLength = b.decompressedLength;
      this.compressionCodec = b.compressionCodec;
      this.meta = b.meta;
      this.isMetadata = b.isMetadata;
      this.archiveType = b.archiveType;
      this.splitfileCryptoAlgorithm = b.splitfileCryptoAlgorithm;
      this.splitfileCryptoKey = copyByteArrayNullable(b.splitfileCryptoKey);
      this.hashThisLayerOnly = copyByteArrayNullable(b.hashThisLayerOnly);
      this.hashes = copyHashArrayNullable(b.hashes);
      this.topDontCompress = b.topDontCompress;
      this.topRequiredBlocks = b.topRequiredBlocks;
      this.topTotalBlocks = b.topTotalBlocks;
      this.origDataSize = b.origDataSize;
      this.origCompressedDataSize = b.origCompressedDataSize;
      this.realTime = b.realTime;
      this.token = b.token;
    }

    private static byte[] copyByteArrayNullable(byte[] input) {
      return input == null ? null : Arrays.copyOf(input, input.length);
    }

    private static HashResult[] copyHashArrayNullable(HashResult[] input) {
      return input == null ? null : Arrays.copyOf(input, input.length);
    }

    /**
     * Builder for {@link Options}.
     *
     * <p>The builder is mutable and not thread-safe. Callers typically set the desired fields using
     * the fluent setters below and finish with {@link Builder#build()} to create an immutable
     * {@link Options} instance suitable for constructing a {@link SplitFileInserter}.
     */
    public static final class Builder {
      private InsertContext ctx;
      private ClientContext context;
      private long decompressedLength;
      private COMPRESSOR_TYPE compressionCodec;
      private ClientMetadata meta;
      private boolean isMetadata;
      private ARCHIVE_TYPE archiveType;
      private byte splitfileCryptoAlgorithm;
      private byte[] splitfileCryptoKey;
      private byte[] hashThisLayerOnly;
      private HashResult[] hashes;
      private boolean topDontCompress;
      private int topRequiredBlocks;
      private int topTotalBlocks;
      private long origDataSize;
      private long origCompressedDataSize;
      private boolean realTime;
      private Object token;

      /**
       * Creates a new builder with default values.
       *
       * <p>All fields are initialized to their language defaults. Call the fluent setters to
       * customize options and then {@link #build()} to create an immutable snapshot.
       */
      public Builder() {
        // Intentionally empty: the builder uses language-default field values and is
        // configured via the fluent setters before creating an immutable Options snapshot.
      }

      /**
       * Sets the high-level insert context controlling encoding, priorities, and callbacks.
       *
       * @param v context instance; must remain valid for the lifetime of the insert; never {@code
       *     null}
       * @return this builder for fluent chaining; the instance is reused
       */
      public Builder ctx(InsertContext v) {
        this.ctx = v;
        return this;
      }

      /**
       * Sets the execution context providing job runners, buffers, and utilities.
       *
       * @param v client execution context; provides schedulers and factories; never {@code null}
       * @return this builder for fluent chaining; modifies internal state
       */
      public Builder context(ClientContext v) {
        this.context = v;
        return this;
      }

      /**
       * Specifies the decompressed byte length when the input is compressed.
       *
       * @param v size in bytes; non-negative; use {@code 0} when the value is unknown
       * @return this builder for fluent chaining; leaves other fields unchanged
       */
      public Builder decompressedLength(long v) {
        this.decompressedLength = v;
        return this;
      }

      /**
       * Selects the compression codec to use at the top layer.
       *
       * @param v codec enum value or {@code null} to disable top-level compression
       * @return this builder for fluent chaining; sets the compression preference
       */
      public Builder compressionCodec(COMPRESSOR_TYPE v) {
        this.compressionCodec = v;
        return this;
      }

      /**
       * Provides optional client metadata to be returned with the result.
       *
       * @param v arbitrary metadata to associate with the insert; may be {@code null}
       * @return this builder for fluent chaining; does not copy the reference
       */
      public Builder meta(ClientMetadata v) {
        this.meta = v;
        return this;
      }

      /**
       * Indicates that the payload is metadata rather than regular content.
       *
       * @param v {@code true} when the data represents metadata for a higher-level object
       * @return this builder for fluent chaining; toggles a simple boolean flag
       */
      public Builder isMetadata(boolean v) {
        this.isMetadata = v;
        return this;
      }

      /**
       * Sets the archive format to use when framing or bundling the payload.
       *
       * @param v archive type; determines container behavior; may be {@code null}
       * @return this builder for fluent chaining; updates the archive preference
       */
      public Builder archiveType(ARCHIVE_TYPE v) {
        this.archiveType = v;
        return this;
      }

      /**
       * Configures the splitfile crypto algorithm identifier.
       *
       * @param v algorithm id as a small numeric value; accepted range depends on runtime
       * @return this builder for fluent chaining; stores the provided value verbatim
       */
      public Builder splitfileCryptoAlgorithm(byte v) {
        this.splitfileCryptoAlgorithm = v;
        return this;
      }

      /**
       * Supplies the splitfile crypto key material.
       *
       * @param v key bytes copied when non-null
       * @return this builder for fluent chaining
       */
      public Builder splitfileCryptoKey(byte[] v) {
        this.splitfileCryptoKey = Options.copyByteArrayNullable(v);
        return this;
      }

      /**
       * Restricts hashing to the current layer by providing a layer-local hash.
       *
       * @param v optional hash bytes indicating current-layer hashing only; copied when non-null
       * @return this builder for fluent chaining; replaces any prior value
       */
      public Builder hashThisLayerOnly(byte[] v) {
        this.hashThisLayerOnly = Options.copyByteArrayNullable(v);
        return this;
      }

      /**
       * Provides precomputed hash results for segments or blocks to speed up verification.
       *
       * @param v array of hash results; elements may be {@code null} if unavailable
       * @return this builder for fluent chaining; stores a shallow copy
       */
      public Builder hashes(HashResult[] v) {
        this.hashes = Options.copyHashArrayNullable(v);
        return this;
      }

      /**
       * Disables compression at the top level when set to {@code true}.
       *
       * @param v {@code true} to skip compression even if a codec is configured
       * @return this builder for fluent chaining; flips a boolean control
       */
      public Builder topDontCompress(boolean v) {
        this.topDontCompress = v;
        return this;
      }

      /**
       * Sets the required number of blocks that must succeed at the top layer.
       *
       * @param v non-negative number of mandatory blocks; must be ≤ total blocks
       * @return this builder for fluent chaining; validates later in construction
       */
      public Builder topRequiredBlocks(int v) {
        this.topRequiredBlocks = v;
        return this;
      }

      /**
       * Sets the total number of top-layer blocks including redundancy.
       *
       * @param v non-negative total blocks; must be ≥ required blocks to be valid
       * @return this builder for fluent chaining; used to compute redundancy
       */
      public Builder topTotalBlocks(int v) {
        this.topTotalBlocks = v;
        return this;
      }

      /**
       * Records the uncompressed size of the original input.
       *
       * @param v byte length of the input data; non-negative; {@code 0} when unknown
       * @return this builder for fluent chaining; informational only
       */
      public Builder origDataSize(long v) {
        this.origDataSize = v;
        return this;
      }

      /**
       * Records the compressed size of the original input when available.
       *
       * @param v byte length of the compressed form; non-negative; {@code 0} when unavailable
       * @return this builder for fluent chaining; used for progress reporting when present
       */
      public Builder origCompressedDataSize(long v) {
        this.origCompressedDataSize = v;
        return this;
      }

      /**
       * Requests real-time scheduling for the insert when {@code true}.
       *
       * @param v {@code true} to prioritize latency over throughput; otherwise background behavior
       * @return this builder for fluent chaining; maps to scheduler selection
       */
      public Builder realTime(boolean v) {
        this.realTime = v;
        return this;
      }

      /**
       * Associates an opaque caller-defined token with this insert.
       *
       * @param v token object; returned unchanged in callbacks; may be {@code null}
       * @return this builder for fluent chaining; stores the reference only
       */
      public Builder token(Object v) {
        this.token = v;
        return this;
      }

      /**
       * Builds an immutable {@link Options} snapshot from the current builder values.
       *
       * <p>This method creates an immutable snapshot. Mutable byte/hash arrays are defensively
       * copied; other object references are carried through as provided. Validation, when required,
       * is performed by downstream constructors.
       *
       * @return a new {@link Options} instance containing the configured values
       */
      public Options build() {
        return new Options(this);
      }
    }
  }

  SplitFileInserter(
      boolean persistent,
      BaseClientPutter parent,
      PutCompletionCallback cb,
      LockableRandomAccessBuffer originalData,
      boolean freeData,
      Options options)
      throws InsertException {
    this.persistent = persistent;
    this.parent = parent;
    this.cb = cb;
    this.originalData = originalData;
    this.context = options.context;
    this.freeData = freeData;
    SplitFileInserterStorage s;
    try {
      SplitFileInserterStorageRuntimeParams runtimeParams =
          new SplitFileInserterStorageRuntimeParams.Builder()
              .callback(this)
              .random(options.context.fastWeakRandom)
              .memoryLimitedJobRunner(options.context.memoryLimitedJobRunner)
              .jobRunner(options.context.getJobRunner(persistent))
              .ticker(options.context.ticker)
              .keysFetching(options.context.getChkInsertScheduler(options.realTime).fetchingKeys())
              .build();
      SplitFileInserterStorageInitParams initParams =
          new SplitFileInserterStorageInitParams.Builder()
              .originalData(originalData)
              .decompressedLength(options.decompressedLength)
              .runtime(runtimeParams)
              .compressionCodec(options.compressionCodec)
              .meta(options.meta)
              .isMetadata(options.isMetadata)
              .archiveType(options.archiveType)
              .rafFactory(options.context.getRandomAccessBufferFactory(persistent))
              .persistent(persistent)
              .ctx(options.ctx)
              .splitfileCryptoAlgorithm(options.splitfileCryptoAlgorithm)
              .splitfileCryptoKey(options.splitfileCryptoKey)
              .hashThisLayerOnly(options.hashThisLayerOnly)
              .hashes(options.hashes)
              .tempBucketFactory(
                  options
                      .context
                      .tempBucketFactory /* only used for temporaries within constructor */)
              .checker(new CRCChecksumChecker())
              .topDontCompress(options.topDontCompress)
              .topRequiredBlocks(options.topRequiredBlocks)
              .topTotalBlocks(options.topTotalBlocks)
              .origDataSize(options.origDataSize)
              .origCompressedDataSize(options.origCompressedDataSize)
              .build();
      SplitFileInserterStorage storage = new SplitFileInserterStorage(initParams);
      int mustSucceed = storage.topRequiredBlocks - options.topRequiredBlocks;
      parent.addMustSucceedBlocks(mustSucceed);
      parent.addRedundantBlocksInsert(
          storage.topTotalBlocks - options.topTotalBlocks - mustSucceed);
      parent.notifyClients(options.context);
      s = storage;
    } catch (IOException e) {
      throw new InsertException(InsertExceptionMode.BUCKET_ERROR, e, null);
    }
    this.raf = s.getRAF();
    this.storageRef = new AtomicReference<>();
    this.senderRef = new AtomicReference<>();
    this.storageRef.set(s);
    this.senderRef.set(new SplitFileInserterSender(this, s));
    this.realTime = options.realTime;
    this.token = options.token;
    this.ctx = options.ctx;
  }

  /** {@inheritDoc} */
  @Override
  public BaseClientPutter getParent() {
    return parent;
  }

  /**
   * Requests cancellation of the insert and fails the operation.
   *
   * <p>This method propagates a {@link InsertExceptionMode#CANCELLED} to the underlying storage,
   * which triggers cleanup and completion callbacks. It is safe to call multiple times; later calls
   * have no additional effect once failure handling has begun.
   *
   * @param context execution context used by the caller; ignored for cancellation semantics
   */
  @Override
  public void cancel(ClientContext context) {
    storageRef.get().fail(new InsertException(InsertExceptionMode.CANCELLED));
  }

  /**
   * Starts or continues the insert by encoding data and scheduling network activity.
   *
   * <p>Notifies the callback that block selection is finished, starts the storage encoding
   * pipeline, and, when not in CHK-only mode, schedules the sender to insert any available blocks.
   * Callers may invoke this after construction or from progress callbacks to advance work.
   *
   * @param context execution context providing schedulers and timing; never {@code null}
   * @throws InsertException if scheduling or storage start fails for a recoverable reason
   */
  @Override
  public void schedule(ClientContext context) throws InsertException {
    cb.onBlockSetFinished(this, context);
    storageRef.get().start();
    if (!ctx.isGetCHKOnly()) {
      senderRef.get().clearWakeupTime(context);
      senderRef.get().schedule(context);
    }
  }

  /**
   * Returns the opaque token originally provided by the caller.
   *
   * @return caller-supplied token associated with this insert; may be {@code null}
   */
  @Override
  public Object getToken() {
    return token;
  }

  /**
   * Resumes a previously persistent insert by restoring state from disk and re-scheduling work.
   *
   * <p>This method re-initializes transient collaborators, replays storage state from the RAF,
   * updates internals, and then calls {@link #schedule(ClientContext)} to continue. It is
   * idempotent: only the first call takes effect; later calls are ignored.
   *
   * @param context execution context for persistent resumes; must be a persistent-capable context
   * @throws InsertException if a storage or scheduling error occurs during resume
   * @throws ResumeFailedException if the on-disk state is corrupt or cannot be reconciled
   */
  @Override
  public void onResume(ClientContext context) throws InsertException, ResumeFailedException {
    assert persistent;
    synchronized (this) {
      if (resumed) return;
      resumed = true;
    }
    this.context = context;
    try {
      raf.onResume(context);
      originalData.onResume(context);
      SplitFileInserterStorageRuntimeParams runtimeParams =
          new SplitFileInserterStorageRuntimeParams.Builder()
              .callback(this)
              .random(context.fastWeakRandom)
              .memoryLimitedJobRunner(context.memoryLimitedJobRunner)
              .jobRunner(context.getJobRunner(true))
              .ticker(context.ticker)
              .keysFetching(context.getChkInsertScheduler(realTime).fetchingKeys())
              .build();
      SplitFileInserterStorageResumeParams resumeParams =
          new SplitFileInserterStorageResumeParams.Builder()
              .raf(raf)
              .originalData(originalData)
              .runtime(runtimeParams)
              .persistentFG(context.persistentFG)
              .persistentFileTracker(context.getPersistentFileTracker())
              .masterKey(context.getPersistentMasterSecret())
              .build();
      SplitFileInserterStorage storage = new SplitFileInserterStorage(resumeParams);
      storage.onResume(context);
      this.storageRef = new AtomicReference<>();
      this.senderRef = new AtomicReference<>();
      this.storageRef.set(storage);
      this.senderRef.set(new SplitFileInserterSender(this, storage));
      schedule(context);
    } catch (IOException | StorageFormatException | ChecksumFailedException e) {
      raf.close();
      raf.free();
      originalData.close();
      if (freeData) originalData.free();
      throw new InsertException(InsertExceptionMode.BUCKET_ERROR, "Resume failed", e, null);
    }
  }

  @Override
  public void onFinishedEncode() {
    // Ignore.
  }

  /**
   * Called when additional encoding progress is available.
   *
   * <p>If not in CHK-only mode, this reschedules the sender so newly created blocks can be inserted
   * as soon as possible. In CHK-only mode, it returns immediately and waits for key availability.
   */
  @Override
  public void encodingProgress() {
    // We've encoded a segment. Start inserting the blocks we have immediately.
    if (ctx.isGetCHKOnly()) {
      // We are not inserting any blocks. Wait for onHasKeys().
      return;
    }
    try {
      // Reschedule to insert the new check blocks.
      schedule(context);
    } catch (InsertException e) {
      storageRef.get().fail(e);
    }
  }

  /**
   * Called when keys for the split-file are available.
   *
   * <p>When early-encode or CHK-only modes are enabled, encodes metadata on a background runner and
   * reports it to the callback, short-circuiting to success in CHK-only mode.
   */
  @Override
  public void onHasKeys() {
    if (ctx.isEarlyEncode() || ctx.isGetCHKOnly()) {
      context
          .getJobRunner(persistent)
          .queueNormalOrDrop(
              _ -> {
                try {
                  Metadata metadata = storageRef.get().encodeMetadata();
                  reportMetadata(metadata);
                  if (ctx.isGetCHKOnly()) onSucceeded(metadata);
                } catch (IOException e) {
                  storageRef
                      .get()
                      .fail(new InsertException(InsertExceptionMode.BUCKET_ERROR, e, null));
                } catch (MissingKeyException e) {
                  storageRef
                      .get()
                      .fail(
                          new InsertException(
                              InsertExceptionMode.BUCKET_ERROR, "Lost one or more keys", e, null));
                }
                return false;
              });
    }
  }

  /**
   * Signals successful completion of the insert, performs cleanup, and notifies the callback.
   *
   * <p>Ensures the sender is unregistered, reports metadata if it has not already been reported,
   * then closes and frees owned buffers. Runs on a job runner suitable for the persistence mode.
   *
   * @param metadata final metadata describing the inserted split-file; never {@code null}
   */
  @Override
  public void onSucceeded(final Metadata metadata) {
    context
        .getJobRunner(persistent)
        .queueNormalOrDrop(
            jobCtx -> {
              if (LOG.isDebugEnabled()) LOG.debug("Succeeding on {}", SplitFileInserter.this);
              unregisterSender();
              if (!(ctx.isEarlyEncode() || ctx.isGetCHKOnly())) {
                reportMetadata(metadata);
              }
              cb.onSuccess(SplitFileInserter.this, jobCtx);
              raf.close();
              raf.free();
              originalData.close();
              if (freeData) originalData.free();
              return true;
            });
  }

  /**
   * Unregisters the sender with schedulers, so it no longer participates in network activity.
   *
   * <p>This helper is invoked on success and failure paths to ensure resources are released and the
   * scheduler state is updated consistently.
   */
  protected void unregisterSender() {
    SplitFileInserterSender s = senderRef.get();
    if (s != null) s.unregister(context, parent.getPriorityClass());
  }

  /**
   * Reports the metadata for this insert to the completion callback.
   *
   * <p>Split-file inserts always operate in a “report metadata only” mode at this layer: the
   * metadata is returned to the parent, which may persist it to a bucket and perform any follow-up
   * insert.
   *
   * @param metadata the computed metadata describing the encoded split-file; never {@code null}
   */
  protected void reportMetadata(Metadata metadata) {
    // Splitfile insert is always reportMetadataOnly: metadata is returned to the parent
    // SingleFileInserter, which will persist it and likely insert it as needed.
    cb.onMetadata(metadata, this, context);
  }

  /**
   * Signals a terminal failure, performs cleanup, and notifies the callback.
   *
   * <p>Unregisters the sender, releases resources, and calls the completion callback with the
   * encountered exception. Runs on a job runner suitable for the persistence mode.
   *
   * @param e the reason for failure
   */
  @Override
  public void onFailed(final InsertException e) {
    context
        .getJobRunner(persistent)
        .queueNormalOrDrop(
            jobCtx -> {
              unregisterSender();
              raf.close();
              raf.free();
              originalData.close();
              if (freeData) originalData.free();
              cb.onFailure(e, SplitFileInserter.this, jobCtx);
              return true;
            });
  }

  /**
   * Returns the total length in bytes of the original data being inserted.
   *
   * <p>The value reflects the authoritative length recorded by the storage layer and may be used by
   * callers for progress reporting and validation.
   *
   * @return original data length in bytes; non-negative and constant for the lifetime of the insert
   */
  public long getLength() {
    return storageRef.get().dataLength;
  }

  /** Notifies the parent that a block has been inserted so progress can be updated. */
  @Override
  public void onInsertedBlock() {
    parent.completedBlock(false, context);
  }

  /**
   * Propagates shutdown to the storage layer so it can quiesce and persist state.
   *
   * @param context execution context used for shutdown; never {@code null}
   */
  @Override
  public void onShutdown(ClientContext context) {
    storageRef.get().onShutdown(context);
  }

  /** Clears any sender backoff so scheduling can proceed without delay. */
  @Override
  public void clearCooldown() {
    senderRef.get().clearWakeupTime(context);
  }

  /**
   * Returns the priority class associated with this insert as defined by the parent.
   *
   * @return a priority class identifier; larger values typically indicate lower priority
   */
  @Override
  public short getPriorityClass() {
    return parent.getPriorityClass();
  }

  /* ===== Java serialization support ===== */

  /**
   * Custom Java serialization hook to persist non-transient state.
   *
   * <p>Writes the default serial form; transient collaborators are reconstructed on resume rather
   * than serialized directly.
   *
   * @param out target output stream used by the Java serialization mechanism
   * @throws IOException if an I/O error occurs while writing the default serial form
   */
  @Serial
  private void writeObject(java.io.ObjectOutputStream out) throws IOException {
    out.defaultWriteObject();
  }

  /**
   * Custom Java deserialization hook to restore transient holders.
   *
   * <p>Reads the default serial form and recreates transient {@link AtomicReference} fields. Actual
   * operational state is re-established later in {@link #onResume(ClientContext)}.
   *
   * @param in source input stream used by the Java serialization mechanism
   * @throws IOException if an I/O error occurs while reading the default serial form
   * @throws ClassNotFoundException if a class for a serialized field cannot be located
   */
  @Serial
  private void readObject(java.io.ObjectInputStream in) throws IOException, ClassNotFoundException {
    in.defaultReadObject();
    // Recreate transient holders; actual values are restored on resume.
    this.storageRef = new AtomicReference<>();
    this.senderRef = new AtomicReference<>();
  }
}

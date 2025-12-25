package network.crypta.client.async;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serial;
import java.io.Serializable;
import java.net.MalformedURLException;
import java.util.HashMap;
import network.crypta.client.ArchiveManager.ARCHIVE_TYPE;
import network.crypta.client.ClientMetadata;
import network.crypta.client.InsertBlock;
import network.crypta.client.InsertContext;
import network.crypta.client.InsertContext.CompatibilityMode;
import network.crypta.client.InsertException;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.client.Metadata;
import network.crypta.client.Metadata.DocumentType;
import network.crypta.client.MetadataUnresolvedException;
import network.crypta.client.events.ExpectedHashesEvent;
import network.crypta.client.events.FinishedCompressionEvent;
import network.crypta.client.events.StartedCompressionEvent;
import network.crypta.crypt.HashResult;
import network.crypta.crypt.HashType;
import network.crypta.crypt.MultiHashOutputStream;
import network.crypta.keys.BaseClientKey;
import network.crypta.keys.CHKBlock;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.SSKBlock;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.compress.Compressor.COMPRESSOR_TYPE;
import network.crypta.support.io.BucketTools;
import network.crypta.support.io.NotPersistentBucket;
import network.crypta.support.io.NullOutputStream;
import network.crypta.support.io.ResumeFailedException;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Inserts a single logical file, optionally accompanied by client metadata.
 *
 * <p>This component prepares content for insertion by computing optional multi-algorithm hashes,
 * selecting and applying a compression codec when beneficial, and then delegating to either a
 * {@code SingleBlockInserter} (for small payloads) or a {@code SplitFileInserter} (for larger
 * payloads). Compression may be performed off the calling thread; after compression, this instance
 * coordinates subsequent steps and emits progress via a {@link PutCompletionCallback}.
 *
 * <p>Typical usage is: construct an instance with the desired {@link InsertContext} and {@link
 * InsertBlock}, call {@link #start(ClientContext)} to begin preprocessing, and allow it to drive
 * the operation until success or failure. For larger content, this class also arranges insertion of
 * an accompanying metadata document (redirect or archive manifest) and exposes {@link SplitHandler}
 * to coordinate between the splitfile and its metadata.
 *
 * <ul>
 *   <li>Concurrency: lifecycle flags are synchronized; callbacks may arrive at worker threads.
 *   <li>Mutability: instances are stateful and often persisted for durable requests. Transient
 *       links are restored on resume.
 *   <li>Trade-offs: compression is skipped when disabled by context or when the data already fits a
 *       block without benefit.
 * </ul>
 *
 * <p>WARNING: Changing non-transient members on classes that are {@link Serializable} can result in
 * losing uploads across restarts. Maintain serialization compatibility.
 */
class SingleFileInserter implements ClientPutState, Serializable {
  private static final Logger LOG = LoggerFactory.getLogger(SingleFileInserter.class);

  @Serial private static final long serialVersionUID = 1L;

  final BaseClientPutter parent;
  InsertBlock block;
  final InsertContext ctx;
  final boolean metadata;

  // Callback for lifecycle events. Must remain serializable because SingleFileInserter
  // is persisted for durable requests and resumes after restarts.
  @SuppressWarnings("java:S1948")
  PutCompletionCallback cb;

  final ARCHIVE_TYPE archiveType;

  /**
   * If true, we are not the top level request, and should not update our parent to point to us as
   * current put-stage.
   */
  private final boolean reportMetadataOnly;

  /**
   * Application correlation token associated with this insert.
   *
   * <p>The token is echoed to callbacks so callers can correlate lifecycle events. It must be
   * serializable because durable puts may be persisted and later resumed. Prefer small, immutable
   * identifiers rather than large objects or sensitive data.
   */
  @SuppressWarnings("java:S1948")
  public final Object token;

  private final boolean freeData; // this is being set, but never read ???
  private final String targetFilename;
  private final boolean persistent;
  private boolean started;
  private boolean cancelled;
  private final boolean forSplitfile;
  private final long origDataLength;
  private final long origCompressedDataLength;
  private HashResult[] origHashes;

  /** Caller preference to disable compression for this inserter. */
  private final boolean dontCompress;

  /** If true, use random crypto keys for CHKs. */
  private final byte[] forceCryptoKey;

  private final byte cryptoAlgorithm;
  private final boolean realTimeFlag;

  /**
   * When positive, means we will return metadata rather than a URI, once the metadata is under this
   * length. If it is too short it is still possible to return a URI, but we won't return both.
   */
  private final long metadataThreshold;

  // A persistent hashCode is helpful in debugging, and also means we can put
  // these objects into sets etc. when we need to.

  private final int hashCode;

  @Override
  public int hashCode() {
    return hashCode;
  }

  @Override
  @SuppressWarnings("RedundantMethodOverride")
  public boolean equals(Object obj) {
    return this == obj;
  }

  /**
   * Creates a new single-file inserter for the provided block and context.
   *
   * <p>The inserter may compress the data, compute hash digests, and then choose the appropriate
   * underlying strategy (single block vs. splitfile). For large content, it may also construct and
   * insert metadata such as a redirect or archive manifest.
   *
   * @param parent owning putter that receives state transitions and aggregates results; never
   *     {@code null}.
   * @param cb callback that observes progress and completion events; must be serializable for
   *     durable requests.
   * @param block input data and client metadata to insert; desired URI determines key type and
   *     sizing.
   * @param metadata whether this inserter represents metadata rather than primary data; affects
   *     hashing and redirect behavior.
   * @param ctx insertion configuration including compatibility mode, compression policy, and event
   *     producer.
   * @param realTimeFlag hint that the request prefers reduced latency to throughput; may affect
   *     scheduling.
   * @param dontCompress when {@code true}, disables compression regardless of heuristics.
   * @param reportMetadataOnly when {@code true}, do not insert metadata; return it directly
   *     instead.
   * @param token application correlation token echoed on callbacks; may be {@code null}.
   * @param archiveType optional archive type indicating an archive manifest should be produced
   *     (when applicable); may be {@code null}.
   * @param freeData when {@code true}, frees underlying data as soon as possible to reduce resource
   *     usage.
   * @param targetFilename optional preferred filename for redirect/manifest entries; may be {@code
   *     null}.
   * @param forSplitfile whether this insertion is above a splitfile, affecting duplicate extra
   *     insert policy.
   * @param persistent whether the request is durable across restarts; influences bucket selection
   *     and resume behavior.
   * @param origDataLength original uncompressed length for reporting; {@code 0} when unknown.
   * @param origCompressedDataLength original compressed length for reporting; {@code 0} when
   *     unknown.
   * @param origHashes optional precomputed hashes to reuse; {@code null} to compute if needed.
   * @param cryptoAlgorithm CHK cryptographic algorithm identifier to use when generating keys.
   * @param forceCryptoKey optional explicit CHK key material; {@code null} to use a random key.
   * @param metadataThreshold when positive, return metadata bytes directly if serialized metadata
   *     is shorter than this many bytes.
   */
  SingleFileInserter(
      BaseClientPutter parent,
      PutCompletionCallback cb,
      InsertBlock block,
      boolean metadata,
      InsertContext ctx,
      boolean realTimeFlag,
      boolean dontCompress,
      boolean reportMetadataOnly,
      Object token,
      ARCHIVE_TYPE archiveType,
      boolean freeData,
      String targetFilename,
      boolean forSplitfile,
      boolean persistent,
      long origDataLength,
      long origCompressedDataLength,
      HashResult[] origHashes,
      byte cryptoAlgorithm,
      byte[] forceCryptoKey,
      long metadataThreshold) {
    hashCode = super.hashCode();
    this.reportMetadataOnly = reportMetadataOnly;
    this.token = token;
    this.parent = parent;
    this.block = block;
    this.ctx = ctx;
    this.realTimeFlag = realTimeFlag;
    this.metadata = metadata;
    this.cb = cb;
    this.archiveType = archiveType;
    this.freeData = freeData;
    this.targetFilename = targetFilename;
    this.persistent = persistent;
    this.forSplitfile = forSplitfile;
    this.origCompressedDataLength = origCompressedDataLength;
    this.origDataLength = origDataLength;
    this.origHashes = origHashes;
    this.forceCryptoKey = forceCryptoKey;
    this.cryptoAlgorithm = cryptoAlgorithm;
    this.metadataThreshold = metadataThreshold;
    this.dontCompress = dontCompress;
    if (LOG.isDebugEnabled())
      LOG.debug("Created {} persistent={} freeData={}", this, persistent, freeData);
  }

  /**
   * Starts preprocessing (compression and hashing) and advances insertion.
   *
   * <p>When compression is likely to help, work is dispatched to a background worker. After
   * completion, this instance determines whether the data fits in a single block or requires a
   * splitfile and proceeds accordingly. Progress and terminal events are delivered through the
   * configured callback.
   *
   * @param context execution context providing job runners and bucket factories; must not be {@code
   *     null}.
   * @throws InsertException if preprocessing cannot be started due to invalid inputs or context
   *     state.
   */
  public void start(ClientContext context) throws InsertException {
    tryCompress(context);
  }

  @SuppressWarnings("java:S1181")
  void onCompressed(CompressionOutput output, ClientContext context) {
    synchronized (this) {
      if (started) {
        LOG.error("Already started, not starting again");
        return;
      }
      if (cancelled) {
        LOG.error("Already cancelled, not starting");
        return;
      }
    }
    try {
      onCompressedInner(output, context);
    } catch (InsertException e) {
      cb.onFailure(e, SingleFileInserter.this, context);
    } catch (Throwable t) {
      LOG.error("Caught in OffThreadCompressor: {}", t, t);
      // Try to fail gracefully
      cb.onFailure(
          new InsertException(InsertExceptionMode.INTERNAL_ERROR, t, null),
          SingleFileInserter.this,
          context);
    }
  }

  void onCompressedInner(CompressionOutput output, ClientContext context) throws InsertException {
    long origSize = block.getData().size();
    HashProcess hp = processHashes(output, context);
    HashResult[] hashes = hp.hashes;
    byte[] hashThisLayerOnly = hp.hashThisLayerOnly;

    DataPrep dp = prepareData(output, origSize);
    RandomAccessBucket data = dp.data;
    long bestCompressedDataSize = dp.bestCompressedDataSize;
    COMPRESSOR_TYPE bestCodec = dp.bestCodec;
    boolean shouldFreeData = dp.shouldFreeData;

    KeyKind key = computeKeyKind(block.desiredURI);
    int blockSize = key.blockSize;
    int oneBlockCompressedSize = key.oneBlockCompressedSize;
    boolean isCHK = key.isCHK;
    boolean isUSK = key.isUSK;

    // Compressed data ; now insert it
    // We do NOT need to switch threads here: the actual compression is done by InsertCompressor on
    // the RealCompressor thread,
    // which then switches either to the database thread or to a new executable to run this method.

    if (parent == cb)
      emitCompressionFinished(bestCodec, origSize, bestCompressedDataSize, data, context);

    // Insert it...
    short codecNumber = bestCodec == null ? -1 : bestCodec.metadataID;
    long compressedDataSize = data.size();
    Fit fits = computeFitFlags(bestCodec, compressedDataSize, blockSize, oneBlockCompressedSize);
    boolean fitsInOneBlockAsIs = fits.inBlock;
    boolean fitsInOneCHK = fits.inCHK;

    if ((fitsInOneBlockAsIs || fitsInOneCHK) && origSize > Integer.MAX_VALUE)
      throw new InsertException(
          InsertExceptionMode.INTERNAL_ERROR, "2GB+ should not encode to one block!", null);

    boolean noMetadata =
        ((block.clientMetadata == null) || block.clientMetadata.isTrivial())
            && targetFilename == null;
    if ((noMetadata || metadata) && archiveType == null && fitsInOneBlockAsIs) {
      handleDirectInsertWithoutMetadata(
          data, codecNumber, origSize, isUSK, isCHK, shouldFreeData, context);
      return;
    }
    if (fitsInOneCHK) {
      handleInsertFitsInOneCHK(data, codecNumber, origSize, isUSK, shouldFreeData, hashes, context);
      return;
    }
    handleSplitfile(data, origSize, bestCodec, hashThisLayerOnly, hashes, shouldFreeData, context);
  }

  private static class HashProcess {
    final HashResult[] hashes;
    final byte[] hashThisLayerOnly;

    HashProcess(HashResult[] hashes, byte[] hashThisLayerOnly) {
      this.hashes = hashes;
      this.hashThisLayerOnly = hashThisLayerOnly;
    }
  }

  private HashProcess processHashes(CompressionOutput output, ClientContext context) {
    HashResult[] hashes = output.hashes();
    long origSize = block.getData().size();
    byte[] hashThisLayerOnly = null;
    if (hashes != null && metadata) {
      if (HashResult.contains(hashes, HashType.SHA256)) {
        hashThisLayerOnly = HashResult.get(hashes, HashType.SHA256);
      }
      hashes = null; // Inherit origHashes
    }
    if (hashes != null) {
      if (LOG.isTraceEnabled()) {
        LOG.debug("Computed hashes for {} for {} size {}", this, block.desiredURI, origSize);
        for (HashResult res : hashes) {
          LOG.trace("{} : {}", res.type.name(), res.hashAsHex());
        }
      }
      HashResult[] clientHashes = hashes;
      if (persistent) clientHashes = HashResult.copy(hashes);
      ctx.getEventProducer().produceEvent(new ExpectedHashesEvent(clientHashes), context);
      origHashes = hashes;
    } else {
      hashes = origHashes; // Inherit so it goes all the way to the top.
    }
    return new HashProcess(hashes, hashThisLayerOnly);
  }

  private record DataPrep(
      RandomAccessBucket data,
      long bestCompressedDataSize,
      COMPRESSOR_TYPE bestCodec,
      boolean shouldFreeData) {}

  /**
   * Prepare the data bucket and related compression metadata for insertion.
   *
   * <p>Note on resource management (java:S2095): the {@link RandomAccessBucket} obtained from the
   * provided {@link CompressionOutput} is intentionally not closed in this method. Ownership of the
   * bucket is transferred to downstream inserters, which will free/close it according to the {@code
   * shouldFreeData} flag and insertion flow. Closing it here would prematurely release the
   * underlying storage and break subsequent processing.
   */
  @SuppressWarnings({"resource"})
  private DataPrep prepareData(CompressionOutput output, long origSize) {
    RandomAccessBucket bestCompressedData = output.data();
    long bestCompressedDataSize = bestCompressedData.size();
    RandomAccessBucket data = bestCompressedData;
    COMPRESSOR_TYPE bestCodec = output.bestCodec();
    boolean shouldFreeData = freeData;
    if (bestCodec != null) {
      if (LOG.isDebugEnabled())
        LOG.debug(
            "The best compression algorithm is {} we have gained{}% ! ({}/{})",
            bestCodec,
            100 - (bestCompressedDataSize * 100 / origSize),
            origSize,
            bestCompressedDataSize);
      shouldFreeData =
          true; // must be freed regardless of whether the original data was to be freed
      if (freeData) {
        block.getData().free();
      }
      block.nullData();
    } else {
      data = block.getData();
      bestCompressedDataSize = origSize;
    }
    return new DataPrep(data, bestCompressedDataSize, bestCodec, shouldFreeData);
  }

  private record KeyKind(int blockSize, int oneBlockCompressedSize, boolean isCHK, boolean isUSK) {}

  private KeyKind computeKeyKind(FreenetURI uri) throws InsertException {
    if (uri == null) {
      throw new InsertException(InsertExceptionMode.INVALID_URI, "Null key type", null);
    }
    boolean isCHK = false;
    boolean isUSK = uri.getKeyType().equals("USK");
    int blockSize;
    int oneBlockCompressedSize;
    String type = uri.getKeyType();
    if (type.equals("SSK") || type.equals("KSK") || isUSK) {
      blockSize = SSKBlock.DATA_LENGTH;
      oneBlockCompressedSize = SSKBlock.MAX_COMPRESSED_DATA_LENGTH;
    } else if (type.equals("CHK")) {
      blockSize = CHKBlock.DATA_LENGTH;
      oneBlockCompressedSize = CHKBlock.MAX_COMPRESSED_DATA_LENGTH;
      isCHK = true;
    } else {
      throw new InsertException(InsertExceptionMode.INVALID_URI, "Unknown key type: " + type, null);
    }
    return new KeyKind(blockSize, oneBlockCompressedSize, isCHK, isUSK);
  }

  private record Fit(boolean inBlock, boolean inCHK) {}

  private Fit computeFitFlags(
      COMPRESSOR_TYPE bestCodec,
      long compressedDataSize,
      int blockSize,
      int oneBlockCompressedSize) {
    boolean fitsInOneBlockAsIs =
        bestCodec == null
            ? compressedDataSize <= blockSize
            : compressedDataSize <= oneBlockCompressedSize;
    boolean fitsInOneCHK =
        bestCodec == null
            ? compressedDataSize <= CHKBlock.DATA_LENGTH
            : compressedDataSize <= CHKBlock.MAX_COMPRESSED_DATA_LENGTH;
    return new Fit(fitsInOneBlockAsIs, fitsInOneCHK);
  }

  private void emitCompressionFinished(
      COMPRESSOR_TYPE bestCodec,
      long origSize,
      long bestCompressedDataSize,
      RandomAccessBucket data,
      ClientContext context) {
    short codecID = bestCodec == null ? -1 : bestCodec.metadataID;
    ctx.getEventProducer()
        .produceEvent(
            new FinishedCompressionEvent(codecID, origSize, bestCompressedDataSize), context);
    if (LOG.isDebugEnabled())
      LOG.debug("Compressed {} to {} on {} data = {}", origSize, data.size(), this, data);
  }

  private void handleDirectInsertWithoutMetadata(
      RandomAccessBucket data,
      short codecNumber,
      long origSize,
      boolean isUSK,
      boolean isCHK,
      boolean shouldFreeData,
      ClientContext context)
      throws InsertException {
    if (persistent && (data instanceof NotPersistentBucket)) data = fixNotPersistent(data, context);
    ClientPutState bi =
        createInserter(
            parent,
            data,
            codecNumber,
            ctx,
            cb,
            metadata,
            (int) origSize,
            context,
            shouldFreeData,
            forSplitfile);
    if (LOG.isTraceEnabled()) LOG.trace("Inserting without metadata: {} for {}", bi, this);
    cb.onTransition(this, bi, context);
    if (ctx.isEarlyEncode() && bi instanceof SingleBlockInserter inserter && isCHK)
      inserter.getBlock(context);
    bi.schedule(context);
    if (!isUSK) cb.onBlockSetFinished(this, context);
    synchronized (this) {
      started = true;
    }
    if (persistent) {
      block.nullData();
      block = null;
    }
  }

  private void handleInsertFitsInOneCHK(
      RandomAccessBucket data,
      short codecNumber,
      long origSize,
      boolean isUSK,
      boolean shouldFreeData,
      HashResult[] hashes,
      ClientContext context)
      throws InsertException {
    if (persistent && (data instanceof NotPersistentBucket)) {
      data = fixNotPersistent(data, context);
    }
    if (reportMetadataOnly)
      handleReportMetadataOnlyCHK(
          data, codecNumber, origSize, isUSK, hashes, shouldFreeData, context);
    else handleStandardCHK(data, codecNumber, origSize, isUSK, hashes, shouldFreeData, context);
    synchronized (this) {
      started = true;
    }
    if (persistent) {
      block.nullData();
      block = null;
    }
  }

  private void handleReportMetadataOnlyCHK(
      RandomAccessBucket data,
      short codecNumber,
      long origSize,
      boolean isUSK,
      HashResult[] hashes,
      boolean shouldFreeData,
      ClientContext context)
      throws InsertException {
    SingleBlockInserter dataPutter =
        new SingleBlockInserter(
            parent,
            data,
            codecNumber,
            FreenetURI.EMPTY_CHK_URI,
            ctx,
            realTimeFlag,
            cb,
            metadata,
            (int) origSize,
            -1,
            true,
            true,
            token,
            context,
            persistent,
            shouldFreeData,
            forSplitfile
                ? ctx.getExtraInsertsSplitfileHeaderBlock()
                : ctx.getExtraInsertsSingleBlock(),
            cryptoAlgorithm,
            forceCryptoKey);
    if (LOG.isTraceEnabled()) LOG.trace("Inserting with metadata: {} for {}", dataPutter, this);
    Metadata meta = makeMetadata(archiveType, dataPutter.getURI(context), hashes);
    cb.onMetadata(meta, this, context);
    cb.onTransition(this, dataPutter, context);
    dataPutter.schedule(context);
    if (!isUSK) cb.onBlockSetFinished(this, context);
    synchronized (this) {
      // Don't delete them because they are being passed on.
      origHashes = null;
    }
  }

  private void handleStandardCHK(
      RandomAccessBucket data,
      short codecNumber,
      long origSize,
      boolean isUSK,
      HashResult[] hashes,
      boolean shouldFreeData,
      ClientContext context)
      throws InsertException {
    MultiPutCompletionCallback mcb =
        new MultiPutCompletionCallback(cb, parent, token, persistent, false, ctx.isEarlyEncode());
    SingleBlockInserter dataPutter =
        new SingleBlockInserter(
            parent,
            data,
            codecNumber,
            FreenetURI.EMPTY_CHK_URI,
            ctx,
            realTimeFlag,
            mcb,
            metadata,
            (int) origSize,
            -1,
            true,
            false,
            token,
            context,
            persistent,
            shouldFreeData,
            forSplitfile
                ? ctx.getExtraInsertsSplitfileHeaderBlock()
                : ctx.getExtraInsertsSingleBlock(),
            cryptoAlgorithm,
            forceCryptoKey);
    if (LOG.isTraceEnabled()) LOG.trace("Inserting data: {} for {}", dataPutter, this);
    Metadata meta = makeMetadata(archiveType, dataPutter.getURI(context), hashes);
    RandomAccessBucket metadataBucket;
    try {
      metadataBucket = meta.toBucket(context.getBucketFactory(persistent));
    } catch (IOException e) {
      throw new InsertException(InsertExceptionMode.BUCKET_ERROR, e, null);
    } catch (MetadataUnresolvedException e) {
      // Impossible, we're not inserting a manifest.
      throw new InsertException(
          InsertExceptionMode.INTERNAL_ERROR,
          "Got MetadataUnresolvedException in SingleFileInserter: " + e,
          null);
    }
    ClientPutState metaPutter =
        createInserter(
            parent,
            metadataBucket,
            (short) -1,
            ctx,
            mcb,
            true,
            (int) origSize,
            context,
            true,
            false);
    if (LOG.isTraceEnabled()) LOG.trace("Inserting metadata: {} for {}", metaPutter, this);
    mcb.addURIGenerator(metaPutter);
    mcb.add(dataPutter);
    cb.onTransition(this, mcb, context);
    LOG.trace("{} : data {} meta {}", mcb, dataPutter, metaPutter);
    mcb.arm(context);
    dataPutter.schedule(context);
    if (ctx.isEarlyEncode() && metaPutter instanceof SingleBlockInserter inserter)
      inserter.getBlock(context);
    metaPutter.schedule(context);
    if (!isUSK) cb.onBlockSetFinished(this, context);
    // Deleting origHashes is fine, we are done with them.
  }

  private void handleSplitfile(
      RandomAccessBucket data,
      long origSize,
      COMPRESSOR_TYPE bestCodec,
      byte[] hashThisLayerOnly,
      HashResult[] hashes,
      boolean shouldFreeData,
      ClientContext context)
      throws InsertException {

    // Otherwise the file is too big to fit into one block
    // We therefore must make a splitfile
    // Job of SplitHandler: when the splitinserter has the metadata,
    // insert it. Then when the splitinserter has finished, and the
    // metadata insert has finished too, tell the master callback.
    LockableRandomAccessBuffer dataRAF;
    try {
      dataRAF = data.toRandomAccessBuffer();
    } catch (IOException e) {
      throw new InsertException(InsertExceptionMode.BUCKET_ERROR, e, null);
    }
    if (reportMetadataOnly) {
      SplitFileInserter.Options opts =
          new SplitFileInserter.Options.Builder()
              .ctx(ctx)
              .context(context)
              .decompressedLength(origSize)
              .compressionCodec(bestCodec)
              .meta(block.clientMetadata)
              .isMetadata(metadata)
              .archiveType(archiveType)
              .splitfileCryptoAlgorithm(cryptoAlgorithm)
              .splitfileCryptoKey(forceCryptoKey)
              .hashThisLayerOnly(hashThisLayerOnly)
              .hashes(hashes)
              .topDontCompress((ctx.isDontCompress() || this.dontCompress))
              .topRequiredBlocks(parent.getMinSuccessFetchBlocks())
              .topTotalBlocks(parent.getTotalBlocks())
              .origDataSize(origDataLength)
              .origCompressedDataSize(origCompressedDataLength)
              .realTime(realTimeFlag)
              .token(token)
              .build();
      SplitFileInserter sfi =
          new SplitFileInserter(persistent, parent, cb, dataRAF, shouldFreeData, opts);
      if (LOG.isTraceEnabled()) LOG.trace("Inserting as splitfile: {} for {}", sfi, this);
      cb.onTransition(this, sfi, context);
      sfi.schedule(context);
      block.nullData();
      block.nullMetadata();
      synchronized (this) {
        // Don't delete them because they are being passed on.
        origHashes = null;
      }
    } else {
      CompatibilityMode cmode = ctx.getCompatibilityMode();
      boolean allowSizes =
          (cmode == CompatibilityMode.COMPAT_CURRENT
              || cmode.ordinal() >= CompatibilityMode.COMPAT_1255.ordinal());
      if (metadata) allowSizes = false;
      SplitHandler sh = new SplitHandler(origSize, data.size(), allowSizes);
      SplitFileInserter.Options opts =
          new SplitFileInserter.Options.Builder()
              .ctx(ctx)
              .context(context)
              .decompressedLength(origSize)
              .compressionCodec(bestCodec)
              .meta(block.clientMetadata)
              .isMetadata(metadata)
              .archiveType(archiveType)
              .splitfileCryptoAlgorithm(cryptoAlgorithm)
              .splitfileCryptoKey(forceCryptoKey)
              .hashThisLayerOnly(hashThisLayerOnly)
              .hashes(hashes)
              .topDontCompress((ctx.isDontCompress() || this.dontCompress))
              .topRequiredBlocks(parent.getMinSuccessFetchBlocks())
              .topTotalBlocks(parent.getTotalBlocks())
              .origDataSize(origDataLength)
              .origCompressedDataSize(origCompressedDataLength)
              .realTime(realTimeFlag)
              .token(token)
              .build();
      SplitFileInserter sfi =
          new SplitFileInserter(persistent, parent, sh, dataRAF, shouldFreeData, opts);
      sh.sfi = sfi;
      if (LOG.isTraceEnabled())
        LOG.trace("Inserting as splitfile: {} for {} for {}", sfi, sh, this);
      cb.onTransition(this, sh, context);
      sfi.schedule(context);
      synchronized (this) {
        started = true;
      }
      // SplitHandler will need this.origHashes.
    }
  }

  private RandomAccessBucket fixNotPersistent(RandomAccessBucket data, ClientContext context)
      throws InsertException {
    try {
      if (LOG.isDebugEnabled()) LOG.debug("Copying data from {} length {}", data, data.size());
      RandomAccessBucket newData = context.persistentBucketFactory.makeBucket(data.size());
      BucketTools.copy(data, newData);
      data.free();
      data = newData;
    } catch (IOException e) {
      throw new InsertException(InsertExceptionMode.BUCKET_ERROR, e, null);
    }
    // Note that SegmentedBCB *does* support splitting, so we don't need to do anything to the data
    // if it doesn't fit in a single block.
    return data;
  }

  private void tryCompress(ClientContext context) throws InsertException {
    RandomAccessBucket origData = block.getData();
    if (block.desiredURI == null) {
      throw new InsertException(InsertExceptionMode.INVALID_URI, "Null key type", null);
    }
    BlockSizes sizes = determineBlockSizes(block.desiredURI.getKeyType().toUpperCase());
    long origSize = origData.size();
    long wantHashes = computeWantedHashes(origData.size());
    boolean tryCompress =
        (origSize > sizes.blockSize) && !(ctx.isDontCompress() || this.dontCompress);
    if (tryCompress) {
      InsertCompressor.start(
          context,
          this,
          origData,
          sizes.oneBlockCompressedSize,
          context.getBucketFactory(persistent),
          persistent,
          wantHashes);
    } else {
      scheduleNoCompression(origData, wantHashes, origSize, sizes.blockSize, context);
    }
  }

  private void scheduleNoCompression(
      RandomAccessBucket origData,
      long wantHashes,
      long origSize,
      int blockSize,
      ClientContext context)
      throws InsertException {
    if (LOG.isDebugEnabled())
      LOG.debug("Not compressing {} size = {} block size = {}", origData, origSize, blockSize);
    HashResult[] hashes = null;
    if (wantHashes != 0) {
      // Need to get the hashes anyway
      NullOutputStream nos = new NullOutputStream();
      MultiHashOutputStream hasher = new MultiHashOutputStream(nos, wantHashes);
      try {
        BucketTools.copyTo(origData, hasher, origData.size());
      } catch (IOException e) {
        throw new InsertException(
            InsertExceptionMode.BUCKET_ERROR, "I/O error generating hashes", e, null);
      }
      hashes = hasher.getResults();
    }
    final CompressionOutput output = new CompressionOutput(origData, null, hashes);
    context
        .getJobRunner(persistent)
        .queueNormalOrDrop(
            context1 -> {
              onCompressed(output, context1);
              return true;
            });
  }

  private long computeWantedHashes(long size) {
    // We always want SHA256, even for small files.
    long wantHashes = 0;
    CompatibilityMode cmode = ctx.getCompatibilityMode();
    boolean atLeast1254 =
        (cmode == CompatibilityMode.COMPAT_CURRENT
            || cmode.ordinal() >= CompatibilityMode.COMPAT_1255.ordinal());
    if (atLeast1254) {
      // We verify this. We want it for *all* files.
      wantHashes |= HashType.SHA256.bitmask;
      // If the user requests it, calculate the others for small files.
      // The thresholds could be made configurable in the future.
      if (size >= 1024 * 1024 && !metadata) {
        // SHA1 is common and MD5 is cheap.
        wantHashes |= HashType.SHA1.bitmask;
        wantHashes |= HashType.MD5.bitmask;
      }
      if (size >= 4 * 1024 * 1024 && !metadata) {
        // Useful for cross-network, and cheap.
        wantHashes |= HashType.ED2K.bitmask;
        // Very widely supported for cross-network.
        wantHashes |= HashType.TTH.bitmask;
        // For completeness.
        wantHashes |= HashType.SHA512.bitmask;
      }
    }
    return wantHashes;
  }

  private record BlockSizes(int blockSize, int oneBlockCompressedSize) {}

  private BlockSizes determineBlockSizes(String type) throws InsertException {
    int blockSize;
    int oneBlockCompressedSize;
    if (type.equals("SSK") || type.equals("KSK") || type.equals("USK")) {
      blockSize = SSKBlock.DATA_LENGTH;
      oneBlockCompressedSize = SSKBlock.MAX_COMPRESSED_DATA_LENGTH;
    } else if (type.equals("CHK")) {
      blockSize = CHKBlock.DATA_LENGTH;
      oneBlockCompressedSize = CHKBlock.MAX_COMPRESSED_DATA_LENGTH;
    } else {
      throw new InsertException(InsertExceptionMode.INVALID_URI, "Unknown key type: " + type, null);
    }
    return new BlockSizes(blockSize, oneBlockCompressedSize);
  }

  private Metadata makeMetadata(ARCHIVE_TYPE archiveType, FreenetURI uri, HashResult[] hashes) {
    Metadata meta;
    boolean allowTopBlocks = origDataLength != 0;
    int req = 0;
    int total = 0;
    long data = 0;
    long compressed = 0;
    boolean topDontCompress = false;
    CompatibilityMode topCompatibilityMode = CompatibilityMode.COMPAT_UNKNOWN;
    if (allowTopBlocks) {
      req = parent.getMinSuccessFetchBlocks();
      total = parent.totalBlocks;
      topDontCompress = (ctx.isDontCompress() || this.dontCompress);
      topCompatibilityMode = ctx.getCompatibilityMode();
      data = origDataLength;
      compressed = origCompressedDataLength;
    }
    if (archiveType != null) {
      meta =
          new Metadata(
              DocumentType.ARCHIVE_MANIFEST,
              archiveType,
              null,
              uri,
              block.clientMetadata,
              data,
              compressed,
              req,
              total,
              topDontCompress,
              topCompatibilityMode,
              hashes);
    } else { // redirect
      meta =
          new Metadata(
              DocumentType.SIMPLE_REDIRECT,
              null,
              null,
              uri,
              block.clientMetadata,
              data,
              compressed,
              req,
              total,
              topDontCompress,
              topCompatibilityMode,
              hashes);
    }
    if (targetFilename != null) {
      HashMap<String, Object> hm = new HashMap<>();
      hm.put(targetFilename, meta);
      meta = Metadata.mkRedirectionManifestWithMetadata(hm);
    }
    return meta;
  }

  /**
   * Create an inserter, either for a USK or a single block.
   *
   * <p>Within this helper, we always add the created inserter to the parent and use a sentinel
   * token value of {@code -1}. Call sites that need different behavior construct inserters
   * directly.
   *
   * @param forSplitfile Whether this insert is above a splitfile. This affects whether we do
   *     multiple inserts of the same block.
   */
  private ClientPutState createInserter(
      BaseClientPutter parent,
      Bucket data,
      short compressionCodec,
      InsertContext ctx,
      PutCompletionCallback cb,
      boolean isMetadata,
      int sourceLength,
      ClientContext context,
      boolean freeData,
      boolean forSplitfile)
      throws InsertException {

    FreenetURI uri = block.desiredURI;
    if (uri == null) {
      throw new InsertException(InsertExceptionMode.INVALID_URI, "Null key type", null);
    }
    uri.checkInsertURI(); // will throw an exception if needed

    if (uri.getKeyType().equals("USK")) {
      try {
        return new USKInserter(
            parent,
            data,
            compressionCodec,
            uri,
            ctx,
            cb,
            isMetadata,
            sourceLength,
            -1,
            true,
            this.token,
            context,
            freeData,
            persistent,
            realTimeFlag,
            forSplitfile
                ? ctx.getExtraInsertsSplitfileHeaderBlock()
                : ctx.getExtraInsertsSingleBlock(),
            cryptoAlgorithm,
            forceCryptoKey);
      } catch (MalformedURLException e) {
        throw new InsertException(InsertExceptionMode.INVALID_URI, e, null);
      }
    } else {
      SingleBlockInserter sbi =
          new SingleBlockInserter(
              parent,
              data,
              compressionCodec,
              uri,
              ctx,
              realTimeFlag,
              cb,
              isMetadata,
              sourceLength,
              -1,
              true,
              false,
              this.token,
              context,
              persistent,
              freeData,
              forSplitfile
                  ? ctx.getExtraInsertsSplitfileHeaderBlock()
                  : ctx.getExtraInsertsSingleBlock(),
              cryptoAlgorithm,
              forceCryptoKey);
      // pass uri to SBI
      block.nullURI();
      return sbi;
    }
  }

  /**
   * Coordinates insertion of a splitfile and its companion metadata.
   *
   * <p>{@code SplitHandler} listens to child inserter callbacks, tracks whether the data splitfile
   * and the metadata branch have each finished, and forwards progress to the upstream callback. For
   * small metadata under the inlining threshold, it returns the metadata bytes directly; otherwise
   * it constructs and schedules a dedicated metadata inserter.
   *
   * <p>Lifecycle: the handler tolerates out-of-order completion (metadata first or data first),
   * idempotently ignores duplicate notifications, and ensures both branches are cancelled on
   * failure. On resume, it rewires missing callbacks for deserialized children and restarts work as
   * permitted by policy.
   */
  public class SplitHandler implements PutCompletionCallback, ClientPutState, Serializable {

    @Serial private static final long serialVersionUID = 1L;

    @SuppressWarnings("java:S1948")
    ClientPutState sfi;

    @SuppressWarnings("java:S1948")
    ClientPutState metadataPutter;

    boolean finished;
    boolean splitInsertSuccess;
    boolean metaInsertSuccess;
    boolean splitInsertSetBlocks;
    boolean metaInsertSetBlocks;
    boolean metaInsertStarted;
    boolean metaFetchable;
    final boolean persistent;
    final long origDataLength;
    final long origCompressedDataLength;
    private transient boolean resumed;

    // A persistent hashCode is helpful in debugging, and also means we can put
    // these objects into sets etc. when we need to.

    private final int hashCode;

    @Override
    public int hashCode() {
      return hashCode;
    }

    @Override
    @SuppressWarnings("RedundantMethodOverride")
    public boolean equals(Object obj) {
      return this == obj;
    }

    /**
     * Constructs a handler with size hints for reporting when allowed.
     *
     * @param origDataLength original uncompressed length for UI/reporting when available; ignored
     *     if {@code allowSizes} is {@code false}.
     * @param origCompressedDataLength original compressed length for UI/reporting; ignored when
     *     {@code allowSizes} is {@code false}.
     * @param allowSizes when {@code true}, copies the supplied sizes; otherwise stores zeroes.
     */
    public SplitHandler(long origDataLength, long origCompressedDataLength, boolean allowSizes) {
      // Default constructor
      this.persistent = SingleFileInserter.this.persistent;
      this.hashCode = super.hashCode();
      this.origDataLength = allowSizes ? origDataLength : 0;
      this.origCompressedDataLength = allowSizes ? origCompressedDataLength : 0;
    }

    /**
     * Rewire callbacks for deserialized children to this handler when missing.
     *
     * <p>Older serialized forms omitted the callback on the metadata inserter (a {@link
     * SingleFileInserter}). If found {@code null} or incorrectly pointing to the parent putter,
     * restore it to this handler so lifecycle events reach the coordinating SplitHandler.
     */
    @Serial
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
      in.defaultReadObject();
      // Only fix when callback is absent or points to the parent putter (unsafe fallback).
      if (metadataPutter instanceof SingleFileInserter childSfi
          && (childSfi.cb == null || childSfi.cb == parent)) {
        childSfi.cb = this;
      }
    }

    /** {@inheritDoc} */
    @Override
    public synchronized void onTransition(
        ClientPutState oldState, ClientPutState newState, ClientContext context) {
      if (persistent && LOG.isTraceEnabled()) {
        LOG.trace("Transition: {} -> {}", oldState, newState);
      }
      if (oldState == sfi) sfi = newState;
      if (oldState == metadataPutter) metadataPutter = newState;
    }

    /**
     * Handles successful completion of a child inserter and advances the overall flow.
     *
     * <p>When the splitfile completes first, metadata may be started immediately (depending on
     * early-encode policy). When metadata completes first, this records success and waits for the
     * splitfile to finish before reporting overall success.
     *
     * @param state the child inserter that completed; either the splitfile or metadata inserter.
     * @param context runtime context used to schedule follow-up work and emit events.
     */
    @Override
    public void onSuccess(ClientPutState state, ClientContext context) {
      if (LOG.isDebugEnabled()) LOG.debug("onSuccess({}) for {}", state, this);
      boolean lateStart = false;
      if (state == sfi) {
        lateStart = markSfiSuccess();
      } else if (state == metadataPutter) {
        markMetadataPutterSuccess();
      } else {
        LOG.warn("Unknown: {} for {}", state, this);
        return;
      }
      boolean finishedNow;
      synchronized (this) {
        finishedNow = (splitInsertSuccess && metaInsertSuccess);
        if (finishedNow) {
          if (LOG.isDebugEnabled()) LOG.debug("Both succeeded for {}", this);
          finished = true;
          if (freeData) block.free();
          else block.nullData();
        }
      }
      if (lateStart && startMetadata(context)) {
        synchronized (this) {
          sfi = null;
        }
      }
      if (finishedNow) cb.onSuccess(this, context);
    }

    private boolean markSfiSuccess() {
      synchronized (this) {
        if (LOG.isTraceEnabled()) LOG.trace("Splitfile insert succeeded for {}", this);
        splitInsertSuccess = true;
        if (!metaInsertSuccess && !metaInsertStarted) return true; // lateStart
        sfi = null;
        if (LOG.isDebugEnabled())
          LOG.debug(
              "Metadata already started for {} : success={} started={}",
              this,
              metaInsertSuccess,
              metaInsertStarted);
      }
      return false;
    }

    private void markMetadataPutterSuccess() {
      synchronized (this) {
        if (LOG.isTraceEnabled()) LOG.trace("Metadata insert succeeded for {}", this);
        metaInsertSuccess = true;
        metadataPutter = null;
      }
    }

    /**
     * Receives a failure from a child inserter and fails the coordinated operation.
     *
     * <p>Cancels the remaining child (if any) and propagates the first observed failure upstream to
     * avoid duplicate notifications.
     *
     * @param e the failure encountered by the child; contains mode and cause details.
     * @param state the child inserter that failed.
     * @param context execution context used for cancellation and callbacks.
     */
    @Override
    public void onFailure(InsertException e, ClientPutState state, ClientContext context) {
      boolean toFail = true;
      synchronized (this) {
        if (LOG.isDebugEnabled())
          LOG.debug(
              "onFailure(): {} on {} on {} sfi = {} metadataPutter = {}",
              e,
              state,
              this,
              sfi,
              metadataPutter);
        if (state == sfi) {
          sfi = null;
        } else if (state == metadataPutter) {
          metadataPutter = null;
        } else {
          LOG.error("onFailure() on unknown state {} on {}", state, this, new Exception("debug"));
        }
        if (finished) {
          toFail = false; // Already failed
        }
      }
      // fail() will cancel the other one, so we don't need to.
      // When it does, it will come back here, and we won't call fail(), because fail() has already
      // set finished = true.
      if (toFail) fail(e, context);
    }

    /**
     * Handles metadata production and decides whether to inline or insert separately.
     *
     * <p>Small metadata (under threshold) is returned directly to the caller. Otherwise, a new
     * metadata inserter is created and started when policy permits. Duplicate notifications from
     * the splitfile are ignored once metadata handling has begun.
     *
     * @param meta the computed metadata document (redirect or archive manifest).
     * @param state the child state producing the metadata, typically the splitfile inserter.
     * @param context runtime context for building buckets and scheduling insertion.
     */
    @Override
    public void onMetadata(Metadata meta, ClientPutState state, ClientContext context) {
      if (LOG.isDebugEnabled()) LOG.debug("Got metadata for {} from {}", this, state);
      // Allow metadata produced by the metadata inserter itself; forward upstream without
      // starting another metadata inserter.
      if (state == metadataPutter) {
        cb.onMetadata(meta, this, context);
        return;
      }
      // Ignore duplicate notifications from the splitfile inserter after metadata has begun.
      if (isDuplicateSplitMetadata(state)) return;
      InsertException e = precheckMetadataState(state);
      if (reportMetadataOnly) {
        cb.onMetadata(meta, this, context);
        return;
      }
      if (e != null) {
        onFailure(e, state, context);
        return;
      }

      byte[] metaBytes = toMetaBytesOrFail(meta, context);
      if (metaBytes.length == 0) return;

      RedirectResult rr = maybeWrapRedirect(meta, metaBytes, context);
      meta = rr.meta();
      metaBytes = rr.bytes();
      String metaPutterTargetFilename = rr.target();
      if (metaBytes.length == 0) return;

      RandomAccessBucket metadataBucket = toMetadataBucketOrFail(metaBytes, context);
      if (metadataBucket == null) return;
      ClientMetadata m = computeClientMetadataForMeta(meta);
      if (tryInlineMetadata(metaBytes, metadataBucket, state, context)) return;
      createAndMaybeStartMetadataPutter(metadataBucket, m, metaPutterTargetFilename, context);
    }

    private boolean isDuplicateSplitMetadata(ClientPutState state) {
      synchronized (this) {
        if (state == sfi && (metadataPutter != null || metaInsertSuccess)) {
          if (LOG.isDebugEnabled())
            LOG.debug("Ignoring duplicate onMetadata from splitfile inserter for {}", this);
          return true;
        }
      }
      return false;
    }

    private ClientMetadata computeClientMetadataForMeta(Metadata meta) {
      ClientMetadata m = meta.getClientMetadata();
      CompatibilityMode cmode = ctx.getCompatibilityMode();
      if (!(cmode == CompatibilityMode.COMPAT_CURRENT
          || cmode.ordinal() >= CompatibilityMode.COMPAT_1255.ordinal())) m = null;
      return m;
    }

    private boolean tryInlineMetadata(
        byte[] metaBytes,
        RandomAccessBucket metadataBucket,
        ClientPutState state,
        ClientContext context) {
      if (metadataThreshold > 0 && metaBytes.length < metadataThreshold) {
        synchronized (this) {
          metaInsertSuccess = true;
        }
        cb.onMetadata(metadataBucket, state, context);
        return true;
      }
      return false;
    }

    private record RedirectResult(Metadata meta, byte[] bytes, String target) {
      @Override
      public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof RedirectResult(var m, var b, var t))) return false;
        if (!java.util.Objects.equals(meta, m)) return false;
        if (!java.util.Arrays.equals(bytes, b)) return false;
        return java.util.Objects.equals(target, t);
      }

      @Override
      public int hashCode() {
        int result = java.util.Objects.hash(meta, target);
        result = 31 * result + java.util.Arrays.hashCode(bytes);
        return result;
      }

      /** {@inheritDoc} */
      @Override
      public @NotNull String toString() {
        return "RedirectResult[meta="
            + meta
            + ", bytes="
            + java.util.Arrays.toString(bytes)
            + ", target="
            + target
            + "]";
      }
    }

    private RedirectResult maybeWrapRedirect(
        Metadata meta, byte[] metaBytes, ClientContext context) {
      String metaPutterTargetFilename = targetFilename;
      if (targetFilename != null && metaBytes.length <= Short.MAX_VALUE) {
        HashMap<String, Object> hm = new HashMap<>();
        hm.put(targetFilename, meta);
        meta = Metadata.mkRedirectionManifestWithMetadata(hm);
        metaPutterTargetFilename = null;
        metaBytes = toMetaBytesOrFail(meta, context);
        if (metaBytes == null) metaBytes = new byte[0];
      }
      return new RedirectResult(meta, metaBytes, metaPutterTargetFilename);
    }

    private InsertException precheckMetadataState(ClientPutState state) {
      InsertException e = null;
      synchronized (this) {
        if (finished)
          return new InsertException(InsertExceptionMode.INTERNAL_ERROR, "Finished", null);
        if (reportMetadataOnly) {
          metaInsertSuccess = true;
        } else if (state != sfi) {
          LOG.error(
              "Got metadata from unknown state {} sfi={} metadataPutter={} on {} persistent={}",
              state,
              sfi,
              metadataPutter,
              this,
              persistent,
              new Exception("debug"));
          e =
              new InsertException(
                  InsertExceptionMode.INTERNAL_ERROR, "Got metadata from unknown state", null);
        } // else state == sfi; metadata may be about to start here.
      }
      return e;
    }

    private RandomAccessBucket toMetadataBucketOrFail(byte[] metaBytes, ClientContext context) {
      try {
        return BucketTools.makeImmutableBucket(context.getBucketFactory(persistent), metaBytes);
      } catch (IOException e1) {
        InsertException ex = new InsertException(InsertExceptionMode.BUCKET_ERROR, e1, null);
        fail(ex, context);
        return null;
      }
    }

    private void createAndMaybeStartMetadataPutter(
        RandomAccessBucket metadataBucket,
        ClientMetadata m,
        String metaPutterTargetFilename,
        ClientContext context) {
      InsertBlock newBlock = new InsertBlock(metadataBucket, m, block.desiredURI);
      synchronized (this) {
        metadataPutter =
            new SingleFileInserter(
                parent,
                this,
                newBlock,
                true,
                ctx,
                realTimeFlag,
                false,
                false,
                token,
                archiveType,
                true,
                metaPutterTargetFilename,
                true,
                persistent,
                origDataLength,
                origCompressedDataLength,
                origHashes,
                cryptoAlgorithm,
                forceCryptoKey,
                metadataThreshold);
        if (origHashes != null) {
          SingleFileInserter.this.origHashes = null;
        }
        if (LOG.isDebugEnabled())
          LOG.debug(
              "Created metadata putter for {} : {} bucket {} size {}",
              this,
              metadataPutter,
              metadataBucket,
              metadataBucket.size());
        if (!(ctx.isEarlyEncode() || splitInsertSuccess)) return;
      }
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Putting metadata on {} from {} ({})",
            metadataPutter,
            sfi,
            ((SplitFileInserter) sfi).getLength());
      if (!startMetadata(context)) {
        LOG.error("onMetadata() yet unable to start metadata due to not having all URIs?!?!");
        fail(
            new InsertException(
                InsertExceptionMode.INTERNAL_ERROR,
                "onMetadata() yet unable to start metadata due to not having all URIs",
                null),
            context);
        return;
      }
      synchronized (this) {
        if (splitInsertSuccess && sfi != null) {
          sfi = null;
        }
      }
    }

    private byte[] toMetaBytesOrFail(Metadata meta, ClientContext context) {
      try {
        return meta.writeToByteArray();
      } catch (MetadataUnresolvedException e1) {
        LOG.error("Impossible: {}", e1, e1);
        fail(
            (InsertException)
                new InsertException(
                        InsertExceptionMode.INTERNAL_ERROR,
                        "MetadataUnresolvedException in SingleFileInserter.SplitHandler: " + e1,
                        null)
                    .initCause(e1),
            context);
        return new byte[0];
      }
    }

    /**
     * Fails the overall operation and cancels outstanding child inserters.
     *
     * @param e the failure to propagate upstream; not {@code null}.
     * @param context context used to cancel children and invoke the upstream callback.
     */
    private void fail(InsertException e, ClientContext context) {
      if (LOG.isTraceEnabled()) LOG.trace("Failing: {}", e, e);
      ClientPutState oldSFI;
      ClientPutState oldMetadataPutter;
      synchronized (this) {
        if (finished) {
          return;
        }
        finished = true;
        oldSFI = sfi;
        oldMetadataPutter = metadataPutter;
      }
      if (oldSFI != null) oldSFI.cancel(context);
      if (oldMetadataPutter != null) oldMetadataPutter.cancel(context);
      synchronized (this) {
        if (freeData) block.free();
        else {
          block.nullData();
        }
      }
      cb.onFailure(e, this, context);
    }

    /** {@inheritDoc} */
    @Override
    public BaseClientPutter getParent() {
      return parent;
    }

    /** {@inheritDoc} */
    @Override
    public void onEncode(BaseClientKey key, ClientPutState state, ClientContext context) {
      if (persistent && LOG.isTraceEnabled())
        LOG.trace("onEncode() for {} : {} : {}", this, state, key);
      synchronized (this) {
        if (state != metadataPutter) {
          if (LOG.isTraceEnabled()) LOG.trace("ignored onEncode() for {} : {}", this, state);
          return;
        }
      }
      cb.onEncode(key, this, context);
    }

    /** {@inheritDoc} */
    @Override
    public void cancel(ClientContext context) {
      if (LOG.isDebugEnabled()) LOG.debug("Cancelling {}", this);
      ClientPutState oldSFI;
      ClientPutState oldMetadataPutter;
      synchronized (this) {
        oldSFI = sfi;
        oldMetadataPutter = metadataPutter;
      }
      if (oldSFI != null) oldSFI.cancel(context);
      if (oldMetadataPutter != null) oldMetadataPutter.cancel(context);

      // In other cases (fail() and onSuccess()), we only free when we set finished.
      // Here we free defensively to avoid leaking, even if callbacks also free.
      if (freeData) {
        block.free();
      } else {
        block.nullData();
      }
    }

    /** {@inheritDoc} */
    @Override
    public void onBlockSetFinished(ClientPutState state, ClientContext context) {
      synchronized (this) {
        if (state == sfi) splitInsertSetBlocks = true;
        else if (state == metadataPutter) metaInsertSetBlocks = true;
        else if (LOG.isTraceEnabled()) LOG.trace("Unrecognised: {} in onBlockSetFinished()", state);
        if (!(splitInsertSetBlocks && metaInsertSetBlocks)) return;
      }
      cb.onBlockSetFinished(this, context);
    }

    /** {@inheritDoc} */
    @Override
    public void schedule(ClientContext context) throws InsertException {
      sfi.schedule(context);
    }

    /** {@inheritDoc} */
    @Override
    public Object getToken() {
      return token;
    }

    /** {@inheritDoc} */
    @Override
    public void onFetchable(ClientPutState state) {
      if (LOG.isDebugEnabled()) {
        if (persistent) LOG.debug("onFetchable on {}", this);
        LOG.debug("onFetchable({})", state);
      }
      boolean isMeta = state == metadataPutter;
      if (!(isMeta || state == sfi)) {
        LOG.error("onFetchable for unknown state {}", state);
        return;
      }
      if (isMeta) {
        synchronized (this) {
          if (!metaInsertStarted) {
            LOG.error(
                "Metadata insert not started yet got onFetchable for it: {} on {}", state, this);
          }
          if (!metaFetchable) metaFetchable = true;
        }
        cb.onFetchable(this);
      } // else state == sfi; for data blocks we do not signal fetchable here
    }

    /**
     * Starts inserting the metadata branch when policy and prerequisites allow.
     *
     * @param context runtime context used to schedule the metadata inserter.
     * @return {@code true} if metadata is already started or successfully scheduled; {@code false}
     *     when the metadata inserter is not yet available.
     */
    private boolean startMetadata(ClientContext context) {
      if (persistent && LOG.isDebugEnabled()) LOG.debug("startMetadata() on {}", this);
      try {
        ClientPutState putter;
        synchronized (this) {
          if (metaInsertStarted) return true;
          putter = metadataPutter;
          if (putter == null) {
            if (LOG.isTraceEnabled()) LOG.trace("Cannot start metadata yet: no metadataPutter");
          } else metaInsertStarted = true;
        }
        if (putter != null) {
          if (LOG.isTraceEnabled())
            LOG.trace("Starting metadata inserter: {} for {}", putter, this);
          putter.schedule(context);
          if (LOG.isTraceEnabled()) LOG.trace("Started metadata inserter: {} for {}", putter, this);
          return true;
        } else {
          return false;
        }
      } catch (InsertException e1) {
        LOG.error("Failing {} : {}", this, e1, e1);
        fail(e1, context);
        return true;
      }
    }

    /** {@inheritDoc} */
    @Override
    public void onMetadata(Bucket meta, ClientPutState state, ClientContext context) {
      if (LOG.isDebugEnabled()) LOG.debug("Got metadata bucket for {} from {}", this, state);
      boolean freeIt = false;
      synchronized (this) {
        if (finished) return;
        if (state == sfi) {
          if (metadataPutter != null) {
            LOG.error(
                "Got metadata from {} even though already started inserting metadata on the next"
                    + " layer on {} !!",
                sfi,
                this);
            freeIt = true;
          } else {
            // Okay, return it.
            metaInsertSuccess = true; // Not going to start it now, so effectively it has succeeded.
          }
        } else if (reportMetadataOnly) {
          metaInsertSuccess = true;
        } else if (state != metadataPutter) {
          LOG.error("Got metadata from unknown object {}", state);
          freeIt = true;
        } // else state == metadataPutter: default path, hand metadata to callback below
      }
      if (freeIt) {
        meta.free();
        return;
      }
      cb.onMetadata(meta, this, context);
    }

    /** {@inheritDoc} */
    @Override
    public void onResume(ClientContext context) throws InsertException, ResumeFailedException {
      synchronized (this) {
        if (resumed) return;
        resumed = true;
      }
      if (sfi != null) sfi.onResume(context);
      if (metadataPutter != null) metadataPutter.onResume(context);
      if (sfi != null) sfi.schedule(context);
      if (metadataPutter != null && (ctx.isEarlyEncode() || sfi == null || metaInsertStarted))
        metadataPutter.schedule(context);
    }

    /** {@inheritDoc} */
    @Override
    public void onShutdown(ClientContext context) {
      ClientPutState splitfileInserter;
      ClientPutState metadataInserter;
      synchronized (this) {
        splitfileInserter = sfi;
        metadataInserter = metadataPutter;
      }
      if (splitfileInserter != null) splitfileInserter.onShutdown(context);
      if (metadataInserter != null) metadataInserter.onShutdown(context);
    }
  }

  /** {@inheritDoc} */
  @Override
  public BaseClientPutter getParent() {
    return parent;
  }

  /**
   * Cancels the operation and reports a {@link InsertExceptionMode#CANCELLED} failure.
   *
   * <p>Cancelling may free underlying data when configured to do so. The upstream callback is
   * invoked to ensure the request is removed from any scheduling structures.
   *
   * @param context runtime context used to perform cancellation and callbacks.
   */
  @Override
  public void cancel(ClientContext context) {
    if (LOG.isDebugEnabled()) LOG.debug("Cancel {}", this);
    synchronized (this) {
      if (cancelled) return;
      cancelled = true;
    }
    if (freeData) {
      block.free();
    }
    // Must call onFailure so get removeFrom()'ed
    cb.onFailure(new InsertException(InsertExceptionMode.CANCELLED), this, context);
  }

  /** {@inheritDoc} */
  @Override
  public void schedule(ClientContext context) throws InsertException {
    start(context);
  }

  /**
   * Returns the application-provided correlation token for this request.
   *
   * @return a token suitable for correlating callbacks with the originating request; may be {@code
   *     null} depending on caller choice.
   */
  @Override
  public Object getToken() {
    return token;
  }

  /**
   * Emits a compression-start event when the outer callback represents the application boundary.
   *
   * <p>This method is invoked by the compressor thread as soon as compression begins so observers
   * can display progress.
   *
   * @param ctype compression algorithm selected for the attempt; never {@code null}.
   * @param context runtime context used to publish the event.
   */
  public void onStartCompression(COMPRESSOR_TYPE ctype, ClientContext context) {
    if (parent == cb) {
      if (ctx == null) throw new NullPointerException();
      if (ctx.getEventProducer() == null) throw new NullPointerException();
      ctx.getEventProducer().produceEvent(new StartedCompressionEvent(ctype), context);
    }
  }

  synchronized boolean cancelled() {
    return cancelled;
  }

  synchronized boolean started() {
    return started;
  }

  private transient boolean resumed = false;

  /** {@inheritDoc} */
  @Override
  public final void onResume(ClientContext context) throws InsertException, ResumeFailedException {
    synchronized (this) {
      if (resumed) return;
      resumed = true;
    }
    if (block != null && block.getData() != null) block.getData().onResume(context);
    if (cb != null && cb != parent) cb.onResume(context);
    synchronized (this) {
      if (started || cancelled) return;
    }
    tryCompress(context);
  }

  /** {@inheritDoc} */
  @Override
  public void onShutdown(ClientContext context) {
    // Ignore.
  }

  /* ===== Java serialization support ===== */

  /**
   * Custom Java deserialization hook to restore transient/runtime links.
   *
   * <p>Older serialized forms written when the callback field was transient will deserialize with
   * {@code cb == null}. To preserve resume behavior, default the callback to the parent putter in
   * that case. Newer serialized forms carry the callback and need no adjustment.
   */
  @Serial
  private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    in.defaultReadObject();
    // Backward compatibility: older persisted forms (where cb was transient) restore with cb==null.
    // Default to the parent putter when it implements PutCompletionCallback so resuming
    // persistent inserts from pre-change versions keeps delivering lifecycle events.
    if (cb == null) {
      if (parent instanceof PutCompletionCallback pcc) {
        cb = pcc;
      } else {
        // Extremely unlikely in current flows, but avoid NPEs if encountered.
        // Prefer logging to throwing to preserve resume behavior.
        if (LOG.isWarnEnabled())
          LOG.warn(
              "Restored SingleFileInserter without callback and parent does not implement "
                  + "PutCompletionCallback; using no-op callback: {}",
              this);
        cb =
            new PutCompletionCallback() {
              @Override
              public void onSuccess(ClientPutState state, ClientContext context) {
                // Intentionally no-op: fallback callback for legacy-deserialized inserters.
                // We only need a safe stub to avoid NPEs when older states resume.
              }

              @Override
              public void onFailure(
                  InsertException e, ClientPutState state, ClientContext context) {
                // Intentionally no-op: see rationale above. Failures are observed upstream when
                // a real callback exists; this stub avoids crashing on legacy resumes.
              }

              @Override
              public void onEncode(BaseClientKey usk, ClientPutState state, ClientContext context) {
                // Intentionally no-op: fallback stub; no external observer to notify.
              }

              @Override
              public void onTransition(
                  ClientPutState oldState, ClientPutState newState, ClientContext context) {
                // Intentionally no-op: fallback stub; used only to prevent NPEs on legacy resumes.
              }

              @Override
              public void onMetadata(Metadata m, ClientPutState state, ClientContext context) {
                // Intentionally no-op: fallback stub for legacy-deserialized inserters without a
                // real observer.
              }

              @Override
              public void onMetadata(Bucket meta, ClientPutState state, ClientContext context) {
                meta.free();
              }

              @Override
              public void onFetchable(ClientPutState state) {
                // Intentionally no-op: no observer present for this legacy fallback.
              }

              @Override
              public void onBlockSetFinished(ClientPutState state, ClientContext context) {
                // Intentionally no-op: fallback stub; prevents NPEs only.
              }

              @Override
              public void onResume(ClientContext context) {
                // Intentionally no-op: fallback stub; nothing to re-attach for a no-op observer.
              }
            };
      }
    }
  }
}

package network.crypta.client.async;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.Serial;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Objects;
import network.crypta.keys.ClientKeyBlock;
import network.crypta.keys.Key;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.io.BucketTools;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Writes a sequence of key blocks to a Binary Blob stream.
 *
 * <p>This utility coordinates the incremental creation of a {@linkplain BinaryBlob Binary Blob}
 * payload that consists of a header, zero or more block records, and a terminating end marker. It
 * supports two operating modes: a single-bucket mode where callers supply the destination bucket at
 * construction time, and a factory-backed mode that accumulates intermediate data across multiple
 * buckets and assembles a final, read-only result on {@link #finalizeBucket()}. The writer ensures
 * that each {@code Key} is written at most once by tracking keys already added.
 *
 * <p>Typical usage creates an instance, adds blocks as they become available, and either snapshots
 * the current content or finalizes the blob when no further data is expected. The class writes the
 * Binary Blob header lazily on the first emission and appends the end marker for snapshots and
 * finalization as needed. Methods that mutate internal state are synchronized to coordinate access
 * when used from multiple threads, but callers should still arrange a clear life-cycle to avoid
 * racing finalization against ongoing writes.
 *
 * <ul>
 *   <li>Single-bucket mode: writes directly to the provided {@code Bucket} and closes its stream on
 *       finalization.
 *   <li>Factory-backed mode: streams to temporary buckets, then builds a single read-only result
 *       bucket, and frees intermediates.
 *   <li>Deduplication: further attempts to add the same {@code Key} are ignored.
 * </ul>
 *
 * @author saces
 * @see BinaryBlob
 */
public final class BinaryBlobWriter {
  private static final Logger LOG = LoggerFactory.getLogger(BinaryBlobWriter.class);

  private final HashSet<Key> binaryBlobKeysAddedAlready;
  private final BucketFactory bf;
  private final ArrayList<Bucket> buckets;
  private final Bucket out;
  private final boolean isSingleBucket;

  private volatile boolean started = false;
  private volatile boolean finalized = false;

  private DataOutputStream streamCache = null;

  /**
   * Persistent/"BigFile" constructor.
   *
   * <p>Creates a writer that allocates intermediate storage from the supplied {@link
   * BucketFactory}. Data is streamed into a series of temporary buckets. When {@link
   * #finalizeBucket()} is called, the writer assembles a single, read-only result bucket that
   * contains the header, all emitted block records, and the end marker.
   *
   * @param bf bucket factory used to create internal temporary buckets; must not be {@code null}.
   */
  public BinaryBlobWriter(BucketFactory bf) {
    binaryBlobKeysAddedAlready = new HashSet<>();
    buckets = new ArrayList<>();
    this.bf = bf;
    out = null;
    isSingleBucket = false;
  }

  /**
   * Transient constructor.
   *
   * <p>Creates a writer that emits directly to the given destination {@code Bucket}. The header is
   * written on first use. On {@link #finalizeBucket()}, the end marker is appended and the
   * underlying stream is closed. The caller retains ownership of the bucket object.
   *
   * @param out destination bucket that receives the blob content; must not be {@code null}.
   */
  public BinaryBlobWriter(Bucket out) {
    binaryBlobKeysAddedAlready = new HashSet<>();
    buckets = null;
    bf = null;
    Objects.requireNonNull(out, "out");
    this.out = out;
    isSingleBucket = true;
  }

  private DataOutputStream getOutputStream() throws IOException, BinaryBlobAlreadyClosedException {
    if (finalized) {
      throw new BinaryBlobAlreadyClosedException(
          "Already finalized (getting final data) on " + this);
    }
    if (streamCache == null) {
      if (isSingleBucket) {
        streamCache = new DataOutputStream(Objects.requireNonNull(out, "out").getOutputStream());
      } else {
        BucketFactory localBf = this.bf;
        ArrayList<Bucket> localBuckets = this.buckets;
        if (localBf == null || localBuckets == null) {
          throw new IllegalStateException("BucketFactory mode requires non-null fields");
        }
        Bucket newBucket = localBf.makeBucket(-1);
        localBuckets.add(newBucket);
        streamCache = new DataOutputStream(newBucket.getOutputStream());
      }
    }
    if (!started) {
      BinaryBlob.writeBinaryBlobHeader(streamCache);
      started = true;
    }
    return streamCache;
  }

  /**
   * Adds a single key block to the binary blob.
   *
   * <p>The Binary Blob header is written lazily on the first call. If the {@code Key} associated
   * with {@code block} has already been added, the call is a no-op and returns silently. The method
   * does not close or flush the destination stream. Callers may invoke this method multiple times
   * from different threads; internal synchronization ensures a consistent serialization order.
   *
   * @param block the block to serialize into the blob; its {@code Key} identifies deduplication and
   *     must be consistent with its internal metadata; must not be {@code null}.
   * @param context optional client context related to the caller; may be {@code null} and is used
   *     only for diagnostic logging, not for serialization semantics.
   * @throws IOException if writing to the underlying stream fails at any point during emission.
   * @throws BinaryBlobAlreadyClosedException if the writer has been finalized or closed and can no
   *     longer accept additional blocks.
   */
  public synchronized void addKey(ClientKeyBlock block, ClientContext context)
      throws IOException, BinaryBlobAlreadyClosedException {
    if (LOG.isTraceEnabled()) {
      LOG.trace("addKey invoked; context present? {}", context != null);
    }
    Key key = block.getKey();
    if (binaryBlobKeysAddedAlready.contains(key)) return;
    BinaryBlob.writeKey(getOutputStream(), block.getBlock(), key);
    binaryBlobKeysAddedAlready.add(key);
  }

  /**
   * Finalizes the blob and seals the result.
   *
   * <p>Appends the Binary Blob end marker and transitions the writer into the finalized state. In
   * single-bucket mode, the underlying stream is closed. In factory-backed mode, the writer creates
   * one read-only bucket containing the full payload, frees any temporary buckets, and retains the
   * result for retrieval via {@link #getFinalBucket()}.
   *
   * @throws IOException if an I/O error occurs while appending the end marker or composing the
   *     final bucket content.
   * @throws BinaryBlobAlreadyClosedException if this writer has already been finalized and cannot
   *     be finalized again.
   */
  public void finalizeBucket() throws IOException, BinaryBlobAlreadyClosedException {
    if (finalized) {
      throw new BinaryBlobAlreadyClosedException("Already finalized (closing blob).");
    }
    finalizeInternal();
  }

  private void finalizeInternal() throws IOException, BinaryBlobAlreadyClosedException {
    if (finalized)
      throw new BinaryBlobAlreadyClosedException("Already finalized (closing blob - 2).");
    if (LOG.isDebugEnabled()) LOG.debug("Finalizing binary blob {}", this);
    if (!isSingleBucket) {
      ArrayList<Bucket> localBuckets = this.buckets;
      BucketFactory localBf = this.bf;
      if (localBuckets == null || localBf == null) {
        throw new IllegalStateException("BucketFactory mode requires non-null fields");
      }
      Bucket resultBucket = localBf.makeBucket(-1);
      snapshotWithEndmarker(resultBucket);
      for (Bucket localBucket : localBuckets) {
        localBucket.free();
      }
      resultBucket.setReadOnly();
      localBuckets.clear();
      localBuckets.addFirst(resultBucket);
    } else {
      DataOutputStream stream = getOutputStream();
      BinaryBlob.writeEndBlob(stream);
      stream.close();
    }
    finalized = true;
  }

  /**
   * Writes a snapshot of the current blob into the provided bucket.
   *
   * <p>The snapshot contains all data written so far and an explicit end marker so that readers can
   * process it immediately. When the writer is already finalized, this method copies the final
   * result instead. In single-bucket mode (transient constructor), no intermediate state exists,
   * and the method returns without writing.
   *
   * @param bucket the destination bucket that receives a complete snapshot, including the end
   *     marker, must be writable; the method closes only the snapshot's output stream it gets.
   * @throws IOException if writing the snapshot to the destination bucket fails at any point.
   * @throws BinaryBlobAlreadyClosedException if the writer is finalized and a non-final snapshot is
   *     requested in a context where it cannot be produced safely.
   */
  public synchronized void getSnapshot(Bucket bucket)
      throws IOException, BinaryBlobAlreadyClosedException {
    if (buckets == null || buckets.isEmpty()) return;
    if (finalized) {
      BucketTools.copy(buckets.getFirst(), bucket);
      return;
    }
    snapshotWithEndmarker(bucket);
  }

  private void snapshotWithEndmarker(Bucket bucket)
      throws IOException, BinaryBlobAlreadyClosedException {
    if (buckets == null || buckets.isEmpty()) return;
    if (finalized) {
      throw new BinaryBlobAlreadyClosedException("Already closed (getting final data snapshot)");
    }
    try (OutputStream os = bucket.getOutputStream()) {
      for (Bucket value : buckets) {
        BucketTools.copyTo(value, os, -1);
      }
      DataOutputStream dout = new DataOutputStream(os);
      BinaryBlob.writeEndBlob(dout);
      dout.flush();
    }
  }

  /**
   * Returns the finalized result bucket.
   *
   * <p>Valid only after a successful call to {@link #finalizeBucket()}. In single-bucket mode, this
   * is the same {@code Bucket} instance that was supplied to the constructor. In factory-backed
   * mode, it is a newly created read-only bucket that contains the complete blob.
   *
   * @return the bucket whose content is the immutable, finalized Binary Blob; its content remains
   *     stable for further reads and may be read concurrently by clients.
   * @throws IllegalStateException if the writer has not been finalized yet or no final bucket is
   *     available.
   */
  public synchronized Bucket getFinalBucket() {
    if (!finalized) {
      throw new IllegalStateException("Not finalized!");
    }
    if (isSingleBucket) {
      return out;
    } else {
      if (buckets == null || buckets.isEmpty()) {
        throw new IllegalStateException("Final bucket not available");
      }
      return buckets.getFirst();
    }
  }

  @Override
  public String toString() {
    int bucketCount = buckets == null ? 0 : buckets.size();
    return "BinaryBlobWriter{mode="
        + (isSingleBucket ? "single" : "factory")
        + ", started="
        + started
        + ", finalized="
        + finalized
        + ", buckets="
        + bucketCount
        + "}";
  }

  /**
   * Signals that an operation was attempted on a writer that has already been closed/finalized.
   *
   * <p>Methods such as {@link #addKey(ClientKeyBlock, ClientContext)} and snapshot helpers throw
   * this exception when further writes or snapshots are invalid due to a completed life-cycle.
   */
  public static class BinaryBlobAlreadyClosedException extends Exception {

    @Serial private static final long serialVersionUID = -1L;

    /**
     * Creates a new exception with the given detail message.
     *
     * @param message human-readable explanation of the failure condition encountered by the caller;
     *     included verbatim in logs and exception messages.
     */
    public BinaryBlobAlreadyClosedException(String message) {
      super(message);
    }
  }

  /**
   * Reports whether the writer has been finalized.
   *
   * <p>After finalization no further blocks can be added and {@link #getFinalBucket()} becomes
   * available. Before finalization, snapshots may be taken in factory-backed mode.
   *
   * @return {@code true} once {@link #finalizeBucket()} has been called successfully; {@code false}
   *     otherwise.
   */
  public boolean isFinalized() {
    return finalized;
  }
}

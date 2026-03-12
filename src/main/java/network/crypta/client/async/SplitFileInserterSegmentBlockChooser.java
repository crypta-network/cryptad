package network.crypta.client.async;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Random;
import network.crypta.client.async.SplitFileInserterSegmentStorage.BlockInsert;
import network.crypta.node.KeysFetchingLocally;
import network.crypta.support.io.StorageFormatException;

/**
 * Chooses and tracks insert attempts for blocks within a single split-file segment.
 *
 * <p>This chooser extends {@link SimpleBlockChooser} to add handling for consecutive RNF outcomes
 * and for avoiding duplicate in-flight work. It determines the set of eligible block indices based
 * on the state of the associated {@link SplitFileInserterSegmentStorage}: before encoding only data
 * blocks are considered; after encoding, both data and redundancy blocks are eligible. When the
 * optional RNF-as-success policy is enabled, a block that observes a configured number of
 * consecutive RNF results is marked successful to prevent wasting retries on paths that cannot
 * progress. Eligibility also checks {@link KeysFetchingLocally} to avoid selecting blocks that are
 * already being inserted elsewhere in the client.
 *
 * <p>Thread-safety: instances are stateful. Methods that mutate the RNF counters synchronize on
 * {@code this}; callers should prefer invoking instances from a scheduling thread that owns the
 * lifecycle of a segment. The {@link #write(DataOutputStream)} and {@link #read(DataInputStream)}
 * methods serialize/restore chooser state, including RNF counters when the policy is enabled.
 *
 * <ul>
 *   <li>Eligibility rule: data blocks only before encoding; all blocks after encoding.
 *   <li>RNF handling: optional threshold treats N consecutive RNFs as success.
 *   <li>De-duplication: consults {@link KeysFetchingLocally} to skip duplicate inserts.
 *   <li>Persistence: state can be written to and read from a data stream.
 * </ul>
 *
 * @see SimpleBlockChooser
 * @see SplitFileInserterSegmentStorage
 * @see KeysFetchingLocally
 * @see SplitFileInserter
 */
public class SplitFileInserterSegmentBlockChooser extends SimpleBlockChooser {

  final SplitFileInserterSegmentStorage segment;
  final KeysFetchingLocally keysFetching;
  final int[] consecutiveRNFs;

  /** If positive, these many RNFs count as success. */
  final int consecutiveRNFsCountAsSuccess;

  /**
   * Creates a chooser for a segment, configuring retry and RNF handling.
   *
   * <p>The {@code blocks} parameter defines the number of candidate block indices managed by this
   * chooser. The {@code maxRetries} parameter limits how many non-fatal failures are tolerated per
   * block before it is abandoned. When {@code consecutiveRNFsCountAsSuccess} is positive, that many
   * consecutive RNF outcomes for a block cause it to be treated as successfully inserted.
   *
   * @param segment the backing segment storage; not {@code null}; its state defines eligibility.
   * @param blocks total number of block positions tracked by this chooser; non-negative value.
   * @param random randomness source used by the base chooser when selecting among candidates.
   * @param maxRetries maximum number of non-fatal failures per block before giving up;
   *     non-negative.
   * @param keysFetching coordinator that tracks keys being inserted to avoid duplicate work.
   * @param consecutiveRNFsCountAsSuccess if greater than zero, treat N consecutive RNFs as a
   *     success; zero or negative disables the policy.
   */
  public SplitFileInserterSegmentBlockChooser(
      SplitFileInserterSegmentStorage segment,
      int blocks,
      Random random,
      int maxRetries,
      KeysFetchingLocally keysFetching,
      int consecutiveRNFsCountAsSuccess) {
    super(blocks, random, maxRetries);
    this.segment = segment;
    this.keysFetching = keysFetching;
    this.consecutiveRNFsCountAsSuccess = consecutiveRNFsCountAsSuccess;
    if (consecutiveRNFsCountAsSuccess > 0) consecutiveRNFs = new int[blocks];
    else consecutiveRNFs = null;
  }

  /**
   * Returns the exclusive upper bound for currently eligible block indices.
   *
   * <p>Before encoding, only data blocks are considered and the bound equals {@code
   * segment.dataBlockCount}. After encoding, all blocks are eligible and the bound equals {@code
   * segment.totalBlockCount}.
   *
   * @return exclusive upper bound for block indices considered by this chooser.
   */
  @Override
  protected int getMaxBlockNumber() {
    // Ignore cross-segment: We either send all blocks, if the segment has been encoded, or
    // only the data blocks, if it hasn't (even if the cross-segment blocks have been encoded).
    if (segment.hasEncoded()) return segment.totalBlockCount;
    else return segment.dataBlockCount;
  }

  /**
   * Signals that all blocks managed by this chooser have completed insertion.
   *
   * <p>Invoked by the base class when every tracked block has reached a terminal successful state;
   * delegates to the backing segment storage.
   */
  @Override
  protected void onCompletedAll() {
    segment.onInsertedAllBlocks();
  }

  /**
   * Checks whether a candidate block is currently eligible for insertion.
   *
   * <p>Combines the base validity checks with a deduplication guard that skips blocks already being
   * inserted as reported by {@link KeysFetchingLocally}.
   *
   * @param chosen zero-based block index to validate for selection.
   * @return {@code true} if the block passes base checks and is not yet being inserted; {@code
   *     false} otherwise.
   */
  @Override
  protected boolean checkValid(int chosen) {
    if (!super.checkValid(chosen)) return false;
    return !keysFetching.hasInsert(new BlockInsert(segment, chosen));
  }

  /**
   * Records an RNF outcome for a block when RNF-as-success is enabled.
   *
   * <p>This increments the block's consecutive RNF counter. If the configured threshold is reached,
   * the block is treated as successful by delegating to {@link #onSuccess(int)}. Call this method
   * only when {@link #consecutiveRNFsCountAsSuccess} is greater than zero; otherwise RNFs are not
   * tracked and this method performs no action.
   *
   * @param blockNo zero-based block index for which the RNF occurred; must be within the current
   *     eligible range as defined by {@link #getMaxBlockNumber()}.
   */
  public void onRNF(int blockNo) {
    synchronized (this) {
      if (consecutiveRNFs == null) return;
      if (++consecutiveRNFs[blockNo] < consecutiveRNFsCountAsSuccess) return;
    }
    onSuccess(blockNo);
  }

  /**
   * Converts accumulated RNFs into retry penalties when a non-RNF error follows.
   *
   * <p>If RNF-as-success is disabled, this method returns {@code false} and leaves state unchanged.
   * Otherwise, it resets the RNF counter for the block and applies up to that many non-fatal
   * failures, consuming the retry budget via {@link #onNonFatalFailure(int)}. This is synchronized
   * to maintain consistent counters.
   *
   * @param blockNo zero-based block index whose RNF streak should count against retries; must be
   *     within bounds.
   * @return {@code true} if applying the RNF streak exhausted the retry budget and the block moved
   *     to its terminal state; {@code false} otherwise.
   */
  public synchronized boolean pushRNFs(int blockNo) {
    if (consecutiveRNFs == null) return false;
    int ret = consecutiveRNFs[blockNo];
    consecutiveRNFs[blockNo] = 0;
    for (int i = 0; i < ret; i++) if (onNonFatalFailure(blockNo)) return true;
    return false;
  }

  /**
   * Writes the chooser state to the given stream, including RNF counters when enabled.
   *
   * <p>Delegates to {@code super.write(dos)} to persist common state, then emits one {@code
   * int}-encoded RNF counter per managed block if {@link #consecutiveRNFsCountAsSuccess} is greater
   * than zero. The caller retains ownership of the stream and is responsible for flushing/closing
   * it.
   *
   * @param dos destination stream to receive the serialized state; must be open and writable.
   * @throws IOException if writing to the underlying stream fails.
   */
  @Override
  public void write(DataOutputStream dos) throws IOException {
    super.write(dos);
    if (consecutiveRNFsCountAsSuccess > 0) {
      int[] rnfs = this.consecutiveRNFs;
      if (rnfs != null) {
        for (int i : rnfs) dos.writeInt(i);
      }
    }
  }

  /**
   * Reads the chooser state from the given stream, restoring RNF counters when present.
   *
   * <p>Delegates to {@code super.read(dis)} for common state, then, when the RNF-as-success policy
   * is enabled, reads one {@code int} per managed block to restore the RNF counters. The input must
   * match the layout written by {@link #write(DataOutputStream)}.
   *
   * @param dis source stream providing the serialized state; must be open and readable.
   * @throws IOException if reading from the underlying stream fails.
   * @throws StorageFormatException if the serialized data is structurally invalid for this type.
   */
  @Override
  public synchronized void read(DataInputStream dis) throws IOException, StorageFormatException {
    super.read(dis);
    if (consecutiveRNFsCountAsSuccess > 0) {
      int[] rnfs = this.consecutiveRNFs;
      if (rnfs != null) {
        for (int i = 0; i < rnfs.length; i++) {
          rnfs[i] = dis.readInt();
        }
      }
    }
  }
}

package network.crypta.client.async;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Random;
import network.crypta.keys.NodeCHK;
import network.crypta.support.io.StorageFormatException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Chooses and tracks work units for split-file block operations such as fetching or inserting.
 *
 * <p>This helper maintains per-block completion state and retry counters, and exposes a {@code
 * chooseKey()} method that selects the next eligible block to attempt. Selection is randomized
 * across the subset of blocks with the current minimal retry count, which helps spread attempts
 * fairly and avoid repeatedly hammering the same problematic block when others are still pending. A
 * maximum retry budget can be enforced; when {@code maxRetries} is {@code -1} there is no limit.
 *
 * <p>Instances are stateful and use {@code synchronized} methods to guard internal arrays. As a
 * result, individual operations are thread-safe with respect to this instance; callers should avoid
 * holding external locks while invoking callbacks to prevent deadlocks. The supplied {@link
 * java.util.Random} is used only for selection and need not be cryptographically secure; it is
 * injected primarily for determinism under test.
 *
 * <ul>
 *   <li>Completion and retry state are maintained per block index in {@code [0, blocks)}.
 *   <li>Retries increase on non-fatal failures; success marks the block complete.
 *   <li>When all blocks succeed, {@link #onCompletedAll()} is invoked.
 * </ul>
 *
 * @author toad
 * @see #chooseKey()
 * @see #onNonFatalFailure(int)
 * @see #onSuccess(int)
 */
public class SimpleBlockChooser {
  private static final Logger LOG = LoggerFactory.getLogger(SimpleBlockChooser.class);

  private final int blocks;
  private final boolean[] completed;
  private int completedCount;
  private final int[] retries;

  /**
   * Maximum number of non-fatal retry attempts permitted per block.
   *
   * <p>A value of {@code -1} disables the limit and allows unbounded retries. Callers typically use
   * a small positive number for fetchers and a stricter value for inserters where failure may be
   * terminal. The value is applied when evaluating {@link #chooseKey()} eligibility and when
   * computing failure/eligibility statistics.
   */
  protected final int maxRetries;

  private final Random random;

  /**
   * Creates a chooser for a fixed number of blocks with a retry policy.
   *
   * <p>The {@code random} instance is used to break ties among blocks that currently share the same
   * minimal retry count. Supplying a deterministic {@link Random} is useful in tests to produce
   * stable selection sequences.
   *
   * @param blocks total number of blocks tracked by this chooser; valid indices are {@code [0,
   *     blocks)} and must be non-negative.
   * @param random source of randomness for fair selection among equally retried blocks; must not be
   *     {@code null} and should be thread-confined to the caller.
   * @param maxRetries maximum non-fatal retries allowed per block; use {@code -1} to allow
   *     unlimited retries without exclusion.
   */
  public SimpleBlockChooser(int blocks, Random random, int maxRetries) {
    this.maxRetries = maxRetries;
    this.blocks = blocks;
    this.random = random;
    this.completed = new boolean[blocks];
    this.retries = new int[blocks];
  }

  /**
   * Chooses the next eligible block index to work on.
   *
   * <p>The selection considers only blocks that are not completed, deemed valid by {@link
   * #checkValid(int)}, and have not exceeded {@link #maxRetries} (unless it is {@code -1}). Among
   * the eligible set, the method selects uniformly at random from the subset with the lowest
   * observed retry count, providing a simple fairness heuristic across pending work.
   *
   * @return the chosen block index in {@code [0, blocks)}, or {@code -1} when no block is currently
   *     eligible due to completion, validation, or retry limits.
   */
  public synchronized int chooseKey() {
    int max = getMaxBlockNumber();
    int[] candidates = new int[max];
    int count = 0;
    int minRetryCount = Integer.MAX_VALUE;
    for (int i = 0; i < max; i++) {
      int retry = retries[i];
      boolean tooManyRetries = (maxRetries != -1 && retry > maxRetries);
      if (tooManyRetries || retry > minRetryCount || !checkValid(i)) continue;
      if (retry < minRetryCount) {
        count = 0;
        candidates[count++] = i;
        minRetryCount = retry;
      } else { // retry == minRetryCount
        candidates[count++] = i;
      }
    }
    if (count == 0) {
      return -1;
    } else {
      return candidates[random.nextInt(count)];
    }
  }

  /**
   * Records a non-fatal failure for a block and reports whether the retry limit is now exceeded.
   *
   * <p>Call this when an attempt fails, but the caller wishes to retry, according to the configured
   * policy. The internal counter for the block is incremented, and the method returns {@code true}
   * if retries have now surpassed {@link #maxRetries} (when a limit applies).
   *
   * @param blockNo zero-based block index that experienced a non-fatal failure; must be within the
   *     configured range for this instance.
   * @return {@code true} when the block's retry count now exceeds {@code maxRetries}; {@code false}
   *     otherwise or when unlimited retries are configured.
   */
  public boolean onNonFatalFailure(int blockNo) {
    return isFatalRetries(innerOnNonFatalFailure(blockNo));
  }

  private boolean isFatalRetries(int retries) {
    if (maxRetries == -1) return false;
    return retries > maxRetries;
  }

  /**
   * Registers a non-fatal failure and returns the updated attempt count.
   *
   * <p>This method mutates internal state by incrementing the retry counter for {@code blockNo} and
   * is invoked by {@link #onNonFatalFailure(int)}. Callers can use the returned value to apply
   * their own terminal-failure thresholds when a global {@link #maxRetries} is not appropriate.
   *
   * @param blockNo zero-based index of the block whose retry count should be incremented; must be a
   *     valid block index for this chooser.
   * @return the total number of attempts recorded for the block after the increment; this value
   *     starts at {@code 1} for the first failure and increases monotonically.
   */
  protected synchronized int innerOnNonFatalFailure(int blockNo) {
    return ++retries[blockNo];
  }

  /**
   * Marks a block as successfully completed.
   *
   * <p>If the block was not already marked complete, this updates internal state and returns {@code
   * true}. When the final outstanding block completes, the hook {@link #onCompletedAll()} is
   * invoked after releasing the synchronization lock. Repeated calls for an already-completed block
   * return {@code false} and leave state unchanged.
   *
   * @param blockNo zero-based index of the block to mark as complete; must be a valid block index.
   * @return {@code true} if the call changed state and recorded a new completion; {@code false} if
   *     the block had already been marked complete by an earlier call.
   */
  public boolean onSuccess(int blockNo) {
    synchronized (this) {
      if (completed[blockNo]) return false;
      completed[blockNo] = true;
      completedCount++;
      if (completedCount < blocks) {
        if (LOG.isDebugEnabled()) LOG.debug("Completed blocks: {}/{}", completedCount, blocks);
        return true;
      }
    }
    onCompletedAll();
    return true;
  }

  /**
   * Notify that a block has no longer succeeded. E.g., we downloaded it, but now the data is no
   * longer available due to disk corruption.
   *
   * @param blockNo zero-based index of the block to mark as not complete any longer; the block must
   *     have been previously marked complete.
   */
  public synchronized void onUnSuccess(int blockNo) {
    if (!completed[blockNo]) return;
    completed[blockNo] = false;
    completedCount--;
  }

  /**
   * Hook invoked once all blocks have been marked complete.
   *
   * <p>Subclasses may override to trigger follow-up behavior such as notifying listeners or
   * advancing a higher-level state machine. The default implementation is a no-op.
   */
  protected void onCompletedAll() {
    // Do nothing.
  }

  /**
   * Is the proposed block valid? Override to implement custom logic e.g., checking which requests
   * are already running.
   *
   * @param chosen candidate block index to evaluate for eligibility; the value is within {@code [0,
   *     blocks)} when invoked.
   * @return {@code true} when the block may be selected and attempted now; {@code false} to exclude
   *     it from {@link #chooseKey()} consideration at this time.
   */
  @SuppressWarnings("BooleanMethodIsAlwaysInverted")
  protected boolean checkValid(int chosen) {
    return !completed[chosen];
  }

  /**
   * Can be overridden to restrict chooseKey() to a subset of the available blocks. Useful for
   * inserts where we will be able to insert all the blocks until after encoding has finished.
   *
   * @return The upper bound on the block number chosen.
   */
  protected int getMaxBlockNumber() {
    return blocks;
  }

  /**
   * Mass replacement of success/failure. Used by fetchers when we try to decode and fail, possibly
   * because of disk corruption.
   *
   * <p>The {@code used} array represents the authoritative completion state and must have a length
   * at least equal to {@code blocks}. For each index, this method calls either {@link
   * #onSuccess(int)} or {@link #onUnSuccess(int)} to bring internal state in sync.
   *
   * @param used array where {@code used[i] == true} indicates block {@code i} is present and valid;
   *     entries beyond {@code blocks} are ignored if present.
   */
  public synchronized void replaceSuccesses(boolean[] used) {
    for (int i = 0; i < blocks; i++) {
      if (used[i] && !completed[i]) onSuccess(i);
      else if (!used[i] && completed[i]) onUnSuccess(i);
    }
  }

  /**
   * Returns the number of blocks currently marked as successfully completed.
   *
   * @return count of completed blocks; the value ranges from {@code 0} to {@code blocks} and
   *     increases monotonically until a call to {@link #onUnSuccess(int)} decrements it.
   */
  public synchronized int successCount() {
    return completedCount;
  }

  /**
   * Returns the current non-fatal retry count for a block.
   *
   * @param blockNumber zero-based block index whose retry counter is requested; must be within the
   *     configured range.
   * @return number of attempts recorded so far for the block; {@code 0} indicates no failures have
   *     been recorded yet.
   */
  public synchronized int getRetries(int blockNumber) {
    return retries[blockNumber];
  }

  /**
   * Returns the block number for a known key, taking the completed state into account.
   *
   * <p>This convenience delegates to {@link SplitFileSegmentKeys#getBlockNumber(NodeCHK,
   * boolean[])} while keeping the internal {@code completed} array encapsulated.
   *
   * @param keys segment mapping that can resolve a {@link NodeCHK} to its block index; must not be
   *     {@code null}.
   * @param key content hash key to look up; must not be {@code null} and must belong to the segment
   *     represented by {@code keys}.
   * @return the zero-based block index for the provided key, or {@code -1} when the key is unknown
   *     or filtered by the completed mask.
   */
  public synchronized int getBlockNumber(SplitFileSegmentKeys keys, NodeCHK key) {
    return keys.getBlockNumber(key, completed);
  }

  /**
   * Indicates whether the specified block is marked as complete.
   *
   * @param blockNumber zero-based index of the block to inspect; must be within range.
   * @return {@code true} if the block has been recorded as completed via {@link #onSuccess(int)};
   *     {@code false} otherwise.
   */
  public synchronized boolean hasSucceeded(int blockNumber) {
    return completed[blockNumber];
  }

  /**
   * Write the retry counts only, and only if maxRetries != -1. Used if the caller will manage
   * persistence for the actual list of blocks fetched, as in SplitFileFetcherSegment.
   *
   * <p>Writes {@code retries.length} integers in index order. When unlimited retries are configured
   * ({@code maxRetries == -1}) nothing is written.
   *
   * @param dos destination to receive the retry counters in binary form; the stream remains open on
   *     return and is not flushed by this method.
   * @throws IOException if the underlying stream reports an I/O error while writing the counters.
   */
  public void writeRetries(DataOutputStream dos) throws IOException {
    if (maxRetries == -1) return;
    for (int retry : retries) dos.writeInt(retry);
  }

  /**
   * Reads retry counts in index order and replaces the in-memory values.
   *
   * <p>When unlimited retries are configured ({@code maxRetries == -1}), this method performs no
   * I/O and returns immediately. Otherwise, exactly {@code blocks} integers are read from the
   * stream.
   *
   * @param dis source of retry counters previously written by {@link
   *     #writeRetries(DataOutputStream)}; the stream remains open on return.
   * @throws IOException if the underlying stream fails or does not contain enough data for all
   *     entries.
   */
  public void readRetries(DataInputStream dis) throws IOException {
    if (maxRetries == -1) return;
    for (int i = 0; i < blocks; i++) retries[i] = dis.readInt();
  }

  static final int VERSION = 1;

  /**
   * Writes the serialized form of this chooser's state.
   *
   * <p>The format is: version (int), {@code blocks} booleans for completion flags in index order,
   * the configured {@code maxRetries} (int), and then retry counters via {@link
   * #writeRetries(DataOutputStream)}. The method leaves the supplied stream open.
   *
   * @param dos the destination stream that receives the serialized state; not closed by this
   *     method.
   * @throws IOException if writing to the destination stream fails at any point.
   */
  public void write(DataOutputStream dos) throws IOException {
    dos.writeInt(VERSION);
    for (boolean b : completed) dos.writeBoolean(b);
    dos.writeInt(maxRetries);
    writeRetries(dos);
  }

  /**
   * Reads and restores a state previously written by {@link #write(DataOutputStream)}.
   *
   * <p>This method validates the on-disk version and the configured {@code maxRetries}. It rebuilds
   * the completion count from the per-block flags and then delegates to {@link
   * #readRetries(DataInputStream)} to load retry counters. The provided stream remains open when
   * the method returns.
   *
   * @param dis source stream containing a state snapshot in the {@link #write(DataOutputStream)}
   *     format.
   * @throws StorageFormatException if the serialized version does not match or the stored {@code
   *     maxRetries} differs from this instance's configuration.
   * @throws IOException if reading from the stream fails.
   */
  public synchronized void read(DataInputStream dis) throws StorageFormatException, IOException {
    if (dis.readInt() != VERSION) throw new StorageFormatException("Bad version in block chooser");
    for (int i = 0; i < completed.length; i++) {
      completed[i] = dis.readBoolean();
      if (completed[i]) completedCount++;
    }
    if (dis.readInt() != maxRetries) throw new StorageFormatException("Max retries has changed");
    readRetries(dis);
  }

  /**
   * Counts blocks that have exceeded the configured retry budget and are not complete.
   *
   * <p>When unlimited retries are configured ({@code maxRetries == -1}), the method returns {@code
   * 0}. Otherwise, it inspects the retry counters for unfinished blocks and counts those that now
   * exceed {@code maxRetries}.
   *
   * @return number of unfinished blocks whose retry counters are greater than {@code maxRetries};
   *     {@code 0} when unlimited retries apply.
   */
  public synchronized int countFailedBlocks() {
    if (maxRetries == -1) return 0;
    int total = 0;
    for (int i = 0; i < retries.length; i++) {
      if (completed[i]) continue;
      if (retries[i] > maxRetries) total++;
    }
    return total;
  }

  /**
   * Returns a shallow copy of the current completion mask.
   *
   * <p>The returned array is a snapshot at the time of the call and is safe to modify by the
   * caller.
   *
   * @return a new {@code boolean[]} where {@code result[i] == true} indicates block {@code i} is
   *     marked complete in this chooser at call time.
   */
  public synchronized boolean[] copyDownloadedBlocks() {
    return completed.clone();
  }

  /**
   * Counts blocks that are currently eligible for fetching, according to policy.
   *
   * <p>Eligibility requires that a block is not completed, {@link #checkValid(int)} returns {@code
   * true}, and either unlimited retries are configured or the retry counter has not reached the
   * configured limit.
   *
   * @return number of blocks that could be returned by a call to {@link #chooseKey()} at this
   *     moment; {@code 0} when unlimited retries are configured but no valid blocks exist.
   */
  public synchronized int countFetchable() {
    if (maxRetries == -1) return 0;
    int count = 0;
    for (int i = 0; i < blocks; i++) {
      boolean tooManyRetries = retries[i] >= maxRetries;
      if (tooManyRetries || !checkValid(i) || completed[i]) continue;
      count++;
    }
    return count;
  }

  /**
   * Returns {@code true} when every block has been marked complete.
   *
   * @return {@code true} if {@link #successCount()} equals the total number of blocks; {@code
   *     false} otherwise.
   */
  public synchronized boolean hasSucceededAll() {
    return completedCount == blocks;
  }
}

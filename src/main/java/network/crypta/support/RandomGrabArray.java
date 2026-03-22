package network.crypta.support;

import java.util.Arrays;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientRequestSelector;
import network.crypta.client.async.RequestSelectionTreeNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An array which supports remove-and-return-a-random-element very fast.
 *
 * <p>This is *NOT* persistent. The request selection structures are reconstructed on restart.
 * However, it used to be, and probably has a lot of cruft and inefficiency as a result.
 *
 * <p>LOCKING: There is a single lock for the entire tree, the ClientRequestSelector. This must be
 * taken before calling any methods on RGA or SRGA. See the Javadocs there for a deeper explanation.
 *
 * <p>Note: This implementation could be simplified and optimized. Many operations are O(n). Memory
 * usage was historically a concern but is mitigated by large item sizes (entire splitfiles or at
 * least entire segments).
 */
public class RandomGrabArray implements RemoveRandom, RequestSelectionTreeNode {
  private static final Logger LOG = LoggerFactory.getLogger(RandomGrabArray.class);

  // Intentionally empty: no static initialization required.

  private static class Block {
    RandomGrabArrayItem[] reqs;
  }

  /**
   * Array of items. Non-null's followed by null's. We used to have a Set so we could check whether
   * something is in the set quickly. We got rid of this because for persistent requests it is
   * vastly faster to just loop the loop and check ==, and for non-persistent requests it doesn't
   * matter much.
   */
  private Block[] blocks;

  /** Index of the first null item. */
  private int index;

  private static final int MIN_SIZE = 32;
  private static final int BLOCK_SIZE = 1024;
  private RemoveRandomParent parent;

  /**
   * Shared selector root used as the synchronization monitor for this node (and siblings).
   *
   * <p>All public methods synchronize on this object. Callers must avoid holding other locks when
   * entering this API to prevent deadlocks.
   */
  protected final ClientRequestSelector root;

  private long wakeupTime;

  public RandomGrabArray(RemoveRandomParent parent, ClientRequestSelector root) {
    this.blocks = new Block[] {new Block()};
    blocks[0].reqs = new RandomGrabArrayItem[MIN_SIZE];
    index = 0;
    this.parent = parent;
    this.root = root;
  }

  // Identity semantics: membership and equality checks compare references (==) only.

  /**
   * Adds an item if not already present.
   *
   * <p>Behavior:
   *
   * <ul>
   *   <li>If {@code context != null} and {@code req.getWakeupTime(context, now) < 0}, the item is
   *       considered finished and is ignored.
   *   <li>Otherwise the item is appended to the dense prefix, and its parent pointer is set to this
   *       array.
   *   <li>Duplicates are ignored using identity comparison.
   * </ul>
   *
   * <p>Threading: Synchronizes on {@link #root}. May clear this node's stored wakeup time to force
   * re-evaluation on later selections.
   *
   * @param req the item to add; must be non-null
   * @param context client context; may be {@code null}
   */
  public void add(RandomGrabArrayItem req, ClientContext context) {
    if (context != null && req.getWakeupTime(context, System.currentTimeMillis()) < 0) {
      if (LOG.isDebugEnabled()) LOG.debug("add: skipping finished item {}", req);
      return;
    }
    req.setParentGrabArray(this); // will store() self
    synchronized (root) {
      if (context != null) {
        clearWakeupTime(context);
      }
      if (tryAddSingleBlockFastPath(req)) {
        return;
      }
      int targetBlock = index / BLOCK_SIZE;
      if (containsAndValidateBlocks(req)) {
        return;
      }
      ensureBlocksCapacity(targetBlock);
      appendToTargetBlock(targetBlock, req);
    }
  }

  /**
   * Maximum limited-path exclusions before falling back to compaction (must be < {@code
   * BLOCK_SIZE}).
   */
  static final int MAX_EXCLUDED = 10;

  /**
   * Returns a ready item uniformly at random, or the earliest wake time if none are ready.
   *
   * <p>Readiness at {@code now} (ms since epoch):
   *
   * <ul>
   *   <li>Item: {@code getWakeupTime(context, now) == 0} → candidate; {@code > 0} → excluded until
   *       that time; {@code -1} → canceled and removed.
   *   <li>Scheduler: {@code excluding.exclude(item, context, now) <= 0} → candidate; {@code > 0} →
   *       excluded until that time.
   * </ul>
   *
   * <p>On success, the item is not removed from this structure. Cancellation is the only path that
   * removes items during selection.
   *
   * @param excluding provider of scheduler-level exclusion times; non-null
   * @param context client context with RNG and timing utilities; non-null
   * @param now current time in milliseconds since the epoch
   * @return a {@link RemoveRandom.RemoveRandomReturn} containing either a ready item, or {@code
   *     item == null} and the earliest wakeup time when none are ready; {@code null} only if the
   *     container becomes empty due to cancellations
   */
  @Override
  public RemoveRandomReturn removeRandom(
      RandomGrabArrayItemExclusionList excluding, ClientContext context, long now) {
    if (LOG.isDebugEnabled()) LOG.debug("removeRandom() on {} index={}", this, index);
    synchronized (root) {
      if (index == 0) {
        if (LOG.isDebugEnabled()) LOG.debug("removeRandom: empty array on {}", this);
        return null;
      }
      if (index < MAX_EXCLUDED) {
        return removeRandomExhaustiveSearch(excluding, context, now);
      }
      RandomGrabArrayItem ret = removeRandomLimited(excluding, context, now);
      if (ret != null) return new RemoveRandomReturn(ret);
      if (index == 0) {
        if (LOG.isDebugEnabled()) LOG.debug("removeRandom: empty after limited search on {}", this);
        return null;
      }
      return removeRandomExhaustiveSearch(excluding, context, now);
    }
  }

  private RandomGrabArrayItem removeRandomLimited(
      RandomGrabArrayItemExclusionList excluding, ClientContext context, long now) {
    int excluded = 0;
    while (true) {
      AttemptOutcome outcome = tryOnceLimited(excluding, context, now);
      switch (outcome.kind) {
        case RETURN_ITEM:
          return outcome.item;
        case EXCLUDED:
          if (++excluded > MAX_EXCLUDED) return null;
          break; // try again
        case REMOVED_RETURN_NULL:
          return null;
        case RETRY:
        default:
          break; // try again
      }
    }
  }

  private RemoveRandomReturn removeRandomExhaustiveSearch(
      RandomGrabArrayItemExclusionList excluding, ClientContext context, long now) {
    if (LOG.isDebugEnabled()) LOG.debug("removeRandom: exhaustive search+compaction on {}", this);
    CompactResult r = compactAndCount(excluding, context, now);
    if (index != r.newIndex) index = r.newIndex;

    if (r.valid == 0 && r.exclude == 0) {
      if (LOG.isDebugEnabled()) LOG.debug("removeRandom: no valid/excluded items size={}", index);
      return null;
    }
    if (r.valid == 0) {
      if (LOG.isDebugEnabled())
        LOG.debug("removeRandom: no valid items excluded={} size={}", r.exclude, index);
      setWakeupTime(r.minWakeupTime, context);
      return new RemoveRandomReturn(r.minWakeupTime);
    }
    if (r.valid == 1) {
      if (LOG.isDebugEnabled())
        LOG.debug("removeRandom: single valid item {} size={}", r.firstValidItem, index);
      return new RemoveRandomReturn(r.firstValidItem);
    }

    int rnd = context.fastWeakRandomSource.nextInt(r.valid);
    if (LOG.isDebugEnabled())
      LOG.debug("removeRandom: choose nth={} of valid={} excluded={}", rnd, r.valid, r.exclude);
    RandomGrabArrayItem chosen = findNthValid(rnd, excluding, context, now);
    return new RemoveRandomReturn(chosen);
  }

  private RandomGrabArrayItem findNthValid(
      int nth, RandomGrabArrayItemExclusionList excluding, ClientContext context, long now) {
    int count = 0;
    int blockNum = 0;
    int offset = -1;
    RandomGrabArrayItem[] reqs = blocks[0].reqs;
    for (int i = 0; i < index; i++) {
      offset++;
      if (offset == BLOCK_SIZE) {
        offset = 0;
        blockNum++;
        reqs = blocks[blockNum].reqs;
      }
      RandomGrabArrayItem item = reqs[offset];
      if (item == null) continue;
      long wake = item.getWakeupTime(context, now);
      if (wake == 0 && excluding.exclude(item, context, now) == 0) {
        if (count == nth) return item;
        count++;
      }
    }
    return null;
  }

  private record CompactResult(
      int exclude,
      int valid,
      int newIndex,
      long minWakeupTime,
      RandomGrabArrayItem firstValidItem) {}

  private record ItemDecision(boolean excludeItem, boolean cancelled, long minWakeupTime) {}

  private ItemDecision analyzeItem(
      RandomGrabArrayItem item,
      RandomGrabArrayItemExclusionList excluding,
      ClientContext context,
      long now) {
    long itemWakeTime = item.getWakeupTime(context, now);
    if (itemWakeTime > 0) {
      return new ItemDecision(true, false, itemWakeTime);
    } else if (itemWakeTime == -1) {
      return new ItemDecision(false, true, Long.MAX_VALUE);
    } else {
      long excludeTime = excluding.exclude(item, context, now);
      if (excludeTime > 0) {
        return new ItemDecision(true, false, excludeTime);
      }
      return new ItemDecision(false, false, Long.MAX_VALUE);
    }
  }

  private CompactResult compactAndCount(
      RandomGrabArrayItemExclusionList excluding, ClientContext context, long now) {
    RandomGrabArrayItem[] reqsReading = blocks[0].reqs;
    RandomGrabArrayItem[] reqsWriting = blocks[0].reqs;
    int blockNumReading = 0;
    int blockNumWriting = 0;
    int offset = -1;
    int writeOffset = -1;
    int exclude = 0;
    int valid = 0;
    int target = 0;
    RandomGrabArrayItem firstValidItem = null;
    long wakeupTimeMin = Long.MAX_VALUE;

    for (int i = 0; i < index; i++) {
      offset++;
      if (offset == BLOCK_SIZE) {
        offset = 0;
        blockNumReading++;
        reqsReading = blocks[blockNumReading].reqs;
      }
      RandomGrabArrayItem item = reqsReading[offset];

      if (item == null) {
        if (LOG.isDebugEnabled())
          LOG.debug(
              "compaction: null slot offset={} i={} block={} in {}",
              offset,
              i,
              blockNumReading,
              this);
      } else {
        CompactionRW rw = new CompactionRW(reqsWriting, writeOffset, blockNumWriting);
        CompactionCounts cnt =
            new CompactionCounts(i, target, exclude, valid, firstValidItem, wakeupTimeMin, now);
        processNonNullItem(reqsReading, offset, item, excluding, context, rw, cnt);
        reqsWriting = rw.reqsWriting;
        writeOffset = rw.writeOffset;
        blockNumWriting = rw.blockNumWriting;
        target = cnt.target;
        exclude = cnt.exclude;
        valid = cnt.valid;
        if (firstValidItem == null) firstValidItem = cnt.firstValidItem;
        wakeupTimeMin = cnt.wakeupTimeMin;
      }
    }

    return new CompactResult(exclude, valid, target, wakeupTimeMin, firstValidItem);
  }

  private static final class CompactionRW {
    RandomGrabArrayItem[] reqsWriting;
    int writeOffset;
    int blockNumWriting;

    CompactionRW(RandomGrabArrayItem[] reqsWriting, int writeOffset, int blockNumWriting) {
      this.reqsWriting = reqsWriting;
      this.writeOffset = writeOffset;
      this.blockNumWriting = blockNumWriting;
    }
  }

  private static final class CompactionCounts {
    int i;
    int target;
    int exclude;
    int valid;
    RandomGrabArrayItem firstValidItem;
    long wakeupTimeMin;
    final long now;

    CompactionCounts(
        int i,
        int target,
        int exclude,
        int valid,
        RandomGrabArrayItem firstValidItem,
        long wakeupTimeMin,
        long now) {
      this.i = i;
      this.target = target;
      this.exclude = exclude;
      this.valid = valid;
      this.firstValidItem = firstValidItem;
      this.wakeupTimeMin = wakeupTimeMin;
      this.now = now;
    }
  }

  private void processNonNullItem(
      RandomGrabArrayItem[] reqsReading,
      int offset,
      RandomGrabArrayItem item,
      RandomGrabArrayItemExclusionList excluding,
      ClientContext context,
      CompactionRW rw,
      CompactionCounts cnt) {
    ItemDecision decision = analyzeItem(item, excluding, context, cnt.now);
    if (decision.minWakeupTime < cnt.wakeupTimeMin) {
      cnt.wakeupTimeMin = decision.minWakeupTime;
    }
    if (decision.cancelled) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("compaction: drop cancelled item {} from {}", item, this);
      }
      reqsReading[offset] = null;
      item.setParentGrabArray(null);
      return;
    }

    rw.writeOffset++;
    if (rw.writeOffset == BLOCK_SIZE) {
      rw.writeOffset = 0;
      rw.blockNumWriting++;
      rw.reqsWriting = blocks[rw.blockNumWriting].reqs;
    }
    if (cnt.i != cnt.target) {
      reqsReading[offset] = null;
      rw.reqsWriting[rw.writeOffset] = item;
    }
    cnt.target++;
    if (decision.excludeItem) {
      cnt.exclude++;
    } else {
      if (cnt.firstValidItem == null) cnt.firstValidItem = item;
      cnt.valid++;
    }
  }

  private void handleNullPickedSlot(int blockNo, int i) {
    LOG.error("selection: null slot at index {}", i);
    remove(blockNo, i);
  }

  private void removeCancelledAndSkipNulls(int blockNo, int i) {
    RandomGrabArrayItem oret;
    do {
      remove(blockNo, i);
      oret = blocks[blockNo].reqs[i % BLOCK_SIZE];
      // Check for nulls, but don't check for canceled, since we'd have to activate.
    } while (index > i && oret == null);
  }

  private void shrinkBlocksIfNeeded() {
    int newBlockCount;
    if (blocks.length == 1
        && index < blocks[0].reqs.length / 4
        && blocks[0].reqs.length > MIN_SIZE) {
      blocks[0].reqs = Arrays.copyOf(blocks[0].reqs, Math.max(index * 2, MIN_SIZE));
    } else if (blocks.length > 1
        && (newBlockCount = (((index + (BLOCK_SIZE / 2)) / BLOCK_SIZE) + 1)) < blocks.length) {
      if (LOG.isDebugEnabled()) LOG.debug("shrink: reducing blocks for {}", this);
      blocks = Arrays.copyOf(blocks, newBlockCount);
    }
  }

  private enum AttemptKind {
    RETRY,
    EXCLUDED,
    REMOVED_RETURN_NULL,
    RETURN_ITEM
  }

  private record AttemptOutcome(AttemptKind kind, RandomGrabArrayItem item) {

    static AttemptOutcome retry() {
      return new AttemptOutcome(AttemptKind.RETRY, null);
    }

    static AttemptOutcome excluded() {
      return new AttemptOutcome(AttemptKind.EXCLUDED, null);
    }

    static AttemptOutcome removedReturnNull() {
      return new AttemptOutcome(AttemptKind.REMOVED_RETURN_NULL, null);
    }

    static AttemptOutcome returnItem(RandomGrabArrayItem item) {
      return new AttemptOutcome(AttemptKind.RETURN_ITEM, item);
    }
  }

  private AttemptOutcome tryOnceLimited(
      RandomGrabArrayItemExclusionList excluding, ClientContext context, long now) {
    int i = context.fastWeakRandomSource.nextInt(index);
    int blockNo = i / BLOCK_SIZE;
    RandomGrabArrayItem ret = blocks[blockNo].reqs[i % BLOCK_SIZE];

    if (ret == null) {
      handleNullPickedSlot(blockNo, i);
      return AttemptOutcome.retry();
    }

    long itemWakeTime = ret.getWakeupTime(context, now);
    if (itemWakeTime > 0) {
      return AttemptOutcome.excluded();
    }

    if (itemWakeTime == -1) {
      if (LOG.isDebugEnabled()) LOG.debug("limited-pick: cancelled item {}", ret);
      ret.setParentGrabArray(null);
      removeCancelledAndSkipNulls(blockNo, i);
      shrinkBlocksIfNeeded();
      return AttemptOutcome.removedReturnNull();
    }

    long excludeTime = excluding.exclude(ret, context, now);
    if (excludeTime > 0) {
      return AttemptOutcome.excluded();
    }

    if (LOG.isDebugEnabled()) LOG.debug("limited-pick: returning item {} size={}", ret, index);
    return AttemptOutcome.returnItem(ret);
  }

  /**
   * Removes the logical element at {@code i} by swapping in the last logical element.
   *
   * <p>Preconditions: {@code blockNo} refers to an allocated block that contains logical index
   * {@code i}. The final block beyond the last logical index is not yet active for appending.
   */
  private void remove(int blockNo, int i) {
    index--;
    int endBlock = index / BLOCK_SIZE;
    if (blocks.length == 1 || blockNo == endBlock) {
      RandomGrabArrayItem[] items = blocks[blockNo].reqs;
      int idx = index % BLOCK_SIZE;
      items[i % BLOCK_SIZE] = items[idx];
      items[idx] = null;
    } else {
      RandomGrabArrayItem[] toItems = blocks[blockNo].reqs;
      RandomGrabArrayItem[] endItems = blocks[endBlock].reqs;
      toItems[i % BLOCK_SIZE] = endItems[index % BLOCK_SIZE];
      endItems[index % BLOCK_SIZE] = null;
    }
  }

  /**
   * Removes the given item if present and detaches its parent pointer.
   *
   * <p>If this array becomes empty afterward, {@link RemoveRandomParent#maybeRemove(RemoveRandom,
   * ClientContext)} is invoked on the parent.
   *
   * @param it the item reference to remove; non-null
   * @param context client context used for parent notifications
   */
  public void remove(RandomGrabArrayItem it, ClientContext context) {
    if (LOG.isDebugEnabled()) LOG.debug("remove: request removal of {} from {}", it, this);

    boolean matched;
    boolean empty = false;
    synchronized (root) {
      if (blocks.length == 1) {
        matched = removeFromSingleBlock(blocks[0], it);
      } else {
        matched = removeFromMultiBlocks(it);
      }
      if (index == 0) empty = true;
    }
    // Caller will typically clear it before calling for synchronization reasons.
    RandomGrabArray oldArray = it.getParentGrabArray();
    if (oldArray == this) it.setParentGrabArray(null);
    else if (oldArray != null)
      LOG.error(
          "remove: parent mismatch for item {} in {} actual {}",
          it,
          this,
          it.getParentGrabArray(),
          new Exception("debug"));
    if (!matched) {
      if (LOG.isDebugEnabled()) LOG.debug("remove: item not found {} in {}", it, this);
      return;
    }
    if (empty && parent != null) {
      parent.maybeRemove(this, context);
    }
  }

  private boolean removeFromSingleBlock(Block block, RandomGrabArrayItem it) {
    for (int i = 0; i < index; i++) {
      if (block.reqs[i] == it) {
        block.reqs[i] = block.reqs[--index];
        block.reqs[index] = null;
        return true;
      }
    }
    return false;
  }

  private boolean removeFromMultiBlocks(RandomGrabArrayItem it) {
    int x = 0;
    for (int i = 0; i < blocks.length; i++) {
      Block block = blocks[i];
      for (int j = 0; j < block.reqs.length && x < index; j++, x++) {
        if (block.reqs[j] == it) {
          int pullFrom = --index;
          int idx = pullFrom % BLOCK_SIZE;
          int endBlock = pullFrom / BLOCK_SIZE;
          if (i == endBlock) {
            block.reqs[j] = block.reqs[idx];
            block.reqs[idx] = null;
          } else {
            Block fromBlock = blocks[endBlock];
            block.reqs[j] = fromBlock.reqs[idx];
            fromBlock.reqs[idx] = null;
          }
          return true;
        }
      }
    }
    return false;
  }

  /**
   * Returns whether no items are stored.
   *
   * @return {@code true} if {@link #size()} is {@code 0}
   */
  public boolean isEmpty() {
    synchronized (root) {
      return index == 0;
    }
  }

  /**
   * Returns whether the exact object reference is present (identity semantics).
   *
   * @param item the object to search for
   * @return {@code true} if {@code item} is present
   */
  public boolean contains(RandomGrabArrayItem item) {
    synchronized (root) {
      if (blocks.length == 1) {
        return containsInSingleBlock(blocks[0], item);
      } else {
        return containsInMultiBlocks(item);
      }
    }
  }

  private boolean containsInSingleBlock(Block block, RandomGrabArrayItem item) {
    for (int i = 0; i < index; i++) {
      if (block.reqs[i] == item) {
        return true;
      }
    }
    return false;
  }

  private boolean containsInMultiBlocks(RandomGrabArrayItem item) {
    int x = 0;
    for (Block block : blocks) {
      for (int j = 0; j < block.reqs.length && x < index; j++, x++) {
        if (block.reqs[j] == item) {
          return true;
        }
      }
    }
    return false;
  }

  /** Fast-path add for single-block arrays; requires caller to hold {@code root} lock. */
  private boolean tryAddSingleBlockFastPath(RandomGrabArrayItem req) {
    if (blocks.length == 1 && index < BLOCK_SIZE) {
      for (int i = 0; i < index; i++) {
        if (blocks[0].reqs[i] == req) {
          return true;
        }
      }
      if (index >= blocks[0].reqs.length) {
        blocks[0].reqs =
            Arrays.copyOf(blocks[0].reqs, Math.min(BLOCK_SIZE, blocks[0].reqs.length * 2));
      }
      blocks[0].reqs[index++] = req;
      if (LOG.isDebugEnabled()) LOG.debug("add-fastpath: appended {} newIndex={}", req, index);
      return true;
    }
    return false;
  }

  /** Scan blocks to detect duplicates and validate block sizing; requires caller to hold lock. */
  private boolean containsAndValidateBlocks(RandomGrabArrayItem req) {
    validateBlockSizes();
    return containsReq(req);
  }

  private void validateBlockSizes() {
    for (int i = 0; i < blocks.length; i++) {
      Block block = blocks[i];
      if (i != (blocks.length - 1) && block.reqs.length != BLOCK_SIZE) {
        LOG.error(
            "Block {} of {} is wrong size: {} should be " + BLOCK_SIZE,
            i,
            blocks.length,
            block.reqs.length);
      }
    }
  }

  private boolean containsReq(RandomGrabArrayItem req) {
    int x = 0;
    for (int i = 0; i < blocks.length; i++) {
      Block block = blocks[i];
      for (int j = 0; j < block.reqs.length && x < index; j++, x++) {
        if (block.reqs[j] == req) {
          if (LOG.isDebugEnabled())
            LOG.debug("add: duplicate item {} in {} size={}", req, this, index);
          return true;
        }
        if (block.reqs[j] == null) {
          LOG.error("contains: null slot at block {} index {} in {}", i, j, this);
        }
      }
    }
    return false;
  }

  /**
   * Ensure the backing block array can address {@code targetBlock}; requires caller to hold lock.
   */
  private void ensureBlocksCapacity(int targetBlock) {
    if (blocks.length <= targetBlock) {
      if (LOG.isDebugEnabled()) LOG.debug("add: expanding blocks for {}", this);
      Block[] newBlocks = Arrays.copyOf(blocks, targetBlock + 1);
      for (int i = blocks.length; i < newBlocks.length; i++) {
        newBlocks[i] = new Block();
        newBlocks[i].reqs = new RandomGrabArrayItem[BLOCK_SIZE];
      }
      blocks = newBlocks;
    }
  }

  /** Append {@code req} into the target block; requires caller to hold lock. */
  private void appendToTargetBlock(int targetBlock, RandomGrabArrayItem req) {
    Block target = blocks[targetBlock];
    target.reqs[index++ % BLOCK_SIZE] = req;
    if (LOG.isDebugEnabled()) LOG.debug("add: appended {} to {} size={}", req, this, index);
  }

  /**
   * Returns the number of stored items.
   *
   * @return logical size (non-negative)
   */
  public int size() {
    synchronized (root) {
      return index;
    }
  }

  /**
   * Returns the item at the given logical index without removing it.
   *
   * <p>No bounds checks are performed.
   *
   * @param idx zero-based logical index
   * @return the item at {@code idx}
   */
  public RandomGrabArrayItem get(int idx) {
    synchronized (root) {
      int blockNo = idx / BLOCK_SIZE;
      return blocks[blockNo].reqs[idx % BLOCK_SIZE];
    }
  }

  // Method removed: previously moved elements to another RGA; no current callers.

  /**
   * Sets the parent node used for wakeup propagation and emptiness notifications.
   *
   * @param newParent the new parent; may be {@code null}
   */
  @Override
  public void setParent(RemoveRandomParent newParent) {
    synchronized (root) {
      this.parent = newParent;
    }
  }

  /**
   * Returns the parent in the selection tree.
   *
   * @return the parent node, or {@code null} if this is a top-level node
   */
  @Override
  public RequestSelectionTreeNode getParentGrabArray() {
    synchronized (root) {
      return parent;
    }
  }

  /**
   * Returns this node's stored wakeup time, normalized to {@code 0} when already past {@code now}.
   *
   * <p>The value reflects the earliest exclusion observed during the last exhaustive selection. It
   * is cleared or reduced when readiness changes.
   *
   * @param context client context (ignored)
   * @param now current time in milliseconds since the epoch
   * @return {@code 0} when ready; otherwise a future timestamp
   */
  @Override
  public long getWakeupTime(ClientContext context, long now) {
    synchronized (root) {
      if (wakeupTime < now) wakeupTime = 0;
      return wakeupTime;
    }
  }

  /**
   * Stores a new wakeup time and, when reduced, propagates the reduction to the parent.
   *
   * <p>Used after an exhaustive pass determines no items are ready. Increases do not propagate
   * because parents re-evaluate when needed.
   *
   * @param wakeupTime future timestamp in milliseconds since the epoch
   * @param context the client context used for parent notifications
   */
  private void setWakeupTime(long wakeupTime, ClientContext context) {
    if (LOG.isDebugEnabled())
      LOG.debug("setCooldownTime({}) on {}", wakeupTime - System.currentTimeMillis(), this);
    synchronized (root) {
      if (this.wakeupTime > wakeupTime) {
        this.wakeupTime = wakeupTime; // Set before calling parent.
        if (parent != null) parent.reduceWakeupTime(wakeupTime, context);
      } else {
        this.wakeupTime = wakeupTime;
      }
    }
  }

  /**
   * Reduces the stored wakeup time and propagates the reduction to the parent.
   *
   * @param wakeupTime candidate timestamp; only applies if smaller than the current one
   * @param context client context used for parent notifications
   * @return {@code true} if the stored value was reduced
   */
  @Override
  public boolean reduceWakeupTime(long wakeupTime, ClientContext context) {
    if (LOG.isDebugEnabled())
      LOG.debug("reduceCooldownTime({}) on {}", wakeupTime - System.currentTimeMillis(), this);
    synchronized (root) {
      if (this.wakeupTime > wakeupTime) {
        this.wakeupTime = wakeupTime;
        if (parent != null) parent.reduceWakeupTime(wakeupTime, context);
        return true;
      }
      return false;
    }
  }

  /**
   * Clears the stored wakeup time and requests the parent to clear its cached state as well.
   *
   * @param context client context used for parent notifications
   */
  @Override
  public void clearWakeupTime(ClientContext context) {
    if (LOG.isDebugEnabled()) LOG.debug("clearCooldownTime() on {}", this);
    synchronized (root) {
      wakeupTime = 0;
      if (parent != null) parent.clearWakeupTime(context);
    }
  }
}

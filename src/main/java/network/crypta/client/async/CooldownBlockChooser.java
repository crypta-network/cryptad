package network.crypta.client.async;

import java.util.Random;

/**
 * A {@link SimpleBlockChooser} variant that introduces per-block cooldown windows after repeated
 * non‑fatal failures.
 *
 * <p>This chooser behaves like the base implementation for tracking completion and retry counts but
 * augments selection with a configurable cooldown policy. After a block accumulates a defined
 * number of consecutive non‑fatal failures, it becomes temporarily ineligible for selection. The
 * goal is to avoid continuously hammering problematic blocks while allowing other work to proceed
 * and potentially change the network or cache state. Cooldowns are tracked per block, while a
 * cached "overall" wakeup time exposes when any block may next become eligible again.
 *
 * <p>Instances are stateful and use synchronized methods; individual operations are thread‑safe
 * with respect to a single instance. The supplied {@link Random} is used only to break ties among
 * currently eligible blocks with equal retry counts in the inherited strategy. All timings are in
 * wall‑clock milliseconds as returned by {@link System#currentTimeMillis()}.
 *
 * <ul>
 *   <li>Cooldown begins when the attempt count for a block is an exact multiple of {@code
 *       cooldownTries} (and {@code cooldownTries != 0}).
 *   <li>During a cooldown window, a block is treated as invalid by {@link #checkValid(int)} and is
 *       excluded from selection.
 *   <li>{@link #chooseKey()} returns {@code -1} while all candidates are cooling down and provides
 *       the next wake‑up via {@link #overallCooldownTime()}.
 * </ul>
 *
 * @see SimpleBlockChooser
 */
public class CooldownBlockChooser extends SimpleBlockChooser {
  /**
   * Creates a chooser that enforces a periodic cooldown after a configurable number of attempts.
   *
   * <p>The base retry accounting from {@link SimpleBlockChooser} remains intact. Whenever the
   * number of attempts for a block becomes a multiple of {@code cooldownTries}, the block enters a
   * cooling period and is not eligible for selection until the period expires.
   *
   * @param blocks total number of blocks managed by this chooser; valid indices are {@code [0,
   *     blocks)} and the value must be non‑negative and consistent with callers.
   * @param random randomness source to break ties between equally retried, eligible blocks; must
   *     not be {@code null} and is used only for selection fairness.
   * @param maxRetries maximum non‑fatal retries allowed per block; use {@code -1} for unlimited
   *     retries without exclusion by retry budget alone.
   * @param cooldownTries number of attempts between cooldowns; when non‑zero, every {@code
   *     cooldownTries}th attempt schedules a cooldown window for the block.
   * @param cooldownTime cooldown duration in milliseconds, added to {@link
   *     System#currentTimeMillis()} to derive the per‑block wake‑up timestamp.
   */
  public CooldownBlockChooser(
      int blocks, Random random, int maxRetries, int cooldownTries, long cooldownTime) {
    super(blocks, random, maxRetries);
    this.cooldownTries = cooldownTries;
    this.cooldownTime = cooldownTime;
    blockCooldownTimes = new long[blocks];
  }

  /** Every cooldownTries attempts, a key will enter cooldown and won't be re-tried for a period. */
  private final int cooldownTries;

  /** Cooldown lasts this long for each key. */
  private final long cooldownTime;

  /**
   * Time at which the whole block chooser will next become fetchable. 0 to mean it is fetchable
   * now. Equal to the earliest valid cooldown time for any individual block. INVARIANT: This can
   * safely be too early (small) but not too late (large).
   */
  private long overallCooldownTime;

  /** Time at which each block becomes fetchable again. 0 means it is fetchable now. */
  private final long[] blockCooldownTimes;

  /** Current time, updated at the beginning of chooseKey(). */
  private long now;

  /**
   * {@inheritDoc}
   *
   * <p>This override first checks a cached, conservative wake‑up timestamp. When the overall
   * cooldown has not yet expired, the method returns {@code -1} without delegating to the base
   * selection logic. Otherwise, it defers to {@link SimpleBlockChooser#chooseKey()} and clears the
   * gate when a block is successfully chosen.
   *
   * <pre>{@code
   * // Example: poll until a block becomes eligible
   * int idx = chooser.chooseKey();
   * if (idx == -1) Thread.sleep(Math.max(1, chooser.overallCooldownTime() - System.currentTimeMillis()));
   * }</pre>
   */
  @Override
  public synchronized int chooseKey() {
    now = System.currentTimeMillis();
    if (overallCooldownTime > now) return -1;
    overallCooldownTime = Long.MAX_VALUE; // Will find the earliest wake-up.
    int ret = super.chooseKey();
    if (ret != -1) overallCooldownTime = 0; // Fetchable now, else waiting for cooldown.
    return ret;
  }

  @Override
  protected synchronized boolean checkValid(int blockNo) {
    if (!super.checkValid(blockNo)) return false;
    long wakeUp = blockCooldownTimes[blockNo];
    // Consider cooldown ending exactly at 'now' as expired to avoid edge races
    // where callers observe a zero-length remaining cooldown. Using '>=' here
    // makes a block eligible when wakeUp equals the current time.
    if (now >= wakeUp) {
      blockCooldownTimes[blockNo] = 0;
      return true;
    } else {
      // Update the overall cooldown wakeup time.
      overallCooldownTime = Math.min(overallCooldownTime, wakeUp);
      return false;
    }
  }

  /** {@inheritDoc} */
  @Override
  protected synchronized int innerOnNonFatalFailure(int blockNo) {
    int ret = super.innerOnNonFatalFailure(blockNo);
    // If a retry limit applies, and we've exceeded it, skip cooldown adjustments.
    if (!(maxRetries != -1 && ret > maxRetries)) {
      if (cooldownTries != 0 && ret % cooldownTries == 0) {
        blockCooldownTimes[blockNo] = System.currentTimeMillis() + cooldownTime;
        overallCooldownTime =
            Math.min(
                blockCooldownTimes[blockNo], overallCooldownTime); // Must not be left at infinite!
      } else {
        // Fetchable.
        blockCooldownTimes[blockNo] = 0;
        overallCooldownTime = 0;
      }
    }
    return ret;
  }

  /**
   * Clears the global cooldown gate so selection can resume immediately.
   *
   * <p>This resets the cached "overall" wake‑up timestamp used by {@link #chooseKey()} to decide
   * whether any block may be eligible. It does not modify per‑block cooldown timers or retry
   * counters. Callers typically invoke this after externally changing the set of selectable blocks
   * (for example, after a change in {@link #getMaxBlockNumber()}) to force a prompt re‑evaluation.
   */
  public final synchronized void clearCooldown() {
    overallCooldownTime = 0;
  }

  /**
   * Marks a block as no longer successful and clears any associated cooldown.
   *
   * <p>This override resets the per‑block cooldown timer for {@code blockNo} and clears the cached
   * overall cooldown gate so that further calls to {@link #chooseKey()} consider eligibility
   * immediately. Callers use this when previously downloaded data becomes unusable (for example,
   * after validation failure or corruption), and the block needs to be retried without an
   * artificial delay.
   *
   * @param blockNo zero‑based index of the block to mark as not successful; must be within range
   *     and refer to a block tracked by this chooser.
   */
  @Override
  public synchronized void onUnSuccess(int blockNo) {
    blockCooldownTimes[blockNo] = 0;
    clearCooldown();
  }

  /**
   * Returns the earliest time at which any block may next be eligible for selection.
   *
   * <p>The value has been a wall‑clock timestamp in milliseconds since the epoch, as produced by
   * {@link System#currentTimeMillis()}. A return value of {@code 0} means no global cooldown
   * applies and a block may be immediately available if other eligibility conditions hold. While
   * best‑effort and safe to be conservative, this time is never later than the actual earliest
   * per‑block wake‑up.
   *
   * @return timestamp in milliseconds for the next potential eligibility across all blocks, or
   *     {@code 0} when cooldown does not globally delay selection.
   */
  public synchronized long overallCooldownTime() {
    return overallCooldownTime;
  }

  /**
   * Returns the per‑block cooldown wake‑up timestamp for the given block.
   *
   * <p>If the block has already succeeded, the method reports {@code 0}. Otherwise, it returns the
   * wall‑clock time in milliseconds at which the block becomes eligible again. A value of {@code 0}
   * indicates that no cooldown currently prevents the block from being considered.
   *
   * @param blockNumber zero‑based index of the block whose cooldown timestamp is requested; must be
   *     within the configured range for this chooser instance.
   * @return a millisecond epoch timestamp for the block's cooldown expiry, or {@code 0} if the
   *     block has succeeded or is not subject to cooldown at present.
   */
  public synchronized long getCooldownTime(int blockNumber) {
    if (hasSucceeded(blockNumber)) return 0;
    return blockCooldownTimes[blockNumber];
  }
}

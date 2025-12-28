package network.crypta.support

import java.util.concurrent.TimeUnit.MILLISECONDS
import java.util.concurrent.TimeUnit.NANOSECONDS
import org.slf4j.LoggerFactory

/**
 * Token-bucket throttle for outbound bandwidth limiting.
 *
 * This minimal, thread-safe implementation replaces the legacy Java `TokenBucket` while retaining
 * only the behavior the node relies on:
 * - `changeNanosAndBucketSize()`
 * - `forceGrab()`
 * - `getCount()`
 * - `getNanosPerTick()`
 *
 * Tokens accrue at a fixed rate of one token every `nanosPerTick` nanoseconds up to a capacity of
 * `maxTokens`. The time source is `System.currentTimeMillis()` converted to nanoseconds, not a
 * monotonic clock. Clock regressions are detected and handled by resynchronizing without adding
 * tokens.
 *
 * Concurrency: all public methods are `synchronized` on `this`, matching the synchronization
 * semantics of the former implementation and providing safe publication of state across threads.
 * This class does not provide a blocking acquire API; some legacy callers may still `wait()` on the
 * instance monitor. To accommodate them, decreasing `nanosPerTick` (a faster rate) triggers a
 * `notifyAll()` so external waiters can re-check their conditions promptly.
 *
 * Preconditions:
 * - `nanosPerTick > 0`
 * - `maxTokens > 0`
 * - `initialTokens` is clamped to `maxTokens` (an error is logged if it exceeds the maximum).
 *
 * Postconditions:
 * - After construction, `current` lies in `[0, maxTokens]`.
 * - Balances may become negative only via `forceGrab()`; regular accrual does not clamp at 0 and
 *   only clips the upper bound to `maxTokens`.
 *
 * Complexity: all operations are O(1).
 *
 * @param maxTokens maximum capacity of the bucket (tokens).
 * @param nanosPerTick nanoseconds per token (rate), strictly positive.
 * @param initialTokens initial token count; clamped to `maxTokens` if higher.
 * @throws IllegalArgumentException if `nanosPerTick <= 0` or `maxTokens <= 0`.
 */
class OutputThrottle(maxTokens: Long, nanosPerTick: Long, initialTokens: Long) {

  private val log = LoggerFactory.getLogger(OutputThrottle::class.java)

  // State mirrors the legacy implementation for deterministic behavior.
  private var current: Long
  private var max: Long
  private var timeLastTick: Long
  private var nanosPerTick: Long

  init {
    require(nanosPerTick > 0) { "nanosPerTick must be > 0" }
    require(maxTokens > 0) { "maxTokens must be > 0" }
    this.max = maxTokens
    var cur = initialTokens
    if (cur > max) {
      log.error("initial value ($cur) > max ($max) in $this", Exception("error"))
      cur = max
    }
    this.current = cur
    this.nanosPerTick = nanosPerTick
    val nowMs = System.currentTimeMillis()
    // Use wall-clock time (ms converted to ns). Not monotonic but sufficient for coarse accrual.
    this.timeLastTick = NANOSECONDS.convert(nowMs, MILLISECONDS)
  }

  /**
   * Updates both the token accrual rate and the bucket capacity at runtime.
   *
   * Behavior:
   * - Accrues tokens using the previous `nanosPerTick` before applying the new settings to preserve
   *   continuity.
   * - If the new `nanosPerTick` represents a faster rate (smaller value), calls `notifyAll()` on
   *   this instance to wake external waiters that might be `wait()`ing on the monitor.
   * - Applies the new maximum and clamps the current balance to the new `newMaxTokens`.
   *
   * Thread-safety: synchronized.
   *
   * @param nanosPerTick new nanoseconds per token; must be > 0.
   * @param newMaxTokens new capacity in tokens; must be > 0.
   * @throws IllegalArgumentException if `nanosPerTick <= 0` or `newMaxTokens <= 0`.
   */
  @Synchronized
  fun changeNanosAndBucketSize(nanosPerTick: Long, newMaxTokens: Long) {
    require(nanosPerTick > 0) { "nanosPerTick must be > 0" }
    require(newMaxTokens > 0) { "newMaxTokens must be > 0" }
    // Accrue using the old rate; avoid clipping before changing the maximum.
    addTokensNoClip()
    // Rate increased (smaller nanos per tick): nudge any external waiters to re-evaluate.
    if (nanosPerTick < this.nanosPerTick) notifyAllWaiters()
    this.nanosPerTick = nanosPerTick
    this.max = newMaxTokens
    if (current > max) current = max
  }

  /**
   * Notifies any threads waiting on this instance's monitor.
   *
   * Kotlin `Any` does not expose `notifyAll()`, so we call the JVM method via a suppressed cast.
   */
  @Suppress("PLATFORM_CLASS_MAPPED_TO_KOTLIN")
  private fun notifyAllWaiters() {
    (this as Object).notifyAll()
  }

  /**
   * Removes tokens without blocking, allowing the balance to go negative.
   *
   * Accrues any due tokens first and then subtracts `tokens` from the current balance. This is used
   * for unconditional reservations where the caller must proceed regardless of the current bucket
   * level.
   *
   * Thread-safety: synchronized.
   *
   * @param tokens number of tokens to remove; must be >= 0.
   * @throws IllegalArgumentException if `tokens < 0`.
   */
  @Synchronized
  fun forceGrab(tokens: Long) {
    require(tokens >= 0) { "Can't grab negative tokens: $tokens" }
    addTokens()
    current -= tokens
  }

  /**
   * Returns the current number of tokens after accruing any due ticks.
   *
   * May return a negative value if previous calls to `forceGrab()` over-drew the bucket; only the
   * upper bound is clipped to the capacity.
   *
   * Thread-safety: synchronized.
   *
   * @return the current token balance (may be negative).
   */
  @Synchronized
  fun getCount(): Long {
    addTokens()
    return current
  }

  /**
   * Returns the configured nanoseconds per token (accrual rate).
   *
   * Thread-safety: synchronized; returns a stable snapshot at call time.
   *
   * @return nanoseconds per token.
   */
  @Synchronized fun getNanosPerTick(): Long = nanosPerTick

  /** Bring the bucket up to date and clip to [max]. */
  @Synchronized
  private fun addTokens() {
    addTokensNoClip()
    if (current > max) current = max
  }

  /** Update the number of tokens according to elapsed time, without clipping. */
  @Synchronized
  private fun addTokensNoClip() {
    val add = tokensToAdd()
    if (add == 0L) return
    current += add
    // Advance the internal time by the number of full ticks credited to avoid double-counting.
    timeLastTick += add * nanosPerTick
  }

  @Synchronized
  private fun tokensToAdd(): Long {
    val nowNs = NANOSECONDS.convert(System.currentTimeMillis(), MILLISECONDS)
    if (timeLastTick > nowNs) {
      // Clock moved backwards; resync to now and add nothing.
      log.error("CLOCK SKEW DETECTED! timeLastTick > now; resyncing")
      timeLastTick = nowNs
      return 0
    }
    val nextTick = timeLastTick + nanosPerTick
    if (nextTick > nowNs) return 0 // No full tick elapsed.
    if (nextTick + nanosPerTick > nowNs) return 1 // Exactly one tick elapsed.
    // Compute the number of full ticks that elapsed since the first pending tick.
    return (nowNs - nextTick) / nanosPerTick
  }
}

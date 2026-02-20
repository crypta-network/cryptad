package network.crypta.support;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.NANOSECONDS;

/**
 * Token-bucket throttle for outbound bandwidth limiting.
 *
 * <p>This class implements a compact token-bucket rate limiter used to cap outbound bandwidth-like
 * activity in terms of abstract tokens. Tokens increase over time according to a configured
 * nanoseconds-per-token rate, and callers can inspect or consume available capacity via
 * synchronized operations. The implementation intentionally preserves legacy behavior expected by
 * the node, including runtime reconfiguration and support for non-blocking forced debits that may
 * drive the balance negative temporarily.
 *
 * <p>All mutable states are guarded by the instance monitor, making reads and updates thread-safe
 * for concurrent callers. Time is derived from wall-clock milliseconds converted to nanoseconds,
 * and skew handling prevents runaway token grants when the clock moves backward.
 */
public final class OutputThrottle {
  private final Logger log = LoggerFactory.getLogger(OutputThrottle.class);

  // State mirrors the legacy implementation for deterministic behavior.
  private long current;
  private long max;
  private long timeLastTick;
  private long nanosPerTick;

  /**
   * Creates a token-bucket throttle with explicit capacity, rate, and initial balance.
   *
   * <p>The initial token balance is clamped to the configured maximum if it exceeds bucket
   * capacity.
   *
   * @param maxTokens the maximum capacity of the bucket (tokens) must be > 0.
   * @param nanosPerTick nanoseconds per token (rate) must be > 0.
   * @param initialTokens initial token count; clamped to maxTokens if higher.
   * @throws IllegalArgumentException if {@code maxTokens <= 0} or {@code nanosPerTick <= 0}
   */
  public OutputThrottle(long maxTokens, long nanosPerTick, long initialTokens) {
    if (nanosPerTick <= 0) {
      throw new IllegalArgumentException("nanosPerTick must be > 0");
    }
    if (maxTokens <= 0) {
      throw new IllegalArgumentException("maxTokens must be > 0");
    }
    this.max = maxTokens;
    long cur = initialTokens;
    if (cur > max) {
      log.error("initial value ({}) > max ({}) in {}", cur, max, this, new Exception("error"));
      cur = max;
    }
    this.current = cur;
    this.nanosPerTick = nanosPerTick;
    long nowMs = System.currentTimeMillis();
    this.timeLastTick = NANOSECONDS.convert(nowMs, MILLISECONDS);
  }

  /**
   * Updates both the token accrual rate and the bucket capacity at runtime.
   *
   * <p>If the new nanosPerTick is smaller (faster rate), waiters are notified.
   *
   * @param nanosPerTick replacement nanoseconds-per-token rate; must be greater than zero
   * @param newMaxTokens replacement maximum bucket capacity; must be greater than zero
   * @throws IllegalArgumentException if either supplied value is not positive
   */
  public synchronized void changeNanosAndBucketSize(long nanosPerTick, long newMaxTokens) {
    if (nanosPerTick <= 0) {
      throw new IllegalArgumentException("nanosPerTick must be > 0");
    }
    if (newMaxTokens <= 0) {
      throw new IllegalArgumentException("newMaxTokens must be > 0");
    }
    addTokensNoClip();
    if (nanosPerTick < this.nanosPerTick) {
      notifyAll();
    }
    this.nanosPerTick = nanosPerTick;
    this.max = newMaxTokens;
    if (current > max) {
      current = max;
    }
  }

  /**
   * Removes tokens without blocking, allowing the balance to go negative.
   *
   * @param tokens number of tokens to remove; must be >= 0.
   */
  public synchronized void forceGrab(long tokens) {
    if (tokens < 0) {
      throw new IllegalArgumentException("Can't grab negative tokens: " + tokens);
    }
    addTokens();
    current -= tokens;
  }

  /**
   * Returns the current token balance after accruing elapsed ticks.
   *
   * @return up-to-date token count, clipped to the configured maximum capacity
   */
  public synchronized long getCount() {
    addTokens();
    return current;
  }

  /**
   * Returns the configured token accrual rate.
   *
   * @return nanoseconds required to generate one token
   */
  public synchronized long getNanosPerTick() {
    return nanosPerTick;
  }

  /** Bring the bucket up to date and clip to max. */
  private synchronized void addTokens() {
    addTokensNoClip();
    if (current > max) {
      current = max;
    }
  }

  /** Update the token count according to elapsed time, without clipping. */
  private synchronized void addTokensNoClip() {
    long add = tokensToAdd();
    if (add == 0L) {
      return;
    }
    current += add;
    timeLastTick += add * nanosPerTick;
  }

  private synchronized long tokensToAdd() {
    long nowNs = NANOSECONDS.convert(System.currentTimeMillis(), MILLISECONDS);
    if (timeLastTick > nowNs) {
      log.error("CLOCK SKEW DETECTED! timeLastTick > now; resyncing");
      timeLastTick = nowNs;
      return 0;
    }
    long nextTick = timeLastTick + nanosPerTick;
    if (nextTick > nowNs) {
      return 0;
    }
    if (nextTick + nanosPerTick > nowNs) {
      return 1;
    }
    return (nowNs - nextTick) / nanosPerTick;
  }
}

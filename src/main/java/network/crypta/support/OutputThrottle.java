package network.crypta.support;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.NANOSECONDS;

/**
 * Token-bucket throttle for outbound bandwidth limiting.
 *
 * <p>This minimal, thread-safe implementation replaces the legacy Java `TokenBucket` while
 * retaining only the behavior the node relies on.
 */
public final class OutputThrottle {
  private final Logger log = LoggerFactory.getLogger(OutputThrottle.class);

  // State mirrors the legacy implementation for deterministic behavior.
  private long current;
  private long max;
  private long timeLastTick;
  private long nanosPerTick;

  /**
   * @param maxTokens maximum capacity of the bucket (tokens), must be > 0.
   * @param nanosPerTick nanoseconds per token (rate), must be > 0.
   * @param initialTokens initial token count; clamped to maxTokens if higher.
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

  /** Returns the current number of tokens after accruing due ticks. */
  public synchronized long getCount() {
    addTokens();
    return current;
  }

  /** Returns the configured nanoseconds per token. */
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

  /** Update token count according to elapsed time, without clipping. */
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

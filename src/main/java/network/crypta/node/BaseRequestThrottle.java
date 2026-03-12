package network.crypta.node;

import static java.util.concurrent.TimeUnit.MINUTES;

/**
 * Defines the minimal contract for request throttling.
 *
 * <p>Implementations expose a current inter-request delay and typically use the provided constants
 * as conventional bounds. The delay represents the time a caller should wait between scheduling or
 * issuing consecutive requests.
 *
 * <p>Unless otherwise specified by an implementation, values are expressed in milliseconds. The
 * method may be called frequently and from multiple threads; implementations commonly make it
 * thread-safe and may vary the returned value over time in response to load or policy.
 */
public interface BaseRequestThrottle {

  /**
   * Maximum recommended inter-request delay in milliseconds.
   *
   * <p>Adaptive throttlers typically cap the delay at this value to avoid excessively stalling
   * progress under sustained back-pressure. Implementations may enforce this bound when computing
   * {@link #getDelay()}.
   */
  long MAX_DELAY = MINUTES.toMillis(5);

  /**
   * Minimum recommended inter-request delay in milliseconds.
   *
   * <p>Adaptive throttlers typically never go below this floor to prevent busy-waiting or flooding
   * downstream components. Implementations may enforce this bound when computing {@link
   * #getDelay()}.
   */
  long MIN_DELAY = 20L;

  /**
   * Returns the current inter-request delay in milliseconds.
   *
   * <p>The value is a snapshot and may change between calls. Implementations often bound the result
   * to the inclusive range defined by {@link #MIN_DELAY} and {@link #MAX_DELAY}, but this interface
   * does not mandate a specific policy.
   *
   * @return the time to wait between consecutive requests, in milliseconds
   */
  long getDelay();
}

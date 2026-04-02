package network.crypta.node.probe;

/**
 * Mutable, bounds-checked counter used to track accepted probes within a time window.
 *
 * <p>This utility maintains a single integer that is expected to stay within the closed interval
 * {@code [0, maxAccepted]}. It deliberately throws an {@link IllegalStateException} when the
 * invariant is violated, which helps surface logic errors or missing synchronization in the code
 * that orchestrates updates. Typical usage follows a "check-then-increment" pattern: call {@link
 * #value()} and compare it to {@link #maxAccepted}; if the current value is below the maximum, call
 * {@link #increment()} to reserve capacity, and later call {@link #decrement()} to release it.
 *
 * <p>The counter is intentionally lightweight and does not perform any implicit synchronization or
 * time-based decay. It is not thread-safe; callers must provide external synchronization when the
 * instance is accessed from multiple threads. The class does not validate constructor arguments and
 * therefore accepts negative maxima; while supported, such values will make any increment fail
 * immediately and should be avoided in normal operation.
 *
 * <ul>
 *   <li>State space: {@code 0 <= value() <= maxAccepted} under correct usage.
 *   <li>Failure mode: throws {@link IllegalStateException} on overflow or underflow.
 *   <li>Thread-safety: not thread-safe; synchronize externally if shared.
 * </ul>
 */
class Counter {
  /**
   * Maximum number of accepted probes allowed at any given moment.
   *
   * <p>The value is provided by the constructor and never changes for the lifetime of the instance.
   * Units are in "probes" (count of accepted operations). While negative values are technically
   * allowed, they make the counter unusable for increments because any call to {@link #increment()}
   * will overflow immediately. Access is thread-safe only to the extent the surrounding code
   * protects it; the field itself is {@code final} and read-mostly.
   */
  public final int maxAccepted;

  private int c = 0;

  /**
   * Creates a new counter with the provided maximum.
   *
   * <p>No validation is performed on the {@code maxAccepted} argument. A negative value results in
   * a counter that cannot be incremented without throwing an exception. Callers are expected to
   * choose a non-negative maximum when the counter is used to enforce a capacity limit.
   *
   * <pre>{@code
   * Counter counter = new Counter(100);
   * if (counter.value() < counter.maxAccepted) {
   *   counter.increment();
   * }
   * }</pre>
   *
   * @param maxAccepted upper bound for the counter; supply a non-negative integer representing the
   *     allowed number of concurrent or recent probes; negative values are accepted but render the
   *     counter unusable for increments in practice
   */
  public Counter(int maxAccepted) {
    this.maxAccepted = maxAccepted;
  }

  /**
   * Increments the counter by one with overflow checking.
   *
   * <p>Callers should only invoke this method after confirming that {@link #value()} is strictly
   * less than {@link #maxAccepted}. If the increment would move the counter above the configured
   * maximum, an {@link IllegalStateException} is thrown. The method is not idempotent and performs
   * no internal synchronization; coordinate concurrent access externally.
   *
   * @throws IllegalStateException if the counter exceeds {@link #maxAccepted} after the increment;
   *     the exception message includes the observed illegal value to aid diagnostics
   */
  public void increment() {
    c++;
    if (c > maxAccepted) {
      /*
       * The counter should never be incremented above the maximum, as an increment should
       * only happen after it has been confirmed to be below the limit. If this happens, it
       * indicates a concurrency problem or logic error.
       */
      throw new IllegalStateException("Number of accepted probes exceeds the maximum: " + c);
    }
  }

  /**
   * Decrements the counter by one with underflow checking.
   *
   * <p>This method should always be paired with a prior successful {@link #increment()} on the same
   * counter instance. If the decrement would move the value below zero, an {@link
   * IllegalStateException} is thrown. The method is not idempotent and does not synchronize; ensure
   * that concurrent callers cannot interleave decrements in a way that violates invariants.
   *
   * @throws IllegalStateException if the counter becomes negative after the decrement; the
   *     exception message includes the observed illegal value to aid diagnostics
   */
  public void decrement() {
    c--;
    if (c < 0) {
      /*
       * The counter should never be decremented lower than zero, as a decrement should always
       * be paired with an increment before it, and if a counter reaches zero it should be
       * removed to avoid memory leaks. If this happens, it indicates a concurrency problem or
       * logic error.
       */
      throw new IllegalStateException("Number of accepted probes is negative: " + c);
    }
  }

  /**
   * Returns the current counter value.
   *
   * <p>The returned value is a simple snapshot taken without synchronization. Under correct usage
   * the value stays within {@code [0, maxAccepted]}; concurrent, unsynchronized access may observe
   * intermediate states. The method performs no allocation and runs in constant time.
   *
   * @return the current number of accepted probes accounted for by this counter; non-negative under
   *     correct usage and at most {@link #maxAccepted}
   */
  public int value() {
    return c;
  }
}

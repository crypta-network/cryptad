package network.crypta.support;

/**
 * Provides a minimal {@link Ticker} implementation for tests that must avoid real scheduling.
 *
 * <p>This test utility implements the {@code Ticker} contract while deliberately performing no
 * timing or background work. It is intended for unit tests that exercise higher-level components
 * which accept a {@code Ticker} but should not spawn threads, sleep, or enqueue delayed tasks. The
 * two queueing methods are implemented as intentional no-ops, which keeps tests deterministic and
 * avoids surprise callbacks. The remaining operations are intentionally unsupported and throw
 * {@link UnsupportedOperationException} to make accidental reliance on real scheduling visible.
 *
 * <p>Concurrency and state: instances are stateless and thread-safe because they never mutate or
 * capture internal state. Calls are idempotent, and no work is retained between invocations. The
 * trade-off is that this implementation does not model timing behavior or cancellation semantics,
 * so it should only be used in tests where "do nothing" is the desired outcome.
 *
 * <ul>
 *   <li><strong>Responsibilities:</strong> provide a no-op scheduler substitute.
 *   <li><strong>Notable behavior:</strong> no jobs run; unsupported paths fail fast.
 * </ul>
 *
 * @see Ticker
 * @see PriorityAwareExecutor
 */
public class SpeedyTicker implements Ticker {

  /**
   * Creates a new no-op ticker instance for tests.
   *
   * <p>The instance holds no state and performs no scheduling, so construction is cheap and safe to
   * repeat. Tests typically create a new {@code SpeedyTicker} per fixture to avoid any accidental
   * coupling, even though instances are effectively interchangeable.
   */
  public SpeedyTicker() {
    // Intentionally empty: this test helper has no state to initialize.
  }

  /**
   * Accepts a delayed job but intentionally does not schedule or run it.
   *
   * <p>This no-op implementation is used in tests to avoid any interaction with timing or thread
   * scheduling. The method is idempotent and does not validate parameters; it simply returns
   * immediately. Use it when the caller should "pretend" to enqueue a job without causing any side
   * effects, even if {@code job} is {@code null} or {@code offset} is negative.
   *
   * @param job the runnable that would be scheduled; may be {@code null} in tests
   * @param offset delay in milliseconds, ignored because no scheduling occurs
   */
  @Override
  public void queueTimedJob(Runnable job, long offset) {
    // Intentionally no-op in tests to avoid background scheduling.
  }

  /**
   * Accepts a delayed job with metadata but intentionally does not schedule or run it.
   *
   * <p>This variant mirrors the full {@link Ticker} signature but keeps test behavior deterministic
   * by doing nothing. The call has no observable side effects and does not enforce the {@code
   * runOnTickerAnyway} or {@code noDupes} hints. This makes it safe for tests that only need to
   * verify call paths rather than timing or de-duplication behavior.
   *
   * @param job the runnable that would be scheduled; may be {@code null} in tests
   * @param name optional diagnostic name, ignored by this no-op implementation
   * @param offset delay in milliseconds, ignored because no scheduling occurs
   * @param runOnTickerAnyway hint to start on ticker thread; ignored here
   * @param noDupes hint to prevent duplicates; ignored because nothing is queued
   */
  @Override
  public void queueTimedJob(
      Runnable job, String name, long offset, boolean runOnTickerAnyway, boolean noDupes) {
    // Intentionally no-op in tests to avoid background scheduling.
  }

  /**
   * Always throws because this test helper has no backing executor.
   *
   * <p>The {@link SpeedyTicker} is intentionally minimal and does not create threads or executors.
   * Tests that require a real {@link PriorityAwareExecutor} should provide a different
   * implementation. Calling this method is therefore treated as a misuse and fails fast.
   *
   * @return never returns normally because it always throws
   * @throws UnsupportedOperationException always thrown to indicate unsupported access
   */
  @Override
  public PriorityAwareExecutor getExecutor() {
    throw new UnsupportedOperationException();
  }

  /**
   * Always throws because cancellation is not supported by this no-op ticker.
   *
   * <p>This implementation does not queue any work, so there is nothing to cancel. The method
   * throws consistently to surface accidental reliance on cancellation logic in tests that should
   * avoid background scheduling.
   *
   * @param job the runnable that would be removed; may be {@code null} in tests
   * @throws UnsupportedOperationException always thrown because no jobs are stored
   */
  @Override
  public void removeQueuedJob(Runnable job) {
    throw new UnsupportedOperationException();
  }

  /**
   * Always throws because absolute-time scheduling is not supported by this no-op ticker.
   *
   * <p>Absolute scheduling requires a real timing facility, which this class intentionally avoids.
   * Tests that need to simulate time-based execution should substitute a dedicated scheduler. This
   * method fails fast to make such usage explicit and prevent silent omissions.
   *
   * @param runner the runnable that would be scheduled; may be {@code null} in tests
   * @param name optional diagnostic name, ignored by this implementation
   * @param time absolute time in milliseconds, ignored because scheduling is unsupported
   * @param runOnTickerAnyway hint to start on ticker thread; ignored here
   * @param noDupes hint to prevent duplicates; ignored because nothing is queued
   * @throws UnsupportedOperationException always thrown because scheduling is unsupported
   */
  @Override
  public void queueTimedJobAbsolute(
      Runnable runner, String name, long time, boolean runOnTickerAnyway, boolean noDupes) {
    throw new UnsupportedOperationException();
  }
}

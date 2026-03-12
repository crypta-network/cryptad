package network.crypta.support;

/**
 * A budgeted slice of a limited resource (typically bytes of memory) that has been allocated to a
 * {@link MemoryLimitedJob} by a {@link MemoryLimitedJobRunner}.
 *
 * <p>The chunk tracks how much of the allocation is still considered in use and allows releasing
 * some or all of it back to the runner. Usage can only decrease; it cannot be increased through
 * this API. Releasing forwards the amount to the runner so it can update its accounting and
 * potentially start queued jobs.
 *
 * <p>Thread-safety: methods are thread-safe. Updates to the internal {@code used} counter are
 * guarded by this instance's monitor. Calls into the runner happen outside the synchronized block
 * to avoid nested locking.
 *
 * <p>Invariants:
 *
 * <ul>
 *   <li>{@code used >= 0} at all times.
 *   <li>Released bytes are reported exactly once to the runner.
 * </ul>
 *
 * @author toad
 */
public final class MemoryLimitedChunk {
  private final MemoryLimitedJobRunner memoryLimitedJobRunner;
  // Current amount of resource in use. Guarded by this instance's monitor.
  private long used;

  /**
   * Creates a new chunk bound to the given runner with the specified initial usage.
   *
   * @param memoryLimitedJobRunner runner that receives deallocation notifications; if {@code null},
   *     subsequent calls to {@link #release()} or {@link #release(long)} will throw {@link
   *     NullPointerException} when notifying the runner.
   * @param used initial amount considered in use; must be {@code >= 0} and is expressed in the same
   *     units as the runner capacity (typically bytes).
   * @throws IllegalArgumentException if {@code used < 0}
   */
  MemoryLimitedChunk(MemoryLimitedJobRunner memoryLimitedJobRunner, long used) {
    this.memoryLimitedJobRunner = memoryLimitedJobRunner;
    if (used < 0) throw new IllegalArgumentException();
    this.used = used;
  }

  /**
   * Releases all remaining usage back to the runner.
   *
   * <p>Typical usage: call when a {@link MemoryLimitedJob} has finished using a temporary buffer
   * and there are no remaining strong references so the memory can be reclaimed.
   *
   * <p>This method is idempotent: subsequent calls after the first return {@code 0} and have no
   * effect.
   *
   * @return the number of units released (zero if already fully released)
   * @throws NullPointerException if this chunk was constructed with a {@code null} runner
   */
  public long release() {
    long released;
    synchronized (this) {
      if (used == 0) return 0;
      released = used;
      used = 0;
    }
    // Notify the runner outside the synchronized block so we don't hold this lock while it updates
    // its own state or schedules other jobs.
    this.memoryLimitedJobRunner.deallocate(released, true);
    return released;
  }

  /**
   * Releases a portion of the remaining usage.
   *
   * <p>Intended for transitions such as shrinking a buffer from large to small. The operation is
   * irreversible: the internal accounting only ever decreases.
   *
   * @param amount the number of units to release; must satisfy {@code 0 <= amount <= used} at the
   *     time of the call
   * @return the same {@code amount} that was released
   * @throws IllegalArgumentException if {@code amount} exceeds the amount currently in use
   * @throws NullPointerException if this chunk was constructed with a {@code null} runner
   *     <p>Implementation note: negative {@code amount} is not validated here; the {@link
   *     MemoryLimitedJobRunner} will reject negative values in {@link
   *     MemoryLimitedJobRunner#deallocate(long, boolean)}.
   */
  public long release(long amount) {
    boolean finishedThread;
    synchronized (this) {
      if (amount > used)
        throw new IllegalArgumentException(
            "Only have " + used + " in use but asked to release " + amount);
      used -= amount;
      finishedThread = (used == 0);
    }
    // Inform the runner of the partial (or final) release. When usage reaches zero we mark the
    // thread as finished so the runner can update its concurrency accounting.
    this.memoryLimitedJobRunner.deallocate(amount, finishedThread);
    return amount;
  }

  // Package-private for tests and internal coordination; not part of the public API of this type.
  MemoryLimitedJobRunner getRunner() {
    return this.memoryLimitedJobRunner;
  }
}

package network.crypta.support;

/**
 * A unit of work that consumes a bounded amount of a scarce resource (typically bytes of memory)
 * managed by a {@link MemoryLimitedJobRunner}.
 *
 * <p>The runner admits jobs while sufficient capacity is available and defers the rest. Each job
 * declares its initial resource requirement via {@link #initialAllocation}. When the runner starts
 * a job, it provides a {@link MemoryLimitedChunk} representing the job's current usage. The job may
 * release part or all of that allocation as it progresses but cannot increase it through the chunk
 * API. Accounting updates propagate back to the runner so that waiting jobs can be scheduled.
 *
 * <p>Threading: the runner invokes {@link #start(MemoryLimitedChunk)} on a worker thread supplied
 * by its {@link network.crypta.support.PriorityAwareExecutor}. The worker's native priority is the
 * runner's {@link MemoryLimitedJobRunner#THREAD_PRIORITY}. The value returned by {@link
 * #getPriority()} influences queue ordering only; it does not change the thread's OS priority.
 *
 * <p>Implementation guidelines:
 *
 * <ul>
 *   <li>Implementations must ensure the allocated {@code chunk} is eventually fully released on all
 *       code paths, including error paths.
 *   <li>Prefer not to throw from {@link #start(MemoryLimitedChunk)}. If an exception escapes, the
 *       runner will not automatically release the chunk.
 *   <li>Use {@code chunk.release(amount)} to return memory as soon as it is no longer needed to
 *       improve overall throughput.
 * </ul>
 */
public abstract class MemoryLimitedJob {

  /**
   * Initial amount of the limited resource that must be available for this job to start.
   *
   * <p>Units match the runner's capacity metric (typically bytes). The runner allocates a {@link
   * MemoryLimitedChunk} with exactly this initial usage when starting the job. This value must be
   * non-negative and should not exceed the runner's {@link MemoryLimitedJobRunner#getCapacity()} or
   * {@link MemoryLimitedJobRunner#queueJob(MemoryLimitedJob)} will throw {@link
   * IllegalArgumentException}.
   */
  protected final long initialAllocation;

  /**
   * Creates a job with the specified initial allocation.
   *
   * @param initial the initial resource usage required to start; must be {@code >= 0} and expressed
   *     in the same units as the runner's capacity (typically bytes)
   */
  protected MemoryLimitedJob(long initial) {
    this.initialAllocation = initial;
  }

  /**
   * Returns the queue priority bucket for this job.
   *
   * <p>The runner maintains multiple FIFO queues, one per priority. When capacity becomes available
   * it scans priorities in ascending numeric order and starts the first available job. Therefore,
   * lower values denote higher scheduling preference.
   *
   * <p>Valid values are implementation- and runner-dependent but must be within {@code [0,
   * priorities)} where {@code priorities} is the number configured for the {@link
   * MemoryLimitedJobRunner}. An out-of-range value will cause an {@link IndexOutOfBoundsException}
   * when the job is queued.
   *
   * @return zero-based priority index used for queue placement (0 = highest)
   */
  public abstract int getPriority();

  /**
   * Starts execution using the provided resource chunk.
   *
   * <p>The method may execute work synchronously and return a completion signal, or it may initiate
   * asynchronous work and return immediately. The {@code chunk} represents the currently-accounted
   * usage. It can be partially or fully released as buffers are discarded; it cannot be increased
   * via this API.
   *
   * <p>Completion and resource release:
   *
   * <ul>
   *   <li>If the method returns {@code true}, the runner will automatically call {@link
   *       MemoryLimitedChunk#release()} after this method returns. Implementations must ensure they
   *       no longer need the associated memory when returning {@code true}.
   *   <li>If the method returns {@code false}, the job remains responsible for calling {@link
   *       MemoryLimitedChunk#release()} when it has fully completed. It may call {@link
   *       MemoryLimitedChunk#release(long)} earlier to give back memory progressively.
   * </ul>
   *
   * <p>Threading: called by the {@link MemoryLimitedJobRunner} on a worker thread. This method must
   * not block indefinitely.
   *
   * @param chunk the resource allocation granted to this job; never {@code null}
   * @return {@code true} if the job finished synchronously and the runner should release the chunk;
   *     {@code false} if the job continues asynchronously and will release the chunk later
   * @throws RuntimeException implementations may throw unchecked exceptions; the runner does not
   *     automatically release the chunk on exception, so implementations should catch and release
   *     as needed
   */
  public abstract boolean start(MemoryLimitedChunk chunk);
}

package network.crypta.client.async;

/**
 * Coordinates execution of {@link PersistentJob} tasks that mutate persistent state and mediates
 * checkpoint operations so on-disk data remains consistent.
 *
 * <p>This runner provides a disciplined way to run jobs while periodically suspending mutating work
 * to write a consistent checkpoint. While a checkpoint is in progress, no jobs run; jobs that are
 * safe to delay will be queued and resumed afterward. Jobs that do not modify persistent state, or
 * purely read state, can safely run on any thread outside of this runner.
 *
 * <p>Typical usage is to submit jobs that represent meaningful persistence-affecting transitions
 * (for example, scheduling or advancing a client request), while allowing jobs to signal that a
 * checkpoint should occur soon after completion. The runner also supports a small set of "internal"
 * jobs that form short atomic sequences which must not be checkpointed midway.
 *
 * <p>Concurrency and lifecycle: the implementation ensures that no new jobs are started while a
 * checkpoint is being written, and that internal jobs complete before checkpointing begins. Callers
 * may obtain a lightweight {@link CheckpointLock} to delay checkpointing around small critical
 * sections when direct job submission is not appropriate.
 *
 * <ul>
 *   <li>Queues persistence-affecting jobs and schedules checkpoints.
 *   <li>Prevents job execution during checkpoint writes to preserve atomicity.
 *   <li>Allows internal, short-lived job chains to execute atomically.
 *   <li>Exposes utilities to force an early checkpoint when significant changes occur.
 * </ul>
 *
 * @see PersistentJob
 * @see PersistentJobRunnerImpl
 */
public interface PersistentJobRunner {

  /**
   * Enqueue a persistence-affecting job for immediate execution unless a checkpoint is pending, in
   * which case the job runs after the checkpoint completes.
   *
   * <p>The job itself is not persisted. Prefer this for operations that are recoverable across an
   * unclean shutdown (for example, refetching data from the datastore or network) or where the
   * system will re-establish the situation on startup (for example, resuming a decode stage via a
   * callback). This is also appropriate for housekeeping such as freeing temporary on-disk files
   * after a checkpoint.
   *
   * <pre>{@code
   * // Example: schedule a job at medium priority
   * runner.queue(job, NativeThread.PriorityLevel.NORM_PRIORITY.value);
   * }</pre>
   *
   * @param persistentJob the persistence-affecting unit of work to run; must be non-null and
   *     tolerate being delayed when a checkpoint is pending.
   * @param threadPriority the platform-specific priority to apply when running the job; higher
   *     numbers indicate higher priority as defined by the executor.
   * @throws PersistenceDisabledException if persistence is not available or the runner is shutting
   *     down so jobs cannot be accepted.
   */
  void queue(PersistentJob persistentJob, int threadPriority) throws PersistenceDisabledException;

  /**
   * Queue a job at the normal priority, or silently drop it when persistence is disabled.
   *
   * <p>This is a convenience for callers that can safely ignore the work when persistence is not
   * active, avoiding checked exception handling. The job is not persisted and may be delayed until
   * after a pending checkpoint has completed.
   *
   * @param persistentJob the job to execute opportunistically; ignored when the runner cannot
   *     accept work because persistence is disabled.
   */
  void queueNormalOrDrop(PersistentJob persistentJob);

  /**
   * Start an "internal" job. We will not checkpoint until all the internal jobs have finished; we
   * do not queue them at all. Hence, a series of internal jobs is atomic. This should be used for
   * stuff like creating the next stage of a request, where storing the half-way state would lead to
   * it potentially not restarting properly after shutdown. It MUST NOT be used for events from
   * outside the client layer, including finding blocks in the datastore, on the network etc.
   *
   * <p>FIXME this doesn't queue at all. Come up with a better name! :)
   *
   * <p>Internal jobs often continue an in-progress workflow on a different thread to minimize lock
   * contention or increase throughput while preserving atomicity with respect to checkpointing
   * boundaries.
   *
   * @param job the internal job forming part of an atomic sequence; must avoid blocking external
   *     events and must be safe to run without queuing.
   * @param threadPriority the priority to use for the internal job; larger values typically map to
   *     higher scheduling preference in the executor.
   * @throws PersistenceDisabledException if the runner is unable to accept internal work because it
   *     is shutting down or persistence is disabled.
   */
  void queueInternal(PersistentJob job, int threadPriority) throws PersistenceDisabledException;

  /**
   * Start an "internal" job. We will not checkpoint until all the internal jobs have finished; we
   * do not queue them at all. Hence, a series of internal jobs is atomic. This should be used for
   * stuff like creating the next stage of a request, where storing the half-way state would lead to
   * it potentially not restarting properly after shutdown. It MUST NOT be used for events from
   * outside the client layer, including finding blocks in the datastore, on the network etc.
   *
   * <p>Often when we call this we could have continued the job on the same thread. That's not
   * always the best thing to do however; we frequently move work to another job to minimize lock
   * contention or increase throughput.
   *
   * <p>FIXME this doesn't queue at all. Come up with a better name! :)
   *
   * @param job the internal job to execute immediately at the default priority; must participate in
   *     a short atomic sequence that should not be checkpointed midway.
   */
  void queueInternal(PersistentJob job);

  /**
   * Request that the runner perform a checkpoint as soon as practical.
   *
   * <p>Jobs may also request a checkpoint by returning {@code true} from {@link
   * PersistentJob#run(ClientContext)}. This method allows callers to request an early checkpoint
   * inline, outside of job execution, for example when several related updates have just been
   * enqueued.
   */
  void setCheckpointASAP();

  /**
   * Return whether the runner has completed initial loading and accepted at least one checkpointed
   * state.
   *
   * @return {@code true} when the runner has transitioned out of the initial loading phase and is
   *     ready to accept jobs; {@code false} while still starting up.
   */
  boolean hasLoaded();

  /**
   * A lightweight guard that temporarily prevents checkpointing while held.
   *
   * <p>Use this around brief critical sections that may touch persistent state but are not suitable
   * to express as a {@link PersistentJob}. Always use a try/finally block to ensure the lock is
   * released. Holding the lock does not block unrelated read-only operations; it only defers the
   * start of a checkpoint.
   */
  interface CheckpointLock {
    /**
     * Release the lock, optionally requesting an immediate checkpoint.
     *
     * <p>Callers should keep the protected section as small as possible to minimize checkpoint
     * delay. Unlocking may trigger a write immediately when there are no running jobs and the
     * caller priority permits off-thread checkpointing.
     *
     * @param forceWrite set to {@code true} to request a checkpoint as soon as feasible after the
     *     lock is released; {@code false} to leave scheduling unchanged.
     * @param threadPriority the priority to use when scheduling any work resulting from the unlock;
     *     higher values map to higher executor priority.
     */
    void unlock(boolean forceWrite, int threadPriority);
  }

  /**
   * Obtain a lock which will prevent checkpointing until it is unlocked. This counts as a thread,
   * and can be used for e.g. MemoryLimitedJob's that can change persistent data. Like any lock, you
   * MUST use a try/finally block. lock() may block if a checkpoint is in progress or is scheduled.
   *
   * @return a {@link CheckpointLock} that defers checkpointing while held and must be released to
   *     allow the next checkpoint to proceed.
   * @throws PersistenceDisabledException if unable to obtain the lock because the system is
   *     shutting down or persistence is disabled.
   */
  CheckpointLock lock() throws PersistenceDisabledException;

  /**
   * For persistent requests, return true if the bloom filter salt has changed when loading the
   * requests. In which case all the Bloom filters will be invalid and will need to be recomputed.
   *
   * @return {@code true} when a new salt was detected during load and dependent Bloom filters must
   *     be rebuilt; {@code false} when existing filters remain valid.
   */
  boolean newSalt();

  /**
   * Indicate whether the node is in the process of shutting down and no longer accepts new work.
   *
   * @return {@code true} if shutdown has been requested and new submissions may be rejected;
   *     otherwise {@code false}.
   */
  boolean shuttingDown();
}

package network.crypta.node;

/**
 * A {@link Runnable} that exposes a numeric priority.
 *
 * <p>Schedulers or queues that support priority-based execution can use this interface to get a
 * task's priority and order execution accordingly. The meaning of the returned number (e.g.,
 * whether higher or lower values denote "higher" priority) is defined by the scheduler using it.
 * Implementations should avoid heavy computation inside {@link #getPriority()}.
 *
 * @author toad
 */
public interface PrioRunnable extends Runnable {

  /**
   * Returns the priority associated with this task.
   *
   * <p>The value is an arbitrary integer consumed by the scheduling component. Callers commonly
   * expect the priority to remain stable while a task is enqueued; if it is dynamic, document the
   * behavior in the implementation.
   *
   * @return the priority value used by the scheduler
   */
  int getPriority();
}

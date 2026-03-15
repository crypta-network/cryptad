package network.crypta.runtime.spi;

/**
 * Functional interface representing one persistent-request queue task.
 *
 * <p>This interface models the smallest unit of work that the runtime request queue accepts. It is
 * deliberately narrower than the daemon's legacy job types, so runtime-spi remains JDK-only and
 * does not expose queue infrastructure details. Typical tasks perform one lookup, mutation, or
 * removal step and then return promptly.
 *
 * <p>The boolean result preserves the daemon's legacy persistent-job convention. Returning {@code
 * true} requests an early persistence checkpoint after the task completes, while {@code false}
 * indicates that no immediate checkpoint is needed for this unit of work.
 */
@FunctionalInterface
public interface RequestQueueTask {
  /**
   * Executes the task.
   *
   * <p>Implementations should finish promptly, avoid blocking unrelated infrastructure work longer
   * than necessary, and keep protocol-specific error mapping in the caller that submits the task.
   *
   * @return {@code true} to request an early persistence checkpoint after execution; {@code false}
   *     when no immediate checkpoint is needed
   */
  boolean run();
}

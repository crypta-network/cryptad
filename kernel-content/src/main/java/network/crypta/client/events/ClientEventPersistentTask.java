package network.crypta.client.events;

/**
 * One persistence-affecting work item queued from client event handling.
 *
 * <p>This functional interface is the smallest unit of persistent follow-up work that the
 * compile-neutral event layer can request from the runtime. Event listeners use it when they need
 * to move a tiny state update off the synchronous dispatch path but still run that update under the
 * node's normal persistence rules. Typical examples are compatibility or metadata merges that
 * should happen through the persistent client queue instead of inline inside a callback.
 *
 * <p>The task deliberately exposes only a boolean result. Returning {@code true} mirrors the
 * runtime persistence runner's "checkpoint soon" signal, while returning {@code false} leaves
 * checkpoint timing unchanged. Implementations should stay small, deterministic, and free of
 * blocking I/O beyond whatever the runtime persistence queue already coordinates.
 */
@FunctionalInterface
public interface ClientEventPersistentTask {

  /**
   * Runs the queued event task.
   *
   * <p>The task executes later on the runtime-owned persistence queue, not on the original event
   * dispatch thread. Implementations should perform one focused persistence-affecting action and
   * then report whether that action warrants an earlier checkpoint of the wider persistent state.
   *
   * @return {@code true} to request an immediate persistence checkpoint; otherwise {@code false}
   */
  boolean run();
}

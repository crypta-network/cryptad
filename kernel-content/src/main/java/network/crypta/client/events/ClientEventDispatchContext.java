package network.crypta.client.events;

import network.crypta.client.async.PersistenceDisabledException;

/**
 * Narrow event-dispatch context exposed to client event listeners and producers.
 *
 * <p>This interface is the runtime-facing half of the event extraction seam. It allows
 * compile-neutral event code in {@code :kernel-content} to ask a small set of questions about the
 * current runtime environment without depending on the full, runtime-owned {@code ClientContext}
 * type. Event listeners and producers only need to know whether a persistent state is ready and how
 * to enqueue one persistence-affecting follow-up task at a chosen priority. They do not need
 * request schedulers, bucket factories, or broader runtime services.
 *
 * <p>The contract is intentionally restrictive. Implementations are expected to delegate to the
 * node's existing persistence machinery and to preserve the normal ordering, checkpoint, and
 * shutdown semantics of that machinery. Callers should treat the context as ephemeral and scoped to
 * the current dispatch. If no persistence-backed follow-up work is needed, listeners can ignore it
 * completely.
 *
 * <ul>
 *   <li>Scope: event dispatch only, not a general runtime SPI.
 *   <li>Primary uses: readiness checks and queued compatibility or metadata merges.
 *   <li>Ownership: implemented in runtime code, consumed from compile-neutral event code.
 * </ul>
 */
public interface ClientEventDispatchContext {

  /**
   * Returns whether a persistent client state has finished loading and is ready to accept queued
   * event work.
   *
   * <p>Listeners can use this as a fast gate before attempting persistence-affecting follow-up
   * work. A return value of {@code false} means the caller should either defer to a transient path
   * or skip the queued persistence action for now, depending on the event's semantics. The method
   * is intended to be inexpensive and side-effect free.
   *
   * @return {@code true} when persistence-backed event work can be queued; otherwise {@code false}
   */
  boolean hasLoadedPersistentState();

  /**
   * Queues one persistence-affecting event task at the supplied priority.
   *
   * <p>The task is executed by the runtime's existing persistence-aware queue rather than inline in
   * the event callback. This keeps event listeners lightweight while still allowing narrowly scoped
   * state updates, such as compatibility-mode merges, to observe the same checkpointing and
   * ordering rules as the rest of the persistent client layer. Callers should pass only small,
   * deterministic work items and should choose a priority that matches the urgency of the event.
   *
   * @param task task to run through the persistence-aware event queue
   * @param threadPriority executor priority to apply to the queued work item
   * @throws PersistenceDisabledException when persistence is unavailable and the task cannot be
   *     queued
   */
  void queuePersistentEventTask(ClientEventPersistentTask task, int threadPriority)
      throws PersistenceDisabledException;
}

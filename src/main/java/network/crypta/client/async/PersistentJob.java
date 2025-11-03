package network.crypta.client.async;

/**
 * Represents a single unit of work that mutates or otherwise affects the node's persistent state.
 * Implementations typically enqueue changes that should be reflected in on-disk data structures
 * (for example, registering a new long‑running request, updating durable metadata, or removing
 * completed items). Jobs are executed by a {@link PersistentJobRunner} which coordinates ordering
 * and temporary suspension during persistence checkpoints.
 *
 * <p>Use this interface when an operation has side effects that must survive restarts or interact
 * with serialized request state. The job object itself is intentionally ephemeral: it is not
 * serialized or replayed across runs. Instead, the job performs the change and, if appropriate,
 * requests that the wider persistent state be saved soon after completion. This design keeps the
 * queued objects small and avoids complex deserialization logic while still providing a clear hook
 * to trigger durable snapshots.
 *
 * <p>Concurrency and lifecycle: implementations should be thread‑safe if they can be scheduled from
 * multiple threads; the {@link PersistentJobRunner} may invoke jobs on its own worker. Jobs are
 * expected to be short‑lived and idempotent with respect to external retries, but idempotency is
 * not enforced by this interface. A job instance is used at most once by the runner. When a job
 * necessitates an immediate persistence cycle (for example, after adding or removing a persistent
 * request), it should indicate this via the return value of {@link #run(ClientContext)}.
 *
 * <ul>
 *   <li>Responsibilities: perform a single persistence‑affecting change, optionally request a
 *       serialization pass.
 *   <li>Scope: job objects are transient; only their effects become durable.
 *   <li>Coordination: scheduled and executed by {@link PersistentJobRunner} with checkpoint
 *       awareness.
 * </ul>
 *
 * @author toad
 * @see PersistentJobRunner
 * @see ClientContext
 */
public interface PersistentJob {

  /**
   * Executes the job within the provided client context.
   *
   * <p>Implementations should perform exactly one logical persistence‑affecting action. The method
   * may be called on a background thread managed by the job runner. If the resulting state change
   * warrants prompt serialization of the node's durable state (for example, creating or deleting a
   * persistent request), the implementation should return {@code true}. Returning {@code false}
   * indicates that no immediate checkpoint is required; regular periodic saves may persist the
   * change later. Implementations should handle being called when the system is under load and
   * avoid blocking for extended periods.
   *
   * <pre>{@code
   * // Example: enqueue a job that makes a durable change and asks for a save
   * jobRunner.enqueue(() -> {
   *   // Perform persistence-affecting work using the provided context
   *   return true; // request immediate serialization of persistent state
   * });
   * }</pre>
   *
   * @param context execution context providing access to schedulers, storage factories, alerts, and
   *     other collaborators; never {@code null} and valid only for the duration of the call.
   * @return {@code true} to request serialization of the entire persistent state as soon as
   *     practical; {@code false} if no immediate persistence cycle is necessary.
   */
  boolean run(ClientContext context);
}

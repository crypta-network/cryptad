package network.crypta.clients.fcp;

import network.crypta.client.async.persistence.PersistentRequestRuntimeContext;

/**
 * Detached persistent-job seam used by adapter-owned FCP server infrastructure.
 *
 * <p>This functional interface represents the small amount of queued, persistence-affecting work
 * that still originates inside the FCP adapter after the server/runtime boundary hardening. It is
 * intentionally narrower than the runtime-owned persistent-job contract: the adapter can describe
 * what work should run and whether that work should request a checkpoint, but it does not own the
 * live job-runner type or the concrete daemon-core scheduling machinery.
 *
 * <p>Typical jobs wrap operations such as restart, remove, or connection-cleanup handling for
 * persistent FCP requests. The bridge layer converts each instance into the runtime-owned job type
 * and executes it against a live daemon context. Adapter code therefore stays detached from
 * runtime-owned infrastructure types while preserving the same queue ordering, checkpoint
 * semantics, and operational labels that the underlying runtime still expects.
 *
 * <ul>
 *   <li>Describes only server-owned FCP persistence work, not a generic platform job API.
 *   <li>Runs against a detached persistent-request runtime context supplied by the bridge layer.
 *   <li>Returns a checkpoint hint so the existing persistence timing stays unchanged.
 * </ul>
 */
@FunctionalInterface
public interface FcpPersistentJob {

  /**
   * Runs one unit of queued FCP persistent work.
   *
   * <p>Implementations should perform only the minimal persistent operation that was queued and
   * then return promptly. The supplied context is detached at the adapter boundary but backed by
   * the live daemon runtime, so implementations may pass it into other detached FCP seams without
   * reintroducing direct runtime-owned job types. Returning {@code true} preserves the existing
   * behavior of jobs that ask the runtime to checkpoint state immediately after completion.
   *
   * @param context detached runtime context associated with the live persistent-job execution
   * @return {@code true} when the job should request an immediate persistence checkpoint
   */
  boolean run(PersistentRequestRuntimeContext context);
}
